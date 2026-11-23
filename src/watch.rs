//! `ashealth watch` — 定期再チェックと差分通知 (監視プロダクトの種)。
//!
//! 1サイクル = 健康診断を実行 → 前回結果 (状態ファイル) と所見集合を比較 →
//! 新規/解消/スコア変化を報告 → 状態を永続化。
//! 変化があったとき (および初回) は Webhook に JSON を POST する。
//! ペイロードには Discord Webhook がそのまま解釈できる `content`
//! (日本語1行サマリ) を含める。
//!
//! 所見の同一性は「チェック種別 + 対象プレフィックス + 深刻度」([`FindingKey`]) で
//! 判定し、差分計算 ([`diff_findings`]) は純粋関数として単体テストできる。

use crate::checks::{self, Severity};
use crate::report::Report;
use crate::sources::{fixture::FixtureSource, DataSource, LiveSource};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

/// 所見の同一性判定キー (チェック種別 + 対象 + 深刻度)。
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct FindingKey {
    /// 機械可読チェックID (例: "rpki-invalid")
    pub check: String,
    /// 対象プレフィックス等 (チェックによっては無し)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// "FAIL" / "WARN" / "INFO"
    pub severity: String,
}

impl FindingKey {
    fn describe(&self) -> String {
        match &self.subject {
            Some(s) => format!("[{}] {} ({})", self.severity, s, self.check),
            None => format!("[{}] {}", self.severity, self.check),
        }
    }
}

/// 履歴に保持するスコア推移の1エントリ ([`HISTORY_CAP`] 件を上限にFIFOで追記)。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HistoryEntry {
    /// RFC3339形式のタイムスタンプ (例: "2026-07-07T09:00:00Z")
    pub timestamp: String,
    pub score: i32,
    pub grade: char,
    pub fail_count: usize,
    pub warn_count: usize,
}

/// 履歴に保持する最大エントリ数 (FIFO — 超過分は古い方から破棄)。
pub const HISTORY_CAP: usize = 90;

/// 状態ファイルに永続化する前回実行の要約。
#[derive(Debug, Serialize, Deserialize)]
pub struct WatchState {
    pub asn: u32,
    pub score: i32,
    pub grade: char,
    pub findings: Vec<FindingKey>,
    /// UNIXタイムスタンプ (秒)
    pub checked_at: u64,
    /// スコア推移の履歴 (直近 [`HISTORY_CAP`] 件、古い順)。
    /// 旧バージョンの状態ファイルには存在しないフィールドなので serde デフォルトで後方互換を保つ。
    #[serde(default)]
    pub history: Vec<HistoryEntry>,
    /// 直近の `ashealth report` 実行時刻 (RFC3339)。未実行なら None。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_report_at: Option<String>,
}

/// 履歴に1件追記し、[`HISTORY_CAP`] を超えた分を古い方から破棄する (純粋関数)。
pub fn push_history(history: &mut Vec<HistoryEntry>, entry: HistoryEntry) {
    history.push(entry);
    if history.len() > HISTORY_CAP {
        let excess = history.len() - HISTORY_CAP;
        history.drain(0..excess);
    }
}

/// 現在時刻のRFC3339文字列 (UTC、タイムゾーンDBなしの手組み実装)。
/// 依存クレートを増やさないため、UNIX epoch秒からグレゴリオ暦を計算する。
pub fn rfc3339_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    rfc3339_from_unix(secs)
}

/// UNIXタイムスタンプ (秒) をRFC3339 (UTC) 文字列に変換する (純粋関数、単体テスト用に公開)。
pub fn rfc3339_from_unix(secs: u64) -> String {
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);

    // civil_from_days: Howard Hinnant's algorithm (proleptic Gregorian, epoch = 1970-01-01)
    let z = days as i64 + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let mth = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let y = if mth <= 2 { y + 1 } else { y };

    format!("{y:04}-{mth:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

/// 2つの所見集合の差分。
#[derive(Debug, Default, PartialEq, Eq)]
pub struct FindingDiff {
    pub new: Vec<FindingKey>,
    pub resolved: Vec<FindingKey>,
}

impl FindingDiff {
    pub fn is_empty(&self) -> bool {
        self.new.is_empty() && self.resolved.is_empty()
    }
}

/// 前回と今回の所見集合を比較する (純粋関数)。
pub fn diff_findings(prev: &[FindingKey], curr: &[FindingKey]) -> FindingDiff {
    let prev_set: BTreeSet<&FindingKey> = prev.iter().collect();
    let curr_set: BTreeSet<&FindingKey> = curr.iter().collect();
    FindingDiff {
        new: curr_set
            .difference(&prev_set)
            .map(|k| (*k).clone())
            .collect(),
        resolved: prev_set
            .difference(&curr_set)
            .map(|k| (*k).clone())
            .collect(),
    }
}

fn severity_label(sev: Severity) -> &'static str {
    match sev {
        Severity::Ok => "OK",
        Severity::Info => "INFO",
        Severity::Warn => "WARN",
        Severity::Fail => "FAIL",
    }
}

/// レポートから比較用の所見キー集合を抽出する (OK所見は問題ではないので除外)。
pub fn finding_keys(report: &Report) -> Vec<FindingKey> {
    report
        .findings
        .iter()
        .filter(|f| f.severity != Severity::Ok)
        .map(|f| FindingKey {
            check: f.check.to_string(),
            subject: f.subject.clone(),
            severity: severity_label(f.severity).to_string(),
        })
        .collect()
}

/// 既定の状態ファイルパス: `$XDG_STATE_HOME/ashealth/asXXXX.json`
/// (未設定なら `~/.local/state/ashealth/asXXXX.json`)。
///
/// `demo == true` の場合は実運用の状態ファイルを汚染しないよう `demo/` サブディレクトリに書く
/// (`$XDG_STATE_HOME/ashealth/demo/asXXXX.json`、未設定なら `~/.local/state/ashealth/demo/asXXXX.json`)。デモを何度も試した結果が
/// 実際の監視状態(スコア履歴・差分基準)に混ざらないようにするため。
pub fn default_state_path_for(asn: u32, demo: bool) -> PathBuf {
    let base = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(std::env::var_os("HOME").unwrap_or_default())
                .join(".local")
                .join("state")
        });
    let dir = base.join("ashealth");
    let dir = if demo { dir.join("demo") } else { dir };
    dir.join(format!("as{asn}.json"))
}

/// watchサブコマンドの本体。`once` なら1サイクルで終了、そうでなければ無限ループ。
pub async fn run(
    asn: u32,
    demo: bool,
    limit: usize,
    interval_secs: u64,
    webhook: Option<String>,
    state_path: Option<PathBuf>,
    once: bool,
) -> Result<()> {
    let path = state_path.unwrap_or_else(|| default_state_path_for(asn, demo));
    println!(
        "ashealth watch: AS{asn} を監視します (状態: {}, 間隔: {}秒{})",
        path.display(),
        interval_secs,
        if once { ", --once" } else { "" }
    );
    loop {
        match run_cycle(asn, demo, limit, &path, webhook.as_deref()).await {
            Ok(_outcome) => {}
            Err(e) if once => return Err(e),
            Err(e) => eprintln!("watch: サイクル失敗 (次回に再試行): {e:#}"),
        }
        if once {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(interval_secs)).await;
    }
}

/// 1サイクル分の結果 (複数AS監視のサマリ集計用)。
pub struct CycleOutcome {
    pub changed: bool,
}

/// 1AS分の健康診断→差分検知→Webhook通知→状態永続化を実行する。
/// `ashealth watch <ASN>` (単一AS) と `ashealth watch --config` (複数AS) の両方から使う共通ロジック。
pub async fn run_cycle(
    asn: u32,
    demo: bool,
    limit: usize,
    path: &Path,
    webhook: Option<&str>,
) -> Result<CycleOutcome> {
    // 1. 健康診断を実行
    let source: Arc<dyn DataSource> = if demo {
        Arc::new(FixtureSource::new())
    } else {
        Arc::new(LiveSource::new()?)
    };
    let input = checks::collect(source, asn, limit).await?;
    let findings = checks::run_checks(&input);
    let report = Report::build(&input, findings);
    let curr = finding_keys(&report);

    // 2. 前回状態を読み込み比較
    let prev: Option<WatchState> = match std::fs::read_to_string(path) {
        Ok(s) => Some(
            serde_json::from_str(&s)
                .with_context(|| format!("状態ファイルの解析に失敗: {}", path.display()))?,
        ),
        Err(_) => None,
    };
    let first_run = prev.is_none();
    let prev_score = prev.as_ref().map(|s| s.score);
    let prev_history = prev.as_ref().map(|s| s.history.clone()).unwrap_or_default();
    let prev_last_report_at = prev.as_ref().and_then(|s| s.last_report_at.clone());
    let prev_keys = prev.map(|s| s.findings).unwrap_or_default();
    let diff = diff_findings(&prev_keys, &curr);
    let score_changed = prev_score.is_some_and(|s| s != report.score);
    let changed = !diff.is_empty() || score_changed;

    // 3. 標準出力に報告
    let summary = build_summary(&report, prev_score, &diff, first_run);
    println!("{summary}");
    for k in &diff.new {
        println!("  + 新規: {}", k.describe());
    }
    for k in &diff.resolved {
        println!("  - 解消: {}", k.describe());
    }

    // 4. 変化時 (または初回) に Webhook 通知
    if let Some(url) = webhook {
        if first_run || changed {
            if let Err(e) = post_webhook(url, &report, &diff, &summary).await {
                eprintln!("watch: Webhook通知に失敗しました: {e:#}");
            } else {
                println!("  → Webhook通知を送信しました");
            }
        }
    }

    // 5. 状態を永続化 (履歴に今回分を追記、90件上限でFIFO)
    let fail_count = report
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Fail)
        .count();
    let warn_count = report
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Warn)
        .count();
    let mut history = prev_history;
    push_history(
        &mut history,
        HistoryEntry {
            timestamp: rfc3339_now(),
            score: report.score,
            grade: report.grade,
            fail_count,
            warn_count,
        },
    );
    let state = WatchState {
        asn: report.asn,
        score: report.score,
        grade: report.grade,
        findings: curr,
        checked_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        history,
        last_report_at: prev_last_report_at,
    };
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("状態ディレクトリの作成に失敗: {}", dir.display()))?;
    }
    std::fs::write(path, serde_json::to_string_pretty(&state)?)
        .with_context(|| format!("状態ファイルの書き込みに失敗: {}", path.display()))?;
    Ok(CycleOutcome { changed })
}

/// 日本語1行サマリ (Webhook の content にもそのまま使う)。
fn build_summary(
    report: &Report,
    prev_score: Option<i32>,
    diff: &FindingDiff,
    first_run: bool,
) -> String {
    let base = format!("ashealth watch AS{}", report.asn);
    if first_run {
        return format!(
            "{base}: 初回チェック完了 — スコア {}点 (グレード{}), 所見 {}件",
            report.score,
            report.grade,
            diff.new.len()
        );
    }
    let score_part = match prev_score {
        Some(p) if p != report.score => {
            format!("スコア {p} → {}点 (グレード{})", report.score, report.grade)
        }
        _ => format!("スコア {}点 (グレード{})", report.score, report.grade),
    };
    if diff.is_empty() && prev_score == Some(report.score) {
        format!("{base}: 変化なし — {score_part}")
    } else {
        format!(
            "{base}: 変化を検出 — {score_part}, 新規 {}件 / 解消 {}件",
            diff.new.len(),
            diff.resolved.len()
        )
    }
}

/// Webhook に JSON を POST する。`content` は Discord Webhook 互換の1行サマリ。
async fn post_webhook(url: &str, report: &Report, diff: &FindingDiff, summary: &str) -> Result<()> {
    let payload = serde_json::json!({
        "asn": report.asn,
        "score": report.score,
        "grade": report.grade,
        "new": diff.new,
        "resolved": diff.resolved,
        "summary": summary,
        "content": summary,
    });
    post_webhook_json(url, &payload).await
}

/// 任意のJSONペイロードをWebhookにPOSTする共通クライアント。
/// `watch` (差分通知) と `report` (定期サマリ) の両方から使う。
/// Discord Webhookはそのまま`content`フィールドを1行メッセージとして表示するため、
/// 呼び出し側はペイロードに `"content"` (日本語サマリ文字列) を含めること。
pub async fn post_webhook_json(url: &str, payload: &serde_json::Value) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .user_agent(concat!("ashealth/", env!("CARGO_PKG_VERSION")))
        .build()?;
    let resp = client.post(url).json(payload).send().await?;
    let status = resp.status();
    anyhow::ensure!(
        status.is_success(),
        "Webhook先が {status} を返しました: {}",
        resp.text().await.unwrap_or_default()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(check: &str, subject: Option<&str>, severity: &str) -> FindingKey {
        FindingKey {
            check: check.to_string(),
            subject: subject.map(str::to_string),
            severity: severity.to_string(),
        }
    }

    #[test]
    fn diff_detects_new_and_resolved() {
        let prev = vec![
            key("roa-missing", Some("198.51.100.0/24"), "FAIL"),
            key("irr-stale", Some("203.0.113.128/25"), "WARN"),
        ];
        let curr = vec![
            key("roa-missing", Some("198.51.100.0/24"), "FAIL"), // 継続
            key("rpki-invalid", Some("203.0.113.0/24"), "FAIL"), // 新規
        ];
        let d = diff_findings(&prev, &curr);
        assert_eq!(
            d.new,
            vec![key("rpki-invalid", Some("203.0.113.0/24"), "FAIL")]
        );
        assert_eq!(
            d.resolved,
            vec![key("irr-stale", Some("203.0.113.128/25"), "WARN")]
        );
    }

    #[test]
    fn diff_identical_sets_is_empty() {
        let a = vec![
            key("roa-missing", Some("2001:db8::/32"), "FAIL"),
            key("peeringdb-missing", None, "WARN"),
        ];
        let d = diff_findings(&a, &a.clone());
        assert!(d.is_empty());
    }

    #[test]
    fn diff_severity_change_counts_as_new_and_resolved() {
        // 同じチェック・同じprefixでも深刻度が変われば「解消+新規」として扱う
        let prev = vec![key("peeringdb-incomplete", None, "INFO")];
        let curr = vec![key("peeringdb-missing", None, "WARN")];
        let d = diff_findings(&prev, &curr);
        assert_eq!(d.new.len(), 1);
        assert_eq!(d.resolved.len(), 1);
    }

    #[test]
    fn diff_empty_prev_marks_everything_new() {
        let curr = vec![key("roa-missing", Some("198.51.100.0/24"), "FAIL")];
        let d = diff_findings(&[], &curr);
        assert_eq!(d.new.len(), 1);
        assert!(d.resolved.is_empty());
    }

    #[test]
    fn diff_order_is_deterministic() {
        let curr = vec![
            key("z-check", Some("b"), "WARN"),
            key("a-check", Some("a"), "FAIL"),
        ];
        let d = diff_findings(&[], &curr);
        // BTreeSetにより check → subject → severity 順でソートされる
        assert_eq!(d.new[0].check, "a-check");
        assert_eq!(d.new[1].check, "z-check");
    }

    #[test]
    fn finding_keys_excludes_ok_findings() {
        use crate::checks::Finding;
        use std::collections::BTreeMap;

        let input = checks::HealthInput {
            overview: crate::sources::AsOverview {
                asn: 64510,
                holder: "TEST-NET".into(),
                announced: true,
            },
            announced: vec!["192.0.2.0/24".into()],
            rpki: BTreeMap::from([(
                "192.0.2.0/24".to_string(),
                crate::sources::RpkiStatus::Valid.into(),
            )]),
            irr_rpki: BTreeMap::new(),
            irr: None,
            pdb_checked: false,
            peeringdb: None,
            notes: vec![],
        };
        let findings: Vec<Finding> = checks::run_checks(&input);
        let report = Report::build(&input, findings);
        let keys = finding_keys(&report);
        assert!(
            keys.iter().all(|k| k.severity != "OK"),
            "OK所見はキーに含めない"
        );
    }

    #[test]
    fn watch_state_roundtrips_through_json() {
        let state = WatchState {
            asn: 64500,
            score: 28,
            grade: 'E',
            findings: vec![key("rpki-invalid", Some("203.0.113.0/24"), "FAIL")],
            checked_at: 1_780_000_000,
            history: vec![HistoryEntry {
                timestamp: "2026-07-01T00:00:00Z".into(),
                score: 28,
                grade: 'E',
                fail_count: 1,
                warn_count: 2,
            }],
            last_report_at: Some("2026-07-01T00:00:00Z".into()),
        };
        let json = serde_json::to_string(&state).unwrap();
        let back: WatchState = serde_json::from_str(&json).unwrap();
        assert_eq!(back.asn, 64500);
        assert_eq!(back.score, 28);
        assert_eq!(back.grade, 'E');
        assert_eq!(back.findings, state.findings);
        assert_eq!(back.history, state.history);
        assert_eq!(back.last_report_at, state.last_report_at);
    }

    #[test]
    fn old_state_file_without_history_loads_fine() {
        // v0.4以前の状態ファイル (history / last_report_at フィールドなし) を模擬。
        let old_json = r#"{
            "asn": 64500,
            "score": 28,
            "grade": "E",
            "findings": [],
            "checked_at": 1780000000
        }"#;
        let state: WatchState = serde_json::from_str(old_json).unwrap();
        assert_eq!(state.asn, 64500);
        assert!(state.history.is_empty());
        assert_eq!(state.last_report_at, None);
    }

    #[test]
    fn push_history_appends() {
        let mut history = vec![HistoryEntry {
            timestamp: "2026-07-01T00:00:00Z".into(),
            score: 28,
            grade: 'E',
            fail_count: 3,
            warn_count: 5,
        }];
        push_history(
            &mut history,
            HistoryEntry {
                timestamp: "2026-07-02T00:00:00Z".into(),
                score: 45,
                grade: 'D',
                fail_count: 1,
                warn_count: 3,
            },
        );
        assert_eq!(history.len(), 2);
        assert_eq!(history[1].score, 45);
    }

    #[test]
    fn push_history_caps_at_90_fifo() {
        let mut history = Vec::new();
        for i in 0..HISTORY_CAP {
            push_history(
                &mut history,
                HistoryEntry {
                    timestamp: format!("entry-{i}"),
                    score: i as i32,
                    grade: 'A',
                    fail_count: 0,
                    warn_count: 0,
                },
            );
        }
        assert_eq!(history.len(), HISTORY_CAP);
        // 90件を超える追記で先頭 (最古) から破棄される
        push_history(
            &mut history,
            HistoryEntry {
                timestamp: "entry-90".into(),
                score: 90,
                grade: 'A',
                fail_count: 0,
                warn_count: 0,
            },
        );
        assert_eq!(history.len(), HISTORY_CAP);
        assert_eq!(history[0].timestamp, "entry-1", "最古のentry-0が破棄される");
        assert_eq!(history.last().unwrap().timestamp, "entry-90");
    }

    #[test]
    fn rfc3339_from_unix_known_value() {
        // 2026-07-07T00:00:00Z の UNIX秒 (date -u -d '2026-07-07T00:00:00Z' +%s で確認)
        assert_eq!(rfc3339_from_unix(1_783_382_400), "2026-07-07T00:00:00Z");
        // epoch
        assert_eq!(rfc3339_from_unix(0), "1970-01-01T00:00:00Z");
    }

    /// P2-6: `--demo` の状態ファイルは `demo/` サブディレクトリに書く
    /// (実運用の監視状態・スコア履歴を汚染しないため)。
    #[test]
    fn default_state_path_for_demo_uses_demo_subdir() {
        let normal = default_state_path_for(64500, false);
        let demo = default_state_path_for(64500, true);
        assert_ne!(normal, demo);
        assert!(
            demo.to_string_lossy().contains("/demo/"),
            "got: {}",
            demo.display()
        );
        assert!(
            !normal.to_string_lossy().contains("/demo/"),
            "got: {}",
            normal.display()
        );
        assert_eq!(demo.file_name(), normal.file_name());
    }

    #[test]
    fn default_state_path_for_differs_per_asn() {
        let a = default_state_path_for(64500, false);
        let b = default_state_path_for(64501, false);
        assert_ne!(a, b);
    }

    /// 状態の保存に失敗したサイクルでも webhook は送信済み (README に記載の挙動)。
    /// 手順4 (webhook送信) が手順5 (状態保存) より先に走るため、サイクルは Err でも通知は届く。
    #[tokio::test]
    async fn cycle_failing_at_state_save_has_already_sent_webhook() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // 1リクエストだけ受けて 200 を返す手製サーバ
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/hook", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                let n = sock.read(&mut chunk).await.unwrap();
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
                let text = String::from_utf8_lossy(&buf).to_string();
                if let Some(pos) = text.find("\r\n\r\n") {
                    let len = text[..pos]
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .and_then(|v| v.trim().parse::<usize>().ok())
                        })
                        .unwrap_or(0);
                    if buf.len() >= pos + 4 + len {
                        break;
                    }
                }
            }
            sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
            sock.shutdown().await.ok();
            String::from_utf8_lossy(&buf).to_string()
        });

        // 通常ファイルの下を指す path → create_dir_all が必ず失敗する
        let dir = std::env::temp_dir().join(format!(
            "ashealth-watch-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("file");
        std::fs::write(&file, b"not a dir").unwrap();
        let bad_path = file.join("as64500.json");

        let result = run_cycle(64500, true, 50, &bad_path, Some(&url)).await;
        let received = tokio::time::timeout(Duration::from_secs(5), server).await;
        std::fs::remove_dir_all(&dir).ok();

        let err = result.err().expect("状態保存に失敗するのでサイクルは Err");
        assert!(
            format!("{err:#}").contains("状態ディレクトリの作成に失敗"),
            "unexpected error: {err:#}"
        );
        let req = received
            .expect("webhook が受信されること")
            .expect("サーバタスクが正常終了すること");
        assert!(req.starts_with("POST /hook"), "unexpected request: {req}");
        assert!(req.contains("\"asn\":64500"), "unexpected request: {req}");
    }
}
