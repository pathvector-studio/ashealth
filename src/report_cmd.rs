//! `ashealth report` — 定期サマリレポート (v0.5)。
//!
//! `watch` が「前回サイクルとの差分」を追うのに対し、`report` は
//! **前回の `report` 実行との差分** (`last_report_at` 基準) と、状態ファイルに
//! 積み上がったスコア履歴 ([`crate::watch::HistoryEntry`]) からのトレンドを
//! まとめて提示する。所見・状態の取得は各AS毎に既存の `checks::collect` /
//! `watch::WatchState` を再利用し、差分計算・トレンド抽出・上位所見選定は
//! すべて純粋関数として単体テストできるようにする。

use crate::checks::{self, Finding, Severity};
use crate::config::{AsEntry, Config};
use crate::fix;
use crate::report::Report;
use crate::sources::{fixture::FixtureSource, DataSource, LiveSource};
use crate::watch::{self, HistoryEntry, WatchState};
use anyhow::{Context, Result};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

/// 複数AS間の休止 (RIPEstatへの配慮。[`crate::multi::INTER_AS_PAUSE`] と同じ値)。
const INTER_AS_PAUSE: Duration = Duration::from_secs(1);

/// トレンド表示に使う直近スコアの件数 (例: "28 → 35 → 45 → 79")。
const TREND_POINTS: usize = 4;

/// 1AS分のレポートブロック。
#[derive(Debug, Serialize)]
pub struct AsReportBlock {
    pub asn: u32,
    pub label: String,
    pub score: i32,
    pub grade: char,
    pub fail_count: usize,
    pub warn_count: usize,
    /// 前回 `report` 実行からのスコア差分 (初回はNone)
    pub delta: Option<i32>,
    /// 直近 [`TREND_POINTS`] 件のスコア推移 (古い順)
    pub trend: Vec<i32>,
    /// 深刻度順 (FAIL→WARN→INFO) の上位3件
    pub top_findings: Vec<String>,
}

/// 全AS分のレポート (組み合わせヘッダ + 各ASブロック)。
#[derive(Debug, Serialize)]
pub struct FullReport {
    pub as_count: usize,
    pub avg_score: i32,
    /// 全AS中もっとも深刻な所見 (FAIL優先)。1件もなければNone
    pub top_action: Option<String>,
    pub blocks: Vec<AsReportBlock>,
}

/// 所見1件を人間可読な1行に整形する (純粋関数)。
fn describe_finding(f: &Finding) -> String {
    let sev = match f.severity {
        Severity::Fail => "FAIL",
        Severity::Warn => "WARN",
        Severity::Info => "INFO",
        Severity::Ok => "OK",
    };
    match &f.subject {
        Some(s) => format!("[{sev}] {s} — {}", f.message),
        None => format!("[{sev}] {}", f.message),
    }
}

/// 深刻度 (FAIL→WARN→INFO、OKは除外) で上位N件を選ぶ (純粋関数)。
pub fn top_findings(findings: &[Finding], n: usize) -> Vec<String> {
    let mut items: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.severity != Severity::Ok)
        .collect();
    items.sort_by_key(|f| std::cmp::Reverse(f.severity));
    items.into_iter().take(n).map(describe_finding).collect()
}

/// 履歴から直近N件のスコアを古い順に抽出する (純粋関数)。
pub fn extract_trend(history: &[HistoryEntry], n: usize) -> Vec<i32> {
    let len = history.len();
    let start = len.saturating_sub(n);
    history[start..].iter().map(|h| h.score).collect()
}

/// トレンドを "28 → 35 → 45 → 79" 形式の文字列にする (純粋関数)。
pub fn format_trend(trend: &[i32]) -> String {
    trend
        .iter()
        .map(|s| s.to_string())
        .collect::<Vec<_>>()
        .join(" → ")
}

/// 前回reportとの差分を "↑+12" / "↓-5" / "±0" 形式にする (純粋関数)。
pub fn format_delta(delta: Option<i32>) -> String {
    match delta {
        None => "初回".to_string(),
        Some(d) if d > 0 => format!("↑+{d}"),
        Some(d) if d < 0 => format!("↓{d}"),
        Some(_) => "±0".to_string(),
    }
}

/// `last_report_at` 以降で最も古い履歴エントリを探す。
/// なければ (= まだreport未実行、または履歴に窓内エントリがない) None。
///
/// 「オーナー窓内の最古エントリ」= 前回report以降の最初の記録。
/// これと現在のスコアを比べることで「前回reportからの変化」を表現する。
fn oldest_in_window<'a>(
    history: &'a [HistoryEntry],
    last_report_at: Option<&str>,
) -> Option<&'a HistoryEntry> {
    match last_report_at {
        Some(cutoff) => history.iter().find(|h| h.timestamp.as_str() >= cutoff),
        None => history.first(),
    }
}

/// 前回reportとの差分スコアを計算する (純粋関数)。
/// `last_report_at` が None (report初回) なら常に None。
pub fn compute_delta(
    history: &[HistoryEntry],
    last_report_at: Option<&str>,
    current_score: i32,
) -> Option<i32> {
    last_report_at?;
    let baseline = oldest_in_window(history, last_report_at)?;
    Some(current_score - baseline.score)
}

/// 全AS中もっとも深刻な所見を選ぶ (純粋関数)。
/// 深刻度 (FAIL優先) → `fix` と共通の修正優先度 ([`fix::check_priority`]) の順で比べ、
/// 同順位なら同一ASでは `fix` と同じく subject 昇順、別ASでは先に現れた方を採る。
pub fn worst_across(blocks: &[(u32, Vec<Finding>)]) -> Option<String> {
    let mut worst: Option<(&Finding, u32)> = None;
    for (asn, findings) in blocks {
        for f in findings.iter().filter(|f| f.severity != Severity::Ok) {
            worst = match worst {
                None => Some((f, *asn)),
                Some((w, w_asn)) => {
                    let key =
                        |x: &Finding| (std::cmp::Reverse(x.severity), fix::check_priority(x.check));
                    let better = match key(f).cmp(&key(w)) {
                        std::cmp::Ordering::Less => true,
                        std::cmp::Ordering::Equal => *asn == w_asn && f.subject < w.subject,
                        std::cmp::Ordering::Greater => false,
                    };
                    if better {
                        Some((f, *asn))
                    } else {
                        Some((w, w_asn))
                    }
                }
            };
        }
    }
    worst.map(|(f, asn)| format!("AS{asn}: {}", describe_finding(f)))
}

/// `report --config` の本体。各ASの健康診断を実行し、状態ファイルから
/// 前回report以降の差分・履歴トレンドを組み立てる。状態ファイルは
/// `watch` と共有 (同じ `asXXXX.json`) — history / last_report_at を更新する。
pub async fn run_all(
    config: &Config,
    demo: bool,
    state_dir: Option<&PathBuf>,
) -> Result<FullReport> {
    let mut blocks = Vec::with_capacity(config.entries.len());
    let mut raw_findings: Vec<(u32, Vec<Finding>)> = Vec::with_capacity(config.entries.len());
    let mut total_score = 0i32;

    for (i, entry) in config.entries.iter().enumerate() {
        if i > 0 {
            tokio::time::sleep(INTER_AS_PAUSE).await;
        }
        let path = match state_dir {
            Some(dir) => dir.join(format!("as{}.json", entry.asn)),
            None => watch::default_state_path_for(entry.asn, demo),
        };
        match run_one(entry, demo, config.limit, &path).await {
            Ok((block, findings)) => {
                total_score += block.score;
                raw_findings.push((entry.asn, findings));
                blocks.push(block);
            }
            Err(e) => {
                eprintln!(
                    "report: AS{} ({}) の集計に失敗: {e:#}",
                    entry.asn, entry.name
                );
            }
        }
    }

    let as_count = blocks.len();
    let avg_score = if as_count == 0 {
        0
    } else {
        total_score / as_count as i32
    };
    let top_action = worst_across(&raw_findings);

    Ok(FullReport {
        as_count,
        avg_score,
        top_action,
        blocks,
    })
}

/// 1AS分: 健康診断→状態読込→差分/トレンド計算→状態更新 (last_report_atを刻む)。
async fn run_one(
    entry: &AsEntry,
    demo: bool,
    limit: usize,
    path: &Path,
) -> Result<(AsReportBlock, Vec<Finding>)> {
    let source: Arc<dyn DataSource> = if demo {
        Arc::new(FixtureSource::new())
    } else {
        Arc::new(LiveSource::new()?)
    };
    let input = checks::collect(source, entry.asn, limit).await?;
    let findings = checks::run_checks(&input);
    let report = Report::build(&input, findings.clone());

    let fail_count = findings
        .iter()
        .filter(|f| f.severity == Severity::Fail)
        .count();
    let warn_count = findings
        .iter()
        .filter(|f| f.severity == Severity::Warn)
        .count();

    // 既存の状態ファイル (watch/reportどちらが書いたものでも共通) を読み込む
    let prev: Option<WatchState> = match std::fs::read_to_string(path) {
        Ok(s) => Some(
            serde_json::from_str(&s)
                .with_context(|| format!("状態ファイルの解析に失敗: {}", path.display()))?,
        ),
        Err(_) => None,
    };
    let prev_history = prev.as_ref().map(|s| s.history.clone()).unwrap_or_default();
    let prev_last_report_at = prev.as_ref().and_then(|s| s.last_report_at.clone());
    let prev_curr_findings = prev
        .as_ref()
        .map(|s| s.findings.clone())
        .unwrap_or_default();

    let delta = compute_delta(&prev_history, prev_last_report_at.as_deref(), report.score);
    let trend = extract_trend(&prev_history, TREND_POINTS);
    let top = top_findings(&findings, 3);

    let block = AsReportBlock {
        asn: entry.asn,
        label: entry.name.clone(),
        score: report.score,
        grade: report.grade,
        fail_count,
        warn_count,
        delta,
        trend,
        top_findings: top,
    };

    // 状態を更新: 履歴に追記 + last_report_at を今回時刻に更新。
    // findings (差分検知キー) は watch と食い違わないよう、既存があれば維持しつつ
    // 今回の所見で上書きする (watchのdiff検知と同じキー生成ロジックを再利用)。
    let curr_keys = watch::finding_keys(&report);
    let now = watch::rfc3339_now();
    let mut history = prev_history;
    watch::push_history(
        &mut history,
        watch::HistoryEntry {
            timestamp: now.clone(),
            score: report.score,
            grade: report.grade,
            fail_count,
            warn_count,
        },
    );
    let _ = prev_curr_findings; // watchとの互換のため読み込むが、reportでは今回値で上書きする
    let state = WatchState {
        asn: report.asn,
        score: report.score,
        grade: report.grade,
        findings: curr_keys,
        checked_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        history,
        last_report_at: Some(now),
    };
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("状態ディレクトリの作成に失敗: {}", dir.display()))?;
    }
    std::fs::write(path, serde_json::to_string_pretty(&state)?)
        .with_context(|| format!("状態ファイルの書き込みに失敗: {}", path.display()))?;

    Ok((block, findings))
}

/// Discord Webhook互換ペイロードを組み立てる (純粋関数)。
/// `content` に日本語コンパクトサマリ、加えてフルJSONフィールドを含める。
pub fn build_webhook_payload(report: &FullReport) -> serde_json::Value {
    let content = compact_summary(report);
    serde_json::json!({
        "as_count": report.as_count,
        "avg_score": report.avg_score,
        "top_action": report.top_action,
        "blocks": report.blocks,
        "content": content,
    })
}

/// Webhookの `content` 用、日本語1行(+α)のコンパクトサマリ (純粋関数)。
pub fn compact_summary(report: &FullReport) -> String {
    let action = report
        .top_action
        .clone()
        .unwrap_or_else(|| "なし (全AS健全)".to_string());
    format!(
        "ashealth report: 対象AS {}件 / 平均スコア {}点 / 最重要アクション: {action}",
        report.as_count, report.avg_score
    )
}

/// Webhookに定期サマリレポートをPOSTする。`watch` の共通クライアントを再利用する。
pub async fn post_webhook(url: &str, report: &FullReport) -> Result<()> {
    let payload = build_webhook_payload(report);
    watch::post_webhook_json(url, &payload).await
}

/// ターミナル向けの日本語レポートを組み立てる (純粋関数、`--json` 以外の既定出力)。
pub fn render_text(report: &FullReport) -> String {
    let mut out = String::new();
    out.push_str("  ashealth ─ 定期サマリレポート\n");
    out.push_str(&format!("  {}\n", "─".repeat(64)));
    out.push_str(&format!(
        "  対象AS数: {}件   平均スコア: {}点\n",
        report.as_count, report.avg_score
    ));
    match &report.top_action {
        Some(a) => out.push_str(&format!("  最重要アクション: {a}\n")),
        None => out.push_str("  最重要アクション: なし (全AS健全)\n"),
    }
    out.push_str(&format!("  {}\n\n", "─".repeat(64)));

    let mut sorted: Vec<&AsReportBlock> = report.blocks.iter().collect();
    sorted.sort_by_key(|b| b.score);
    for b in sorted {
        out.push_str(&format!(
            "  {} (AS{})  スコア {}点 グレード{}  前回比 {}\n",
            b.label,
            b.asn,
            b.score,
            b.grade,
            format_delta(b.delta)
        ));
        out.push_str(&format!(
            "    FAIL {}件 / WARN {}件\n",
            b.fail_count, b.warn_count
        ));
        if !b.trend.is_empty() {
            out.push_str(&format!("    トレンド: {}\n", format_trend(&b.trend)));
        }
        if !b.top_findings.is_empty() {
            out.push_str("    上位所見:\n");
            for f in &b.top_findings {
                out.push_str(&format!("      - {f}\n"));
            }
        }
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(check_no: u8, severity: Severity, subject: Option<&str>, message: &str) -> Finding {
        Finding {
            check_no,
            check: "test",
            severity,
            subject: subject.map(str::to_string),
            message: message.to_string(),
            fix: None,
        }
    }

    fn hist(timestamp: &str, score: i32) -> HistoryEntry {
        HistoryEntry {
            timestamp: timestamp.to_string(),
            score,
            grade: 'D',
            fail_count: 0,
            warn_count: 0,
        }
    }

    #[test]
    fn top_findings_orders_fail_before_warn_before_info() {
        let findings = vec![
            finding(7, Severity::Info, None, "info1"),
            finding(2, Severity::Fail, Some("203.0.113.0/24"), "fail1"),
            finding(4, Severity::Warn, Some("198.51.100.0/24"), "warn1"),
        ];
        let top = top_findings(&findings, 3);
        assert_eq!(top.len(), 3);
        assert!(top[0].starts_with("[FAIL]"));
        assert!(top[1].starts_with("[WARN]"));
        assert!(top[2].starts_with("[INFO]"));
    }

    #[test]
    fn top_findings_excludes_ok_and_caps_at_n() {
        let findings = vec![
            finding(1, Severity::Ok, None, "ok"),
            finding(2, Severity::Fail, None, "f1"),
            finding(2, Severity::Fail, None, "f2"),
            finding(2, Severity::Fail, None, "f3"),
            finding(2, Severity::Fail, None, "f4"),
        ];
        let top = top_findings(&findings, 3);
        assert_eq!(top.len(), 3);
        assert!(top.iter().all(|s| s.starts_with("[FAIL]")));
    }

    #[test]
    fn extract_trend_takes_last_n_oldest_first() {
        let history = vec![
            hist("t0", 10),
            hist("t1", 20),
            hist("t2", 30),
            hist("t3", 40),
            hist("t4", 50),
        ];
        let trend = extract_trend(&history, 4);
        assert_eq!(trend, vec![20, 30, 40, 50]);
    }

    #[test]
    fn extract_trend_handles_fewer_than_n() {
        let history = vec![hist("t0", 28), hist("t1", 35)];
        let trend = extract_trend(&history, 4);
        assert_eq!(trend, vec![28, 35]);
    }

    #[test]
    fn format_trend_joins_with_arrows() {
        assert_eq!(format_trend(&[28, 35, 45, 79]), "28 → 35 → 45 → 79");
    }

    #[test]
    fn format_delta_variants() {
        assert_eq!(format_delta(Some(12)), "↑+12");
        assert_eq!(format_delta(Some(-5)), "↓-5");
        assert_eq!(format_delta(Some(0)), "±0");
        assert_eq!(format_delta(None), "初回");
    }

    #[test]
    fn compute_delta_none_when_never_reported() {
        let history = vec![hist("t0", 28), hist("t1", 45)];
        assert_eq!(compute_delta(&history, None, 45), None);
    }

    #[test]
    fn compute_delta_uses_oldest_entry_within_window() {
        let history = vec![
            hist("2026-07-01T00:00:00Z", 28),
            hist("2026-07-02T00:00:00Z", 35), // last_report_at はこの直前
            hist("2026-07-03T00:00:00Z", 45),
            hist("2026-07-04T00:00:00Z", 79),
        ];
        // last_report_at = 2026-07-02 なので、その時刻以降で最初のエントリ (35) が基準
        let delta = compute_delta(&history, Some("2026-07-02T00:00:00Z"), 79);
        assert_eq!(delta, Some(79 - 35));
    }

    #[test]
    fn compute_delta_falls_back_to_first_entry_if_cutoff_after_all_history() {
        let history = vec![hist("2026-07-01T00:00:00Z", 28)];
        // last_report_atが履歴の全エントリより新しい (通常発生しないが安全側)
        let delta = compute_delta(&history, Some("2099-01-01T00:00:00Z"), 30);
        assert_eq!(delta, None);
    }

    #[test]
    fn worst_across_prefers_fail_over_warn_across_multiple_as() {
        let blocks = vec![
            (
                64500,
                vec![finding(4, Severity::Warn, Some("p1"), "irr missing")],
            ),
            (
                64501,
                vec![finding(2, Severity::Fail, Some("p2"), "rpki invalid")],
            ),
        ];
        let worst = worst_across(&blocks);
        assert!(worst.unwrap().contains("AS64501"));
    }

    #[test]
    fn worst_across_uses_fix_priority_within_same_severity() {
        let mut inv = finding(2, Severity::Fail, Some("z"), "rpki invalid");
        inv.check = "rpki-invalid";
        let mut miss = finding(1, Severity::Fail, Some("a"), "roa missing");
        miss.check = "roa-missing";
        let blocks = vec![(64500, vec![miss, inv])];
        assert!(worst_across(&blocks).unwrap().contains("rpki invalid"));
    }

    #[test]
    fn worst_across_tie_across_as_keeps_first_as_even_with_smaller_subject() {
        // 深刻度・チェックとも同じ。後のASの subject の方が小さくても、別ASなので先のASを採る。
        let blocks = vec![
            (
                64501,
                vec![finding(1, Severity::Fail, Some("z"), "first as")],
            ),
            (
                64500,
                vec![finding(1, Severity::Fail, Some("a"), "second as")],
            ),
        ];
        let top = worst_across(&blocks).unwrap();
        assert!(top.starts_with("AS64501:"), "{top}");
        assert!(top.contains("first as"), "{top}");
    }

    #[test]
    fn worst_across_tie_within_as_picks_smallest_subject_regardless_of_input_order() {
        // 同一AS・同じチェックで subject だけ違う所見。入力順 (m, a, z) に依らず昇順最小 "a" を採る。
        // 入力順は昇順でも降順でもなく、先勝ち (m) でも後勝ち (z) でも期待値にならない。
        let blocks = vec![(
            64500,
            vec![
                finding(1, Severity::Fail, Some("m"), "subject m"),
                finding(1, Severity::Fail, Some("a"), "subject a"),
                finding(1, Severity::Fail, Some("z"), "subject z"),
            ],
        )];
        let top = worst_across(&blocks).unwrap();
        assert!(top.contains("subject a"), "{top}");
    }

    #[tokio::test]
    async fn demo_top_action_matches_fix_top_priority() {
        use crate::checks::{collect, run_checks};
        let src: Arc<dyn DataSource> = Arc::new(FixtureSource::new());
        let input = collect(src, 64500, 50).await.unwrap();
        let findings = run_checks(&input);
        let rems = fix::remediations(&input, &findings);
        let top_fix = &rems[0].finding;
        assert_eq!(top_fix.check, "rpki-invalid");
        let top = worst_across(&[(64500, findings.clone())]).unwrap();
        assert_eq!(top, format!("AS64500: {}", describe_finding(top_fix)));
    }

    #[test]
    fn worst_across_none_when_all_ok() {
        let blocks = vec![(64500, vec![finding(1, Severity::Ok, None, "fine")])];
        assert_eq!(worst_across(&blocks), None);
    }

    #[test]
    fn compact_summary_includes_counts_and_top_action() {
        let report = FullReport {
            as_count: 2,
            avg_score: 64,
            top_action: Some("AS64500: [FAIL] rpki invalid".into()),
            blocks: vec![],
        };
        let s = compact_summary(&report);
        assert!(s.contains("対象AS 2件"));
        assert!(s.contains("平均スコア 64点"));
        assert!(s.contains("AS64500: [FAIL] rpki invalid"));
    }

    #[test]
    fn compact_summary_handles_no_action() {
        let report = FullReport {
            as_count: 1,
            avg_score: 100,
            top_action: None,
            blocks: vec![],
        };
        assert!(compact_summary(&report).contains("なし"));
    }

    #[test]
    fn webhook_payload_has_content_and_full_fields() {
        let report = FullReport {
            as_count: 1,
            avg_score: 28,
            top_action: Some("AS64500: [FAIL] x".into()),
            blocks: vec![AsReportBlock {
                asn: 64500,
                label: "本番AS".into(),
                score: 28,
                grade: 'E',
                fail_count: 3,
                warn_count: 5,
                delta: None,
                trend: vec![28],
                top_findings: vec![],
            }],
        };
        let payload = build_webhook_payload(&report);
        assert!(payload["content"].as_str().unwrap().contains("対象AS 1件"));
        assert_eq!(payload["as_count"], 1);
        assert_eq!(payload["blocks"][0]["asn"], 64500);
    }

    /// `[defaults] limit = 0` は設定の読み込み時には弾かれず、`report --config` では
    /// 各ASの `checks::collect` で拒否される (README「`limit = 0` は実行時に拒否される」の固定)。
    /// 失敗したASは stderr に出るだけでスキップされ、全滅しても `run_all` は `Ok` を返す
    /// (= main は終了コード0) 。集計は0件・状態ファイルは作られない。
    /// フィクスチャ (`--demo` 相当) のみ使い、ネットワークにも webhook にも触れない。
    #[tokio::test]
    async fn run_all_with_config_limit_zero_fails_every_as_but_returns_ok() {
        let cfg = crate::config::parse(
            r#"
[defaults]
limit = 0

[[as]]
asn = 64500
name = "本番AS"
"#,
        )
        .expect("limit = 0 は読み込み時には弾かれない");
        assert_eq!(cfg.limit, 0);

        let dir = std::env::temp_dir().join(format!(
            "ashealth-report-limit0-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let _ = std::fs::remove_dir_all(&dir);

        // run_one 単体: 拒否理由は limit 0 のエラーで、状態ファイルは書かれない
        let path = dir.join("as64500.json");
        let err = run_one(&cfg.entries[0], true, cfg.limit, &path)
            .await
            .expect_err("limit 0 は collect で拒否される");
        assert!(
            format!("{err:#}").contains("limit に 0 は指定できません"),
            "{err:#}"
        );

        // run_all: AS単位の失敗は握りつぶされ Ok(0件) になる
        let report = run_all(&cfg, true, Some(&dir)).await.expect("全滅でも Ok");
        assert_eq!(report.as_count, 0);
        assert_eq!(report.avg_score, 0);
        assert_eq!(report.top_action, None);
        assert!(report.blocks.is_empty());
        let text = render_text(&report);
        assert!(text.contains("対象AS数: 0件   平均スコア: 0点"), "{text}");
        assert!(text.contains("最重要アクション: なし (全AS健全)"), "{text}");

        // 状態ファイル・状態ディレクトリは作られない (history / last_report_at も進まない)
        assert!(!path.exists());
        assert!(!dir.exists());
    }

    #[test]
    fn render_text_includes_header_and_blocks() {
        let report = FullReport {
            as_count: 1,
            avg_score: 28,
            top_action: Some("AS64500: [FAIL] test".into()),
            blocks: vec![AsReportBlock {
                asn: 64500,
                label: "本番AS".into(),
                score: 28,
                grade: 'E',
                fail_count: 3,
                warn_count: 5,
                delta: Some(-5),
                trend: vec![28, 35, 45, 79],
                top_findings: vec!["[FAIL] test".into()],
            }],
        };
        let text = render_text(&report);
        assert!(text.contains("対象AS数: 1件"));
        assert!(text.contains("平均スコア: 28点"));
        assert!(text.contains("↓-5"));
        assert!(text.contains("28 → 35 → 45 → 79"));
    }
}
