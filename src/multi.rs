//! 複数AS管理 (v0.4) — 設定ファイル駆動の `check` / `watch` 一括実行。
//!
//! `config::Config` に列挙された全ASNを順に処理する。RIPEstatへの配慮として
//! 並列化はせず、AS間に短い休止を挟む ([`INTER_AS_PAUSE`])。
//! `check` は各ASの `Report` を集めて要約テーブルを出力し、`watch` は
//! 既存の [`crate::watch`] サイクルロジックをAS単位で再利用する。

use crate::checks;
use crate::config::{AsEntry, Config};
use crate::report::Report;
use crate::sources::{fixture::FixtureSource, DataSource, LiveSource};
use crate::watch;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

/// 複数AS間の休止 (RIPEstatへの配慮)。
const INTER_AS_PAUSE: Duration = Duration::from_secs(1);

/// `check --config` の1AS分の結果。
pub struct AsCheckResult {
    pub entry: AsEntry,
    pub report: Report,
}

/// 設定内の全ASを順にチェックする (デモモード時はフィクスチャを使用)。
pub async fn check_all(config: &Config, demo: bool) -> Vec<AsCheckResult> {
    let mut results = Vec::with_capacity(config.entries.len());
    for (i, entry) in config.entries.iter().enumerate() {
        if i > 0 {
            tokio::time::sleep(INTER_AS_PAUSE).await;
        }
        let source: Arc<dyn DataSource> = if demo {
            Arc::new(FixtureSource::new())
        } else {
            match LiveSource::new() {
                Ok(s) => Arc::new(s),
                Err(e) => {
                    eprintln!("AS{}: LiveSourceの初期化に失敗: {e:#}", entry.asn);
                    continue;
                }
            }
        };
        match checks::collect(source, entry.asn, config.limit).await {
            Ok(input) => {
                let findings = checks::run_checks(&input);
                let report = Report::build(&input, findings);
                results.push(AsCheckResult {
                    entry: entry.clone(),
                    report,
                });
            }
            Err(e) => {
                eprintln!(
                    "AS{} ({}) のチェックに失敗しました: {e:#}",
                    entry.asn, entry.name
                );
            }
        }
    }
    results
}

/// 単一AS向けの短い日本語サマリ行。
pub fn compact_summary_line(r: &AsCheckResult) -> String {
    let fail = r
        .report
        .findings
        .iter()
        .filter(|f| f.severity == checks::Severity::Fail)
        .count();
    let warn = r
        .report
        .findings
        .iter()
        .filter(|f| f.severity == checks::Severity::Warn)
        .count();
    format!(
        "  {:<12} AS{:<8} スコア {:>3}点 グレード{}  (FAIL {}件 / WARN {}件)",
        r.entry.name, r.entry.asn, r.report.score, r.report.grade, fail, warn
    )
}

/// スコア昇順 (悪い順) にソートしたテーブルをターミナルへ出力する。
pub fn render_terminal_table(results: &[AsCheckResult]) {
    println!();
    println!("  ashealth ─ 複数AS健康診断サマリ (worst-first)");
    println!("  {}", "─".repeat(64));
    let mut sorted: Vec<&AsCheckResult> = results.iter().collect();
    sorted.sort_by_key(|r| r.report.score);
    for r in &sorted {
        println!("{}", compact_summary_line(r));
    }
    println!("  {}", "─".repeat(64));
    let total: i32 = results.iter().map(|r| r.report.score).sum();
    let avg = if results.is_empty() {
        0
    } else {
        total / results.len() as i32
    };
    println!("  合計 {} AS を診断 — 平均スコア {}点", results.len(), avg);
    println!();
}

/// `--json` 用の配列表現。
pub fn to_json_array(results: &[AsCheckResult]) -> serde_json::Value {
    serde_json::Value::Array(
        results
            .iter()
            .map(|r| {
                let mut v = serde_json::json!(r.report);
                if let Some(obj) = v.as_object_mut() {
                    obj.insert("label".into(), serde_json::json!(r.entry.name));
                }
                v
            })
            .collect(),
    )
}

/// 設定内の全ASを1サイクル分監視する (状態ファイルはAS毎に既定パス、またはstate_dir配下)。
///
/// 戻り値: (チェックしたAS数, 変化があったAS数)
pub async fn watch_cycle(
    config: &Config,
    demo: bool,
    state_dir: Option<&PathBuf>,
) -> (usize, usize) {
    let mut checked = 0usize;
    let mut changed_count = 0usize;
    for (i, entry) in config.entries.iter().enumerate() {
        if i > 0 {
            tokio::time::sleep(INTER_AS_PAUSE).await;
        }
        let path = match state_dir {
            Some(dir) => dir.join(format!("as{}.json", entry.asn)),
            None => watch::default_state_path_for(entry.asn, demo),
        };
        println!("── AS{} ({}) ──", entry.asn, entry.name);
        match watch::run_cycle(entry.asn, demo, config.limit, &path, select_webhook(entry)).await {
            Ok(outcome) => {
                checked += 1;
                if outcome.changed {
                    changed_count += 1;
                }
            }
            Err(e) => {
                eprintln!("watch: AS{} サイクル失敗 (次回に再試行): {e:#}", entry.asn);
            }
        }
    }
    (checked, changed_count)
}

/// サイクル完了時の1行サマリ。
pub fn cycle_summary_line(checked: usize, changed: usize) -> String {
    format!("ashealth watch --config: {checked}件のASをチェック — 変化 {changed}件")
}

/// このASに使うWebhook URLを選ぶ (純粋関数)。
/// 優先順位: AS個別設定 > defaults。[`crate::config`] の `validate()` が
/// `AsEntry::webhook` に既に継承済みの値を入れているため、実体はそのまま返すだけだが、
/// 呼び出し側の意図を明示し単体テストできるようにするためのヘルパー。
pub fn select_webhook(entry: &AsEntry) -> Option<&str> {
    entry.webhook.as_deref()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;

    #[test]
    fn select_webhook_prefers_per_as_override() {
        let toml = r#"
[defaults]
webhook = "https://example.com/default"

[[as]]
asn = 64500
webhook = "https://example.com/override"

[[as]]
asn = 64501
"#;
        let cfg = config::parse(toml).unwrap();
        assert_eq!(
            select_webhook(&cfg.entries[0]),
            Some("https://example.com/override")
        );
        assert_eq!(
            select_webhook(&cfg.entries[1]),
            Some("https://example.com/default")
        );
    }

    #[test]
    fn select_webhook_none_when_unset_anywhere() {
        let toml = r#"
[[as]]
asn = 64500
"#;
        let cfg = config::parse(toml).unwrap();
        assert_eq!(select_webhook(&cfg.entries[0]), None);
    }

    /// フィクスチャのASを1件だけチェックして結果を得る (1件なので AS間休止は発生しない)。
    async fn demo_result(asn: u32, name: &str) -> AsCheckResult {
        let cfg = Config {
            interval: 21600,
            limit: 50,
            entries: vec![AsEntry {
                asn,
                name: name.to_string(),
                webhook: None,
            }],
        };
        check_all(&cfg, true).await.remove(0)
    }

    #[tokio::test]
    async fn compact_summary_line_unhealthy_fixture() {
        // AS64500 (不健全): スコア28点・グレードE・FAIL 3件 / WARN 5件
        let r = demo_result(64500, "本番AS").await;
        assert_eq!(
            compact_summary_line(&r),
            "  本番AS         AS64500    スコア  28点 グレードE  (FAIL 3件 / WARN 5件)"
        );
    }

    #[tokio::test]
    async fn compact_summary_line_healthy_fixture() {
        // AS64501 (健全): スコアは3桁で右寄せ、FAIL/WARN は0件
        let r = demo_result(64501, "検証AS").await;
        assert_eq!(
            compact_summary_line(&r),
            "  検証AS         AS64501    スコア 100点 グレードA  (FAIL 0件 / WARN 0件)"
        );
    }

    #[tokio::test]
    async fn compact_summary_line_counts_only_fail_and_warn() {
        // INFO は FAIL/WARN どちらにも数えない
        let mut r = demo_result(64500, "x").await;
        let sev_count = |r: &AsCheckResult, s: checks::Severity| {
            r.report.findings.iter().filter(|f| f.severity == s).count()
        };
        assert!(sev_count(&r, checks::Severity::Fail) > 0);
        r.report
            .findings
            .retain(|f| f.severity == checks::Severity::Info);
        let line = compact_summary_line(&r);
        assert!(line.ends_with("(FAIL 0件 / WARN 0件)"), "{line}");
    }

    #[tokio::test]
    async fn compact_summary_line_padding_and_overflow() {
        let mut r = demo_result(64500, "ab").await;
        // 名前は文字数で12桁左寄せ、ASNは8桁左寄せ、スコアは3桁右寄せ
        r.report.score = 5;
        r.report.grade = 'F';
        assert_eq!(
            compact_summary_line(&r),
            "  ab           AS64500    スコア   5点 グレードF  (FAIL 3件 / WARN 5件)"
        );
        // 12文字を超える名前・8桁を超えるASNは切り詰めずそのまま出る (列がずれる)
        r.entry.name = "とても長い名前のラベルです".to_string(); // 13文字
        r.entry.asn = 4_200_000_000;
        let line = compact_summary_line(&r);
        assert!(
            line.starts_with("  とても長い名前のラベルです AS4200000000 スコア"),
            "{line}"
        );
    }

    #[test]
    fn cycle_summary_line_format() {
        assert_eq!(
            cycle_summary_line(2, 1),
            "ashealth watch --config: 2件のASをチェック — 変化 1件"
        );
        // 0件でも省略されず、桁の埋めもない
        assert_eq!(
            cycle_summary_line(0, 0),
            "ashealth watch --config: 0件のASをチェック — 変化 0件"
        );
        assert_eq!(
            cycle_summary_line(120, 15),
            "ashealth watch --config: 120件のASをチェック — 変化 15件"
        );
    }

    #[test]
    fn select_webhook_per_as_wins_even_without_defaults() {
        // defaults 無し・AS個別のみ設定
        let toml = r#"
[[as]]
asn = 64500
webhook = "https://example.com/only-per-as"

[[as]]
asn = 64501
"#;
        let cfg = config::parse(toml).unwrap();
        assert_eq!(
            select_webhook(&cfg.entries[0]),
            Some("https://example.com/only-per-as")
        );
        assert_eq!(select_webhook(&cfg.entries[1]), None);
    }

    #[test]
    fn select_webhook_defaults_only_applies_to_all() {
        let toml = r#"
[defaults]
webhook = "https://example.com/default"

[[as]]
asn = 64500

[[as]]
asn = 64501
"#;
        let cfg = config::parse(toml).unwrap();
        for e in &cfg.entries {
            assert_eq!(select_webhook(e), Some("https://example.com/default"));
        }
    }

    #[test]
    fn select_webhook_does_not_fall_back_itself() {
        // select_webhook は entry.webhook を返すだけで defaults を参照しない
        // (継承は config::parse の段階で済んでいる)。手組みの AsEntry では None のまま。
        let e = AsEntry {
            asn: 64500,
            name: "x".to_string(),
            webhook: None,
        };
        assert_eq!(select_webhook(&e), None);
        let e = AsEntry {
            webhook: Some("https://example.com/h".to_string()),
            ..e
        };
        assert_eq!(select_webhook(&e), Some("https://example.com/h"));
    }

    #[test]
    fn select_webhook_empty_string_is_returned_as_is() {
        // 空文字の webhook は未設定扱いにならず Some("") のまま (per-AS が defaults を上書きする)
        let toml = r#"
[defaults]
webhook = "https://example.com/default"

[[as]]
asn = 64500
webhook = ""
"#;
        let cfg = config::parse(toml).unwrap();
        assert_eq!(select_webhook(&cfg.entries[0]), Some(""));
    }

    #[test]
    fn to_json_array_empty_is_empty_array() {
        let v = to_json_array(&[]);
        assert_eq!(v, serde_json::json!([]));
        assert_eq!(v.to_string(), "[]");
    }

    #[tokio::test]
    async fn to_json_array_shape_and_label() {
        let results = vec![
            demo_result(64500, "本番AS").await,
            demo_result(64501, "検証AS").await,
        ];
        let v = to_json_array(&results);
        let arr = v.as_array().expect("配列であること");
        // 入力順のまま (ソートしない)、1AS1要素
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["asn"], 64500);
        assert_eq!(arr[0]["label"], "本番AS");
        assert_eq!(arr[0]["score"], 28);
        assert_eq!(arr[0]["grade"], "E");
        assert_eq!(arr[1]["asn"], 64501);
        assert_eq!(arr[1]["label"], "検証AS");
        assert_eq!(arr[1]["score"], 100);
        // 各要素は単体 Report の JSON + label キー
        for (el, r) in arr.iter().zip(&results) {
            let mut expected = serde_json::json!(r.report);
            expected["label"] = serde_json::json!(r.entry.name);
            assert_eq!(el, &expected);
            let obj = el.as_object().unwrap();
            for k in ["asn", "score", "grade", "findings", "coverage", "label"] {
                assert!(obj.contains_key(k), "キー {k} がない");
            }
            assert!(el["findings"].is_array());
        }
    }

    #[tokio::test]
    async fn config_driven_watch_cycle_notifies_once_then_silent() {
        let toml = r#"
[[as]]
asn = 64500
name = "本番AS"

[[as]]
asn = 64501
name = "検証AS"
"#;
        let cfg = config::parse(toml).unwrap();
        let tmp = std::env::temp_dir().join(format!("ashealth-multi-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        // 1回目: 状態ファイルが存在しないため両AS初回チェック。
        // AS64500は所見ありなので diff が非空 = changed、AS64501は健全 (所見なし) = not changed。
        let (checked1, changed1) = watch_cycle(&cfg, true, Some(&tmp)).await;
        assert_eq!(checked1, 2);
        assert_eq!(changed1, 1);

        // 2回目: 状態が同一なので両ASとも変化なし。
        let (checked2, changed2) = watch_cycle(&cfg, true, Some(&tmp)).await;
        assert_eq!(checked2, 2);
        assert_eq!(changed2, 0);

        let _ = std::fs::remove_dir_all(&tmp);
    }
}
