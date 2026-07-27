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
