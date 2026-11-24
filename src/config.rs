//! 複数AS管理用の設定ファイル (`~/.config/ashealth/config.toml`)。
//!
//! `[defaults]` に共通値 (interval / webhook / limit) を置き、`[[as]]` で
//! 監視対象の AS を列挙する。優先順位は「AS個別設定 > defaults > 組み込み既定値」。
//! パース・検証はネットワークなしで完結するため純粋関数として単体テストできる。

use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// 組み込み既定値 (defaults セクション省略時、および各値の省略時に使う)。
pub const DEFAULT_INTERVAL: u64 = 21600;
pub const DEFAULT_LIMIT: usize = 50;

/// `config.toml` の生パース結果。
#[derive(Debug, Deserialize)]
struct RawConfig {
    #[serde(default)]
    defaults: RawDefaults,
    #[serde(rename = "as", default)]
    r#as: Vec<RawAsEntry>,
}

#[derive(Debug, Default, Deserialize)]
struct RawDefaults {
    interval: Option<u64>,
    webhook: Option<String>,
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct RawAsEntry {
    asn: u32,
    name: Option<String>,
    webhook: Option<String>,
}

/// 検証・デフォルト適用済みの1AS設定。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsEntry {
    pub asn: u32,
    /// 表示用ラベル (省略時 "AS<asn>")
    pub name: String,
    /// per-AS override (省略時 defaults.webhook を継承、それも無ければ None)
    pub webhook: Option<String>,
}

/// 検証・デフォルト適用済みの設定全体。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub interval: u64,
    pub limit: usize,
    pub entries: Vec<AsEntry>,
}

/// `$XDG_CONFIG_HOME/ashealth/config.toml` (未設定なら `~/.config/ashealth/config.toml`)。
pub fn default_config_path() -> PathBuf {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".config")
        });
    base.join("ashealth").join("config.toml")
}

/// 設定ファイルを読み込み・パース・検証する。
pub fn load(path: &Path) -> Result<Config> {
    let text = std::fs::read_to_string(path).with_context(|| {
        format!(
            "設定ファイルが読み込めません: {} (--config でパスを指定するか、リポジトリの examples/config.example.toml を参考に作成してください)",
            path.display()
        )
    })?;
    parse(&text)
}

/// `--demo` 用にバンドルされたフィクスチャ2AS (AS64500/AS64501) だけを含む
/// インメモリ設定を合成する。ファイルI/Oを一切行わないため、
/// `--config` に実ファイルが存在しない環境でも `check --config --demo` /
/// `report --config --demo` がそのまま動く (README記載のデモコマンドを成立させる)。
pub fn demo_config() -> Config {
    Config {
        interval: DEFAULT_INTERVAL,
        limit: DEFAULT_LIMIT,
        entries: vec![
            AsEntry {
                asn: crate::sources::fixture::DEMO_ASN,
                name: "本番AS".to_string(),
                webhook: None,
            },
            AsEntry {
                asn: crate::sources::fixture::HEALTHY_DEMO_ASN,
                name: "検証AS".to_string(),
                webhook: None,
            },
        ],
    }
}

/// `--config` 指定時の読み込み方針を1箇所にまとめる。
/// `demo == true` かつ設定ファイルが存在しない場合はインメモリのデモ設定 ([`demo_config`]) を使う。
/// ファイルが存在する場合は `--demo` でも尊重してそのまま読み込む (明示的な設定を優先)。
pub fn load_for_demo(path: &Path, demo: bool) -> Result<Config> {
    if demo && !path.exists() {
        return Ok(demo_config());
    }
    load(path)
}

/// TOML文字列から `Config` を組み立てる (純粋関数、単体テスト用に公開)。
pub fn parse(text: &str) -> Result<Config> {
    let raw: RawConfig = toml::from_str(text).context("設定ファイルの形式が不正です (TOML)")?;
    validate(raw)
}

fn validate(raw: RawConfig) -> Result<Config> {
    anyhow::ensure!(
        !raw.r#as.is_empty(),
        "設定ファイルに監視対象AS ([[as]]) が1件もありません"
    );

    let interval = raw.defaults.interval.unwrap_or(DEFAULT_INTERVAL);
    let limit = raw.defaults.limit.unwrap_or(DEFAULT_LIMIT);
    let default_webhook = raw.defaults.webhook.clone();

    let mut seen = BTreeSet::new();
    let mut entries = Vec::with_capacity(raw.r#as.len());
    for e in raw.r#as {
        anyhow::ensure!(
            e.asn != 0,
            "asn は必須です (0は不正な値): [[as]] を確認してください"
        );
        if !seen.insert(e.asn) {
            anyhow::bail!(
                "AS番号が重複しています: AS{} は1度しか指定できません",
                e.asn
            );
        }
        entries.push(AsEntry {
            asn: e.asn,
            name: e.name.unwrap_or_else(|| format!("AS{}", e.asn)),
            webhook: e.webhook.or_else(|| default_webhook.clone()),
        });
    }

    Ok(Config {
        interval,
        limit,
        entries,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_config() {
        let toml = r#"
[defaults]
interval = 3600
webhook = "https://discord.com/api/webhooks/default"
limit = 100

[[as]]
asn = 64500
name = "本番AS"
webhook = "https://discord.com/api/webhooks/prod"

[[as]]
asn = 64501
name = "検証AS"
"#;
        let cfg = parse(toml).unwrap();
        assert_eq!(cfg.interval, 3600);
        assert_eq!(cfg.limit, 100);
        assert_eq!(cfg.entries.len(), 2);
        assert_eq!(cfg.entries[0].asn, 64500);
        assert_eq!(cfg.entries[0].name, "本番AS");
        assert_eq!(
            cfg.entries[0].webhook.as_deref(),
            Some("https://discord.com/api/webhooks/prod")
        );
        assert_eq!(cfg.entries[1].asn, 64501);
        assert_eq!(cfg.entries[1].name, "検証AS");
        // per-AS webhook省略時はdefaultsを継承
        assert_eq!(
            cfg.entries[1].webhook.as_deref(),
            Some("https://discord.com/api/webhooks/default")
        );
    }

    #[test]
    fn parses_minimal_config() {
        let toml = r#"
[[as]]
asn = 64500
"#;
        let cfg = parse(toml).unwrap();
        assert_eq!(cfg.interval, DEFAULT_INTERVAL);
        assert_eq!(cfg.limit, DEFAULT_LIMIT);
        assert_eq!(cfg.entries.len(), 1);
        assert_eq!(cfg.entries[0].name, "AS64500");
        assert_eq!(cfg.entries[0].webhook, None);
    }

    #[test]
    fn per_as_webhook_overrides_defaults() {
        let toml = r#"
[defaults]
webhook = "https://example.com/default"

[[as]]
asn = 64500
webhook = "https://example.com/override"

[[as]]
asn = 64501
"#;
        let cfg = parse(toml).unwrap();
        assert_eq!(
            cfg.entries[0].webhook.as_deref(),
            Some("https://example.com/override")
        );
        assert_eq!(
            cfg.entries[1].webhook.as_deref(),
            Some("https://example.com/default")
        );
    }

    #[test]
    fn duplicate_asn_is_rejected() {
        let toml = r#"
[[as]]
asn = 64500

[[as]]
asn = 64500
"#;
        let err = parse(toml).unwrap_err();
        assert!(err.to_string().contains("重複"), "got: {err}");
    }

    #[test]
    fn empty_as_list_is_rejected() {
        let toml = r#"
[defaults]
interval = 3600
"#;
        let err = parse(toml).unwrap_err();
        assert!(err.to_string().contains("1件もありません"), "got: {err}");
    }

    #[test]
    fn missing_file_gives_clear_japanese_error() {
        let err = load(Path::new("/nonexistent/path/ashealth-config-test.toml")).unwrap_err();
        assert!(err.to_string().contains("読み込めません"), "got: {err}");
    }

    #[test]
    fn invalid_toml_gives_clear_error() {
        let err = parse("this is not valid toml [[[").unwrap_err();
        assert!(err.to_string().contains("形式が不正"), "got: {err}");
    }

    #[test]
    fn bundled_example_config_parses() {
        let text = include_str!("../examples/config.example.toml");
        let cfg = parse(text).unwrap();
        assert_eq!(cfg.entries.len(), 2);
        assert_eq!(cfg.entries[0].asn, 64500);
        assert_eq!(cfg.entries[1].asn, 64501);
    }

    /// P2-5: `demo_config()` はフィクスチャ2AS (64500/64501) をファイルI/Oなしで合成する。
    #[test]
    fn demo_config_contains_both_fixture_asns() {
        let cfg = demo_config();
        assert_eq!(cfg.entries.len(), 2);
        assert_eq!(cfg.entries[0].asn, crate::sources::fixture::DEMO_ASN);
        assert_eq!(
            cfg.entries[1].asn,
            crate::sources::fixture::HEALTHY_DEMO_ASN
        );
        assert_eq!(cfg.interval, DEFAULT_INTERVAL);
        assert_eq!(cfg.limit, DEFAULT_LIMIT);
    }

    /// P2-5: `--config --demo` で設定ファイルが存在しない場合、インメモリのデモ設定にフォールバックする
    /// (README記載の `ashealth check --config --demo` / `report --config --demo` を成立させる)。
    #[test]
    fn load_for_demo_synthesizes_config_when_file_missing() {
        let path = Path::new("/nonexistent/path/ashealth-load-for-demo-test.toml");
        let cfg = load_for_demo(path, true).unwrap();
        assert_eq!(cfg.entries.len(), 2);
        assert_eq!(cfg.entries[0].asn, crate::sources::fixture::DEMO_ASN);
    }

    /// P2-5: ファイルが存在しないのに `demo == false` なら、従来通りエラーになる。
    #[test]
    fn load_for_demo_still_errors_without_demo_flag() {
        let path = Path::new("/nonexistent/path/ashealth-load-for-demo-test2.toml");
        assert!(load_for_demo(path, false).is_err());
    }

    /// P2-5: 実ファイルが存在する場合は `--demo` でも明示的な設定を優先してそのまま読み込む。
    #[test]
    fn load_for_demo_respects_existing_file_even_with_demo_flag() {
        let dir = std::env::temp_dir().join(format!(
            "ashealth-load-for-demo-test-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        std::fs::write(
            &path,
            r#"
[[as]]
asn = 12345
name = "カスタムAS"
"#,
        )
        .unwrap();
        let cfg = load_for_demo(&path, true).unwrap();
        assert_eq!(cfg.entries.len(), 1);
        assert_eq!(cfg.entries[0].asn, 12345);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `[[as]]` に書いた `interval` / `limit` は読み込み時にエラーにならず黙って無視され、
    /// 結果は `[defaults]` (省略時は組み込み既定値) の値になる。README 英日に記載の仕様を固定。
    /// エラーにするかは ashealth#19 の判断待ちのため、挙動を変えたらこのテストを見直す。
    #[test]
    fn per_as_interval_and_limit_are_silently_ignored() {
        // [defaults] あり: [[as]] の interval=60 / limit=5 ではなく defaults の 3600 / 20
        let with_defaults = r#"
[defaults]
interval = 3600
limit = 20

[[as]]
asn = 64500
name = "本番AS"
webhook = "https://example.com/prod"
interval = 60
limit = 5
"#;
        let cfg = parse(with_defaults).expect("[[as]] の interval/limit はエラーにならない");
        assert_eq!(cfg.interval, 3600);
        assert_eq!(cfg.limit, 20);
        assert_eq!(cfg.entries.len(), 1);
        assert_eq!(cfg.entries[0].asn, 64500);
        assert_eq!(cfg.entries[0].name, "本番AS");
        assert_eq!(
            cfg.entries[0].webhook.as_deref(),
            Some("https://example.com/prod")
        );

        // [defaults] なし: 組み込み既定値 (DEFAULT_INTERVAL / DEFAULT_LIMIT)
        let without_defaults = r#"
[[as]]
asn = 64501
interval = 60
limit = 5
"#;
        let cfg = parse(without_defaults).expect("[[as]] の interval/limit はエラーにならない");
        assert_eq!(cfg.interval, DEFAULT_INTERVAL);
        assert_eq!(cfg.limit, DEFAULT_LIMIT);
        assert_eq!(cfg.entries[0].asn, 64501);
        assert_eq!(cfg.entries[0].name, "AS64501");
        assert_eq!(cfg.entries[0].webhook, None);
    }

    /// 読めない設定ファイルのエラーは、実在するサンプル (examples/config.example.toml) を案内し、
    /// 存在しないサブコマンド (ashealth config example) を案内しない。
    #[test]
    fn load_error_points_to_example_file() {
        let dir = std::env::temp_dir().join(format!(
            "ashealth-load-error-hint-test-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("missing.toml");
        let err = load(&path).unwrap_err();
        let msg = format!("{:#}", err);
        assert!(msg.contains("examples/config.example.toml"), "{msg}");
        assert!(!msg.contains("ashealth config example"), "{msg}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
