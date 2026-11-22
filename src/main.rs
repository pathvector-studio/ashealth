//! ashealth — AS運用の健康診断ツール。
//!
//! BGP広報 / RPKI ROA / IRR routeオブジェクト / PeeringDB の4情報源を突き合わせ、
//! ズレを検出してスコア付きの健康診断レポートを出力する。

mod checks;
mod config;
mod fix;
mod multi;
mod report;
mod report_cmd;
mod server;
mod sources;
mod watch;

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use sources::{fixture::FixtureSource, DataSource, LiveSource};
use std::sync::Arc;

#[derive(Parser)]
#[command(
    name = "ashealth",
    version,
    about = "AS運用の健康診断 — BGP / RPKI / IRR / PeeringDB の整合性チェック"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// AS番号を指定して健康診断を実行する
    Check {
        /// 対象のAS番号 (例: 64496, AS64496)。--demo 時は省略可 (AS64500)。--config 使用時は指定不要
        asn: Option<String>,
        /// レポートをJSONで出力する
        #[arg(long)]
        json: bool,
        /// バンドルされたフィクスチャ (架空のAS64500) を使いオフラインでデモ実行する
        #[arg(long)]
        demo: bool,
        /// RPKI検証を行う広報プレフィックスの最大数 (ライブAPIの負荷抑制。0は指定不可)
        #[arg(long, default_value_t = 50)]
        limit: usize,
        /// 設定ファイルのパス。指定時は設定内の全ASを順にチェックする (省略時: ~/.config/ashealth/config.toml)
        #[arg(long, num_args = 0..=1, default_missing_value = "")]
        config: Option<String>,
    },
    /// 診断結果から修正オブジェクト (ROAパラメータ / RPSL route) を自動生成する
    Fix {
        /// 対象のAS番号 (例: 64496, AS64496)。--demo 時は省略可 (AS64500)
        asn: Option<String>,
        /// バンドルされたフィクスチャ (架空のAS64500) を使いオフラインでデモ実行する
        #[arg(long)]
        demo: bool,
        /// 出力フォーマット
        #[arg(long, value_enum, default_value_t = FixFormat::Text)]
        format: FixFormat,
        /// RPKI検証を行う広報プレフィックスの最大数 (ライブAPIの負荷抑制。0は指定不可)
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Web UIサーバを起動する
    Serve {
        /// 待ち受けポート
        #[arg(long, default_value_t = 8080)]
        port: u16,
        /// /api/check のIPあたり許可リクエスト数/分 (0で無制限)
        #[arg(long, default_value_t = 10)]
        rate_limit: u32,
        /// 診断結果キャッシュのTTL秒 (0で無効)
        #[arg(long, default_value_t = 600)]
        cache_ttl: u64,
        /// 設定ファイルのパス。指定時はトップページが複数ASダッシュボードになり、
        /// /api/summary が有効になる (省略時: 従来通りの単体AS診断フォーム)
        #[arg(long, num_args = 0..=1, default_missing_value = "")]
        config: Option<String>,
        /// 完全オフラインデモモード。全ASNをバンドルされたフィクスチャ (AS64500) で応答し、
        /// ライブAPIには一切アクセスしない (AS64500/AS64501は常時フィクスチャ応答)
        #[arg(long)]
        demo: bool,
    },
    /// 定期的に再チェックし、前回との差分をWebhookに通知する
    Watch {
        /// 対象のAS番号 (例: 64496)。--demo 時は省略可 (AS64500)。--config 使用時は指定不要
        asn: Option<String>,
        /// チェック間隔 (秒)。既定 21600 = 6時間 (--config 使用時は設定ファイルの値を使用)
        #[arg(long, default_value_t = 21600)]
        interval: u64,
        /// 変化時にJSONをPOSTするWebhook URL (Discord Webhook互換のcontent付き)
        #[arg(long)]
        webhook: Option<String>,
        /// 状態ファイルのパス (既定: $XDG_STATE_HOME/ashealth/asXXXX.json、未設定なら ~/.local/state/ashealth/asXXXX.json。--demo で省略時は ashealth/demo/ 配下)。
        /// --config 使用時はこのディレクトリ配下に asXXXX.json を作る
        #[arg(long)]
        state: Option<std::path::PathBuf>,
        /// 1回だけ比較・通知して終了する (cron / systemd timer 向け)
        #[arg(long)]
        once: bool,
        /// バンドルされたフィクスチャ (架空のAS64500) を使いオフラインで実行する
        #[arg(long)]
        demo: bool,
        /// RPKI検証を行う広報プレフィックスの最大数 (0は指定不可)
        #[arg(long, default_value_t = 50)]
        limit: usize,
        /// 設定ファイルのパス。指定時は設定内の全ASを毎サイクル監視する (省略時: ~/.config/ashealth/config.toml)
        #[arg(long, num_args = 0..=1, default_missing_value = "")]
        config: Option<String>,
    },
    /// 定期サマリレポートを出力する (前回report実行からのスコア推移 + 上位所見)
    Report {
        /// 設定ファイルのパス (省略時: ~/.config/ashealth/config.toml)
        #[arg(long, num_args = 0..=1, default_missing_value = "")]
        config: Option<String>,
        /// レポート完了時にJSONをPOSTするWebhook URL (Discord Webhook互換のcontent付き)
        #[arg(long)]
        webhook: Option<String>,
        /// バンドルされたフィクスチャ (架空のAS64500/AS64501) を使いオフラインでデモ実行する
        #[arg(long)]
        demo: bool,
        /// レポートをJSONで出力する
        #[arg(long)]
        json: bool,
        /// 状態ファイルを置くディレクトリ (既定: $XDG_STATE_HOME/ashealth/、未設定なら ~/.local/state/ashealth/。--demo で省略時は ashealth/demo/ 配下)
        #[arg(long)]
        state: Option<std::path::PathBuf>,
    },
}

/// `fix` の出力フォーマット。
#[derive(Debug, Clone, Copy, ValueEnum)]
enum FixFormat {
    /// 人間向けの日本語レポート (アーティファクトはコードブロック)
    Text,
    /// 貼り付け用RPSLオブジェクトのみ (ファイル/メール本文にリダイレクト可)
    Rpsl,
    /// 構造化JSON [{finding, artifact_type, artifact, submission_hint}]
    Json,
}

/// `--config` の値からパスを解決する。
/// `default_missing_value = ""` により `--config` (値省略) は `Some("")` になるため、
/// 空文字は「既定パスを使う」を意味する。
fn resolve_config_path(config: &Option<String>) -> Option<std::path::PathBuf> {
    config.as_ref().map(|s| {
        if s.is_empty() {
            config::default_config_path()
        } else {
            std::path::PathBuf::from(s)
        }
    })
}

/// "AS64496" / "as64496" / "64496" のいずれも受け付ける。
/// 数値としての形式のみを検証する (予約AS番号かどうかは [`validate_asn`] が別途判定する)。
pub fn parse_asn(s: &str) -> Result<u32> {
    let t = s.trim();
    let t = t
        .strip_prefix("AS")
        .or_else(|| t.strip_prefix("as"))
        .or_else(|| t.strip_prefix("As"))
        .unwrap_or(t);
    t.parse::<u32>()
        .map_err(|_| anyhow::anyhow!("AS番号の形式が不正です: {s}"))
}

/// AS0 (RFC 7607) — 経路のnull origin表現専用。実運用ASとしては存在しえない。
const AS_ZERO: u32 = 0;
/// AS23456 (AS_TRANS, RFC 6793) — 32bit AS番号を16bit経由網に通すためのプレースホルダ。
const AS_TRANS: u32 = 23456;
/// AS65535 (RFC 7300) — 予約。
const AS_16BIT_RESERVED: u32 = 65535;
/// AS4294967295 (RFC 7300) — 予約 (32bit空間の末尾)。
const AS_32BIT_RESERVED: u32 = 4_294_967_295;

/// ライブ診断の対象として意味を持たないASNを拒否する (RFC 7607 / RFC 6793)。
/// ドキュメント用・private-use ASN帯はWARNのみ (フィクスチャ AS64500/AS64501 も
/// この帯に属するため、拒否せず「実運用ASではない」ことを知らせるに留める)。
///
/// 戻り値: `Ok(warnings)` — 拒否理由がなければ空 or 警告メッセージのVec。
/// `Err` — AS0 / AS23456 など、ライブ診断そのものが無意味なASN。
pub fn validate_asn(asn: u32) -> Result<Vec<String>> {
    if asn == AS_ZERO {
        anyhow::bail!(
            "AS0 は実運用のAS番号として使用できません (RFC 7607: 経路のnull origin表現専用の予約番号です)。診断対象のAS番号を確認してください"
        );
    }
    if asn == AS_TRANS {
        anyhow::bail!(
            "AS23456 は実運用のAS番号ではありません (RFC 6793: AS_TRANS — 32bit AS番号を16bit経由網に通すためのプレースホルダ予約番号です)。診断対象のAS番号を確認してください"
        );
    }
    let mut warnings = Vec::new();
    let reason = if (64496..=64511).contains(&asn) {
        Some("RFC 5398 ドキュメント用 (例示) AS番号帯です")
    } else if (64512..=65534).contains(&asn) || asn == AS_16BIT_RESERVED {
        Some("RFC 6996 / RFC 7300 の16bit private-use・予約AS番号帯です")
    } else if (4_200_000_000..=4_294_967_294).contains(&asn) || asn == AS_32BIT_RESERVED {
        Some("RFC 6996 / RFC 7300 の32bit private-use・予約AS番号帯です")
    } else {
        None
    };
    if let Some(reason) = reason {
        warnings.push(format!(
            "AS{asn} は{reason} — インターネット上で広報される実運用ASNではないため、ライブ診断の結果 (特にIRR/RPKI) は意味を持たない可能性があります"
        ));
    }
    Ok(warnings)
}

/// [`validate_asn`] を呼び、AS0/AS23456なら即エラーを返す。予約帯の警告は標準エラーに出力する。
/// `--demo` 実行時は呼ばない (フィクスチャAS64500/64501が予約帯に属するため)。
fn validate_asn_or_warn(asn: u32) -> Result<()> {
    for w in validate_asn(asn)? {
        eprintln!("警告: {w}");
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Check {
            asn,
            json,
            demo,
            limit,
            config: config_arg,
        } => {
            if let Some(path) = resolve_config_path(&config_arg) {
                anyhow::ensure!(
                    asn.is_none(),
                    "AS番号と --config は同時に指定できません (どちらか一方を使ってください)"
                );
                let cfg = config::load_for_demo(&path, demo)?;
                let results = multi::check_all(&cfg, demo).await;
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&multi::to_json_array(&results))?
                    );
                } else {
                    for r in &results {
                        println!("{}", multi::compact_summary_line(r));
                    }
                    multi::render_terminal_table(&results);
                }
                return Ok(());
            }
            let asn = match (&asn, demo) {
                (Some(s), _) => parse_asn(s)?,
                (None, true) => sources::fixture::DEMO_ASN,
                (None, false) => {
                    anyhow::bail!("AS番号を指定してください (例: ashealth check 64496)")
                }
            };
            if !demo {
                validate_asn_or_warn(asn)?;
            }
            let source: Arc<dyn DataSource> = if demo {
                Arc::new(FixtureSource::new())
            } else {
                Arc::new(LiveSource::new()?)
            };
            let input = checks::collect(source, asn, limit).await?;
            let findings = checks::run_checks(&input);
            let rep = report::Report::build(&input, findings);
            if json {
                println!("{}", serde_json::to_string_pretty(&rep)?);
            } else {
                report::render_terminal(&rep);
            }
        }
        Cmd::Fix {
            asn,
            demo,
            format,
            limit,
        } => {
            let asn = match (&asn, demo) {
                (Some(s), _) => parse_asn(s)?,
                (None, true) => sources::fixture::DEMO_ASN,
                (None, false) => {
                    anyhow::bail!("AS番号を指定してください (例: ashealth fix 64496)")
                }
            };
            if !demo {
                validate_asn_or_warn(asn)?;
            }
            let source: Arc<dyn DataSource> = if demo {
                Arc::new(FixtureSource::new())
            } else {
                Arc::new(LiveSource::new()?)
            };
            let input = checks::collect(source, asn, limit).await?;
            let findings = checks::run_checks(&input);
            let rems = fix::remediations(&input, &findings);
            match format {
                FixFormat::Text => print!("{}", fix::render_text(&input, &rems)),
                FixFormat::Rpsl => println!("{}", fix::render_rpsl(&rems)),
                FixFormat::Json => println!("{}", fix::render_json(&rems)?),
            }
        }
        Cmd::Serve {
            port,
            rate_limit,
            cache_ttl,
            config: config_arg,
            demo,
        } => {
            let cfg = match resolve_config_path(&config_arg) {
                Some(path) => Some(config::load_for_demo(&path, demo)?),
                None => None,
            };
            server::serve_with_config(port, rate_limit, cache_ttl, cfg, demo).await?
        }
        Cmd::Watch {
            asn,
            interval,
            webhook,
            state,
            once,
            demo,
            limit,
            config: config_arg,
        } => {
            if let Some(path) = resolve_config_path(&config_arg) {
                anyhow::ensure!(
                    asn.is_none(),
                    "AS番号と --config は同時に指定できません (どちらか一方を使ってください)"
                );
                let cfg = config::load_for_demo(&path, demo)?;
                println!(
                    "ashealth watch --config: {} を {}件のASで監視します (間隔: {}秒{})",
                    path.display(),
                    cfg.entries.len(),
                    cfg.interval,
                    if once { ", --once" } else { "" }
                );
                loop {
                    let (checked, changed) = multi::watch_cycle(&cfg, demo, state.as_ref()).await;
                    println!("{}", multi::cycle_summary_line(checked, changed));
                    if once {
                        return Ok(());
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(cfg.interval)).await;
                }
            }
            let asn = match (&asn, demo) {
                (Some(s), _) => parse_asn(s)?,
                (None, true) => sources::fixture::DEMO_ASN,
                (None, false) => {
                    anyhow::bail!("AS番号を指定してください (例: ashealth watch 64496 --once)")
                }
            };
            if !demo {
                validate_asn_or_warn(asn)?;
            }
            watch::run(asn, demo, limit, interval, webhook, state, once).await?;
        }
        Cmd::Report {
            config: config_arg,
            webhook,
            demo,
            json,
            state,
        } => {
            let path = resolve_config_path(&config_arg).ok_or_else(|| {
                anyhow::anyhow!(
                    "report は --config が必須です (例: ashealth report --config、または ashealth report --config <path>)"
                )
            })?;
            let cfg = config::load_for_demo(&path, demo)?;
            let report = report_cmd::run_all(&cfg, demo, state.as_ref()).await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print!("{}", report_cmd::render_text(&report));
            }
            if let Some(url) = &webhook {
                match report_cmd::post_webhook(url, &report).await {
                    Ok(()) => println!("  → Webhook通知を送信しました"),
                    Err(e) => eprintln!("report: Webhook通知に失敗しました: {e:#}"),
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_asn_accepts_various_forms() {
        assert_eq!(parse_asn("64496").unwrap(), 64496);
        assert_eq!(parse_asn("AS64496").unwrap(), 64496);
        assert_eq!(parse_asn("as64496").unwrap(), 64496);
        assert_eq!(parse_asn("As64496").unwrap(), 64496);
        assert_eq!(parse_asn(" 64496 ").unwrap(), 64496);
    }

    #[test]
    fn parse_asn_rejects_garbage() {
        assert!(parse_asn("not-an-asn").is_err());
        assert!(parse_asn("").is_err());
    }

    /// P0-1: AS0 (RFC 7607) — 実運用ASとして存在しえない。ライブ診断は無意味なので拒否する。
    #[test]
    fn validate_asn_rejects_as_zero() {
        let err = validate_asn(0).unwrap_err();
        assert!(err.to_string().contains("AS0"), "got: {err}");
        assert!(err.to_string().contains("RFC 7607"), "got: {err}");
    }

    /// P0-1: AS23456 (AS_TRANS, RFC 6793) — 32bit→16bit変換用のプレースホルダ。拒否する。
    #[test]
    fn validate_asn_rejects_as_trans() {
        let err = validate_asn(23456).unwrap_err();
        assert!(err.to_string().contains("23456"), "got: {err}");
        assert!(err.to_string().contains("RFC 6793"), "got: {err}");
    }

    /// P0-1: RFC 5398 ドキュメント用AS帯 (64496-64511) は拒否ではなく警告に留める
    /// (フィクスチャ AS64500 もこの帯に属するため)。
    #[test]
    fn validate_asn_warns_on_documentation_range() {
        let warnings = validate_asn(64500).unwrap();
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("AS64500"), "got: {warnings:?}");
        assert!(warnings[0].contains("RFC 5398"), "got: {warnings:?}");
    }

    /// P0-1: 16bit private-use/予約帯 (64512-65534, 65535)。
    #[test]
    fn validate_asn_warns_on_16bit_private_and_reserved() {
        assert_eq!(validate_asn(64512).unwrap().len(), 1);
        assert_eq!(validate_asn(65534).unwrap().len(), 1);
        assert_eq!(validate_asn(65535).unwrap().len(), 1);
    }

    /// P0-1: 32bit private-use/予約帯 (4200000000-4294967294, 4294967295)。
    #[test]
    fn validate_asn_warns_on_32bit_private_and_reserved() {
        assert_eq!(validate_asn(4_200_000_000).unwrap().len(), 1);
        assert_eq!(validate_asn(4_294_967_294).unwrap().len(), 1);
        assert_eq!(validate_asn(4_294_967_295).unwrap().len(), 1);
    }

    /// P0-1: 実運用範囲のASNは警告なしで通す。
    #[test]
    fn validate_asn_accepts_normal_asn_without_warnings() {
        assert!(validate_asn(4713).unwrap().is_empty());
        assert!(validate_asn(13335).unwrap().is_empty());
    }

    /// 各帯の境界値を固定する。実装の判定範囲は 64496-64511 / 64512-65535 /
    /// 4200000000-4294967295 のみで、32bitのドキュメント用帯 (65536-65551, RFC 5398) は
    /// 現状どの帯にも含まれず警告なしで通る (挙動の記録であり、仕様としての推奨ではない)。
    #[test]
    fn validate_asn_boundary_values() {
        // 警告なし: 最小値、ドキュメント帯の直前、実運用ASN。
        for asn in [1, 64495, 13335] {
            assert!(validate_asn(asn).unwrap().is_empty(), "AS{asn}");
        }
        // 警告あり (ちょうど1件): 各帯の端。
        for asn in [
            64496,
            64511,
            64512,
            65534,
            65535,
            4_200_000_000,
            4_294_967_294,
            4_294_967_295,
        ] {
            assert_eq!(validate_asn(asn).unwrap().len(), 1, "AS{asn}");
        }
        // 32bit private-use 帯の直前は警告なし。
        assert!(validate_asn(4_199_999_999).unwrap().is_empty());
        // 32bit ドキュメント帯 (65536-65551) は現状警告なし。
        for asn in [65536, 65551] {
            assert!(validate_asn(asn).unwrap().is_empty(), "AS{asn}");
        }
    }

    #[test]
    fn validate_asn_or_warn_errors_only_on_as_zero_and_as_trans() {
        assert!(validate_asn_or_warn(0).is_err());
        assert!(validate_asn_or_warn(23456).is_err());
        // 予約帯は警告のみ(標準エラー出力)で Ok を返す。
        assert!(validate_asn_or_warn(64500).is_ok());
        assert!(validate_asn_or_warn(64510).is_ok());
    }
}
