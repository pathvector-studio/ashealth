//! データソース層。
//!
//! `DataSource` トレイトが 4 つの情報源 (BGP 広報 / RPKI / IRR / PeeringDB) への
//! アクセスを抽象化する。実装は 2 つ:
//! - [`LiveSource`]   : 実際の公開 API (RIPEstat, PeeringDB, whois.radb.net) を叩く
//! - [`fixture::FixtureSource`] : バンドルされたフィクスチャを返す (--demo / 単体テスト用)

pub mod fixture;
pub mod irr;
pub mod peeringdb;
pub mod ripestat;

use anyhow::Result;
use serde::Serialize;
use std::time::Duration;

/// as-overview の要約。
#[derive(Debug, Clone, Serialize)]
pub struct AsOverview {
    pub asn: u32,
    pub holder: String,
    pub announced: bool,
}

/// RPKI 検証結果 (RIPEstat rpki-validation の status に対応)。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RpkiStatus {
    /// 有効な ROA に一致
    Valid,
    /// ROA はあるが origin AS が不一致
    InvalidAsn,
    /// ROA はあるが prefix 長が maxLength を超過
    InvalidLength,
    /// カバーする ROA が存在しない (RIPEstat では "unknown")
    NotFound,
    /// 判定不能 (API エラー等)
    Unknown,
}

/// RPKI 検証で見つかったカバー ROA (RIPEstat rpki-validation の validating_roas 要素)。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Roa {
    pub prefix: String,
    pub origin: u32,
    pub max_length: u8,
}

/// RPKI 検証の結果一式 (ステータス + カバー ROA 群)。
/// `fix` サブコマンドが ROA と広報の不一致を具体的に提示するために ROA 詳細を保持する。
#[derive(Debug, Clone, Serialize)]
pub struct RpkiValidation {
    pub status: RpkiStatus,
    pub roas: Vec<Roa>,
}

impl From<RpkiStatus> for RpkiValidation {
    fn from(status: RpkiStatus) -> Self {
        Self {
            status,
            roas: Vec::new(),
        }
    }
}

impl RpkiStatus {
    pub fn from_api(s: &str) -> Self {
        let s = s.trim().to_ascii_lowercase();
        match s.as_str() {
            "valid" => RpkiStatus::Valid,
            "invalid_asn" | "invalid asn" => RpkiStatus::InvalidAsn,
            "invalid_length" | "invalid length" => RpkiStatus::InvalidLength,
            "unknown" | "not-found" | "not_found" | "none" => RpkiStatus::NotFound,
            other if other.starts_with("invalid") => RpkiStatus::InvalidAsn,
            _ => RpkiStatus::Unknown,
        }
    }

    pub fn is_invalid(&self) -> bool {
        matches!(self, RpkiStatus::InvalidAsn | RpkiStatus::InvalidLength)
    }

    pub fn label(&self) -> &'static str {
        match self {
            RpkiStatus::Valid => "valid",
            RpkiStatus::InvalidAsn => "invalid_asn",
            RpkiStatus::InvalidLength => "invalid_length",
            RpkiStatus::NotFound => "not_found",
            RpkiStatus::Unknown => "unknown",
        }
    }
}

/// IRR の route / route6 オブジェクト。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IrrRoute {
    pub prefix: String,
    pub origin: u32,
    /// 登録元 IRR データベース (RADB, RIPE, ALTDB, JPIRR, ...)
    pub source: String,
}

/// PeeringDB の net レコード要約。
#[derive(Debug, Clone, Serialize)]
pub struct PeeringDbNet {
    pub name: String,
    pub policy: String,
    pub website: String,
    pub ix_count: usize,
}

/// 4 情報源へのアクセスを抽象化するトレイト。
#[async_trait::async_trait]
pub trait DataSource: Send + Sync {
    async fn as_overview(&self, asn: u32) -> Result<AsOverview>;
    async fn announced_prefixes(&self, asn: u32) -> Result<Vec<String>>;
    async fn rpki_validation(&self, asn: u32, prefix: &str) -> Result<RpkiValidation>;
    async fn irr_routes(&self, asn: u32) -> Result<Vec<IrrRoute>>;
    async fn peeringdb_net(&self, asn: u32) -> Result<Option<PeeringDbNet>>;
}

/// 実 API を叩く実装。
pub struct LiveSource {
    client: reqwest::Client,
}

impl LiveSource {
    pub fn new() -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .user_agent(concat!("ashealth/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self { client })
    }
}

#[async_trait::async_trait]
impl DataSource for LiveSource {
    async fn as_overview(&self, asn: u32) -> Result<AsOverview> {
        ripestat::as_overview(&self.client, asn).await
    }

    async fn announced_prefixes(&self, asn: u32) -> Result<Vec<String>> {
        ripestat::announced_prefixes(&self.client, asn).await
    }

    async fn rpki_validation(&self, asn: u32, prefix: &str) -> Result<RpkiValidation> {
        ripestat::rpki_validation(&self.client, asn, prefix).await
    }

    async fn irr_routes(&self, asn: u32) -> Result<Vec<IrrRoute>> {
        irr::routes(asn).await
    }

    async fn peeringdb_net(&self, asn: u32) -> Result<Option<PeeringDbNet>> {
        peeringdb::net(&self.client, asn).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 全変種 (label との対応確認用)。
    const ALL: [RpkiStatus; 5] = [
        RpkiStatus::Valid,
        RpkiStatus::InvalidAsn,
        RpkiStatus::InvalidLength,
        RpkiStatus::NotFound,
        RpkiStatus::Unknown,
    ];

    #[test]
    fn from_api_known_strings() {
        // 既知の文字列を固定
        assert_eq!(RpkiStatus::from_api("valid"), RpkiStatus::Valid);
        assert_eq!(RpkiStatus::from_api("invalid_asn"), RpkiStatus::InvalidAsn);
        assert_eq!(RpkiStatus::from_api("invalid asn"), RpkiStatus::InvalidAsn);
        assert_eq!(
            RpkiStatus::from_api("invalid_length"),
            RpkiStatus::InvalidLength
        );
        assert_eq!(
            RpkiStatus::from_api("invalid length"),
            RpkiStatus::InvalidLength
        );
        // RIPEstat では「カバーする ROA なし」が "unknown" で返る
        assert_eq!(RpkiStatus::from_api("unknown"), RpkiStatus::NotFound);
        assert_eq!(RpkiStatus::from_api("not-found"), RpkiStatus::NotFound);
        assert_eq!(RpkiStatus::from_api("not_found"), RpkiStatus::NotFound);
        assert_eq!(RpkiStatus::from_api("none"), RpkiStatus::NotFound);
    }

    #[test]
    fn from_api_ignores_whitespace_and_case() {
        // 前後空白と大文字小文字は無視
        assert_eq!(RpkiStatus::from_api("  VALID "), RpkiStatus::Valid);
        assert_eq!(
            RpkiStatus::from_api("Invalid_Length"),
            RpkiStatus::InvalidLength
        );
        assert_eq!(
            RpkiStatus::from_api("\tINVALID ASN\n"),
            RpkiStatus::InvalidAsn
        );
        assert_eq!(RpkiStatus::from_api(" Not-Found "), RpkiStatus::NotFound);
    }

    #[test]
    fn from_api_unknown_invalid_prefix_is_invalid_asn() {
        // 現挙動を固定: "invalid" で始まる未知の文字列は InvalidAsn に倒れる
        // (良し悪しの判断はしない)
        assert_eq!(RpkiStatus::from_api("invalid"), RpkiStatus::InvalidAsn);
        assert_eq!(RpkiStatus::from_api("invalid_foo"), RpkiStatus::InvalidAsn);
        assert_eq!(
            RpkiStatus::from_api("  INVALID_Foo "),
            RpkiStatus::InvalidAsn
        );
    }

    #[test]
    fn from_api_other_unknown_strings_are_unknown() {
        assert_eq!(RpkiStatus::from_api(""), RpkiStatus::Unknown);
        assert_eq!(RpkiStatus::from_api("   "), RpkiStatus::Unknown);
        assert_eq!(RpkiStatus::from_api("garbage"), RpkiStatus::Unknown);
        // "valid" の前方一致は拾わない
        assert_eq!(RpkiStatus::from_api("validish"), RpkiStatus::Unknown);
    }

    #[test]
    fn is_invalid_only_for_invalid_variants() {
        assert!(RpkiStatus::InvalidAsn.is_invalid());
        assert!(RpkiStatus::InvalidLength.is_invalid());
        assert!(!RpkiStatus::Valid.is_invalid());
        assert!(!RpkiStatus::NotFound.is_invalid());
        assert!(!RpkiStatus::Unknown.is_invalid());
    }

    #[test]
    fn label_all_variants() {
        assert_eq!(RpkiStatus::Valid.label(), "valid");
        assert_eq!(RpkiStatus::InvalidAsn.label(), "invalid_asn");
        assert_eq!(RpkiStatus::InvalidLength.label(), "invalid_length");
        assert_eq!(RpkiStatus::NotFound.label(), "not_found");
        assert_eq!(RpkiStatus::Unknown.label(), "unknown");
    }

    #[test]
    fn label_matches_serde_serialization() {
        // JSON 出力 (serde の snake_case) と label() は全変種で一致する
        for s in ALL {
            assert_eq!(
                serde_json::to_string(&s).unwrap(),
                format!("\"{}\"", s.label()),
                "{s:?}"
            );
        }
    }

    #[test]
    fn label_from_api_roundtrip() {
        // Unknown 以外は label → from_api で元に戻る
        for s in ALL.into_iter().filter(|s| *s != RpkiStatus::Unknown) {
            assert_eq!(RpkiStatus::from_api(s.label()), s, "{s:?}");
        }
        // 現挙動を固定: Unknown の label "unknown" は from_api では NotFound になる
        assert_eq!(
            RpkiStatus::from_api(RpkiStatus::Unknown.label()),
            RpkiStatus::NotFound
        );
    }

    #[test]
    fn rpki_validation_from_status_keeps_status_and_has_no_roas() {
        for s in ALL {
            let v: RpkiValidation = s.into();
            assert_eq!(v.status, s);
            assert!(v.roas.is_empty());
        }
    }
}
