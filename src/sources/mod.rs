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
