//! バンドルされたフィクスチャを返す DataSource 実装 (--demo / 単体テスト用)。
//!
//! フィクスチャは2つの架空AS (ドキュメント用予約AS番号) を用意している:
//!
//! - **AS64500** (`fixtures/as64500/`): 意図的に問題を混ぜた不健全なAS。
//!   - 203.0.113.0/24   : RPKI invalid (ROA の origin が AS64501)
//!   - 198.51.100.0/24  : ROA 未作成 + IRR 未登録
//!   - 2001:db8::/32    : ROA 未作成
//!   - 203.0.113.128/25 : 広報されていないのに IRR route と ROA が残存
//!   - 192.0.2.0/24     : IRR の origin が RADB(AS64500) と ALTDB(AS64501) で不一致
//!   - PeeringDB        : 未登録
//! - **AS64501** (`fixtures/as64501/`): 4情報源がすべて揃った健全なAS
//!   (スコア100・グレードA)。複数AS診断で対比を示すためのフィクスチャ。
//!
//! `FixtureSource` は要求された ASN 用のフィクスチャディレクトリがあればそれを使い、
//! なければ AS64500 のフィクスチャにフォールバックする (--demo は任意の複数ASNを
//! 設定できるが、実際のフィクスチャは64500/64501の2種類のみバンドルしている)。

use super::{ripestat, AsOverview, DataSource, IrrRoute, PeeringDbNet, RpkiStatus, RpkiValidation};
use anyhow::Result;
use serde_json::Value;

/// `--demo` (ASN省略時) の既定AS (不健全なフィクスチャ)。
pub const DEMO_ASN: u32 = 64500;
/// 健全なフィクスチャAS。`serve` の `/api/check/64501` を特別扱いするために使う。
pub const HEALTHY_DEMO_ASN: u32 = 64501;

struct FixtureSet {
    as_overview: &'static str,
    announced: &'static str,
    irr_whois: &'static str,
    peeringdb: &'static str,
    rpki: &'static [(&'static str, &'static str)],
}

const AS64500: FixtureSet = FixtureSet {
    as_overview: include_str!("../../fixtures/as64500/as-overview.json"),
    announced: include_str!("../../fixtures/as64500/announced-prefixes.json"),
    irr_whois: include_str!("../../fixtures/as64500/irr-whois.txt"),
    peeringdb: include_str!("../../fixtures/as64500/peeringdb.json"),
    rpki: &[
        (
            "192.0.2.0/24",
            include_str!("../../fixtures/as64500/rpki-192.0.2.0-24.json"),
        ),
        (
            "198.51.100.0/24",
            include_str!("../../fixtures/as64500/rpki-198.51.100.0-24.json"),
        ),
        (
            "203.0.113.0/24",
            include_str!("../../fixtures/as64500/rpki-203.0.113.0-24.json"),
        ),
        (
            "203.0.113.128/25",
            include_str!("../../fixtures/as64500/rpki-203.0.113.128-25.json"),
        ),
        (
            "2001:db8::/32",
            include_str!("../../fixtures/as64500/rpki-2001-db8-32.json"),
        ),
    ],
};

const AS64501: FixtureSet = FixtureSet {
    as_overview: include_str!("../../fixtures/as64501/as-overview.json"),
    announced: include_str!("../../fixtures/as64501/announced-prefixes.json"),
    irr_whois: include_str!("../../fixtures/as64501/irr-whois.txt"),
    peeringdb: include_str!("../../fixtures/as64501/peeringdb.json"),
    rpki: &[
        (
            "198.51.100.0/24",
            include_str!("../../fixtures/as64501/rpki-198.51.100.0-24.json"),
        ),
        (
            "2001:db8:1::/32",
            include_str!("../../fixtures/as64501/rpki-2001-db8-1-32.json"),
        ),
    ],
};

/// 要求ASN用のフィクスチャがあればそれを、なければ AS64500 を返す。
/// AS64500 のデータをそのまま返す場合でも `as-overview` の resource は要求元 asn として
/// 上書きされる ([`ripestat::parse_as_overview`] に asn を渡すため)。
fn fixture_for(asn: u32) -> &'static FixtureSet {
    match asn {
        64501 => &AS64501,
        _ => &AS64500,
    }
}

#[derive(Default)]
pub struct FixtureSource;

impl FixtureSource {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl DataSource for FixtureSource {
    async fn as_overview(&self, asn: u32) -> Result<AsOverview> {
        let v: Value = serde_json::from_str(fixture_for(asn).as_overview)?;
        Ok(ripestat::parse_as_overview(&v, asn))
    }

    async fn announced_prefixes(&self, asn: u32) -> Result<Vec<String>> {
        let v: Value = serde_json::from_str(fixture_for(asn).announced)?;
        Ok(ripestat::parse_announced_prefixes(&v))
    }

    async fn rpki_validation(&self, asn: u32, prefix: &str) -> Result<RpkiValidation> {
        let prefix = prefix.to_ascii_lowercase();
        for (p, body) in fixture_for(asn).rpki {
            if *p == prefix {
                let v: Value = serde_json::from_str(body)?;
                return Ok(ripestat::parse_rpki_validation(&v));
            }
        }
        Ok(RpkiStatus::NotFound.into())
    }

    async fn irr_routes(&self, asn: u32) -> Result<Vec<IrrRoute>> {
        Ok(super::irr::parse_whois(fixture_for(asn).irr_whois))
    }

    async fn peeringdb_net(&self, asn: u32) -> Result<Option<PeeringDbNet>> {
        let v: Value = serde_json::from_str(fixture_for(asn).peeringdb)?;
        Ok(super::peeringdb::parse_net(&v))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn as64501_fixture_is_healthy() {
        let src = FixtureSource::new();
        let overview = src.as_overview(64501).await.unwrap();
        assert_eq!(overview.asn, 64501);
        assert!(overview.announced);

        let announced = src.announced_prefixes(64501).await.unwrap();
        assert_eq!(announced.len(), 2);

        for p in &announced {
            let v = src.rpki_validation(64501, p).await.unwrap();
            assert_eq!(v.status, RpkiStatus::Valid, "prefix {p} should be valid");
        }

        let irr = src.irr_routes(64501).await.unwrap();
        assert_eq!(irr.len(), 2);

        let pdb = src.peeringdb_net(64501).await.unwrap();
        assert!(pdb.is_some());
    }

    #[tokio::test]
    async fn unknown_asn_falls_back_to_as64500_fixture() {
        let src = FixtureSource::new();
        // AS64502 has no dedicated fixture dir -> falls back to AS64500 data,
        // but as_overview.asn should reflect the requested ASN.
        let overview = src.as_overview(64502).await.unwrap();
        assert_eq!(overview.asn, 64502);
        let announced = src.announced_prefixes(64502).await.unwrap();
        assert_eq!(announced.len(), 4); // same prefixes as AS64500 fixture
    }
}
