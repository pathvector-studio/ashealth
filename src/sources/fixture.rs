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
/// AS64500 のデータを返す場合も、`as_overview` の `asn` は要求元 ASN になる
/// ([`ripestat::parse_as_overview`] はフィクスチャの `data.resource` を読まず、渡した asn をそのまま使うため)。
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
    use crate::sources::Roa;

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

    /// `fixture_for` が返した集合が期待の集合か判定する。
    /// `AS64500` / `AS64501` は `const` なので、参照のアドレスが同一になることは保証されず
    /// `std::ptr::eq` に頼れない。そのため埋め込みフィクスチャの内容で比較する。
    fn is(set: &FixtureSet, expected: &FixtureSet) -> bool {
        set.as_overview == expected.as_overview
            && set.announced == expected.announced
            && set.irr_whois == expected.irr_whois
            && set.peeringdb == expected.peeringdb
            && set.rpki == expected.rpki
    }

    #[test]
    fn as64500_and_as64501_sets_are_distinguishable() {
        // 以降の `is` 判定が意味を持つための前提
        assert!(!is(&AS64500, &AS64501));
    }

    #[test]
    fn fixture_for_selects_dedicated_set_per_asn() {
        assert!(is(fixture_for(64500), &AS64500));
        assert!(is(fixture_for(64501), &AS64501));
        // 既定 ASN 定数とフィクスチャの対応も固定する
        assert!(is(fixture_for(DEMO_ASN), &AS64500));
        assert!(is(fixture_for(HEALTHY_DEMO_ASN), &AS64501));
    }

    #[test]
    fn fixture_for_falls_back_to_as64500_for_unknown_asn() {
        for asn in [65000, 0, 64502, 64499, u32::MAX] {
            assert!(
                is(fixture_for(asn), &AS64500),
                "AS{asn} は AS64500 に落ちる"
            );
        }
    }

    #[test]
    fn demo_constants_match_documented_values() {
        assert_eq!(DEMO_ASN, 64500);
        assert_eq!(HEALTHY_DEMO_ASN, 64501);
    }

    #[tokio::test]
    async fn as64500_overview_and_announced_prefixes() {
        let src = FixtureSource::new();
        let overview = src.as_overview(64500).await.unwrap();
        assert_eq!(overview.asn, 64500);
        assert_eq!(overview.holder, "EXAMPLE-NET Example Internet Services");
        assert!(overview.announced);

        // 203.0.113.128/25 は広報されていない (doc コメントどおり)
        let announced = src.announced_prefixes(64500).await.unwrap();
        assert_eq!(
            announced,
            vec![
                "192.0.2.0/24",
                "198.51.100.0/24",
                "203.0.113.0/24",
                "2001:db8::/32"
            ]
        );
        assert!(!announced.iter().any(|p| p == "203.0.113.128/25"));
    }

    #[tokio::test]
    async fn as64500_rpki_203_0_113_0_24_is_invalid_with_as64501_roa() {
        let src = FixtureSource::new();
        let v = src.rpki_validation(64500, "203.0.113.0/24").await.unwrap();
        assert_eq!(v.status, RpkiStatus::InvalidAsn);
        assert!(v.status.is_invalid());
        // ROA の origin が AS64501 (doc コメントどおり)
        assert_eq!(
            v.roas,
            vec![Roa {
                prefix: "203.0.113.0/24".to_string(),
                origin: 64501,
                max_length: 24,
            }]
        );
    }

    #[tokio::test]
    async fn as64500_rpki_missing_roa_prefixes_are_not_found() {
        let src = FixtureSource::new();
        // 198.51.100.0/24 と 2001:db8::/32 は ROA 未作成
        for p in ["198.51.100.0/24", "2001:db8::/32"] {
            let v = src.rpki_validation(64500, p).await.unwrap();
            assert_eq!(v.status, RpkiStatus::NotFound, "{p}");
            assert!(v.roas.is_empty(), "{p}");
        }
    }

    #[tokio::test]
    async fn as64500_rpki_valid_prefixes_including_unannounced_roa() {
        let src = FixtureSource::new();
        let v = src.rpki_validation(64500, "192.0.2.0/24").await.unwrap();
        assert_eq!(v.status, RpkiStatus::Valid);
        assert_eq!(v.roas.len(), 1);
        assert_eq!(v.roas[0].origin, 64500);
        assert_eq!(v.roas[0].max_length, 24);

        // 広報されていないのに ROA が残存している /25
        let v = src
            .rpki_validation(64500, "203.0.113.128/25")
            .await
            .unwrap();
        assert_eq!(v.status, RpkiStatus::Valid);
        assert_eq!(v.roas.len(), 1);
        assert_eq!(v.roas[0].origin, 64500);
        assert_eq!(v.roas[0].max_length, 25);
    }

    #[tokio::test]
    async fn rpki_lookup_is_case_insensitive_on_prefix() {
        let src = FixtureSource::new();
        // 問い合わせ側のプレフィックスは小文字化されて照合される
        let v = src.rpki_validation(64500, "2001:DB8::/32").await.unwrap();
        assert_eq!(v.status, RpkiStatus::NotFound);
        let v = src.rpki_validation(64501, "2001:DB8:1::/32").await.unwrap();
        assert_eq!(v.status, RpkiStatus::Valid);
    }

    #[tokio::test]
    async fn rpki_prefix_without_fixture_is_not_found_with_no_roas() {
        let src = FixtureSource::new();
        // フィクスチャ未収録のプレフィックス・空文字・前後空白付きはいずれも NotFound (エラーにならない)
        for p in ["10.0.0.0/8", "", " 203.0.113.0/24"] {
            let v = src.rpki_validation(64500, p).await.unwrap();
            assert_eq!(v.status, RpkiStatus::NotFound, "{p:?}");
            assert!(v.roas.is_empty(), "{p:?}");
        }
        // AS64501 のフィクスチャには 203.0.113.0/24 が無い (ASN ごとに別テーブル)
        let v = src.rpki_validation(64501, "203.0.113.0/24").await.unwrap();
        assert_eq!(v.status, RpkiStatus::NotFound);
        assert!(v.roas.is_empty());
    }

    #[tokio::test]
    async fn as64500_irr_has_origin_mismatch_between_radb_and_altdb() {
        let src = FixtureSource::new();
        let irr = src.irr_routes(64500).await.unwrap();
        assert_eq!(irr.len(), 5);

        let for_192: Vec<(u32, &str)> = irr
            .iter()
            .filter(|r| r.prefix == "192.0.2.0/24")
            .map(|r| (r.origin, r.source.as_str()))
            .collect();
        assert_eq!(for_192, vec![(64500, "RADB"), (64501, "ALTDB")]);

        // 198.51.100.0/24 は IRR 未登録
        assert!(!irr.iter().any(|r| r.prefix == "198.51.100.0/24"));
        // 203.0.113.128/25 は広報されていないのに IRR route が残存
        assert!(irr
            .iter()
            .any(|r| r.prefix == "203.0.113.128/25" && r.origin == 64500));
    }

    #[tokio::test]
    async fn as64500_peeringdb_is_unregistered() {
        let src = FixtureSource::new();
        assert!(src.peeringdb_net(64500).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn as64501_details_are_fully_consistent() {
        let src = FixtureSource::new();
        let overview = src.as_overview(64501).await.unwrap();
        assert_eq!(overview.holder, "HEALTHY-NET Example Internet Services");

        let announced = src.announced_prefixes(64501).await.unwrap();
        assert_eq!(announced, vec!["198.51.100.0/24", "2001:db8:1::/32"]);

        // 広報プレフィックスごとに ROA が AS64501 を指す
        for p in &announced {
            let v = src.rpki_validation(64501, p).await.unwrap();
            assert_eq!(v.roas.len(), 1, "{p}");
            assert_eq!(v.roas[0].origin, 64501, "{p}");
        }

        // IRR は全件 RADB・origin AS64501 (不一致なし)
        let irr = src.irr_routes(64501).await.unwrap();
        let got: Vec<(&str, u32, &str)> = irr
            .iter()
            .map(|r| (r.prefix.as_str(), r.origin, r.source.as_str()))
            .collect();
        assert_eq!(
            got,
            vec![
                ("198.51.100.0/24", 64501, "RADB"),
                ("2001:db8:1::/32", 64501, "RADB"),
            ]
        );

        let pdb = src.peeringdb_net(64501).await.unwrap().unwrap();
        assert_eq!(pdb.name, "HEALTHY-NET");
        assert_eq!(pdb.policy, "Open");
        assert_eq!(pdb.website, "https://healthy-net.example");
        assert_eq!(pdb.ix_count, 2);
    }

    #[tokio::test]
    async fn unknown_asn_overview_uses_requested_asn_and_as64500_data() {
        let src = FixtureSource::new();
        // フィクスチャ内の resource（"64500"）は読まれず、asn は要求元 ASN になる。
        // holder / announced は AS64500 のフィクスチャのまま。
        for asn in [65000, 0] {
            let o = src.as_overview(asn).await.unwrap();
            assert_eq!(o.asn, asn);
            assert_eq!(o.holder, "EXAMPLE-NET Example Internet Services");
            assert!(o.announced);
        }
    }

    #[tokio::test]
    async fn unknown_asn_returns_as64500_data_for_every_source() {
        let src = FixtureSource::new();
        let base_prefixes = src.announced_prefixes(64500).await.unwrap();
        let base_irr = src.irr_routes(64500).await.unwrap();
        for asn in [65000, 0] {
            assert_eq!(src.announced_prefixes(asn).await.unwrap(), base_prefixes);

            let v = src.rpki_validation(asn, "203.0.113.0/24").await.unwrap();
            assert_eq!(v.status, RpkiStatus::InvalidAsn, "AS{asn}");

            let irr = src.irr_routes(asn).await.unwrap();
            assert_eq!(irr.len(), base_irr.len());
            assert!(irr.iter().zip(&base_irr).all(|(a, b)| {
                a.prefix == b.prefix && a.origin == b.origin && a.source == b.source
            }));

            assert!(src.peeringdb_net(asn).await.unwrap().is_none());
        }
    }
}
