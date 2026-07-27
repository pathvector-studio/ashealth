//! RIPEstat Data API クライアント。
//! https://stat.ripe.net/docs/02.data-api/
//!
//! パース関数は fixture からも再利用できるよう、fetch と分離してある。

use super::{AsOverview, Roa, RpkiStatus, RpkiValidation};
use anyhow::{Context, Result};
use serde_json::Value;

const BASE: &str = "https://stat.ripe.net/data";
const SOURCEAPP: &str = "sourceapp=ashealth";

async fn get_json(client: &reqwest::Client, url: &str) -> Result<Value> {
    let v = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("RIPEstat への接続に失敗: {url}"))?
        .error_for_status()
        .with_context(|| format!("RIPEstat がエラーを返却: {url}"))?
        .json::<Value>()
        .await
        .context("RIPEstat 応答の JSON パースに失敗")?;
    Ok(v)
}

pub async fn as_overview(client: &reqwest::Client, asn: u32) -> Result<AsOverview> {
    let url = format!("{BASE}/as-overview/data.json?resource=AS{asn}&{SOURCEAPP}");
    let v = get_json(client, &url).await?;
    Ok(parse_as_overview(&v, asn))
}

pub fn parse_as_overview(v: &Value, asn: u32) -> AsOverview {
    let d = &v["data"];
    AsOverview {
        asn,
        holder: d["holder"].as_str().unwrap_or("(不明)").to_string(),
        announced: d["announced"].as_bool().unwrap_or(false),
    }
}

pub async fn announced_prefixes(client: &reqwest::Client, asn: u32) -> Result<Vec<String>> {
    let url = format!("{BASE}/announced-prefixes/data.json?resource=AS{asn}&{SOURCEAPP}");
    let v = get_json(client, &url).await?;
    Ok(parse_announced_prefixes(&v))
}

pub fn parse_announced_prefixes(v: &Value) -> Vec<String> {
    v["data"]["prefixes"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|p| p["prefix"].as_str())
                .map(|s| s.trim().to_ascii_lowercase())
                .collect()
        })
        .unwrap_or_default()
}

pub async fn rpki_validation(
    client: &reqwest::Client,
    asn: u32,
    prefix: &str,
) -> Result<RpkiValidation> {
    let url =
        format!("{BASE}/rpki-validation/data.json?resource=AS{asn}&prefix={prefix}&{SOURCEAPP}");
    let v = get_json(client, &url).await?;
    Ok(parse_rpki_validation(&v))
}

pub fn parse_rpki_validation(v: &Value) -> RpkiValidation {
    let status = match v["data"]["status"].as_str() {
        Some(s) => RpkiStatus::from_api(s),
        None => RpkiStatus::Unknown,
    };
    // カバーする ROA の詳細 (fix サブコマンドが不一致の提示に使う)
    let roas = v["data"]["validating_roas"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|r| {
                    let prefix = r["prefix"].as_str()?.trim().to_ascii_lowercase();
                    let origin = r["origin"]
                        .as_str()?
                        .trim()
                        .trim_start_matches("AS")
                        .trim_start_matches("as")
                        .parse::<u32>()
                        .ok()?;
                    let max_length = r["max_length"].as_u64().filter(|&m| m <= 128)? as u8;
                    Some(Roa {
                        prefix,
                        origin,
                        max_length,
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    RpkiValidation { status, roas }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_announced_prefixes_fixture() {
        let v: Value = serde_json::from_str(include_str!(
            "../../fixtures/as64500/announced-prefixes.json"
        ))
        .unwrap();
        let prefixes = parse_announced_prefixes(&v);
        assert_eq!(prefixes.len(), 4);
        assert!(prefixes.contains(&"2001:db8::/32".to_string()));
    }

    #[test]
    fn parses_rpki_validation_with_covering_roas() {
        let v: Value = serde_json::from_str(include_str!(
            "../../fixtures/as64500/rpki-203.0.113.0-24.json"
        ))
        .unwrap();
        let val = parse_rpki_validation(&v);
        assert_eq!(val.status, RpkiStatus::InvalidAsn);
        assert_eq!(
            val.roas,
            vec![Roa {
                prefix: "203.0.113.0/24".into(),
                origin: 64501,
                max_length: 24,
            }]
        );
    }

    #[test]
    fn parses_rpki_validation_without_roas() {
        let v: Value = serde_json::from_str(include_str!(
            "../../fixtures/as64500/rpki-198.51.100.0-24.json"
        ))
        .unwrap();
        let val = parse_rpki_validation(&v);
        assert_eq!(val.status, RpkiStatus::NotFound);
        assert!(val.roas.is_empty());
    }

    #[test]
    fn maps_rpki_statuses() {
        assert_eq!(RpkiStatus::from_api("valid"), RpkiStatus::Valid);
        assert_eq!(RpkiStatus::from_api("Invalid_ASN"), RpkiStatus::InvalidAsn);
        assert_eq!(
            RpkiStatus::from_api("invalid_length"),
            RpkiStatus::InvalidLength
        );
        assert_eq!(RpkiStatus::from_api("unknown"), RpkiStatus::NotFound);
        assert_eq!(RpkiStatus::from_api("???"), RpkiStatus::Unknown);
    }
}
