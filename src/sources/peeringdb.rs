//! PeeringDB API クライアント。
//! https://www.peeringdb.com/apidocs/

use super::PeeringDbNet;
use anyhow::{Context, Result};
use serde_json::Value;

/// `GET /api/net?asn=<asn>&depth=2` — depth=2 で netixlan_set (IX 接続) が展開される。
pub async fn net(client: &reqwest::Client, asn: u32) -> Result<Option<PeeringDbNet>> {
    let url = format!("https://www.peeringdb.com/api/net?asn={asn}&depth=2");
    let resp = client
        .get(&url)
        .send()
        .await
        .context("PeeringDB への接続に失敗")?;
    // PeeringDB は該当なしを 404 で返すことがある
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    let v: Value = resp
        .error_for_status()
        .context("PeeringDB がエラーを返却")?
        .json()
        .await
        .context("PeeringDB 応答の JSON パースに失敗")?;
    Ok(parse_net(&v))
}

pub fn parse_net(v: &Value) -> Option<PeeringDbNet> {
    let first = v["data"].as_array()?.first()?;
    Some(PeeringDbNet {
        name: first["name"].as_str().unwrap_or("").to_string(),
        policy: first["policy_general"].as_str().unwrap_or("").to_string(),
        website: first["website"].as_str().unwrap_or("").to_string(),
        ix_count: first["netixlan_set"]
            .as_array()
            .map(|a| a.len())
            .unwrap_or(0),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_data_means_no_record() {
        let v: Value =
            serde_json::from_str(include_str!("../../fixtures/as64500/peeringdb.json")).unwrap();
        assert!(parse_net(&v).is_none());
    }

    #[test]
    fn parses_populated_record() {
        let v: Value = serde_json::from_str(
            r#"{"data":[{"name":"Example Net","policy_general":"Open",
                "website":"https://example.net","netixlan_set":[{"id":1},{"id":2}]}]}"#,
        )
        .unwrap();
        let net = parse_net(&v).unwrap();
        assert_eq!(net.name, "Example Net");
        assert_eq!(net.ix_count, 2);
    }
}
