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

    fn parse(json: &str) -> Option<PeeringDbNet> {
        parse_net(&serde_json::from_str::<Value>(json).unwrap())
    }

    /// 全フィールドが空・0 の Some であることを確認する。
    fn assert_all_empty(net: Option<PeeringDbNet>) {
        let net = net.expect("Some のはず");
        assert_eq!(net.name, "");
        assert_eq!(net.policy, "");
        assert_eq!(net.website, "");
        assert_eq!(net.ix_count, 0);
    }

    #[test]
    fn parses_all_fields_of_populated_record() {
        // name / policy / website / ix_count の全フィールドを固定
        let net = parse(
            r#"{"data":[{"name":"Example Net","policy_general":"Selective",
                "website":"https://example.net","netixlan_set":[{"id":1},{"id":2},{"id":3}]}]}"#,
        )
        .unwrap();
        assert_eq!(net.name, "Example Net");
        assert_eq!(net.policy, "Selective");
        assert_eq!(net.website, "https://example.net");
        assert_eq!(net.ix_count, 3);
    }

    #[test]
    fn missing_data_key_is_none() {
        // data キーが無ければ None
        assert!(parse(r#"{}"#).is_none());
        assert!(parse(r#"{"meta":{}}"#).is_none());
    }

    #[test]
    fn non_array_data_is_none() {
        // data が配列でなければ None (オブジェクト・文字列・null・数値)
        assert!(parse(r#"{"data":{"name":"x"}}"#).is_none());
        assert!(parse(r#"{"data":"x"}"#).is_none());
        assert!(parse(r#"{"data":null}"#).is_none());
        assert!(parse(r#"{"data":1}"#).is_none());
    }

    #[test]
    fn inline_empty_data_array_is_none() {
        // 空配列は None (フィクスチャ以外のインライン JSON でも)
        assert!(parse(r#"{"data":[]}"#).is_none());
    }

    #[test]
    fn non_object_top_level_is_none() {
        // トップレベルがオブジェクトでなければ None (パニックしない)
        assert!(parse(r#"[]"#).is_none());
        assert!(parse(r#"[{"name":"x"}]"#).is_none());
        assert!(parse(r#"null"#).is_none());
        assert!(parse(r#""data""#).is_none());
        assert!(parse(r#"1"#).is_none());
    }

    #[test]
    fn empty_object_element_gives_some_with_defaults() {
        // フィールド全欠落の要素は Some で空文字・0
        assert_all_empty(parse(r#"{"data":[{}]}"#));
    }

    #[test]
    fn wrong_typed_fields_fall_back_to_defaults() {
        // 型違いは個別に空文字・0 へフォールバック
        let net = parse(
            r#"{"data":[{"name":123,"policy_general":null,"website":true,
                "netixlan_set":{"id":1}}]}"#,
        )
        .unwrap();
        assert_eq!(net.name, "");
        assert_eq!(net.policy, "");
        assert_eq!(net.website, "");
        assert_eq!(net.ix_count, 0);

        // netixlan_set が文字列でも 0
        let net = parse(r#"{"data":[{"name":"A","netixlan_set":"abc"}]}"#).unwrap();
        assert_eq!(net.name, "A");
        assert_eq!(net.ix_count, 0);

        // 型違いのフィールドがあっても、正しい型のフィールドは拾う
        let net =
            parse(r#"{"data":[{"name":1,"policy_general":"Open","website":["x"]}]}"#).unwrap();
        assert_eq!(net.name, "");
        assert_eq!(net.policy, "Open");
        assert_eq!(net.website, "");
    }

    #[test]
    fn ix_count_is_length_of_netixlan_set_regardless_of_elements() {
        // 空配列は 0
        let net = parse(r#"{"data":[{"netixlan_set":[]}]}"#).unwrap();
        assert_eq!(net.ix_count, 0);
        // 要素の中身 (null・数値・文字列・空オブジェクト) に関わらず len を数える
        let net = parse(r#"{"data":[{"netixlan_set":[null,1,"a",{},[]]}]}"#).unwrap();
        assert_eq!(net.ix_count, 5);
    }

    #[test]
    fn multiple_data_entries_use_only_first() {
        // 複数要素は先頭だけ使い、2 番目以降の値は出ない
        let net = parse(
            r#"{"data":[
                {"name":"First","policy_general":"Open","website":"https://first.example",
                 "netixlan_set":[{"id":1}]},
                {"name":"Second","policy_general":"Closed","website":"https://second.example",
                 "netixlan_set":[{"id":1},{"id":2},{"id":3}]}]}"#,
        )
        .unwrap();
        assert_eq!(net.name, "First");
        assert_eq!(net.policy, "Open");
        assert_eq!(net.website, "https://first.example");
        assert_eq!(net.ix_count, 1);
    }

    #[test]
    fn non_object_first_element_gives_some_with_defaults() {
        // 先頭が非オブジェクトでも Some (全部空・0)。2 番目の有効なオブジェクトは見ない
        assert_all_empty(parse(
            r#"{"data":[1,{"name":"Second","policy_general":"Open","website":"w",
                "netixlan_set":[{"id":1}]}]}"#,
        ));
        assert_all_empty(parse(r#"{"data":[null]}"#));
        assert_all_empty(parse(r#"{"data":["x"]}"#));
        assert_all_empty(parse(r#"{"data":[[]]}"#));
    }
}
