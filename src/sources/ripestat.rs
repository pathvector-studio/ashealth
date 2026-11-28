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

    fn overview(json: &str) -> AsOverview {
        parse_as_overview(&serde_json::from_str::<Value>(json).unwrap(), 64500)
    }

    fn prefixes(json: &str) -> Vec<String> {
        parse_announced_prefixes(&serde_json::from_str::<Value>(json).unwrap())
    }

    fn rpki(json: &str) -> RpkiValidation {
        parse_rpki_validation(&serde_json::from_str::<Value>(json).unwrap())
    }

    /// validating_roas を 1 要素だけ持つ JSON を作り、パース結果の ROA 群を返す。
    fn roas_of(roa: &str) -> Vec<Roa> {
        rpki(&format!(
            r#"{{"data":{{"status":"invalid_asn","validating_roas":[{roa}]}}}}"#
        ))
        .roas
    }

    /// origin だけを変えた ROA (prefix 10.0.0.0/8, max_length 8) のパース結果。
    fn roas_with_origin(origin_json: &str) -> Vec<Roa> {
        roas_of(&format!(
            r#"{{"prefix":"10.0.0.0/8","origin":{origin_json},"max_length":8}}"#
        ))
    }

    /// max_length だけを変えた ROA (origin "AS64501") のパース結果。
    fn roas_with_max_length(max_length_json: &str) -> Vec<Roa> {
        roas_of(&format!(
            r#"{{"prefix":"2001:db8::/32","origin":"AS64501","max_length":{max_length_json}}}"#
        ))
    }

    #[test]
    fn as_overview_parses_holder_and_announced() {
        let o = overview(r#"{"data":{"holder":"EXAMPLE-AS - Example Inc.","announced":true}}"#);
        assert_eq!(o.asn, 64500);
        assert_eq!(o.holder, "EXAMPLE-AS - Example Inc.");
        assert!(o.announced);
    }

    #[test]
    fn as_overview_missing_data_falls_back_to_defaults() {
        // 現状の挙動: data 欠落・null・非オブジェクトでも panic せず (不明) / false になる
        for json in [
            r#"{}"#,
            r#"{"data":null}"#,
            r#"{"data":"x"}"#,
            r#"{"data":[]}"#,
            r#"{"data":1}"#,
            r#"[]"#,
            r#"null"#,
        ] {
            let o = overview(json);
            assert_eq!(o.asn, 64500, "{json}");
            assert_eq!(o.holder, "(不明)", "{json}");
            assert!(!o.announced, "{json}");
        }
    }

    #[test]
    fn as_overview_missing_or_non_string_holder_is_unknown() {
        // holder 欠落・null・数値・配列は (不明)。announced は独立して読まれる
        for json in [
            r#"{"data":{"announced":true}}"#,
            r#"{"data":{"holder":null,"announced":true}}"#,
            r#"{"data":{"holder":123,"announced":true}}"#,
            r#"{"data":{"holder":["x"],"announced":true}}"#,
        ] {
            let o = overview(json);
            assert_eq!(o.holder, "(不明)", "{json}");
            assert!(o.announced, "{json}");
        }
    }

    #[test]
    fn as_overview_empty_holder_is_kept_as_is() {
        // 現状の挙動: 空文字・空白のみの holder は (不明) にならず、trim もされない
        assert_eq!(overview(r#"{"data":{"holder":""}}"#).holder, "");
        assert_eq!(overview(r#"{"data":{"holder":"  X  "}}"#).holder, "  X  ");
    }

    #[test]
    fn as_overview_non_bool_announced_is_false() {
        // 現状の挙動: announced が bool 以外 (文字列 "true"・数値 1・null) だと黙って false
        for json in [
            r#"{"data":{"holder":"X","announced":"true"}}"#,
            r#"{"data":{"holder":"X","announced":1}}"#,
            r#"{"data":{"holder":"X","announced":null}}"#,
            r#"{"data":{"holder":"X"}}"#,
        ] {
            let o = overview(json);
            assert!(!o.announced, "{json}");
            assert_eq!(o.holder, "X", "{json}");
        }
        assert!(!overview(r#"{"data":{"announced":false}}"#).announced);
    }

    #[test]
    fn announced_prefixes_missing_or_non_array_is_empty() {
        for json in [
            r#"{}"#,
            r#"{"data":null}"#,
            r#"{"data":{}}"#,
            r#"{"data":{"prefixes":null}}"#,
            r#"{"data":{"prefixes":"10.0.0.0/8"}}"#,
            r#"{"data":{"prefixes":{"prefix":"10.0.0.0/8"}}}"#,
            r#"{"data":{"prefixes":[]}}"#,
            r#"[]"#,
        ] {
            assert!(prefixes(json).is_empty(), "{json}");
        }
    }

    #[test]
    fn announced_prefixes_trims_and_lowercases() {
        // 前後空白 (空白・タブ・改行) の除去と ASCII 小文字化は行われる
        let p = prefixes(
            r#"{"data":{"prefixes":[
                {"prefix":"  2001:DB8::/32 "},
                {"prefix":"\t10.0.0.0/8\n"},
                {"prefix":"2001:DB8:ABCD::/48"}
            ]}}"#,
        );
        assert_eq!(p, vec!["2001:db8::/32", "10.0.0.0/8", "2001:db8:abcd::/48"]);
    }

    #[test]
    fn announced_prefixes_does_not_validate_or_canonicalize() {
        // 現状の挙動: trim + 小文字化のみ。構文検証・重複排除・IPv6 の圧縮表記への正規化・
        // 内部空白の除去はしない。不正な文字列や空文字もそのまま通る
        let p = prefixes(
            r#"{"data":{"prefixes":[
                {"prefix":"not-a-prefix"},
                {"prefix":""},
                {"prefix":"   "},
                {"prefix":"2001:DB8:0:0::/32"},
                {"prefix":"10.0.0.0/8"},
                {"prefix":"10.0.0.0/8"},
                {"prefix":"10.0. 0.0/8"}
            ]}}"#,
        );
        assert_eq!(
            p,
            vec![
                "not-a-prefix",
                "",
                "",
                "2001:db8:0:0::/32",
                "10.0.0.0/8",
                "10.0.0.0/8",
                "10.0. 0.0/8",
            ]
        );
    }

    #[test]
    fn announced_prefixes_skips_elements_without_string_prefix() {
        // prefix が欠落・非文字列の要素は黙って読み飛ばされ、順序は保たれる
        let p = prefixes(
            r#"{"data":{"prefixes":[
                {"prefix":"10.0.0.0/8"},
                {"prefix":null},
                {"prefix":123},
                {"prefix":["1.0.0.0/8"]},
                {"other":"x"},
                "192.0.2.0/24",
                null,
                {"prefix":"192.0.2.0/24","timelines":[]}
            ]}}"#,
        );
        assert_eq!(p, vec!["10.0.0.0/8", "192.0.2.0/24"]);
    }

    #[test]
    fn rpki_validation_missing_data_is_unknown_without_roas() {
        // 現状の挙動: data 欠落・非オブジェクトでも panic せず Unknown + ROA なし
        for json in [r#"{}"#, r#"{"data":null}"#, r#"{"data":"x"}"#, r#"[]"#] {
            let v = rpki(json);
            assert_eq!(v.status, RpkiStatus::Unknown, "{json}");
            assert!(v.roas.is_empty(), "{json}");
        }
    }

    #[test]
    fn rpki_validation_missing_or_non_string_status_is_unknown() {
        // status 欠落・null・数値は Unknown (NotFound ではない)。ROA は status と独立に読まれる
        for json in [
            r#"{"data":{"validating_roas":[{"prefix":"10.0.0.0/8","origin":"AS1","max_length":8}]}}"#,
            r#"{"data":{"status":null,"validating_roas":[{"prefix":"10.0.0.0/8","origin":"AS1","max_length":8}]}}"#,
            r#"{"data":{"status":1,"validating_roas":[{"prefix":"10.0.0.0/8","origin":"AS1","max_length":8}]}}"#,
        ] {
            let v = rpki(json);
            assert_eq!(v.status, RpkiStatus::Unknown, "{json}");
            assert_eq!(v.roas.len(), 1, "{json}");
        }
        // 文字列の status は from_api に委ねられる (大文字・前後空白を許容)
        assert_eq!(
            rpki(r#"{"data":{"status":" VALID "}}"#).status,
            RpkiStatus::Valid
        );
    }

    #[test]
    fn rpki_validation_missing_or_non_array_roas_is_empty() {
        for json in [
            r#"{"data":{"status":"valid"}}"#,
            r#"{"data":{"status":"valid","validating_roas":null}}"#,
            r#"{"data":{"status":"valid","validating_roas":"x"}}"#,
            r#"{"data":{"status":"valid","validating_roas":{"prefix":"10.0.0.0/8"}}}"#,
            r#"{"data":{"status":"valid","validating_roas":[]}}"#,
        ] {
            let v = rpki(json);
            assert_eq!(v.status, RpkiStatus::Valid, "{json}");
            assert!(v.roas.is_empty(), "{json}");
        }
    }

    #[test]
    fn roa_prefix_is_trimmed_and_lowercased_like_announced_prefixes() {
        // ROA の prefix も announced_prefixes と同じく trim + 小文字化される
        let r = roas_of(r#"{"prefix":" 2001:DB8::/32\n","origin":"AS64501","max_length":48}"#);
        assert_eq!(
            r,
            vec![Roa {
                prefix: "2001:db8::/32".into(),
                origin: 64501,
                max_length: 48,
            }]
        );
    }

    #[test]
    fn roa_without_string_prefix_is_dropped() {
        for prefix in ["null", "123", r#"["10.0.0.0/8"]"#] {
            let r = roas_of(&format!(
                r#"{{"prefix":{prefix},"origin":"AS1","max_length":8}}"#
            ));
            assert!(r.is_empty(), "{prefix}");
        }
        assert!(roas_of(r#"{"origin":"AS1","max_length":8}"#).is_empty());
    }

    #[test]
    fn roa_prefix_is_not_validated() {
        // 現状の挙動: 不正な prefix 文字列の ROA も落ちずに通る (空文字も)
        let r = roas_of(r#"{"prefix":"garbage","origin":"AS1","max_length":8}"#);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].prefix, "garbage");
        let r = roas_of(r#"{"prefix":"","origin":"AS1","max_length":8}"#);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].prefix, "");
    }

    #[test]
    fn roa_origin_accepts_as_prefixed_and_plain_strings() {
        // "AS" / "as" 付き・数字のみの文字列・前後空白付きはすべて u32 として読める
        for origin in [
            r#""AS13335""#,
            r#""as13335""#,
            r#""13335""#,
            r#"" AS13335 ""#,
            r#""\tas13335\n""#,
        ] {
            let r = roas_with_origin(origin);
            assert_eq!(r.len(), 1, "{origin}");
            assert_eq!(r[0].origin, 13335, "{origin}");
        }
        assert_eq!(roas_with_origin(r#""AS0""#)[0].origin, 0);
        assert_eq!(roas_with_origin(r#""AS4294967295""#)[0].origin, u32::MAX);
    }

    #[test]
    fn roa_origin_odd_but_accepted_forms() {
        // 現状の挙動 (緩い): "AS"/"as" の繰り返し・混在 (ASas…)・先頭 '+'・先頭ゼロも通る。
        // "AS" と "as" は固定順 (AS → as) で剥がされるので "asAS1" は通らない (下のテスト参照)
        for (origin, expected) in [
            (r#""ASAS13335""#, 13335),
            (r#""asas13335""#, 13335),
            (r#""ASas13335""#, 13335),
            (r#""AS+13335""#, 13335),
            (r#""+13335""#, 13335),
            (r#""AS00013335""#, 13335),
        ] {
            let r = roas_with_origin(origin);
            assert_eq!(r.len(), 1, "{origin}");
            assert_eq!(r[0].origin, expected, "{origin}");
        }
    }

    #[test]
    fn roa_origin_numeric_json_value_is_dropped() {
        // 現状の挙動: origin が JSON 数値だと as_str() が None なので ROA ごと黙って除外される
        // (RIPEstat は文字列で返す想定だが、数値型で来ると不一致検出から漏れる)
        for origin in ["13335", "0", "13335.0", "-1"] {
            assert!(roas_with_origin(origin).is_empty(), "{origin}");
        }
    }

    #[test]
    fn roa_origin_invalid_values_are_dropped() {
        // 不正値は ROA ごと黙って除外される (エラーにも警告にもならない)
        for origin in [
            "null",
            "true",
            r#"["AS1"]"#,
            r#"{"asn":1}"#,
            r#""""#,
            r#""AS""#,
            r#""as""#,
            r#""ASx""#,
            r#""AS-1""#,
            r#""AS 13335""#,
            r#""As13335""#,
            r#""aS13335""#,
            r#""asAS13335""#,
            r#""AS13335.0""#,
            r#""AS4294967296""#,
            r#""AS13335 AS1""#,
            r#""AS_13335""#,
        ] {
            assert!(roas_with_origin(origin).is_empty(), "{origin}");
        }
        // origin 欠落
        assert!(roas_of(r#"{"prefix":"10.0.0.0/8","max_length":8}"#).is_empty());
    }

    #[test]
    fn roa_max_length_boundaries() {
        // 0 から 128 までは受理される。129 以上は除外される (IPv4 の ROA でも 32 超を許容する)
        assert_eq!(roas_with_max_length("0")[0].max_length, 0);
        assert_eq!(roas_with_max_length("48")[0].max_length, 48);
        assert_eq!(roas_with_max_length("128")[0].max_length, 128);
        for ml in ["129", "255", "256", "1000", "18446744073709551615"] {
            assert!(roas_with_max_length(ml).is_empty(), "{ml}");
        }
        // IPv4 prefix で max_length 33..=128 でも通る (family との整合性は見ない)
        let r = roas_of(r#"{"prefix":"10.0.0.0/8","origin":"AS1","max_length":128}"#);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].max_length, 128);
        // prefix 長より短い max_length も検証されない
        let r = roas_of(r#"{"prefix":"10.0.0.0/24","origin":"AS1","max_length":8}"#);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].max_length, 8);
    }

    #[test]
    fn roa_max_length_missing_or_wrong_type_is_dropped() {
        // 現状の挙動: 欠落・null・文字列・小数・負数・bool は ROA ごと黙って除外される
        // ("48" のような数字文字列や 48.0 も不可。origin は文字列を読むのに max_length は数値のみ)
        for ml in [
            "null", r#""48""#, r#""""#, "48.0", "48.5", "-1", "true", "[48]",
        ] {
            assert!(roas_with_max_length(ml).is_empty(), "{ml}");
        }
        assert!(roas_of(r#"{"prefix":"10.0.0.0/8","origin":"AS1"}"#).is_empty());
    }

    #[test]
    fn invalid_roas_are_dropped_individually_keeping_valid_ones() {
        // 不正な ROA だけが落ち、残りは順序を保ったまま残る。status には影響しない
        let v = rpki(
            r#"{"data":{"status":"invalid_asn","validating_roas":[
                {"prefix":"10.0.0.0/8","origin":"AS1","max_length":8},
                {"prefix":"10.0.0.0/8","origin":1,"max_length":8},
                {"prefix":"10.0.0.0/8","origin":"AS2","max_length":129},
                {"prefix":"10.0.0.0/8","origin":"AS3","max_length":"8"},
                "junk",
                null,
                {"prefix":"10.1.0.0/16","origin":"as4","max_length":24}
            ]}}"#,
        );
        assert_eq!(v.status, RpkiStatus::InvalidAsn);
        assert_eq!(
            v.roas,
            vec![
                Roa {
                    prefix: "10.0.0.0/8".into(),
                    origin: 1,
                    max_length: 8,
                },
                Roa {
                    prefix: "10.1.0.0/16".into(),
                    origin: 4,
                    max_length: 24,
                },
            ]
        );
    }
}
