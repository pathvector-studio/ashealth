//! IRR (Internet Routing Registry) クライアント。
//!
//! whois.radb.net (TCP 43) に `-i origin ASxxxx` を送り、
//! route / route6 オブジェクトをパースする。
//! RADB は主要 IRR (RIPE, APNIC, ALTDB, JPIRR など) をミラーしているため、
//! 1 クエリで複数 DB のオブジェクトが得られ、source 属性で登録元が分かる。

use super::IrrRoute;
use anyhow::{Context, Result};
use std::collections::BTreeSet;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const WHOIS_HOST: &str = "whois.radb.net:43";

pub async fn routes(asn: u32) -> Result<Vec<IrrRoute>> {
    let mut stream = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(WHOIS_HOST))
        .await
        .context("whois.radb.net への接続がタイムアウト")?
        .context("whois.radb.net への接続に失敗")?;

    stream
        .write_all(format!("-i origin AS{asn}\r\n").as_bytes())
        .await
        .context("whois クエリの送信に失敗")?;

    let mut buf = Vec::new();
    tokio::time::timeout(Duration::from_secs(30), stream.read_to_end(&mut buf))
        .await
        .context("whois 応答の読み取りがタイムアウト")?
        .context("whois 応答の読み取りに失敗")?;

    let text = String::from_utf8_lossy(&buf);
    Ok(parse_whois(&text))
}

/// whois 出力から route/route6 オブジェクトを抽出する。
pub fn parse_whois(text: &str) -> Vec<IrrRoute> {
    let mut seen = BTreeSet::new();
    let mut routes = Vec::new();

    let mut prefix: Option<String> = None;
    let mut origin: Option<u32> = None;
    let mut source: Option<String> = None;

    let flush = |prefix: &mut Option<String>,
                 origin: &mut Option<u32>,
                 source: &mut Option<String>,
                 routes: &mut Vec<IrrRoute>,
                 seen: &mut BTreeSet<(String, u32, String)>| {
        if let (Some(p), Some(o)) = (prefix.take(), origin.take()) {
            let s = source.take().unwrap_or_else(|| "UNKNOWN".to_string());
            if seen.insert((p.clone(), o, s.clone())) {
                routes.push(IrrRoute {
                    prefix: p,
                    origin: o,
                    source: s,
                });
            }
        } else {
            prefix.take();
            origin.take();
            source.take();
        }
    };

    for line in text.lines() {
        let line = line.trim_end();
        if line.is_empty() {
            flush(
                &mut prefix,
                &mut origin,
                &mut source,
                &mut routes,
                &mut seen,
            );
            continue;
        }
        if line.starts_with('%') || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        match key.trim().to_ascii_lowercase().as_str() {
            "route" | "route6" => {
                // 直前のオブジェクトが空行なしで続いた場合に備えて flush
                flush(
                    &mut prefix,
                    &mut origin,
                    &mut source,
                    &mut routes,
                    &mut seen,
                );
                prefix = Some(value.to_ascii_lowercase());
            }
            "origin" => {
                origin = value
                    .trim_start_matches("AS")
                    .trim_start_matches("as")
                    .parse::<u32>()
                    .ok();
            }
            "source" => {
                // "RADB # Filtered" のようなコメント付きに対応
                let s = value.split_whitespace().next().unwrap_or(value);
                source = Some(s.to_ascii_uppercase());
            }
            _ => {}
        }
    }
    flush(
        &mut prefix,
        &mut origin,
        &mut source,
        &mut routes,
        &mut seen,
    );
    routes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_fixture_whois_output() {
        let routes = parse_whois(include_str!("../../fixtures/as64500/irr-whois.txt"));
        assert_eq!(routes.len(), 5);
        assert!(routes
            .iter()
            .any(|r| r.prefix == "192.0.2.0/24" && r.origin == 64501 && r.source == "ALTDB"));
        assert!(routes
            .iter()
            .any(|r| r.prefix == "2001:db8::/32" && r.origin == 64500));
    }

    #[test]
    fn ignores_comments_and_dedupes() {
        let text = "% This is RADb\n\nroute: 10.0.0.0/8\norigin: AS65000\nsource: RADB # Filtered\n\nroute: 10.0.0.0/8\norigin: AS65000\nsource: RADB\n";
        let routes = parse_whois(text);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].source, "RADB");
    }

    fn route(prefix: &str, origin: u32, source: &str) -> IrrRoute {
        IrrRoute {
            prefix: prefix.to_string(),
            origin,
            source: source.to_string(),
        }
    }

    #[test]
    fn empty_and_blank_input_yield_no_routes() {
        assert!(parse_whois("").is_empty());
        assert!(parse_whois("\n\n   \n\t\n").is_empty());
    }

    #[test]
    fn parses_route6_and_lowercases_prefix() {
        let text = "route6: 2001:DB8::/32\norigin: AS64500\nsource: RADB\n";
        // 最初の ':' だけでキーと値に分割されるので、値の IPv6 の ':' はそのまま残り、小文字化される
        assert_eq!(
            parse_whois(text),
            vec![route("2001:db8::/32", 64500, "RADB")]
        );
    }

    #[test]
    fn separates_objects_by_blank_line_and_keeps_order() {
        let text = "route: 10.0.0.0/8\norigin: AS1\nsource: RADB\n\nroute6: 2001:db8::/32\norigin: AS2\nsource: RIPE\n";
        assert_eq!(
            parse_whois(text),
            vec![
                route("10.0.0.0/8", 1, "RADB"),
                route("2001:db8::/32", 2, "RIPE"),
            ]
        );
    }

    #[test]
    fn next_route_line_flushes_previous_object_without_blank_line() {
        let text = "route: 10.0.0.0/8\norigin: AS1\nsource: RADB\nroute: 10.1.0.0/16\norigin: AS2\nsource: ALTDB\n";
        assert_eq!(
            parse_whois(text),
            vec![
                route("10.0.0.0/8", 1, "RADB"),
                route("10.1.0.0/16", 2, "ALTDB"),
            ]
        );
    }

    #[test]
    fn handles_crlf_and_trailing_whitespace() {
        let text = "route: 10.0.0.0/8  \r\norigin: AS1\t\r\nsource: RADB \r\n\r\n";
        assert_eq!(parse_whois(text), vec![route("10.0.0.0/8", 1, "RADB")]);
    }

    #[test]
    fn keys_are_case_insensitive_and_trimmed() {
        let text = "ROUTE :\t10.0.0.0/8\n Origin :AS1\nSource:radb\n";
        // 行頭の空白があっても属性として扱われ、source は大文字化される
        assert_eq!(parse_whois(text), vec![route("10.0.0.0/8", 1, "RADB")]);
    }

    #[test]
    fn origin_accepts_as_prefix_variants_and_bare_number() {
        let cases = [
            ("AS65000", 65000),
            ("as65000", 65000),
            ("65000", 65000),
            ("ASAS65000", 65000),
            ("ASas65000", 65000),
            ("AS0", 0),
            ("AS4294967295", u32::MAX),
            // u32::from_str が '+' を許すため通る (バグっぽいが現状の挙動)
            ("AS+65000", 65000),
        ];
        for (value, expected) in cases {
            let text = format!("route: 10.0.0.0/8\norigin: {value}\nsource: RADB\n");
            assert_eq!(
                parse_whois(&text),
                vec![route("10.0.0.0/8", expected, "RADB")],
                "origin: {value}"
            );
        }
    }

    #[test]
    fn invalid_origin_drops_the_object() {
        let cases = [
            "",
            "AS",
            "AS 65000",
            "As65000",
            "AS65000 # note",
            "AS-65000",
            "ASxyz",
            "AS4294967296",
            "AS1.1",
        ];
        for value in cases {
            let text = format!("route: 10.0.0.0/8\norigin: {value}\nsource: RADB\n");
            assert!(parse_whois(&text).is_empty(), "origin: {value:?}");
        }
    }

    #[test]
    fn missing_origin_drops_the_object_but_not_its_neighbours() {
        let text =
            "route: 10.0.0.0/8\nsource: RADB\n\nroute: 10.1.0.0/16\norigin: AS2\nsource: RADB\n";
        assert_eq!(parse_whois(text), vec![route("10.1.0.0/16", 2, "RADB")]);
    }

    #[test]
    fn origin_without_route_is_ignored() {
        assert!(parse_whois("origin: AS1\nsource: RADB\n").is_empty());
    }

    #[test]
    fn origin_before_route_is_lost_because_route_flushes() {
        // route 行で必ず flush されるため、route より前の origin / source は捨てられる
        let text = "origin: AS1\nsource: RADB\nroute: 10.0.0.0/8\n";
        assert!(parse_whois(text).is_empty());

        // origin だけ route より後ろなら取れ、source は UNKNOWN になる
        let text = "source: RADB\nroute: 10.0.0.0/8\norigin: AS1\n";
        assert_eq!(parse_whois(text), vec![route("10.0.0.0/8", 1, "UNKNOWN")]);
    }

    #[test]
    fn origin_before_source_or_after_source_both_work() {
        let a = "route: 10.0.0.0/8\nsource: RADB\norigin: AS1\n";
        let b = "route: 10.0.0.0/8\norigin: AS1\nsource: RADB\n";
        assert_eq!(parse_whois(a), parse_whois(b));
        assert_eq!(parse_whois(a), vec![route("10.0.0.0/8", 1, "RADB")]);
    }

    #[test]
    fn blank_line_between_route_and_origin_loses_the_object() {
        let text = "route: 10.0.0.0/8\n\norigin: AS1\nsource: RADB\n";
        assert!(parse_whois(text).is_empty());
    }

    #[test]
    fn missing_source_becomes_unknown_and_empty_source_stays_empty() {
        let text = "route: 10.0.0.0/8\norigin: AS1\n";
        assert_eq!(parse_whois(text), vec![route("10.0.0.0/8", 1, "UNKNOWN")]);

        // "source:" が値なしで存在する場合は UNKNOWN にならず空文字になる
        let text = "route: 10.0.0.0/8\norigin: AS1\nsource:\n";
        assert_eq!(parse_whois(text), vec![route("10.0.0.0/8", 1, "")]);
    }

    #[test]
    fn source_takes_first_token_and_uppercases() {
        let text = "route: 10.0.0.0/8\norigin: AS1\nsource: ripe-nonauth # legacy\n";
        assert_eq!(
            parse_whois(text),
            vec![route("10.0.0.0/8", 1, "RIPE-NONAUTH")]
        );
    }

    #[test]
    fn comment_lines_are_skipped_without_ending_the_object() {
        let text = "% header\n# top\nroute: 10.0.0.0/8\n% mid-object\n# route: 99.0.0.0/8\norigin: AS1\n% origin: AS2\nsource: RADB\n";
        assert_eq!(parse_whois(text), vec![route("10.0.0.0/8", 1, "RADB")]);
    }

    #[test]
    fn indented_comment_marker_is_not_a_comment() {
        // 行頭が '%' / '#' のときだけコメント。インデントされていれば通常行として扱われる
        let text = "route: 10.0.0.0/8\n  % origin: AS2\norigin: AS1\nsource: RADB\n";
        // "  % origin" はキーが "% origin" になり未知キーとして無視される
        assert_eq!(parse_whois(text), vec![route("10.0.0.0/8", 1, "RADB")]);
    }

    #[test]
    fn lines_without_colon_and_unknown_keys_are_ignored() {
        let text = "garbage line\nroute: 10.0.0.0/8\nroute-set: AS-FOO\nmnt-by: MAINT\nexport: to AS1\norigin: AS1\norigins: AS9\nsource: RADB\n";
        assert_eq!(parse_whois(text), vec![route("10.0.0.0/8", 1, "RADB")]);
    }

    #[test]
    fn continuation_lines_do_not_split_objects() {
        // RPSL の継続行 (行頭空白 / '+') は空行ではないので flush されない
        let text = "route: 10.0.0.0/8\ndescr: first\n  second line\n+\n+ third line\norigin: AS1\nsource: RADB\n";
        assert_eq!(parse_whois(text), vec![route("10.0.0.0/8", 1, "RADB")]);
    }

    #[test]
    fn indented_continuation_with_known_key_overrides_attribute() {
        // 継続行を区別していないため、descr の継続行が "origin: ..." の形だと origin を上書きする
        // (バグっぽいが現状の挙動)
        let text = "route: 10.0.0.0/8\norigin: AS1\ndescr: foo\n    origin: AS2\nsource: RADB\n";
        assert_eq!(parse_whois(text), vec![route("10.0.0.0/8", 2, "RADB")]);

        // '+' で始まる継続行はキーが "+ origin" になるため無視される
        let text = "route: 10.0.0.0/8\norigin: AS1\ndescr: foo\n+ origin: AS2\nsource: RADB\n";
        assert_eq!(parse_whois(text), vec![route("10.0.0.0/8", 1, "RADB")]);
    }

    #[test]
    fn duplicate_origin_or_source_lines_last_one_wins() {
        let text = "route: 10.0.0.0/8\norigin: AS1\norigin: AS2\nsource: RADB\nsource: ripe\n";
        assert_eq!(parse_whois(text), vec![route("10.0.0.0/8", 2, "RIPE")]);

        // 後勝ちなので、最後の origin が不正だと先に有効な値があってもオブジェクトごと落ちる
        let text = "route: 10.0.0.0/8\norigin: AS1\norigin: bogus\nsource: RADB\n";
        assert!(parse_whois(text).is_empty());
    }

    #[test]
    fn duplicate_route_lines_in_one_object_keep_only_the_last_prefix() {
        // 2 つ目の route 行で flush されるが、origin 未取得の最初の route は捨てられる
        let text = "route: 10.0.0.0/8\nroute: 10.1.0.0/16\norigin: AS1\nsource: RADB\n";
        assert_eq!(parse_whois(text), vec![route("10.1.0.0/16", 1, "RADB")]);
    }

    #[test]
    fn dedupe_key_is_prefix_origin_source() {
        let text = "route: 10.0.0.0/8\norigin: AS1\nsource: RADB\n\n\
                    route: 10.0.0.0/8\norigin: AS1\nsource: RADB\n\n\
                    route: 10.0.0.0/8\norigin: AS2\nsource: RADB\n\n\
                    route: 10.0.0.0/8\norigin: AS1\nsource: ALTDB\n\n\
                    route6: 2001:DB8::/32\norigin: AS1\nsource: RADB\n\n\
                    route6: 2001:db8::/32\norigin: AS1\nsource: radb\n";
        // 完全一致のみ除去。origin / source が違えば残り、prefix・source は正規化後に比較される。順序は初出順
        assert_eq!(
            parse_whois(text),
            vec![
                route("10.0.0.0/8", 1, "RADB"),
                route("10.0.0.0/8", 2, "RADB"),
                route("10.0.0.0/8", 1, "ALTDB"),
                route("2001:db8::/32", 1, "RADB"),
            ]
        );
    }

    #[test]
    fn prefix_value_is_not_validated() {
        // prefix は検証されず、空でもそのまま (小文字化のみで) 出力される
        let text =
            "route:\norigin: AS1\nsource: RADB\n\nroute: Not-A-Prefix\norigin: AS2\nsource: RADB\n";
        assert_eq!(
            parse_whois(text),
            vec![route("", 1, "RADB"), route("not-a-prefix", 2, "RADB")]
        );
    }

    #[test]
    fn trailing_object_without_final_newline_is_flushed() {
        let text = "route: 10.0.0.0/8\norigin: AS1\nsource: RADB";
        assert_eq!(parse_whois(text), vec![route("10.0.0.0/8", 1, "RADB")]);
    }
}
