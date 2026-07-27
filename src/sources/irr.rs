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
}
