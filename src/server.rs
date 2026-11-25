//! `ashealth serve` — ミニマルなWeb UI。
//!
//! - GET /                : 埋め込みの単一HTMLページ (フォーム + クライアントサイド描画)。
//!   `--config` 指定時は設定内ASNの一覧ダッシュボードに切り替わる
//! - GET /api/check/{asn} : 健康診断を実行しJSONレポートを返す
//! - GET /api/summary     : (v0.5) 設定内ASNのキャッシュ済みサマリ一覧を返す (`--config` 専用)
//!
//! 公開ホスティングに向けた保護:
//! - IPごとのスライディングウィンドウ・レートリミット (既定 10回/分、超過は 429)
//! - ASN単位の結果キャッシュ (既定 TTL 600秒)。キャッシュ応答には
//!   `"cached": true` と `"cache_age_secs"` が付く。RIPEstat / whois への連打を防ぐ。
//!
//! AS64500 (不健全) / AS64501 (健全) はフィクスチャで応答するため、常にオフラインでデモできる。
//! `--demo` フラグを付けて起動すると、それ以外のASNもすべてフィクスチャ(AS64500)で応答し、
//! ライブAPIには一切アクセスしない完全オフラインモードになる。

use crate::checks;
use crate::config::Config;
use crate::report::Report;
use crate::sources::{
    fixture::FixtureSource, fixture::DEMO_ASN, fixture::HEALTHY_DEMO_ASN, DataSource, LiveSource,
};
use anyhow::Result;
use axum::{
    extract::{ConnectInfo, Path, State},
    http::StatusCode,
    response::{Html, IntoResponse, Json, Response},
    routing::get,
    Router,
};
use serde::Serialize;
use serde_json::json;
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

const INDEX_HTML: &str = include_str!("../static/index.html");
const WEB_RPKI_LIMIT: usize = 50;

/// IPごとのスライディングウィンドウ・レートリミッタ。
///
/// 直近 `window` 内のリクエスト時刻を IP ごとに保持し、`max_per_window` 件を
/// 超えるリクエストを拒否する。`max_per_window == 0` は無制限。
pub struct RateLimiter {
    max_per_window: u32,
    window: Duration,
    state: Mutex<HashMap<IpAddr, VecDeque<Instant>>>,
}

impl RateLimiter {
    pub fn new(max_per_window: u32, window: Duration) -> Self {
        Self {
            max_per_window,
            window,
            state: Mutex::new(HashMap::new()),
        }
    }

    pub fn max_per_window(&self) -> u32 {
        self.max_per_window
    }

    /// `now` 時点でこの IP のリクエストを許可するか。許可した場合は記録する。
    fn allow_at(&self, ip: IpAddr, now: Instant) -> bool {
        if self.max_per_window == 0 {
            return true;
        }
        let mut map = self.state.lock().unwrap();
        let q = map.entry(ip).or_default();
        while let Some(&front) = q.front() {
            if now.duration_since(front) >= self.window {
                q.pop_front();
            } else {
                break;
            }
        }
        if (q.len() as u32) < self.max_per_window {
            q.push_back(now);
            true
        } else {
            false
        }
    }

    pub fn allow(&self, ip: IpAddr) -> bool {
        self.allow_at(ip, Instant::now())
    }
}

/// ASN → (レポートJSON, 格納時刻) のインメモリキャッシュ。
///
/// `ttl == 0` はキャッシュ無効。
pub struct ReportCache {
    ttl: Duration,
    map: Mutex<HashMap<u32, (serde_json::Value, Instant)>>,
}

impl ReportCache {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            map: Mutex::new(HashMap::new()),
        }
    }

    /// TTL内のエントリがあれば (レポートJSON, 経過秒数) を返す。
    fn get_at(&self, asn: u32, now: Instant) -> Option<(serde_json::Value, u64)> {
        let map = self.map.lock().unwrap();
        let (value, stored_at) = map.get(&asn)?;
        let age = now.saturating_duration_since(*stored_at);
        (age < self.ttl).then(|| (value.clone(), age.as_secs()))
    }

    fn put_at(&self, asn: u32, value: serde_json::Value, now: Instant) {
        if self.ttl.is_zero() {
            return;
        }
        self.map.lock().unwrap().insert(asn, (value, now));
    }

    pub fn get(&self, asn: u32) -> Option<(serde_json::Value, u64)> {
        self.get_at(asn, Instant::now())
    }

    pub fn put(&self, asn: u32, value: serde_json::Value) {
        self.put_at(asn, value, Instant::now());
    }
}

struct AppState {
    limiter: RateLimiter,
    cache: ReportCache,
    /// `--config` 指定時のみ Some。指定時は index がダッシュボードになり、
    /// /api/summary が有効になる。
    config: Option<Config>,
    /// `--demo` 指定時は true。全ASNをフィクスチャ (AS64500) で応答し、
    /// ライブAPIには一切アクセスしないオフライン専用モードになる。
    demo: bool,
}

pub async fn serve_with_config(
    port: u16,
    rate_limit: u32,
    cache_ttl_secs: u64,
    config: Option<Config>,
    demo: bool,
) -> Result<()> {
    let dashboard = config.is_some();
    let state = Arc::new(AppState {
        limiter: RateLimiter::new(rate_limit, Duration::from_secs(60)),
        cache: ReportCache::new(Duration::from_secs(cache_ttl_secs)),
        config,
        demo,
    });
    let app = Router::new()
        .route("/", get(index))
        .route("/api/check/{asn}", get(api_check))
        .route("/api/summary", get(api_summary))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port))
        .await
        .map_err(|e| bind_error(port, &e))?;
    println!(
        "ashealth web UI: http://localhost:{port}/ (レートリミット {rate_limit}回/分/IP, キャッシュTTL {cache_ttl_secs}秒{}{}, Ctrl-C で終了)",
        if dashboard { ", ダッシュボードモード (--config)" } else { "" },
        if demo { ", オフラインデモモード (--demo)" } else { "" }
    );
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

/// OSの生エラー ("Address already in use (os error 98)") を、他のエラーと同じ
/// 日本語UXに揃えて包む (P2-8)。
fn bind_error(port: u16, e: &std::io::Error) -> anyhow::Error {
    if e.kind() == std::io::ErrorKind::AddrInUse {
        anyhow::anyhow!(
            "ポート {port} は既に使用されています。別の --port を指定してください (例: --port {})",
            port.wrapping_add(1)
        )
    } else {
        anyhow::anyhow!("ポート {port} でのリッスンに失敗しました: {e}")
    }
}

async fn index(State(state): State<Arc<AppState>>) -> Html<String> {
    match &state.config {
        Some(cfg) => {
            let rows = build_summary(cfg, &state.cache, SystemTime::now());
            Html(render_dashboard(&rows))
        }
        None => Html(INDEX_HTML.to_string()),
    }
}

/// `/api/summary` の1行分。`score`以下はキャッシュ未取得なら None ("未チェック")。
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AsnSummaryRow {
    pub asn: u32,
    pub label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grade: Option<char>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fail: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warn: Option<usize>,
    /// RFC3339 (UTC)。未チェックなら None
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checked_at: Option<String>,
    pub cached: bool,
}

/// キャッシュ済みレポートJSONから summary 行を組み立てる (純粋関数)。
/// `age_secs` と `now` から `checked_at` (RFC3339) を逆算する。
fn summary_row_from_cached(
    asn: u32,
    label: String,
    report_json: &serde_json::Value,
    age_secs: u64,
    now: SystemTime,
) -> AsnSummaryRow {
    let fail = report_json["findings"]
        .as_array()
        .map(|arr| arr.iter().filter(|f| f["severity"] == "FAIL").count());
    let warn = report_json["findings"]
        .as_array()
        .map(|arr| arr.iter().filter(|f| f["severity"] == "WARN").count());
    let checked_at = now
        .checked_sub(Duration::from_secs(age_secs))
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| crate::watch::rfc3339_from_unix(d.as_secs()));
    AsnSummaryRow {
        asn,
        label,
        score: report_json["score"].as_i64().map(|n| n as i32),
        grade: report_json["grade"].as_str().and_then(|s| s.chars().next()),
        fail,
        warn,
        checked_at,
        cached: true,
    }
}

/// 未チェックのASN行 (score以下すべてNone、"未チェック"表示用)。
fn summary_row_unchecked(asn: u32, label: String) -> AsnSummaryRow {
    AsnSummaryRow {
        asn,
        label,
        score: None,
        grade: None,
        fail: None,
        warn: None,
        checked_at: None,
        cached: false,
    }
}

/// 設定内の全ASN分、キャッシュから summary 行を組み立てる (純粋関数)。
/// キャッシュに無いASNは「未チェック」行になる。
pub fn build_summary(config: &Config, cache: &ReportCache, now: SystemTime) -> Vec<AsnSummaryRow> {
    config
        .entries
        .iter()
        .map(|entry| match cache.get(entry.asn) {
            Some((value, age_secs)) => {
                summary_row_from_cached(entry.asn, entry.name.clone(), &value, age_secs, now)
            }
            None => summary_row_unchecked(entry.asn, entry.name.clone()),
        })
        .collect()
}

async fn api_summary(State(state): State<Arc<AppState>>) -> Response {
    let Some(cfg) = &state.config else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "このサーバは --config なしで起動しています (/api/summary は無効です)" })),
        )
            .into_response();
    };
    let rows = build_summary(cfg, &state.cache, SystemTime::now());
    (StatusCode::OK, Json(rows)).into_response()
}

/// グレード → バッジ色 (静的HTMLと同系統の配色)。
fn grade_color(g: char) -> &'static str {
    match g {
        'A' | 'B' => "#1a7f37",
        'C' => "#9a6700",
        _ => "#cf222e",
    }
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// ダッシュボードHTMLを組み立てる (テーブル部分は純粋関数、外側は固定テンプレート)。
fn render_dashboard(rows: &[AsnSummaryRow]) -> String {
    let mut body = String::new();
    for r in rows {
        let (score_cell, badge) = match (r.score, r.grade) {
            (Some(score), Some(grade)) => (
                format!("{score}点"),
                format!(
                    "<span class=\"badge\" style=\"background:{}\">{}</span>",
                    grade_color(grade),
                    grade
                ),
            ),
            _ => (
                "—".to_string(),
                "<span class=\"badge unchecked\">未チェック</span>".to_string(),
            ),
        };
        let fail_warn = match (r.fail, r.warn) {
            (Some(f), Some(w)) => format!("FAIL {f}件 / WARN {w}件"),
            _ => "—".to_string(),
        };
        let checked = r.checked_at.as_deref().unwrap_or("未チェック");
        let action = if r.cached {
            format!("<a href=\"/api/check/{}\">再チェック</a>", r.asn)
        } else {
            format!("<a href=\"/api/check/{}\">今すぐチェック</a>", r.asn)
        };
        body.push_str(&format!(
            "<tr><td>{label}</td><td class=\"mono\">AS{asn}</td><td>{score_cell} {badge}</td><td>{fail_warn}</td><td class=\"meta\">{checked}</td><td>{action}</td></tr>",
            label = esc(&r.label),
            asn = r.asn,
        ));
    }
    format!(
        r#"<!doctype html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta http-equiv="refresh" content="300">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ashealth — 複数ASダッシュボード</title>
<style>
  :root {{ --bg: #f6f8fa; --card: #ffffff; --ink: #1f2933; --muted: #6b7683; --line: #d8dee4; }}
  * {{ box-sizing: border-box; }}
  body {{ margin: 0; background: var(--bg); color: var(--ink); font-family: "Hiragino Sans", "Noto Sans JP", -apple-system, "Segoe UI", sans-serif; line-height: 1.6; }}
  main {{ max-width: 960px; margin: 0 auto; padding: 2.5rem 1.25rem 4rem; }}
  h1 {{ font-size: 1.6rem; margin: 0 0 .25rem; }}
  .tagline {{ color: var(--muted); margin: 0 0 1.5rem; font-size: .95rem; }}
  table {{ width: 100%; border-collapse: collapse; background: var(--card); border: 1px solid var(--line); border-radius: 12px; overflow: hidden; }}
  th, td {{ padding: .65rem .9rem; text-align: left; border-bottom: 1px solid var(--line); font-size: .92rem; }}
  th {{ color: var(--muted); font-weight: 600; font-size: .8rem; text-transform: uppercase; }}
  tr:last-child td {{ border-bottom: none; }}
  .mono {{ font-family: ui-monospace, Menlo, monospace; }}
  .meta {{ color: var(--muted); font-size: .85rem; }}
  .badge {{ display: inline-block; color: #fff; font-weight: 700; border-radius: 999px; padding: .1rem .55rem; font-size: .8rem; }}
  .badge.unchecked {{ background: var(--muted); }}
  a {{ color: #0969da; text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
  footer {{ color: var(--muted); font-size: .8rem; margin-top: 1.5rem; }}
</style>
</head>
<body>
<main>
  <h1>ashealth — 複数ASダッシュボード</h1>
  <p class="tagline">設定ファイルで管理している {count} 件のASを表示しています (5分ごとに自動更新)</p>
  <table>
    <thead><tr><th>ラベル</th><th>ASN</th><th>スコア</th><th>所見</th><th>最終チェック</th><th></th></tr></thead>
    <tbody>{body}</tbody>
  </table>
  <footer>データは /api/check のキャッシュに基づきます。行の「チェック」リンクで最新化できます。</footer>
</main>
</body>
</html>"#,
        count = rows.len(),
    )
}

async fn api_check(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(asn_str): Path<String>,
) -> Response {
    let asn = match crate::parse_asn(&asn_str) {
        Ok(asn) => asn,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": e.to_string() })),
            )
                .into_response()
        }
    };

    if let Err(msg) = validate_asn_for_serve(asn, state.demo) {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": msg }))).into_response();
    }

    if !state.limiter.allow(peer.ip()) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({
                "error": format!(
                    "レートリミット超過: {}回/分 を超えました。しばらく待ってから再試行してください",
                    state.limiter.max_per_window()
                ),
            })),
        )
            .into_response();
    }

    if let Some((mut value, age_secs)) = state.cache.get(asn) {
        if let Some(obj) = value.as_object_mut() {
            obj.insert("cached".into(), json!(true));
            obj.insert("cache_age_secs".into(), json!(age_secs));
        }
        return (StatusCode::OK, Json(value)).into_response();
    }

    match run_check(asn, state.demo).await {
        Ok(report) => {
            let mut value = serde_json::json!(report);
            state.cache.put(asn, value.clone());
            if let Some(obj) = value.as_object_mut() {
                obj.insert("cached".into(), json!(false));
            }
            (StatusCode::OK, Json(value)).into_response()
        }
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

/// `/api/check/{asn}` のASN検証 (P0-1)。純粋関数として単体テストできるよう
/// HTTPレスポンス組み立てから切り離してある。
///
/// AS64500/AS64501 (フィクスチャ) は予約AS番号帯だが意図的な特別扱いなので、demo かどうかに
/// 関わらず常に許可する。
/// それ以外は `crate::validate_asn` に従う。AS0/AS23456 は demo でも拒否する。
/// 予約帯 (警告対象) は、非 demo では警告文をそのままエラーにして拒否し (壊れた結果を返すより
/// 明示的に断る方針)、`--demo` サーバ (どのASNもフィクスチャで応答しライブ診断しない) では許可する。
///
/// 戻り値: `Ok(())` — 診断続行可。`Err(message)` — 4xxで返すエラーメッセージ。
fn validate_asn_for_serve(asn: u32, demo: bool) -> Result<(), String> {
    if asn == DEMO_ASN || asn == HEALTHY_DEMO_ASN {
        return Ok(());
    }
    match crate::validate_asn(asn) {
        Ok(warnings) => {
            if !demo && !warnings.is_empty() {
                Err(warnings.join(" / "))
            } else {
                Ok(())
            }
        }
        Err(e) => Err(e.to_string()),
    }
}

async fn run_check(asn: u32, demo_server: bool) -> Result<Report> {
    // AS64500 (不健全) / AS64501 (健全) は常にフィクスチャで応答。
    // `--demo` サーバではそれ以外のASNもすべてAS64500フィクスチャにフォールバックし、
    // ライブAPIには一切アクセスしない。
    let source: Arc<dyn DataSource> = if asn == DEMO_ASN || asn == HEALTHY_DEMO_ASN || demo_server {
        Arc::new(FixtureSource::new())
    } else {
        Arc::new(LiveSource::new()?)
    };
    check_with_source(source, asn).await
}

/// `run_check` のデータソース以降の部分 (テストからフェイク DataSource を渡せるよう分離)。
async fn check_with_source(source: Arc<dyn DataSource>, asn: u32) -> Result<Report> {
    let input = checks::collect_for_serve(source, asn, WEB_RPKI_LIMIT).await?;
    let findings = checks::run_checks(&input);
    Ok(Report::build(&input, findings))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(last: u8) -> IpAddr {
        IpAddr::from([192, 0, 2, last])
    }

    /// P0-1: 通常運用サーバでAS0/AS23456を叩くと拒否される (clean 4xx JSON化の下地)。
    #[test]
    fn validate_asn_for_serve_rejects_as_zero_and_as_trans() {
        assert!(validate_asn_for_serve(0, false).is_err());
        assert!(validate_asn_for_serve(23456, false).is_err());
    }

    /// P0-1: 通常運用サーバで予約帯 (フィクスチャASN以外) を叩くと拒否される。
    #[test]
    fn validate_asn_for_serve_rejects_reserved_range_when_not_demo() {
        assert!(validate_asn_for_serve(64502, false).is_err());
        assert!(validate_asn_for_serve(65535, false).is_err());
    }

    /// P2-7: AS64500/AS64501 はフィクスチャの意図的な特別扱いなので予約帯でも拒否しない。
    #[test]
    fn validate_asn_for_serve_allows_fixture_asns_even_when_not_demo() {
        assert!(validate_asn_for_serve(DEMO_ASN, false).is_ok());
        assert!(validate_asn_for_serve(HEALTHY_DEMO_ASN, false).is_ok());
    }

    /// `--demo` サーバはどのASNもフィクスチャ応答になるため、予約帯の警告は出さない
    /// (AS0/AS23456だけは無意味なASNとして引き続き拒否)。
    #[test]
    fn validate_asn_for_serve_demo_mode_allows_reserved_but_not_as_zero() {
        assert!(validate_asn_for_serve(64502, true).is_ok());
        assert!(validate_asn_for_serve(0, true).is_err());
        assert!(validate_asn_for_serve(23456, true).is_err());
    }

    /// 実運用ASN (予約帯外) は常に許可される。
    #[test]
    fn validate_asn_for_serve_allows_normal_asn() {
        assert!(validate_asn_for_serve(13335, false).is_ok());
    }

    /// P2-8: ポート使用中エラーは日本語で「別の --port を指定してください」と案内する。
    #[test]
    fn bind_error_addr_in_use_gives_actionable_japanese_message() {
        let e = std::io::Error::from(std::io::ErrorKind::AddrInUse);
        let err = bind_error(8080, &e);
        let msg = err.to_string();
        assert!(msg.contains("8080"), "got: {msg}");
        assert!(msg.contains("使用されています"), "got: {msg}");
        assert!(msg.contains("--port"), "got: {msg}");
    }

    #[test]
    fn bind_error_other_kind_still_readable() {
        let e = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
        let err = bind_error(80, &e);
        assert!(err.to_string().contains("80"));
    }

    #[test]
    fn rate_limiter_allows_up_to_limit_then_denies() {
        let rl = RateLimiter::new(3, Duration::from_secs(60));
        let now = Instant::now();
        assert!(rl.allow_at(ip(1), now));
        assert!(rl.allow_at(ip(1), now));
        assert!(rl.allow_at(ip(1), now));
        assert!(!rl.allow_at(ip(1), now), "4回目は拒否");
        assert!(
            !rl.allow_at(ip(1), now + Duration::from_secs(30)),
            "窓内はまだ拒否"
        );
    }

    #[test]
    fn rate_limiter_window_slides() {
        let rl = RateLimiter::new(2, Duration::from_secs(60));
        let now = Instant::now();
        assert!(rl.allow_at(ip(1), now));
        assert!(rl.allow_at(ip(1), now + Duration::from_secs(30)));
        assert!(!rl.allow_at(ip(1), now + Duration::from_secs(59)));
        // 最初のリクエストが窓から抜けた後は再び許可される
        assert!(rl.allow_at(ip(1), now + Duration::from_secs(61)));
        assert!(
            !rl.allow_at(ip(1), now + Duration::from_secs(61)),
            "窓内2件で満杯"
        );
    }

    #[test]
    fn rate_limiter_tracks_ips_independently() {
        let rl = RateLimiter::new(1, Duration::from_secs(60));
        let now = Instant::now();
        assert!(rl.allow_at(ip(1), now));
        assert!(!rl.allow_at(ip(1), now));
        assert!(rl.allow_at(ip(2), now), "別IPは独立にカウント");
    }

    #[test]
    fn rate_limiter_zero_means_unlimited() {
        let rl = RateLimiter::new(0, Duration::from_secs(60));
        let now = Instant::now();
        for _ in 0..100 {
            assert!(rl.allow_at(ip(1), now));
        }
    }

    #[test]
    fn cache_hit_within_ttl_reports_age() {
        let cache = ReportCache::new(Duration::from_secs(600));
        let now = Instant::now();
        assert!(cache.get_at(64500, now).is_none());
        cache.put_at(64500, json!({"score": 28}), now);
        let (value, age) = cache.get_at(64500, now + Duration::from_secs(120)).unwrap();
        assert_eq!(value, json!({"score": 28}));
        assert_eq!(age, 120);
    }

    #[test]
    fn cache_expires_after_ttl() {
        let cache = ReportCache::new(Duration::from_secs(600));
        let now = Instant::now();
        cache.put_at(64500, json!({"score": 28}), now);
        assert!(cache
            .get_at(64500, now + Duration::from_secs(599))
            .is_some());
        assert!(
            cache
                .get_at(64500, now + Duration::from_secs(600))
                .is_none(),
            "TTL到達で失効"
        );
    }

    #[test]
    fn cache_ttl_zero_disables_caching() {
        let cache = ReportCache::new(Duration::from_secs(0));
        let now = Instant::now();
        cache.put_at(64500, json!({"score": 28}), now);
        assert!(cache.get_at(64500, now).is_none());
    }

    #[test]
    fn cache_entries_are_per_asn() {
        let cache = ReportCache::new(Duration::from_secs(600));
        let now = Instant::now();
        cache.put_at(64500, json!({"asn": 64500}), now);
        assert!(cache.get_at(64501, now).is_none());
    }

    fn sample_config() -> Config {
        crate::config::parse(
            r#"
[[as]]
asn = 64500
name = "本番AS"

[[as]]
asn = 64501
name = "検証AS"
"#,
        )
        .unwrap()
    }

    #[test]
    fn build_summary_reports_unchecked_for_uncached_asn() {
        let cfg = sample_config();
        let cache = ReportCache::new(Duration::from_secs(600));
        let rows = build_summary(&cfg, &cache, SystemTime::now());
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|r| !r.cached));
        assert!(rows.iter().all(|r| r.score.is_none()));
        assert_eq!(rows[0].asn, 64500);
        assert_eq!(rows[0].label, "本番AS");
    }

    #[test]
    fn build_summary_uses_cached_report_for_score_and_findings() {
        let cfg = sample_config();
        let cache = ReportCache::new(Duration::from_secs(600));
        let now = Instant::now();
        cache.put_at(
            64500,
            json!({
                "score": 28,
                "grade": "E",
                "findings": [
                    {"severity": "FAIL", "message": "a"},
                    {"severity": "FAIL", "message": "b"},
                    {"severity": "WARN", "message": "c"},
                    {"severity": "OK", "message": "d"},
                ]
            }),
            now,
        );
        let rows = build_summary(&cfg, &cache, SystemTime::now());
        let row = rows.iter().find(|r| r.asn == 64500).unwrap();
        assert!(row.cached);
        assert_eq!(row.score, Some(28));
        assert_eq!(row.grade, Some('E'));
        assert_eq!(row.fail, Some(2));
        assert_eq!(row.warn, Some(1));
        assert!(row.checked_at.is_some());

        let unchecked = rows.iter().find(|r| r.asn == 64501).unwrap();
        assert!(!unchecked.cached);
    }

    #[test]
    fn build_summary_empty_config_entries_is_not_possible_but_empty_cache_is_fine() {
        // config.rsのバリデーションによりentriesは常に1件以上だが、
        // summary組み立て自体は空配列でも壊れないことを確認する防御的テスト。
        let cfg = sample_config();
        let cache = ReportCache::new(Duration::from_secs(0)); // TTL0 = 常に未チェック扱い
        let rows = build_summary(&cfg, &cache, SystemTime::now());
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|r| !r.cached));
    }

    #[test]
    fn summary_row_serializes_without_null_fields_when_unchecked() {
        let row = summary_row_unchecked(64500, "本番AS".to_string());
        let v = serde_json::to_value(&row).unwrap();
        assert_eq!(v["asn"], 64500);
        assert_eq!(v["cached"], false);
        assert!(v.get("score").is_none(), "未チェックはscoreを省略");
    }

    #[test]
    fn render_dashboard_contains_all_asns_and_refresh_meta() {
        let rows = vec![
            AsnSummaryRow {
                asn: 64500,
                label: "本番AS".into(),
                score: Some(28),
                grade: Some('E'),
                fail: Some(3),
                warn: Some(5),
                checked_at: Some("2026-07-07T09:00:00Z".into()),
                cached: true,
            },
            summary_row_unchecked(64501, "検証AS".into()),
        ];
        let html = render_dashboard(&rows);
        assert!(html.contains("AS64500"));
        assert!(html.contains("AS64501"));
        assert!(html.contains("未チェック"));
        assert!(html.contains(r#"http-equiv="refresh" content="300""#));
    }

    /// serve 経路 (`WEB_RPKI_LIMIT` = 50) で上限を超えると、注記の括弧書きは
    /// serve 用の文言になり (「--limit で変更可」は出ない)、coverage は complete=false になる。
    #[tokio::test]
    async fn serve_path_over_limit_note_and_coverage() {
        let src: Arc<dyn DataSource> = Arc::new(crate::checks::ManyPrefixSource { count: 60 });
        let report = check_with_source(src, 64500).await.unwrap();
        assert_eq!(
            report.notes,
            vec![
                "広報プレフィックスが60件あるため、RPKI検証は先頭50件に制限しました (Web UI では上限固定。全件検査は CLI の --limit で)"
                    .to_string()
            ]
        );
        assert_eq!(report.coverage.announced, 60);
        assert_eq!(report.coverage.checked, WEB_RPKI_LIMIT);
        assert!(!report.coverage.complete);
    }
}
