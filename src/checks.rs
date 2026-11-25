//! 健康診断のチェックロジック。
//!
//! [`collect`] が DataSource から入力 ([`HealthInput`]) を組み立て、
//! [`run_checks`] が純粋関数として所見 ([`Finding`]) を導出する。
//! この分離により、チェックロジックはネットワークなしで単体テストできる。

use crate::sources::{AsOverview, DataSource, IrrRoute, PeeringDbNet, RpkiStatus, RpkiValidation};
use anyhow::Result;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::sync::Arc;
use tokio::task::JoinSet;

/// 広報していない IRR プレフィックスに対する RPKI 照会の上限 (チェック 3 用)。
const MAX_EXTRA_RPKI_LOOKUPS: usize = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Ok,
    Info,
    Warn,
    Fail,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    /// チェック番号 (1-7)
    pub check_no: u8,
    /// 機械可読 ID
    pub check: &'static str,
    pub severity: Severity,
    /// 対象 (プレフィックス等)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    pub message: String,
    /// 修正アクション
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix: Option<String>,
}

impl Finding {
    fn new(
        check_no: u8,
        check: &'static str,
        severity: Severity,
        message: impl Into<String>,
    ) -> Self {
        Self {
            check_no,
            check,
            severity,
            subject: None,
            message: message.into(),
            fix: None,
        }
    }

    fn subject(mut self, s: impl Into<String>) -> Self {
        self.subject = Some(s.into());
        self
    }

    fn fix(mut self, f: impl Into<String>) -> Self {
        self.fix = Some(f.into());
        self
    }
}

/// レポートのセクション見出し (チェック番号 → タイトル)。
pub const SECTION_TITLES: [(u8, &str); 7] = [
    (1, "ROAカバレッジ — 広報中プレフィックスにROAはあるか"),
    (2, "RPKI検証 — invalidな広報はないか"),
    (3, "未使用ROA — 広報していないのにROAだけ残っていないか"),
    (4, "IRR登録 — route/route6オブジェクトはあるか"),
    (5, "IRR陳腐化 — 広報していないrouteオブジェクトはないか"),
    (6, "IRR origin整合性 — DB間でoriginが食い違っていないか"),
    (7, "PeeringDB登録"),
];

/// チェックへの入力。すべて取得済みデータの純粋な集合。
#[derive(Debug)]
pub struct HealthInput {
    pub overview: AsOverview,
    /// 広報中プレフィックス (正規化・ソート済み)
    pub announced: Vec<String>,
    /// 広報中プレフィックスの RPKI 検証結果 (--limit で切り詰められる場合あり)
    pub rpki: BTreeMap<String, RpkiValidation>,
    /// IRR にはあるが広報されていないプレフィックスの RPKI 検証結果 (チェック 3 用)
    pub irr_rpki: BTreeMap<String, RpkiValidation>,
    /// IRR route/route6 オブジェクト。None = 取得失敗 (チェック 4-6 をスキップ)
    pub irr: Option<Vec<IrrRoute>>,
    /// PeeringDB への問い合わせが成功したか。false ならチェック 7 をスキップ
    pub pdb_checked: bool,
    pub peeringdb: Option<PeeringDbNet>,
    /// レポートに添える注記 (取得失敗・件数制限など)
    pub notes: Vec<String>,
}

/// DataSource から HealthInput を組み立てる。
///
/// `limit` : RPKI 検証を行う広報プレフィックスの最大数。
/// 大規模 AS で RIPEstat に大量のリクエストを送らないための上限。
/// `0` は「RPKI検証を全件スキップ」を意味してしまい、ROA未作成・RPKI invalidの
/// FAIL所見をすべて握りつぶしてスコアを不当に押し上げるため拒否する。
pub async fn collect(source: Arc<dyn DataSource>, asn: u32, limit: usize) -> Result<HealthInput> {
    collect_inner(source, asn, limit, CLI_LIMIT_HINT).await
}

/// `serve` (Web UI) 用の入口。`--limit` が無いため、上限注記の括弧書きだけを差し替える。
/// それ以外は [`collect`] と同一。
pub async fn collect_for_serve(
    source: Arc<dyn DataSource>,
    asn: u32,
    limit: usize,
) -> Result<HealthInput> {
    collect_inner(source, asn, limit, SERVE_LIMIT_HINT).await
}

/// 上限注記の括弧書き (CLI: check / fix / watch / report)。
const CLI_LIMIT_HINT: &str = "--limit で変更可";
/// 上限注記の括弧書き (serve: 上限固定)。
const SERVE_LIMIT_HINT: &str = "Web UI では上限固定。全件検査は CLI の --limit で";

/// [`collect`] / [`collect_for_serve`] の本体。`hint` は上限注記の括弧内に入る文言。
async fn collect_inner(
    source: Arc<dyn DataSource>,
    asn: u32,
    limit: usize,
    hint: &str,
) -> Result<HealthInput> {
    anyhow::ensure!(
        limit > 0,
        "limit に 0 は指定できません(CLI の --limit、または設定ファイル [defaults] の limit) — RPKI検証(ROA未作成・RPKI invalidの検出)が全件スキップされ、スコアが実態より高く出てしまいます。件数を絞りたい場合は1以上の値を指定してください"
    );
    let overview = source.as_overview(asn).await?;

    let mut announced: Vec<String> = source
        .announced_prefixes(asn)
        .await?
        .into_iter()
        .map(|p| p.trim().to_ascii_lowercase())
        .collect();
    announced.sort();
    announced.dedup();

    let mut notes = Vec::new();
    let truncated = announced.len() > limit;
    if truncated {
        notes.push(format!(
            "広報プレフィックスが{}件あるため、RPKI検証は先頭{}件に制限しました ({})",
            announced.len(),
            limit,
            hint
        ));
    }

    // 広報中プレフィックスの RPKI 検証 (並列)
    let rpki = rpki_lookup(
        &source,
        asn,
        announced.iter().take(limit).cloned().collect(),
        &mut notes,
    )
    .await;

    // IRR route/route6 オブジェクト
    let irr = match source.irr_routes(asn).await {
        Ok(routes) => Some(routes),
        Err(e) => {
            notes.push(format!(
                "IRR (whois.radb.net) の取得に失敗したためチェック4-6をスキップ: {e}"
            ));
            None
        }
    };

    // IRR にはあるが広報されていないプレフィックス → ROA が残っていないか照会 (チェック 3)
    let mut irr_rpki = BTreeMap::new();
    if let Some(routes) = &irr {
        let announced_set: BTreeSet<&str> = announced.iter().map(|s| s.as_str()).collect();
        let extras: Vec<String> = routes
            .iter()
            .filter(|r| r.origin == asn && !announced_set.contains(r.prefix.as_str()))
            .map(|r| r.prefix.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .take(MAX_EXTRA_RPKI_LOOKUPS)
            .collect();
        irr_rpki = rpki_lookup(&source, asn, extras, &mut notes).await;
    }

    // PeeringDB
    let (pdb_checked, peeringdb) = match source.peeringdb_net(asn).await {
        Ok(p) => (true, p),
        Err(e) => {
            notes.push(format!(
                "PeeringDB の取得に失敗したためチェック7をスキップ: {e}"
            ));
            (false, None)
        }
    };

    Ok(HealthInput {
        overview,
        announced,
        rpki,
        irr_rpki,
        irr,
        pdb_checked,
        peeringdb,
        notes,
    })
}

async fn rpki_lookup(
    source: &Arc<dyn DataSource>,
    asn: u32,
    prefixes: Vec<String>,
    notes: &mut Vec<String>,
) -> BTreeMap<String, RpkiValidation> {
    let mut set = JoinSet::new();
    for prefix in prefixes {
        let src = Arc::clone(source);
        set.spawn(async move {
            let validation = src.rpki_validation(asn, &prefix).await;
            (prefix, validation)
        });
    }
    let mut out = BTreeMap::new();
    let mut failures = 0usize;
    while let Some(joined) = set.join_next().await {
        if let Ok((prefix, validation)) = joined {
            let validation = validation.unwrap_or_else(|_| {
                failures += 1;
                RpkiStatus::Unknown.into()
            });
            out.insert(prefix, validation);
        }
    }
    if failures > 0 {
        notes.push(format!(
            "{failures}件のプレフィックスでRPKI検証APIの呼び出しに失敗しました (unknown 扱い)"
        ));
    }
    out
}

/// 7 種のチェックをすべて実行し、所見リストを返す (純粋関数)。
pub fn run_checks(input: &HealthInput) -> Vec<Finding> {
    let asn = input.overview.asn;
    let mut findings = Vec::new();
    let announced_set: BTreeSet<&str> = input.announced.iter().map(|s| s.as_str()).collect();

    // ---- チェック 1 & 2: ROA カバレッジ / RPKI invalid --------------------
    let mut missing_roa = 0usize;
    let mut invalid = 0usize;
    for (prefix, validation) in &input.rpki {
        match &validation.status {
            RpkiStatus::NotFound => {
                missing_roa += 1;
                findings.push(
                    Finding::new(1, "roa-missing", Severity::Fail,
                        "ROA未作成 — このプレフィックスをカバーするROAが存在せず、RPKI的に保護されていません")
                        .subject(prefix)
                        .fix(format!("RIRのポータル(JPNIC/APNIC/RIPE NCC等)で {prefix} のROAを作成する (origin AS{asn}, maxLengthは広報長に合わせる)")),
                );
            }
            s if s.is_invalid() => {
                invalid += 1;
                findings.push(
                    Finding::new(2, "rpki-invalid", Severity::Fail,
                        format!("RPKI invalid ({}) — ROV実施ネットワークからこの経路は破棄されます【最優先】", s.label()))
                        .subject(prefix)
                        .fix(format!("{prefix} のROA (origin/maxLength) と実際の広報の不一致を解消する。ROAの修正または広報の是正を直ちに行う")),
                );
            }
            _ => {}
        }
    }
    if missing_roa == 0 {
        findings.push(Finding::new(
            1,
            "roa-missing",
            Severity::Ok,
            format!(
                "検証した{}件の広報プレフィックスすべてにROAが存在します",
                input.rpki.len()
            ),
        ));
    }
    if invalid == 0 {
        findings.push(Finding::new(
            2,
            "rpki-invalid",
            Severity::Ok,
            "RPKI invalidな広報はありません",
        ));
    }

    // ---- チェック 3: 未使用 ROA -------------------------------------------
    // 制約: RIPEstat では AS 単位の ROA 一覧が取れないため、IRR に登録があるのに
    // 広報されていないプレフィックスについて ROA の有無を照会する近似実装。
    let mut unused_roa = 0usize;
    for (prefix, validation) in &input.irr_rpki {
        if validation.status == RpkiStatus::Valid {
            unused_roa += 1;
            findings.push(
                Finding::new(3, "roa-unused", Severity::Warn,
                    "広報していないプレフィックスにROAが存在します (古い設定の可能性)")
                    .subject(prefix)
                    .fix(format!("{prefix} を今後も広報しないなら、誤用防止のためROAの削除(または見直し)を検討する")),
            );
        }
    }
    if input.irr.is_some() && unused_roa == 0 {
        findings.push(Finding::new(
            3,
            "roa-unused",
            Severity::Ok,
            "未使用ROAは検出されませんでした (IRR登録プレフィックスからの推定)",
        ));
    }

    // ---- チェック 4-6: IRR ------------------------------------------------
    if let Some(irr) = &input.irr {
        // 4: 広報しているのに IRR に route オブジェクトがない
        let mut no_irr = 0usize;
        for prefix in &input.announced {
            let covered = irr
                .iter()
                .any(|r| r.origin == asn && (r.prefix == *prefix || covers(&r.prefix, prefix)));
            if !covered {
                no_irr += 1;
                findings.push(
                    Finding::new(4, "irr-missing", Severity::Warn,
                        "IRR未登録 — route/route6オブジェクトがなく、IRRベースのピアフィルタで経路が落ちる可能性があります")
                        .subject(prefix)
                        .fix(format!("RADBまたは自RIRのIRRに {prefix} (origin: AS{asn}) のroute/route6オブジェクトを作成する")),
                );
            }
        }
        if no_irr == 0 {
            findings.push(Finding::new(
                4,
                "irr-missing",
                Severity::Ok,
                "広報中の全プレフィックスにIRR route/route6オブジェクトがあります",
            ));
        }

        // 5: IRR にあるのに広報されていない (陳腐化)
        let mut stale = 0usize;
        let mut stale_seen = BTreeSet::new();
        for r in irr.iter().filter(|r| r.origin == asn) {
            if !announced_set.contains(r.prefix.as_str()) && stale_seen.insert(r.prefix.clone()) {
                stale += 1;
                findings.push(
                    Finding::new(5, "irr-stale", Severity::Warn,
                        format!("陳腐化したIRRオブジェクト — {} に登録がありますが現在広報されていません", r.source))
                        .subject(&r.prefix)
                        .fix(format!("{} を今後も広報しないなら、{} のroute/route6オブジェクトを削除する", r.prefix, r.source)),
                );
            }
        }
        if stale == 0 {
            findings.push(Finding::new(
                5,
                "irr-stale",
                Severity::Ok,
                "広報されていないIRRオブジェクトはありません",
            ));
        }

        // 6: 同一プレフィックスに対して DB 間で origin が食い違う
        let mut by_prefix: BTreeMap<&str, Vec<&IrrRoute>> = BTreeMap::new();
        for r in irr {
            by_prefix.entry(r.prefix.as_str()).or_default().push(r);
        }
        let mut conflicts = 0usize;
        for (prefix, routes) in &by_prefix {
            let origins: BTreeSet<u32> = routes.iter().map(|r| r.origin).collect();
            if origins.len() > 1 {
                conflicts += 1;
                let detail = routes
                    .iter()
                    .map(|r| format!("AS{}({})", r.origin, r.source))
                    .collect::<Vec<_>>()
                    .join(", ");
                findings.push(
                    Finding::new(6, "irr-origin-conflict", Severity::Warn,
                        format!("originが不一致: {detail} — ピアのフィルタ生成が不安定になります"))
                        .subject(*prefix)
                        .fix(format!("{prefix} の正しいorigin ASを確認し、食い違っているDB側のオブジェクト(多くは他者のproxy登録)を削除・修正依頼する")),
                );
            }
        }
        if conflicts == 0 {
            findings.push(Finding::new(
                6,
                "irr-origin-conflict",
                Severity::Ok,
                "IRR DB間のorigin不整合はありません",
            ));
        }
    }

    // ---- チェック 7: PeeringDB --------------------------------------------
    if input.pdb_checked {
        match &input.peeringdb {
            None => {
                findings.push(
                    Finding::new(7, "peeringdb-missing", Severity::Warn,
                        "PeeringDBにレコードがありません — ピアリング依頼の受付窓口が存在しない状態です")
                        .fix(format!("peeringdb.com でAS{asn}のネットワークレコードを作成する (ポリシー・連絡先・IX情報を記載)")),
                );
            }
            Some(net) => {
                let mut gaps = Vec::new();
                if net.ix_count == 0 {
                    gaps.push("IX接続情報なし");
                }
                if net.policy.trim().is_empty() {
                    gaps.push("ピアリングポリシー未記載");
                }
                if net.website.trim().is_empty() {
                    gaps.push("Webサイト未記載");
                }
                if gaps.is_empty() {
                    findings.push(Finding::new(
                        7,
                        "peeringdb",
                        Severity::Ok,
                        format!(
                            "PeeringDB登録あり: {} (IX接続 {}件, ポリシー: {})",
                            net.name, net.ix_count, net.policy
                        ),
                    ));
                } else {
                    findings.push(
                        Finding::new(
                            7,
                            "peeringdb-incomplete",
                            Severity::Info,
                            format!("PeeringDB登録はありますが情報が不足: {}", gaps.join(" / ")),
                        )
                        .fix("PeeringDBレコードにIX接続・ポリシー・連絡先を追記する".to_string()),
                    );
                }
            }
        }
    }

    findings
}

/// プレフィックスを (IPv6フラグ, 上位詰めアドレス, プレフィックス長) にパースする。
/// IPv4 は上位 32bit に詰めて u128 で統一的に扱う。
fn parse_prefix(p: &str) -> Option<(bool, u128, u8)> {
    let (addr, len) = p.split_once('/')?;
    let len: u8 = len.trim().parse().ok()?;
    match addr.trim().parse::<IpAddr>().ok()? {
        IpAddr::V4(a) => (len <= 32).then(|| (false, (u32::from(a) as u128) << 96, len)),
        IpAddr::V6(a) => (len <= 128).then(|| (true, u128::from(a), len)),
    }
}

/// `sup` が `sub` をカバーする (同じか、より短いプレフィックスで包含する) か。
pub fn covers(sup: &str, sub: &str) -> bool {
    let (Some((v6a, ipa, la)), Some((v6b, ipb, lb))) = (parse_prefix(sup), parse_prefix(sub))
    else {
        return false;
    };
    if v6a != v6b || la > lb {
        return false;
    }
    let mask = if la == 0 { 0 } else { u128::MAX << (128 - la) };
    ipa & mask == ipb & mask
}

/// 上限超過の動作を確かめるためのフェイク DataSource (ネットワークに出ない)。
/// `count` 件の広報プレフィックスを返し、RPKI は常に NotFound、IRR は空、PeeringDB は無し。
#[cfg(test)]
pub(crate) struct ManyPrefixSource {
    pub count: usize,
}

#[cfg(test)]
#[async_trait::async_trait]
impl DataSource for ManyPrefixSource {
    async fn as_overview(&self, asn: u32) -> Result<AsOverview> {
        Ok(AsOverview {
            asn,
            holder: "TEST-NET".into(),
            announced: true,
        })
    }
    async fn announced_prefixes(&self, _asn: u32) -> Result<Vec<String>> {
        Ok((0..self.count)
            .map(|i| format!("10.{}.{}.0/24", i / 256, i % 256))
            .collect())
    }
    async fn rpki_validation(&self, _asn: u32, _prefix: &str) -> Result<RpkiValidation> {
        Ok(RpkiStatus::NotFound.into())
    }
    async fn irr_routes(&self, _asn: u32) -> Result<Vec<IrrRoute>> {
        Ok(Vec::new())
    }
    async fn peeringdb_net(&self, _asn: u32) -> Result<Option<PeeringDbNet>> {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{compute_score, grade};
    use crate::sources::fixture::FixtureSource;

    fn count(findings: &[Finding], no: u8, sev: Severity) -> usize {
        findings
            .iter()
            .filter(|f| f.check_no == no && f.severity == sev)
            .count()
    }

    /// デモフィクスチャ (AS64500) で 7 チェックすべての異常系が発火することを確認。
    #[tokio::test]
    async fn demo_fixture_triggers_every_check() {
        let src: Arc<dyn DataSource> = Arc::new(FixtureSource::new());
        let input = collect(src, 64500, 50).await.unwrap();
        let findings = run_checks(&input);

        assert_eq!(count(&findings, 1, Severity::Fail), 2, "ROA未作成 x2");
        assert_eq!(count(&findings, 2, Severity::Fail), 1, "RPKI invalid x1");
        assert_eq!(count(&findings, 3, Severity::Warn), 1, "未使用ROA x1");
        assert_eq!(count(&findings, 4, Severity::Warn), 1, "IRR未登録 x1");
        assert_eq!(count(&findings, 5, Severity::Warn), 1, "陳腐化IRR x1");
        assert_eq!(count(&findings, 6, Severity::Warn), 1, "origin不一致 x1");
        assert_eq!(count(&findings, 7, Severity::Warn), 1, "PeeringDB未登録 x1");

        // スコア: 100 - 25(invalid) - 20(ROA未作成x2) - 3(未使用ROA)
        //             - 5(IRR未登録) - 4(陳腐化) - 5(origin不一致) - 10(PeeringDB) = 28
        let (score, _) = compute_score(&findings);
        assert_eq!(score, 28);
        assert_eq!(grade(score), 'E');
    }

    fn severity_total(findings: &[Finding], sev: Severity) -> usize {
        findings.iter().filter(|f| f.severity == sev).count()
    }

    /// デモフィクスチャ AS64500 の `check --demo` 結果 (スコア・グレード・重大度別件数) を固定する。
    #[tokio::test]
    async fn demo_as64500_check_result_is_pinned() {
        let src: Arc<dyn DataSource> = Arc::new(FixtureSource::new());
        let input = collect(src, 64500, 50).await.unwrap();
        let findings = run_checks(&input);
        let (score, deductions) = compute_score(&findings);

        assert_eq!(score, 28);
        assert_eq!(grade(score), 'E');
        assert_eq!(findings.len(), 8);
        assert_eq!(severity_total(&findings, Severity::Fail), 3);
        assert_eq!(severity_total(&findings, Severity::Warn), 5);
        assert_eq!(severity_total(&findings, Severity::Info), 0);
        assert_eq!(severity_total(&findings, Severity::Ok), 0);
        assert_eq!(deductions.len(), 7);
    }

    /// デモフィクスチャ AS64501 (健全) の `check --demo` 結果を固定する。
    #[tokio::test]
    async fn demo_as64501_check_result_is_pinned() {
        let src: Arc<dyn DataSource> = Arc::new(FixtureSource::new());
        let input = collect(src, 64501, 50).await.unwrap();
        let findings = run_checks(&input);
        let (score, deductions) = compute_score(&findings);

        assert_eq!(score, 100);
        assert_eq!(grade(score), 'A');
        assert_eq!(findings.len(), 7);
        assert_eq!(severity_total(&findings, Severity::Fail), 0);
        assert_eq!(severity_total(&findings, Severity::Warn), 0);
        assert_eq!(severity_total(&findings, Severity::Info), 0);
        assert_eq!(severity_total(&findings, Severity::Ok), 7);
        assert!(deductions.is_empty());
    }

    fn healthy_input() -> HealthInput {
        HealthInput {
            overview: AsOverview {
                asn: 64510,
                holder: "TEST-NET".into(),
                announced: true,
            },
            announced: vec!["192.0.2.0/24".into()],
            rpki: BTreeMap::from([("192.0.2.0/24".to_string(), RpkiStatus::Valid.into())]),
            irr_rpki: BTreeMap::new(),
            irr: Some(vec![IrrRoute {
                prefix: "192.0.2.0/24".into(),
                origin: 64510,
                source: "RADB".into(),
            }]),
            pdb_checked: true,
            peeringdb: Some(PeeringDbNet {
                name: "Test Net".into(),
                policy: "Open".into(),
                website: "https://test.example".into(),
                ix_count: 2,
            }),
            notes: vec![],
        }
    }

    #[test]
    fn healthy_as_scores_100_grade_a() {
        let findings = run_checks(&healthy_input());
        assert!(findings.iter().all(|f| f.severity == Severity::Ok));
        let (score, deductions) = compute_score(&findings);
        assert_eq!(score, 100);
        assert!(deductions.is_empty());
        assert_eq!(grade(score), 'A');
    }

    #[test]
    fn incomplete_peeringdb_is_info() {
        let mut input = healthy_input();
        input.peeringdb = Some(PeeringDbNet {
            name: "Test Net".into(),
            policy: String::new(),
            website: String::new(),
            ix_count: 0,
        });
        let findings = run_checks(&input);
        assert_eq!(count(&findings, 7, Severity::Info), 1);
        let (score, _) = compute_score(&findings);
        assert_eq!(score, 97);
    }

    #[test]
    fn rpki_invalid_deduction_is_capped() {
        let mut input = healthy_input();
        // invalid を 4 件に増やす → 25*4=100 だが上限 50
        input.announced = (0..4).map(|i| format!("10.{i}.0.0/16")).collect();
        input.rpki = input
            .announced
            .iter()
            .map(|p| (p.clone(), RpkiStatus::InvalidAsn.into()))
            .collect();
        input.irr = Some(
            input
                .announced
                .iter()
                .map(|p| IrrRoute {
                    prefix: p.clone(),
                    origin: 64510,
                    source: "RADB".into(),
                })
                .collect(),
        );
        let findings = run_checks(&input);
        assert_eq!(count(&findings, 2, Severity::Fail), 4);
        let (score, _) = compute_score(&findings);
        assert_eq!(score, 50);
        assert_eq!(grade(score), 'D');
    }

    #[test]
    fn irr_fetch_failure_skips_checks_4_to_6() {
        let mut input = healthy_input();
        input.irr = None;
        let findings = run_checks(&input);
        assert!(findings.iter().all(|f| !(4..=6).contains(&f.check_no)));
    }

    #[test]
    fn covering_less_specific_irr_object_satisfies_check4() {
        let mut input = healthy_input();
        input.announced = vec!["192.0.2.128/25".into()];
        input.rpki = BTreeMap::from([("192.0.2.128/25".to_string(), RpkiStatus::Valid.into())]);
        // IRR には /24 のみ → /25 の広報をカバーしているので OK 扱い
        let findings = run_checks(&input);
        assert_eq!(count(&findings, 4, Severity::Warn), 0);
        // ただし /24 自体は広報されていないので陳腐化 WARN になる
        assert_eq!(count(&findings, 5, Severity::Warn), 1);
    }

    #[test]
    fn covers_helper() {
        assert!(covers("192.0.2.0/24", "192.0.2.0/24"));
        assert!(covers("192.0.2.0/24", "192.0.2.128/25"));
        assert!(!covers("192.0.2.128/25", "192.0.2.0/24"));
        assert!(!covers("192.0.2.0/24", "198.51.100.0/24"));
        assert!(covers("2001:db8::/32", "2001:db8:1::/48"));
        assert!(!covers("2001:db8::/32", "192.0.2.0/24"));
        assert!(!covers("garbage", "192.0.2.0/24"));
    }

    /// P0-2: `--limit 0` は「RPKI検証を全件スキップ」を意味してしまい、FAIL所見を
    /// すべて握りつぶしてスコアを不当に押し上げる (28/E → 73/C 相当の実害) ため拒否する。
    ///
    /// 同じエラーが出る経路は CLI の `--limit 0` と設定ファイルの `[defaults] limit = 0` の2系統。
    /// CLI 側は `check` / `fix` が main.rs から直接 `collect`、`watch` が main.rs → watch.rs の
    /// `run_cycle` → `collect`。設定ファイル側は `check --config` (`multi::check_all`)、
    /// `watch --config` (`multi::watch_cycle`)、`report --config` (`report_cmd::run_all` → `run_one`)
    /// が `config.limit` を渡す。
    /// `serve` は limit を受け取らず固定値 (server.rs の `WEB_RPKI_LIMIT`) を使うため対象外。
    /// `[[as]]` ごとの limit は読まれないため、エラー文は `[[as]]` に誘導してはならない。
    #[tokio::test]
    async fn collect_rejects_limit_zero() {
        let src: Arc<dyn DataSource> = Arc::new(FixtureSource::new());
        let err = collect(src, 64500, 0).await.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("--limit"), "got: {err}");
        assert!(msg.contains("[defaults]"), "got: {err}");
        assert!(msg.contains("0 は指定できません"), "got: {err}");
        assert!(!msg.contains("[[as]]"), "got: {err}");
    }

    #[tokio::test]
    async fn collect_accepts_limit_one() {
        let src: Arc<dyn DataSource> = Arc::new(FixtureSource::new());
        assert!(collect(src, 64500, 1).await.is_ok());
    }

    /// 現状固定: 上限超過時の注記は「(--limit で変更可)」を含む全文で出て、
    /// `Report::build` 後の coverage は announced=総数 / checked=上限 / complete=false になる。
    #[tokio::test]
    async fn collect_over_limit_note_and_coverage_are_pinned() {
        let src: Arc<dyn DataSource> = Arc::new(ManyPrefixSource { count: 60 });
        let input = collect(src, 64500, 50).await.unwrap();
        assert_eq!(
            input.notes,
            vec![
                "広報プレフィックスが60件あるため、RPKI検証は先頭50件に制限しました (--limit で変更可)"
                    .to_string()
            ]
        );
        let findings = run_checks(&input);
        let report = crate::report::Report::build(&input, findings);
        assert_eq!(report.coverage.announced, 60);
        assert_eq!(report.coverage.checked, 50);
        assert!(!report.coverage.complete);
    }

    /// 上限ちょうど (50件/limit 50) なら注記なし・complete=true。
    #[tokio::test]
    async fn collect_at_limit_has_no_note_and_complete_coverage() {
        let src: Arc<dyn DataSource> = Arc::new(ManyPrefixSource { count: 50 });
        let input = collect(src, 64500, 50).await.unwrap();
        assert!(input.notes.is_empty());
        let report = crate::report::Report::build(&input, run_checks(&input));
        assert!(report.coverage.complete);
    }

    /// serve 用の入口は括弧書きだけを差し替え、coverage は CLI と同じになる。
    #[tokio::test]
    async fn collect_for_serve_over_limit_note_replaces_only_the_hint() {
        let src: Arc<dyn DataSource> = Arc::new(ManyPrefixSource { count: 60 });
        let input = collect_for_serve(src, 64500, 50).await.unwrap();
        assert_eq!(
            input.notes,
            vec![
                "広報プレフィックスが60件あるため、RPKI検証は先頭50件に制限しました (Web UI では上限固定。全件検査は CLI の --limit で)"
                    .to_string()
            ]
        );
        let report = crate::report::Report::build(&input, run_checks(&input));
        assert_eq!(report.coverage.announced, 60);
        assert_eq!(report.coverage.checked, 50);
        assert!(!report.coverage.complete);
    }

    /// serve 用でも `limit = 0` の拒否は共通 (serve は固定値なので実際には到達しない)。
    #[tokio::test]
    async fn collect_for_serve_rejects_limit_zero() {
        let src: Arc<dyn DataSource> = Arc::new(ManyPrefixSource { count: 1 });
        assert!(collect_for_serve(src, 64500, 0).await.is_err());
    }
}
