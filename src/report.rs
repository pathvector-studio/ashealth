//! スコア計算とレポート生成 (ターミナル / JSON)。

use crate::checks::{Finding, HealthInput, Severity, SECTION_TITLES};
use owo_colors::OwoColorize;
use serde::Serialize;

/// 減点ルール。
/// スコアは 100 点から開始し、チェックごとに「1 件あたり per 点、上限 cap 点」を減点する。
///
/// | チェック | 減点/件 | 上限 |
/// |---|---|---|
/// | 2: RPKI invalid        | 25 | 50 |
/// | 1: ROA未作成           | 10 | 30 |
/// | 4: IRR未登録           |  5 | 15 |
/// | 6: IRR origin不一致    |  5 | 10 |
/// | 5: 陳腐化IRR           |  4 | 12 |
/// | 3: 未使用ROA           |  3 |  9 |
/// | 7: PeeringDB未登録     | 10 | 10 |
/// | 7: PeeringDB情報不足   |  3 |  3 |
struct Rule {
    check_no: u8,
    severity: Severity,
    per: i32,
    cap: i32,
    label: &'static str,
}

const RULES: &[Rule] = &[
    Rule {
        check_no: 2,
        severity: Severity::Fail,
        per: 25,
        cap: 50,
        label: "RPKI invalidな広報",
    },
    Rule {
        check_no: 1,
        severity: Severity::Fail,
        per: 10,
        cap: 30,
        label: "ROA未作成",
    },
    Rule {
        check_no: 4,
        severity: Severity::Warn,
        per: 5,
        cap: 15,
        label: "IRR未登録",
    },
    Rule {
        check_no: 6,
        severity: Severity::Warn,
        per: 5,
        cap: 10,
        label: "IRR origin不一致",
    },
    Rule {
        check_no: 5,
        severity: Severity::Warn,
        per: 4,
        cap: 12,
        label: "陳腐化したIRRオブジェクト",
    },
    Rule {
        check_no: 3,
        severity: Severity::Warn,
        per: 3,
        cap: 9,
        label: "未使用ROA",
    },
    Rule {
        check_no: 7,
        severity: Severity::Warn,
        per: 10,
        cap: 10,
        label: "PeeringDB未登録",
    },
    Rule {
        check_no: 7,
        severity: Severity::Info,
        per: 3,
        cap: 3,
        label: "PeeringDB情報不足",
    },
];

#[derive(Debug, Clone, Serialize)]
pub struct Deduction {
    pub label: &'static str,
    pub count: usize,
    pub points: i32,
}

/// 減点の内訳と最終スコア (0-100) を計算する。
pub fn compute_score(findings: &[Finding]) -> (i32, Vec<Deduction>) {
    let mut deductions = Vec::new();
    let mut total = 0i32;
    for rule in RULES {
        let count = findings
            .iter()
            .filter(|f| f.check_no == rule.check_no && f.severity == rule.severity)
            .count();
        if count > 0 {
            let points = (count as i32 * rule.per).min(rule.cap);
            total += points;
            deductions.push(Deduction {
                label: rule.label,
                count,
                points,
            });
        }
    }
    ((100 - total).max(0), deductions)
}

/// RPKI検証の被覆状況。`--limit` によって広報プレフィックス全件を検証しきれていない
/// (サンプリングされた) 場合、スコア・グレードは推定値であることを利用者に明示するために使う。
#[derive(Debug, Clone, Serialize)]
pub struct Coverage {
    /// 広報中プレフィックス総数
    pub announced: usize,
    /// 実際にRPKI検証したプレフィックス数 (`--limit` で切り詰められることがある)
    pub checked: usize,
    /// `announced == checked` なら true (全件検証済み)
    pub complete: bool,
}

impl Coverage {
    fn build(input: &HealthInput) -> Self {
        let announced = input.announced.len();
        let checked = input.rpki.len();
        Coverage {
            announced,
            checked,
            complete: checked >= announced,
        }
    }
}

/// スコア → グレード (A: 90+, B: 75+, C: 60+, D: 40+, E: それ未満)。
pub fn grade(score: i32) -> char {
    match score {
        90..=100 => 'A',
        75..=89 => 'B',
        60..=74 => 'C',
        40..=59 => 'D',
        _ => 'E',
    }
}

fn grade_comment(g: char) -> &'static str {
    match g {
        'A' => "良好 — 4つの情報源がきれいに揃っています",
        'B' => "概ね良好 — 軽微なズレのみです",
        'C' => "要改善 — 情報源間のズレが目立ちます",
        'D' => "不健全 — ピアフィルタや到達性に影響しうる問題があります",
        _ => "危険 — 経路が破棄される深刻な問題があります。至急対応してください",
    }
}

/// 人間向けレポートの修正アクション欄に列挙する最大件数。これを超える分は
/// 「…他N件は --json で」という注記に折りたたむ (JSON側は常に全件を含む)。
pub const FIX_ACTIONS_DISPLAY_CAP: usize = 10;

/// 人間向けレポートの1チェックセクションに列挙する所見の最大件数。
/// 大規模ASではチェック5(陳腐化IRR)等が数十件になりうるため、
/// ターミナル出力が「ノイズの壁」にならないよう先頭のみ表示し件数を明記する
/// (JSON側の `findings` は常に全件を含む)。
pub const SECTION_DISPLAY_CAP: usize = 10;

#[derive(Debug, Serialize)]
pub struct Report {
    pub asn: u32,
    pub holder: String,
    pub announced_count: usize,
    pub ipv4_count: usize,
    pub ipv6_count: usize,
    pub rpki_checked: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub irr_route_count: Option<usize>,
    /// RPKI検証の被覆状況 (`--limit` によるサンプリングの有無)
    pub coverage: Coverage,
    pub score: i32,
    pub grade: char,
    pub grade_comment: &'static str,
    pub deductions: Vec<Deduction>,
    pub findings: Vec<Finding>,
    /// 全件 (JSON消費者向け)。人間向けターミナル表示は先頭 [`FIX_ACTIONS_DISPLAY_CAP`] 件に絞る。
    pub fix_actions: Vec<String>,
    pub notes: Vec<String>,
}

impl Report {
    pub fn build(input: &HealthInput, findings: Vec<Finding>) -> Self {
        let (score, deductions) = compute_score(&findings);
        let g = grade(score);

        // 修正アクション: FAIL → WARN → INFO、同一深刻度内は減点の重いチェック順
        let urgency = |no: u8| {
            RULES
                .iter()
                .position(|r| r.check_no == no)
                .unwrap_or(RULES.len())
        };
        let mut with_fix: Vec<&Finding> = findings.iter().filter(|f| f.fix.is_some()).collect();
        with_fix.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then(urgency(a.check_no).cmp(&urgency(b.check_no)))
        });
        let fix_actions = with_fix
            .iter()
            .map(|f| f.fix.clone().unwrap_or_default())
            .collect();

        let ipv6_count = input.announced.iter().filter(|p| p.contains(':')).count();
        Report {
            asn: input.overview.asn,
            holder: input.overview.holder.clone(),
            announced_count: input.announced.len(),
            ipv4_count: input.announced.len() - ipv6_count,
            ipv6_count,
            rpki_checked: input.rpki.len(),
            irr_route_count: input.irr.as_ref().map(|v| v.len()),
            coverage: Coverage::build(input),
            score,
            grade: g,
            grade_comment: grade_comment(g),
            deductions,
            findings,
            fix_actions,
            notes: input.notes.clone(),
        }
    }
}

fn severity_tag(sev: Severity) -> String {
    match sev {
        Severity::Ok => format!("{}", " OK ".green().bold()),
        Severity::Info => format!("{}", "INFO".cyan().bold()),
        Severity::Warn => format!("{}", "WARN".yellow().bold()),
        Severity::Fail => format!("{}", "FAIL".red().bold()),
    }
}

/// ターミナル向けのカラーレポートを表示する。
pub fn render_terminal(r: &Report) {
    println!();
    println!(
        "  {}",
        format!("ashealth ─ AS{} 健康診断レポート", r.asn).bold()
    );
    println!("  {}", "─".repeat(64));
    println!("  対象     : AS{} ({})", r.asn, r.holder);
    println!(
        "  広報経路 : {} prefixes (IPv4 {} / IPv6 {}) — RPKI検証 {}件",
        r.announced_count, r.ipv4_count, r.ipv6_count, r.rpki_checked
    );
    if let Some(n) = r.irr_route_count {
        println!("  IRR      : route/route6 オブジェクト {n}件 (whois.radb.net)");
    }
    println!();

    for (no, title) in SECTION_TITLES {
        let items: Vec<&Finding> = r.findings.iter().filter(|f| f.check_no == no).collect();
        let count = items.len();
        let heading = if count > SECTION_DISPLAY_CAP {
            format!("[{no}] {title} ({count}件)")
        } else {
            format!("[{no}] {title}")
        };
        println!("  {}", heading.bold());
        if items.is_empty() {
            println!("       {}", "(データ取得失敗のためスキップ)".dimmed());
        }
        let shown = count.min(SECTION_DISPLAY_CAP);
        for f in items.iter().take(shown) {
            let subject = f
                .subject
                .as_deref()
                .map(|s| format!("{s} — "))
                .unwrap_or_default();
            println!(
                "    {} {}{}",
                severity_tag(f.severity),
                subject.bold(),
                f.message
            );
        }
        let remaining = count - shown;
        if remaining > 0 {
            println!(
                "    {}",
                format!("… 他{remaining}件は --json で確認してください").dimmed()
            );
        }
        println!();
    }

    println!("  {}", "─".repeat(64));
    if !r.coverage.complete {
        println!(
            "  {}",
            format!(
                "⚠ RPKI検証は広報{}件中{}件のみ (--limit) — 未検査分にFAIL所見が潜んでいる可能性があります",
                r.coverage.announced, r.coverage.checked
            )
            .yellow()
            .bold()
        );
    }
    let grade_qualifier = if r.coverage.complete {
        String::new()
    } else {
        format!(
            "   (推定 — {}/{}プレフィックス検査)",
            r.coverage.checked, r.coverage.announced
        )
    };
    let score_line = format!(
        "総合スコア: {} / 100   グレード: {}{grade_qualifier}",
        r.score, r.grade
    );
    let colored = match r.grade {
        'A' | 'B' => format!("{}", score_line.green().bold()),
        'C' => format!("{}", score_line.yellow().bold()),
        _ => format!("{}", score_line.red().bold()),
    };
    println!("  {colored}");
    println!("  {}", r.grade_comment);
    if !r.deductions.is_empty() {
        println!();
        println!("  減点内訳:");
        for d in &r.deductions {
            // RPKI由来のチェック (1: ROA未作成, 2: RPKI invalid) はサンプリング時に
            // 分母を明記する ("6/20検査中" 形式)。それ以外のチェックは検査範囲に
            // --limit の影響を受けないため従来通り件数のみ表示する。
            let rpki_derived = matches!(d.label, "ROA未作成" | "RPKI invalidな広報");
            if rpki_derived && !r.coverage.complete {
                println!(
                    "    -{:<3} {} × {}件 ({}/{}検査中)",
                    d.points, d.label, d.count, r.coverage.checked, r.coverage.announced
                );
            } else {
                println!("    -{:<3} {} × {}件", d.points, d.label, d.count);
            }
        }
    }
    if !r.fix_actions.is_empty() {
        println!();
        println!("  {}", "修正アクション (優先度順):".bold());
        let shown = r.fix_actions.len().min(FIX_ACTIONS_DISPLAY_CAP);
        for (i, action) in r.fix_actions.iter().take(shown).enumerate() {
            println!("    {}. {}", i + 1, action);
        }
        let remaining = r.fix_actions.len() - shown;
        if remaining > 0 {
            println!(
                "    {}",
                format!("… 他{remaining}件は --json で確認してください").dimmed()
            );
        }
    }
    if !r.notes.is_empty() {
        println!();
        for note in &r.notes {
            println!("  {}", format!("※ {note}").dimmed());
        }
    }
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grade_boundaries() {
        assert_eq!(grade(100), 'A');
        assert_eq!(grade(90), 'A');
        assert_eq!(grade(89), 'B');
        assert_eq!(grade(75), 'B');
        assert_eq!(grade(74), 'C');
        assert_eq!(grade(60), 'C');
        assert_eq!(grade(59), 'D');
        assert_eq!(grade(40), 'D');
        assert_eq!(grade(39), 'E');
        assert_eq!(grade(0), 'E');
    }

    #[test]
    fn score_never_goes_below_zero() {
        // 全ルールの上限をすべて食らっても 0 で止まる
        let mut findings = Vec::new();
        for no in 1..=7u8 {
            for _ in 0..10 {
                findings.push(Finding {
                    check_no: no,
                    check: "x",
                    severity: if no <= 2 {
                        Severity::Fail
                    } else {
                        Severity::Warn
                    },
                    subject: None,
                    message: String::new(),
                    fix: None,
                });
            }
        }
        let (score, _) = compute_score(&findings);
        assert_eq!(score, 0);
    }

    fn healthy_input_with(announced_count: usize, checked_count: usize) -> HealthInput {
        use crate::sources::{AsOverview, RpkiStatus};
        use std::collections::BTreeMap;
        let announced: Vec<String> = (0..announced_count)
            .map(|i| format!("10.{}.{}.0/24", i / 256, i % 256))
            .collect();
        let rpki: BTreeMap<String, _> = announced
            .iter()
            .take(checked_count)
            .map(|p| (p.clone(), RpkiStatus::Valid.into()))
            .collect();
        HealthInput {
            overview: AsOverview {
                asn: 64510,
                holder: "TEST-NET".into(),
                announced: true,
            },
            announced,
            rpki,
            irr_rpki: BTreeMap::new(),
            irr: None,
            pdb_checked: false,
            peeringdb: None,
            notes: vec![],
        }
    }

    /// P0-2/P1-3: 全件検査時は `coverage.complete == true` で `announced == checked`。
    #[test]
    fn coverage_complete_when_all_prefixes_checked() {
        let input = healthy_input_with(10, 10);
        let findings = crate::checks::run_checks(&input);
        let report = Report::build(&input, findings);
        assert_eq!(report.coverage.announced, 10);
        assert_eq!(report.coverage.checked, 10);
        assert!(report.coverage.complete);
    }

    /// P0-2: `--limit` によるサンプリング時は `coverage.complete == false` になり、
    /// JSON消費者が「打ち切りがあった」ことを検出できる。
    #[test]
    fn coverage_incomplete_when_limit_truncates() {
        let input = healthy_input_with(20, 5);
        let findings = crate::checks::run_checks(&input);
        let report = Report::build(&input, findings);
        assert_eq!(report.coverage.announced, 20);
        assert_eq!(report.coverage.checked, 5);
        assert!(!report.coverage.complete);
    }

    /// P1-4: 修正アクションが [`FIX_ACTIONS_DISPLAY_CAP`] を超えても JSON の `fix_actions` は
    /// 全件保持する (人間向けターミナル表示のみが先頭N件に切り詰められる)。
    #[test]
    fn fix_actions_json_keeps_full_detail_beyond_cap() {
        let mut input =
            healthy_input_with(FIX_ACTIONS_DISPLAY_CAP + 5, FIX_ACTIONS_DISPLAY_CAP + 5);
        // IRR未登録WARN(チェック4)をfix_actions付きで大量発生させる
        input.irr = Some(vec![]);
        let findings = crate::checks::run_checks(&input);
        let report = Report::build(&input, findings);
        assert!(
            report.fix_actions.len() > FIX_ACTIONS_DISPLAY_CAP,
            "got: {}",
            report.fix_actions.len()
        );
    }

    /// `check --demo --json` (AS64500) のトップレベルキー集合を固定する。
    #[tokio::test]
    async fn demo_json_top_level_keys_are_pinned() {
        use crate::checks::{collect, run_checks};
        use crate::sources::{fixture::FixtureSource, DataSource};
        use std::collections::BTreeSet;
        use std::sync::Arc;

        let src: Arc<dyn DataSource> = Arc::new(FixtureSource::new());
        let input = collect(src, 64500, 50).await.unwrap();
        let findings = run_checks(&input);
        let rep = Report::build(&input, findings);
        let v = serde_json::to_value(&rep).unwrap();
        let keys: BTreeSet<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        let expected: BTreeSet<&str> = [
            "announced_count",
            "asn",
            "coverage",
            "deductions",
            "findings",
            "fix_actions",
            "grade",
            "grade_comment",
            "holder",
            "ipv4_count",
            "ipv6_count",
            "irr_route_count",
            "notes",
            "rpki_checked",
            "score",
        ]
        .into_iter()
        .collect();
        assert_eq!(keys, expected);
    }
}
