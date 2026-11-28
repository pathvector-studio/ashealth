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

    fn finding(check_no: u8, severity: Severity) -> Finding {
        Finding {
            check_no,
            check: "x",
            severity,
            subject: None,
            message: String::new(),
            fix: None,
        }
    }

    fn findings_of(check_no: u8, severity: Severity, n: usize) -> Vec<Finding> {
        (0..n).map(|_| finding(check_no, severity)).collect()
    }

    #[test]
    fn score_is_100_without_findings() {
        let (score, deductions) = compute_score(&[]);
        assert_eq!(score, 100);
        assert!(deductions.is_empty());
    }

    /// 各ルールの「1件あたりの減点」。(チェック番号, 重大度, 減点, ラベル)
    #[test]
    fn score_single_finding_deducts_per_rule_points() {
        let cases = [
            (2u8, Severity::Fail, 25, "RPKI invalidな広報"),
            (1, Severity::Fail, 10, "ROA未作成"),
            (4, Severity::Warn, 5, "IRR未登録"),
            (6, Severity::Warn, 5, "IRR origin不一致"),
            (5, Severity::Warn, 4, "陳腐化したIRRオブジェクト"),
            (3, Severity::Warn, 3, "未使用ROA"),
            (7, Severity::Warn, 10, "PeeringDB未登録"),
            (7, Severity::Info, 3, "PeeringDB情報不足"),
        ];
        for (no, sev, points, label) in cases {
            let (score, deductions) = compute_score(&[finding(no, sev)]);
            assert_eq!(score, 100 - points, "check {no} {sev:?}");
            assert_eq!(deductions.len(), 1, "check {no} {sev:?}");
            assert_eq!(deductions[0].label, label);
            assert_eq!(deductions[0].count, 1);
            assert_eq!(deductions[0].points, points);
        }
    }

    /// 各ルールの上限 (cap) ちょうどと、その1件手前・1件超過。
    #[test]
    fn score_deduction_is_capped_per_rule() {
        // (チェック番号, 重大度, 1件あたり, 上限)
        let cases = [
            (2u8, Severity::Fail, 25, 50),
            (1, Severity::Fail, 10, 30),
            (4, Severity::Warn, 5, 15),
            (6, Severity::Warn, 5, 10),
            (5, Severity::Warn, 4, 12),
            (3, Severity::Warn, 3, 9),
            (7, Severity::Warn, 10, 10),
            (7, Severity::Info, 3, 3),
        ];
        for (no, sev, per, cap) in cases {
            let to_cap = (cap / per) as usize;
            let (score, d) = compute_score(&findings_of(no, sev, to_cap));
            assert_eq!(score, 100 - cap, "cap ちょうど: check {no} {sev:?}");
            assert_eq!(d[0].points, cap);
            assert_eq!(d[0].count, to_cap);

            // 上限を超えても減点は増えず、count だけ増える
            let (score, d) = compute_score(&findings_of(no, sev, to_cap + 5));
            assert_eq!(score, 100 - cap, "cap 超過: check {no} {sev:?}");
            assert_eq!(d[0].points, cap);
            assert_eq!(d[0].count, to_cap + 5);
        }
    }

    /// 上限未満では減点は「件数 × 1件あたり」(陳腐化IRR: 4点/件 × 2件 = 8点)。
    #[test]
    fn score_below_cap_is_count_times_per() {
        let (score, d) = compute_score(&findings_of(5, Severity::Warn, 2));
        assert_eq!(score, 92);
        assert_eq!(d[0].points, 8);
        assert_eq!(d[0].count, 2);
    }

    #[test]
    fn score_sums_multiple_rules() {
        let mut findings = Vec::new();
        findings.extend(findings_of(2, Severity::Fail, 1)); // -25
        findings.extend(findings_of(1, Severity::Fail, 2)); // -20
        findings.extend(findings_of(4, Severity::Warn, 1)); // -5
        findings.extend(findings_of(7, Severity::Info, 1)); // -3
        let (score, d) = compute_score(&findings);
        assert_eq!(score, 100 - 25 - 20 - 5 - 3);
        assert_eq!(d.iter().map(|x| x.points).sum::<i32>(), 53);
        // 内訳の順序は RULES の順 (入力順ではない)
        let labels: Vec<&str> = d.iter().map(|x| x.label).collect();
        assert_eq!(
            labels,
            [
                "RPKI invalidな広報",
                "ROA未作成",
                "IRR未登録",
                "PeeringDB情報不足"
            ]
        );
    }

    /// 入力順を入れ替えても結果は同じ。
    #[test]
    fn score_is_independent_of_finding_order() {
        let a = vec![
            finding(4, Severity::Warn),
            finding(2, Severity::Fail),
            finding(7, Severity::Info),
        ];
        let mut b = a.clone();
        b.reverse();
        let (sa, da) = compute_score(&a);
        let (sb, db) = compute_score(&b);
        assert_eq!(sa, sb);
        let la: Vec<_> = da.iter().map(|x| (x.label, x.count, x.points)).collect();
        let lb: Vec<_> = db.iter().map(|x| (x.label, x.count, x.points)).collect();
        assert_eq!(la, lb);
    }

    /// 同一内容 (check_no・severity・subject・message が同じ) の所見も重複排除されず、
    /// 1件ずつ数えられる。
    #[test]
    fn score_counts_identical_findings_separately() {
        let mut f = finding(1, Severity::Fail);
        f.subject = Some("192.0.2.0/24".into());
        f.message = "same".into();
        let (score, d) = compute_score(&[f.clone(), f.clone()]);
        assert_eq!(score, 80);
        assert_eq!(d[0].count, 2);
        assert_eq!(d[0].points, 20);
    }

    /// Ok 所見はどのチェック番号でも減点されない。
    #[test]
    fn score_ignores_ok_findings() {
        let findings: Vec<Finding> = (1..=7u8)
            .flat_map(|no| findings_of(no, Severity::Ok, 3))
            .collect();
        let (score, d) = compute_score(&findings);
        assert_eq!(score, 100);
        assert!(d.is_empty());
    }

    /// (チェック番号, 重大度) が RULES に無い組み合わせは減点されない。
    #[test]
    fn score_ignores_unmatched_check_and_severity_pairs() {
        let mut findings = Vec::new();
        findings.extend(findings_of(2, Severity::Warn, 3)); // 2 は Fail のみ
        findings.extend(findings_of(1, Severity::Warn, 3)); // 1 は Fail のみ
        findings.extend(findings_of(4, Severity::Fail, 3)); // 4 は Warn のみ
        findings.extend(findings_of(3, Severity::Info, 3)); // 3 は Warn のみ
        findings.extend(findings_of(7, Severity::Fail, 3)); // 7 は Warn / Info のみ
        findings.extend(findings_of(0, Severity::Fail, 3)); // 範囲外のチェック番号
        findings.extend(findings_of(8, Severity::Warn, 3));
        let (score, d) = compute_score(&findings);
        assert_eq!(score, 100);
        assert!(d.is_empty());
    }

    /// チェック7は WARN と INFO が別ルールとして独立に集計される。
    #[test]
    fn score_check7_warn_and_info_are_separate_rules() {
        let mut findings = findings_of(7, Severity::Warn, 1);
        findings.extend(findings_of(7, Severity::Info, 2));
        let (score, d) = compute_score(&findings);
        assert_eq!(score, 100 - 10 - 3);
        assert_eq!(d.len(), 2);
        assert_eq!(
            (d[0].label, d[0].count, d[0].points),
            ("PeeringDB未登録", 1, 10)
        );
        assert_eq!(
            (d[1].label, d[1].count, d[1].points),
            ("PeeringDB情報不足", 2, 3)
        );
    }

    /// 全ルールの上限合計は 139 点で 100 を超えるため、スコアは 0 でクランプされる。
    /// 減点合計が 100 に達した時点でスコアは 0 になり、それ以上減点が増えても 0 のまま
    /// 下げ止まる (負にならない)。このとき `deductions` の内訳合計は 100 を超えうる。
    #[test]
    fn score_clamps_at_zero_and_never_negative() {
        let mut findings = Vec::new();
        findings.extend(findings_of(2, Severity::Fail, 2)); // -50
        findings.extend(findings_of(1, Severity::Fail, 3)); // -30
        findings.extend(findings_of(4, Severity::Warn, 3)); // -15
        let (score, _) = compute_score(&findings);
        assert_eq!(score, 5);

        findings.extend(findings_of(6, Severity::Warn, 1)); // -5 → ちょうど 0
        let (score, _) = compute_score(&findings);
        assert_eq!(score, 0);

        findings.extend(findings_of(6, Severity::Warn, 1)); // さらに -5 → 負にならず 0
        let (score, d) = compute_score(&findings);
        assert_eq!(score, 0);
        // 内訳の合計は 100 を超えうる (クランプされるのはスコアだけ)
        assert_eq!(d.iter().map(|x| x.points).sum::<i32>(), 105);
    }

    #[test]
    fn grade_covers_every_grade_at_thresholds() {
        let cases = [
            (100, 'A'),
            (99, 'A'),
            (90, 'A'),
            (89, 'B'),
            (75, 'B'),
            (74, 'C'),
            (60, 'C'),
            (59, 'D'),
            (40, 'D'),
            (39, 'E'),
            (1, 'E'),
            (0, 'E'),
        ];
        for (score, expected) in cases {
            assert_eq!(grade(score), expected, "score {score}");
        }
    }

    /// 範囲外 (compute_score は 0-100 を返すので通常は到達しない) の入力の現状の挙動:
    /// 負数は E、100 超も `90..=100` に入らず E になる。
    #[test]
    fn grade_out_of_range_scores_fall_to_e() {
        assert_eq!(grade(-1), 'E');
        assert_eq!(grade(i32::MIN), 'E');
        assert_eq!(grade(101), 'E');
        assert_eq!(grade(i32::MAX), 'E');
    }

    #[test]
    fn grade_comment_per_grade() {
        assert_eq!(
            grade_comment('A'),
            "良好 — 4つの情報源がきれいに揃っています"
        );
        assert_eq!(grade_comment('B'), "概ね良好 — 軽微なズレのみです");
        assert_eq!(grade_comment('C'), "要改善 — 情報源間のズレが目立ちます");
        assert_eq!(
            grade_comment('D'),
            "不健全 — ピアフィルタや到達性に影響しうる問題があります"
        );
        assert_eq!(
            grade_comment('E'),
            "危険 — 経路が破棄される深刻な問題があります。至急対応してください"
        );
    }

    /// A-E 以外の文字は E と同じ (最も深刻な) コメントになる。小文字も同様。
    #[test]
    fn grade_comment_unknown_char_falls_back_to_e_comment() {
        let e = grade_comment('E');
        assert_eq!(grade_comment('F'), e);
        assert_eq!(grade_comment('a'), e);
        assert_eq!(grade_comment('?'), e);
    }

    /// 各スコア境界で grade → grade_comment がつながり、隣のグレードと異なるコメントになる。
    #[test]
    fn grade_comment_follows_grade_boundaries() {
        assert_eq!(grade_comment(grade(90)), grade_comment('A'));
        assert_eq!(grade_comment(grade(89)), grade_comment('B'));
        assert_eq!(grade_comment(grade(75)), grade_comment('B'));
        assert_eq!(grade_comment(grade(74)), grade_comment('C'));
        assert_eq!(grade_comment(grade(60)), grade_comment('C'));
        assert_eq!(grade_comment(grade(59)), grade_comment('D'));
        assert_eq!(grade_comment(grade(40)), grade_comment('D'));
        assert_eq!(grade_comment(grade(39)), grade_comment('E'));
        assert_ne!(grade_comment('A'), grade_comment('B'));
        assert_ne!(grade_comment('B'), grade_comment('C'));
        assert_ne!(grade_comment('C'), grade_comment('D'));
        assert_ne!(grade_comment('D'), grade_comment('E'));
    }

    /// `severity_tag` は ANSI 装飾付き (太字 `ESC[1m` → 前景色 → 色リセット `ESC[39m` → `ESC[0m`) の
    /// 4文字ラベルを返す。
    /// OK は前後に空白を入れて4桁に揃える。
    #[test]
    fn severity_tag_per_severity() {
        assert_eq!(
            severity_tag(Severity::Ok),
            "\u{1b}[1m\u{1b}[32m OK \u{1b}[39m\u{1b}[0m"
        );
        assert_eq!(
            severity_tag(Severity::Info),
            "\u{1b}[1m\u{1b}[36mINFO\u{1b}[39m\u{1b}[0m"
        );
        assert_eq!(
            severity_tag(Severity::Warn),
            "\u{1b}[1m\u{1b}[33mWARN\u{1b}[39m\u{1b}[0m"
        );
        assert_eq!(
            severity_tag(Severity::Fail),
            "\u{1b}[1m\u{1b}[31mFAIL\u{1b}[39m\u{1b}[0m"
        );
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
