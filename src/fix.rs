//! `ashealth fix` — 所見から修正オブジェクト (remediation artifact) を自動生成する。
//!
//! [`remediations`] が純粋関数として [`HealthInput`] + 所見リストから
//! [`Remediation`] のリストを導出し、`render_text` / `render_rpsl` / `render_json`
//! が 3 フォーマットに描画する。health report が「何がおかしいか」を示すのに対し、
//! fix は「正すために提出する現物」を生成する。

use crate::checks::{Finding, HealthInput, Severity};
use crate::sources::IrrRoute;
use serde::Serialize;

/// 生成するアーティファクトの種類。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ArtifactType {
    /// ROA 新規作成パラメータ
    RoaCreate,
    /// RPKI invalid 解消のための ROA 修正パラメータ (広報是正の選択肢付き)
    RoaFix,
    /// IRR route/route6 オブジェクトの新規作成 (RPSL)
    RpslCreate,
    /// IRR route/route6 オブジェクトの削除 (RPSL + delete 行)
    RpslDelete,
    /// 貼り付け対象のオブジェクトはないが、行うべきアクションがあるもの
    Advice,
}

impl ArtifactType {
    /// `--format rpsl` に含める (= 提出可能な RPSL オブジェクトである) か。
    pub fn is_rpsl(&self) -> bool {
        matches!(self, ArtifactType::RpslCreate | ArtifactType::RpslDelete)
    }
}

/// 1 所見に対する修正アーティファクト。
#[derive(Debug, Clone, Serialize)]
pub struct Remediation {
    pub finding: Finding,
    pub artifact_type: ArtifactType,
    /// 貼り付け可能な本文 (ROA パラメータ / RPSL オブジェクト)。Advice では None
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact: Option<String>,
    /// どこに・どうやって提出するか
    pub submission_hint: String,
    /// セクション見出し (text 描画用)
    #[serde(skip)]
    pub title: String,
    /// 補足説明の行 (text 描画用)
    #[serde(skip)]
    pub notes: Vec<String>,
}

/// ROA 申請先の一般的な案内 (AS 番号から RIR/NIR を推測せず、代表的な窓口を列挙する)。
const ROA_PORTAL_HINT: &str = "自ASのアドレスを管理するRIR/NIRのポータルで実施: JPNIC管理下なら「JPNIC Web公開DB/RPKIシステム」、APNIC直下なら「MyAPNIC」、RIPEなら「LIR Portal」等";

/// RADB への RPSL 提出方法の案内。
const RADB_SUBMIT_HINT: &str =
    "RADbポータル (radb.net) で登録、またはオブジェクトを auto-dbm@radb.net へメール送信。JPIRRを使う場合はJPNIC経由で申請";

/// プレフィックス文字列からプレフィックス長を取り出す ("192.0.2.0/24" → 24)。
pub fn prefix_len(prefix: &str) -> Option<u8> {
    let (addr, len) = prefix.split_once('/')?;
    let len: u8 = len.trim().parse().ok()?;
    let max = if addr.contains(':') { 128 } else { 32 };
    (len <= max).then_some(len)
}

/// ROA の推奨 maxLength = 現在広報しているプレフィックス長。
/// これより大きくすると、未広報の more-specific を第三者が origin 偽装で
/// 広報したときに valid になってしまう (forged-origin subprefix hijack)。
pub fn suggested_max_length(announced_prefix: &str) -> Option<u8> {
    prefix_len(announced_prefix)
}

/// ROA 作成/修正パラメータの貼り付け用テキスト。
fn roa_params(prefix: &str, origin: u32, max_length: Option<u8>) -> String {
    let ml = max_length
        .map(|m| m.to_string())
        .unwrap_or_else(|| "<広報プレフィックス長に合わせる>".to_string());
    format!("prefix:    {prefix}\norigin:    AS{origin}\nmaxLength: {ml}")
}

/// RPSL route/route6 オブジェクトを組み立てる。
///
/// - v4 は `route:`、v6 は `route6:` (RFC 4012 のオブジェクトクラス)
/// - `delete_reason` を与えると末尾に `delete:` 行を付けた削除申請オブジェクトになる
pub fn rpsl_route_object(
    prefix: &str,
    origin: u32,
    descr: &str,
    mnt_by: &str,
    source: &str,
    delete_reason: Option<&str>,
) -> String {
    let class = if prefix.contains(':') {
        "route6"
    } else {
        "route"
    };
    let attr = |key: &str, value: &str| format!("{:<12}{value}", format!("{key}:"));
    let mut lines = vec![
        attr(class, prefix),
        attr("descr", descr),
        attr("origin", &format!("AS{origin}")),
        attr("mnt-by", mnt_by),
        attr("source", source),
    ];
    if let Some(reason) = delete_reason {
        lines.push(attr("delete", reason));
    }
    lines.join("\n")
}

/// 修正の緊急度 (小さいほど先)。`fix` の並び順と `report` の最重要アクション選定で共有する。
/// (report.rs の減点ルール順と同じ思想)
///
/// report 側 (`report_cmd::worst_across`) では深刻度を先に比べ、同じ深刻度のときにこの優先度で選ぶ。
pub fn check_priority(check: &str) -> u8 {
    match check {
        "rpki-invalid" => 0,
        "roa-missing" => 1,
        "irr-missing" => 2,
        "irr-origin-conflict" => 3,
        "irr-stale" => 4,
        "roa-unused" => 5,
        _ => 6,
    }
}

/// 所見リストから修正アーティファクトを導出する (純粋関数)。
///
/// OK 所見は対象外。優先度順 (RPKI invalid → ROA未作成 → IRR未登録 →
/// origin不一致 → 陳腐化IRR → 未使用ROA → PeeringDB) に並べて返す。
pub fn remediations(input: &HealthInput, findings: &[Finding]) -> Vec<Remediation> {
    let asn = input.overview.asn;
    let mut out: Vec<Remediation> = findings
        .iter()
        .filter(|f| f.severity != Severity::Ok)
        .filter_map(|f| remediation_for(input, asn, f))
        .collect();
    out.sort_by(|a, b| {
        check_priority(a.finding.check)
            .cmp(&check_priority(b.finding.check))
            .then_with(|| a.finding.subject.cmp(&b.finding.subject))
    });
    out
}

fn remediation_for(input: &HealthInput, asn: u32, f: &Finding) -> Option<Remediation> {
    let subject = f.subject.as_deref().unwrap_or_default();
    match f.check {
        // ---- 1: ROA未作成 → ROA作成パラメータ --------------------------------
        "roa-missing" => Some(Remediation {
            finding: f.clone(),
            artifact_type: ArtifactType::RoaCreate,
            artifact: Some(roa_params(subject, asn, suggested_max_length(subject))),
            submission_hint: ROA_PORTAL_HINT.to_string(),
            title: format!("ROAを作成する — {subject}"),
            notes: vec![
                format!(
                    "推奨 maxLength = {} (現在の広報プレフィックス長)。",
                    suggested_max_length(subject)
                        .map(|m| format!("/{m}"))
                        .unwrap_or_else(|| "広報長".to_string())
                ),
                "maxLength を広報長より大きくしすぎないこと — 未広報の more-specific まで valid になり、forged-origin subprefix hijack の余地を作ります。".to_string(),
            ],
        }),

        // ---- 2: RPKI invalid → 不一致の提示 + 2つの修正パス【最優先】 ---------
        "rpki-invalid" => {
            let validation = input.rpki.get(subject);
            let roas = validation.map(|v| v.roas.as_slice()).unwrap_or_default();
            let announced_len = prefix_len(subject)
                .map(|l| format!("/{l}"))
                .unwrap_or_else(|| "?".to_string());
            let mut notes = vec![format!(
                "実際の広報   : {subject} (origin AS{asn}, 長さ {announced_len})"
            )];
            if roas.is_empty() {
                notes.push("カバーするROA: (検証データから取得できませんでした — RIR/NIRポータルで確認)".to_string());
            }
            for roa in roas {
                notes.push(format!(
                    "カバーするROA: {} → origin AS{}, maxLength /{}{}",
                    roa.prefix,
                    roa.origin,
                    roa.max_length,
                    if roa.origin != asn {
                        " (origin が広報と不一致)"
                    } else if prefix_len(subject).is_some_and(|l| l > roa.max_length) {
                        " (広報長が maxLength を超過)"
                    } else {
                        ""
                    }
                ));
            }
            notes.push("修正パスは2つ — 実態に合う方を選ぶ:".to_string());
            notes.push(
                "(a) ROAを修正する — この広報が正当なら、下のパラメータでROAを作り直す (旧ROAの削除も忘れずに)。".to_string(),
            );
            let other_origins: Vec<String> = roas
                .iter()
                .filter(|r| r.origin != asn)
                .map(|r| format!("AS{}", r.origin))
                .collect();
            notes.push(if other_origins.is_empty() {
                "(b) 広報を是正する — この広報が誤りなら、広報を停止するか prefix 長を maxLength 以内に収める。".to_string()
            } else {
                format!(
                    "(b) 広報を是正する — この広報が誤りなら、広報を停止するか、ROAが許可する {} から広報する。",
                    other_origins.join(", ")
                )
            });
            Some(Remediation {
                finding: f.clone(),
                artifact_type: ArtifactType::RoaFix,
                artifact: Some(roa_params(subject, asn, suggested_max_length(subject))),
                submission_hint: format!("{ROA_PORTAL_HINT}。ROV実施網で経路が破棄され続けるため最優先で対応"),
                title: format!("【最優先】RPKI invalid を解消する — {subject}"),
                notes,
            })
        }

        // ---- 4: IRR未登録 → 貼り付け可能な RPSL オブジェクト -------------------
        "irr-missing" => Some(Remediation {
            finding: f.clone(),
            artifact_type: ArtifactType::RpslCreate,
            artifact: Some(rpsl_route_object(
                subject,
                asn,
                "<YOUR-NETWORK-NAME>",
                "<YOUR-MAINTAINER>",
                "RADB",
                None,
            )),
            submission_hint: RADB_SUBMIT_HINT.to_string(),
            title: format!(
                "IRRに{}オブジェクトを作成する — {subject}",
                if subject.contains(':') {
                    "route6"
                } else {
                    "route"
                }
            ),
            notes: vec![
                "<YOUR-NETWORK-NAME> / <YOUR-MAINTAINER> を自組織の値に置き換えてください (mntnerが未作成ならまず maintainer オブジェクトを申請)。".to_string(),
            ],
        }),

        // ---- 5: 陳腐化IRR → delete 行付きの削除オブジェクト --------------------
        "irr-stale" => {
            let existing = irr_objects(input, |r| r.prefix == subject && r.origin == asn);
            let obj = existing.first()?;
            Some(Remediation {
                finding: f.clone(),
                artifact_type: ArtifactType::RpslDelete,
                artifact: Some(rpsl_route_object(
                    &obj.prefix,
                    obj.origin,
                    "<REGISTERED-DESCR>",
                    "<YOUR-MAINTAINER>",
                    &obj.source,
                    Some("no longer announced"),
                )),
                submission_hint: format!(
                    "{RADB_SUBMIT_HINT}。削除は登録済みオブジェクトと属性を完全一致させ、delete: 行を付けて提出する"
                ),
                title: format!("陳腐化したIRRオブジェクトを削除する — {subject} ({})", obj.source),
                notes: vec![
                    "今後また広報する予定があるなら削除せず維持してよい (その場合は広報を再開する)。".to_string(),
                    format!(
                        "<REGISTERED-DESCR> / <YOUR-MAINTAINER> は whois -h whois.radb.net {subject} で現物を確認して合わせる。"
                    ),
                ],
            })
        }

        // ---- 6: origin不一致 → 対立オブジェクトの並記 + 誤origin側の削除 --------
        "irr-origin-conflict" => {
            let objs = irr_objects(input, |r| r.prefix == subject);
            // 「現実」= 実際に広報されている origin。このASの広報一覧に含まれていれば asn が正
            let announced_by_us = input.announced.iter().any(|p| p == subject);
            let mut notes = vec!["登録されているオブジェクト:".to_string()];
            for o in &objs {
                notes.push(format!("  - {} → origin AS{} (source: {})", o.prefix, o.origin, o.source));
            }
            let wrong: Vec<&IrrRoute> = objs.iter().filter(|o| o.origin != asn).copied().collect();
            if announced_by_us {
                notes.push(format!(
                    "実際にこのプレフィックスを広報しているのは AS{asn} — AS{asn} のオブジェクトが現実と一致します。"
                ));
                notes.push(format!(
                    "対処: {} を削除 (または origin 修正) する。他者の mnt-by の proxy 登録は自分では消せないため、登録者かDB運営 (例: ALTDBなら db-admin) に削除を依頼する。",
                    wrong
                        .iter()
                        .map(|o| format!("AS{}({})", o.origin, o.source))
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            } else {
                notes.push(
                    "このプレフィックスは現在このASから広報されていません。実際の広報originを確認のうえ、一致しない側を削除してください。"
                        .to_string(),
                );
            }
            let artifact = wrong.first().map(|o| {
                rpsl_route_object(
                    &o.prefix,
                    o.origin,
                    "<REGISTERED-DESCR>",
                    "<OBJECT-MAINTAINER>",
                    &o.source,
                    Some("origin conflict; resolved to the announcing AS"),
                )
            });
            Some(Remediation {
                finding: f.clone(),
                artifact_type: if artifact.is_some() {
                    ArtifactType::RpslDelete
                } else {
                    ArtifactType::Advice
                },
                artifact,
                submission_hint: format!(
                    "{RADB_SUBMIT_HINT}。他者管理のオブジェクトは登録者・DB運営への削除依頼が必要"
                ),
                title: format!("IRRのorigin不一致を解消する — {subject}"),
                notes,
            })
        }

        // ---- 3: 未使用ROA → アクション1行 --------------------------------------
        "roa-unused" => Some(Remediation {
            finding: f.clone(),
            artifact_type: ArtifactType::Advice,
            artifact: None,
            submission_hint: ROA_PORTAL_HINT.to_string(),
            title: format!("未使用ROAを見直す — {subject}"),
            notes: vec![format!(
                "{subject} を今後も広報しないなら、RIR/NIRポータルでROAを削除する (放置すると移転先とのトラブルや誤用の元)。再広報の予定があるなら維持してよい。"
            )],
        }),

        // ---- 7: PeeringDB → アクション1行 --------------------------------------
        "peeringdb-missing" => Some(Remediation {
            finding: f.clone(),
            artifact_type: ArtifactType::Advice,
            artifact: None,
            submission_hint: "https://www.peeringdb.com/ でアカウントを作成し、組織に紐付けてnetレコードを登録する".to_string(),
            title: "PeeringDBにネットワークレコードを作成する".to_string(),
            notes: vec![format!(
                "AS{asn} のnetレコードを作成し、ピアリングポリシー・NOC/ピアリング連絡先・接続IXを記載する。"
            )],
        }),
        "peeringdb-incomplete" => Some(Remediation {
            finding: f.clone(),
            artifact_type: ArtifactType::Advice,
            artifact: None,
            submission_hint: "https://www.peeringdb.com/ の自組織netレコードを編集する".to_string(),
            title: "PeeringDBレコードの不足情報を埋める".to_string(),
            notes: vec![
                "IX接続・ピアリングポリシー・Webサイト/連絡先など、不足している項目を追記する。".to_string(),
            ],
        }),

        // OK 所見や未知の所見はアーティファクトなし
        _ => None,
    }
}

/// IRR オブジェクトのフィルタ取得 (irr が None なら空)。
fn irr_objects(input: &HealthInput, pred: impl Fn(&IrrRoute) -> bool) -> Vec<&IrrRoute> {
    input
        .irr
        .as_ref()
        .map(|v| v.iter().filter(|r| pred(r)).collect())
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// 描画
// ---------------------------------------------------------------------------

/// `--format text` : 人間向けの日本語レポート。
pub fn render_text(input: &HealthInput, rems: &[Remediation]) -> String {
    let asn = input.overview.asn;
    let mut out = String::new();
    let push = |out: &mut String, line: &str| {
        out.push_str(line);
        out.push('\n');
    };
    push(&mut out, "");
    push(
        &mut out,
        &format!("  ashealth fix ─ AS{asn} 修正オブジェクト"),
    );
    push(&mut out, &format!("  {}", "─".repeat(64)));
    push(
        &mut out,
        &format!("  対象   : AS{} ({})", asn, input.overview.holder),
    );
    if rems.is_empty() {
        push(
            &mut out,
            "  修正が必要な所見はありません — 4つの情報源は整合しています。",
        );
        push(&mut out, "");
        return out;
    }
    let rpsl_count = rems.iter().filter(|r| r.artifact_type.is_rpsl()).count();
    push(
        &mut out,
        &format!(
            "  生成   : 修正アーティファクト {}件 (うち貼り付け可能なRPSL {}件 — `--format rpsl` で単体出力)",
            rems.len(),
            rpsl_count
        ),
    );
    for (i, r) in rems.iter().enumerate() {
        push(&mut out, "");
        push(&mut out, &format!("  [{}] {}", i + 1, r.title));
        for note in &r.notes {
            push(&mut out, &format!("      {note}"));
        }
        if let Some(artifact) = &r.artifact {
            push(
                &mut out,
                "      ┌──────────────────────────────────────────",
            );
            for line in artifact.lines() {
                push(&mut out, &format!("      │ {line}"));
            }
            push(
                &mut out,
                "      └──────────────────────────────────────────",
            );
        }
        push(&mut out, &format!("      提出先: {}", r.submission_hint));
    }
    push(&mut out, "");
    out
}

/// `--format rpsl` : 貼り付け用 RPSL オブジェクトのみ (作成 + 削除)。
/// ファイルへのリダイレクトや auto-dbm へのメール本文にそのまま使える。
pub fn render_rpsl(rems: &[Remediation]) -> String {
    rems.iter()
        .filter(|r| r.artifact_type.is_rpsl())
        .filter_map(|r| r.artifact.as_deref())
        .collect::<Vec<_>>()
        .join("\n\n")
}

/// `--format json` : 構造化出力 [{finding, artifact_type, artifact, submission_hint}]。
pub fn render_json(rems: &[Remediation]) -> serde_json::Result<String> {
    serde_json::to_string_pretty(rems)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::{collect, run_checks};
    use crate::sources::{fixture::FixtureSource, DataSource};
    use std::sync::Arc;

    /// デモフィクスチャで全アーティファクトを生成する共通ヘルパ。
    async fn demo_remediations() -> (HealthInput, Vec<Remediation>) {
        let src: Arc<dyn DataSource> = Arc::new(FixtureSource::new());
        let input = collect(src, 64500, 50).await.unwrap();
        let findings = run_checks(&input);
        let rems = remediations(&input, &findings);
        (input, rems)
    }

    fn by_check<'a>(rems: &'a [Remediation], check: &str) -> Vec<&'a Remediation> {
        rems.iter().filter(|r| r.finding.check == check).collect()
    }

    #[tokio::test]
    async fn demo_fixture_generates_every_artifact_type() {
        let (_, rems) = demo_remediations().await;
        // 8所見 (FAIL x3 + WARN x5) すべてにアーティファクトが付く
        assert_eq!(rems.len(), 8);
        assert_eq!(by_check(&rems, "roa-missing").len(), 2);
        assert_eq!(by_check(&rems, "rpki-invalid").len(), 1);
        assert_eq!(by_check(&rems, "irr-missing").len(), 1);
        assert_eq!(by_check(&rems, "irr-stale").len(), 1);
        assert_eq!(by_check(&rems, "irr-origin-conflict").len(), 1);
        assert_eq!(by_check(&rems, "roa-unused").len(), 1);
        assert_eq!(by_check(&rems, "peeringdb-missing").len(), 1);
        // 全 ArtifactType が登場する
        for t in [
            ArtifactType::RoaCreate,
            ArtifactType::RoaFix,
            ArtifactType::RpslCreate,
            ArtifactType::RpslDelete,
            ArtifactType::Advice,
        ] {
            assert!(
                rems.iter().any(|r| r.artifact_type == t),
                "missing artifact type {t:?}"
            );
        }
    }

    #[tokio::test]
    async fn rpki_invalid_comes_first_and_shows_roa_mismatch() {
        let (_, rems) = demo_remediations().await;
        let first = &rems[0];
        assert_eq!(first.finding.check, "rpki-invalid");
        assert!(first.title.contains("【最優先】"));
        // カバーROA (AS64501, maxLength /24) と両修正パスが提示される
        let notes = first.notes.join("\n");
        assert!(
            notes.contains("origin AS64501"),
            "covering ROA origin: {notes}"
        );
        assert!(
            notes.contains("maxLength /24"),
            "covering ROA maxLength: {notes}"
        );
        assert!(notes.contains("(a) ROAを修正する"));
        assert!(notes.contains("(b) 広報を是正する"));
        assert!(notes.contains("AS64501 から広報する"));
        // 修正パス(a)の推奨パラメータは実際の広報に合わせる
        let artifact = first.artifact.as_deref().unwrap();
        assert!(artifact.contains("prefix:    203.0.113.0/24"));
        assert!(artifact.contains("origin:    AS64500"));
        assert!(artifact.contains("maxLength: 24"));
    }

    #[tokio::test]
    async fn roa_missing_suggests_announced_length_as_max_length() {
        let (_, rems) = demo_remediations().await;
        let v4 = by_check(&rems, "roa-missing")
            .into_iter()
            .find(|r| r.finding.subject.as_deref() == Some("198.51.100.0/24"))
            .unwrap()
            .clone();
        let artifact = v4.artifact.as_deref().unwrap();
        assert!(artifact.contains("origin:    AS64500"));
        assert!(artifact.contains("maxLength: 24"));
        assert!(v4.notes.iter().any(|n| n.contains("forged-origin")));
        // v6 側は /32
        let v6 = by_check(&rems, "roa-missing")
            .into_iter()
            .find(|r| r.finding.subject.as_deref() == Some("2001:db8::/32"))
            .unwrap()
            .clone();
        assert!(v6.artifact.as_deref().unwrap().contains("maxLength: 32"));
    }

    #[tokio::test]
    async fn irr_stale_produces_delete_object_from_parsed_whois() {
        let (_, rems) = demo_remediations().await;
        let stale = &by_check(&rems, "irr-stale")[0];
        assert_eq!(stale.artifact_type, ArtifactType::RpslDelete);
        let artifact = stale.artifact.as_deref().unwrap();
        assert!(artifact.contains("route:      203.0.113.128/25"));
        assert!(artifact.contains("origin:     AS64500"));
        assert!(artifact.contains("source:     RADB"));
        assert!(artifact.contains("delete:     no longer announced"));
    }

    #[tokio::test]
    async fn origin_conflict_targets_the_wrong_origin_object() {
        let (_, rems) = demo_remediations().await;
        let conflict = &by_check(&rems, "irr-origin-conflict")[0];
        assert_eq!(conflict.artifact_type, ArtifactType::RpslDelete);
        // 現実 = 広報中の AS64500。削除対象は ALTDB の AS64501 proxy 登録
        let artifact = conflict.artifact.as_deref().unwrap();
        assert!(artifact.contains("origin:     AS64501"));
        assert!(artifact.contains("source:     ALTDB"));
        assert!(artifact.contains("delete:"));
        let notes = conflict.notes.join("\n");
        assert!(notes.contains("実際にこのプレフィックスを広報しているのは AS64500"));
        assert!(notes.contains("AS64501(ALTDB)"));
    }

    #[tokio::test]
    async fn rpsl_format_contains_only_paste_ready_objects() {
        let (_, rems) = demo_remediations().await;
        let rpsl = render_rpsl(&rems);
        // 作成 (route: 198.51.100.0/24) と削除 (203.0.113.128/25, 192.0.2.0/24) を含む
        assert!(rpsl.contains("route:      198.51.100.0/24"));
        assert!(rpsl.contains("route:      203.0.113.128/25"));
        assert!(rpsl.contains("route:      192.0.2.0/24"));
        // ROAパラメータや日本語の説明は含まない
        assert!(!rpsl.contains("maxLength"));
        assert!(!rpsl.contains("提出先"));
        // オブジェクトは空行区切りで3つ
        assert_eq!(rpsl.split("\n\n").count(), 3);
    }

    #[tokio::test]
    async fn json_format_roundtrips_with_expected_fields() {
        let (_, rems) = demo_remediations().await;
        let json = render_json(&rems).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let arr = v.as_array().unwrap();
        assert_eq!(arr.len(), 8);
        for item in arr {
            assert!(item["finding"]["check"].is_string());
            assert!(item["artifact_type"].is_string());
            assert!(item["submission_hint"].is_string());
        }
        // kebab-case の artifact_type
        assert!(arr.iter().any(|i| i["artifact_type"] == "rpsl-delete"));
        assert!(arr.iter().any(|i| i["artifact_type"] == "roa-fix"));
    }

    #[tokio::test]
    async fn text_format_renders_sections_and_artifacts() {
        let (input, rems) = demo_remediations().await;
        let text = render_text(&input, &rems);
        assert!(text.contains("ashealth fix ─ AS64500 修正オブジェクト"));
        assert!(text.contains("[1] 【最優先】RPKI invalid を解消する — 203.0.113.0/24"));
        assert!(text.contains("│ route:      198.51.100.0/24"));
        assert!(text.contains("提出先:"));
    }

    #[test]
    fn healthy_findings_produce_no_remediations() {
        use crate::sources::{AsOverview, PeeringDbNet, RpkiStatus};
        use std::collections::BTreeMap;
        let input = HealthInput {
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
        };
        let findings = run_checks(&input);
        let rems = remediations(&input, &findings);
        assert!(rems.is_empty());
        let text = render_text(&input, &rems);
        assert!(text.contains("修正が必要な所見はありません"));
        assert_eq!(render_rpsl(&rems), "");
    }

    #[test]
    fn suggested_max_length_parses_v4_and_v6() {
        assert_eq!(suggested_max_length("198.51.100.0/24"), Some(24));
        assert_eq!(suggested_max_length("203.0.113.128/25"), Some(25));
        assert_eq!(suggested_max_length("2001:db8::/32"), Some(32));
        assert_eq!(suggested_max_length("2001:db8::/129"), None);
        assert_eq!(suggested_max_length("10.0.0.0/33"), None);
        assert_eq!(suggested_max_length("garbage"), None);
    }

    #[test]
    fn rpsl_v4_object_is_exactly_formatted() {
        let obj = rpsl_route_object(
            "198.51.100.0/24",
            64500,
            "<YOUR-NETWORK-NAME>",
            "<YOUR-MAINTAINER>",
            "RADB",
            None,
        );
        assert_eq!(
            obj,
            "route:      198.51.100.0/24\n\
             descr:      <YOUR-NETWORK-NAME>\n\
             origin:     AS64500\n\
             mnt-by:     <YOUR-MAINTAINER>\n\
             source:     RADB"
        );
    }

    #[test]
    fn rpsl_v6_object_uses_route6_class() {
        let obj = rpsl_route_object(
            "2001:db8::/32",
            64500,
            "<YOUR-NETWORK-NAME>",
            "<YOUR-MAINTAINER>",
            "RADB",
            None,
        );
        assert!(obj.starts_with("route6:     2001:db8::/32\n"));
        assert!(obj.contains("origin:     AS64500"));
    }

    #[test]
    fn rpsl_delete_appends_delete_attribute_last() {
        let obj = rpsl_route_object(
            "203.0.113.128/25",
            64500,
            "<REGISTERED-DESCR>",
            "<YOUR-MAINTAINER>",
            "RADB",
            Some("no longer announced"),
        );
        assert!(obj.ends_with("delete:     no longer announced"));
    }
}
