# ashealth — AS運用の健康診断

[English](README.md) | 日本語

小規模 AS 運用者(地域 ISP・ホスティング・大学ネットワークなど)向けの **予防的な経路衛生チェックツール** です。
AS 番号を 1 つ与えると、放っておくと必ずズレていく「4 つの情報源」を突き合わせ、
スコアと具体的な修正アクション付きの健康診断レポートを出力します。

リアルタイムのハイジャック検知(BGPalerter 等)が「救急医療」だとすれば、
ashealth は「定期健診」です。

## なぜ 4 つの情報源はズレるのか

| # | 情報源 | 実体 | ズレる典型的な理由 |
|---|--------|------|--------------------|
| 1 | BGP 広報 | いま実際にインターネットに流れている経路 | 新規プレフィックスの広報開始、返却・移転、広報停止 |
| 2 | RPKI ROA | RIR に登録した「この AS がこの prefix を広報してよい」という暗号署名付き宣言 | 広報を始めたのに ROA を作り忘れる / origin 変更や再分割で ROA が古いまま残る |
| 3 | IRR route オブジェクト | RADB・JPIRR 等に登録するルーティングポリシー DB | 昔の担当者が登録したまま放置 / 旧トランジット事業者による proxy 登録が残存 / DB 間で origin が食い違う |
| 4 | PeeringDB | ピアリングの連絡先・IX 接続情報のディレクトリ | そもそも未登録 / IX 増設やポリシー変更を反映していない |

これらは **登録主体も更新タイミングも別々** なので、運用を続けるほど自然にズレます。
そしてズレの代償は静かに現れます:

- ROA がない/invalid → ROV(RPKI Origin Validation)を実施する網から **経路ごと破棄** される
- IRR に route オブジェクトがない → IRR ベースでフィルタを生成するピア・トランジットに **経路を落とされる**
- 古い IRR/ROA の残存 → 移転先とのトラブルや、乗っ取り時の悪用余地
- PeeringDB 未整備 → ピアリング依頼の窓口がなく、機会損失

## インストール / ビルド

```
cargo build --release
# バイナリ: target/release/ashealth
```

## 使い方

```
# ライブ診断 (RIPEstat / PeeringDB / whois.radb.net に問い合わせ)
ashealth check <AS番号>              # 例: ashealth check AS64496
ashealth check <AS番号> --json       # JSONで全文出力
ashealth check <AS番号> --limit 100  # RPKI検証するprefix数の上限を変更 (既定50。0は指定不可)

# オフラインデモ (バンドルされた架空のAS64500フィクスチャを使用)
ashealth check --demo

# 修正オブジェクトの自動生成 (診断結果から提出用アーティファクトを作る)
ashealth fix <AS番号>                # 人間向けの日本語レポート (既定)
ashealth fix <AS番号> --format rpsl  # 貼り付け用RPSLオブジェクトのみ (> objects.txt でファイル化)
ashealth fix <AS番号> --format json  # 構造化JSON (自動化・他ツール連携向け)
ashealth fix <AS番号> --limit 100    # RPKI検証するprefix数の上限 (check と同じ。既定50)
ashealth fix --demo                  # フィクスチャ(AS64500)でデモ実行

# Web UI (フォームにAS番号を入れて診断。64500=不健全フィクスチャ / 64501=健全フィクスチャ、常時オフライン応答)
ashealth serve --port 8080
ashealth serve --port 8080 --rate-limit 10 --cache-ttl 600
ashealth serve --port 8080 --demo    # 完全オフラインデモモード。全ASNをフィクスチャ(AS64500)で応答、ライブAPIには一切アクセスしない
#   --port       : 待ち受けポート (既定8080)
#   --rate-limit : /api/check のIPあたり許可回数/分 (既定10、超過は429。0で無制限)
#   --cache-ttl  : 診断結果キャッシュの保持秒数 (既定600、0で無効)
#   --port が使用中の場合は「ポートNは使用中です。別の --port を指定してください」と案内して終了

# 複数ASダッシュボード (--config 指定時。詳細は下の「複数ASダッシュボード」章)
ashealth serve --port 8080 --config ~/.config/ashealth/config.toml

# 定期監視 (差分検知 + Webhook通知。cronなら --once、常駐なら interval ループ)
ashealth watch <AS番号> --interval 21600 --webhook https://discord.com/api/webhooks/...
ashealth watch <AS番号> --once       # 1回だけ比較・通知して終了 (cron向け)
ashealth watch --demo --once         # フィクスチャ(AS64500)で動作確認

# 複数AS管理 (設定ファイルで一括診断・一括監視。詳細は下の「複数AS管理」章)
ashealth check --config ~/.config/ashealth/config.toml
ashealth watch --config ~/.config/ashealth/config.toml --once
ashealth check --config --demo        # パス省略時は既定の配置場所 (~/.config/ashealth/config.toml)

# 定期サマリレポート (前回report比のスコア差分・トレンド・上位所見。詳細は下の「定期サマリレポート」章)
ashealth report --config ~/.config/ashealth/config.toml
ashealth report --config --webhook https://discord.com/api/webhooks/... --json
ashealth report --config --demo        # フィクスチャ(AS64500/AS64501)で動作確認
```

## AS番号の検証

診断対象のAS番号は、実運用上意味を持つASNかどうかを事前にチェックします(AS番号を引数で指定した
`check` / `fix` / `watch` のライブ実行、および `serve` の `/api/check/{asn}`)。`--config` による複数AS経路
(`check --config` / `watch --config` / `report`)では、設定ファイル内のAS番号に対してこの検証は行いません
(AS番号の値について設定ファイル読み込み時に拒否するのは `asn = 0` のみで、重複も拒否します)。
`serve --config` のダッシュボードの一覧表示(と `/api/summary`)は設定内のAS番号を検証せずに表示しますが、
各行のチェックリンクは `/api/check/{asn}` を通るため、後述の `serve` の検証が適用されます。
CLI の `--demo` 実行時はこの検証をスキップします
(バンドルされたフィクスチャ AS64500/AS64501 自体がドキュメント用予約帯に属するため)。`serve --demo` では
予約帯は許可しますが、`AS0` / `AS23456` は引き続き拒否します。

- **拒否 (エラー終了 / HTTP 400)**: `AS0`(RFC 7607 — 経路のnull origin表現専用)、
  `AS23456`(AS_TRANS、RFC 6793 — 32bit AS番号を16bit経由網に通すためのプレースホルダ)。
  これらは実運用ASとして存在しえず、診断結果が無意味になるため常に拒否します。
- **警告 (実行は継続)**: ドキュメント用 (RFC 5398: `64496`-`64511`)・16bit private-use/予約
  (RFC 6996 / RFC 7300: `64512`-`65534`, `65535`)・32bit private-use/予約
  (RFC 6996 / RFC 7300: `4200000000`-`4294967294`, `4294967295`) の各帯は、標準エラー出力に
  日本語の警告(「インターネット上で広報される実運用ASNではないため、診断結果は意味を持たない
  可能性があります」)を出したうえで実行を継続します。`serve` の場合はこの警告がそのままHTTP 400
  のエラーメッセージになります(「壊れた結果を返すよりは明示的に拒否する」方針)。ただしフィクスチャの
  AS64500/AS64501 は `serve` でも常に許可されます。

```
ashealth check AS0        # → エラー: AS0 は実運用のAS番号として使用できません (RFC 7607: ...)
ashealth check AS23456    # → エラー: AS23456 は実運用のAS番号ではありません (RFC 6793: ...)
ashealth check AS64500    # → 警告を標準エラーに出しつつ実行 (フィクスチャと同じ帯だが実ASとして診断可能)
```

## チェック一覧

| # | チェック内容 | 判定 | 意味 |
|---|--------------|------|------|
| 1 | 広報中プレフィックスにカバーする ROA がない | **FAIL** | ROA 未作成。ROV 網で不利になる |
| 2 | 広報が RPKI invalid (origin / maxLength 不一致) | **FAIL** | 最も危険。ROV 網から経路が破棄される |
| 3 | 広報していないプレフィックスに ROA が残っている | WARN | 古い ROA の可能性(IRR 登録プレフィックスからの推定) |
| 4 | 広報中プレフィックスに IRR route/route6 オブジェクトがない | WARN | IRR ベースのピアフィルタで経路が落ちる可能性 |
| 5 | IRR にあるのに広報されていない route オブジェクト | WARN | 陳腐化した IRR オブジェクト |
| 6 | 同一プレフィックスの origin が IRR DB 間で食い違う | WARN | フィルタ生成が不安定になる(proxy 登録の残骸など) |
| 7 | PeeringDB レコードがない / 情報不足 | WARN / INFO | ピアリング窓口の欠如 / IX・ポリシー未記載 |

## スコア計算式

100 点満点から、チェックごとに「1 件あたりの減点 × 件数(上限あり)」を差し引きます。

| チェック | 減点/件 | 上限 |
|----------|---------|------|
| 2: RPKI invalid な広報 | -25 | -50 |
| 1: ROA 未作成 | -10 | -30 |
| 4: IRR 未登録 | -5 | -15 |
| 6: IRR origin 不一致 | -5 | -10 |
| 5: 陳腐化した IRR オブジェクト | -4 | -12 |
| 3: 未使用 ROA | -3 | -9 |
| 7: PeeringDB 未登録 | -10 | -10 |
| 7: PeeringDB 情報不足 | -3 | -3 |

グレード: **A** (90+) / **B** (75+) / **C** (60+) / **D** (40+) / **E** (40 未満)。下限は 0 点。

## RPKI検証のサンプリングと被覆状況 (`--limit`)

大規模ASでは広報プレフィックス数がRIPEstatへの配慮上の上限 (`--limit`、既定50) を超えることがあります。
超過分はRPKI検証(チェック1・2)をスキップするため、**スコア・グレードは実際には「検査できた範囲内での
推定値」**になります。未検査分にFAIL所見(ROA未作成・RPKI invalid)が潜んでいる可能性があるため、以下の
仕組みで打ち切りを常に可視化します:

- **ターミナル出力**: 被覆が不完全なとき、スコア行の直前に警告(`⚠ RPKI検証は広報186件中20件のみ
  (--limit) — 未検査分にFAIL所見が潜んでいる可能性があります`)を表示し、グレード自体にも
  `(推定 — 20/186プレフィックス検査)` という注記が付きます。RPKI由来の減点内訳(ROA未作成 /
  RPKI invalid)にも検査件数の分母を明記します。
- **JSON出力**: `coverage: {announced, checked, complete}` オブジェクトを追加。`complete: false`
  なら自動化パイプライン側でもサンプリングされたことを機械的に検出できます。
- **`--limit 0` は指定できません**。`0` は「RPKI検証を全件スキップ」を意味してしまい、ROA未作成・
  RPKI invalidのFAIL所見をすべて握りつぶしてスコアを不当に押し上げます(実例: 本来28点/グレードEの
  ASが `--limit 0` では73点/グレードC相当に見えてしまう)。件数を絞りたい場合は1以上の値を指定してください。

## 大規模ASでの出力の絞り込み

所見数が多いAS(陳腐化IRRオブジェクトが数十件など)では、ターミナル出力が「ノイズの壁」になるのを防ぐため:

- 各チェックセクションの表示は先頭10件まで(超過時は見出しに `(N件)`、末尾に `… 他N件は --json で確認してください`)
- 修正アクション一覧も先頭10件まで、同様に折りたたみ表示
- 同一チェック種別の所見はセクション単位でまとまるため件数の傾向がひと目で分かる
- **`--json` 出力は常に全件を含みます**(`findings` / `fix_actions` とも切り詰めなし)。自動化・詳細確認には `--json` を使ってください

## サンプル出力 (`ashealth check --demo`)

架空の AS64500 に「ROA 未作成 ×2、RPKI invalid ×1、陳腐化 IRR ×1、origin 不一致 ×1、PeeringDB 未登録」を仕込んだフィクスチャでの実出力:

```
  ashealth ─ AS64500 健康診断レポート
  ────────────────────────────────────────────────────────────────
  対象     : AS64500 (EXAMPLE-NET Example Internet Services)
  広報経路 : 4 prefixes (IPv4 3 / IPv6 1) — RPKI検証 4件
  IRR      : route/route6 オブジェクト 5件 (whois.radb.net)

  [1] ROAカバレッジ — 広報中プレフィックスにROAはあるか
    FAIL 198.51.100.0/24 — ROA未作成 — このプレフィックスをカバーするROAが存在せず、RPKI的に保護されていません
    FAIL 2001:db8::/32 — ROA未作成 — このプレフィックスをカバーするROAが存在せず、RPKI的に保護されていません

  [2] RPKI検証 — invalidな広報はないか
    FAIL 203.0.113.0/24 — RPKI invalid (invalid_asn) — ROV実施ネットワークからこの経路は破棄されます【最優先】

  [3] 未使用ROA — 広報していないのにROAだけ残っていないか
    WARN 203.0.113.128/25 — 広報していないプレフィックスにROAが存在します (古い設定の可能性)

  [4] IRR登録 — route/route6オブジェクトはあるか
    WARN 198.51.100.0/24 — IRR未登録 — route/route6オブジェクトがなく、IRRベースのピアフィルタで経路が落ちる可能性があります

  [5] IRR陳腐化 — 広報していないrouteオブジェクトはないか
    WARN 203.0.113.128/25 — 陳腐化したIRRオブジェクト — RADB に登録がありますが現在広報されていません

  [6] IRR origin整合性 — DB間でoriginが食い違っていないか
    WARN 192.0.2.0/24 — originが不一致: AS64500(RADB), AS64501(ALTDB) — ピアのフィルタ生成が不安定になります

  [7] PeeringDB登録
    WARN PeeringDBにレコードがありません — ピアリング依頼の受付窓口が存在しない状態です

  ────────────────────────────────────────────────────────────────
  総合スコア: 28 / 100   グレード: E
  危険 — 経路が破棄される深刻な問題があります。至急対応してください

  減点内訳:
    -25  RPKI invalidな広報 × 1件
    -20  ROA未作成 × 2件
    -5   IRR未登録 × 1件
    -5   IRR origin不一致 × 1件
    -4   陳腐化したIRRオブジェクト × 1件
    -3   未使用ROA × 1件
    -10  PeeringDB未登録 × 1件

  修正アクション (優先度順):
    1. 203.0.113.0/24 のROA (origin/maxLength) と実際の広報の不一致を解消する。ROAの修正または広報の是正を直ちに行う
    2. RIRのポータル(JPNIC/APNIC/RIPE NCC等)で 198.51.100.0/24 のROAを作成する (origin AS64500, maxLengthは広報長に合わせる)
    3. RIRのポータル(JPNIC/APNIC/RIPE NCC等)で 2001:db8::/32 のROAを作成する (origin AS64500, maxLengthは広報長に合わせる)
    4. RADBまたは自RIRのIRRに 198.51.100.0/24 (origin: AS64500) のroute/route6オブジェクトを作成する
    5. 192.0.2.0/24 の正しいorigin ASを確認し、食い違っているDB側のオブジェクト(多くは他者のproxy登録)を削除・修正依頼する
    6. 203.0.113.128/25 を今後も広報しないなら、RADB のroute/route6オブジェクトを削除する
    7. 203.0.113.128/25 を今後も広報しないなら、誤用防止のためROAの削除(または見直し)を検討する
    8. peeringdb.com でAS64500のネットワークレコードを作成する (ポリシー・連絡先・IX情報を記載)
```

実在の AS に対しても同様に実行できます(結果の公開は各自の判断で)。
なお大規模 AS では歴史的経緯による IRR の残骸が大量に検出されがちなため、WARN 系は上限つき減点になっています。

## 修正オブジェクトの自動生成 (`ashealth fix`)

`check` が「何がおかしいか」を示すのに対し、`fix` は **正すために提出する現物** を生成します。
所見ごとに ROA 申請パラメータ・貼り付け可能な RPSL route/route6 オブジェクト(作成/削除)・提出先の案内を出力します。

- ROA の推奨 maxLength は **現在広報しているプレフィックス長** に合わせます(maxLength を広報長より大きくすると、未広報の more-specific が origin 偽装で valid になる forged-origin subprefix hijack の余地を作るため)
- RPKI invalid には「実際の広報 vs カバーする ROA (origin / maxLength)」の不一致を並記し、**(a) ROA を修正 / (b) 広報を是正** の両パスを提示します
- 陳腐化 IRR・origin 不一致には `delete:` 行付きの削除オブジェクトを生成します

### サンプル出力 (`ashealth fix --demo`) — 抜粋

```
  ashealth fix ─ AS64500 修正オブジェクト
  ────────────────────────────────────────────────────────────────
  対象   : AS64500 (EXAMPLE-NET Example Internet Services)
  生成   : 修正アーティファクト 8件 (うち貼り付け可能なRPSL 3件 — `--format rpsl` で単体出力)

  [1] 【最優先】RPKI invalid を解消する — 203.0.113.0/24
      実際の広報   : 203.0.113.0/24 (origin AS64500, 長さ /24)
      カバーするROA: 203.0.113.0/24 → origin AS64501, maxLength /24 (origin が広報と不一致)
      修正パスは2つ — 実態に合う方を選ぶ:
      (a) ROAを修正する — この広報が正当なら、下のパラメータでROAを作り直す (旧ROAの削除も忘れずに)。
      (b) 広報を是正する — この広報が誤りなら、広報を停止するか、ROAが許可する AS64501 から広報する。
      ┌──────────────────────────────────────────
      │ prefix:    203.0.113.0/24
      │ origin:    AS64500
      │ maxLength: 24
      └──────────────────────────────────────────
      提出先: 自ASのアドレスを管理するRIR/NIRのポータルで実施: JPNIC管理下なら「JPNIC Web公開DB/RPKIシステム」、APNIC直下なら「MyAPNIC」、RIPEなら「LIR Portal」等。ROV実施網で経路が破棄され続けるため最優先で対応

  [2] ROAを作成する — 198.51.100.0/24
      推奨 maxLength = /24 (現在の広報プレフィックス長)。
      maxLength を広報長より大きくしすぎないこと — 未広報の more-specific まで valid になり、forged-origin subprefix hijack の余地を作ります。
      ┌──────────────────────────────────────────
      │ prefix:    198.51.100.0/24
      │ origin:    AS64500
      │ maxLength: 24
      └──────────────────────────────────────────
      提出先: 自ASのアドレスを管理するRIR/NIRのポータルで実施: JPNIC管理下なら「JPNIC Web公開DB/RPKIシステム」、APNIC直下なら「MyAPNIC」、RIPEなら「LIR Portal」等

  [4] IRRにrouteオブジェクトを作成する — 198.51.100.0/24
      <YOUR-NETWORK-NAME> / <YOUR-MAINTAINER> を自組織の値に置き換えてください (mntnerが未作成ならまず maintainer オブジェクトを申請)。
      ┌──────────────────────────────────────────
      │ route:      198.51.100.0/24
      │ descr:      <YOUR-NETWORK-NAME>
      │ origin:     AS64500
      │ mnt-by:     <YOUR-MAINTAINER>
      │ source:     RADB
      └──────────────────────────────────────────
      提出先: RADbポータル (radb.net) で登録、またはオブジェクトを auto-dbm@radb.net へメール送信。JPIRRを使う場合はJPNIC経由で申請

  [6] 陳腐化したIRRオブジェクトを削除する — 203.0.113.128/25 (RADB)
      今後また広報する予定があるなら削除せず維持してよい (その場合は広報を再開する)。
      <REGISTERED-DESCR> / <YOUR-MAINTAINER> は whois -h whois.radb.net 203.0.113.128/25 で現物を確認して合わせる。
      ┌──────────────────────────────────────────
      │ route:      203.0.113.128/25
      │ descr:      <REGISTERED-DESCR>
      │ origin:     AS64500
      │ mnt-by:     <YOUR-MAINTAINER>
      │ source:     RADB
      │ delete:     no longer announced
      └──────────────────────────────────────────
      提出先: RADbポータル (radb.net) で登録、またはオブジェクトを auto-dbm@radb.net へメール送信。JPIRRを使う場合はJPNIC経由で申請。削除は登録済みオブジェクトと属性を完全一致させ、delete: 行を付けて提出する
```

(実際の出力には ROA 作成 (IPv6)、IRR origin 不一致の解消、未使用 ROA の見直し、PeeringDB 登録の各セクションも含まれます)

### RPSL のみの出力 (`ashealth fix --demo --format rpsl`)

作成 + 削除の RPSL オブジェクトだけを空行区切りで出力します。そのままファイルや auto-dbm 宛メール本文にできます:

```
route:      198.51.100.0/24
descr:      <YOUR-NETWORK-NAME>
origin:     AS64500
mnt-by:     <YOUR-MAINTAINER>
source:     RADB

route:      192.0.2.0/24
descr:      <REGISTERED-DESCR>
origin:     AS64501
mnt-by:     <OBJECT-MAINTAINER>
source:     ALTDB
delete:     origin conflict; resolved to the announcing AS

route:      203.0.113.128/25
descr:      <REGISTERED-DESCR>
origin:     AS64500
mnt-by:     <YOUR-MAINTAINER>
source:     RADB
delete:     no longer announced
```

`--format json` は `[{finding, artifact_type, artifact, submission_hint}]` の構造化配列を返します
(`artifact_type`: `roa-create` / `roa-fix` / `rpsl-create` / `rpsl-delete` / `advice`)。

## アーキテクチャ

```
src/
├── main.rs            CLI (clap) — check / fix / serve / watch / report サブコマンド
├── config.rs          複数AS管理用の設定ファイル (config.toml) のパース・検証
├── multi.rs           check --config / watch --config — 複数ASの一括診断・監視
├── checks.rs          collect(): DataSource → HealthInput / run_checks(): 純粋なチェックロジック
├── fix.rs             remediations(): 所見 → 修正アーティファクト (ROAパラメータ/RPSL) + text/rpsl/json描画
├── report.rs          スコア計算・減点内訳・ターミナル/JSONレポート (単体AS診断の描画)
├── report_cmd.rs       report サブコマンド — 前回report比の差分・履歴トレンド・上位所見・Webhook通知
├── server.rs          axum Webサーバ (GET /, GET /api/check/{asn}, GET /api/summary) +
│                       IP別レートリミット + 結果キャッシュ + --config時の複数ASダッシュボード
├── watch.rs           watchサブコマンド — 前回結果との差分検知・状態ファイル永続化(スコア履歴含む)・Webhook通知
└── sources/
    ├── mod.rs         trait DataSource + LiveSource (実API実装)
    ├── ripestat.rs    RIPEstat Data API (announced-prefixes / rpki-validation / as-overview)
    ├── peeringdb.rs   PeeringDB REST API (net?asn=...&depth=2)
    ├── irr.rs         whois.radb.net:43 への生whois (-i origin ASxxxx) + パーサ
    └── fixture.rs     FixtureSource — fixtures/ の応答を返す (--demo / 単体テスト)
static/index.html      埋め込み単一ページUI (ビルド不要のプレーンJS。--config無し時のトップページ)
fixtures/as64500/      不健全な架空ASのデモ用フィクスチャ (スコア28点・グレードE)
fixtures/as64501/      健全な架空ASのデモ用フィクスチャ (スコア100点・グレードA)
examples/config.example.toml  複数AS管理設定ファイルのサンプル
```

設計のポイント:

- **フェッチとチェックの分離** — `collect()` が入力 (`HealthInput`) を組み立て、`run_checks()` と
  `fix::remediations()` は純粋関数。チェック・修正生成ロジックはネットワークなしで単体テスト可能
  (`cargo test` で 100+ テスト)。
- **`DataSource` トレイト** — `LiveSource` と `FixtureSource` を差し替えるだけで
  CLI・Web・テストのすべてが同じコードパスを通る。`FixtureSource` は要求ASN用のフィクスチャが
  あればそれを、なければ AS64500 のフィクスチャにフォールバックする。
- **API への配慮** — RPKI 検証は既定で先頭 50 prefix に制限(`--limit` で変更可)。
  RIPEstat には `sourceapp=ashealth` を付与。複数AS診断・監視 (`--config`) では並列化せず、
  AS間に1秒の休止を挟む。
- **フォールバック** — IRR や PeeringDB の取得に失敗した場合は該当チェックをスキップし、
  注記を添えて残りの診断を継続する。
- **状態ファイルは `watch` と `report` で共有** — 同じ `asXXXX.json` にスコア履歴 (`history`,
  直近90件FIFO) と `last_report_at` を持たせることで、両コマンドが同じ状態を独立した視点
  (「前サイクル比」 vs 「前report比」)で使い分けられる。旧バージョンの状態ファイル
  (履歴フィールド無し) も `serde` のデフォルト値で問題なく読み込める。`--demo` 時は
  `demo/` サブディレクトリに分離し、実運用の状態を汚染しない (`watch::default_state_path_for()`)。
- **Webhookクライアントの共通化** — `watch::post_webhook_json()` を `report` からも再利用し、
  Discord互換の `content` フィールド運用を1箇所に集約している。
- **ASN検証は1箇所に集約** — `validate_asn()` (main.rs) がAS0/AS23456の拒否と予約帯の警告を
  純粋関数として提供し、CLI (`validate_asn_or_warn`) と `serve` (`server::validate_asn_for_serve`)
  の両方から呼ばれる。判定ロジックの重複を避け、どちらの経路でも同じ基準・同じ日本語文言になる。
- **サンプリングの可視性** — `report::Coverage` が「広報数 vs 検査数」を `Report` に常に含めることで、
  `--limit` による打ち切りをターミナル表示・JSON出力の両方で一貫して可視化する。

## 既知の制限

- チェック 3(未使用 ROA)は、RIPEstat に「AS 単位の ROA 一覧」API がないため、
  **IRR に登録があるのに広報されていないプレフィックス** に対して ROA の有無を照会する近似実装です
  (IRR にも載っていない純粋な放置 ROA は検出できません)。
- チェック 4 は「同一 origin の route オブジェクトが exact match または less-specific でカバーしていれば OK」、
  チェック 5 は「exact match の広報がなければ陳腐化」という基準です(more-specific 広報の扱いは簡略化)。
- RPKI 検証は RIPEstat のバリデータ(routinator)のスナップショットに依存します。

## 定期監視 (`ashealth watch`)

`watch` は check を定期実行し、**前回結果との差分**(新規所見 / 解消所見 / スコア変化)を検出します。

- 所見の同一性は「チェック種別 + プレフィックス + 深刻度」で判定
- 状態は既定で `asXXXX.json` に永続化(`$XDG_STATE_HOME` が設定されていれば `$XDG_STATE_HOME/ashealth/`、未設定なら `~/.local/state/ashealth/` 配下)。`--state <path>` で変更可(`watch <ASN>` ではファイルそのもの、`--config` 使用時はディレクトリ)
  - **`--demo` 実行時は `~/.local/state/ashealth/demo/asXXXX.json`**(`demo/` サブディレクトリ)に書きます。
    デモを何度も試した結果が実運用の監視状態・スコア履歴に混ざらないようにするためです。`--state` で
    明示的にパスを指定した場合はそちらが優先されます
- 変化があったとき(および初回)に `--webhook` の URL へ JSON を POST
  - ペイロード: `{"asn":..., "score":..., "grade":..., "new":[...], "resolved":[...], "summary":"..."}`
  - あわせて日本語1行サマリの `content` フィールドを含むため、**Discord の Webhook URL をそのまま指定するだけで通知が届きます**
- `--once` で1サイクルだけ実行して終了(cron / systemd timer 向け)。指定しなければ `--interval` 秒(既定 21600 = 6時間)ごとにループ(`--config` 使用時は設定ファイルの `interval` を使い、`--interval` は使われません)
- `--limit` でRPKI検証するprefix数の上限を変更可(既定 50。`check` と同じ。`--config` 使用時は設定ファイルの `limit` を使います)

## 複数AS管理 (`--config`)

複数のASを運用している場合、設定ファイルに列挙して `check` / `watch` を1コマンドで一括実行できます。
既定の配置場所は `~/.config/ashealth/config.toml`(`XDG_CONFIG_HOME` があればそちら)。
サンプルは [examples/config.example.toml](examples/config.example.toml) を参照してください。

```toml
# ~/.config/ashealth/config.toml
[defaults]
interval = 21600          # watch間隔 (秒)。既定 21600 = 6時間
webhook = "https://discord.com/api/webhooks/xxxxxxxx/yyyyyyyy"   # 省略可
limit = 50                # RPKI検証プレフィックス上限。既定 50

[[as]]
asn = 64500
name = "本番AS"           # 表示用ラベル (省略時 "AS64500")
webhook = "https://discord.com/api/webhooks/xxxxxxxx/prod-channel"  # per-AS override (省略時 defaults)

[[as]]
asn = 64501
name = "検証AS"
```

優先順位は **AS個別設定 > defaults > 組み込み既定値**。`asn` は必須・重複不可で、
不正な設定は日本語のエラーメッセージで理由を示して起動時に弾かれます。

### `--config` と `--demo` の組み合わせ

`check` / `watch` / `report` / `serve` はいずれも `--config --demo` を受け付けます。
**設定ファイルが実際に存在する場合はその内容をそのまま使い**(明示的な設定を優先)、
**存在しない場合はバンドルされたフィクスチャ2AS(AS64500/AS64501)のインメモリ設定を
自動的に合成します**。設定ファイルを一切用意していない環境でも、複数AS向けコマンドを
そのままデモできます。

```
ashealth check --config --demo    # 設定ファイル未作成でもAS64500/AS64501の2ASを一括診断
ashealth report --config --demo   # 同様に定期サマリレポートをデモ実行
ashealth serve --config --demo    # 同様にダッシュボードをデモ表示
```

### `check --config`

設定内の全ASを順にチェックし(RIPEstat への配慮として並列化せず、AS間に1秒休止)、
1AS1行のサマリ → スコア昇順(悪い順)の一覧テーブル → 合計、の順で出力します。

```
ashealth check --config ~/.config/ashealth/config.toml
ashealth check --config                # パス省略時は既定の配置場所を使用
ashealth check --config <path> --json  # 各ASのレポートをJSON配列で出力
```

出力例(バンドルされたフィクスチャ AS64500・AS64501 で `--demo` 実行した場合):

```
  本番AS         AS64500    スコア  28点 グレードE  (FAIL 3件 / WARN 5件)
  検証AS         AS64501    スコア 100点 グレードA  (FAIL 0件 / WARN 0件)

  ashealth ─ 複数AS健康診断サマリ (worst-first)
  ────────────────────────────────────────────────────────────────
  本番AS         AS64500    スコア  28点 グレードE  (FAIL 3件 / WARN 5件)
  検証AS         AS64501    スコア 100点 グレードA  (FAIL 0件 / WARN 0件)
  ────────────────────────────────────────────────────────────────
  合計 2 AS を診断 — 平均スコア 64点
```

### `watch --config`

設定内の全ASを毎サイクル監視します。状態ファイルは既存の `watch <ASN>` と同じくAS単位
(`--state` にディレクトリを指定するとその配下に `asXXXX.json` を作成)。差分検知・Webhook通知の
ロジックは単体AS監視と共通です。ASごとのWebhook上書きも設定どおりに使われます。

```
ashealth watch --config ~/.config/ashealth/config.toml --once   # cron向け: 1サイクルで終了
ashealth watch --config                                          # 常駐: config.toml の interval でループ
```

cron 例(6時間ごとに複数ASをまとめて監視):

```cron
0 */6 * * * /usr/local/bin/ashealth watch --config --once >> /var/log/ashealth.log 2>&1
```

## 定期サマリレポート (`ashealth report`)

`watch` が「前サイクルとの差分」を追いかけるのに対し、`report` は運用者向けの
**定期サマリ**(週次・月次のダイジェスト)です。各ASについて:

- 現在のスコア / グレード / FAIL・WARN件数
- **前回 `report` 実行からのスコア差分**(`↑+12` / `↓-5` / `±0` / 初回report時は「初回」)
- 直近4回分のスコア推移("トレンド": 例 `28 → 35 → 45 → 79`)
- 深刻度順(FAIL→WARN→INFO)の上位3所見

を1AS1ブロックで出力し、先頭に **対象AS数・平均スコア・全AS中もっとも深刻な所見(最重要アクション)**
をまとめたヘッダを付けます。`--config` が必須です(単体AS向けの入力はありません)。

```
ashealth report --config ~/.config/ashealth/config.toml
ashealth report --config                                  # パス省略時は既定の配置場所
ashealth report --config <path> --json                    # 構造化JSONで出力 (自動化向け)
ashealth report --config <path> --webhook <URL>           # 完了後にDiscord Webhook互換payloadをPOST
```

状態ファイルは `watch` と共有(`asXXXX.json`。既定の置き場所は、`$XDG_STATE_HOME` が設定されていれば
`$XDG_STATE_HOME/ashealth/`、未設定なら `~/.local/state/ashealth/`。`--state <dir>` でディレクトリを変更可)し、履歴(直近90件のスコア推移)と
`last_report_at`(前回report実行時刻)を書き込みます。**`report` を実行するたびに
差分の基準点が更新される**ため、`watch` の変化検知とは独立して運用できます。

出力例(バンドルされたフィクスチャ AS64500・AS64501 で `--demo` を2回連続実行した場合。
1回目は「初回」、2回目は履歴が1件だけなのでトレンドは単一値・差分は `±0`):

```
  ashealth ─ 定期サマリレポート
  ────────────────────────────────────────────────────────────────
  対象AS数: 2件   平均スコア: 64点
  最重要アクション: AS64500: [FAIL] 203.0.113.0/24 — RPKI invalid (invalid_asn) — ROV実施ネットワークからこの経路は破棄されます【最優先】
  ────────────────────────────────────────────────────────────────

  本番AS (AS64500)  スコア 28点 グレードE  前回比 ±0
    FAIL 3件 / WARN 5件
    トレンド: 28
    上位所見:
      - [FAIL] 198.51.100.0/24 — ROA未作成 — このプレフィックスをカバーするROAが存在せず、RPKI的に保護されていません
      - [FAIL] 2001:db8::/32 — ROA未作成 — このプレフィックスをカバーするROAが存在せず、RPKI的に保護されていません
      - [FAIL] 203.0.113.0/24 — RPKI invalid (invalid_asn) — ROV実施ネットワークからこの経路は破棄されます【最優先】

  検証AS (AS64501)  スコア 100点 グレードA  前回比 ±0
    FAIL 0件 / WARN 0件
    トレンド: 100
```

運用が進み履歴が積み上がると、トレンド行は `28 → 35 → 45 → 79` のように直近4回分の
推移を表示するようになります。

読み方の補足:

- トレンドは `watch` と共有する履歴から、**今回の実行分を除いた**直近最大4件を古い順に表示します。
  そのためトレンドが空になるのは状態ファイルにまだ履歴が無い場合だけで、`watch` がすでに履歴を
  記録していれば、初回の `report` でもトレンドが表示されます。
- 差分が「初回」になるのは `last_report_at` が無いとき、つまりそのASで最初の `report` 実行時だけです。
  先に `watch` を実行していても「初回」のままです。
- `--demo` の状態は既定の状態ディレクトリ配下の `demo/` に分けて保存されます
  (`$XDG_STATE_HOME` 未設定なら `~/.local/state/ashealth/demo/asXXXX.json`。`--state <dir>` 指定時は
  そのディレクトリ直下)。過去の実行で残っていると、1回目の `--demo` 実行でも「初回」にならず、
  すでにトレンドが表示されます。上の出力例を再現するには、これらのファイルを削除してください。

`--webhook` を指定すると、Discord Webhook がそのまま解釈できる日本語コンパクトサマリ
(`content` フィールド)に加え、`as_count` / `avg_score` / `top_action` / `blocks`(各ASブロックの
フルJSON)を含むペイロードを1回POSTします(`watch` と共通のWebhookクライアントを再利用)。

cron 例(週次レポートを日曜3時に送信):

```cron
0 3 * * 0 /usr/local/bin/ashealth report --config --webhook https://discord.com/api/webhooks/... >> /var/log/ashealth-report.log 2>&1
```

## Web UI のオフラインデモ (`serve --demo`)

`serve` は既定でも `AS64500`(不健全フィクスチャ)・`AS64501`(健全フィクスチャ)の2つを
常時フィクスチャ応答するため、フォームにこれらを入力するだけでライブAPIなしにデモできます。

`--demo` フラグを付けて起動すると、**入力されたASN全てがフィクスチャ (AS64500) で応答する
完全オフラインモード**になります。ライブAPI(RIPEstat / PeeringDB / whois.radb.net)には
一切アクセスしません。デモ環境をネットワーク隔離した状態で動かしたい場合や、任意のASNを
入力してもエラーにならないUIデモを見せたい場合に使います。

```
ashealth serve --port 8080 --demo
```

`--config` と組み合わせた `serve --config --demo` は、設定ファイルが存在しない環境では
バンドルされたフィクスチャ2AS(AS64500/AS64501)のダッシュボードを自動的に合成します
(詳細は「`--config` と `--demo` の組み合わせ」を参照)。

## 複数ASダッシュボード (`serve --config`)

`serve` に `--config` を渡すと、トップページが単体AS診断フォームから
**設定内ASNの一覧ダッシュボード** に切り替わります。

```
ashealth serve --port 8080 --config ~/.config/ashealth/config.toml
```

- 表: ラベル・ASN・スコアバッジ(グレード別に色分け)・FAIL/WARN件数・最終チェック時刻・
  チェック用リンク。まだ一度も `/api/check/{asn}` されていないASNは「未チェック」表示になり、
  「今すぐチェック」リンクから実行できます
- データソースは既存の `/api/check` 結果キャッシュ(`--cache-ttl` 共通)。ダッシュボード自体は
  バックグラウンドで診断を走らせません — キャッシュが空なら「未チェック」のままです
- `<meta http-equiv="refresh" content="300">` による5分ごとの自動更新(ビルド不要、素のHTML)
- 新エンドポイント `GET /api/summary`: `[{asn,label,score,grade,fail,warn,checked_at,cached}]`
  を返します。未チェックのASNは `score` 以下のフィールドが省略され `cached: false` になります。
  設定内ASNが0件でも(構造上あり得ませんが)配列だけを返し常に200
- `--config` を渡さない既存の挙動(単体AS診断フォーム、`/api/summary` は404)は完全に維持

`/api/summary` の応答例(AS64500だけ `/api/check/64500` 済み、AS64501は未チェック):

```json
[
  {
    "asn": 64500,
    "label": "本番AS",
    "score": 28,
    "grade": "E",
    "fail": 3,
    "warn": 5,
    "checked_at": "2026-07-07T00:31:26Z",
    "cached": true
  },
  {
    "asn": 64501,
    "label": "検証AS",
    "cached": false
  }
]
```

レートリミット・キャッシュTTLは `--config` の有無に関わらず共通の `RateLimiter` / `ReportCache` を使うため、
挙動は変わりません。

## 今後の構想

[ROADMAP.md](ROADMAP.md) を参照してください。修正オブジェクトの自動生成 (`fix`) は v0.3、
複数AS管理 (`--config`) と定期レポート (`report`)・複数ASダッシュボード (`serve --config`) は
v0.4/v0.5、入力検証の堅牢化(予約ASN拒否・サンプリング可視化)とデモ体験の改善は v0.6 で実装済み。
bgp-sentinel との製品ライン統合、公開ホスティング・SaaS化 (v1.0) を予定しています。

## ライセンス / 免責

MIT License。本ツールの診断結果は公開 API のスナップショットに基づく参考情報であり、
実際の経路制御・登録変更は各自の責任で確認のうえ実施してください。
