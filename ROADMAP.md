# ashealth ロードマップ

## v0.2 (今回)

- ✅ README の実在ASスコア掲載を廃止(架空AS例に差し替え)
- ✅ serve のレートリミット+結果キャッシュ
- ✅ `watch` サブコマンド(定期再チェック+Webhook通知)

## v0.3

- health.pathvector.dev での公開ホスティング
- ✅ 修正オブジェクトの自動生成(ROA申請パラメータ・RPSL route オブジェクトの雛形出力)— `fix` サブコマンド (text / rpsl / json)

## v0.4

- ✅ 複数AS管理(設定ファイル駆動の `check --config` / `watch --config`)
- ✅ 定期レポート — `report` サブコマンド(前回report比のスコア差分・トレンド・上位所見、Webhook通知)
- bgp-sentinel との統合(検知=sentinel / 予防=ashealth の製品ライン)

## v0.5 (今回)

- ✅ スコア履歴(状態ファイルに直近90件のスコア推移を保持、後方互換あり)
- ✅ `report` サブコマンド(定期サマリレポート。前回report比の差分・トレンド・上位所見・Webhook通知)
- ✅ `serve --config` の複数ASダッシュボード(`GET /api/summary` + 自動更新トップページ)

## v0.6 (今回)

- ✅ AS0 (RFC 7607) / AS23456 (AS_TRANS, RFC 6793) の拒否 — 実運用上意味を持たないASNでの誤診断を防止
- ✅ ドキュメント用・private-use・予約ASN帯 (64496-64511 / 64512-65534 / 65535 / 4200000000-4294967295) の警告表示 (`serve` は同等の検証をHTTP 4xxで実施)
- ✅ `--limit 0` の拒否 — RPKI検証の全件スキップによるスコア不当上昇を防止。JSONに `coverage` オブジェクト (`announced`/`checked`/`complete`) を追加
- ✅ `--limit` によるサンプリング時、グレード行に推定である旨を明示 (「推定 (20/186プレフィックス検査)」)
- ✅ 人間向けターミナル出力のノイズ削減 — 修正アクション・チェックセクションの表示件数上限 (JSONは常に全件)
- ✅ `check --config --demo` / `report --config --demo` / `serve --config --demo` — 設定ファイルが存在しない場合にインメモリのデモ設定へフォールバック
- ✅ `--demo` の状態ファイルを `demo/` サブディレクトリに分離 (実運用の監視状態・スコア履歴を汚染しない)
- ✅ `serve` で AS64501 (健全フィクスチャ) を特別扱い、`serve --demo` (全ASNをフィクスチャ応答するオフライン専用モード) を追加
- ✅ ポート使用中エラーを日本語で案内 (「別の --port を指定してください」)

## v1.0

- health.pathvector.dev での公開ホスティング
- bgp-sentinel との統合(検知=sentinel / 予防=ashealth の製品ライン)
- SaaS化(認証・チーム・課金)
