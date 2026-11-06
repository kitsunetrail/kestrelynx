## 概要

KestreLynx は、`example/app` の `svc/go.mod` にある 2 件のパッケージエントリを `go` で更新することを提案します。

- 依存関係のディレクトリ: `svc`
- パッケージマネージャー: `go`
- これらのパッケージを実行しているワークロード: `compose/app/web`
- 変更したファイル: `svc/go.mod`、`svc/go.sum`

**1 件のパッケージが別のメジャーバージョンに上がります (0.x では別のマイナーバージョン)。アプリケーションの変更が必要になることがあるため、最初に確認してください。**

## 変更内容

更新前の稼働中の版から更新後の版へ、プロジェクトがそのパッケージをどう要求しているかとあわせて示します。

- `lodash`: `4.17.20` から `4.17.21` へ (直接依存)
- `minimist`: `0.2.1` から `1.2.8` へ (間接依存) — **メジャーバージョンの変更**
- `odd`: `2.0.0` から `2.0.1` へ (関係は不明)

### この更新が対象とする脆弱性

- `lodash` の `CVE-2026-1111`、重大度 `CRITICAL`、CISA KEV カタログに掲載、優先度 `act_now`
- `minimist` の `CVE-2026-2222`、重大度 `HIGH`

## 確認したこと

- 実行環境: `golang1.26` `1.26.10`
  - 公式イメージ: `golang@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc`
  - 選んだ版: go.mod の go・toolchain の行と、対象の新しい版の go の行のうち最も高い版以上で、サポート中の Go の最小の版

**実行した操作**

- `go get golang.org/x/net@v0.53.0`
  - 終了コード: 0

**Go モジュールの更新**

- go.mod の go の行が `1.22` から `1.25.0` に上がります
  - 更新後の版の go.mod が宣言する最も高い go の行に合わせています
  - 稼働中のバイナリをビルドした Go `1.26.10` 以下に収まっています
  - go の行が上がると、言語の機能や既定の動き (GODEBUG の既定値) が変わることがあります
  - ビルドが通ることは確かめていません
- go.mod の toolchain の行が なし から `go1.25.3` に変わります
- 対象の版を Go module proxy (proxy.golang.org)で確かめました
  - 公開されていること
  - 正規の表記であること
  - 撤回されていないこと
- 更新後の各版の go.mod もそこから取得しました
  - 対象のほかに動いたモジュールは、すべてそれらの go.mod がその版で要求しているものです
- go.sum は Go の checksum database (sum.golang.org)と照合しました
  - 更新で追加・変更したすべての行
  - 更新後の版ごとの 2 つのハッシュ (モジュールと go.mod)
- 下のスキャンの対象は、go.mod に書かれた版です
  - go コマンドの既定の -mod=readonly のビルドはこの版だけを使います
  - 必要なモジュールが go.mod にない、または書かれた版が必要な版より低い場合、そのビルドは止まります

**対象の新しい版が要求するため、あわせて上がったモジュール (2)**

- `golang.org/x/text`: `v0.14.0` から `v0.36.0` へ
- `golang.org/x/sys`: `v0.40.0` を追加

**更新後の版について checksum database から補った go.sum の行 (1)**

- `golang.org/x/text v0.36.0/go.mod h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=`

**依存関係ファイルの更新前後のスキャン (Trivy、ファイルシステムモード)**

- 更新前: `svc/go.mod sha256:aaaaaaaaaaaa`
- 更新後: `svc/go.mod sha256:bbbbbbbbbbbb`
- ファイルの全パッケージの検出結果 (更新したパッケージに限らない)
  - 解消: 2 件
  - 残存: 1 件
  - 新規: 0 件
- 以下の一覧は途中で切ってあります

**解消 (2)**

- `lodash` `4.17.20` の `CVE-2026-1111`、重大度 `CRITICAL`、CISA KEV カタログに掲載、修正版 `4.17.21`
- `minimist` `0.2.1` の `CVE-2026-2222`

**残存 (1)**

- `semver` `7.5.4` の `CVE-2026-3333`、重大度 `HIGH`

**新規 (0)**

- なし

両方のスキャンを次の条件で実行しました。

- Trivy: `0.71.2`
- 脆弱性データベースの作成時刻: 2026-10-09T01:02:03Z
- 重大度の範囲: `CRITICAL`、`HIGH`
- 設定: 両方のスキャンで同じ

リポジトリ自身の Trivy 設定、ignore ファイル、VEX ドキュメントは読んでいません。

- マージ前に、CI で go.mod をそのまま使うビルドとテストを実行してください
  - 例: `go build -mod=readonly ./... && go test -mod=readonly ./...`
  - その前に go get・go mod tidy・-mod=mod のビルドは実行しないでください
  - 上の確認は、go.mod に必要なモジュールが足りなければビルドが止まるという、go コマンドの既定の動きを前提にしています

<!-- kestrelynx:{"v":1,"repo_id":7,"base_branch":"main","path":"compose.yml","locations":["services.web.image"],"current_ref":"nginx:1.25.3","candidate_tag":"1.25.4","candidate_digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","base_sha":"1111111111111111111111111111111111111111","head_sha":"2222222222222222222222222222222222222222","input_blob_sha":"3333333333333333333333333333333333333333","changes":[{"path":"compose.yml","mode":"100644","blob_sha":"4444444444444444444444444444444444444444"}],"target_key":"d596a66a37dc307e942721c34ab9e199f77f040025dd35c89eca19f67f63a6ca","update_key":"e513bca69279da9566db0a06ac85a0a173b88d9bf1a0a76acc455a31016fe979","attempt_key":"e17763c925cde9702bea370d076aec40d211b1d0658f6a78f56fbf450df9d39d","fix_targets":[{"location":"services.web.image","vuln_id":"CVE-1","package":{"ecosystem":"debian","class":"os","name":"libc"}}]} -->