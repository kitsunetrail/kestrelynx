## 概要

KestreLynx は、`example/app` の `svc/gradle.lockfile` にある 2 件のパッケージエントリを `gradle` で更新することを提案します。

- 依存関係のディレクトリ: `svc`
- パッケージマネージャー: `gradle`
- これらのパッケージを実行しているワークロード: `compose/app/web`
- 変更したファイル: `svc/gradle.lockfile`

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

- 実行環境: `gradle9.8.2-jdk17` `9.8.2`
  - 公式イメージ: `gradle@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc`

**実行した操作**

- `gradle.update_locks`
  - 終了コード: 0

**Gradle の更新**

- `svc/gradle.properties`: Spring Boot の BOM のプロパティ `snakeyaml.version` を、`2.6` の代わりに `2.7` で上書きします (`org.yaml:snakeyaml` の版を決めています)
- `svc/build.gradle.kts`: 末尾に、`org.apache.commons:commons-lang3` を `3.18.0` 以上にする constraints を追加します
- gradle.lockfile は、上のとおり書き換えたファイルから、作業用コンテナの Gradle `9.8.2` で作り直しました
- 返ってきた結果を KestreLynx が次のとおり検査しました
  - 変わったのは gradle.lockfile だけ
  - エントリの削除はなし
  - lock する構成は同じ
  - 対象はすべての構成で目標の版
  - 追加または変更された版にはすべて Maven Central に pom がある
- プロジェクトに設定した Spring Boot の BOM のプロパティは、消すまで残ります
  - 修正を含む版に Spring Boot のプラグインを上げるときに上書きを外してください
  - 外さないと、この版のままになります
- constraints は消すまで残ります
  - そのパッケージを持ち込む依存が、修正版を要求する版に上がったら外してください

**あわせて lock された版が変わった、または追加されたパッケージ (1)**

- `org.example:up`: `1` から `2` へ

**依存関係ファイルの更新前後のスキャン (Trivy、ファイルシステムモード)**

- 更新前: `svc/gradle.lockfile sha256:aaaaaaaaaaaa`
- 更新後: `svc/gradle.lockfile sha256:bbbbbbbbbbbb`
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

- マージ前に、CI で依存の一覧の表示と、gradle.lockfile をそのまま使うビルドとテストを実行してください
  - 例: `./gradlew dependencies && ./gradlew build`
  - その前に --write-locks や --update-locks は実行しないでください
  - 実行すると、上で確認した gradle.lockfile が置き換わります

<!-- kestrelynx:{"v":1,"repo_id":7,"base_branch":"main","path":"compose.yml","locations":["services.web.image"],"current_ref":"nginx:1.25.3","candidate_tag":"1.25.4","candidate_digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","base_sha":"1111111111111111111111111111111111111111","head_sha":"2222222222222222222222222222222222222222","input_blob_sha":"3333333333333333333333333333333333333333","changes":[{"path":"compose.yml","mode":"100644","blob_sha":"4444444444444444444444444444444444444444"}],"target_key":"d596a66a37dc307e942721c34ab9e199f77f040025dd35c89eca19f67f63a6ca","update_key":"e513bca69279da9566db0a06ac85a0a173b88d9bf1a0a76acc455a31016fe979","attempt_key":"e17763c925cde9702bea370d076aec40d211b1d0658f6a78f56fbf450df9d39d","fix_targets":[{"location":"services.web.image","vuln_id":"CVE-1","package":{"ecosystem":"debian","class":"os","name":"libc"}}]} -->