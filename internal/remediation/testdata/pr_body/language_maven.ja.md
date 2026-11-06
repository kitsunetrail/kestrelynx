## 概要

KestreLynx は、`example/app` の `svc/pom.xml` にある 2 件のパッケージエントリを `maven` で更新することを提案します。

- 依存関係のディレクトリ: `svc`
- パッケージマネージャー: `maven`
- これらのパッケージを実行しているワークロード: `compose/app/web`
- 変更したファイル: `svc/pom.xml`

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

- パッケージマネージャーは実行していません。KestreLynx が pom ファイルを直接書き換えました (内容は下記のとおり)

**Maven の更新**

- `svc/pom.xml`: 親の pom のプロパティ `snakeyaml.version` を、`2.6` の代わりに `2.7` で上書きします (`org.yaml:snakeyaml` の版を決めています)
- 版は Maven Central で確かめました
- 更新前後の pom ファイルは、Trivy が Maven Central から解決してスキャンしました
  - Trivy が解決を再現できない書き方 (profile、ほかのリポジトリ、版の範囲、relocation など) があれば、更新を止めています
- 親のプロパティの上書きと dependencyManagement の固定は、消すまで残ります
  - 修正を含む版に親 (Spring Boot など) を上げるときに外してください
  - 外さないと、この版に固定されたままになります

**あわせて解決後の版が変わったパッケージ (1)**

- `org.example:up`: `1` から `2` へ

**依存関係ファイルの更新前後のスキャン (Trivy、ファイルシステムモード)**

- 更新前: `svc/pom.xml sha256:aaaaaaaaaaaa`
- 更新後: `svc/pom.xml sha256:bbbbbbbbbbbb`
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

- マージ前に、Maven が解決する依存を確かめ、ビルドを実行してください
  - 例: `mvn -B dependency:tree && mvn -B verify`
  - 上の確認は、Maven ではなく Trivy による pom ファイルの解決で行いました

<!-- kestrelynx:{"v":1,"repo_id":7,"base_branch":"main","path":"compose.yml","locations":["services.web.image"],"current_ref":"nginx:1.25.3","candidate_tag":"1.25.4","candidate_digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","base_sha":"1111111111111111111111111111111111111111","head_sha":"2222222222222222222222222222222222222222","input_blob_sha":"3333333333333333333333333333333333333333","changes":[{"path":"compose.yml","mode":"100644","blob_sha":"4444444444444444444444444444444444444444"}],"target_key":"d596a66a37dc307e942721c34ab9e199f77f040025dd35c89eca19f67f63a6ca","update_key":"e513bca69279da9566db0a06ac85a0a173b88d9bf1a0a76acc455a31016fe979","attempt_key":"e17763c925cde9702bea370d076aec40d211b1d0658f6a78f56fbf450df9d39d","fix_targets":[{"location":"services.web.image","vuln_id":"CVE-1","package":{"ecosystem":"debian","class":"os","name":"libc"}}]} -->