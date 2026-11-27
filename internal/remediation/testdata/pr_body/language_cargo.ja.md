## 概要

KestreLynx は、`example/app` の `svc/Cargo.lock` にある 2 件のパッケージエントリを `cargo` で更新することを提案します。

- 依存関係のディレクトリ: `svc`
- パッケージマネージャー: `cargo`
- これらのパッケージを実行しているワークロード: `compose/app/web`
- 変更したファイル: `svc/Cargo.lock`

## 変更内容

更新前の稼働中の版から更新後の版へ、プロジェクトがそのパッケージをどう要求しているかとあわせて示します。

- `mio`: `0.8.0` から `0.8.11` へ (間接依存)
- `tokio`: `1.18.0` から `1.18.4` へ (直接依存)

### この更新が対象とする脆弱性

- `mio` の `CVE-2026-2222`、重大度 `HIGH`
- `tokio` の `CVE-2026-1111`、重大度 `CRITICAL`、CISA KEV カタログに掲載、優先度 `act_now`

## 確認したこと

- 実行環境: `rust1.100` `1.100.0`
  - 公式イメージ: `rust@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc`

**実行した操作**

- `cargo.update`
  - 終了コード: 0
- `cargo.update`
  - 終了コード: 0

**Cargo の更新**

- 作業用コンテナで実行したのは cargo update だけです
  - ビルドはしていません
  - ソースファイルは渡していません
  - ビルド対象は空のファイルにして渡しました
- 返ってきた結果を KestreLynx が次のとおり検査しました
  - 変わったのは Cargo.lock だけ
  - Cargo.toml は渡したまま
  - ワークスペースのパッケージは同じ
  - 対象はすべて目標の版
  - 更新前の Cargo.lock になかった版の crate はすべて、crates.io の索引にある版で、yank されておらず、チェックサムが Cargo.lock のものと一致する
- Cargo.lock の形式の版を `3` から `4` に変えます
- 更新前の Cargo.lock になかった版の crate について、crates.io の索引が示す rust-version のうち最も高いのは `1.70.0` です
- 更新前の Cargo.lock になかった版の crate 4 個のうち、crates.io の索引に読み取れる rust-version がないのは 1 個です

**更新の対象にした crate (2)**

- `mio`: `0.8.0` から `0.8.11` へ
- `tokio`: `1.18.0` から `1.18.4` へ

**あわせて版が変わった、追加された、または削除された crate (3)**

- `bytes`: `1.5.0` から `1.6.1` へ
- `once_cell`: `1.21.4` を削除
- `windows-sys`: `0.48.0` で追加

**依存関係ファイルの更新前後のスキャン (Trivy、ファイルシステムモード)**

- 更新前: `svc/Cargo.lock sha256:aaaaaaaaaaaa`
- 更新後: `svc/Cargo.lock sha256:bbbbbbbbbbbb`
- ファイルの全パッケージの所見 (更新したパッケージに限らない)
  - 解消: 2 件
  - 残存: 1 件
  - 新規: 0 件
- 以下の一覧は途中で切ってあります

**解消 (2)**

- `tokio` `1.18.0` の `CVE-2026-1111`、重大度 `CRITICAL`、CISA KEV カタログに掲載、修正版 `1.18.4`
- `mio` `0.8.0` の `CVE-2026-2222`

**残存 (1)**

- `time` `0.1.45` の `CVE-2026-3333`、重大度 `HIGH`

**新規 (0)**

- なし

両方のスキャンを次の条件で実行しました。

- Trivy: `0.71.2`
- 脆弱性データベースの作成時刻: 2026-10-09T01:02:03Z
- 重大度の範囲: `CRITICAL`、`HIGH`
- 設定: 両方のスキャンで同じ

リポジトリ自身の Trivy 設定、ignore ファイル、VEX ドキュメントは読んでいません。

- マージ前に、CI で Cargo.lock をそのまま使うビルドとテストを実行してください
  - 例: `cargo build --locked && cargo test --locked`
  - --locked を付けると、Cargo.lock の変更が必要になった時点で cargo が止まります

<!-- kestrelynx:{"v":1,"repo_id":7,"base_branch":"main","path":"compose.yml","locations":["services.web.image"],"current_ref":"nginx:1.25.3","candidate_tag":"1.25.4","candidate_digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","base_sha":"1111111111111111111111111111111111111111","head_sha":"2222222222222222222222222222222222222222","input_blob_sha":"3333333333333333333333333333333333333333","changes":[{"path":"compose.yml","mode":"100644","blob_sha":"4444444444444444444444444444444444444444"}],"target_key":"d596a66a37dc307e942721c34ab9e199f77f040025dd35c89eca19f67f63a6ca","update_key":"e513bca69279da9566db0a06ac85a0a173b88d9bf1a0a76acc455a31016fe979","attempt_key":"e17763c925cde9702bea370d076aec40d211b1d0658f6a78f56fbf450df9d39d","fix_targets":[{"location":"services.web.image","vuln_id":"CVE-1","package":{"ecosystem":"debian","class":"os","name":"libc"}}]} -->