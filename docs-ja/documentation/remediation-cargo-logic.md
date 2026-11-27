---
title: Rustの更新
---

# Rustの更新

KestreLynxは、稼働イメージで見つかったRustの依存パッケージ（crate）の脆弱性を修正するため、`Cargo.lock`だけを更新するPRを提案します。
稼働イメージへの反映には、利用者が更新後の`Cargo.lock`でバイナリを再ビルドし、そのバイナリを含むイメージを配置する必要があります。

更新は次の順に進みます。

1. 稼働イメージの所見をリポジトリの依存ファイルと照合する
2. 稼働版と互換な系列で修正版を選び、公開と取り下げの有無を確かめる
3. 更新を実行する作業用のRustを選ぶ
4. 選んだRustで対象ごとに`cargo update`を実行する
5. ファイルの差分、依存の要求、チェックサム、スキャン結果を検査する

詳しくは、[Rustの候補選定](#cargo-package-selection)、[作業用のRust](#cargo-runtime-selection)、[Rustの実行設定](#cargo-worker-settings)、[Rustの更新結果の検査](#cargo-update-validation)を参照してください。
このページで使う用語は[用語](index.md#terms)を参照してください。

## Rustの候補選定 {#cargo-package-selection}

更新対象は、Trivyがcargo-auditableでビルドしたバイナリから検出した所見（`rustbinary`）と、イメージ内の`Cargo.lock`などから検出した所見（`cargo`）にあるcrates.ioのcrateです。

バイナリの起点となるパッケージ（root）は、単独のパッケージまたはワークスペースに属するパッケージ（メンバー）の`Cargo.toml`と照合します。

| 所見 | 照合する内容 | 扱い |
| --- | --- | --- |
| `rustbinary` | rootの名前・版がメンバーと一致し、組み込まれたほかのcrateをすべてそのメンバーから`Cargo.lock`の依存関係でたどれる | 更新候補の選定に進む |
| `rustbinary` | rootを特定できたが、名前・版がどのメンバーとも一致しない | そのバイナリの所見を計画に含めない |
| `rustbinary` | rootが1つに決まらないか、バイナリのパッケージ一覧が欠落・重複・省略されている | `rust_binary_not_from_source`で手動対応にする |
| `rustbinary` | 一致したメンバーからたどれないcrateが組み込まれている | `rust_binary_not_from_source`で手動対応にする |
| `cargo` | 所見の名前・稼働版がリポジトリの`Cargo.lock`にある | crates.ioのcrateを更新候補として調べる |
| `cargo`・`rustbinary` | 所見の対象がメンバー自身である | `non_registry_source`で手動対応にする |
| `cargo` | 所見の名前・稼働版が`Cargo.lock`にない | `not_found_in_source`で手動対応にする |

必要なファイルと手動対応になる入力は、[Rustの依存ファイル](remediation-dependency-formats.md#cargo-inputs)を参照してください。

### crateの目標版 {#cargo-target-versions}

crateの目標版は、修正版から選び、crates.ioの公開情報で確かめます。
互換な系列は、`1.x.y`以降ではメジャー版、`0.x.y`（`x > 0`）ではマイナー版まで、`0.0.y`ではパッチ版までが同じ版のまとまりです。

1. 勧告ごとに、稼働版と互換な系列で稼働版より新しい最小の修正版を選ぶ
2. 勧告ごとに選んだ版の最大値を更新の下限とし、メンバーの依存宣言がその版を許すか確かめる
3. `index.crates.io`の索引にある同じ系列の正式版から、下限以上で取り下げ（yank）されていない最も低い版を選ぶ

| 状況 | 扱い |
| --- | --- |
| ある勧告の修正版が互換でない系列にしかない | `cargo_fix_in_other_series`で手動対応にする |
| 手順2で、メンバーの`Cargo.toml`の要求が更新の下限となる版を許さない | `range_excludes_fix`で手動対応にする |
| 手順2で、メンバーの`Cargo.toml`の要求が更新の下限となる版を許すか判定できない | `range_not_evaluable`で手動対応にする |
| 索引に条件を満たす版がないか、選んだ版に`+`で始まるビルド情報が付く | `cargo_release_not_found`で手動対応にする |
| 対象と同じ名前のcrates.ioのcrateが`Cargo.lock`に複数の版で入っている | `multiple_versions`で手動対応にする |

互換でない系列の案内では、勧告に挙がった版のうち、すべての対象脆弱性の修正条件を満たす最も低い別系列の版を示します。
共通の版を選べず、各勧告に別系列の修正版があれば、勧告ごとに最も低い別系列の修正版を示します。

## 作業用のRust {#cargo-runtime-selection}

作業用のRustは、依存ファイルの更新を実行するために選びます。
[実行環境の一覧](remediation-reference.md#supported-runtimes)の`rust`の行のうち、公式イメージがあり、実行するプラットフォームで動作を確認した最も新しい版を使います。

| 確認する内容 | 扱い |
| --- | --- |
| 条件を満たす実行版がない | `cargo_runtime_unavailable`で手動対応にする |
| メンバーの`rust-version` | ワークスペースから継承した値を含め、宣言のあるメンバーの最小値をプロジェクトが対応するRustの版とする |
| 新しく入ったcrateの版がプロジェクトの宣言より新しいRustを要求する | `cargo_rust_version_too_new`で手動対応にする |
| プロジェクトに宣言がない | crateが要求するRustの版との比較を省く |

`Cargo.lock`は形式3と4を扱います。形式3から4への変更は、次の条件をすべて満たす場合に限って採用します。

- プロジェクトの`rust-version`が未宣言または1.78以上である
- 対応付けたディレクトリとその祖先にある`rust-toolchain`・`rust-toolchain.toml`が、どれも`stable`または1.78以上と読み取れるリリース版を指定している

条件を満たさない形式3から4への変更や、形式4から3への変更は`lockfile_format_changed`で手動対応にします。

## Rustの実行設定 {#cargo-worker-settings}

更新は、作業用コンテナ（Kubernetesでは作業用Pod）で行います。
Cargoの実行時には、次の環境変数を固定して渡します。

| 環境変数 | 値・扱い |
| --- | --- |
| `CARGO_HOME` | 索引のキャッシュを置く、メモリ上の一時領域の空のディレクトリ`/home/worker/cargo-home` |
| `RUSTC` | 選んだRustのコンパイラの絶対パス |
| `PATH` | 選んだRustのコマンドのディレクトリ、`/usr/bin`、`/bin`の順 |
| `CARGO_REGISTRIES_CRATES_IO_PROTOCOL` | `sparse` |
| `CARGO_TERM_COLOR` | `never` |

- Cargoがビルド対象を見つけられるよう、ソースの内容を渡さず、ビルド対象と同じパスに空のファイルを置く
- 公式イメージのCargoを絶対パスで呼び、対象ごとに`cargo update --manifest-path Cargo.toml -p <名前>@<稼働版> --precise <目標版>`を順に実行する
- Docker・Kubernetesともにルートファイルシステムを読み取り専用にし、非rootで実行する

共通の制限は[作業用コンテナの制限](remediation-worker-logic.md#worker-restrictions)、通信先は[依存パッケージの取得](outbound-communication.md#dependency-downloads)を参照してください。

## Rustの更新結果の検査 {#cargo-update-validation}

更新結果は、ファイルの変更、依存の要求、crates.ioの索引、スキャン結果の条件をすべて満たした場合だけ採用します。
実行した更新から一部の対象を外して残りを再実行する分割は行いません。

### ファイルと依存の変更

| 検査対象 | 採用条件 |
| --- | --- |
| 変更するファイル | 各操作の後と最後に回収した入力のうち、変わったのが`Cargo.lock`だけであること |
| パッケージと版 | メンバーの名前・版が変わらず、各対象のcrateが指定した目標版だけになること |
| crateの追加・削除・版の変更 | 対象自身か、更新前の対象の旧版または更新後の対象の新版から依存をたどれるcrates.ioのcrateであること |
| 変更範囲の外の依存 | 参照先の変更は、消えた版から範囲内の同名・同じ取得元・同じ互換系列の後継版への変更に限ること |
| 新しい依存と参照先が変わった依存 | 依存元の`Cargo.toml`または索引にある版の要求を満たすこと |
| 更新後の依存全体 | すべてのcrateをいずれかのメンバーからたどれること |
| 版が変わらないcrate | 取得元とチェックサムが変わらないこと |
| 既存の系列 | 同じ系列で版を下げないこと |
| 低い系列の追加 | 範囲内の依存元の要求を既存のどの版でも満たせず、高い系列の版とその依存が変わらないこと |

更新前になかったcrates.ioの版は、索引で公開とyankの有無を調べ、`Cargo.lock`の`checksum`を索引のチェックサムと照合します。
索引にあるRustの要求は[プロジェクトの宣言](#cargo-runtime-selection)と照合します。

### スキャンと利用者のビルド

更新前後の`Cargo.lock`だけを、同じTrivy・脆弱性データベース・重大度でスキャンして比較します。

1. 各スキャンのパッケージ一覧に、その`Cargo.lock`に記録されたcrates.ioの全crateの名前と版があることを確かめる
2. 対象の脆弱性が消え、crateの名前・版・脆弱性IDの組み合わせで新しい所見がないことを確かめる

利用者はマージ前に、対象のワークスペースでPRの`Cargo.lock`をそのまま使い、`cargo build --locked && cargo test --locked`でビルドとテストを行います。
必要な依存が欠けているなど、ビルドに`Cargo.lock`の変更が必要なら`--locked`でCargoが停止します。

PR本文の記載内容は、[RustのPR](remediation-pr-results.md#cargo-pull-requests)を参照してください。
