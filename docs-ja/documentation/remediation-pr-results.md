---
title: 修正PRの内容
---

# 修正PRの内容

KestreLynxが作成したPRの本文に何が書いてあるかを説明します。
Slackの通知の読み方は[Slackの修正計画](remediation-results.md#reading-results-in-slack-and-webhooks)、用語は[用語](index.md#terms)を参照してください。

## PR本文の内容 {#pr-body-and-checks}

PR本文には「概要」「変更内容」「確認したこと」の3つの節があります。
Kubernetes向けのPRには、[KubernetesのPR](#kubernetes-pr-results)で説明する「この変更の前提」と「マージ後」の節が加わります（Dockerfileは「マージ後」のみ）。

次は、ComposeのPR本文の例です。

> **概要**
>
> KestreLynx は、`example/app` の `compose.yml` にある 2 件の Compose サービスについて、新しいイメージタグを提案します。
>
> - 稼働中のイメージ: `nginx:1.25.3`
> - 編集したサービス: `web`、`worker`
> - これらを実行しているワークロード: `compose/app/web`、`compose/app/worker`
> - 同じイメージを実行していますが編集していないもの (Compose の対応付けなし): `app/extra (app-extra-1)`、`loose`
>
> **変更内容**
>
> - `services.web.image`: `nginx:1.25.3` から `nginx:1.25.4` へ
> - `services.worker.image`: `nginx:1.25.3` から `nginx:1.25.4` へ
>
> **確認したこと**
>
> - 稼働中: `nginx:1.25.3`
>     - config digest: `sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`
>     - プラットフォーム: `linux/amd64`
>     - 稼働中の digest はコンテナランタイムから得たもので、イメージの config digest か、index または manifest の digest かは確認していません。
> - 候補: `nginx:1.25.4`
>     - タグの digest: `sha256:1111111111111111111111111111111111111111111111111111111111111111`
>     - プラットフォームの manifest: `sha256:2222222222222222222222222222222222222222222222222222222222222222`
>     - config digest: `sha256:3333333333333333333333333333333333333333333333333333333333333333`
>     - プラットフォーム: `linux/amd64`
> - 場所: `services.web.image`、`services.worker.image`
> - 確認の記録
>     - 計画の生成時刻: 2026-10-09T04:00:00Z
>     - 変更前のスキャン: `scan-base-1`
>     - 候補のスキャン: `scan-cand-1`
> - この更新が対象とする所見 (稼働中のイメージの修正可能な所見)
>     - 解消: 2 件
>     - 残存: 1 件
> - 稼働中のイメージのその他の所見 (この更新の対象外。修正版の報告がないものなど)
>     - 候補のイメージで検出されなくなるもの: 1 件
>     - 候補のイメージに残るもの: 1 件
> - 候補のイメージで新たに入る所見: 0 件
>
> **解消 (2)**
>
> - `libc6` の `CVE-2026-0001` (`debian`、`os`)、重大度 `CRITICAL`、CISA KEV カタログに掲載、優先度 `act_now`
> - `openssl` の `CVE-2026-0002` (`debian`、`os`)、重大度 `HIGH`
>
> **対象の所見のうち残存 (1)**
>
> - `zlib1g` の `CVE-2026-0003` (`debian`、`os`)、重大度 `HIGH`
>
> **候補のイメージで検出されなくなるその他の所見 (1)**
>
> - `libheif1` の `CVE-2026-0005` (`debian`、`os`)、重大度 `HIGH`
>
> **候補のイメージに残るその他の所見 (1)**
>
> - `tar` の `CVE-2026-0004` (`debian`、`os`)
>
> **新規 (0)**
>
> - なし
>
> 両方のイメージを次の条件でスキャンしました。
>
> - Trivy: `0.71.2`
> - 脆弱性データベースの作成時刻: 2026-10-09T01:02:03Z
> - 重大度の範囲: `CRITICAL`、`HIGH`
> - 対象範囲: `os packages`

各節には、次の情報が載ります。

| 節 | 書いてあること |
| --- | --- |
| 概要 | 変更するファイル、稼働中またはベースのイメージ、編集対象、ワークロード |
| 変更内容 | イメージタグやパッケージの変更前後の版、変更箇所 |
| 確認したこと | 比較したイメージや依存ファイル、スキャン結果、言語パッケージでマージ前にCIで実行するコマンドの案内 |

言語パッケージのメジャーバージョン変更（0.xではマイナーバージョン変更）は、「概要」に太字の警告で示します。
許可するメジャーバージョンを切り替える版指定の編集も、太字の警告で示します。

計画した更新の一部だけがPRに含まれる場合の読み方は[部分PR](remediation-update-results.md#partial-pull-requests)を参照してください。

依存元も更新したPRの「あわせて更新したパッケージ」には、版が変わった直接依存と変更前後の版、更新を妨げていた指定が載ります。
例えば、`mkdirp`の更新で`minimist`を修正版に上げる場合の記載は「`mkdirp`: `0.5.1` から `0.5.6` へ（`minimist` `0.0.8` を要求していた）」です。

更新後も持ち越す脆弱性がある場合は、件数と例が1件載ります（[脆弱性の持ち越し](remediation-reresolution-logic.md#dependent-reresolution-carried-findings)）。

### KubernetesのPR {#kubernetes-pr-results}

Kubernetes向けのPRは、リポジトリのファイルを変えるだけで、クラスターへの反映はしません。
本文の「この変更の前提」と「マージ後」に、KestreLynxが確かめていない点が載ります。

PRの種類ごとに、次の内容が載ります。

| PRの種類 | 本文に書いてあること |
| --- | --- |
| すべて（Dockerfileを含む） | マージすると、自動同期やCIによって変更がそのまま配備される場合がある |
| マニフェスト・Kustomize・Helmのvalues | 変更するファイルが配備に使われているかは確かめていない |
| マニフェスト・Kustomize・Helmのvalues（CronJob・Jobを含む場合） | すでにあるJobには変更が反映されない |
| マニフェスト | 対象と同じイメージを使っているが変更しないワークロードとコンテナ |
| Kustomize | kustomizationを描画しておらず、一覧のコンテナ以外への影響は確かめていない |
| Helmのvalues | チャートを描画しておらず、変更するキーが最終的な値になるかは確かめていない |
| Helmのvalues（二重引用符を足す場合） | 新しいタグを文字列として読ませるため、二重引用符で囲んで書くこと |

管理ツール（Argo CD・Flux・Helm）の表示は、ラベルやアノテーションによる[管理元の推定](remediation-kubernetes-logic.md#management-markers)です。

KustomizeとHelmのvaluesのPR本文のコンテナ一覧は、設定の`workload`と`affects`に書いたコンテナです。

PRで変更するコンテナは、KestreLynxの設定で変えられます。

- マニフェストのPRで変更しないと記載された通常のコンテナ・ネイティブsidecarもKestreLynxに更新させるには、そのコンテナの[対応付け](remediation-setup-kubernetes.md#kubernetes-pull-requests)を足す
- マニフェストのPRでは、通常のinit containerは、対応付けを足してもKestreLynxは編集しない（[マニフェストの形式](remediation-source-formats.md#manifest-formats)）
- [Kustomize](remediation-setup-kubernetes.md#kustomize-pull-requests)・[Helmのvalues](remediation-setup-kubernetes.md#helm-values-pull-requests)で一覧にないコンテナにも変更が効く場合は、`affects`に足す

確認範囲の仕組みは[KustomizeのPR](remediation-kubernetes-logic.md#kustomize-prs)と[HelmのvaluesのPR](remediation-kubernetes-logic.md#helm-values-prs)を参照してください。

### GoのPR {#go-pull-requests}

GoのPRは、`go.mod`と`go.sum`の更新を提案します。
「確認したこと」には、次の情報が載ります。

- 「Go モジュールの更新」
    - `proxy.golang.org`での版の確認と、`sum.golang.org`とのハッシュの照合
    - `go`・`toolchain`の変更と、言語の機能や`GODEBUG`の既定値が変わる可能性
- 「対象の新しい版が要求するため、あわせて上がったモジュール」
    - 付随して版が上がった、または追加されたモジュール（ある場合だけ載る）
- 「更新後の版について checksum database から補った go.sum の行」
    - `sum.golang.org`の記録から補った行（ある場合だけ載る）
- 「マージ前に、CI で go.mod をそのまま使うビルドとテストを実行してください」
    - `go build -mod=readonly ./... && go test -mod=readonly ./...`というコマンドの例
    - ビルドとテストの前に`go get`・`go mod tidy`・`-mod=mod`のビルドを実行しない案内
    - 必要なモジュールが`go.mod`に足りなければビルドが止まる、Goコマンドの既定の動きに基づく確認

KestreLynxは`go.mod`に書かれた版の所見を比べますが、アプリケーションのビルド・テスト・動作は確かめていません。
採用条件は[Goの更新結果の検査](remediation-go-logic.md#go-update-validation)を参照してください。

### MavenのPR {#maven-pull-requests}

MavenのPRは、`pom.xml`の更新を提案します。
「確認したこと」には、次の情報が載ります。

- 「Maven の更新」
    - Mavenの実行なしでの版・プロパティの編集や上書き、`dependencyManagement`の固定
    - Maven Centralでの版の確認と、Trivyによる依存の解決・スキャン
    - 親を修正版を含む版へ更新するときに、プロパティの上書きと`dependencyManagement`の固定を外す案内
- 「あわせて解決後の版が変わったパッケージ」
    - 対象以外で版が変わった、または追加・削除されたパッケージ（ある場合だけ載る）
- 「マージ前に、Maven が解決する依存を確かめ、ビルドを実行してください」
    - `mvn -B dependency:tree && mvn -B verify`というコマンドの例
    - KestreLynxの確認で使ったのは、MavenではなくTrivyによるPOMファイルの依存の解決であること

KestreLynxはTrivyがPOMから解決した依存と所見を確かめますが、Mavenによるビルド・検証やアプリケーションの動作は確かめていません。
採用条件は[Mavenの更新結果の検査](remediation-maven-logic.md#maven-update-validation)を参照してください。

### GradleのPR {#gradle-pull-requests}

GradleのPRは、版の宣言と`gradle.lockfile`の更新を提案します。
「確認したこと」には、次の情報が載ります。

- 「Gradle の更新」
    - catalog・依存宣言・プロパティの編集とconstraintsの追記
    - 作業用コンテナのGradleの版
    - lockfileのエントリ削除・構成変更がないこと
    - 各構成の対象が選んだ公開版以上で、追加・変更した版の`.pom`がMaven Centralにあること
    - Spring Bootプラグインを修正版を含む版へ更新するときに、BOMのプロパティの上書きを外す案内
    - 依存元が修正版を要求する版に上がったときに、constraintsを外す案内
- 「同じ値で版が決まるパッケージ (Maven Central で確認済み)」
    - 編集したプロパティやcatalogの値を共有し、Maven Centralで版を確かめたパッケージ（ある場合だけ載る）
- 「あわせて lock された版が変わった、または追加されたパッケージ」
    - 対象以外でlockされた版が変わった、または追加されたパッケージ（ある場合だけ載る）
- 「マージ前に、CI で依存の一覧の表示と、gradle.lockfile をそのまま使うビルドとテストを実行してください」
    - `./gradlew dependencies && ./gradlew build`というコマンドの例
    - ビルドとテストの前に`--write-locks`・`--update-locks`を実行しない案内
    - `--write-locks`・`--update-locks`は、KestreLynxが確かめた`gradle.lockfile`を置き換えること

KestreLynxは更新後のlockfileの版と更新前後の所見を確かめますが、アプリケーションのビルド・テスト・動作は確かめていません。
採用条件は[Gradleの更新結果の検査](remediation-gradle-logic.md#gradle-update-validation)を参照してください。

### RustのPR {#cargo-pull-requests}

RustのPRは、`Cargo.lock`の更新を提案します。
「確認したこと」には次の内容が載ります。

- 作業用のRustの版、公式イメージ、対象ごとに実行した`cargo.update`の終了コード
- ビルド対象を空のファイルで渡し、ビルドせずに`cargo update`だけを実行したこと
- 各`Cargo.toml`とメンバーが変わらず、すべての対象が目標版になったこと
- 新しく入った版について、crates.ioの索引で公開・チェックサム・取り下げの有無を確認したこと
- 形式が変わる場合の`Cargo.lock`の新旧の形式番号
- 新しく入った版について読み取れた`rust-version`の最大値と、読み取れないものがある場合の件数
- 対象のcrateの新旧の版と、付随して版が変わった・追加された・削除されたcrateの一覧
- 更新前後の`Cargo.lock`のスキャンで解消・残存・新規となった所見

マージ前に、CIで`cargo build --locked && cargo test --locked`を実行してください。
採用条件は[Rustの更新結果の検査](remediation-cargo-logic.md#cargo-update-validation)を参照してください。

## 解消・残存・新規と、KestreLynxが確かめていないこと {#verification-results}

PR本文の「解消」「残存」「新規」とSlackの修正計画の解消件数は、次の表に示す更新前後のスキャンの比較結果です。

| 表示 | 意味 |
| --- | --- |
| 解消・`Resolved` | 更新前に検出され、更新後には検出されなかった所見 |
| 残存・`Remaining` | 更新後にも残っている所見 |
| 新規・`Introduced` | 更新前にはなく、更新後に検出された所見 |

更新の種類によって、スキャンして比べるものが異なります。

| 更新の種類 | 更新前としてスキャンしたもの | 更新後としてスキャンしたもの |
| --- | --- | --- |
| 配布イメージ | 稼働イメージ | 候補のタグが指す、レジストリから取得したイメージ |
| ベースイメージ（Dockerfileの`FROM`） | 現在の`FROM`のタグが指す、レジストリから取得したイメージ | 候補のタグが指す、レジストリから取得したベースイメージ |
| 言語パッケージ | リポジトリから取得した更新前の依存ファイル | PRで提案する更新後の依存ファイル |

比較方法は[スキャンの比較条件](remediation-logic.md#comparison-conditions)、DockerfileでNode.js・Python・Java本体の所見を含める条件は[ランタイム本体の扱い](remediation-base-image-logic.md#base-runtime-findings)を参照してください。

「確認したこと」の所見の項目の例は、[PR本文の内容](#pr-body-and-checks)に載っています。

Compose・Kubernetesマニフェスト・Kustomize・Helmのvaluesでは、「確認したこと」の所見が次の項目に分かれます。
表の項目名では、括弧内の説明と件数を省略しています。

| 本文の項目 | 書いてあること | 所見の一覧の見出し |
| --- | --- | --- |
| この更新が対象とする所見 | 更新で解消を目指す、修正版が報告されている所見の解消と残存 | 解消、対象の所見のうち残存 |
| 稼働中のイメージのその他の所見 | 修正版の報告がないものなど、対象外の所見が候補で消える件数と残る件数 | 候補のイメージで検出されなくなるその他の所見、候補のイメージに残るその他の所見 |
| 候補のイメージで新たに入る所見 | 更新前にはなく、候補で検出された所見 | 新規 |

件数の後に所見の一覧が続き、「候補のイメージで検出されなくなるその他の所見」は該当する所見がある場合だけ載ります。
Dockerfileでは「比較した両ベースイメージのその他の所見」に、候補のベースに残る件数と新たに入る件数が載ります。

言語パッケージでは、依存ファイル内の全パッケージについて解消・残存・新規が載ります。

KestreLynxは、次の結果を確かめていません。

- 変更後のDockerfileからビルドしたイメージでの所見の解消
- 配置後の稼働中のコンテナでの所見の解消
- 更新後の依存ファイルを使った実際の依存のインストール
- アプリケーションのビルド・テストの成功や動作

配置後のスキャンで所見が解消と判定される条件は[解消の判定](diff-logic.md#resolved-findings)を参照してください。

検査範囲と採用条件は[対象別の検証範囲](remediation-logic.md#verification-scope)を参照してください。
