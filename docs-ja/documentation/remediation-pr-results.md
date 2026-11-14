---
title: 修正PRの内容とマージ前の確認
---

# 修正PRの内容とマージ前の確認

KestreLynxが作成したPRについて、本文の読み方と、利用者がマージ前に行う確認を説明します。
Slackの通知の読み方は[Slackの修正計画](remediation-results.md#reading-results-in-slack-and-webhooks)を参照してください。

どのPRでも、KestreLynxは完成イメージや配置後の稼働コンテナでの解消を確認していません。
依存のインストールとアプリケーションの動作も未確認であり、詳細は[比較結果の解消](#verification-results)を参照してください。

このページで使う用語は[用語](remediation.md#terms)を参照してください。

## PR本文の内容とマージ前の確認 {#pr-body-and-checks}

PR本文には、提案する変更、KestreLynxが確認した結果、利用者の確認が必要な前提を載せます。
マージ前の確認は、利用者が自分のプロジェクトで行ってください。

Compose・Dockerfile・言語パッケージのPRを含め、すべてのPRで次の点を確認してください。

- PRの変更内容と、本文に記載された検査結果・未確認の前提
- [比較結果の解消](#verification-results)に示す比較対象と、検査で確かめていないこと
- PR本文にCIでの確認事項がある場合、その実行結果

npm・pnpm・uv・pipでは、PR本文の案内に従い、更新後の依存ファイルを使うインストールをプロジェクトのCIで確認してください。
次の種類のPRでは、各節の追加確認も行ってください。

| PRの種類 | 確認する節 |
| --- | --- |
| Kubernetes向けのPR | [KubernetesのPR](#kubernetes-pr-results) |
| Goの依存更新 | [GoのPRとCIでの確認](#go-pull-requests) |
| Mavenの依存更新 | [MavenのPRとCIでの確認](#maven-pull-requests) |
| Gradleの依存更新 | [GradleのPRとCIでの確認](#gradle-pull-requests) |

計画した更新の一部だけがPRに含まれる場合の読み方は[部分PR](remediation-update-results.md#partial-pull-requests)を参照してください。

### KubernetesのPR {#kubernetes-pr-results}

Kubernetes向けのPR本文は、変更するファイルやコンテナに加え、マージによる配備への影響と未確認の前提を示します。

KustomizeとHelmのvaluesでは、`remediation.mappings`の`workload`に、対応付けるコンテナのワークロードキーを指定します。
同じ変更が効くほかのコンテナは、`kustomize.affects`または`helm_values.affects`に列挙します。

PR本文のコンテナ一覧は、`workload`と`affects`に指定したコンテナを合わせたものです。
マニフェスト・Kustomize・Helmのvalues・DockerfileのPRについて、種類ごとの記載内容を示します。

- Kubernetes向けPRに共通（マニフェスト・Kustomize・Helmのvalues・Dockerfile）
    - 管理元の検出有無にかかわらず、マージ後に外部の自動同期やCIで変更が反映されうる注意
    - ラベルやアノテーションが示すArgo CD・Flux・Helmなどの管理元と、実際の管理関係は未確認である旨
- マニフェスト・Kustomize・HelmのvaluesのPR
    - CronJob・Jobを含む場合、既存のJobには変更が反映されない注意
- マニフェストのPR
    - 同じイメージで稼働していてマニフェストの対応付けがないワークロードと、同じPodテンプレート内で変更しないコンテナ
- Kustomize・HelmのvaluesのPR
    - `workload`と`affects`に挙げたコンテナの一覧と、そのうち通常のinit containerとして確認したものの一覧
    - ファイルと稼働イメージを照合し、コンテナの列挙漏れを調べた範囲
- KustomizeのPR
    - Kustomizeを展開しておらず、列挙したコンテナ以外に変更が効かないことは未確認である旨
- HelmのvaluesのPR
    - Helmを描画しておらず、指定したキーが最終的な値であることと、コンテナ一覧に漏れがないことは未確認である旨
    - ほかのvaluesファイル・CIの`--set`・Argo CDの`parameters`・`valuesObject`・`valuesFrom`による上書きと、ほかのツールによるタグの管理は未確認である旨
    - Flux HelmReleaseを示すラベルを検出したワークロードと、読み取っていないHelmReleaseの`spec.values`がvaluesファイルより優先されうる注意
    - HelmリリースもFlux HelmReleaseも検出できない場合、valuesファイルが配備に使われるか分からない旨
    - 新しいタグに二重引用符を追加する場合、Helmに文字列として読ませるために必要である旨

KustomizeとHelmのvaluesでは、対応付けを設定した時点で、`workload`と`affects`が変更の効く全コンテナを挙げていることを利用者が確認した前提で扱います。

マージ前にも、実際の配備で使うKustomizeの設定やHelmのチャート・valuesで変更が効くコンテナを確認し、PR本文の一覧にすべて含まれることを照合してください。
確認範囲の詳細は[KustomizeのPR](remediation-kubernetes-logic.md#kustomize-prs)と[HelmのvaluesのPR](remediation-kubernetes-logic.md#helm-values-prs)を参照してください。

HelmのvaluesのPRでは、配備に使われる値を次の順に確認してください。

1. 変更するvaluesファイルが実際の配備に使われることを確認する
2. ほかのvaluesファイル、CIの`--set`、Argo CDの`parameters`・`valuesObject`・`valuesFrom`、Flux HelmReleaseの`spec.values`による上書きを確認する
3. PRで変更するキーが、配備に使われるイメージの最終的な値であることを確認する

### GoのPRとCIでの確認 {#go-pull-requests}

GoのPRは、`go.mod`と`go.sum`の更新を提案します。
PR本文には、次の情報を載せます。

- 公開レジストリのGo module proxy（`proxy.golang.org`）での版の確認と、`sum.golang.org`によるハッシュの照合
- 更新対象の新しい版が要求するために、あわせて版が上がったモジュールや追加されたモジュール
- `go`・`toolchain`の行の変更と、`go`の行が上がることで言語の機能や`GODEBUG`の既定値が変わりうること
- KestreLynxが`sum.golang.org`の記録から補った`go.sum`の行

マージ前に、利用者がプロジェクトのCIで、更新後の`go.mod`をそのまま使ってビルドとテストを実行してください。
実行するコマンドは次のとおりです。

```sh
go build -mod=readonly ./... && go test -mod=readonly ./...
```

検査した`go.mod`が書き換わる可能性があるため、上の確認より先に`go get`・`go mod tidy`・`-mod=mod`のビルドを実行しないでください。
`-mod=readonly`では、必要なモジュールが足りない場合や版が低い場合にビルドが止まるため、CIの結果を確認してからマージしてください。

KestreLynxの検査は、`go.mod`に書かれた版を対象とします。
採用条件は[Goの更新結果の検査](remediation-go-logic.md#go-update-validation)、ビルドや動作を含む未確認事項は[比較結果の解消](#verification-results)を参照してください。

### MavenのPRとCIでの確認 {#maven-pull-requests}

MavenのPRは、`pom.xml`の更新を提案します。
PR本文には、次の情報を載せます。

- 変更したファイルと、版の直書き・プロパティ・親のプロパティの上書き・`dependencyManagement`での固定の内容
- Maven Centralでの版の確認と、Trivyによる更新前後の依存の解決・スキャンの結果
- 対象以外に解決後の版が変わったパッケージと、追加・削除されたパッケージ
- Mavenを実行せず、KestreLynxがPOMを書き換えたこと

マージ前に、利用者がプロジェクトのCIで、Mavenが解決する依存を確認し、ビルドと検証を実行してください。
マルチモジュールでは、ルートの`pom.xml`があるディレクトリで次のコマンドを実行してください。

```sh
mvn -B dependency:tree
mvn -B verify
```

依存一覧を、PR本文の更新対象のパッケージ名と採用版（更新後の依存ファイルで確認した版）に照らして確認してください。
更新対象が修正版へ解決されていることを確認してください。

親のプロパティの上書きと`dependencyManagement`の固定は、消すまで残ります。
親のPOMを、対象パッケージの修正版を指定する版へ更新するときに、今回追加した上書きや固定を外してください。

上書きや固定を外したあとも、対象パッケージが修正版へ解決されることを確認してください。

KestreLynxの検査は、TrivyによるPOMの解決を対象とします。
採用条件は[Mavenの更新結果の検査](remediation-maven-logic.md#maven-update-validation)、ビルドや動作を含む未確認事項は[比較結果の解消](#verification-results)を参照してください。

### GradleのPRとCIでの確認 {#gradle-pull-requests}

GradleのPRは、版の宣言と`gradle.lockfile`の更新を提案します。

PR本文には、次の情報を載せます。

- 変更したファイルと、catalog・依存宣言・プロパティの変更や上書き・constraintsの追記の内容
- 作業用コンテナのGradleの版と、作業用コンテナが更新して返した`gradle.lockfile`についての次の確認結果
    - エントリが削除されていないこと
    - lockする構成が更新前後で同じであること
    - 更新対象が存在したすべての構成で、対象の版が選んだ公開版以上になっていること
    - 追加・変更された版の`.pom`がMaven Centralにあること
- 同じプロパティやcatalogの値で版が決まり、Maven Centralで確認したほかのパッケージ
- 対象以外にlockされた版が変わったパッケージと、追加されたパッケージ
- Trivyによる更新前後のスキャン結果と、マージ前のCIでの確認事項

マージ前に、利用者がプロジェクトのCIで、依存一覧を表示し、`gradle.lockfile`をそのまま使ってビルドとテストを実行してください。
実行するコマンドは次のとおりです。

```sh
./gradlew dependencies && ./gradlew build
```

依存一覧では、PR本文にある更新対象のパッケージを、そのパッケージが更新前に存在した構成ごとに確認してください。
各構成で解決された版がPRの`gradle.lockfile`に記録された版と一致し、修正版へ上がっていることを、ビルドとテストの成功に加えて確認してください。

検査した`gradle.lockfile`が置き換わるため、上の確認より先に`--write-locks`・`--update-locks`を実行しないでください。

Spring BootのBOMのプロパティの上書きは、消すまで残ります。
Spring Bootプラグインを、BOMが対象パッケージの修正版を指定する版へ更新するときに、上書きを外してください。

追記したconstraintsも、消すまで残ります。
constraintsで修正版以上を要求する更新対象については、そのパッケージを要求する依存元の更新に合わせて、constraintsを外す時期を判断してください。

依存元を、更新対象の修正版を要求する版へ更新したら、追記したconstraintsを外してください。
constraintsを外したあとも、更新対象が修正版へ解決されることを確認してください。

KestreLynxの検査は、lockfileとスキャンの結果を対象とします。
採用条件は[Gradleの更新結果の検査](remediation-gradle-logic.md#gradle-update-validation)、ビルドや動作を含む未確認事項は[比較結果の解消](#verification-results)を参照してください。

## 比較結果の解消 {#verification-results}

PR本文とSlackの「解消」「残存」「新規」は、更新前後のスキャンを比較した結果を表します。

表示の意味は次のとおりです。

| 表示 | 意味 |
| --- | --- |
| 解消・`Resolved` | 比較元では検出され、比較先では検出されなかった所見 |
| 残存 | 比較先にも残っている所見 |
| 新規 | 比較元では検出されず、比較先で検出された所見 |

比較したものを確認できるよう、更新の種類ごとに比較元と比較先を示します。

| 更新の種類 | 比較元 | 比較先 |
| --- | --- | --- |
| 配布イメージ | 稼働イメージ | 候補のタグが指す、レジストリから取得したイメージ |
| ベースイメージ（Dockerfileの`FROM`で指定するイメージ） | 現在の`FROM`のタグが指す、レジストリから取得したイメージ | 候補のタグが指す、レジストリから取得したベースイメージ |
| 言語パッケージ | リポジトリから取得した更新前の依存ファイル | PRで提案する更新後の依存ファイル |

ベースイメージの比較では、現在の`FROM`のタグが指す内容のレイヤーと、稼働イメージの先頭のレイヤーが一致することを確認します。
比較条件の詳細は[スキャンの比較条件](remediation-logic.md#comparison-conditions)を参照してください。

イメージタグとベースイメージの更新では、PR本文の所見を次の区分に分けます。

| 区分 | 意味 | PR本文での表示 | Slack・Webhookの件数に入るか |
| --- | --- | --- | --- |
| 対象 | 修正版が報告されている、更新で解消を目指す所見 | 対象の解消と残存 | 解消・残存の件数に含む |
| その他 | 修正版の報告がない所見など、更新対象に含まれない所見 | 対象とは別の一覧・件数 | 対象の解消・残存の件数に含めない |
| 新規 | 比較元にはなく、候補で検出された所見 | 対象・その他とは別の一覧・件数 | 新規の件数に含む |

Dockerfileのベースイメージ更新では、ベースのレイヤーに帰属する所見を対象にします。
レイヤーが分からなくても、稼働イメージとベースイメージで版を示す環境変数が一致するNode.js・Pythonのランタイム本体の所見を含めます。

詳しくは[ランタイム本体の扱い](remediation-base-image-logic.md#base-runtime-findings)を参照してください。
候補に残るその他の所見と、新規の所見は、対象の解消・残存とは分けて表示します。

Compose・Kubernetesマニフェスト・Kustomize・HelmのvaluesのPRでは、その他の所見が候補で検出されなくなった件数も表示します。
該当する所見がある場合だけ、検出されなくなったその他の所見の一覧を載せます。

KestreLynxが確かめていないことは次のとおりです。

- 変更後のDockerfileからビルドした完成イメージでの解消
- 配置後の稼働中のコンテナでの解消
- 更新後の依存ファイルを使った実際の依存のインストール
- アプリケーションのビルド・テストの成功や動作

!!! note "解消の表示と稼働状態"

    PRやSlackの「解消」は比較結果です。
    再ビルドした完成イメージや、配置後の稼働中のコンテナで解消したことを示すものではありません。

更新の種類ごとの検査範囲と採用条件は[対象別の検証範囲](remediation-logic.md#verification-scope)を参照してください。
