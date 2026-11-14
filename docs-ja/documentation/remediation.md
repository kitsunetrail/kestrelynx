# 修正計画と修正PR

!!! warning "実験的な機能"

    修正計画と修正PRは実験的な機能です。設定・通知・PRの形式は今後変わることがあります。

## 機能の概要 {#overview}

修正計画は、稼働イメージの所見を基に、イメージや依存パッケージの更新を提案します。
修正PRを追加で有効にすると、設定で指定したGitHubリポジトリのファイルに対し、条件を満たす更新のPRを作成します。

提案とPRの状態はSlackの「修正計画」に表示されます。
このページで使う用語は[用語](#terms)を参照してください。

既製のイメージをそのまま使う場合は、配布イメージのタグが更新対象です。
自分たちのソースからビルドする場合は、レジストリへの登録の有無にかかわらず、Dockerfileのベースイメージと依存ファイルを更新対象として設定します。

更新対象ごとに、計画が示す内容と、修正PRを有効にした場合の変更先を示します。

| 更新するもの | 例 | 修正計画が示すこと | 修正PR |
| --- | --- | --- | --- |
| 配布イメージの固定タグ | `nginx:1.27.0` | タグの更新候補とスキャンの比較結果 | Compose・Kubernetesマニフェスト・Kustomize・Helmのvaluesのタグ変更 |
| 配布イメージの浮動タグ | `latest` | 同じタグの新しい内容を再取得する案内 | 作成なし |
| Dockerfileのベースイメージ | `FROM python:3.12.3-slim` | ベースイメージの更新候補とスキャンの比較結果 | Dockerfileの`FROM`の固定タグ変更 |
| 言語パッケージ（npm・pnpm・pip・uv・Go・Maven・Gradle） | `pnpm-lock.yaml`・`pom.xml` | パッケージの更新候補 | 依存ファイルの変更 |

`docker run`で起動したコンテナには、Dockerfileと依存パッケージの更新PRを作成できます。
起動時のイメージタグを変更するPRは作成しません。

次は、依存パッケージの更新PRを作成した場合のSlack表示の抜粋です。
架空の例で、変更先のファイル、PR番号、更新前後の版を確認できます。

```text
🔧 修正計画

イメージ: example/app:latest
修正するファイル: example/application の pnpm-lock.yaml
Pull Request: #12 (今回作成)
更新: package-a 1.2.3 → 1.2.4
```

表示項目や件数の意味、詳細な結果の確認先は[通知の読み方](remediation-results.md)を参照してください。

計画だけの場合と修正PRを有効にした場合では、KestreLynxが行う処理が異なります。
利用者が行う作業と合わせて示します。

| 有効にする機能 | KestreLynxが行うこと | 利用者が行うこと |
| --- | --- | --- |
| 修正計画のみ | 候補を選び、設定で指定したGitHub上のComposeファイル・Dockerfile・依存ファイルなどを読み、イメージ候補のスキャン結果を比較する | 提案を確認し、イメージの取得・ビルド、配置、配置後の確認を行う |
| 修正PRも有効 | 計画の処理に加え、言語パッケージの更新・検査を行い、条件を満たす変更のPRを作成・管理する | 変更内容の確認とマージ後、イメージの取得・ビルド、配置、配置後の確認を行う |

計画だけの場合は、パッケージマネージャーの実行やGitHubへの書き込みを行いません。
処理範囲の詳細は[計画とPRの実行範囲](remediation-logic.md#plan-and-pr-execution)を参照してください。

修正計画と修正PRは、Dockerモード（Composeと`docker run`を含む）とKubernetesモードで利用できます。
ソースホストはGitHubのみで、言語パッケージの取得元は公開レジストリのみです。

環境ごとの前提と更新対象は[対応範囲](remediation-reference.md#scope-and-requirements)を参照してください。

## 用語 {#terms}

この章の各ページで共通に使う用語を、参照用の表にまとめます。

| 用語 | 意味 |
| --- | --- |
| 所見 | スキャンで検出した脆弱性 |
| 稼働イメージ | 稼働中のコンテナが使っているイメージ |
| 配布イメージ | レジストリから取得してそのまま動かす既製イメージ |
| ベースイメージ | Dockerfileの`FROM`で指定するイメージ |
| 固定タグ | `1.27.0`のように完全な版を指定するタグ |
| 浮動タグ | `latest`や`22-alpine`のように、指す内容が変わるタグ |
| 系列（イメージのタグ） | イメージのタグで、major・minor・接頭辞・接尾辞が同じ版のまとまり |
| 対応付け | 稼働中のコンテナとGitHubリポジトリのファイルを結び付ける設定で、`remediation.mappings`の1項目 |
| ワークロードキー | 対応付けの`workload`で、対象のComposeサービス、Dockerコンテナ、Kubernetesのコンテナを識別する値 |
| 修正版 | 脆弱性情報が「この版で直る」と報告している版 |
| 稼働版 | 稼働イメージで検出した版 |
| 更新目標 | 更新先を選ぶときの下限の版 |
| 採用版 | 更新後の依存ファイルで確認した版 |
| 手動対応 | KestreLynxが自動では更新せず、利用者に判断を任せる扱い（値は`manual`、Slackでは「要判断」） |
| 保留 | 上限や待機などのために、後のサイクルへ回す扱い（値は`deferred`、Slackでは「保留」） |
| 作業用コンテナ（作業用Pod） | パッケージマネージャーを実行するためにKestreLynxが作る使い捨てのコンテナ（Kubernetesでは作業用Pod） |
| サイクル | 定期的に実行するスキャンから通知までの1回分 |

## ページの案内 {#contents}

この章のページを、導入時に読む順番と、調べたい内容別に案内します。
初めて使う場合は、次の順番で読みます。

1. [機能の概要](#overview)で、提案の内容と利用者が行う作業を確認する
2. [共通の準備](remediation-setup.md)を読み、監視対象に合わせて[Docker](remediation-setup-docker.md)または[Kubernetes](remediation-setup-kubernetes.md)の有効化手順へ進む
3. [通知の読み方](remediation-results.md)で、提案とPRの状態を確認する

導入時に読む概要と有効化の手順は、次のページにあります。

| 知りたいこと | ページ |
| --- | --- |
| 機能の全体像と利用者が行う作業 | [修正計画と修正PR（概要）](#overview) |
| 有効化に必要な共通の設定 | [共通の準備](remediation-setup.md) |
| Compose・docker runの有効化手順 | [Docker](remediation-setup-docker.md) |
| Kubernetesの有効化手順 | [Kubernetes](remediation-setup-kubernetes.md) |
| Kubernetesでパッケージマネージャーを実行する使い捨てPodの設定 | [Kubernetesの作業用Pod](remediation-setup-work-pods.md) |

通知の読み方は、導入時に結果を確認するために読みます。
更新結果やPRの確認、問題の切り分けに必要なページも合わせて示します。

| 知りたいこと | ページ |
| --- | --- |
| Slackの表示と詳細な結果の確認先 | [通知の読み方](remediation-results.md) |
| 更新結果と「再pull」「再ビルド」などの案内 | [更新結果と案内の読み方](remediation-update-results.md) |
| PR本文とマージ前に行う検証 | [PRの内容とマージ前の確認](remediation-pr-results.md) |
| 脆弱性情報が修正済みと報告する版へ更新できない理由 | [修正版に上げられないときの案内](remediation-fix-hints.md) |
| 診断情報の取得と、計画・更新・PR・記録の問題の確認 | [候補やPRが出ない場合](remediation-troubleshooting.md) |

候補の選定やPR処理の仕組みを詳しく知りたい場合は、次のページを参照してください。

| 知りたいこと | ページ |
| --- | --- |
| 計画とPRの実行範囲、比較の条件 | [処理の流れ](remediation-logic.md) |
| 配布イメージの更新候補の選び方 | [配布イメージ](remediation-image-logic.md) |
| マニフェスト・Kustomize・Helmのvaluesの変更 | [Kubernetesのタグ更新PR](remediation-kubernetes-logic.md) |
| Dockerfileの更新候補の選び方 | [ベースイメージ](remediation-base-image-logic.md) |
| パッケージの候補・実行環境の選定と更新結果の採用 | [言語パッケージの共通の規則](remediation-package-logic.md) |
| Node.js・Pythonの依存更新の規則 | [npm・pnpm・uv・pip](remediation-node-python-logic.md) |
| 対象を依存先に持つパッケージも更新する処理 | [依存元からの再解決](remediation-reresolution-logic.md) |
| Goモジュールの更新候補と検査 | [Go](remediation-go-logic.md) |
| Mavenの更新候補と検査 | [Maven](remediation-maven-logic.md) |
| Gradleの更新候補と検査 | [Gradle](remediation-gradle-logic.md) |
| パッケージマネージャーを実行する使い捨てコンテナの動作 | [作業用コンテナ](remediation-worker-logic.md) |
| 既存PRの扱いとPR処理の記録 | [PRの管理と記録](remediation-pr-logic.md) |

対応範囲、ファイルの制約、結果の値や理由コードを調べる場合は、次のページを参照してください。

| 知りたいこと | ページ |
| --- | --- |
| 利用環境・更新対象・対応する実行環境 | [対応範囲](remediation-reference.md) |
| Compose・マニフェスト・Kustomize・Helmのvalues・Dockerfileの記述条件 | [イメージを指定するファイルの形式](remediation-source-formats.md) |
| 依存ファイルと版の指定方法の条件 | [依存ファイルと版宣言の形式](remediation-dependency-formats.md) |
| 結果の値と、処理が進まなかった理由 | [結果の値と理由コード](remediation-reason-codes.md) |
| イメージの候補選定と変更対象ファイルに関する理由 | [イメージとソースの理由コード](remediation-image-reason-codes.md) |
| パッケージ更新とPR処理が進まなかった理由 | [更新とPR処理の理由コード](remediation-update-reason-codes.md) |

関連する設定と仕様は、次のページにあります。

- [設定：修正計画と修正PR](configuration.md#remediation)
- [仕組み：スキャン通知の送信条件](notification-conditions.md#notification-conditions)
- [仕組み：修正計画の共通フィールド](webhook-remediation-reference.md#remediation-fields)
- [仕組み：通信先一覧](outbound-communication.md#outbound-communication)
