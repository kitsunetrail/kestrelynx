---
title: 修正計画と修正PRの有効化の手順
---

# 修正計画と修正PRの有効化の手順

まず修正計画だけを有効にして通知を確認し、その後で修正PRを有効にします。
このページで環境に共通する準備を行い、設定の反映と起動確認は環境ごとのページで進めてください。

機能については[機能の概要](remediation.md#overview)、対象となる環境と入力は[対応範囲](remediation-reference.md#scope-and-requirements)で確認できます。
必要な通信先は[通信先一覧](outbound-communication.md#outbound-communication)を参照してください。

このページで使う用語は[用語](remediation.md#terms)を参照してください。

## 修正計画の有効化 {#enable-fix-plans}

修正計画の有効化は、共通の準備から始め、環境ごとの起動確認へ進めます。

配布イメージの候補だけを調べる場合は、GitHubリポジトリ・token・対応付けの準備を省き、手順3から進んでください。
ベースイメージや言語パッケージも調べる場合は、手順1から進んでください。

次の順で作業してください。

1. [GitHubアクセスの準備](#prepare-github-access)で、対象リポジトリと必要なtokenを用意する
2. [ソースの対応付け](#map-source)で、更新対象に合う設定キーと対象ファイルの場所を決める
3. 非公開イメージを使う場合は、[非公開イメージの認証](#configure-registry-auth)を設定する
4. 監視対象の環境に合うページへ進み、必要な設定を編集・反映して起動と通知を確認する

監視対象の環境に合わせて、次のページへ進んでください。

| 監視対象の環境 | 進むページ |
| --- | --- |
| Compose・docker run | [Dockerでの修正計画と修正PRの有効化](remediation-setup-docker.md) |
| Kubernetes | [修正計画の設定](remediation-setup-kubernetes.md#kubernetes-plans) |

編集する設定の場所と反映方法は、KestreLynx自身の起動方法で選びます。
配布構成では、次の設定を編集します。

| KestreLynxの起動方法 | 編集するファイル／設定の場所 | 反映方法 |
| --- | --- | --- |
| Compose | 配置ディレクトリの`config.yml` | コンテナの再作成 |
| docker run | `/etc/kestrelynx/config.yml`へマウントしているホスト上の`config.yml` | コンテナの再作成 |
| Kubernetesクラスタ内 | `deploy/kubernetes/configmap.yaml`の`data.config.yml` | ConfigMapの適用とPodの再起動 |

設定をSecretで管理している場合は、Secretの作成に使った`config.yml`を編集します。
反映には[クラスタ内での非公開レジストリの認証](getting-started.md#kubernetes-private-registry)にあるSecretの更新手順を使ってください。

以下の設定例は、編集対象の既存の`config.yml`へ統合してください。
同じファイルに`remediation`セクションを重複して追加しないでください。

配布のCompose構成では、計画やPR処理の記録は状態保存用のボリュームに保存されます。
`remediation.storage_dir`を変更する場合は、コンテナを作り直しても残る場所を指定してください（[基本設定](configuration.md#remediation-basics)）。

### GitHubアクセスの準備 {#prepare-github-access}

GitHubアクセスの準備では、ソースの取得元・PRの宛先と、必要なtokenを決めます。
用途に合わせて、tokenの要否と権限を確認してください。

| やりたいこと | token |
| --- | --- |
| 公開リポジトリのソースを読んで修正計画だけを作る | 不要 |
| 非公開リポジトリのソースを読んで修正計画だけを作る | Contents: Read |
| 公開・非公開リポジトリで修正PRを作成・管理する | ContentsとPull requests: Read and write |

対象リポジトリとtokenを、次の順で準備してください。

1. 対象のGitHubリポジトリと、ソースの取得元・PRの宛先にするブランチを決める
2. tokenが必要な場合は、対象リポジトリに限定したfine-grained tokenを用意する
3. 編集対象の`config.yml`に、既定の`remediation.github.token`か、所有者ごとの`remediation.github.tokens`を設定する
4. tokenを含む設定ファイルは所有者だけが読めるようにし、リポジトリへのコミット対象から外す

対象リポジトリの所有者が複数ある場合は、所有者ごとにtokenを用意してください。
fine-grained tokenが権限を持てるのは、1つの所有者（ユーザーまたは組織）のリポジトリだけです。

`example-org/application`と`example-user/deployment`を使う場合は、`config.yml`の`remediation.github.tokens`へ次の設定を統合します。
例のtokenを、各所有者の対象リポジトリに権限を持つtokenへ置き換えてください。

```yaml
remediation:
  github:
    tokens:
      - owner: example-org
        token: example-token-for-org
      - owner: example-user
        token: example-token-for-user
```

`tokens`にない所有者には、既定の`remediation.github.token`を使います。
`token`だけでも設定でき、すべての所有者を`tokens`に設定する場合は既定のtokenを省略できます。

PR作成が無効で、所有者ごとのtokenも既定のtokenもない場合は、公開リポジトリを匿名で読み取ります。
設定の細目は[GitHubアクセス](configuration.md#remediation-github)を参照してください。

### ソースの対応付け {#map-source}

更新したいものと監視対象の環境に合わせて、設定するキーを選んでください。

| 更新したいもの | 設定するキー | 使える環境 |
| --- | --- | --- |
| Composeファイルのイメージタグ | `compose` | Compose |
| Kubernetesマニフェストのイメージタグ | `manifest` | Kubernetes |
| Kustomizeの`images`のタグ | `kustomize` | Kubernetes |
| Helmのvaluesのイメージタグ | `helm_values` | Kubernetes |
| Dockerfileのベースイメージ | `dockerfile` | Compose・docker run・Kubernetes |
| 言語パッケージ | `dependencies` | Compose・docker run・Kubernetes |

ここでは、更新対象の設定キーと対象ファイルの場所を決めます。
`remediation.mappings`の編集と修正計画の有効化は、環境ごとのページで行ってください。

`path`と`directory`は、GitHubリポジトリのルートからのパスです。
たとえば`path: compose.yml`は、リポジトリのルートにある`compose.yml`を指します。

Maven・Gradleを使う場合は、次のディレクトリを`dependencies.directory`に指定してください。

| パッケージマネージャー | `dependencies.directory`に指定するディレクトリ |
| --- | --- |
| Maven | `pom.xml`のあるディレクトリ |
| Gradle | `gradle.lockfile`・ビルドスクリプト・settingsのあるディレクトリ |

Mavenのマルチモジュールでは、`modules`で各モジュールをたどれるルートの`pom.xml`のディレクトリを指定してください。
`pom.xml`がリポジトリのルートにある場合は、`.`を指定します。

Gradleのlockの設定や必要なファイルは、[Gradleの依存ファイル](remediation-dependency-formats.md#gradle-inputs)で確認してください。
複数の対応付けを使う場合の制約は[ソースの対応付け](configuration.md#remediation-mappings)、有効化キーは[基本設定](configuration.md#remediation-basics)を参照してください。

### 非公開イメージの認証 {#configure-registry-auth}

非公開イメージの認証は、修正計画と通常のスキャンでイメージを読み取るための設定です。
公開イメージだけを扱う場合、この設定は不要です。

認証が必要な場合は、次の順で`config.yml`を編集してください。

1. 対象イメージを読み取れる認証情報を用意する
2. `config.yml`のトップレベルに、対象ホストの`registries`を追加する

    `registry.example.com`を使う場合は、次の設定を統合し、認証情報を実際の値へ置き換えてください。

    ```yaml
    registries:
      - host: registry.example.com
        username: example-puller
        password: "REPLACE_WITH_REGISTRY_READ_TOKEN"
    ```

3. 一時的なtokenを発行するサーバー（token service）が別ホストにある場合は、認証情報の送付先を確認して`token_hosts`に追加する

    Docker Hubを使う場合は、同じ`config.yml`の`registries`に次の設定を統合し、認証情報を実際の値へ置き換えてください。

    ```yaml
    registries:
      - host: docker.io
        username: example-puller
        password: "REPLACE_WITH_REGISTRY_READ_TOKEN"
        token_hosts: [auth.docker.io]
    ```

各キーの設定条件は[イメージレジストリの認証](configuration.md#registries)、送付先の制限は[認証情報の送付範囲](outbound-communication.md#credential-destinations)を参照してください。
Kubernetesクラスタ内での設定と反映は、[クラスタ内での非公開レジストリの認証](getting-started.md#kubernetes-private-registry)に従ってください。

## 修正PRの有効化 {#enable-pull-requests}

修正PRの設定・反映・確認は、環境ごとのページで行います。
環境ごとの手順で修正計画の起動を確認し、通知のワークロード・ソース・更新対象が意図したものか確認してから進んでください。

先に[PR作成の前提と注意](#enable-pr-creation)を確認し、監視対象の環境に合う節へ進んでください。

| 監視対象の環境 | 進む節 |
| --- | --- |
| Compose・docker run | [修正PRの有効化](remediation-setup-docker.md#docker-enable-pull-requests) |
| Kubernetes | [修正PRの設定](remediation-setup-kubernetes.md#kubernetes-enable-pull-requests) |

### PR作成の前提と注意 {#enable-pr-creation}

PR作成を有効にする前に、tokenの権限と複数ホストでの担当を確認します。
[GitHubアクセスの準備](#prepare-github-access)に従い、対応付けたすべてのリポジトリにPR作成の権限を持つtokenがあることを確認してください。

複数ホストで動かす場合、同じリポジトリの同じファイルを更新するPRの作成は1つのインスタンスに任せてください。
対象はComposeファイル・Kubernetesマニフェスト・Kustomize・Helmのvalues・Dockerfile・依存ファイルです。

PRの重複を防ぐ仕組みはホストごとです。
他のホストでは対象の対応付けを設定しないか、`remediation.pull_requests.enabled: false`で計画だけを有効にしてください。

PRを作ると、対象リポジトリの`pull_request`を契機とするワークフローが起動することがあります。
PR本文を編集する場合は、記録の照合と復旧に使うHTMLコメントの識別マーカーを残してください。

設定の編集と反映は、Dockerでは[修正PRの有効化](remediation-setup-docker.md#docker-enable-pull-requests)、Kubernetesでは[PR作成の有効化と反映](remediation-setup-kubernetes.md#kubernetes-enable-pr-creation)に従ってください。
