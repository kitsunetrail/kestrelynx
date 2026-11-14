---
title: Kubernetesでの修正計画と修正PRの有効化
---

# Kubernetesでの修正計画と修正PRの有効化

Kubernetesで動かしているKestreLynxで、修正計画を確認してから修正PRを有効にする手順です。
先に[共通の準備](remediation-setup.md#enable-fix-plans)（GitHubアクセスの準備、ソースの対応付け、必要なら非公開イメージの認証）を済ませ、修正計画の設定、起動確認、修正PRの設定、[PR作成の有効化と反映](#kubernetes-enable-pr-creation)の順に進めてください。

このページで使う用語は[用語](remediation.md#terms)を参照してください。

## 修正計画の設定 {#kubernetes-plans}

修正計画で調べる対象を設定します。

1. `deploy/kubernetes/configmap.yaml`の`data`内の`config.yml`に、次の最小設定を統合する

    配布イメージの候補だけを調べる場合は、次の設定だけで始められます。
    設定をSecretで管理している場合は、Secretの作成に使った`config.yml`を編集してください。

    ```yaml
    remediation:
      enabled: true
    ```

    `remediation`を重複して追加せず、PR作成は`remediation.pull_requests.enabled: false`（既定値）のままにしてください。

2. 言語パッケージやベースイメージも調べる場合は、対応付けを追加する

    `deploy/kubernetes/configmap.yaml`の`data`内の`config.yml`（Secretの場合は`config.yml`）で、言語パッケージとベースイメージを指定する例です。

    ```yaml
    remediation:
      mappings:
        - workload: deployment/example/web/app
          repository: example/application
          base_branch: main
          dependencies:
            directory: .
          dockerfile:
            path: docker/Dockerfile
    ```

    調べない対象の`dependencies`または`dockerfile`は省いてください。
    キーの選び方と依存ディレクトリの準備は[ソースの対応付け](remediation-setup.md#map-source)を参照してください。

`workload`には、通知に表示されたワークロードキーを使います。
`deployment/example/web/app`は、種類が`deployment`、名前空間が`example`、ワークロード名が`web`、コンテナ名が`app`を表します。

キーの制約は[Kubernetesの対応付け](configuration.md#remediation-mappings-kubernetes)、有効化の設定は[基本設定](configuration.md#remediation-basics)を参照してください。

修正計画では追加で`deployments`・`statefulsets`・`daemonsets`・`cronjobs`をLISTしますが、配布の読み取り専用ClusterRoleに権限の追加は不要です。

## 修正計画の起動確認 {#kubernetes-verify-plans}

編集した設定を反映し、修正計画が動くことを確認します。

1. `deploy/kubernetes/configmap.yaml`の`data`内の`config.yml`（Secretの場合は`config.yml`）に、[修正計画の設定](#kubernetes-plans)を統合したことを確認する

2. リポジトリのルートで、ConfigMapを適用してKestreLynxのPodを再起動する

    Secretの場合は、先頭のConfigMap適用を[クラスタ内での非公開レジストリの認証](getting-started.md#kubernetes-private-registry)にあるSecretの更新手順に置き換えてください。

    ```sh
    kubectl apply -f deploy/kubernetes/configmap.yaml
    kubectl rollout restart -n kestrelynx deployment/kestrelynx
    kubectl rollout status -n kestrelynx deployment/kestrelynx
    ```

3. 次のコマンドで、設定の読み込みと修正計画の処理結果を確認する

    ```sh
    kubectl logs -n kestrelynx deployment/kestrelynx -f
    ```

    次のログと値で、有効化と計画の作成を確認してください。

    | 確認すること | ログ | 確認する値 |
    | --- | --- | --- |
    | 修正計画の有効化 | `fix plan enabled` | `pull_requests=false` |
    | 計画の作成 | `fix plan built` | 項目数の`items`・`dependency_units`・`dockerfile_items` |
    | 更新候補の件数 | `fix plan built` | `update_candidate`・`dependency_update_candidates`・`dockerfile_update_candidates` |

    計画の項目数や更新候補の件数が0でも、有効化の失敗ではありません。

    起動後または次の予定時刻のスキャンで、通知のワークロード、ソース、更新対象が意図したものか確認してください。
    表示の意味は[表示項目](remediation-results.md#slack-fields)、計画が見つからない場合は[計画が出ない場合の確認](remediation-troubleshooting.md#check-missing-plan)を参照してください。

## 修正PRの設定 {#kubernetes-enable-pull-requests}

修正PRで更新するファイルを指定します。
[修正計画の起動確認](#kubernetes-verify-plans)を終えてから、次の順に進めてください。

1. このページの各節で、更新したいものの対応付けを設定する
2. npm・pnpm・pip・uv・Go・Gradleの言語パッケージを更新する場合は、[作業用Podの準備](remediation-setup-work-pods.md#kubernetes-language-updates)で作業用namespaceと対応付けの設定まで済ませ、このページへ戻る（Mavenだけなら不要）
3. [PR作成の有効化と反映](#kubernetes-enable-pr-creation)を行い、起動と処理結果を確認する

更新したいものから、設定するキーと手順を選びます。

| 更新したいもの | 設定するキー | 手順 |
| --- | --- | --- |
| マニフェストのイメージタグ | `manifest` | [マニフェストとDockerfileのPR設定](#kubernetes-pull-requests) |
| Kustomizeのイメージタグ | `kustomize` | [KustomizeのPR設定](#kustomize-pull-requests) |
| Helmのvaluesのイメージタグ | `helm_values` | [HelmのvaluesのPR設定](#helm-values-pull-requests) |
| Dockerfileのベースイメージ | `dockerfile` | [マニフェストとDockerfileのPR設定](#kubernetes-pull-requests) |
| 言語パッケージ | `dependencies` | [ソースの対応付け](remediation-setup.md#map-source)と[作業用Podの準備](remediation-setup-work-pods.md#kubernetes-language-updates) |

1つのコンテナのイメージタグには、`manifest`・`kustomize`・`helm_values`のうち1種類だけを指定してください。
言語パッケージの更新には、Mavenを除き、作業用Podが必要です。

### マニフェストとDockerfileのPR設定 {#kubernetes-pull-requests}

マニフェストのイメージタグと、Dockerfileのベースイメージの更新先を指定します。

`deploy/kubernetes/configmap.yaml`の`data`内の`config.yml`（Secretの場合は`config.yml`）の`remediation.mappings`を編集してください。
`web/app`のタグを`apps/web.yaml`で、`api/app`のベースイメージを`docker/Dockerfile`で更新する例です。

```yaml
remediation:
  mappings:
    - workload: deployment/example/web/app
      repository: example/deployment
      base_branch: main
      manifest:
        path: apps/web.yaml
    - workload: deployment/example/api/app
      repository: example/application
      base_branch: main
      dockerfile:
        path: docker/Dockerfile
        target: runtime
```

`target: runtime`の`runtime`は、`docker/Dockerfile`の`FROM ... AS runtime`で付けたステージ名です。
対象イメージをビルドするステージ名に置き換え、最後のステージを使う場合は`target`を省略できます。

言語パッケージも更新する場合、npm・pnpm・pip・uv・Go・Gradleには[作業用Podの準備](remediation-setup-work-pods.md#kubernetes-language-updates)が必要です。
編集できる書式は[マニフェストの書式](remediation-source-formats.md#manifest-formats)、PRの作成条件は[KubernetesのマニフェストPR](remediation-kubernetes-logic.md#kubernetes-manifest-prs)を参照してください。

### KustomizeのPR設定 {#kustomize-pull-requests}

Kustomizeの`images`で管理するタグの更新先と、タグの変更で影響を受けるコンテナを指定します。
同じコンテナのイメージタグには1種類だけを指定するため、既存の`manifest`または`helm_values`の指定は`kustomize`に置き換えてください。

1. 対象リポジトリの`apps/kustomization.yaml`で、更新する`images`の項目を確認する

    `nginx`のタグを管理するファイルの例です。

    ```yaml
    apiVersion: kustomize.config.k8s.io/v1beta1
    kind: Kustomization
    resources:
      - web.yaml
      - worker.yaml
    images:
      - name: nginx
        newTag: "1.27.2" # 使用するタグ
    ```

2. `deploy/kubernetes/configmap.yaml`の`data`内の`config.yml`（Secretの場合は`config.yml`）の`remediation.mappings`を編集する

    `web`と`worker`の`app`、および`web`の通常のinit containerである`prepare`が、同じ`images`の項目を使う例です。

    ```yaml
    remediation:
      mappings:
        - workload: deployment/example/web/app
          repository: example/deployment
          base_branch: main
          kustomize:
            path: apps/kustomization.yaml
            image: nginx
            affects:
              - deployment/example/worker/app
              - deployment/example/web/prepare
    ```

    通常のinit containerは、Podのstatusから、同じPod内の列挙済み稼働コンテナとイメージ名・中身が一致すると確認できる必要があります。
    その稼働コンテナのスキャン結果も必要です。

    条件を確認できない場合の詳しい確認方法は、[PRを作れない場合の確認](remediation-troubleshooting.md#check-missing-pr)を参照してください。

    `image`には`images[].name`を指定します。
    `workload`には、その`images`の項目でタグが決まるコンテナから任意の1つを選びます。

    選んだコンテナ以外は、通常のinit containerも含め、すべて`affects`に書きます。
    例のコンテナは次のように分けて書きます。

    | コンテナ | どこに書くか |
    | --- | --- |
    | `deployment/example/web/app` | `workload` |
    | `deployment/example/worker/app` | `kustomize.affects` |
    | `deployment/example/web/prepare`（通常のinit container） | `kustomize.affects` |

3. タグの変更で影響を受けるコンテナを、通常のinit containerも含め、`workload`と`affects`にすべて書いたことを確認する

    KestreLynxはKustomizeを展開しないため、利用者が確認してください。
    `affects`を省略できるのは、影響を受けるコンテナが`workload`の1つだけだと確認した場合です。

設定の制約は[Kubernetesの対応付け](configuration.md#remediation-mappings-kubernetes)、書式は[Kustomizeの書式](remediation-source-formats.md#kustomize-formats)、PRの作成条件は[KustomizeのPR](remediation-kubernetes-logic.md#kustomize-prs)を参照してください。

### HelmのvaluesのPR設定 {#helm-values-pull-requests}

Helmのvaluesで管理するタグの更新先と、タグの変更で影響を受けるコンテナを指定します。
同じコンテナのイメージタグには1種類だけを指定するため、既存の`manifest`または`kustomize`の指定は`helm_values`に置き換えてください。

1. 対象リポジトリの`apps/values.yaml`で、イメージを指定しているYAMLのキーを確認する

    `image`キーでイメージを指定するファイルの例です。

    ```yaml
    image:
      registry: docker.io
      repository: library/nginx
      tag: "1.27.2" # 使用するタグ
    ```

    `helm_values.key`には、`tag`自体ではなく、`repository`と`tag`を持つキーへの経路を指定します。
    `registry`は省略でき、`image: "nginx:1.27.2"`のような文字列にも`key: image`を使えます。

    `apps/values.yaml`が`app: {image: "nginx:1.27.2"}`という入れ子の記述なら、`helm_values.key`には`app.image`を指定します。

2. `deploy/kubernetes/configmap.yaml`の`data`内の`config.yml`（Secretの場合は`config.yml`）の`remediation.mappings`を編集する

    `web`と`worker`の`app`、および`web`の通常のinit containerである`prepare`が、最初の例の`image`キーを使う設定です。

    ```yaml
    remediation:
      mappings:
        - workload: deployment/example/web/app
          repository: example/deployment
          base_branch: main
          helm_values:
            path: apps/values.yaml
            key: image
            affects:
              - deployment/example/worker/app
              - deployment/example/web/prepare
    ```

    通常のinit containerは、Podのstatusから、同じPod内の列挙済み稼働コンテナとイメージ名・中身が一致すると確認できる必要があります。
    その稼働コンテナのスキャン結果も必要です。

    条件を確認できない場合の詳しい確認方法は、[PRを作れない場合の確認](remediation-troubleshooting.md#check-missing-pr)を参照してください。

    `workload`には、そのvaluesのキーでタグが決まるコンテナから任意の1つを選びます。
    残りは、通常のinit containerも含め、すべて`affects`に書きます。

    | コンテナ | どこに書くか |
    | --- | --- |
    | `deployment/example/web/app` | `workload` |
    | `deployment/example/worker/app` | `helm_values.affects` |
    | `deployment/example/web/prepare`（通常のinit container） | `helm_values.affects` |

3. タグの変更で影響を受けるコンテナを、通常のinit containerも含め、`workload`と`affects`にすべて書いたことを確認する

    `affects`を省略できるのは、影響を受けるコンテナが`workload`の1つだけだと確認した場合です。

4. 指定したキーの値が最終的なイメージの値であり、ほかの設定で上書きされないことを確認する

    KestreLynxはHelmを描画しないため、利用者が次の上書き元を確認してください。

    - Flux HelmReleaseの`spec.values`
    - Argo CDの`parameters`・`valuesObject`・`valuesFrom`
    - CIの`--set`やほかのvaluesファイル

設定の制約は[Kubernetesの対応付け](configuration.md#remediation-mappings-kubernetes)、書式は[Helmのvaluesの書式](remediation-source-formats.md#helm-values-formats)、PRの作成条件は[HelmのvaluesのPR](remediation-kubernetes-logic.md#helm-values-prs)を参照してください。

### PR作成の有効化と反映 {#kubernetes-enable-pr-creation}

設定した更新先へのPR作成を有効にし、KestreLynxに反映します。
先に[PR作成の前提と注意](remediation-setup.md#enable-pr-creation)で、tokenの権限と共通の注意を確認してください。
保存先は、[基本設定の`remediation.storage_dir`](configuration.md#remediation-basics)を確認してください。

1. 既存の対応付け、GitHub token、認証情報、保存先を保持し、`deploy/kubernetes/configmap.yaml`の`data`内の`config.yml`（Secretの場合は`config.yml`）に次の設定を統合する

    ```yaml
    remediation:
      enabled: true
      pull_requests:
        enabled: true
    ```

    マニフェスト・Dockerfile・Kustomize・Helmのvaluesの更新には、スキャン用の読み取り専用RBACだけを使います。

2. リポジトリのルートで、ConfigMapを適用してKestreLynxのPodを再起動する

    Secretの場合は、先頭のConfigMap適用を[クラスタ内での非公開レジストリの認証](getting-started.md#kubernetes-private-registry)にあるSecretの更新手順に置き換えてください。

    ```sh
    kubectl apply -f deploy/kubernetes/configmap.yaml
    kubectl rollout restart -n kestrelynx deployment/kestrelynx
    kubectl rollout status -n kestrelynx deployment/kestrelynx
    ```

3. 次のコマンドで、PR作成の有効化と処理結果を確認する

    ```sh
    kubectl logs -n kestrelynx deployment/kestrelynx -f
    ```

    次のログと値で、PR作成の有効化と処理結果を確認してください。

    | 確認すること | ログ | 確認する値 |
    | --- | --- | --- |
    | PR作成の有効化 | `fix plan enabled` | `pull_requests=true` |
    | PR処理の結果 | `pull request stage finished` | 作成数の`created`と、PR処理全体の問題の件数を示す`problems` |

    PRが作られない場合は、[PRを作れない場合の確認](remediation-troubleshooting.md#check-missing-pr)を参照してください。
