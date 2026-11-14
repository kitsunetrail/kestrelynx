---
title: Kubernetesの言語パッケージ更新の準備
---

# Kubernetesの言語パッケージ更新の準備

## 作業用Podの準備 {#kubernetes-language-updates}

npm・pnpm・pip・uv・Go・Gradleの更新は、利用者が用意した作業用namespaceにKestreLynxが作る使い捨ての作業用Podで実行します。
npm・pnpm・uvでは、更新を妨げる依存元も更新する[依存元からの再解決](remediation-reresolution-logic.md#dependent-reresolution)にも同じPodを使います。

Mavenの更新はKestreLynxによる`pom.xml`の編集とTrivyの検査で行うため、作業用Podの準備は不要です。

先に[GitHubアクセスの準備](remediation-setup.md#prepare-github-access)で、修正PRに必要な権限を持つGitHub tokenを設定してください。
[ソースの対応付け](remediation-setup.md#map-source)に従い、更新対象の`remediation.mappings`に`dependencies.directory`を設定してください。

作業用Podの準備は、次の順に進めます。

1. [導入条件](#work-pod-requirements)を確認する
2. [マニフェストの準備](#work-pod-manifests)に従ってファイルを編集する
3. [マニフェストの適用](#work-pod-apply)のコマンドを実行する
4. [設定](#work-pod-config)に従って作業用namespaceと対応付けを設定し、Kubernetesのページへ戻る

このページで使う用語は[用語](remediation.md#terms)を参照してください。

### 導入条件 {#work-pod-requirements}

作業用Podを実行するクラスタとノードについて、次の条件を満たすことを確認します。

| 条件 | 必要な値や状態 |
| --- | --- |
| Kubernetesの版 | `1.30`以上 |
| KestreLynxの設定 | `kubernetes.enabled: true` |
| ノードのログ保存設定 | 作業用Podを実行する全ノードで、kubeletの`containerLogMaxSize`が`144Mi`以上 |
| ノードのプロセス数制限 | 作業用Podを実行する全ノードで、Podごとのプロセス数を制限するPID上限が設定済み |
| ネットワーク機能 | NetworkPolicyを実施するCNI |

`144Mi`以上が必要なのは、最大の結果ログがAPI経由では約94.56 MiB、ノード上の保存時には約143.69 MiBになるためです。
ログの切り詰めやローテーションで結果が欠けると、KestreLynxはその結果を採用しません。

### マニフェストの準備 {#work-pod-manifests}

作業用Podの名前・許可するイメージ・通信先を、配布マニフェストで配置先に合わせます。

1. `deploy/kubernetes/work/`があるKestreLynxのリポジトリのルートへ移動する

    手元にない場合は、次のコマンドで取得して移動します。

    ```sh
    git clone https://github.com/kitsunetrail/kestrelynx.git
    cd kestrelynx
    ```

2. `deploy/kubernetes/work/`内のファイルを、次の表に従って編集する

表のファイル名は、すべて`deploy/kubernetes/work/`からの相対パスです。

作業用namespaceの名前は、次のファイルの各キーでそろえます。

| ファイル | キー |
| --- | --- |
| `00-namespace.yaml` | Namespaceの`metadata.name`、ServiceAccountの`metadata.namespace` |
| `10-rbac.yaml` | RoleとRoleBindingの`metadata.namespace` |
| `30-resourcequota.yaml` | `metadata.namespace` |
| `40-networkpolicy.yaml` | `metadata.namespace` |
| `51-validatingadmissionpolicybinding.yaml` | `spec.paramRef.namespace`、`spec.matchResources.namespaceSelector.matchLabels["kubernetes.io/metadata.name"]` |
| `52-policy-params.yaml` | `metadata.namespace` |

作業用ServiceAccountの名前は、次のファイルの各キーでそろえます。

| ファイル | キー |
| --- | --- |
| `00-namespace.yaml` | ServiceAccountの`metadata.name` |
| `52-policy-params.yaml` | `data.serviceAccount` |

PriorityClassの名前は、次のファイルの各キーでそろえます。

| ファイル | キー |
| --- | --- |
| `20-priorityclass.yaml` | `metadata.name` |
| `52-policy-params.yaml` | `data.priorityClass` |

入力ファイルを受け取るコンテナに許可するKestreLynxイメージのリポジトリは、`receiverRepository`で指定します。
パッケージマネージャーを実行するコンテナに許可するイメージのリポジトリは、`workRepositories`で指定します。

KestreLynxのServiceAccount、イメージ、アーキテクチャ、通信先は、次のキーを編集します。

| 合わせる値 | ファイル | キー |
| --- | --- | --- |
| KestreLynxのServiceAccount名とnamespace | `10-rbac.yaml` | RoleBindingの`subjects[0].name`と`subjects[0].namespace` |
| 入力ファイル受信用のKestreLynxイメージのリポジトリ | `52-policy-params.yaml` | `data.receiverRepository` |
| 更新実行用イメージのリポジトリ | `52-policy-params.yaml` | `data.workRepositories` |
| KestreLynxのPodと実行ノードのアーキテクチャ | `52-policy-params.yaml` | `data.arch` |
| NetworkPolicyのDNSの選択条件 | `40-networkpolicy.yaml` | `spec.egress[0].to[0].namespaceSelector.matchLabels`と`spec.egress[0].to[0].podSelector.matchLabels` |
| TCP443の送信を許可するアドレス範囲 | `40-networkpolicy.yaml` | `spec.egress[1].to[0].ipBlock.cidr` |
| TCP443の送信先から除外するアドレス範囲 | `40-networkpolicy.yaml` | `spec.egress[1].to[0].ipBlock.except` |

`receiverRepository`の既定値は`ghcr.io/kitsunetrail/kestrelynx`です。
`workRepositories`の既定値は`docker.io/library/node,docker.io/library/python,docker.io/library/golang,docker.io/library/gradle`です。

`arch`の既定値は`amd64`です。

リポジトリ名にはレジストリのホスト名を含め、タグとdigestは含めません。
`remediation.worker.registry`でミラーを設定している場合は、`workRepositories`の4つのリポジトリをすべて取得先に合わせます。

配布例は、`cidr: 0.0.0.0/0`から`except`の範囲を除いた宛先にTCP443の送信を許可します。
クラスタのPod・Service・ノードのアドレス範囲を、除外する`except`に反映してください。

イメージの取得先の設定は[作業用コンテナ](configuration.md#remediation-worker)、通信制限の範囲は[作業用コンテナのネットワーク](outbound-communication.md#worker-network)を参照してください。

`50-validatingadmissionpolicy.yaml`と`51-validatingadmissionpolicybinding.yaml`の`metadata.name`は、確認処理が使う`kestrelynx-work`のままにします。
`20-priorityclass.yaml`の`preemptionPolicy: Never`も維持します。

### マニフェストの適用 {#work-pod-apply}

用意したマニフェストを適用し、作業用namespaceと制限、KestreLynxに追加する操作権限を作成します。

KestreLynxのリポジトリのルートで、次のコマンドを順に実行します。
namespace、制限、ポリシーのパラメータ、ポリシーとbinding、操作権限の順に適用します。

```sh
kubectl apply -f deploy/kubernetes/work/00-namespace.yaml
kubectl apply -f deploy/kubernetes/work/20-priorityclass.yaml
kubectl apply -f deploy/kubernetes/work/30-resourcequota.yaml
kubectl apply -f deploy/kubernetes/work/40-networkpolicy.yaml
kubectl apply -f deploy/kubernetes/work/52-policy-params.yaml
kubectl apply -f deploy/kubernetes/work/50-validatingadmissionpolicy.yaml
kubectl apply -f deploy/kubernetes/work/51-validatingadmissionpolicybinding.yaml
kubectl apply -f deploy/kubernetes/work/10-rbac.yaml
```

作業用namespaceにはPod Securityの`restricted`を適用し、作業用ServiceAccountには権限やトークンを持たせません。
配布するResourceQuotaはPod数を8に制限し、CPU・メモリ・一時ストレージにも上限を設けます。

RoleとRoleBindingを適用した場合だけ、作業用namespaceに限ってKestreLynxへ次の権限を追加します。

| 対象 | 追加する操作 |
| --- | --- |
| `pods` | `create`・`get`・`list`・`delete` |
| `pods/attach` | 入力ファイルを受信用コンテナの標準入力へ送る接続の`create`・`get` |
| `pods/log` | 暗号化した結果を回収するための`get` |

スキャン用ClusterRoleは読み取り専用で、Secretを含むほかのリソースの操作権限は追加しません。
Podの安全策と実行条件は[作業用Podの実行](remediation-worker-logic.md#kubernetes-work-pods)を参照してください。

### 設定 {#work-pod-config}

KestreLynxの設定で、`remediation.worker.kubernetes.namespace`に作業用namespaceを指定し、更新対象を対応付けます。

1. `deploy/kubernetes/configmap.yaml`の`data.config.yml`に、次のYAMLを既存の設定と統合する

    既存のGitHub tokenと`remediation.mappings`を保持します。
    設定をSecretで管理している場合は、Secretの作成に使った`config.yml`を編集します。

    例の`namespace`を適用した作業用namespace名に、`workload`と`repository`を更新対象に合わせます。

    ```yaml
    kubernetes:
      enabled: true
    remediation:
      enabled: true
      pull_requests:
        enabled: true
      worker:
        kubernetes:
          namespace: kestrelynx-work
      mappings:
        - workload: deployment/example/api/app
          repository: example/application
          base_branch: main
          dependencies:
            directory: .
    ```

    作業用ServiceAccount名やPriorityClass名を変えた場合は、同じ`config.yml`の`remediation.worker.kubernetes.service_account`と`remediation.worker.kubernetes.priority_class`もそろえます。
    設定キーの既定値と制約は[作業用コンテナのKubernetes設定](configuration.md#remediation-worker-kubernetes)を参照してください。

2. Kubernetesのページの[PR作成の有効化と反映](remediation-setup-kubernetes.md#kubernetes-enable-pr-creation)へ戻り、PR作成の有効化、設定の反映、起動と処理結果の確認を行う
