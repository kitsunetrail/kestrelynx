# セットアップ手順

KestreLynxはDockerホストごとに1つのコンテナとして、またはKubernetesクラスタ内でレプリカ数1のDeploymentとして動作します。
クラスタの外のDockerコンテナからKubernetes APIサーバに接続して、クラスタをスキャンすることもできます。

実行中のコンテナが使用しているイメージを特定してスキャンし、その結果をSlack、メール、またはWebhookへ送信します。

## 必要なもの

- 実行方法に応じた次の環境
    - Dockerホストをスキャンする場合は、Docker ComposeまたはDocker CLIを利用できるDockerホスト
    - Kubernetesクラスタ内で実行する場合は、`kubectl`でアクセスでき、永続ストレージを利用できるクラスタ
    - Kubernetesクラスタの外から接続する場合は、`kubectl`でアクセスできるクラスタと、APIサーバに接続でき、Docker CLIを利用できるDockerホスト
- 次のうち1つ以上の通知先
    - Slack Incoming Webhook
    - Slack Bot Tokenとチャンネル
    - Webhook URL
    - TLS必須のSMTPメール

## 設定ファイルの準備 {#prepare-config}

Docker、Docker Compose、またはKubernetesクラスタの外から接続する場合に使う`config.yml`を作ります。

1. リポジトリをダウンロードまたはcloneし、`config.yml`を作成する

    ```bash
    git clone https://github.com/kitsunetrail/kestrelynx.git
    cd kestrelynx
    cp config.example.yml config.yml
    ```

2. 手順1で作った`config.yml`の`notify`に通知先を1つ以上設定する

    ```yaml
    notify:
      slack_webhook_url: "https://hooks.slack.com/services/..."
    ```

## Dockerで実行

[設定ファイルの準備](#prepare-config)で作った`config.yml`があるディレクトリで、次のコマンドを実行してKestreLynxを起動し、ログを確認します。

```bash
docker run -d --name kestrelynx \
  --restart unless-stopped \
  -e TZ=UTC \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v "$PWD/config.yml:/etc/kestrelynx/config.yml:ro" \
  -v kestrelynx-state:/var/lib/kestrelynx \
  ghcr.io/kitsunetrail/kestrelynx:latest
docker logs -f kestrelynx
```

- `kestrelynx-state`ボリュームがスキャン履歴と脅威情報フィードのキャッシュを保持するため、このボリュームを削除しない

## Docker Composeで実行

[設定ファイルの準備](#prepare-config)で作った`config.yml`があるディレクトリでKestreLynxを起動します。

```bash
docker compose up -d
docker compose logs -f
```

- `kestrelynx-state`ボリュームがスキャン履歴と脅威情報フィードのキャッシュを保持するため、このボリュームを削除しない

## Kubernetesで実行

[クラスタ内に配置する方法](#kubernetes-steps)と、[クラスタの外から接続する方法](#kubernetes-outside)があります。
環境に合う手順を選んでください。

- 1つのインスタンスが1つのクラスタを対象とする
- Trivyがレジストリからイメージを取得するため、KestreLynxが動く場所からレジストリへアクセスできる必要がある

### クラスタ内で実行 {#kubernetes-steps}

1. リポジトリをダウンロードするか、次のコマンドでcloneする

    ```bash
    git clone https://github.com/kitsunetrail/kestrelynx.git
    cd kestrelynx
    ```

2. `deploy/kubernetes/configmap.yaml`を編集する

    - 通知先を1つ以上設定する

        ```yaml
        data:
          config.yml: |
            notify:
              slack_webhook_url: "https://hooks.slack.com/services/..."
        ```

    - 特定の名前空間だけをスキャンする場合は`kubernetes.namespaces`に列挙する（既定はすべての名前空間）
    - 複数のインスタンスから1つのSlackチャンネルへ投稿する場合は、`environment.name`にインスタンスを区別する名前を設定する
    - 他の設定は[設定項目](configuration.md)を参照する

3. `deploy/kubernetes/pvc.yaml`のストレージ設定をクラスタに合わせて編集する

    - 既定はアクセスモード`ReadWriteOnce`で1 GiB
    - このPVCがスキャン履歴、初回検出日、脅威情報フィードのキャッシュを保持するため、Podを再作成してもこれらのデータは失われない

4. 次のコマンドで名前空間を作成する

    ```bash
    kubectl create namespace kestrelynx
    ```

5. 非公開レジストリのイメージをスキャンする場合だけ、[非公開レジストリの認証](#kubernetes-private-registry)を行う

6. 次のコマンドでマニフェストを適用し、起動を待ってからログを確認する

    ```bash
    kubectl apply -f deploy/kubernetes/
    kubectl rollout status -n kestrelynx deployment/kestrelynx
    kubectl logs -n kestrelynx deployment/kestrelynx -f
    ```

    - ServiceAccount、読み取り専用のClusterRoleとClusterRoleBinding、ConfigMap、PVC、Deploymentが作成される
    - `work/`はこのコマンドでは適用されないため、言語パッケージの更新を使う場合だけ、[作業用Podの設定](remediation-setup.md#kubernetes-language-updates)に従って別途適用する

!!! warning "同時に動かさない"

    `deployment.yaml`のレプリカ数1と`Recreate`戦略は変更せず、2つのインスタンスで1つの状態データ用ボリュームを共有しないでください。
    2つのPodが同時に状態データへ書き込むと、スキャン履歴が壊れるためです。

### クラスタ内での非公開レジストリの認証 {#kubernetes-private-registry}

クラスタの外から実行する場合は`config.yml`に直接`registries`を設定するため、この手順は不要です。

KestreLynxはPodの中を読まず、Podが使っているイメージをレジストリから取得してスキャンするため、非公開レジストリのイメージにはログイン情報が必要です。
Podの`imagePullSecrets`は再利用しません。

1. 次のコマンドで、`deploy/kubernetes/configmap.yaml`の設定から`config.yml`を作成する

    ```bash
    sed '1,/config.yml: |/d; s/^    //' deploy/kubernetes/configmap.yaml > config.yml
    ```

    - このファイルはパスワードを含むので、リポジトリにコミットしない

2. 手順1で作った`config.yml`に`registries`を追加する

    ```yaml
    registries:
      - host: registry.example.com
        username: example-puller
        password: "example-read-token"
    ```

    - `token_hosts`など各キーの説明は[イメージレジストリの認証](configuration.md#registries)を参照する
    - Docker Hubの場合は`host: docker.io`と`token_hosts: [auth.docker.io]`を指定する

3. 手順1で作った`config.yml`からSecretを作成する

    ```bash
    kubectl create secret generic kestrelynx-config \
      --namespace kestrelynx \
      --from-file=config.yml=config.yml \
      --save-config
    ```

4. `deploy/kubernetes/deployment.yaml`の`config`ボリュームをSecretに変更する

    ```yaml
    - name: config
      secret:
        secretName: kestrelynx-config
    ```

ログイン情報が無いか違う場合、そのイメージはスキャン失敗として通知に出ます。

設定をSecretに移した後は、他のページに「ConfigMapを適用する」とある手順でも、次のコマンドで設定の変更を反映します。

```bash
kubectl create secret generic kestrelynx-config \
  --namespace kestrelynx \
  --from-file=config.yml=config.yml \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl rollout restart -n kestrelynx deployment/kestrelynx
```

### クラスタの外から実行 {#kubernetes-outside}

クラスタの外のDockerホストでKestreLynxを動かし、APIサーバに接続してクラスタをスキャンします。
この構成では、作業用Podによる言語パッケージ更新の動作は未確認です。詳細は設定ページの[クラスタの外から接続する場合](configuration.md#scan-target-outside)を参照してください。

1. [設定ファイルの準備](#prepare-config)に従ってリポジトリをcloneし、`config.yml`を作成する

2. 次のコマンドで名前空間と、読み取り専用の権限を持つServiceAccountを作成する

    ```bash
    kubectl create namespace kestrelynx
    kubectl apply -f deploy/kubernetes/serviceaccount.yaml \
      -f deploy/kubernetes/clusterrole.yaml \
      -f deploy/kubernetes/clusterrolebinding.yaml
    ```

3. 次のコマンドでServiceAccountの期限のないtokenをSecretとして作成し、tokenの作成を待つ

    ```bash
    kubectl apply -f - <<'EOF'
    apiVersion: v1
    kind: Secret
    metadata:
      name: kestrelynx-token
      namespace: kestrelynx
      annotations:
        kubernetes.io/service-account.name: kestrelynx
    type: kubernetes.io/service-account-token
    EOF
    kubectl wait -n kestrelynx secret/kestrelynx-token --for=jsonpath='{.data.token}'
    ```

4. `config.yml`のあるディレクトリで次のコマンドを実行し、tokenとクラスタのCA証明書をファイルに保存する

    ```bash
    kubectl get secret -n kestrelynx kestrelynx-token -o jsonpath='{.data.token}' | base64 -d > token
    kubectl get secret -n kestrelynx kestrelynx-token -o jsonpath='{.data.ca\.crt}' | base64 -d > ca.crt
    chmod 600 token
    ```

    - `token`はクラスタを読み取れる認証情報なので、リポジトリにコミットしない

5. `config.yml`を編集し、コメントアウトされている`kubernetes`節を次の内容で有効にする

    ```yaml
    kubernetes:
      enabled: true
      api_server: "https://kubernetes.example.com:6443"
      token_file: /etc/kestrelynx/token
      ca_file: /etc/kestrelynx/ca.crt
    ```

    - `api_server`にはKestreLynxのコンテナから届くAPIサーバのURLを設定し、`kubectl`が使っているURLは次のコマンドで確認する（コンテナ内の`127.0.0.1`はDockerホストを指さない点に注意する）

        ```bash
        kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}'
        ```

    - URLのホスト名やアドレスがAPIサーバの証明書に含まれない場合は、[クラスタの外から接続する場合](configuration.md#scan-target-outside)に従って`tls_server_name`を設定する
    - 非公開レジストリのイメージをスキャンする場合は、[イメージレジストリの認証](configuration.md#registries)に従って同じ`config.yml`に`registries`を追加する

6. 次のコマンドでKestreLynxを起動し、ログを確認する

    ```bash
    docker run -d --name kestrelynx \
      --restart unless-stopped \
      -e TZ=UTC \
      -v "$PWD/config.yml:/etc/kestrelynx/config.yml:ro" \
      -v "$PWD/token:/etc/kestrelynx/token:ro" \
      -v "$PWD/ca.crt:/etc/kestrelynx/ca.crt:ro" \
      -v kestrelynx-state:/var/lib/kestrelynx \
      ghcr.io/kitsunetrail/kestrelynx:latest
    docker logs -f kestrelynx
    ```

    - `kestrelynx-state`ボリュームがスキャン履歴と脅威情報フィードのキャッシュを保持するため、このボリュームを削除しない

## 修正計画と修正PR {#remediation}

Docker・Kubernetes向けの機能の概要は[修正計画の案内](remediation.md#overview)を参照してください。

| 操作 | 手順 |
| --- | --- |
| 更新候補の計画を有効にする | [修正計画の有効化](remediation-setup.md#enable-fix-plans) |
| GitHubへのPR作成を有効にする | [修正PRの有効化](remediation-setup.md#enable-pull-requests) |

## タイムゾーンを設定

`schedule.daily_at`は`TZ`で指定したタイムゾーンとして解釈され、既定はUTCです。

- Dockerで実行する場合、またはKubernetesクラスタの外から実行する場合は、各手順の`docker run`の`-e TZ=UTC`を変更する
- Docker Composeで実行する場合は、`docker-compose.yml`の`TZ=UTC`を変更する
- Kubernetesクラスタ内で実行する場合は、`deploy/kubernetes/deployment.yaml`の`TZ`環境変数を変更する

例えば、日本時間を使う場合は`TZ=Asia/Tokyo`を指定します。

## 参考ページ

- [設定](configuration.md) — 設定項目と既定値
- [スキャン通知の送信条件](notification-conditions.md#notification-conditions) — 通知モードごとの送信条件
