# 設定

YAML設定ファイルについて説明します。コンテナイメージでは既定で`/etc/kestrelynx/config.yml`を使用します。未知のYAMLフィールドはエラーになります。

コメント付きの完全な例は[`config.example.yml`](https://github.com/kitsunetrail/kestrelynx/blob/main/config.example.yml)にあります。

## スキャン対象 {#scan-target}

Dockerホストをスキャンする場合、この節の設定は不要です。Kubernetesクラスタをスキャンする場合に設定します。

クラスタ内のPodで動かす場合は、以下の2項目を使い、接続用の`kubernetes.api_server`・`kubernetes.token_file`・`kubernetes.ca_file`・`kubernetes.tls_server_name`は空のままにします。

Kubernetesモードで`schedule.run_on_start`が有効な場合、最初のスキャンの前に、KestreLynx自身のPodの全コンテナがAPI上で`Running`になるまで最長30秒待ちます。

- 自身のPodは、ServiceAccountのnamespaceと`HOSTNAME`で特定します。
- クラスタ外での実行、別クラスタのAPIサーバの指定、`HOSTNAME`がPod名でない場合など、自身のPodを読み取れない場合は待ちません。
- 30秒以内に全コンテナが`Running`にならなければ、警告を出してスキャンを始めます。

| 設定項目 | 既定値 | 説明 |
| --- | --- | --- |
| `kubernetes.enabled` | `false` | Dockerホストの代わりにKubernetesクラスタをスキャンします。 |
| `kubernetes.namespaces` | `[]` | スキャン対象のnamespaceです。空または省略した場合は、すべてのnamespaceを対象にします。各値は小文字英数字とハイフンの1〜63バイトで、先頭と末尾は英数字にします。 |

#### クラスタの外から接続する場合 {#scan-target-outside}

別のホストのDockerコンテナなど、クラスタの外からAPIサーバに接続する場合は、上の設定に加えて以下を設定します。

クラスタの外から接続する構成では、作業用Podによる言語パッケージ更新の動作は未確認です。

| 設定項目 | 必須 | 既定値 | 説明 |
| --- | --- | --- | --- |
| `kubernetes.api_server` | はい | 空 | KestreLynxから到達できるAPIサーバの`https://`のURLです。 |
| `kubernetes.token_file` | はい | 空 | 配布のClusterRole（`deploy/kubernetes/clusterrole.yaml`）の権限を持つServiceAccountのトークンを置いたファイルです。スキャンのたびに読み直すため、ファイルを置き換えると再起動せずに次のスキャンから使われます。`kubectl create token`で作ったトークンには期限があり、期限切れでスキャンが失敗します。期限のないトークンは、種類を`kubernetes.io/service-account-token`、注釈`kubernetes.io/service-account.name`をServiceAccount名にしたSecretで作れます。 |
| `kubernetes.ca_file` | はい | 空 | PEM形式のクラスタCA証明書のファイルです。スキャンのたびに読み直します。実行時に読み取り可能で、有効なPEM証明書を含む必要があります。安全でない接続へのフォールバックはありません。 |
| `kubernetes.tls_server_name` | `api_server`のホスト名やアドレスがAPIサーバの証明書に含まれない場合 | 空 | TLS証明書の検証に使用する、証明書に含まれる名前（例: `kubernetes`）を指定します。ロードバランサーやDNS名を経由する場合などに使います。空の場合はサーバ名を上書きしません。 |

## イメージレジストリの認証 {#registries}

非公開レジストリの認証情報は、トップレベルの`registries`に設定します。
これらの認証情報は、Trivyがそのホストのレジストリからイメージを取得してスキャンするときに使います。また、修正計画で更新先の候補となるタグやイメージの情報を同じレジストリから読むときにも使います。

接続はHTTPSだけで、証明書はKestreLynxから信頼できるものが必要です。

| 設定項目 | 必須 | 既定値 | 説明 |
| --- | --- | --- | --- |
| `registries` | いいえ | `[]` | ホストごとのイメージレジストリの認証設定です。 |

| 設定項目 | 必須 | 既定値 | 説明 |
| --- | --- | --- | --- |
| `host` | はい | なし | イメージ参照に書くホスト名またはIPv4アドレスと任意のポートで、scheme・パス・ユーザー情報は含めません。ポートは`1`〜`65535`です。ホスト名は大文字・小文字を区別せず、`docker.io`・`index.docker.io`・`registry-1.docker.io`は同じホストとして扱います。正規化後に同じ`host`となる認証設定は重複して指定できません。 |
| `username` | はい | なし | 空白・制御文字・`:`を含まない、空でない文字列です。 |
| `password` | はい | なし | 空白・制御文字を含まない、空でないパスワードまたはアクセストークンです。 |
| `token_hosts` | いいえ | `[]` | 認証情報を送ってよい追加のtoken serviceのホスト一覧で、各値の形式は`host`と同じです。Docker Hubの認証には`host: docker.io`と`token_hosts: [auth.docker.io]`を指定します。 |

Trivyが使う環境変数と`token_hosts`の制限の例外、および送付先とリダイレクトの制限は[認証情報の送付範囲](outbound-communication.md#credential-destinations)、設定手順は[非公開イメージの認証](remediation-setup.md#configure-registry-auth)を参照してください。

## スケジュール {#schedule}

| 設定項目 | 既定値 | 説明 |
| --- | --- | --- |
| `schedule.daily_at` | 空 | `HH:MM`形式のローカル時刻です。タイムゾーンはコンテナの`TZ`環境変数で指定します。空の場合は起動時点から24時間ごとに実行します。 |
| `schedule.run_on_start` | `true` | KestreLynxの起動直後に1回スキャンします。 |

## スキャン {#scan}

ランタイム本体の照合の判定規則と制約、セキュリティ情報の取得先は、次のページを参照してください。

- Node.js：[Node.js本体の検出結果](scan-logic.md#node-runtime)、[Node.jsのセキュリティ情報の取得](outbound-communication.md#node-runtime-download)
- Python：[Python本体の検出結果](scan-logic.md#python-runtime)、[Pythonのセキュリティ情報の取得](outbound-communication.md#python-runtime-download)

| 設定項目 | 既定値 | 説明 |
| --- | --- | --- |
| `scan.severity` | `[HIGH, CRITICAL]` | Node.js・Python本体の検出結果を含め、分析と通知の対象にする深刻度です。`UNKNOWN`・`LOW`・`MEDIUM`・`HIGH`・`CRITICAL`を指定できます。 |
| `scan.node_runtime.enabled` | `true` | セキュリティ情報を取得し、`NODE_VERSION`に記録されたNode.jsの版と照合します。`false`では取得と照合の両方を停止します。 |
| `scan.python_runtime.enabled` | `true` | セキュリティ情報を取得し、`PYTHON_VERSION`に記録されたCPythonの版と照合します。`false`では取得と照合の両方を停止します。 |

## 優先順位付け {#triage}

通信先と送信内容は[外向きの通信](outbound-communication.md#outbound-communication)を参照してください。

| 設定項目 | 既定値 | 説明 |
| --- | --- | --- |
| `triage.enabled` | `true` | CISA KEVとEPSSによる優先順位付けを有効にします。 |
| `triage.act_now_epss` | `0.10` | CVEをact nowに分類するEPSS確率の下限です。`triage.watch_epss`以上、`1`以下にします。 |
| `triage.watch_epss` | `0.01` | CVEを少なくともwatchに分類するEPSS確率の下限です。`0`より大きく、`triage.act_now_epss`以下にします。 |
| `triage.kev_url` | 空 | CISA KEVフィードのURLを、ローカルミラーなどへ変更します。 |
| `triage.epss_url` | 空 | EPSSフィードのURLを、ローカルミラーなどへ変更します。 |
| `triage.discussion_links` | `true` | act-now CVEに関するHacker Newsの議論を検索します。 |

## 通知 {#notifications}

### 通知先 {#notify-destinations}

少なくとも1つの通知先が必要です。メールだけでも通知先の要件を満たします。

Slack Incoming WebhookとBot Tokenの組み合わせを同時には設定できません。汎用Webhookとメールは、どちらのSlack通知方式とも併用できます。

スレッドの位置とフッターの読み方は[スレッドのレポート](slack-display.md#thread-display)、翻訳する内容は[通知の言語](slack-display.md#notification-language)を参照してください。

| 設定項目 | 必須 | 既定値 | 説明 |
| --- | --- | --- | --- |
| `notify.slack_webhook_url` | いいえ | 空 | Slack Incoming WebhookのURLです。チャンネルへの通知に対応します。 |
| `notify.slack_bot_token` | `notify.slack_channel`を設定する場合 | 空 | `chat:write`権限を持つSlack Bot Tokenです。Bot通知ではスレッド投稿と前回レポートへのリンクを利用できます。 |
| `notify.slack_channel` | `notify.slack_bot_token`を設定する場合 | 空 | Botで通知するSlackチャンネルIDです。 |
| `notify.generic_webhook_url` | いいえ | 空 | 構造化JSONを受け取るエンドポイントです。 |
| `notify.email.host` | `notify.email`のいずれかの項目を設定する場合 | 空 | スキームとポートを含まないSMTPホスト名またはIPです。 |
| `notify.email.port` | `notify.email`のいずれかの項目を設定する場合 | なし | SMTPポート（`1`〜`65535`）です。 |
| `notify.email.tls` | `notify.email`のいずれかの項目を設定する場合 | なし | `starttls`（接続後にアップグレード）または`tls`（暗黙的TLS）です。暗号化なしのSMTPは拒否されます。 |
| `notify.email.username` | `notify.email.password`を設定する場合 | 空 | SMTPユーザー名です。SMTP認証を使わない場合は`password`とともに省略します。 |
| `notify.email.password` | `notify.email.username`を設定する場合 | 空 | SMTPパスワードです。SMTP認証を使わない場合は`username`とともに省略します。 |
| `notify.email.from` | `notify.email`のいずれかの項目を設定する場合 | 空 | 送信元アドレスです。 |
| `notify.email.to` | `notify.email`のいずれかの項目を設定する場合 | 空 | 1件以上の宛先アドレスです。 |
| `notify.language` | いいえ | `en` | Slackおよびメール通知とPR本文の言語です。`en`か`ja`を指定し、それ以外は設定エラーです。汎用WebhookのJSONは英語のままです。 |

### 通知モード {#notify-mode}

差分として扱う変化は[パッケージの変化](diff-logic.md#package-changes)、送信する条件は[スキャン通知の送信条件](notification-conditions.md#notification-conditions)を参照してください。

| 設定項目 | 既定値 | 説明 |
| --- | --- | --- |
| `notify.mode` | `diff` | `diff`は変化を通知し、`full`はスキャンごとに現在の全項目を通知します。 |
| `notify.full_report_day` | `monday` | diffモードで完全なレポートを送る曜日です。`monday`〜`sunday`の曜日名を指定し、`never`で無効化します。 |
| `notify.notify_on_clean` | `false` | 脆弱性がない場合にも通知します。 |

## 状態と環境名 {#state}

`state.path`を含むディレクトリの永続化は[セットアップ手順](getting-started.md)、履歴の扱いは[履歴の継続](diff-logic.md#state-lifecycle)を参照してください。

| 設定項目 | 既定値 | 説明 |
| --- | --- | --- |
| `state.path` | `/var/lib/kestrelynx/state.json` | スキャン履歴と差分計算に使用するファイルです。 |
| `environment.name` | 空 | このインスタンスのスキャン履歴に付ける名前です。空の場合は名前のない既定の環境になります。指定する場合は小文字英数字とハイフンの1〜63バイトで、先頭と末尾は英数字にします。値は正規化しません。Slackのヘッダーでは`[name]`、汎用Webhookでは`environment.name`として表示します。名前の追加・変更・削除による履歴のリセット、初回検出日の変更、既存の検出項目の再通知はありません。 |

## 修正計画と修正PR {#remediation}

機能の入口は[修正計画の案内](remediation.md#contents)、有効化は[有効化の手順](remediation-setup.md)を参照してください。

### 基本設定 {#remediation-basics}

各設定で行う処理は[計画とPRの実行範囲](remediation-logic.md#plan-and-pr-execution)、保存する内容は[保存ファイル](remediation-reference.md#stored-records)を参照してください。

| 設定項目 | 既定値 | 説明 |
| --- | --- | --- |
| `remediation.enabled` | `false` | Docker・Kubernetesモードで読み取り専用の修正計画を有効にします。 |
| `remediation.pull_requests.enabled` | `false` | 修正PRを有効にします。修正計画の有効化とGitHub tokenが必要です。 |
| `remediation.storage_dir` | `/var/lib/kestrelynx/remediation` | 計画、配信記録、PR記録、ツールキャッシュを保存する絶対パスのディレクトリです。`state.path`を変えても、この保存先は変わりません。 |

### GitHubアクセス {#remediation-github}

修正PRを有効にする場合は、`remediation.mappings`のすべてのリポジトリにtokenが必要です。
`tokens`にも既定のtokenにも該当しないリポジトリがあると、起動時にエラーになります。

| 設定項目 | 必須 | 既定値 | 説明 |
| --- | --- | --- | --- |
| `remediation.github.token` | いいえ | 空 | `tokens`にない所有者のリポジトリに使う既定のGitHub tokenです。空白・制御文字は含められません。 |
| `remediation.github.tokens` | いいえ | `[]` | 所有者ごとのGitHub tokenの一覧です。対象リポジトリの所有者に一致する項目があれば、既定のtokenの代わりに使います。 |
| `remediation.github.tokens[].owner` | はい | なし | GitHubのユーザー名または組織名です。大文字・小文字を区別せずに比較し、同じ所有者の重複指定はエラーになります。 |
| `remediation.github.tokens[].token` | はい | なし | その所有者のリポジトリに使う、空でないGitHub tokenです。空白・制御文字は含められません。 |

#### tokenに必要な権限

GitHub tokenに必要な権限を次の表に示します。
tokenは、対象リポジトリに限定したfine-grained tokenを使います。

| やりたいこと | tokenに必要な権限 |
| --- | --- |
| 公開リポジトリのソースを読んで修正計画を作る | 不要 |
| 非公開リポジトリのソースを読んで修正計画を作る | Contents: Read |
| 修正PRを作成・管理する | ContentsとPull requests: Read and write |

tokenの送付先は[認証情報の送付範囲](outbound-communication.md#credential-destinations)を参照してください。

### ソースの対応付け {#remediation-mappings}

`remediation.mappings`には、稼働中のコンテナに対応するGitHubリポジトリとファイルの場所を設定します。
KestreLynxは、そのファイルを読んで修正計画を作り、修正PRを有効にした場合は更新対象として使います。

1つの項目に書いたソースは、同じ`repository`と`base_branch`を使います。
リポジトリやブランチが異なるソースは、同じ`workload`を指定した別の項目に分けてください。

対応するファイル形式は[対応する入力形式](remediation-reference.md#supported-inputs)を参照してください。

| 設定項目 | 必須 | 既定値 | 説明 |
| --- | --- | --- | --- |
| `remediation.mappings` | いいえ | `[]` | 稼働中のコンテナと、修正計画や修正PRに使うGitHub上のソースファイルとの対応を列挙します。 |

#### docker run {#remediation-mappings-docker-run}

`docker run`で動かしているコンテナには、`workload`に`container/<名前>`を指定します。

Dockerfileのベースイメージを更新するには`dockerfile`、言語パッケージを更新するには`dependencies`を指定します。
どちらか一方、または両方を設定してください。

```yaml
remediation:
  mappings:
    - workload: container/example-api
      repository: example/application
      base_branch: main
      dockerfile:
        path: Dockerfile
      dependencies:
        directory: .
```

| 設定項目 | 必須 | 既定値 | 説明 |
| --- | --- | --- | --- |
| `remediation.mappings[].workload` | はい | なし | 対象コンテナを`container/<名前>`形式で指定します。名前には`docker ps`の`NAMES`の値を使い、大文字・小文字を区別します。 |
| `remediation.mappings[].repository` | はい | なし | 対象ファイルを保存しているGitHubリポジトリを`owner/name`形式で指定します。 |
| `remediation.mappings[].base_branch` | はい | なし | 対象ファイルを読み取るGitブランチ名を指定します。修正PRの宛先にもこのブランチを使います。 |
| `remediation.mappings[].dockerfile.path` | `dockerfile`を設定する場合 | なし | 対象イメージのビルドに使うDockerfileを、リポジトリのルートからのパスで指定します。 |
| `remediation.mappings[].dockerfile.target` | いいえ | Dockerfileの最後のステージ | 対象イメージのビルドに使うステージ名を指定します。そのステージが継承するベースイメージが更新対象になります。 |
| `remediation.mappings[].dependencies.directory` | `dependencies`を設定する場合 | なし | 更新対象の言語パッケージを管理する依存ファイルのあるディレクトリを、リポジトリのルートからのパスで指定します。ルートにある場合は`.`を指定します。 |

#### Compose {#remediation-mappings-compose}

Composeで動かしているサービスには、`workload`に`compose/<project>/<service>`を指定します。

更新対象に合わせて、Composeファイルのイメージタグには`compose`、Dockerfileのベースイメージには`dockerfile`、言語パッケージには`dependencies`を指定します。
この3種類から1種類以上を選びます。

```yaml
remediation:
  mappings:
    - workload: compose/shop/web
      repository: example/shop
      base_branch: main
      compose:
        path: compose.yml
        service: web
      dependencies:
        directory: .
```

| 設定項目 | 必須 | 既定値 | 説明 |
| --- | --- | --- | --- |
| `remediation.mappings[].workload` | はい | なし | 対象サービスを`compose/<project>/<service>`形式で指定します。`project`には稼働コンテナの`com.docker.compose.project`ラベルの値、`service`には`com.docker.compose.service`ラベルの値を使います。 |
| `remediation.mappings[].repository` | はい | なし | 対象ファイルを保存しているGitHubリポジトリを`owner/name`形式で指定します。 |
| `remediation.mappings[].base_branch` | はい | なし | 対象ファイルを読み取るGitブランチ名を指定します。修正PRの宛先にもこのブランチを使います。 |
| `remediation.mappings[].compose.path` | `compose`を設定する場合 | なし | 対象のComposeファイルを、リポジトリのルートからのパスで指定します。 |
| `remediation.mappings[].compose.service` | `compose`を設定する場合 | なし | `compose.path`で指定したファイル内で、イメージタグを更新するサービスの名前を指定します。 |
| `remediation.mappings[].dockerfile.path` | `dockerfile`を設定する場合 | なし | 対象イメージのビルドに使うDockerfileを、リポジトリのルートからのパスで指定します。 |
| `remediation.mappings[].dockerfile.target` | いいえ | Dockerfileの最後のステージ | 対象イメージのビルドに使うステージ名を指定します。そのステージが継承するベースイメージが更新対象になります。 |
| `remediation.mappings[].dependencies.directory` | `dependencies`を設定する場合 | なし | 更新対象の言語パッケージを管理する依存ファイルのあるディレクトリを、リポジトリのルートからのパスで指定します。ルートにある場合は`.`を指定します。 |

Composeの`build`からDockerfileとビルド対象ステージを特定できる場合は、`dockerfile`の指定を省略できます。
特定できる条件と、明示した`dockerfile`との照合は[ベースイメージの特定](remediation-logic.md#base-image-selection)を参照してください。

#### Kubernetes {#remediation-mappings-kubernetes}

Kubernetesのコンテナには、`workload`に`<kind>/<namespace>/<name>/<container>`を指定します。

イメージタグの更新には、通常のマニフェストなら`manifest`、Kustomizeなら`kustomize`、Helmのvaluesファイルなら`helm_values`を選びます。
1つのコンテナには、イメージタグを管理している方法を1種類だけ指定してください。

Dockerfileのベースイメージには`dockerfile`、言語パッケージには`dependencies`を指定します。
各項目には1種類以上のソースが必要です。

修正計画が有効なとき、`kubernetes.namespaces`の対象外の名前空間への対応付けは起動時に警告され、計画には使われません。

```yaml
remediation:
  mappings:
    - workload: deployment/example/web/app
      repository: example/application
      base_branch: main
      manifest:
        path: apps/web.yaml
      dockerfile:
        path: docker/Dockerfile
      dependencies:
        directory: .
```

| 設定項目 | 必須 | 既定値 | 説明 |
| --- | --- | --- | --- |
| `remediation.mappings[].workload` | はい | なし | 対象コンテナを`<kind>/<namespace>/<name>/<container>`形式で指定します。`kind`は`deployment`・`statefulset`・`daemonset`・`job`・`cronjob`・`pod`のいずれか、`namespace`は名前空間、`name`はその種類のワークロードの名前、`container`はコンテナ名です。 |
| `remediation.mappings[].repository` | はい | なし | 対象ファイルを保存しているGitHubリポジトリを`owner/name`形式で指定します。 |
| `remediation.mappings[].base_branch` | はい | なし | 対象ファイルを読み取るGitブランチ名を指定します。修正PRの宛先にもこのブランチを使います。 |
| `remediation.mappings[].manifest.path` | `manifest`を設定する場合 | なし | 対象コンテナのイメージタグを記述したマニフェストを、リポジトリのルートからのパスで指定します。 |
| `remediation.mappings[].manifest.object.kind` | いいえ | `workload`の種類に対応するマニフェストの`kind` | ファイル内の対象オブジェクトの種類を指定します。`workload`の種類に対応する`Deployment`・`StatefulSet`・`DaemonSet`・`Job`・`CronJob`・`Pod`を使います。 |
| `remediation.mappings[].manifest.object.name` | いいえ | `workload`の`name` | ファイル内の対象オブジェクトの名前を指定します。稼働中のワークロード名とファイル内の名前が異なる場合に設定します。 |
| `remediation.mappings[].kustomize.path` | `kustomize`を設定する場合 | なし | 対象のKustomizeファイルを、リポジトリのルートからのパスで指定します。ファイル名は`kustomization.yaml`・`kustomization.yml`・`Kustomization`のいずれかです。 |
| `remediation.mappings[].kustomize.image` | `kustomize`を設定する場合 | なし | `newTag`を更新する`images`の項目を、その項目の`name`の値で指定します。タグやdigestを含めずに書いてください。 |
| `remediation.mappings[].kustomize.affects` | いいえ | `[]` | 指定した`images`のタグ変更で影響を受ける、`workload`以外のコンテナを`<kind>/<namespace>/<name>/<container>`形式ですべて列挙します。通常のinit containerも含めます。省略する前に、影響を受けるのが`workload`のコンテナだけであることを確認してください。 |
| `remediation.mappings[].helm_values.path` | `helm_values`を設定する場合 | なし | 対象のvaluesファイルを、リポジトリのルートからのパスで指定します。拡張子は`.yaml`または`.yml`です。 |
| `remediation.mappings[].helm_values.key` | `helm_values`を設定する場合 | なし | イメージを指定しているキーを`image`や`app.image`のように書きます。`repository`と`tag`を持つ項目、または`nginx:1.27.2`のような文字列の項目を指し、`tag`自体は指しません。ドットは階層の区切りに使い、各キー名には英数字・`_`・`-`を使います。 |
| `remediation.mappings[].helm_values.affects` | いいえ | `[]` | 指定したvaluesのキーのタグ変更で影響を受ける、`workload`以外のコンテナを`<kind>/<namespace>/<name>/<container>`形式ですべて列挙します。通常のinit containerも含めます。省略する前に、影響を受けるのが`workload`のコンテナだけであることを確認してください。 |
| `remediation.mappings[].dockerfile.path` | `dockerfile`を設定する場合 | なし | 対象イメージのビルドに使うDockerfileを、リポジトリのルートからのパスで指定します。 |
| `remediation.mappings[].dockerfile.target` | いいえ | Dockerfileの最後のステージ | 対象イメージのビルドに使うステージ名を指定します。そのステージが継承するベースイメージが更新対象になります。 |
| `remediation.mappings[].dependencies.directory` | `dependencies`を設定する場合 | なし | 更新対象の言語パッケージを管理する依存ファイルのあるディレクトリを、リポジトリのルートからのパスで指定します。ルートにある場合は`.`を指定します。 |

設定例と影響を受けるコンテナの指定方法は、[KustomizeのPR設定](remediation-setup.md#kustomize-pull-requests)と[HelmのvaluesのPR設定](remediation-setup.md#helm-values-pull-requests)を参照してください。

### 処理の上限 {#remediation-limits}

上限による結果は[理由コード](remediation-reference.md#reason-codes)、PRの扱いは[PRの管理](remediation-logic.md#pr-management)、実行期限と後処理は[作業用コンテナの実行](remediation-logic.md#worker-execution)を参照してください。

[新しい系列の確認](remediation-logic.md#newer-series-check)も、候補スキャン・比較元の再スキャン・タグ一覧の取得・レジストリ要求の上限を通常の処理と共有します。

| 設定項目 | 既定値 | 説明 |
| --- | --- | --- |
| `remediation.limits.candidate_scans_per_cycle` | `10` | 1サイクルの候補イメージのスキャン数で、正の整数です。 |
| `remediation.limits.baseline_rescans_per_cycle` | `10` | 比較条件をそろえるための1サイクルの比較元の再スキャン数で、正の整数です。 |
| `remediation.limits.registry_requests_per_cycle` | `200` | token交換を含む1サイクルのイメージレジストリへのHTTP要求数で、正の整数です。稼働イメージのスキャン前にログインの要否を確かめる要求は集計対象外ですが、候補イメージのスキャン前の同様の要求は集計対象です。 |
| `remediation.limits.tag_pages_per_repository` | `20` | イメージリポジトリごとのタグ一覧取得の要求数で、対象系列を探索する要求も含む正の整数です。 |
| `remediation.limits.cycle_timeout` | `30m` | 計画、依存更新、PR処理の期限で、正の期間です。通常の稼働イメージのスキャンは含みません。 |
| `remediation.limits.new_prs_per_cycle` | `3` | PR有効時の1サイクルの新規PR数で、正の整数です。 |
| `remediation.limits.open_prs` | `10` | PR有効時の設定したリポジトリ全体で開いているKestreLynxのPR数で、正の整数です。 |
| `remediation.limits.dependency_jobs_per_cycle` | `3` | 1サイクルで試みる依存更新の単位数で、正の整数です。パッケージ数やコンテナ数ではありません。 |
| `remediation.limits.job_timeout` | `6m` | 各作業用コンテナの作成・実行・結果回収の期限で、`1m`〜`60m30s`です。 |

### 作業用コンテナ {#remediation-worker}

作業用コンテナは、修正PRで言語パッケージを更新する際に、npm・pnpm・pip・uv・Go・Gradleによる依存の更新（lockfileの更新など）をKestreLynx本体とは別に実行するための使い捨てのコンテナです。

作業用イメージの固定と取得不能時の扱いは[公式イメージの固定](remediation-logic.md#worker-images)、系列は[対応する実行環境](remediation-reference.md#supported-runtimes)、通信先は[作業用イメージの取得](outbound-communication.md#worker-image-downloads)を参照してください。

ツールの扱いは[ツール公開後の待機](remediation-logic.md#tool-release-age)、[ツールの取得と照合](remediation-logic.md#tool-verification)、[ツールキャッシュの再利用](remediation-logic.md#tool-cache)を参照してください。

作業プログラムをコンテナに渡す際の検査は[コンテナへの入力](remediation-logic.md#worker-inputs)を参照してください。

| 設定項目 | 既定値 | 説明 |
| --- | --- | --- |
| `remediation.worker.registry` | 空 | Docker Hubミラーの`host[:port][/path]`を小文字で指定します。空の場合はDocker Hubを使います。scheme・タグ・digest・`//`・`..`を含めず、パスには小文字英数字と区切りの`.`・`_`・`-`を使います。ミラーには指定したホストとパスの下に、公式イメージと同じ内容の`library/node`・`library/python`・`library/golang`・`library/gradle`を配置します。 |
| `remediation.worker.tool_versions.min_release_age` | `72h` | npm・pnpm・uvの公開から使用までの最小待機時間で、`72h`や`30m`のような正の期間です。`0`や負の値は指定できません。 |
| `remediation.worker.tool_versions.cache_max_size` | `1GiB` | npm・pnpm・uvのキャッシュ容量の上限です。整数のバイト数、または整数に`B`・`KiB`・`MiB`・`GiB`を付け、最低`128MiB`を指定します。 |
| `remediation.worker.program_dir` | 空 | 空または絶対パスで、開発用の作業プログラムを置くディレクトリです。通常の配布版では指定不要です。 |

#### Kubernetes {#remediation-worker-kubernetes}

Kubernetesモードの言語パッケージ更新に使います。[導入手順](remediation-setup.md#kubernetes-language-updates)に従い、利用者が作業用namespaceと必要なリソースを適用します。

これらの設定には`kubernetes.enabled: true`が必要です。名前・イメージ参照・数値の形式が不正な場合は、起動時にエラーになります。

| 設定項目 | 必須 | 既定値 | 説明 |
| --- | --- | --- | --- |
| `remediation.worker.kubernetes.namespace` | `remediation.worker.kubernetes`のほかの項目を設定する場合 | 空 | 作業用Podを作るnamespace名です。未設定の場合はMaven以外の言語パッケージ更新が`work_namespace_not_configured`で手動対応になります。 |
| `remediation.worker.kubernetes.service_account` | いいえ | `kestrelynx-work` | 作業用PodのServiceAccount名で、権限とトークンを持たないものを指定します。 |
| `remediation.worker.kubernetes.priority_class` | いいえ | `kestrelynx-work` | 作業用PodのPriorityClass名で、`preemptionPolicy: Never`のものを指定します。 |
| `remediation.worker.kubernetes.receiver_image` | クラスタの外から言語パッケージを更新する場合 | 空 | 入力ファイルを受け取るコンテナのKestreLynxイメージを`repository@sha256:...`で指定します。空の場合はKestreLynx自身のPodの状態からdigest付き参照を取得します。クラスタの外では自身のPodから取得できないため、空のままだと言語パッケージ更新は`work_image_unavailable`で行われません。 |
| `remediation.worker.kubernetes.max_concurrent_pods` | いいえ | `1` | 同じインスタンスが同時に保持する作業用Pod数の上限で、`1`〜`16`を指定し、未削除の終了済みPodは数え、削除中のPodは数えません。削除中のPodを含む総数は作業用namespaceのResourceQuotaで制限します。 |
| `remediation.worker.kubernetes.runtime_class` | いいえ | 空 | 未対応のため空にし、指定した場合は`work_runtime_class_unsupported`で手動対応になります。 |

## 稼働時の使用状況 {#runtime}

[稼働時の使用状況](runtime-usage.md)は実験的な機能です。Sensorの導入手順、観測の判定方法、通知オフの条件と通知の再開、権限はリンク先を参照してください。

`io.kestrelynx.runtime.exclude=true`のラベルを持つコンテナは使用状況の判定から外します。値は小文字の`true`だけが該当します。

| 設定項目 | 既定値 | 説明 |
| --- | --- | --- |
| `runtime.enabled` | `false` | Sensorの証拠を読み、使用状況を通知に反映します。Sensorを置かない場合は無効のままにします。Dockerだけで利用でき、`kubernetes.enabled: true`との併用は設定エラーです。 |
| `runtime.mute_unfixable_not_in_use` | `false` | 修正版がなく7日以上使用が確認されない所見のうち、条件を満たすものをSlackで通知オフにします。`runtime.enabled: true`のときだけ有効です。優先度は変えず、汎用Webhookには全件残します。 |
| `runtime.evidence_dir` | `/var/lib/kestrelynx-runtime` | Sensorの証拠ボリュームをマウントした絶対パスです。Sensorの`--evidence-dir`と一致させます。 |
