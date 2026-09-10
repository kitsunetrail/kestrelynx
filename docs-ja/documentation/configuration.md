# 設定

YAML設定ファイルについて説明します。コンテナイメージでは既定で
`/etc/kestrelynx/config.yml`を使用します。未知のYAMLフィールドはエラーになるようになってます。

コメント付きの完全な例は
[`config.example.yml`](https://github.com/kitsunetrail/kestrelynx/blob/main/config.example.yml)に
あります。

## スケジュール

| 設定項目 | 既定値 | 説明 |
| --- | --- | --- |
| `schedule.daily_at` | 空 | `HH:MM`形式のローカル時刻。空の場合は起動時点から24時間ごとに実行します。 |
| `schedule.run_on_start` | `true` | KestreLynxの起動直後に1回スキャンします。 |

`daily_at`で使用するタイムゾーンは、コンテナの`TZ`環境変数で指定します。

## スキャン

| 設定項目 | 既定値 | 説明 |
| --- | --- | --- |
| `scan.severity` | `[HIGH, CRITICAL]` | 分析と通知の対象にするTrivyの深刻度です。 |

指定できる値は`UNKNOWN`、`LOW`、`MEDIUM`、`HIGH`、`CRITICAL`です。

## 通知先

少なくとも1つの通知先が必要です。

| 設定項目 | 既定値 | 説明 |
| --- | --- | --- |
| `notify.slack_webhook_url` | 空 | Slack Incoming WebhookのURLです。 |
| `notify.slack_bot_token` | 空 | `chat:write`権限を持つSlack Bot Tokenです。`slack_channel`と一緒に設定します。 |
| `notify.slack_channel` | 空 | Botで通知するSlackチャンネルIDです。 |
| `notify.generic_webhook_url` | 空 | 構造化JSONを受け取るエンドポイントです。 |
| `notify.notify_on_clean` | `false` | 脆弱性がない場合にも通知します。 |

`slack_webhook_url`とBot Tokenの組み合わせを同時には設定できません。
汎用Webhookは、どちらのSlack通知方式とも併用できます。

Botによる通知では、サマリーメッセージのスレッドに未解決項目の完全なレポートを
追加します。変化がない日はレポートを再投稿せず、直近の完全なレポートへのリンクを
表示します。

## 通知モード

| 設定項目 | 既定値 | 説明 |
| --- | --- | --- |
| `notify.mode` | `diff` | `diff`は変化を通知し、`full`はスキャンごとに現在の全項目を通知します。 |
| `notify.full_report_day` | `monday` | diffモードで完全なレポートを送る曜日です。`never`で無効化します。 |

diffモードでは、新規検出、解消、修正可能化、緊急度上昇を通知します。未解決項目が
残っていても変化がない場合、完全なレポートを繰り返さず、短いハートビート通知を
送信します。

## 状態管理とDocker

| 設定項目 | 既定値 | 説明 |
| --- | --- | --- |
| `docker.socket` | `/var/run/docker.sock` | Dockerソケットのパスです。 |
| `state.path` | `/var/lib/kestrelynx/state.json` | スキャン履歴と差分計算に使用するファイルです。 |

`state.path`を含むディレクトリをDockerボリューム、またはKubernetesの永続ボリュームで
永続化してください。脅威情報フィードのキャッシュは、`state.path`と同じディレクトリ内の
`intel`ディレクトリに保存します。既定のパスは`/var/lib/kestrelynx/intel`です。

## Kubernetes

| 設定項目 | 既定値 | 説明 |
| --- | --- | --- |
| `kubernetes.enabled` | `false` | Dockerホストの代わりにKubernetesクラスタをスキャンします。 |
| `kubernetes.api_server` | 空 | Kubernetes APIサーバのURLです。空の場合は`KUBERNETES_SERVICE_HOST`と`KUBERNETES_SERVICE_PORT`を使用します。空でない値は`https://`で始まる必要があります。 |
| `kubernetes.token_file` | 空 | ServiceAccountのトークンファイルです。空の場合は`/var/run/secrets/kubernetes.io/serviceaccount/token`を使用します。 |
| `kubernetes.ca_file` | 空 | PEM形式のクラスタCAバンドルです。空の場合は`/var/run/secrets/kubernetes.io/serviceaccount/ca.crt`を使用します。 |
| `kubernetes.tls_server_name` | 空 | APIサーバのTLS証明書の検証に使用するサーバ名を上書きします。空の場合は上書きしません。 |
| `kubernetes.namespaces` | `[]` | スキャン対象のnamespaceです。空または省略した場合は、すべてのnamespaceを対象にします。 |

`docker.socket`に値（空文字列`""`を含みます）を設定した状態で`kubernetes.enabled: true`を設定すると、
起動に失敗します。キーを省略するか値を`null`にした場合は、この排他条件に該当しません。
空の`docker:`セクションは受け付けます。Kubernetesを有効にする場合は、`docker:`セクション全体を削除してください。

クラスタ内では、`api_server`、`token_file`、`ca_file`を空のままにすると、
Podに注入されたAPIサーバのアドレスと、マウントされたServiceAccountのトークンおよび
CAを使用できます。Kubernetesが有効な場合、`api_server`が空で、APIサーバの環境変数の
いずれかが欠けていると起動に失敗します。CAバンドルは実行時に読み取り可能で、
有効なPEM証明書を含む必要があります。安全でない接続へのフォールバックはありません。

各namespaceはDNS-1123ラベルである必要があります。使用できる文字は小文字の英数字と
ハイフンで、長さは1〜63バイト、先頭と末尾は英数字にします。namespaceを指定した場合、
Pod、ReplicaSet、Jobの一覧はnamespaceごとに個別に取得します。Nodeの一覧は
引き続きクラスタ全体から取得します。

## 環境

| 設定項目 | 既定値 | 説明 |
| --- | --- | --- |
| `environment.name` | 空 | このインスタンスのスキャン履歴に付ける任意の名前です。空の場合は、名前のない既定の環境になります。 |

空でない名前はDNS-1123ラベルである必要があります。使用できる文字は小文字の英数字と
ハイフンで、長さは1〜63バイト、先頭と末尾は英数字にします。値は正規化しません。
大文字、ドット、アンダースコア、空白文字は受け付けません。

名前を設定すると、Slackのヘッダーには`[name]`として、汎用Webhookのペイロードでは
`environment`オブジェクトの`name`として表示します。このオブジェクトには、
有効なadapterに基づく`kind`が常に含まれ、値は`docker`または`kubernetes`です。
環境種別は設定できません。名前が空の場合、Webhookでは`name`を省略します。

この名前はスキャン履歴に付けるラベルであり、ホストを識別するものではありません。
ホスト名やIPアドレスから生成することもありません。状態ファイルを保持していれば、
ホストの再構築や移行の前後で同じ名前を使い続けても問題ありません。名前を追加、変更、
削除しても、履歴のリセット、初回検出日の変更、既存の検出項目の再通知は行いません。

## 悪用情報に基づく優先順位付け

| 設定項目 | 既定値 | 説明 |
| --- | --- | --- |
| `triage.enabled` | `true` | CISA KEVとEPSSによる優先順位付けを有効にします。 |
| `triage.act_now_epss` | `0.10` | CVEをact nowに分類するEPSS確率の下限です。 |
| `triage.watch_epss` | `0.01` | CVEを少なくともwatchに分類するEPSS確率の下限です。 |
| `triage.kev_url` | 空 | CISA KEVフィードのURLを、ローカルミラーなどへ変更します。 |
| `triage.epss_url` | 空 | EPSSフィードのURLを、ローカルミラーなどへ変更します。 |
| `triage.discussion_links` | `true` | act-now CVEに関するHacker Newsの議論を検索します。 |

KEVとEPSSのフィードは一括でダウンロードされ、CVE IDとの照合はローカルで行われます。
ホストの完全なCVE一覧が外部サービスへアップロードされることはありません。
議論リンクを有効にしている場合、act-now CVEのIDは検索クエリとして
`hn.algolia.com`へ送信されます。この送信を防ぐには`discussion_links: false`、
追加の脅威情報フィードへの通信も止めるにはtriage自体を無効にしてください。

しきい値は次の条件を満たす必要があります。

```text
0 < watch_epss <= act_now_epss <= 1
```
