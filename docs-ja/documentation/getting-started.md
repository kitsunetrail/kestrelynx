# セットアップ手順

StackWatchはDockerホストごとに1つのコンテナとして動作します。  
実行中のコンテナが使用しているイメージを特定してスキャンし、その結果をSlackまたは
Webhookへ送信します。

## 必要なもの

- Dockerホスト
- Docker ComposeまたはDocker CLI
- 次のうち1つ以上の通知先
    - Slack Incoming Webhook
    - Slack Bot Tokenとチャンネル
    - Webhook URL

## Docker Composeで実行

リポジトリをダウンロードまたはcloneし、ローカル設定ファイルを作成します。

```bash
cp config.example.yml config.yml
```

以下のように少なくとも1つの通知先を設定してください。

```yaml
notify:
  slack_webhook_url: "https://hooks.slack.com/services/..."
```

StackWatchを起動します。

```bash
docker compose up -d
docker compose logs -f
```

同梱のComposeファイルは、スキャン履歴を`stackwatch-state`ボリュームへ
永続化します。  
この状態データは、コンテナを再作成した後も差分通知と初回検出日を
維持するために必要です。

## Dockerで実行

```bash
docker run -d --name stackwatch \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v "$PWD/config.yml:/etc/stackwatch/config.yml:ro" \
  -v stackwatch-state:/var/lib/stackwatch \
  ghcr.io/kitsunetrail/stackwatch:latest
```

## タイムゾーンを設定

`schedule.daily_at`は、`TZ`で指定したタイムゾーンとして解釈されます。  
Composeの例ではUTCが既定値です。必要に応じて、運用するホストのタイムゾーンへ
変更してください。

```yaml
environment:
  - TZ=Asia/Tokyo
```

## 参考ページ

- configについては[設定項目](configuration.md)を参照してください。
- 通知ロジックは[通知ロジック](how-it-works.md)を参照してください。
