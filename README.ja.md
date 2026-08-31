# KestreLynx

[English](README.md) | **日本語**

[![CI](https://github.com/kitsunetrail/kestrelynx/actions/workflows/ci.yml/badge.svg)](https://github.com/kitsunetrail/kestrelynx/actions/workflows/ci.yml)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)

[ドキュメント](https://kestrelynx.dev/) ·
[日本語ドキュメント](https://kestrelynx.dev/ja/) ·
[設定リファレンス](https://kestrelynx.dev/documentation/configuration/)

> 稼働中のDockerコンテナを毎日スキャンし、**対処可能な脆弱性**だけを優先順位付きでSlackまたはWebhookへ通知するエージェントです。

セルフホスティングやホームラボでの利用を想定しています。Trivyの生の出力を読み解く面倒な作業を代行し、*今すぐ修正できるもの*を明確にします。

> ⚠️ **ステータス：MVP / 開発中。** 現在はDockerのみを対象としたCVE通知に注力しています。

## 通知の例

```
🛡️ KestreLynx — scan results for 2026-06-28 09:00
12 images scanned, 3 affected

🆕 New since last scan (2)
🚨 nginx:1.25.3
   • libnghttp2-14 1.52.0-1 → 1.52.0-1+deb12u1 (HIGH 2)  🟢 upgrade: distro security patch
     ↳ CVE-2023-44487 HIGH · CISA KEV (exploited in the wild) · EPSS >99%
       📎 advisory · vendor advisory · 💬 HN (166 pts)
🔕 myapp:latest
   • webpack 4.46.0 → 5.89.0 (HIGH 1)  🟠 upgrade: major version bump — needs care [lang]

✅ Resolved since last scan (1)
• myapp:latest: postcss

📌 Open now: 🚨 1 act-now / 👀 2 watch / 🔕 4 low — oldest act-now/watch unresolved 12 day(s)
```

毎日すべてのCVEを羅列するのではなく、**何が変わったか**、そしてそのうち本当に重要なものはどれかを通知します。各検出結果は、深刻度と実際の悪用状況を示すシグナルを組み合わせ、**今すぐ対応（act now）／要監視（watch）／低優先度（low）**に分類されます。利用するシグナルは、実際の悪用が確認された脆弱性を収録する[CISA KEVカタログ](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)と、悪用される確率を予測する[EPSS](https://www.first.org/epss/)です。誰にも悪用されていないCRITICALは通知の邪魔にならない位置に置かれ、ランサムウェア攻撃者が実際に利用しているHIGHは、その根拠とともに通知の先頭に表示されます。既知のCVEが一晩のうちにKEVへ追加された場合、次回のダイジェストで**⬆️ 優先度上昇（escalated）**として通知されます。これこそ、実際に必要な通知です。変更がない日は大量の文章ではなく、1行だけを通知します。完全なレポートは週に1回送信され（設定変更可能）、すべてのデータは汎用Webhookからいつでも取得できます。

「今すぐ対応」に分類された項目には、対応担当者が通常検索することになるリンクも付属します。アドバイザリ、KEVエントリーに掲載されたベンダーのガイダンス、活発な議論がある場合はHacker Newsのスレッドです。AIによる要約ではなくリンクを提示するため、メッセージ内のすべての情報を検証できます。

**プライバシーに関する注意**：脅威情報フィードは一括ダウンロードしてローカルで照合するため、CVEリストがホスト外へ送信されることはありません。ただし、1つだけ明記された例外があります。議論リンクの検索では、**今すぐ対応に分類されたCVEのみ**（広く知られ、実際に悪用されている少数のCVE）について `hn.algolia.com` へ問い合わせます。CVE情報を一切外部送信したくない場合は、`triage.discussion_links: false` を設定してください。

## 主な機能

1. `docker.sock` から稼働中コンテナの一意なイメージを取得します（`GET /containers/json` を1回実行するだけで、コンテナを操作することはありません）
2. 各イメージを[Trivy](https://github.com/aquasecurity/trivy)でスキャンします（CVEデータベースはTrivyが管理します）
3. **HIGH / CRITICAL**の検出結果だけを残します
4. CISA KEVとEPSSを使って、各CVEを**今すぐ対応／要監視／低優先度**に分類します（毎日一括取得してローカルで照合。`triage.enabled: false` で無効化できます）。今すぐ対応に分類された項目には、アドバイザリ、ベンダーガイダンス、Hacker Newsの議論へのリンクも追加します
5. パッケージ単位で集約し、アップグレードのリスクを注記します（言語パッケージでは、セマンティックバージョニングを使って安全な更新か注意を要する更新かを判定します）
6. ベースOSのサポート終了（EOL）を最優先として通知します
7. 前回のスキャン結果との差分を取り、既知のCVEの**優先度上昇**（KEVへの追加やEPSSの急上昇）を含む**変更**だけを通知します。すでに把握している内容を繰り返し通知しません
8. 1日1回、SlackまたはWebhookへ通知します。ただし、対応する価値のある項目が存在する場合に限ります

## クイックスタート

```sh
# 1. 設定ファイルを作成（まずはSlack Incoming Webhook URLを追加するだけで開始できます）
cp config.example.yml config.yml
$EDITOR config.yml

# 2. 起動
docker run -d --name kestrelynx \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v "$PWD/config.yml:/etc/kestrelynx/config.yml:ro" \
  -v kestrelynx-state:/var/lib/kestrelynx \
  ghcr.io/kitsunetrail/kestrelynx:latest
```

（`kestrelynx-state` ボリュームには、差分通知に必要なスキャン履歴が保存されます。このボリュームがない場合、コンテナを再作成するたびに、すべての検出結果が新規項目として再通知されます。）

**Dockerソケットに関する注意**：KestreLynxが行うのは、稼働中コンテナを一覧表示するGETリクエスト（`GET /containers/json`）だけです。コンテナを起動、停止、変更することはありません。ただし、`docker.sock` をマウントすると、そのコンテナにはDocker APIへの特権的なアクセス権が与えられます。`:ro` はファイルシステム上のマウントを読み取り専用にしますが、Docker APIの操作を制限するものではありません。Dockerソケットをマウントするのは、信頼できるイメージだけにしてください。

設定はこれだけです。ホスト上のすべてのコンテナが、どのComposeプロジェクトや単発の `docker run` で起動されたかに関係なく、毎日スキャンされます。コンテナごと、またはComposeプロジェクトごとに起動する必要はありません。**1ホストにつき1インスタンス**で十分です。

### Docker Composeでの実行

すぐに利用できる[docker-compose.yml](docker-compose.yml)が含まれています。

```sh
cp config.example.yml config.yml   # 続いてSlack Webhookをconfig.ymlへ追加
docker compose up -d
docker compose logs -f
```

## 設定

[config.example.yml](config.example.yml)を参照してください。最低限、`notify.slack_webhook_url` または `notify.generic_webhook_url` のいずれかを設定すれば利用を開始できます。

主な設定項目：

- `notify.slack_bot_token` + `notify.slack_channel` — Webhookの代わりにSlack Web API経由で通知します（いずれか一方を使用してください）。チャンネルには同じ概要が投稿され、さらにそのスレッドへ**未解決項目の完全なレポート**が投稿されます。緊急／要監視の項目は、根拠、参照情報、未解決の期間とともに詳しく表示され、低優先度の項目は件数だけにまとめられます。変更がない日はレポートを再投稿せず、概要から直近の完全なレポートへリンクします。`chat:write` スコープを持ち、対象チャンネルへ招待されたBotトークンが必要です。
- `notify.mode` — `diff`（デフォルト）では、前回のスキャンから変化した内容と、現在未解決の項目を示す1行の概要だけを通知します。`full` では、スキャンのたびに完全なレポートを再送します。
- `notify.full_report_day` — diffモードで完全なレポートも送信する曜日です（デフォルトは `monday`。`never` で無効化）。
- `state.path` — diffモードで前回のスキャン結果を保存する場所です（デフォルトは `/var/lib/kestrelynx/state.json`）。
- `triage.enabled` — KEV/EPSSに基づく優先順位付けです（デフォルトは `true`）。`www.cisa.gov` と `epss.empiricalsecurity.com` への外向きHTTPS通信が追加されます（1日2回の一括ダウンロードで、stateファイルと同じ場所にキャッシュされます）。追加の外部通信を行わず、深刻度だけに基づいて通知するには `false` に設定してください。しきい値（`act_now_epss`、`watch_epss`）とミラーURLは変更できます。

## 開発

```sh
go test ./... -short   # 高速な単体テスト（Dockerやネットワークは不要）
go test ./...          # Trivyを利用する結合テストも実行（Trivyとネットワークが必要）
go build ./...
```

ドキュメントをローカルでビルドしてプレビューするには、次のコマンドを実行します。

```sh
python -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-docs.txt
mkdocs serve
```

日本語ドキュメントは別のプロセスでプレビューします。

```sh
mkdocs serve --config-file mkdocs.ja.yml
```

`main` へプッシュされたドキュメントの変更は、[`docs.yml`](.github/workflows/docs.yml)によってビルドおよびデプロイされます。初回デプロイ前に、**Settings → Pages → Build and deployment → Source** で **GitHub Actions** を選択してください。

パイプラインは小さなパッケージに分割されています。`docker`（列挙）→ `scanner`（Trivyの実行と解析）→ `intel`（KEV/EPSSの取得とキャッシュ）→ `analyze`（トリアージ、集約、評価）→ `state`（保存と前回スキャンとの差分取得）→ `notify`（整形と送信）を `runner` が結び付けます。

## ライセンス

[GNU AGPL-3.0](LICENSE)。Copyright (c) 2026 Kitsune Trail.

要約すると、自由に使用、変更、セルフホストできます。変更したバージョンをネットワークサービスとして運用する場合は、その利用者が変更後のソースコードを入手できるようにする必要があります。
