# Dockerイメージの脆弱性通知

KestreLynxは、Dockerホストで現在稼働しているイメージをスキャンし、
対応が必要な脆弱性の変化を通知する軽量なオープンソースエージェントです。

毎日同じスキャン結果をすべて送るのではなく、**新規検出**、**解消**、
**修正版の提供の有無**、**緊急度上昇**を強調します。
[Trivy](https://trivy.dev/)のスキャン結果に
[CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)と
[EPSS](https://www.first.org/epss/)の情報を組み合わせ、緊急の問題とノイズを分離するようにしてます。

<div class="grid cards" markdown>

-   :material-rocket-launch-outline: **KestreLynxセットアップ手順**

    ---

    Dockerホストにコンテナを1つ導入し、結果をSlackもしくはWebhookへ
    送信します。

    [セットアップ手順](documentation/getting-started.md)

-   :material-bell-badge-outline: **通知の判定ロジック**

    ---

    変更検出と悪用情報から、検出結果をact now、watch、lowに分類方法を記載しています。

    [KestreLynxの仕組み](documentation/how-it-works.md)


</div>

!!! warning "初期リリース"
    KestreLynxは現在、DockerホストのCVE通知に重点を置いたMVPです。
