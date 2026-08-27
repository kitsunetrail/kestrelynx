# Dockerイメージの脆弱性通知

KestreLynxは、Dockerホストで現在稼働しているイメージをスキャンし、
対応が必要な脆弱性の変化を通知する軽量なオープンソースエージェントです。

毎日同じスキャン結果をすべて送るのではなく、**新規検出**、**解消**、
**修正版の提供の有無**、**緊急度上昇**を強調します。
[Trivy](https://trivy.dev/)のスキャン結果に
[CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)と
[EPSS](https://www.first.org/epss/)の情報を組み合わせ、緊急の問題とノイズを分離するようにしてます。

- :material-rocket-launch-outline: [KestreLynxセットアップ手順](documentation/getting-started.md)
- :material-bell-badge-outline: [通知の判定ロジック](documentation/how-it-works.md)
- :material-hammer-wrench: [開発ログ](development/index.md)
- :material-book-open-page-variant-outline: [技術記事](articles/index.md)

!!! warning "初期リリース"
    KestreLynxは現在、DockerホストのCVE通知に重点を置いたMVPです。
