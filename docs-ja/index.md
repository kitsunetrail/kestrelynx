# Docker・Kubernetesのコンテナイメージの脆弱性通知

KestreLynxは、DockerまたはKubernetesで稼働中のコンテナが使用するイメージをスキャンし、
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

!!! info "Kubernetes対応の検証範囲"
    Kubernetesでの発見・スキャン・通知は、
    linux/amd64の単一ノードK3sとcontainerdで検証済みです。
    未検証の構成を含む詳細は、[検証記録と制約](development/kubernetes-support.md)を参照してください。
