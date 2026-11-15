# ドキュメント

このセクションでは、KestreLynxのインストール、設定、運用方法について記載します。

## ページの案内 {#contents}

KestreLynxの比較・導入・設定・仕組み・修正計画・稼働時の使用状況を調べるページを案内します。

| 知りたいこと | ページ |
| --- | --- |
| 更新PRとイメージへのパッチ適用の違い・更新前後の脆弱性の確認 | [他のツールとの比較](comparison.md) |
| Docker Compose・`docker run`・Kubernetesでの導入 | [セットアップ](getting-started.md) |
| 実行スケジュール・通知先・Kubernetes・環境名・状態管理・脆弱性の優先順位付けの設定 | [設定](configuration.md) |
| 機能の概要と判定の仕組み・Slackの読み方・Webhookのフィールド仕様・外向きの通信 | [仕組み](how-it-works.md) |
| 修正計画と修正PRの導入・結果の読み方・判定の仕組み・利用できるファイルと版指定 | [修正計画と修正PR（実験的）](remediation.md#contents) |
| 任意のDocker向けSensorによる、優先度を変えない使用中パッケージの表示 | [稼働時の使用状況（実験的）](runtime-usage.md) |

KestreLynxは現在も開発中です。
特記がない限り、このドキュメントは最新のコンテナイメージと`main`ブランチの内容を説明しています。

バグ、機能要望、ドキュメントの修正は[GitHubリポジトリ](https://github.com/kitsunetrail/kestrelynx/issues)へIssueを作成してください。
