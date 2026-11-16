# 仕組み

## 機能の概要 {#overview}

KestreLynxは、稼働中のコンテナが使うイメージをTrivyでスキャンし、所見をパッケージ単位にまとめます。
悪用情報を使って対応の優先度を判定し、保存した履歴との比較から新規検出や解消などの変化を確認できます。

Slackとメールでは変化や現在の所見を、汎用Webhookでは所見と差分の構造化データを確認できます。
通知を送る条件と、通知の表示・フィールドの説明は、それぞれ独立したページに記載しています。

Docker・Compose・Kubernetesでは、所見を直すための修正計画を通知し、GitHubに修正PRを作成することもできます（実験的、既定で無効）。
修正計画はイメージや依存パッケージの更新候補を示し、マージ・ビルド・配置は利用者が行います。
詳細は[修正計画と修正PR](remediation.md)を参照してください。

導入方法は[セットアップ手順](getting-started.md)、設定値は[設定](configuration.md)を参照してください。

## ページの案内 {#contents}

判定の仕組み、通知の読み方、Webhookのフィールド仕様、外向きの通信を調べるページを案内します。

スキャン・差分・通知の判定と外向きの通信は、次のページで説明しています。

| 知りたいこと | ページ |
| --- | --- |
| スキャン対象・結果の集約と悪用情報による優先度 | <span id="cve"></span><span id="cve-priority-rules"></span>[スキャンと優先度の判定](scan-logic.md) |
| パッケージ・イメージの変化と履歴の引き継ぎ | [差分と履歴の判定](diff-logic.md) |
| スキャン通知・修正計画の送信条件と再送 | <span id="notification-conditions"></span><span id="remediation-slack-delivery"></span><span id="remediation-webhook-delivery"></span><span id="remediation-redelivery"></span>[通知の送信条件](notification-conditions.md) |
| 通信先・送信情報・認証情報の送付範囲 | <span id="outbound-communication"></span><span id="kev-download"></span><span id="epss-download"></span><span id="hacker-news-search"></span><span id="trivy-downloads"></span><span id="github-communication"></span><span id="candidate-registry-communication"></span><span id="worker-image-downloads"></span><span id="tool-downloads"></span><span id="dependency-downloads"></span><span id="notification-delivery"></span><span id="credential-destinations"></span><span id="worker-network"></span>[外向きの通信](outbound-communication.md) |

Slackの表示と件数の読み方は、次のページで確認できます。

| 知りたいこと | ページ |
| --- | --- |
| レポートの確認場所・通知の言語・区分の順序・件数 | <span id="slack-display"></span><span id="notification-language"></span>[レポートの構成と件数](slack-display.md) |
| パッケージカードの内容と変化の表示 | [パッケージカードと変化の表示](slack-package-display.md) |
| 使用状況のラベル・観測根拠・通知オフの表示 | [稼働時の使用状況の表示](slack-runtime-display.md) |
| スキャン・脅威情報・Sensor（使用中のパッケージを観測するコンテナ）の警告 | [警告の読み方](slack-warnings-display.md) |

汎用Webhookの基本・差分・稼働時のフィールド仕様は、次のページで確認できます。

| 知りたいこと | ページ |
| --- | --- |
| ペイロード全体・レポート・イメージ・所見のフィールド | <span id="generic-webhook"></span>[基本のフィールド](webhook-reference.md) |
| パッケージ・イメージ・EOLの変化を表すフィールド | [差分のフィールド](webhook-diff-reference.md) |
| Sensorの状態・使用状況・観測根拠のフィールド | [稼働時のフィールド](webhook-runtime-reference.md) |

汎用Webhookに含まれる修正計画のフィールド仕様は、次のページで確認できます。

| 知りたいこと | ページ |
| --- | --- |
| 修正計画の全体像と共通オブジェクト | <span id="remediation-fields"></span>[全体と共通のオブジェクト](webhook-remediation-reference.md) |
| 配布イメージの項目とKubernetesのワークロード情報 | <span id="remediation-image-fields"></span>[配布イメージ](webhook-remediation-image-reference.md) |
| ベースイメージの計画・稼働イメージごとの結果・再ビルドの見込み | <span id="remediation-dockerfile-fields"></span>[ベースイメージ](webhook-remediation-dockerfile-reference.md) |
| 言語パッケージごとの結果と修正版に上げられないときの案内 | <span id="remediation-language-fields"></span>[項目とパッケージ](webhook-remediation-language-reference.md) |
| 言語パッケージの更新記録・実行環境・ツール | [更新の記録](webhook-remediation-update-reference.md) |
| 言語パッケージの更新前後の検査と更新ファイル | [更新前後の検査](webhook-remediation-check-reference.md) |
| PR処理の結果・操作イベント・書き込みを停止する問題 | <span id="remediation-pr-fields"></span><span id="remediation-json-example"></span><span id="remediation-operation-fields"></span><span id="remediation-problem-fields"></span>[PR処理](webhook-remediation-pr-reference.md) |
