# 開発ログ

取り組んでいる課題、試した方法、実装中に分かったこと、技術判断について記載します。

開発ログは検討・実装の過程の記録です。現在利用できる機能の導入・運用方法は[ドキュメント](../documentation/index.md)を参照してください。

- [実行時証拠の観測環境の検証](runtime-environment-validation.md) — 採用した実行時証拠を実装する前に、観測に必要な権限、常駐時の負荷、実運用環境での開始条件と利用経路を確かめた検証(計測完了)
- [実行時証拠の網羅性の検証](runtime-coverage-validation.md) — ワークロードが実際に使ったパッケージ全体のうち各方式がどれだけ確認できるかを、独立した正解データで評価した検証(計測済み)
- [eBPFによる実行時証拠の観測調査](runtime-event-evidence.md) — サンプリングでは確認できなかった短命プロセスと言語パッケージを、eBPF による実行と読み込みのイベント観測で確認できるかの調査
- [実行時証拠による優先順位付けの成立性調査](runtime-prioritization.md) — プロセス・待ち受けポート・権限を
  脆弱性の検出結果に紐づけ、優先順位付けの改善に使えるかを検証した調査(検証完了)
- [Kubernetes対応の開発](kubernetes-support.md) — K3s + containerdを出発点に、KubernetesのWorkloadを
  スキャン・優先順位付け・差分通知へつなぐ実装(実装済み・K3s実環境でエンドツーエンド検証済み)
- [Kubernetes向け脆弱性スキャンツールの調査](kubernetes-scanning-landscape.md) — Kubernetes対応に着手する前に、
  既存ツールの機能と追加実装が必要な点を整理した記録(調査ノート)
- [修正関係モデルの設計](remediation-relations-model.md) — 検出した脆弱性を「どこを直せば消えるか」の
  提案につなげるための関係モデル(モデル定義済み)
- [Environment / Workloadモデルの開発](environment-workload-model.md) — 実行環境の識別と、
  containerとサービスの対応付けを脆弱性の記録へ結び付けるモデルの実装(実装済み)
- [イメージ識別モデルの開発](image-identity-model.md) — イメージ名を中心とした処理から、実際の内容を
  特定できる不変なimage digestでイメージ実体を識別する処理への移行(実装済み)
