# Kubernetes向け脆弱性スキャンツールの調査

- **状態:** Kubernetes対応に着手する前の調査記録
- **公開日:** 2026年9月5日

## 概要

KestreLynxのKubernetes対応を検討するにあたり、既存の脆弱性スキャンツールが提供している機能を調べ、KestreLynxで追加する機能の範囲を整理しました。

KestreLynxで実装しているCISA KEVとEPSSを使って対応の優先度の判定をKubernetesでも同様の仕組みを利用する方針です。

本記事では、既存ツールの機能と、KestreLynxの要件を満たすために追加の実装が必要な点を整理します。調査の観点は次の3つです。

| 観点 | 確認すること |
| --- | --- |
| スキャンと優先度判定 | 稼働中のイメージを検出し、KEVやEPSSなどを使って対応順序を決められるか |
| 差分通知 | 脆弱性の新規検出・悪化・解消を区別して通知できるか |
| イメージの識別 | タグが同じでも内容が変わったことや、複数のワークロードが同じイメージを使っていることを把握できるか |

調査結果は、2026年9月5日時点で確認したバージョンとドキュメントに基づきます。

## 既存ツールの主な機能

### Trivy Operator

[Trivy Operator](https://aquasecurity.github.io/trivy-operator/latest/)は、Kubernetesクラスタを継続的にスキャンするツールです。

- 調査対象はv0.34.0（2026年8月24日公開、Trivy v0.74.0を同梱）
- スキャン結果はKubernetesのカスタムリソースとして保存され、主なレポートは次のとおり

| レポート | 対象 |
| --- | --- |
| `VulnerabilityReport` | イメージの脆弱性 |
| `ConfigAuditReport` | 設定の監査 |
| `ExposedSecretReport` | シークレットの露出 |
| `RbacAssessmentReport` | RBACの評価 |
| `InfraAssessmentReport` | クラスタのインフラ評価 |
| `ClusterComplianceReport` | コンプライアンスの評価 |
| `SbomReport` | ソフトウェア部品表（SBOM） |

- イメージの脆弱性に加え、設定監査、RBAC、クラスタのインフラ評価、コンプライアンスの報告まで1つのOperatorで幅広く扱っており、KestreLynxが対象とする予定の範囲を超えている
- [Prometheus向けのメトリクス](https://aquasecurity.github.io/trivy-operator/latest/tutorials/integrations/metrics/)も提供しており、深刻度別の集計に加えて、設定を有効にするとCVE単位の情報を取得できる
- Webhookでレポートの生成時に全体を送信できる
- SlackやTeamsなどへの通知は、[Postee](https://aquasecurity.github.io/trivy-operator/latest/tutorials/integrations/webhook/)や[Policy Reporter](https://aquasecurity.github.io/trivy-operator/latest/tutorials/integrations/policy-reporter/)との連携が公式ドキュメントで案内されている
- チャットへの通知は組み込み機能ではなく、外部ツールと組み合わせる構成

### Kubescape

[Kubescape](https://kubescape.io/docs/operator/)は、CNCFのIncubatingプロジェクトです。

- Grypeによるイメージスキャン、設定チェック、RBAC分析を提供している
- 特徴の1つが、実行時の情報を使って脆弱性を絞り込む**relevancy**
- eBPFを利用するnode-agentが、コンテナで実際にロードされたパッケージを観測する
- その情報を使い、観測されたパッケージに関係する脆弱性へ対象を絞り込む
- この仕組みは、CVEのノイズを減らす有力な方法
- KestreLynxでは、この実行時の観測機能を実装する予定はない

### Grypeとk8s-inventory

[Grype](https://github.com/anchore/grype)は、[CISA KEVとEPSSに対応](https://github.com/anchore/grype/pull/2587)した脆弱性スキャナーです。

- これらの情報を組み合わせた「Risk」スコアを使い、既定で結果を並べ替える
- スキャン後の優先度判定まで、スキャナー側で行える
- これは、優先度判定を後段のツールに全面的に任せるのではなく、脆弱性スキャナー自体で行う傾向が強まっていることを示す重要な動き
- Anchoreは、クラスタを継続的に監視するために、Grypeと[`k8s-inventory`](https://github.com/anchore/k8s-inventory)を組み合わせている
- `k8s-inventory`はKubernetes APIを定期的に問い合わせ、稼働中のイメージを収集するエージェント
- クラスタ内で実行するほか、外部からkubeconfigを使って接続できる
- この取得方法は、KestreLynxで計画しているKubernetesの探索処理に近い構成

### OWASP Dependency-Track

[Dependency-Track](https://docs.dependencytrack.org/)は、今回調べたOSSの中で、優先度判定と通知の要件に最も近いツールでした。

- CISAとENISA EU KEVのデータを既定で取り込み、[EPSSにも対応](https://dependencytrack.org/news/dependency-track-5-1/)している
- 通知先はSlack、Teams、Mattermost、Jira、メールなど8種類ある
- 新しく見つかった脆弱性をイベントに応じて通知できる

### Policy Reporter

[Policy Reporter](https://github.com/kyverno/policy-reporter)は、`PolicyReport`リソースを監視し、新しく見つかったポリシー違反をSlackやTeamsなどへ通知する軽量なツールです。

- セルフホストできる
- Trivy Operatorともアダプターを通じて連携し、そのレポートを監視できる

### 商用プラットフォーム

商用製品には、優先度判定や通知の面でさらに進んだ機能を提供するものがあります。

| 製品 | 主な機能 |
| --- | --- |
| [Wiz](https://www.wiz.io/solutions/vulnerability-management) | CVSS・EPSS・CISA KEVに加え、外部への露出など環境の情報を使った優先度判定 |
| [Snyk](https://snyk.io/product/container-vulnerability-management/) | CVSS・EPSS・CISA KEVを使った優先度判定 |
| [Sysdig Secure](https://docs.sysdig.com/en/sysdig-secure/vulnerability-management/) | 実行時の使用状況に基づく優先度判定（In Use） |
| [ARMO Platform](https://www.armosec.io/armo-vs-kubescape/) | Kubescapeの商用版。eBPFによるrelevancyと、Slack・Teams・Jiraへの組み込み通知 |

- これらは主に大規模な組織を対象とし、単一バイナリをセルフホストする構成とは異なる
- Wizのクラウドスキャンは既定でエージェントを使わない
- Sysdig、ARMO、SnykのKubernetes連携は、多くの場合、クラスタ内のエージェントとSaaS側のバックエンドを組み合わせる

## 調査で確認できなかったこと

Dockerホスト向けに実装済みの次の3点を、Kubernetesでも必要な要件としています。

| 要件 | Dockerホスト向け | Kubernetes向け |
| --- | --- | --- |
| KEV・EPSSによる優先度判定と、前回の結果に対する新規・悪化・解消を区別する差分通知 | 実装済み | 同じ仕組みが必要 |
| 解消判定での「実際の修正」と「観測できなくなっただけ」の区別 | 実装済み | 同じ区別が必要 |
| digestによるイメージ実体の識別を使った、スキャンの重複排除・ワークロードとの関連付け・通知の重複排除 | 実装済み | 同じ3用途への対応が必要 |

以下では、調査したバージョンとドキュメントに記載された構成について、既存ツール側の状況と、これらの要件を既存ツールの組み合わせで満たす場合に利用者側で必要になる追加実装を整理します。

### 新規・悪化・解消を区別する通知

今回の調査では、KEVとEPSSによる優先度判定に加え、**新規・悪化・解消**を区別し、解消時には修正と観測の中断も区別する通知を、1つのセルフホスト可能なコンポーネントで提供するツールは確認できませんでした。

- Dependency-Trackは優先度判定と新規検出の通知に対応しているが、調査した範囲では解消や深刻度の悪化を通知する機能がない
- Trivy OperatorのWebhookもレポート全体を送る仕組みなので、これを使って差分通知の要件を満たすには、利用者側で前回との差分を判定する処理を別途実装する必要がある

### メトリクスが消えた場合の解消判定

Trivy Operatorの脆弱性ごと（CVE単位）のメトリクスをPrometheusとAlertmanagerと組み合わせると、脆弱性を検出したときに通知し、アラートが解消したときに再度通知する構成を作れます。

- メトリクスが消えただけでは、脆弱性が修正されたとは判断できない
    - ワークロードの縮小・停止、レポートの失効、メトリクス収集の中断でも消えることがある
    - そのまま解消として通知すると、修正されていないのに「修正された」と伝えてしまう可能性がある
- 深刻度ごとにメトリクスを区別している場合は、深刻度の変化にも注意が必要
    - 深刻度が変わると、監視上は古い項目が消えて新しい項目が現れる
    - そのまま通知すると、同じ脆弱性が悪化しただけでも「以前の脆弱性が解消した」「別の脆弱性が新しく見つかった」と扱われる可能性がある
- 正しく判定するには、利用者側で次の2つの処理を設計・実装する必要がある
    - 対象の状態を引き続き正常に確認できているかを調べ、修正と観測の中断を区別する
    - 変化の前後で同じ脆弱性を対応付け、新規・悪化・解消を判定する
- これらの処理はPrometheus内で実装する方法も、別のアプリケーションで行う方法もある

### digestによるイメージの識別

イメージを識別するときは、タグと、そのタグが指す中身を分けて考える必要があります。

- タグが同じでも、更新によってイメージの中身が変わることがある
    - 例えば、`example/api:latest`という名前が変わらなくても、更新後には別の中身を指すことがある
    - 中身を識別するdigestを記録すれば、この変化を追跡できる
- 調査したSBOM生成ツールの`sbom-operator`は、Dependency-Trackへ結果を送る際、タグがあればタグを使って記録を識別する
    - タグの指す中身が入れ替わってdigestが変わっても、同じ記録が上書きされる
    - digestを使って記録を識別するのは、タグがない場合だけ
    - この構成では、タグの指す中身が変わっても、別のイメージとして追跡されない
- この点を含め、digestの使い道を次の3つに分けて確認した

| 確認項目 | 目的 |
| --- | --- |
| スキャンの重複排除 | 同じdigestのイメージに対する重複したスキャンを避ける |
| ワークロードとの関連付け | 複数のワークロードが同じdigestのイメージを使っていることを把握する |
| 通知の重複排除 | 同じdigestについて重複した通知を送らない |

- それぞれに部分的な対応はあったが、3つをまとめて満たす構成は確認できなかった
    - 今回確認した既存ツールを組み合わせて要件を満たすには、利用者側で、それぞれの使い道についてツールが対応する範囲を確認し、不足する処理を実装する必要がある
- 特に、複数のワークロードが同じdigestのイメージを使っていることを関連付ける機能は、ほかのツールにも存在する可能性がある
    - この機能については、既存ツールとの比較・検証を続ける

以上は、2026年9月5日時点で確認できたバージョンとドキュメントに基づく調査結果です。今回確認できなかった機能が、ほかのツールや構成にも存在しない、あるいは今後も存在しないと断定するものではありません。

## Kubernetes対応の方針

調査結果を踏まえ、次の機能を追加する方針です。

- **稼働イメージの探索:** Kubernetes API（`kube-apiserver`）から読み取り専用で情報を取得し、ノードへの直接アクセスや特権エージェントは使わない
- **優先度判定と差分通知:** Dockerホスト向けに実装済みのKEV・EPSSによる判定と、新規・悪化・解消の通知をKubernetesのワークロードにも適用する
- **イメージ実体の追跡:** digestを使ってタグの指す内容の変更を追跡し、同じ実体を使う複数のワークロードを関連付け、同じ実体に対するスキャンと通知の重複を避けることを目指す

---

この記事は、KestreLynxの開発記録です。[KestreLynxについて](../index.md)
