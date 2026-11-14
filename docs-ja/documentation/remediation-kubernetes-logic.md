---
title: Kubernetesのタグ更新PRの条件
---

# Kubernetesのタグ更新PRの条件

Kubernetesのマニフェスト、Kustomize、Helmのvaluesについて、タグ更新PRを作る条件と見送る範囲を説明します。
候補のタグの選び方は[イメージ候補の選定](remediation-image-logic.md#image-selection)を参照してください。

このページで使う用語は[用語](remediation.md#terms)を参照してください。

## Kubernetesのイメージ名と再取得 {#kubernetes-image-references}

Podのspecに書かれたイメージ名が、稼働イメージの名前と同じかを確かめます。
配布イメージの候補を調べる前に行います。

リポジトリ名の省略を補って正規化し、タグとdigestを比較します。
稼働イメージの名前には、通常はPodの`status.containerStatuses[].image`を使います。

containerdでは、ノードがイメージをタグなしで保持していると、`image`がイメージconfigのID（`sha256:…`）になることがあります。
例えば、digestだけで指定して取得した場合が該当します。

`image`がconfigのIDの場合は、同じコンテナの`imageID`を確認して、稼働イメージの名前を選びます。

| `imageID`の内容 | 稼働イメージの名前に使う値 |
| --- | --- |
| `ghcr.io/example/app@sha256:…`のようなリポジトリとdigestを含む名前 | `imageID`のリポジトリとdigest |
| リポジトリを含まない値 | 元の`image`の値 |

リポジトリとdigestを使える場合は、通知のイメージ欄にconfigのIDだけが表示されるのを避けられます。
Podのspecに書かれたdigestを含むイメージ名とも照合できます。

確認するコンテナは、KestreLynxが観測した稼働コンテナから、稼働イメージの名前が同じものを集めます。
Podやワークロードが異なっていても含め、各コンテナのspecのイメージ名を、そのコンテナの稼働イメージ名と比べます。

1つでも一致しない場合は、そのイメージ名の計画項目を比較不能（`not_comparable`）にし、理由を`declared_ref_mismatch`にします。
specのイメージ名を読み取れない場合も比較不能になり、理由は`declared_ref_unavailable`です。

浮動タグの新しい内容で改善を確認した場合は、`imagePullPolicy`に応じて次の再取得方法を案内します。
表の`pull[].guidance`は、Webhookの`remediation.items[]`にある各イメージ項目の再取得案内です。

| `imagePullPolicy` | `pull[].guidance` | 案内 |
| --- | --- | --- |
| `Always` | `restart_pulls` | Podを再起動すると新しい内容を取得する |
| `IfNotPresent` | `change_tag_or_digest` | ノードにある内容を再利用するため、固定タグまたはdigestへの変更が必要 |
| `Never` | `import_to_node` | ノードへのイメージの取り込みが必要 |

## KubernetesのマニフェストPR {#kubernetes-manifest-prs}

マニフェストのPRは、Podのspec・稼働イメージ・編集するファイルのイメージ名が一致し、更新対象で同じ候補を採用できることを確かめて作ります。
確認には、`remediation.mappings`の対応付けを使います。

同じリポジトリ・ベースブランチ・マニフェストファイルを指す対応付けをすべて確認します。
PR作成には、次の条件を満たす必要があります。

- 対応付けた各コンテナに稼働中のPodがあり、稼働イメージ名をすべて取得できる
- 各コンテナのspecのイメージ名と稼働イメージ名が一致する
- 同じワークロードの各Podで、対応付けた同じ名前の稼働コンテナのイメージ名がそろう
- 同じファイルで同じイメージを更新する対象すべてに計画項目があり、同じタグとdigestの候補を採用できる
- ファイル内の編集対象のイメージ名が、Podのspecのイメージ名と稼働イメージ名に一致する

例えば、Deployment`web`では各Podの`app`を比べます。
ローリング更新中に`app`の版が混在する場合は条件を満たしません。

名前の異なるアプリ用コンテナとsidecarのイメージ名をそろえる条件ではありません。

Podのspec、稼働イメージ、`apps/web.yaml`がすべて`nginx:1.27.2`を指す場合を例にします。
同じ系列の`1.27.3`を採用できれば、ファイルのタグだけを更新するPRを作ります。

以下は、`apps/web.yaml`に`web`・`worker`・`api`の3つのDeploymentを置き、それぞれの`app`を対応付けた架空の例です。
稼働状態を確認する対象、更新する対象、確認に失敗した場合の見送り範囲を比べます。

| コンテナ | 使用するイメージ | 確認する内容 | 更新内容 | 確認に失敗した場合 |
| --- | --- | --- | --- | --- |
| `web/app` | `nginx:1.27.2` | 稼働状態と`1.27.3`の候補 | `1.27.3`へのタグ更新 | ファイル全体のPRを見送り |
| `worker/app` | `nginx:1.27.2` | 稼働状態と`1.27.3`の候補 | `1.27.3`へのタグ更新 | ファイル全体のPRを見送り |
| `api/app` | 別のイメージで、直すものなし | 稼働状態 | 更新なし | ファイル全体のPRを見送り |

`web/app`と`worker/app`は同じイメージの更新対象なので、どちらにも計画項目と共通の候補が必要です。
`api/app`は更新対象に含めず、直すものがないことを理由にほかのPRを止めません。

更新しない`api/app`にもstatusが`running`のコンテナがあり、稼働イメージ名をすべて取得できることが必要です。
各Podの`api/app`でイメージ名が1つにそろい、specの名前とも一致する必要があります。

稼働状態や候補の条件を1つでも満たさない場合は、そのマニフェストファイルを対象とするPRをすべて見送ります。

複数の対応付けが同じファイル内の同じ文書・同じコンテナを指す場合は、対応付けの重複として`mapping_conflict`になります。
KestreLynxは手動対応（`manual`、Slackでは「要判断」）にします。

名前空間を省略した文書に、異なる名前空間のワークロードを対応付けた場合も、編集前に重複を確認します。

そのマニフェストへの対応付けがあるコンテナから、同じイメージを更新する対象を決めます。
対応付けがないコンテナは、同じPodテンプレートで同じイメージを使っていても変更しません。

同じPodテンプレートの`app`と`log`が同じイメージを使う架空の例で、更新する範囲を示します。
`app`だけを対応付けた場合は、`app`だけを更新し、`log`は変更なしとしてPR本文に載せます。

設定は[ソースの対応付け](configuration.md#remediation-mappings)、ファイルの制約は[マニフェストの編集制約](remediation-source-formats.md#manifest-formats)を参照してください。

## KustomizeとHelmのvaluesのPR {#kustomize-and-helm-prs}

KustomizeとHelmのvaluesのPRは、タグの変更で影響を受けるコンテナをまとめて確認し、すべてで同じ候補を採用できる場合に作ります。
確認対象は、対応付けの`workload`と、ほかの影響を受けるコンテナを列挙する`affects`に書いたコンテナです。

次は、`workload`と`affects`の関係を示すKustomizeの対応付けです。
Helmでは、`helm_values.affects`に同じ2つのコンテナを列挙します。

```yaml
remediation:
  mappings:
    - workload: deployment/example/web/app
      repository: example/deployment
      base_branch: main
      kustomize:
        path: apps/kustomization.yaml
        image: nginx
        affects:
          - deployment/example/worker/app
          - deployment/example/web/prepare
```

ワークロードキー`deployment/example/web/app`は、名前空間`example`にあるDeployment`web`のコンテナ`app`を指します。
例の確認対象は`web/app`・`worker/app`・`web/prepare`で、`prepare`は`web`の通常のinit containerです。

列挙したコンテナすべてについて、次の条件を確認します。

- 各コンテナを観測したPodで確認でき、specのイメージ名と稼働イメージ名が一致する
- 列挙したコンテナ全体で、現在のイメージ名が1つにそろう
- すべての対象で、同じタグとdigestの候補を採用できる

通常のinit containerは、Podのstatusで使用したイメージを確認し、同じPod内の列挙済み稼働コンテナと照合します。
照合する名前と中身は、次のとおりです。

| 確認項目 | 一致が必要な内容 |
| --- | --- |
| イメージ名 | init containerのspec・statusと稼働コンテナのイメージ名 |
| イメージの中身 | init containerが使用したイメージと稼働コンテナのイメージの中身 |

名前と中身の一致を確認できた場合は、比較した稼働コンテナのスキャン結果をinit containerの確認に使います。

status、イメージの中身、イメージ名、または利用できるスキャン結果を確認できない場合は、PRを作りません。
理由は`init_container_unverified`などです。

タグの変更で影響を受けるコンテナを`workload`と`affects`にすべて列挙したことは、利用者が確認します。
KestreLynxは、その確認を前提に、観測した情報から列挙漏れも調べます。

未列挙のコンテナが、列挙したコンテナと同じイメージ名を宣言していないか調べます。
次の範囲で見つかると、列挙漏れとして`undeclared_affected_workload`でPR作成を停止します。

- 列挙したワークロードと名前空間・Helmリリース・Flux Kustomizationのいずれかを共有する稼働コンテナ
- 列挙したワークロードのPod定義にあるコンテナ（待機中のコンテナ・ネイティブsidecar・通常のinit containerを含む）

同じイメージ名を宣言する設定例で`worker/app`を列挙し忘れると、同じ名前空間`example`の稼働コンテナとして検出します。
`web/prepare`を列挙し忘れると、`web`のPod定義から検出します。

同じファイルの対応付けで稼働状態の確認に失敗すると、そのファイルを対象とするPRをすべて見送ります。
更新対象のコンテナが候補や列挙漏れの確認に通らない場合も、同じファイルのPRをすべて見送ります。

設定の詳細は[Kubernetesの対応付け](configuration.md#remediation-mappings-kubernetes)、設定例は[KustomizeのPR設定](remediation-setup-kubernetes.md#kustomize-pull-requests)と[HelmのvaluesのPR設定](remediation-setup-kubernetes.md#helm-values-pull-requests)を参照してください。

### KustomizeのPR {#kustomize-prs}

Kustomizeでは、`images`の指定した項目から得るイメージ名を照合し、`newTag`を更新できるかを決めます。
設定例では、`web/app`・`worker/app`・`web/prepare`の共通条件を満たすと、`images[nginx].newTag`を更新します。

`name`（既存の`newName`があれば`newName`）と`newTag`から得るイメージ名を使います。
Podのspecのイメージ名と稼働イメージ名のそれぞれに一致する必要があります。

KestreLynxはKustomizeを展開しません。
編集できるファイルの制約は[Kustomizeの編集制約](remediation-source-formats.md#kustomize-formats)を参照してください。

### HelmのvaluesのPR {#helm-values-prs}

Helmのvaluesでは、指定したキーの値から得るイメージ名を照合し、タグを更新できるかを決めます。
[HelmのvaluesのPR設定](remediation-setup-kubernetes.md#helm-values-pull-requests)の例では、`web/app`・`worker/app`・`web/prepare`の共通条件を満たすと、`image.tag`を更新します。

valuesの書き方に応じて、次のイメージ名をPodのspecのイメージ名と稼働イメージ名に照合します。

- `registry`と`repository`を合わせたリポジトリに、`tag`を加えたイメージ名
- 文字列で指定したイメージ名

KestreLynxはHelmを描画しません。
利用者は、指定したキーがほかの設定で上書きされず、キーの変更が実際のイメージ指定に反映されることを確認します。

例えば、ほかのvaluesファイルやCIの`--set`がタグを上書きしていると、指定したキーを変更しても実際のイメージ指定に反映されません。
KestreLynxは、次の上書きを確認しません。

- Flux HelmReleaseの`spec.values`
- Argo CDの`parameters`・`valuesObject`・`valuesFrom`
- CIの`--set`
- ほかのvaluesファイル

PR本文には、値の上書きがなく影響を受けるコンテナをすべて列挙したという前提と、KestreLynxが確認した範囲を載せます。
ほかのツールがタグを管理していないことは確認していない旨も載せます。

検出できるFluxの`$imagepolicy`コメントとArgo CD Image Updaterの書き戻しファイルは、[Helmのvaluesの編集制約](remediation-source-formats.md#helm-values-formats)に従って確認します。
