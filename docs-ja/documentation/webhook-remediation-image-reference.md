---
title: Webhookの修正計画の配布イメージのフィールド
---

# Webhookの修正計画の配布イメージのフィールド

このページでは、汎用Webhookの修正計画に含まれる配布イメージの項目と、Kubernetesのワークロード情報を説明します。
修正計画全体の構造は[修正計画の全体像](webhook-remediation-reference.md#remediation-overview)を参照してください。

## 配布イメージのフィールド {#remediation-image-fields}

`remediation`の配布イメージに関するフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `summary` | object | [分類別の配布イメージの項目数](webhook-remediation-reference.md#remediation-summary-keys) | 計画がなければ省略 |
| `items` | objectの配列 | 配布イメージごとの修正計画 | `[]` |

`summary`は、`items[]`を`category`ごとに数えます。
計画があれば、`pull_again`・`pr_candidate`・`manual`・`not_comparable`・`deferred`・`no_candidate`・`excluded`・`failed`の8つのキーを含み、該当する項目がない分類も`0`を出力します。

`items[]`の1要素は、稼働中のイメージ名と内容の識別情報が同じイメージをまとめた修正計画です。
同じイメージを使う複数のコンテナやワークロードは、1項目の`services[]`にまとめます。

内容の識別には、config digestが分かる場合はそのdigestを使い、それ以外ではレジストリのdigestとプラットフォームを使います。
同じイメージ名でも内容の識別情報が違えば別項目になり、同じ内容でもイメージ名が違えば別項目になります。

次の例は、同じタグの内容を再取得する候補がある1項目から、主要なフィールドを抜粋したものです。

```json
{
  "key": "web:latest|config:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "category": "pull_again",
  "reason": "adopted",
  "tag_kind": "floating",
  "priority": "act_now",
  "services": [
    {
      "project": "shop",
      "service": "web",
      "container": "shop-web-1"
    }
  ],
  "current": {
    "ref": "web:latest",
    "tag": "latest",
    "content": "config:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "digest_kind_unverified": true
  },
  "candidate": {
    "ref": "web:latest",
    "tag": "latest",
    "config_digest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    "manifest_digest": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
    "top_digest": "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
  },
  "targets": 4,
  "kev_targets": 3
}
```

`items[]`の1要素のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `key` | string | 稼働中のイメージ名と内容の識別情報を連結した項目の識別子 | — |
| `category` | string | [計画の分類値](remediation-reference.md#category-values) | — |
| `reason` | string | 分類や処理結果を説明する[理由コード](remediation-reference.md#reason-codes) | 省略 |
| `detail` | string | 理由を補う説明文 | 省略 |
| `tag_kind` | string | 現在のイメージ名に対するタグの分類 | 分類していなければ省略 |
| `priority` | string | 比較対象の所見のうち最も高い[優先度](webhook-reference.md#priority-values) | 情報がなければ省略 |
| `services` | objectの配列 | このイメージを使う[サービスの情報](webhook-remediation-reference.md#remediation-services) | 省略 |
| `declared` | objectの配列 | KubernetesのPodに宣言された[イメージ名と取得方針](#remediation-image-declared) | 省略 |
| `pull` | objectの配列 | Kubernetesの取得方針ごとの[再取得の案内](#remediation-image-pull) | 省略 |
| `management` | objectの配列 | Kubernetesのワークロードごとの[管理元のつながり](#remediation-image-management) | 省略 |
| `current` | object | 現在の[イメージ情報](webhook-remediation-reference.md#remediation-image-state) | — |
| `candidate` | object | 候補の[イメージ情報](webhook-remediation-reference.md#remediation-image-state) | 候補がなければ省略 |
| `targets` | integer | 比較対象の所見数 | `0` |
| `kev_targets` | integer | 比較対象のうちCISA KEVに掲載された所見数 | 0件なら省略 |
| `comparison` | object | 現在のイメージと候補の[比較結果](webhook-remediation-reference.md#remediation-comparison) | 結果がなければ省略 |
| `scans` | objectの配列 | 比較元と候補の[スキャンの記録](webhook-remediation-reference.md#remediation-scan-records) | 記録がなければ省略 |
| `newer_series` | object | [新しい系列の確認結果](webhook-remediation-reference.md#remediation-newer-series) | 結果がなければ省略 |

次のフィールドには補足があります。

- `key`
    - 形式は`<イメージ名>|<内容識別値>`
    - 内容識別値は`config:sha256:<値>`、または`registry:sha256:<値>@<OS>/<アーキテクチャ>`の形式
    - 内容を識別できない場合は`<イメージ名>|unconfirmed`となり、同じイメージ名で内容不明のコンテナをまとめる
    - プラットフォームのvariantは含まれないため、variantだけが違う項目を`key`で区別することはできない
- `targets`・`kev_targets`
    - 脆弱性IDと、パッケージの分類・エコシステム・名前の組み合わせごとに1件と数える
    - 同じ組み合わせが複数の版や場所で検出されても1件と数える
    - 対象は修正状態が`fixed`で修正版情報がある所見で、候補を調べる前に決まり、候補で解消した件数とは異なる

`tag_kind`の値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `pinned` | `1.25.3`や`v2.4.1-bookworm`のように完全な版を指定する固定タグ |
| `floating` | `latest`・`16`・`1.25`・`16-alpine`などの浮動タグ |
| `excluded` | digestによる固定、プレリリース、対応していない形式など、候補探索の対象外となるイメージ名 |

候補の選び方は[配布イメージのタグ](remediation-logic.md#published-image-tags)、対象外となる理由は[イメージ候補の理由](remediation-reference.md#image-reasons)を参照してください。

## Kubernetesのワークロードの情報 {#remediation-image-kubernetes}

`declared`・`pull`・`management`は、Kubernetesのワークロードについて情報がある場合に含めます。
各フィールドで使うワークロードキーの形式は、[イメージ名の更新](webhook-diff-reference.md#reference-change-fields)を参照してください。

### 宣言されたイメージと取得方針 {#remediation-image-declared}

`items[].declared[]`の1要素は、ワークロードキー、Podのspecのイメージ名、取得方針の組み合わせを表します。
同じ組み合わせは1つにまとめ、同じワークロードでもイメージ名や取得方針が違えば別の要素にします。

`items[].declared[]`の1要素のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `workload` | string | 対象のワークロードキー | — |
| `ref` | string | Podのspecにあるイメージ名 | 読み取れなければ省略 |
| `pull_policy` | string | Podのspecにある`imagePullPolicy` | 未指定なら省略 |

`pull_policy`の値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `Always` | コンテナの起動時にレジストリへイメージを確認する方針 |
| `IfNotPresent` | ノードにイメージがなければ取得する方針 |
| `Never` | イメージを取得せず、ノードにあるものを使う方針 |

次のフィールドには補足があります。

- `ref`
    - 稼働中のイメージ名と一致しない宣言や、読み取れなかった宣言も残す
- `workload`
    - `declared[]`には、この項目に属するコンテナの宣言を含む
    - 同じ稼働中のイメージ名でも内容が異なるコンテナについて、宣言されたイメージ名が一致しない場合や読み取れない場合は、その宣言も追加する
    - 追加された宣言には、この項目の`services[]`にないワークロードキーが入ることがある
- `pull_policy`
    - 未指定時の既定値は補わず、実際の取得方針に基づく案内は`pull[]`に出力する

宣言と稼働中のイメージ名の照合は、[Kubernetesのイメージ名と再取得](remediation-logic.md#kubernetes-image-references)を参照してください。

### 再取得の案内 {#remediation-image-pull}

`items[].pull[]`は、`category`が`pull_again`の場合に付く、取得方針ごとの案内です。
同じ取得方針のワークロードキーを重複なくまとめ、並べ替えて出力します。

`items[].pull[]`の1要素のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `guidance` | string | 新しいイメージの内容を使うための対応 | — |
| `policy` | string | specの指定または未指定時の既定値に基づく取得方針 | — |
| `workloads` | stringの配列 | この案内の対象となるワークロードキー | `null` |

`guidance`の値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `restart_pulls` | Podを再起動すると新しい内容を取得する |
| `change_tag_or_digest` | 固定タグまたはdigestへの変更が必要 |
| `import_to_node` | ノードへのイメージの取り込みが必要 |

`policy`の値は、[宣言された取得方針](#remediation-image-declared)と同じ`Always`・`IfNotPresent`・`Never`です。
それぞれ、`restart_pulls`・`change_tag_or_digest`・`import_to_node`に対応します。

次のフィールドには補足があります。

- `policy`
    - specに指定がなければ、タグが`latest`またはタグの指定がない場合は`Always`、それ以外は`IfNotPresent`として案内する
    - 取得方針を読み取れない宣言は案内の対象に含めない
- `workloads`
    - 通常の計画作成では、対象が1つ以上ある取得方針だけを出力する
    - 値がない記録を出力する場合は、キーを省略せず`null`となる

再取得の条件は、[Kubernetesのイメージ名と再取得](remediation-logic.md#kubernetes-image-references)を参照してください。

### 管理元のつながり {#remediation-image-management}

`items[].management[]`は、ワークロードごとに確認できた管理元のつながりを表します。
ここでいう管理元は、ワークロードの作成・更新に関わるKubernetesのリソースや、ラベル・アノテーションで管理元として示されたHelm・Argo CD・Fluxなどのツールです。

同じワークロードキーでも、Podごとに確認できたつながりが異なる場合は複数の要素が入ります。

Deployment `web`に、Helmリリース`my-release`とArgo CD Application `myapp`の管理元の情報が付いている場合の例です。
これは`management[]`の1要素です。

`chains`の外側の配列には経路が1つあり、その内側の配列にワークロードに近い順で3つの管理元が並びます。
経路が1つなので、`conflicting`は省略されます。

```json
{
  "workload": "deployment/default/web/web",
  "chains": [
    [
      {
        "kind": "kubernetes",
        "resource": "deployment",
        "name": "web",
        "scope": "default"
      },
      {
        "kind": "helm",
        "name": "my-release",
        "scope": "default",
        "confidence": "claimed"
      },
      {
        "kind": "argocd",
        "name": "myapp",
        "confidence": "claimed"
      }
    ]
  ]
}
```

`items[].management[]`の1要素のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `workload` | string | 対象のワークロードキー | — |
| `chains` | objectの二重配列 | [管理元](#remediation-image-chain-owner)をワークロードに近い順に並べた経路の一覧 | `null` |
| `conflicting` | boolean | この要素に複数の管理元の経路があるかどうか | `false`なら省略 |

次のフィールドには補足があります。

- `chains`
    - 上の例では、`chains[0]`が1つの経路で、`chains[0][0]`・`chains[0][1]`・`chains[0][2]`がその経路上の管理元を表す
    - 内側の配列は、Kubernetesのリソース、Helmリリース、Argo CD Applicationなど、ワークロードに近い管理元から順に並ぶ
    - 外側に複数の経路があっても、先頭の経路が優先されるという意味はない
    - 通常の収集では経路を確認できたワークロードだけを含め、経路のない記録を出力する場合は`null`となる
- `conflicting`
    - 外側の配列に複数の経路がある場合に`true`となる
    - 1つの経路に複数の管理元が連なるだけでは`true`にならない

### 経路上の管理元 {#remediation-image-chain-owner}

`items[].management[].chains[][]`は、`chains`の内側の配列の1要素で、経路上の管理元1つを表します。
上の例では、`kind`が`kubernetes`・`helm`・`argocd`の3つのオブジェクトがこれに当たります。

`items[].management[].chains[][]`の1要素のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `kind` | string | 管理元となるツールまたはリソースの区分 | `""` |
| `resource` | string | Kubernetesのリソースの種類 | 省略 |
| `resource_id` | string | `kind`と`resource`だけでは区別できないリソースの種類を表す識別子 | 省略 |
| `name` | string | リソース、リリース、Applicationなどの名前 | 省略 |
| `scope` | string | 管理元が属するnamespace | 省略 |
| `confidence` | string | 管理元の情報をどの程度確認できているかを示す値 | 省略 |

`kind`の値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `kubernetes` | Kubernetesのリソース |
| `helm` | Helmリリース |
| `argocd` | Argo CD Application |
| `flux` | FluxのKustomizationまたはHelmRelease |
| `compose` | Docker Composeプロジェクト |
| `kustomize` | Kustomizeのオーバーレイ |
| `""` | 管理元が不明 |

現在のKubernetesの収集で出力する`kind`は、`kubernetes`・`helm`・`argocd`・`flux`です。
通常のKustomizeの適用では管理元を識別するラベルやアノテーションが残らないため、`kustomize`は出力しません。

`resource`の値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `deployment` | Deployment |
| `statefulset` | StatefulSet |
| `daemonset` | DaemonSet |
| `cronjob` | CronJob |
| `job` | Job |
| `replicaset` | ReplicaSet |
| `pod` | 管理するコントローラーがないPod |
| `other` | 列挙された種類以外のKubernetesリソース |

`resource`は`kind`が`kubernetes`の場合に使います。
現在のKubernetesの収集では、`replicaset`と`other`は出力しません。

`confidence`の値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `claimed` | ラベルやアノテーションなどが示す管理元で、管理関係そのものは検証していない |
| `asserted` | 利用者が明示した情報で、ツールによる検証はしていない |
| `attested` | 署名を検証した来歴情報に基づく情報 |

現在のKubernetesの収集では、Helm・Argo CD・Fluxの管理元に`claimed`を出力し、Kubernetesリソースの`confidence`は省略します。
この収集では`asserted`と`attested`は出力しません。

次のフィールドには補足があります。

- `resource_id`
    - FluxのKustomizationは`kustomizations.kustomize.toolkit.fluxcd.io`
    - FluxのHelmReleaseは`helmreleases.helm.toolkit.fluxcd.io`
    - `kind`が`kubernetes`で`resource`が`other`の場合は、リソースの種類とAPIグループを表す`<kind>.<group>`形式
    - リソースの個体を識別するUIDではないため、管理元を区別するときは`kind`・`resource`・`scope`・`name`と組み合わせる
- `scope`
    - 固定の分類値ではなく、Kubernetesリソース、Helmリリース、Fluxリソースが属するnamespaceの名前
    - ワークロードのnamespaceと管理元のnamespaceが異なる場合は、管理元のnamespaceが入る
    - Argo CD Applicationのnamespaceは収集していないため省略する
- `confidence`
    - `claimed`は、管理ツールがリソースに付けたラベルやアノテーションから読み取った情報であることを示す
    - 省略されていても、署名や管理関係を検証済みという意味にはならない
