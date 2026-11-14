---
title: イメージを指定するファイルの対応形式
---

# イメージを指定するファイルの対応形式

Compose、Kubernetesマニフェスト、Kustomize、Helmのvalues、Dockerfileについて、イメージを自動更新できる書き方を確認できます。

確認するファイルに合わせて節を選んでください。

| ファイルの種類 | 参照先 |
| --- | --- |
| Composeファイル | [Composeの形式](#compose-formats) |
| Kubernetesマニフェスト | [マニフェストの形式](#manifest-formats) |
| `kustomization.yaml`など | [Kustomizeの形式](#kustomize-formats) |
| Helmのvaluesファイル | [Helmのvaluesの形式](#helm-values-formats) |
| Dockerfile | [Dockerfileの形式](#dockerfile-formats) |

理由コードの意味は[ソースの理由](remediation-image-reason-codes.md#source-reasons)、PRを見送る範囲は各節末尾の規則を参照してください。
このページで使う用語は[用語](remediation.md#terms)を参照してください。

## Composeの形式 {#compose-formats}

Composeでは、`services.<service>.image`に直接書かれたイメージ名のタグを編集します。
稼働イメージと、イメージのリポジトリ名とタグを照合します。

現在のファイルの記述と稼働イメージが一致するかを、次のように確認します。

| 現在の記述 | 一致の確認 |
| --- | --- |
| `services.<service>.image`の文字列 | 稼働イメージとリポジトリ名・タグが一致し、タグの位置を特定できる |
| `nginx:1.27.2`と`docker.io/library/nginx:1.27.2` | Docker Hubの省略表記を補って同じイメージ名として照合できる |
| `nginx:1.27.2`と`nginx:1.27.3` | タグが異なるため、同じ稼働イメージ名として照合できない |

更新先のタグは、現在の設定との一致確認とは別に選びます。
次は、同じ系列のパッチ更新として選べるタグの例です。

| 更新するタグ | 更新先としての扱い |
| --- | --- |
| 固定タグの`1.2.3`・`1.2.3-alpine` | 同じ系列の新しいパッチへ変更できる |
| `1.2.3-alpine`から`1.2.4-alpine`への変更 | 同じ系列のパッチ更新として扱う |
| `1.2.3-alpine`から`1.3.0-alpine`・`1.2.4-bookworm`への変更 | 同じ系列のパッチ更新としては扱わない |

自動編集を妨げる書き方は、次の理由で手動対応になります。

| 書き方 | 理由コード |
| --- | --- |
| 編集する`image`に`$`を含む値 | `compose_variable` |
| 編集するイメージ名のdigest指定 | `compose_digest` |
| 文書のルートに付けたYAMLのアンカー | `compose_anchor_or_alias` |
| `services`のマッピングのアンカー・エイリアス | `compose_anchor_or_alias` |
| 対象サービスのマッピングのアンカー・エイリアス | `compose_anchor_or_alias` |
| 編集する`image`の値のアンカー・エイリアス | `compose_anchor_or_alias` |
| 文書のルートにあるマージキー | `compose_merge_key` |
| `services`のマッピングにあるマージキー | `compose_merge_key` |
| 対象サービスのマッピングにあるマージキー | `compose_merge_key` |
| `image`のブロックスカラー | `compose_block_scalar` |
| 文字列以外の`image` | `compose_not_string` |
| 文書のルートにある`include` | `compose_include_or_extends` |
| 対象サービスの`extends` | `compose_include_or_extends` |

次は、対象サービス`web`のマッピングと`image`の値にアンカーを付けた例です。

```yaml
services:
  web: &service
    image: &image nginx:1.27.2
```

`&service`だけでも、`&image`だけでも、`compose_anchor_or_alias`で手動対応になります。

`latest`・`22-alpine`・`1.2`などの浮動タグは「再pull」の候補になり、同じタグのイメージ名を書き換えるPRは作りません。

`build:`でビルドしたイメージは、配布イメージの検索から除外します。
`build:`の値が空文字列・null・読み取れない値の場合は、ビルドするかを判定できず、`compose_build_undetermined`になります。

Dockerfileや依存ファイルの更新は、`build:`でビルドしたイメージのタグ更新とは別に扱います。

タグの選び方は[配布イメージのタグ](remediation-image-logic.md#published-image-tags)、ビルド対象の扱いは[ローカルビルドの除外](remediation-image-logic.md#local-builds)を参照してください。

## マニフェストの形式 {#manifest-formats}

マニフェストでは、対象オブジェクトのコンテナの`image`にあるタグだけを編集し、書式とコメントを保ちます。
照合するイメージ名の取得元と、一致が必要な項目を示します。

| 取得元 | 読み取る値 | 一致が必要な項目 |
| --- | --- | --- |
| クラスタ上のPodの宣言 | Podのspecにある対象コンテナの`image` | イメージのリポジトリ名とタグ |
| 実際に稼働中のイメージ | Podのstatusから取得した対象コンテナのイメージ名 | イメージのリポジトリ名とタグ |
| GitHub上のマニフェスト | 編集するコンテナの`image` | イメージのリポジトリ名とタグ |

編集する文書とコンテナは、次の条件で選びます。

| 確認する箇所 | 編集できる条件 |
| --- | --- |
| YAML文書 | プレーンなマニフェストで、1ファイルに複数の文書を含められる |
| `apps/v1`のオブジェクト | `Deployment`・`StatefulSet`・`DaemonSet`である |
| `batch/v1`のオブジェクト | `Job`・`CronJob`である |
| `v1`のオブジェクト | `Pod`である |
| `apiVersion`・`kind` | 対応付けたワークロードの種類に合う |
| `metadata.name` | `manifest.object.name`の指定値と一致し、省略時はワークロード名と一致する |
| 値がある`metadata.namespace` | 対応付けたワークロードの名前空間と一致する |
| 省略した`metadata.namespace` | 名前空間では絞り込まず、ほかの識別項目で文書を1つに絞れる |
| コンテナ名 | 対応付けたコンテナ名と一致する |
| コンテナの種類 | 通常のコンテナ、または`restartPolicy: Always`を持つネイティブsidecarである |
| 編集する`image` | 照合したイメージ名に明示的なタグがある |

手動対応になる書き方と、ファイルの確認条件を示します。

| 書き方 | 理由コード |
| --- | --- |
| ファイル内の重複キー（編集前後の全YAML文書を検査） | `manifest_invalid` |
| 編集するイメージ名のdigest指定 | `manifest_digest` |
| 編集する`image`に`$`を含む値 | `manifest_variable` |
| 編集するイメージ名のタグ省略 | `manifest_tag_missing` |
| `image`のブロックスカラー | `manifest_block_scalar` |
| 単純な文字列以外の`image` | `manifest_not_string` |
| 編集箇所への経路に関わるアンカー・エイリアス | `manifest_anchor_or_alias` |
| 文書の識別情報（`metadata`など）に関わるアンカー・エイリアス | `manifest_anchor_or_alias` |
| 編集箇所への経路にあるマージキー | `manifest_merge_key` |
| 文書の識別情報にあるマージキー | `manifest_merge_key` |
| 編集する`image`の行にあるFluxの`$imagepolicy`コメント | `manifest_image_automation` |
| ファイル内のどこかにある`{{` | `manifest_template` |
| 同じディレクトリにあるArgo CD Image Updaterの書き戻しファイル`.argocd-source-*.yaml` | `image_updater_file` |
| ファイルのイメージ名とPodのspecまたは稼働イメージ名の不一致 | `source_mismatch` |
| 同じ文書の同じコンテナを指す複数の対応付け（名前空間を省略した文書も含む） | `mapping_conflict` |

Fluxの`$imagepolicy`は、行末コメントに書くimage automationの目印です。
次のように編集対象行に`$imagepolicy`があると、手動対応になります。

```yaml
image: nginx:1.25.3 # {"$imagepolicy": "flux-system:web:tag"}
```

`List`内のオブジェクトと、通常のinit containerは編集対象外です。
PRの作成条件は[KubernetesのマニフェストPR](remediation-kubernetes-logic.md#kubernetes-manifest-prs)を参照してください。

## Kustomizeの形式 {#kustomize-formats}

Kustomizeでは、`kustomize.image`で名前を指定した`images`の項目の`newTag`だけを編集します。
`affects`はKestreLynxの`remediation.mappings[].kustomize.affects`で、タグの変更で影響を受けるコンテナのうち、`workload`に指定したコンテナ以外を列挙する設定です。

編集できる書き方と、ファイルから読み取るイメージ名の照合条件を示します。

| 確認する箇所 | 編集できる条件・範囲 |
| --- | --- |
| ファイル名 | `kustomization.yaml`・`kustomization.yml`・`Kustomization`を使う |
| YAML文書 | 1つの文書だけを含む |
| 対象項目 | `kustomize.image`と`images[].name`が一致する項目を1つに絞れる |
| `newTag` | 既存の文字列だけを書き換え、引用符・コメント・改行を保つ |
| `newName` | 既存の値を保つ |
| ファイルから読み取るイメージ名 | `name`または既存の`newName`と`newTag`から得るリポジトリ名・タグが、Podのspecと稼働イメージ名に一致する |

数値として解釈されるタグは引用符で囲みます。

値の検査は、すべての`images`項目の`name`・`newName`と、編集対象の`newTag`に行います。
次の書き方やファイルの状態では手動対応になります。

| 書き方 | 理由コード |
| --- | --- |
| `newTag`の未設定 | `kustomize_tag_not_set` |
| `newTag`の空文字列 | `kustomize_tag_not_set` |
| 読み取る値が文字列以外（数値など） | `kustomize_not_string` |
| 読み取る値に付けた明示的なYAMLタグ | `kustomize_not_string` |
| 読み取る値のブロックスカラー | `kustomize_block_scalar` |
| 読み取る値に含まれる`$` | `kustomize_variable` |
| 対象項目の`digest`フィールド | `kustomize_digest` |
| 対象のイメージ名に含まれるdigest | `kustomize_digest` |
| 文書のルートに関わるアンカー・エイリアス | `kustomize_anchor_or_alias` |
| `images`やその項目に関わるアンカー・エイリアス | `kustomize_anchor_or_alias` |
| 読み取る値に関わるアンカー・エイリアス | `kustomize_anchor_or_alias` |
| 文書のルートにあるマージキー | `kustomize_merge_key` |
| `images`の項目にあるマージキー | `kustomize_merge_key` |
| ファイル内のどこかにある`{{` | `kustomize_template` |
| `Newtag`など、既知のフィールド名と大小文字が異なる綴り | `kustomize_invalid` |
| 大小文字だけが異なる重複キー | `kustomize_invalid` |
| `imageTags`・`patches`・`replacements`・`components`・`helmCharts`・`helmGlobals`の使用 | `kustomize_unsupported_feature` |
| `generators`・`transformers`・`vars`・`patchesStrategicMerge`・`patchesJson6902`の使用 | `kustomize_unsupported_feature` |
| リモートの`resources` | `kustomize_unsupported_feature` |
| リモートの`bases` | `kustomize_unsupported_feature` |
| 別の項目の`name`が、編集対象の変更前・変更後のイメージ名に一致する記述 | `kustomize_image_chained` |
| 編集対象の`name`が、別の項目の変更前・変更後のイメージ名に一致する記述 | `kustomize_image_chained` |
| 正規表現として不正な`name`（対象以外の項目も検査） | `kustomize_invalid` |
| `newTag`の行にあるFluxの`$imagepolicy`コメント | `kustomize_image_automation` |
| 同じディレクトリにある`.argocd-source-*.yaml` | `image_updater_file` |
| 指定したファイルがない状態 | `manifest_file_not_found` |
| 編集できる種類のファイルではない状態 | `manifest_file_unusable` |
| ファイルのイメージ名とPodのspecまたは稼働イメージ名の不一致 | `source_mismatch` |

理由コードを特定せずに、利用者による変更に任せる範囲もあります。

| 変更する箇所 | 扱い |
| --- | --- |
| `newName`自体 | 手動対応 |

Kustomizeは`name`を正規表現として照合します。
次は、別の項目が同じイメージ名を変更するため拒否される書き方の例です。

```yaml
images:
  - {name: busybox, newName: nginx, newTag: "1.27.2"}
  - {name: nginx, newTag: "1.27.2"}
```

1番目の項目の`newTag`だけを`1.27.3`へ変える場合、各項目が指定するイメージ名は次のようになります。

| 項目 | 照合する`name` | 現在の指定で書き込むイメージ名 | 1番目の`newTag`更新後に書き込むイメージ名 |
| --- | --- | --- | --- |
| 1番目 | `busybox` | `nginx:1.27.2` | `nginx:1.27.3` |
| 2番目 | `nginx` | `nginx:1.27.2` | `nginx:1.27.2` |

1番目を編集対象にすると、変更後の`nginx:1.27.3`が2番目の`name: nginx`にも一致するため拒否されます。
2番目を編集対象にしても、1番目が書き込むイメージ名が2番目の`name: nginx`に一致するため、`kustomize_image_chained`になります。

`workload`と`affects`に書いたコンテナの確認条件、通常のinit containerの扱いは[KustomizeとHelmのvaluesのPR](remediation-kubernetes-logic.md#kustomize-and-helm-prs)、対応付けは[KustomizeのPR設定](remediation-setup-kubernetes.md#kustomize-pull-requests)を参照してください。

## Helmのvaluesの形式 {#helm-values-formats}

Helmのvaluesでは、`helm_values.key`で指定した値のタグ部分だけを編集します。
ファイルから読み取るレジストリを含むイメージのリポジトリ名とタグが、Podのspecと稼働イメージ名に一致する必要があります。

指定した値がほかのvaluesファイルや`--set`などで上書きされず、キーの変更が実際のイメージ指定に反映されることは、利用者が確認する必要があります。

YAMLのマッピングは、キーと値を並べた記述です。
次の`apps/values.yaml`では、`helm_values.key: image`を指定してマッピングを選び、`image.tag`は指定しません。

```yaml
image:
  registry: docker.io
  repository: library/nginx
  tag: "1.27.2"
```

編集できる書き方を示します。

| 確認する箇所 | 編集できる条件・範囲 |
| --- | --- |
| ファイル | `.yaml`・`.yml`のvaluesファイルを使う |
| YAML文書 | 重複キーのない1つの文書を含む |
| YAMLのマッピングで指定するイメージ | `repository`と文字列の`tag`を持ち、`registry`は省略できる |
| 文字列で指定するイメージ | `"repo:tag"`のように書く |
| `helm_values.key` | イメージを指定するマッピングまたは文字列への経路を指定する |
| タグの編集 | 既存の引用符とコメントを保つ |
| 引用符なしのタグを持つマッピング | 新しいタグが`1.10`・`on`などHelmで文字列にならない値なら、二重引用符を付ける |

引用符を追加した場合は、PR本文に記載します。

マッピングでは`repository`・`tag`と、指定がある場合の`registry`・`digest`の値を検査します。
文字列によるイメージ指定では、`helm_values.key`で選んだ文字列全体を検査します。

次の書き方やファイルの状態では手動対応になります。

| 書き方 | 理由コード |
| --- | --- |
| `helm_values.key`で指定した値がない記述 | `helm_key_missing` |
| マッピングの`tag`の未設定（チャートの既定値を使う） | `helm_tag_from_chart` |
| マッピングの`tag`の空文字列（チャートの既定値を使う） | `helm_tag_from_chart` |
| 文字列によるイメージ指定でのタグ省略（チャートの既定値を使う） | `helm_tag_from_chart` |
| 読み取る値が文字列以外（数値・真偽値・nullなど） | `helm_not_string` |
| 読み取る値に付けた明示的なYAMLタグ | `helm_not_string` |
| マッピングの既存の`tag`が、Helmで文字列にならない引用符なしの値 | `helm_not_string` |
| 読み取る値のブロックスカラー | `helm_block_scalar` |
| 読み取る値に含まれる`$` | `helm_variable` |
| 対象のマッピングにある非空の`digest` | `helm_digest` |
| 文字列で指定したイメージ名のdigest | `helm_digest` |
| タグを含む`repository` | `helm_values_shape` |
| digestを含む`repository` | `helm_values_shape` |
| `repository`と同じマッピングにある`name` | `helm_values_shape` |
| `repository`と同じマッピングにある`image` | `helm_values_shape` |
| 対象キーまでの経路に関わるアンカー・エイリアス | `helm_anchor_or_alias` |
| 読み取る値に関わるアンカー・エイリアス | `helm_anchor_or_alias` |
| 経路上のマッピングのキーに付けたアンカー | `helm_invalid` |
| 対象のマッピングのキーに付けたアンカー | `helm_invalid` |
| ファイル内のどこかのキーに使ったエイリアス | `helm_anchor_or_alias` |
| 文書のルートにあるマージキー | `helm_merge_key` |
| 対象キーまでの経路にあるマージキー | `helm_merge_key` |
| 対象のマッピングにあるマージキー | `helm_merge_key` |
| 経路上のマッピングにある、Helmで文字列にならない引用符なしのキー | `helm_invalid` |
| 対象のマッピングにある、Helmで文字列にならない引用符なしのキー | `helm_invalid` |
| 経路上のマッピングで同じキーに解釈される記述（`"true"`と`on`など） | `helm_invalid` |
| 対象のマッピングで同じキーに解釈される記述（`"true"`と`on`など） | `helm_invalid` |
| 複数のYAML文書 | `helm_invalid` |
| ファイル内のどこかにある重複キー | `helm_invalid` |
| 不正なYAML | `helm_invalid` |
| ファイル内のどこかにある`{{` | `helm_template` |
| `repository`・`registry`・`tag`の行にあるFluxの`$imagepolicy`コメント | `helm_image_automation` |
| 文字列で指定したイメージの行にあるFluxの`$imagepolicy`コメント | `helm_image_automation` |
| 同じディレクトリにある`.argocd-source-*.yaml` | `image_updater_file` |
| 指定したファイルがない状態 | `manifest_file_not_found` |
| 編集できる種類のファイルではない状態 | `manifest_file_unusable` |
| ファイルのイメージ名とPodのspecまたは稼働イメージ名の不一致 | `source_mismatch` |

タグの変更で影響を受けるコンテナの確認条件と通常のinit containerの扱いは[KustomizeとHelmのvaluesのPR](remediation-kubernetes-logic.md#kustomize-and-helm-prs)、値の上書きに関する前提は[HelmのvaluesのPR](remediation-kubernetes-logic.md#helm-values-prs)を参照してください。
`affects`を含む対応付けは[HelmのvaluesのPR設定](remediation-setup-kubernetes.md#helm-values-pull-requests)を参照してください。

## Dockerfileの形式 {#dockerfile-formats}

Dockerfileでは、選んだビルドステージが使う外部イメージをベースイメージとして特定し、その`FROM`の固定タグを編集します。
編集する`FROM`とDockerfileの場所を決められる書き方を示します。

| 確認する箇所 | 編集できる条件・範囲 |
| --- | --- |
| `FROM`の固定タグ | 変数やdigestを使わず、タグの位置を特定できる |
| ビルドの`target` | 指定した名前のステージを使う |
| `target`の省略 | 最後のステージを使う |
| 前のステージを指定する`FROM` | 外部のベースイメージを指定する`FROM`までたどれる |
| 外部イメージを指定する`FROM`の`--platform` | 静的な値を指定できる |
| Composeのbuild context | リポジトリ内の静的なパスを指定できる |
| Composeの`dockerfile` | build contextからの相対パス（`docker/Dockerfile`など）で、リポジトリ内のファイルを指定する |
| Composeの`target` | `runtime`など、英字で始まる128文字以内のステージ名を英数字・`_`・`.`・`-`で指定する |

Composeの`dockerfile`・`target`は、変数・明示的なYAMLタグ・エイリアスを使わない、空でない文字列で指定します。
値の前後の空白と制御文字も使えません。

`dockerfile`では、絶対パス、`~`で始まるパス、`\`を含むパス、リポジトリ外に出るパスを使えません。

自動更新できず、手動対応になる書き方を示します。

| 書き方 | 理由コード |
| --- | --- |
| 対象ステージからベースまでの`FROM`にあるイメージ名の変数 | `dockerfile_variable` |
| 対象ステージからベースまでの`FROM`にある`--platform`の変数 | `dockerfile_variable` |
| 前のステージ名を指定する`FROM`に付けた`--platform` | `dockerfile_stage_platform` |
| 標準以外の構文フロントエンド | `dockerfile_frontend` |
| `escape`ディレクティブ | `dockerfile_escape` |
| 継承元ステージの`ONBUILD` | `dockerfile_onbuild` |
| ベースイメージの`ONBUILD` | `base_onbuild` |

ComposeからDockerfileの編集先を特定するときには、次の指定を使えません。

| 書き方 | 理由コード |
| --- | --- |
| リモートのbuild context | `compose_build_remote_context` |
| `dockerfile_inline` | `compose_build_inline` |
| `additional_contexts` | `compose_build_additional` |

次のベース指定は、自動編集の対象外です。

| 書き方 | 理由コード |
| --- | --- |
| `FROM scratch` | `dockerfile_scratch` |
| digestを含む`FROM`のイメージ名 | `dockerfile_digest` |

浮動タグでは、現在のタグが指すベースと稼働イメージのレイヤーを照合し、結果に応じてベースを再取得して再ビルドする案内を出します。
浮動タグのタグ更新PRは作らず、確認内容と案内の条件は[ベースレイヤーの照合](remediation-base-image-logic.md#base-layer-matching)に従います。

次は、外部イメージを指定する`FROM`に静的な`--platform`を書く、編集可能な例です。

```dockerfile
FROM --platform=linux/amd64 python:3.12.3-slim AS base
FROM base AS app
```

次は、前のステージ`base`を指定する`FROM`に`--platform`を書く、手動対応になる例です。

```dockerfile
FROM python:3.12.3-slim AS base
FROM --platform=linux/amd64 base AS app
```

編集先の決め方と対応付けの照合は[ベースイメージの特定](remediation-base-image-logic.md#base-image-selection)を参照してください。
