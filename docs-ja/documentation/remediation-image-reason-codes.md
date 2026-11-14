---
title: イメージとソースの理由コード
---

# イメージとソースの理由コード

イメージ候補の比較・採用と、ソースの取得・編集で使う理由コードを調べるページです。
結果の値と理由の分類は[結果の値](remediation-reason-codes.md#result-values)と[理由コード](remediation-reason-codes.md#reason-codes)を参照してください。

KEVは、悪用が確認された脆弱性を収録するCISAのKnown Exploited Vulnerabilities一覧です。

調べる対象や処理に合わせて、小節を選んでください。

| 参照先 |
| --- |
| [比較の条件](#image-comparison-reasons) |
| [タグと候補の判定](#image-candidate-reasons) |
| [上限と取得の失敗](#image-retrieval-reasons) |
| [イメージ名の指定](#image-reference-reasons) |
| [ベースイメージ](#image-base-reasons) |
| [複数のコンテナをまとめた確認](#image-container-reasons) |
| [Dockerfile](#source-dockerfile-reasons) |
| [Compose](#source-compose-reasons) |
| [Kubernetesマニフェスト](#source-kubernetes-reasons) |
| [Kustomize](#source-kustomize-reasons) |
| [Helmのvalues](#source-helm-reasons) |
| [依存ファイル](#source-dependency-reasons) |
| [パッケージ](#source-package-reasons) |
| [ソースの取得](#source-retrieval-reasons) |

Kustomize・Helmのvaluesでも使うファイル取得・イメージ名照合のコードは[Kubernetesマニフェスト](#source-kubernetes-reasons)、通常のinit containerの確認は[Kustomize](#source-kustomize-reasons)にも掲載しています。

このページで使う用語は[用語](remediation.md#terms)を参照してください。

## イメージ候補の理由 {#image-reasons}

イメージ候補の理由は、スキャンを比較できるか、候補を計画に採用できるかを表します。

### 比較の条件 {#image-comparison-reasons}

比較元と候補のスキャンに必要な情報や、比較できない原因を示します。

| コード | 意味 | 詳しい説明 |
| --- | --- | --- |
| `scan_failed` | スキャンに失敗した | [比較条件](remediation-logic.md#comparison-conditions) |
| `entity_unverified` | 稼働イメージを確認できない、またはレジストリの内容と比較できない | [比較条件](remediation-logic.md#comparison-conditions) |
| `conditions_unknown` | 比較元または候補のスキャンで、Trivy・データベース・深刻度・解析設定などの条件が分からない | [比較条件](remediation-logic.md#comparison-conditions) |
| `conditions_differ` | 比較元と候補のスキャンで、Trivy・データベース・深刻度・解析設定などの条件が一致しない | [比較条件](remediation-logic.md#comparison-conditions) |
| `platform_unknown` | イメージのOSまたはCPUアーキテクチャが分からない | [比較条件](remediation-logic.md#comparison-conditions) |
| `platform_differ` | 比較するイメージのOSまたはCPUアーキテクチャが異なる | [比較条件](remediation-logic.md#comparison-conditions) |
| `variant_unsupported` | イメージのプラットフォームに、ARMの`v7`などの`variant`が指定されている | [比較条件](remediation-logic.md#comparison-conditions) |
| `packages_missing` | スキャン結果にパッケージ一覧がない | [比較条件](remediation-logic.md#comparison-conditions) |
| `packages_truncated` | スキャン結果のパッケージ一覧が途中で切れている | [比較条件](remediation-logic.md#comparison-conditions) |
| `unknown_package_type` | 比較元や候補の所見、または候補のパッケージ一覧に、サポートしていない種類のパッケージがある | [比較条件](remediation-logic.md#comparison-conditions) |
| `type_not_analysed` | 候補のスキャンが対象の種類のパッケージを解析していない | [比較条件](remediation-logic.md#comparison-conditions) |
| `targets_not_detected_on_baseline` | 当初のスキャンから選んだ修正対象の所見が、比較用の稼働イメージまたは現在のベースイメージのスキャンでは検出されなかった | [比較条件](remediation-logic.md#comparison-conditions) |
| `analysis_incomplete` | イメージの解析が不完全だった | [比較条件](remediation-logic.md#comparison-conditions) |

比較元には、候補と同じ条件を満たす当初のスキャンを使う場合と、比較のために再スキャンする場合があります。

### タグと候補の判定 {#image-candidate-reasons}

タグを調べた結果と、候補による所見の変化を示します。

| コード | 意味 | 詳しい説明 |
| --- | --- | --- |
| `no_newer_tag` | より新しいタグがない | [配布イメージのタグ](remediation-image-logic.md#published-image-tags) |
| `same_content` | 新しいタグも内容が同じである | [配布イメージのタグ](remediation-image-logic.md#published-image-tags) |
| `candidate_does_not_resolve_targets` | 候補では対象の所見が解消しない | [比較条件](remediation-logic.md#comparison-conditions) |
| `locally_built` | ホストでビルドしたイメージのため、配布イメージの検索対象ではない | [ローカルビルドの除外](remediation-image-logic.md#local-builds) |
| `partial_improvement` | 候補では一部の所見だけが解消する | [比較条件](remediation-logic.md#comparison-conditions) |
| `introduced_findings` | 候補で新たな所見が入る | [比較条件](remediation-logic.md#comparison-conditions) |
| `introduced_kev` | 候補でKEV掲載の脆弱性が新たに入る | [比較条件](remediation-logic.md#comparison-conditions) |
| `adopted` | スキャン比較の判定を通り、候補を修正計画に採用した | [比較条件](remediation-logic.md#comparison-conditions) |

候補の採用だけでは、ファイルの更新やPR作成の完了を表しません。

### 上限と取得の失敗 {#image-retrieval-reasons}

レジストリからの取得や、候補の確認を止めた原因を示します。

| コード | 意味 | 詳しい説明 |
| --- | --- | --- |
| `auth_required` | レジストリへのログインが必要である | [非公開イメージの認証](remediation-setup.md#configure-registry-auth) |
| `platform_not_found` | 候補に稼働イメージと同じプラットフォームのイメージがない | [比較条件](remediation-logic.md#comparison-conditions) |
| `platform_ambiguous` | 候補にプラットフォームが合うイメージが複数ある | [比較条件](remediation-logic.md#comparison-conditions) |
| `platform_mismatch` | 候補のプラットフォームが稼働イメージと異なる | [比較条件](remediation-logic.md#comparison-conditions) |
| `registry_error` | レジストリがエラーを返した | [計画が出ない場合](remediation-troubleshooting.md#check-missing-plan) |
| `tag_listing_incomplete` | タグ一覧を最後まで取得できなかった | [タグ一覧の探索](remediation-image-logic.md#tag-discovery) |
| `newer_series_tag_list_incomplete` | 新しい系列を選ぶためのタグ一覧全体を最後まで取得できなかった | [新しい系列の確認](remediation-image-logic.md#newer-series-check) |
| `newer_series_reserved` | PR処理の時間とレジストリへの要求数を残すため、新しい系列の確認を止めた | [新しい系列の確認](remediation-image-logic.md#newer-series-check) |
| `candidate_scan_limit` | 1サイクルでスキャンできる候補数の上限に達した | [計画が出ない場合](remediation-troubleshooting.md#check-missing-plan) |
| `baseline_rescan_limit` | 比較元イメージを再スキャンできる数の上限に達した | [計画が出ない場合](remediation-troubleshooting.md#check-missing-plan) |
| `tag_page_limit` | タグ一覧の取得回数の上限に達した | [タグ一覧の探索](remediation-image-logic.md#tag-discovery) |
| `registry_budget_exhausted` | レジストリへの要求数の上限に達した | [タグ一覧の探索](remediation-image-logic.md#tag-discovery) |
| `rate_limited` | レジストリ、または計画を作るときのGitHubへのアクセスで、レート制限に掛かった | [計画が出ない場合](remediation-troubleshooting.md#check-missing-plan) |
| `cycle_deadline` | サイクルの実行時間の上限に達した | [計画が出ない場合](remediation-troubleshooting.md#check-missing-plan) |
| `registry_timeout` | レジストリへの要求がタイムアウトした | [計画が出ない場合](remediation-troubleshooting.md#check-missing-plan) |

### イメージ名の指定 {#image-reference-reasons}

候補を探せないイメージ名やタグの指定を示します。

| コード | 意味 | 詳しい説明 |
| --- | --- | --- |
| `digest_only` | タグがなくdigestだけで指定されている | [配布イメージのタグ](remediation-image-logic.md#published-image-tags) |
| `tag_and_digest` | タグとdigestの両方で指定されている | [配布イメージのタグ](remediation-image-logic.md#published-image-tags) |
| `prerelease` | タグがプレリリース版の書き方である | [配布イメージのタグ](remediation-image-logic.md#published-image-tags) |
| `bare_digest` | digestだけで指定されたイメージ名で、リポジトリが分からない | [配布イメージのタグ](remediation-image-logic.md#published-image-tags) |
| `unparsable` | イメージ名を解釈できない | [配布イメージのタグ](remediation-image-logic.md#published-image-tags) |
| `unsupported_tag_format` | サポートしていない書き方のタグである | [配布イメージのタグ](remediation-image-logic.md#published-image-tags) |

### ベースイメージ {#image-base-reasons}

Dockerfileのベースイメージと、稼働イメージのレイヤーを照合した結果を示します。

| コード | 意味 | 詳しい説明 |
| --- | --- | --- |
| `base_layers_mismatch` | タグが指すベースイメージのレイヤーが、稼働イメージの先頭部分と一致しない | [ベースレイヤーの照合](remediation-base-image-logic.md#base-layer-matching) |
| `base_update_not_deployed` | ベースイメージ更新のPRはマージ済みだが、稼働イメージはPR作成時のままである | [ベースレイヤーの照合](remediation-base-image-logic.md#base-layer-matching) |
| `base_layers_unusable` | 稼働イメージとベースイメージのレイヤーを比較できない | [ベースレイヤーの照合](remediation-base-image-logic.md#base-layer-matching) |
| `base_onbuild` | ベースイメージに`ONBUILD`トリガーがある | [ベースイメージの特定](remediation-base-image-logic.md#base-image-selection) |
| `no_base_derived_findings` | 修正可能な所見が、ベースイメージのレイヤーにない | [ベースレイヤーの照合](remediation-base-image-logic.md#base-layer-matching) |
| `base_unchanged` | タグが指す現在のベースイメージのレイヤーが稼働イメージの先頭と一致し、ベースイメージの更新を確認できない | [ベースレイヤーの照合](remediation-base-image-logic.md#base-layer-matching) |
| `floating_base_unconfirmed` | 浮動タグの`FROM`が現在指すベースイメージのレイヤーが、稼働イメージの先頭のレイヤーと一致しない | [ベースレイヤーの照合](remediation-base-image-logic.md#base-layer-matching) |

### 複数のコンテナをまとめた確認 {#image-container-reasons}

同じファイルやイメージを使うコンテナについて、候補を共通して採用できるかを示します。
Kubernetesの宣言との照合では、稼働中のイメージ名が同じコンテナをまとめて確認します。

| コード | 意味 | 詳しい説明 |
| --- | --- | --- |
| `declared_ref_mismatch` | 確認対象のいずれかでPodのspecのイメージ名と稼働中のイメージ名が一致せず、まとめた項目が`not_comparable`になる | [Kubernetesのイメージ名と再取得](remediation-kubernetes-logic.md#kubernetes-image-references) |
| `declared_ref_unavailable` | 確認対象のいずれかでPodのspecのイメージ名を読み取れず、まとめた項目が`not_comparable`になる | [Kubernetesのイメージ名と再取得](remediation-kubernetes-logic.md#kubernetes-image-references) |
| `dockerfile_set_not_adopted` | 同じDockerfileを使う全ワークロードで共通して採用できる候補がなかった | [ベースイメージの特定](remediation-base-image-logic.md#base-image-selection) |
| `compose_set_not_adopted` | 同じイメージを使う全サービスで共通して採用できる候補がなかった | [PRを作れない場合](remediation-troubleshooting.md#check-missing-pr) |
| `instances_missing` | 対応付けたコンテナに、稼働インスタンスがない、稼働イメージ名を取得できない、または計画項目がないインスタンスがある | [KubernetesのマニフェストPR](remediation-kubernetes-logic.md#kubernetes-manifest-prs) |
| `mixed_references` | 稼働インスタンスの間で、宣言したイメージ名または稼働中のイメージ名が一致しない | [KubernetesのマニフェストPR](remediation-kubernetes-logic.md#kubernetes-manifest-prs) |
| `kubernetes_set_not_adopted` | 同じファイルで同じイメージを更新するコンテナの間で、採用した候補が一致しない | [KubernetesのマニフェストPR](remediation-kubernetes-logic.md#kubernetes-manifest-prs) |

DockerfileやComposeで候補を共通して採用できない場合は、個々のワークロードやサービスの理由も確認してください。

## ソースの理由 {#source-reasons}

ソースの理由は、更新するファイルを取得・解釈できるか、稼働イメージと照合できるかを表します。

### Dockerfile {#source-dockerfile-reasons}

Dockerfileの読み取り、ベースイメージの特定、編集の可否を示します。

| コード | 意味 | 詳しい説明 |
| --- | --- | --- |
| `dockerfile_file_not_found` | 設定したパスにDockerfileがない | [計画が出ない場合](remediation-troubleshooting.md#check-missing-plan) |
| `dockerfile_file_unusable` | Dockerfileが通常のファイルではない、Git LFSポインターである、またはPR処理で読むサイズの上限を超えている | [計画が出ない場合](remediation-troubleshooting.md#check-missing-plan) |
| `dockerfile_invalid` | Dockerfileを解釈できない、または編集の検証に失敗した | — |
| `dockerfile_target_missing` | 指定したビルドステージがない | [ベースイメージの特定](remediation-base-image-logic.md#base-image-selection) |
| `dockerfile_stage_cycle` | ステージの参照をたどっても外部イメージに行き着かない | [ベースイメージの特定](remediation-base-image-logic.md#base-image-selection) |
| `dockerfile_variable` | ベースイメージまたはプラットフォームに変数が含まれる | — |
| `dockerfile_scratch` | ベースイメージが`scratch`である | — |
| `dockerfile_digest` | ベースイメージがdigestで指定されている | — |
| `dockerfile_tag_unsupported` | ベースイメージのタグが候補を探せない書き方である | [配布イメージのタグ](remediation-image-logic.md#published-image-tags) |
| `dockerfile_frontend` | 標準以外の構文フロントエンドを指定している | — |
| `dockerfile_escape` | `escape`ディレクティブを設定している | — |
| `dockerfile_ambiguous_range` | ファイル内でタグの位置を正確に特定できない | — |
| `dockerfile_onbuild` | 継承元のステージに`ONBUILD`がある | — |
| `dockerfile_stage_platform` | 継承途中の`FROM`に`--platform`がある | — |
| `dockerfile_not_editable` | ベースイメージが固定タグではない | [ベースイメージの特定](remediation-base-image-logic.md#base-image-selection) |
| `dockerfile_source_mismatch` | Dockerfileから読んだベースイメージやステージが、修正計画で比較した内容と一致しない | [ベースイメージの特定](remediation-base-image-logic.md#base-image-selection) |
| `dockerfile_mapping_differs` | 設定したDockerfileとComposeが指すDockerfileが一致しない | [ベースイメージの特定](remediation-base-image-logic.md#base-image-selection) |

### Compose {#source-compose-reasons}

Composeのビルド設定と、`image`の編集を妨げる条件を示します。

| コード | 意味 | 詳しい説明 |
| --- | --- | --- |
| `compose_no_build` | 対象サービスに`build`の指定がない | [ベースイメージの特定](remediation-base-image-logic.md#base-image-selection) |
| `compose_build_remote_context` | build contextがURLまたはリポジトリである | — |
| `compose_build_inline` | `dockerfile_inline`を使っている | — |
| `compose_build_additional` | `additional_contexts`を使っている | — |
| `compose_build_path` | ビルドのパスが絶対パス、リポジトリ外、または不正な書き方である | — |
| `compose_build_unsupported_form` | `build`の書き方をサポートしていない | — |
| `compose_build_undetermined` | サービスのビルド方法を判断できない | [ローカルビルドの除外](remediation-image-logic.md#local-builds) |
| `compose_invalid` | Composeファイルを解釈できない、または編集の検証に失敗した | — |
| `compose_service_missing` | Composeファイルに対象サービスまたは`image`キーがない | — |
| `compose_build` | サービスがイメージをビルドしている | [ローカルビルドの除外](remediation-image-logic.md#local-builds) |
| `compose_include_or_extends` | Composeファイルのトップレベルに`include`がある、または対象サービスが`extends`を使っている | [Composeの書き方](remediation-source-formats.md#compose-formats) |
| `compose_merge_key` | `image`への経路にマージキーがある | — |
| `compose_anchor_or_alias` | `image`がYAMLのアンカーまたはエイリアスに関わっている | — |
| `compose_not_string` | `image`の値が単純な文字列ではない | — |
| `compose_block_scalar` | `image`の値がブロックスカラーである | — |
| `compose_variable` | `image`の値に変数が含まれる | — |
| `compose_digest` | `image`の値にdigestが付いている | — |
| `compose_source_mismatch` | ファイルの`image`が稼働イメージと異なる | [ソースの確認](remediation-logic.md#source-verification) |
| `compose_file_not_found` | 設定したパスにComposeファイルがない | [計画が出ない場合](remediation-troubleshooting.md#check-missing-plan) |
| `compose_file_unusable` | Composeファイルが通常のファイルではない、Git LFSポインターである、または読み取りサイズの上限を超えている | [計画が出ない場合](remediation-troubleshooting.md#check-missing-plan) |

### Kubernetesマニフェスト {#source-kubernetes-reasons}

マニフェスト内のワークロードやコンテナを特定し、イメージ名を編集できるかを示します。

| コード | 意味 | 詳しい説明 |
| --- | --- | --- |
| `manifest_file_not_found` | 設定したパスにKubernetesマニフェスト、Kustomizeのファイル、またはHelmのvaluesファイルがない | [マニフェストの書き方](remediation-source-formats.md#manifest-formats) |
| `manifest_file_unusable` | Kubernetesマニフェスト・Kustomize・Helmのvaluesの対象ファイルが通常のファイルではない、Git LFSポインターである、または読み取りサイズの上限を超えている | [マニフェストの書き方](remediation-source-formats.md#manifest-formats) |
| `manifest_invalid` | マニフェストを解釈できない、キーが重複している、または編集の検証に失敗した | [マニフェストの書き方](remediation-source-formats.md#manifest-formats) |
| `manifest_anchor_or_alias` | コンテナへの経路または文書の識別情報がYAMLのアンカー・エイリアスに関わっている | [マニフェストの書き方](remediation-source-formats.md#manifest-formats) |
| `manifest_merge_key` | コンテナへの経路または文書の識別情報にマージキーがある | [マニフェストの書き方](remediation-source-formats.md#manifest-formats) |
| `manifest_not_string` | `image`の値が単純な文字列ではない | [マニフェストの書き方](remediation-source-formats.md#manifest-formats) |
| `manifest_block_scalar` | `image`の値がブロックスカラーである | [マニフェストの書き方](remediation-source-formats.md#manifest-formats) |
| `manifest_variable` | `image`の値に変数が含まれる | [マニフェストの書き方](remediation-source-formats.md#manifest-formats) |
| `manifest_digest` | `image`の値にdigestが付いている | [マニフェストの書き方](remediation-source-formats.md#manifest-formats) |
| `manifest_tag_missing` | `image`の値にタグがない | [マニフェストの書き方](remediation-source-formats.md#manifest-formats) |
| `manifest_image_automation` | `image`の行にFlux image automationの`$imagepolicy`コメントがある | [マニフェストの書き方](remediation-source-formats.md#manifest-formats) |
| `manifest_template` | マニフェストにテンプレートの式がある | [マニフェストの書き方](remediation-source-formats.md#manifest-formats) |
| `image_updater_file` | Kubernetesマニフェスト・Kustomize・Helmのvaluesの対象ファイルと同じディレクトリに、Argo CD Image Updaterの書き戻しファイルがある | [マニフェストの書き方](remediation-source-formats.md#manifest-formats) |
| `source_object_missing` | マニフェストにワークロードのオブジェクトの文書がない | [マニフェストの書き方](remediation-source-formats.md#manifest-formats) |
| `source_object_ambiguous` | マニフェストにワークロードのオブジェクトの文書が複数ある | [マニフェストの書き方](remediation-source-formats.md#manifest-formats) |
| `source_container_missing` | オブジェクトに、指定した名前の編集できるコンテナがない | [マニフェストの書き方](remediation-source-formats.md#manifest-formats) |
| `source_mismatch` | Kubernetesマニフェスト・Kustomize・Helmのvaluesから得るイメージ名が、Podのspecまたは稼働中のイメージ名と異なる | [KubernetesのマニフェストPR](remediation-kubernetes-logic.md#kubernetes-manifest-prs)・[KustomizeのPR](remediation-kubernetes-logic.md#kustomize-prs)・[HelmのvaluesのPR](remediation-kubernetes-logic.md#helm-values-prs) |
| `mapping_conflict` | ファイルの2つ以上の対応付けが、同じ文書の同じコンテナを指している | [KubernetesのマニフェストPR](remediation-kubernetes-logic.md#kubernetes-manifest-prs) |

### Kustomize {#source-kustomize-reasons}

kustomizationの`images`の項目を編集できるかを示します。

| コード | 意味 | 詳しい説明 |
| --- | --- | --- |
| `kustomize_invalid` | kustomizationが1つの正しいYAML文書でない、キーが重複している、または編集後の検査に通らない | [Kustomizeの書き方](remediation-source-formats.md#kustomize-formats) |
| `kustomize_image_missing` | kustomizationに対応付けた名前の`images`の項目がない | [Kustomizeの書き方](remediation-source-formats.md#kustomize-formats) |
| `kustomize_image_ambiguous` | 対応付けた名前の`images`の項目が複数ある | [Kustomizeの書き方](remediation-source-formats.md#kustomize-formats) |
| `kustomize_tag_not_set` | `images`の項目に`newTag`がない、または空である | [Kustomizeの書き方](remediation-source-formats.md#kustomize-formats) |
| `kustomize_unsupported_feature` | `images`の設定が効くコンテナを変えうる機能をkustomizationが使っている | [Kustomizeの書き方](remediation-source-formats.md#kustomize-formats) |
| `kustomize_image_chained` | 別の`images`の項目が、編集対象の名前または編集結果をさらに変更する | [Kustomizeの書き方](remediation-source-formats.md#kustomize-formats) |
| `kustomize_digest` | `images`の項目がdigestを固定している | [Kustomizeの書き方](remediation-source-formats.md#kustomize-formats) |
| `kustomize_anchor_or_alias` | `images`の項目に関わるアンカーまたはエイリアスがある | [Kustomizeの書き方](remediation-source-formats.md#kustomize-formats) |
| `kustomize_merge_key` | `images`の項目に関わるマージキーがある | [Kustomizeの書き方](remediation-source-formats.md#kustomize-formats) |
| `kustomize_not_string` | `images`の項目の値が単純な文字列ではない | [Kustomizeの書き方](remediation-source-formats.md#kustomize-formats) |
| `kustomize_block_scalar` | `images`の項目の値がブロックスカラーである | [Kustomizeの書き方](remediation-source-formats.md#kustomize-formats) |
| `kustomize_variable` | `images`の項目の値に変数がある | [Kustomizeの書き方](remediation-source-formats.md#kustomize-formats) |
| `kustomize_template` | kustomizationにテンプレートの式がある | [Kustomizeの書き方](remediation-source-formats.md#kustomize-formats) |
| `kustomize_image_automation` | `newTag`の行にFlux image automationの`$imagepolicy`コメントがある | [Kustomizeの書き方](remediation-source-formats.md#kustomize-formats) |
| `init_container_unverified` | KustomizeまたはHelmのvaluesの対応付けに列挙した通常のinit containerが、同じPodの列挙済みの稼働コンテナと同じイメージを使ったことを確認できない | [KustomizeのPR](remediation-kubernetes-logic.md#kustomize-prs)・[HelmのvaluesのPR](remediation-kubernetes-logic.md#helm-values-prs) |

### Helmのvalues {#source-helm-reasons}

valuesのイメージ指定を編集できるかと、変更の影響を受けるコンテナの宣言を確認した結果を示します。

| コード | 意味 | 詳しい説明 |
| --- | --- | --- |
| `helm_invalid` | valuesファイルが1つの正しいYAML文書でない、キーが重複している、または編集後の検査に通らない | [Helmのvaluesの書き方](remediation-source-formats.md#helm-values-formats) |
| `helm_key_missing` | valuesファイルに対応付けたキーの値がない | [Helmのvaluesの書き方](remediation-source-formats.md#helm-values-formats) |
| `helm_tag_from_chart` | キーにタグがなく、チャート自身の既定値が使われる | [Helmのvaluesの書き方](remediation-source-formats.md#helm-values-formats) |
| `helm_digest` | キーのイメージがdigestで固定されている | [Helmのvaluesの書き方](remediation-source-formats.md#helm-values-formats) |
| `helm_values_shape` | キーが`repository`と`tag`の指定でも`repository:tag`の文字列でもない | [Helmのvaluesの書き方](remediation-source-formats.md#helm-values-formats) |
| `helm_not_string` | イメージ文字列、または`repository`・`tag`・任意の`registry`・`digest`の値が、単純な文字列として読めない | [Helmのvaluesの書き方](remediation-source-formats.md#helm-values-formats) |
| `helm_block_scalar` | イメージ指定の文字列値がブロックスカラーである | [Helmのvaluesの書き方](remediation-source-formats.md#helm-values-formats) |
| `helm_variable` | イメージ指定の文字列値に変数がある | [Helmのvaluesの書き方](remediation-source-formats.md#helm-values-formats) |
| `helm_template` | valuesファイルにテンプレートの式がある | [Helmのvaluesの書き方](remediation-source-formats.md#helm-values-formats) |
| `helm_anchor_or_alias` | キーまでの経路のノードにアンカーまたはエイリアスがある | [Helmのvaluesの書き方](remediation-source-formats.md#helm-values-formats) |
| `helm_merge_key` | キーまでの経路のマッピングにマージキーがある | [Helmのvaluesの書き方](remediation-source-formats.md#helm-values-formats) |
| `helm_image_automation` | イメージの行にFlux image automationの`$imagepolicy`コメントがある | [Helmのvaluesの書き方](remediation-source-formats.md#helm-values-formats) |
| `undeclared_affected_workload` | 対応付けの`workload`と`kustomize.affects`または`helm_values.affects`にないコンテナが、同じイメージ名を宣言していて編集の影響を受けうる | [KustomizeのPR](remediation-kubernetes-logic.md#kustomize-prs)・[HelmのvaluesのPR](remediation-kubernetes-logic.md#helm-values-prs) |

`affects`には、タグ変更の影響を受ける`workload`以外のコンテナを、通常のinit containerも含めて列挙します。

### 依存ファイル {#source-dependency-reasons}

依存の宣言ファイル（`package.json`など）やlockfileを読み取り、更新対象にできるかを示します。

| コード | 意味 | 詳しい説明 |
| --- | --- | --- |
| `dependency_files_not_found` | 依存ファイルが見つからない | [計画が出ない場合](remediation-troubleshooting.md#check-missing-plan) |
| `ambiguous_dependency_files` | 依存ファイルの組み合わせが複数あり、1つに決められない | [計画が出ない場合](remediation-troubleshooting.md#check-missing-plan) |
| `dependency_file_unusable` | 依存ファイルが通常のファイルではない、Git LFSポインターである、または内容を読み取れない | [計画が出ない場合](remediation-troubleshooting.md#check-missing-plan) |
| `unsupported_lockfile` | lockfileの書き方をサポートしていない | — |
| `go_replace_unsupported` | `go.mod`に未対応の`replace`がある | [Goの依存ファイル](remediation-dependency-formats.md#go-inputs) |
| `go_exclude_unsupported` | `go.mod`に未対応の`exclude`がある | [Goの依存ファイル](remediation-dependency-formats.md#go-inputs) |
| `go_binary_not_from_source` | イメージのGoバイナリが対象の`go.mod`と一致しない、またはパッケージ一覧が不完全で照合できない | [Goの依存ファイル](remediation-dependency-formats.md#go-inputs) |
| `jar_bundled_copy` | パッケージの写しが別のアーカイブに同梱されていて、プロジェクトの依存ファイルの更新では直らない | [Mavenの候補選定](remediation-maven-logic.md#maven-package-selection)・[Gradleの候補選定](remediation-gradle-logic.md#gradle-package-selection) |
| `maven_app_jar_ambiguous` | イメージの中で、対象プロジェクトのアーカイブを特定できない | [Mavenの依存ファイル](remediation-dependency-formats.md#maven-inputs) |
| `maven_model_unsupported` | pomファイルが、更新の確認で解決を再現できない書き方をしている | [Mavenの依存ファイル](remediation-dependency-formats.md#maven-inputs) |
| `maven_parent_mismatch` | 親を探す場所にあるpomファイルが、宣言された親と一致しない | [Mavenの依存ファイル](remediation-dependency-formats.md#maven-inputs) |
| `maven_reactor_unsupported` | プロジェクトのモジュールを、1つのビルドとして読めない | [Mavenの依存ファイル](remediation-dependency-formats.md#maven-inputs) |
| `gradle_build_unsupported` | 複数プロジェクト構成や`apply from`・動的な版指定などの未対応の文・引数があり、依存宣言や実行する設定を読み取れない | [ビルドスクリプトの書き方](remediation-dependency-formats.md#gradle-build-forms) |
| `gradle_locking_unenforced` | lockfileのとおりにビルドする設定（lockModeの`STRICT`と全構成のlock）になっていない | [Gradleの依存ファイル](remediation-dependency-formats.md#gradle-inputs) |
| `gradle_plugin_unsupported` | 許可していないプラグインか版を使っている | [プラグインの許可](remediation-dependency-formats.md#gradle-plugins) |
| `workspace_unsupported` | npm・pnpm・uvの未対応のworkspace構成、またはGoの`go.work`・`vendor`がある | [npmの依存ファイル](remediation-dependency-formats.md#npm-inputs)・[pnpmの依存ファイル](remediation-dependency-formats.md#pnpm-inputs)・[uvの依存ファイル](remediation-dependency-formats.md#uv-inputs)・[Goの依存ファイル](remediation-dependency-formats.md#go-inputs) |
| `workspace_settings_unsupported` | workspace設定ファイルの内容をサポートしていない | — |
| `dynamic_metadata` | プロジェクトのメタデータが動的に決まる | — |
| `unsupported_requirements` | requirementsの書き方をサポートしていない | — |
| `unparsable_source` | 依存ファイルを解析できない | — |
| `unsupported_source_settings` | サポートしていないパッケージ取得元の設定がある | — |

### パッケージ {#source-package-reasons}

稼働版と依存ファイルの照合や、パッケージの取得元に関する判定を示します。

| コード | 意味 | 詳しい説明 |
| --- | --- | --- |
| `scan_not_pinned` | スキャン結果が特定のイメージに結び付いていない | [ソースの確認](remediation-logic.md#source-verification) |
| `not_found_in_source` | 依存ファイルに稼働版のパッケージが載っていない | [ソースの確認](remediation-logic.md#source-verification) |
| `global_node_modules` | パッケージがグローバルな`node_modules`にあり、依存ファイルの更新では修正できない | [ソースの確認](remediation-logic.md#source-verification) |
| `non_registry_source` | サポートする公開レジストリ以外から取得されるパッケージである | — |
| `sdist_only` | パッケージにソース配布物しかない | — |
| `forced_by_override` | パッケージの版がoverrideで固定されている | — |
| `marker_not_evaluated` | 依存指定の環境マーカーを評価していない | — |
| `invalid_marker` | 依存指定の環境マーカーが不正である | — |
| `multiple_versions` | 同名パッケージの複数の版や出現箇所を、1つの更新として扱えない | — |
| `unparsable_version` | パッケージの版を解釈できない | — |

グローバルな`node_modules`のパッケージは、通知先によって表示を分けます。

| 通知先 | 表示 |
| --- | --- |
| Webhook | パッケージと理由コードを出力する |
| Slack・メール | 「要判断」に表示せず、ほかに表示するパッケージがなければ項目も省略する |
| Slack・メールのサポート終了の案内 | `runtime_eol`の項目は、ほかに表示するパッケージがなくても残す |

### ソースの取得 {#source-retrieval-reasons}

リポジトリや依存ファイルの取得を止めた原因を示します。

| コード | 意味 | 詳しい説明 |
| --- | --- | --- |
| `source_not_found` | 取得元のリポジトリまたはブランチが見つからない | [計画が出ない場合](remediation-troubleshooting.md#check-missing-plan) |
| `source_access_denied` | 取得元のリポジトリにアクセスできない | [GitHubアクセスの準備](remediation-setup.md#prepare-github-access) |
| `source_too_large` | 取得元が大きすぎて読み込めない | [計画が出ない場合](remediation-troubleshooting.md#check-missing-plan) |
| `file_too_large` | 依存ファイルが大きすぎて読み込めない | [計画が出ない場合](remediation-troubleshooting.md#check-missing-plan) |
| `byte_budget_exhausted` | 取得元から読み込める容量の上限に達した | [計画が出ない場合](remediation-troubleshooting.md#check-missing-plan) |
| `source_error` | 取得元の読み込みに失敗した | [計画が出ない場合](remediation-troubleshooting.md#check-missing-plan) |
| `github_budget_exhausted` | GitHubへの要求数の上限に達した | [計画が出ない場合](remediation-troubleshooting.md#check-missing-plan) |
| `source_read_failed` | 依存ファイルの再取得に失敗した | [更新を実行できない場合](remediation-troubleshooting.md#check-update-failure) |
