---
title: 更新とPR処理の理由コード
---

# 更新とPR処理の理由コード

依存更新の実行環境・ツール取得・検査と、PR処理・保存で使う理由コードを調べるページです。
結果の値と理由の分類は[結果の値](remediation-reason-codes.md#result-values)と[理由コード](remediation-reason-codes.md#reason-codes)を参照してください。

KEVは、悪用が確認された脆弱性を収録するCISAのKnown Exploited Vulnerabilities一覧です。

調べる対象や処理に合わせて、小節を選んでください。

| 参照先 |
| --- |
| [実行環境の理由](#runtime-reasons) |
| [ツール取得の理由](#tool-reasons) |
| [候補の選定](#update-selection-reasons) |
| [Go](#update-go-reasons) |
| [Maven・Gradle](#update-java-reasons) |
| [更新の実行](#update-execution-reasons) |
| [更新後の検査](#update-validation-reasons) |
| [スキャンの比較](#update-scan-reasons) |
| [依存元からの再解決](#update-reresolution-reasons) |
| [PR処理の理由](#pr-reasons) |
| [保存処理の理由](#storage-reasons) |

このページで使う用語は[用語](remediation.md#terms)を参照してください。

## 実行環境の理由 {#runtime-reasons}

実行環境の理由は、更新に使う言語ランタイムや作業用コンテナを選び、実行できるかを表します。

版の宣言や実行環境を確認した結果は、次のコードで区別します。

| コード | 意味 | 詳しい説明 |
| --- | --- | --- |
| `node_spec_invalid` | 宣言されたNode.jsの版を解釈できない | [Node.jsの選定](remediation-node-python-logic.md#node-selection) |
| `python_spec_invalid` | 宣言されたPythonの版を解釈できない | [uv用Pythonの選定](remediation-node-python-logic.md#uv-python-selection) |
| `manager_spec_invalid` | 宣言されたパッケージマネージャーの版を解釈できない | [ツール版の選定](remediation-node-python-logic.md#tool-version-selection) |
| `node_spec_conflict` | `.node-version`・`.nvmrc`と、`package.json`の`engines.node`・`devEngines.runtime`・`engines.runtime`にあるNode.jsの版宣言を同時に満たす版がない | [Node.jsの選定](remediation-node-python-logic.md#node-selection) |
| `python_spec_conflict` | `.python-version`と`pyproject.toml`の`requires-python`を同時に満たすPython版がない | [uv用Pythonの選定](remediation-node-python-logic.md#uv-python-selection) |
| `manager_spec_conflict` | `package.json`のマネージャー名・版の宣言が、lockfileのマネージャーまたは別の宣言と矛盾する | [ツール版の選定](remediation-node-python-logic.md#tool-version-selection) |
| `node_spec_unsupported` | 宣言されたNode.jsの版をサポートしていない | [Node.jsの選定](remediation-node-python-logic.md#node-selection) |
| `python_spec_unsupported` | 宣言されたPythonの版をサポートしていない | [uv用Pythonの選定](remediation-node-python-logic.md#uv-python-selection) |
| `manager_spec_unsupported` | 宣言されたパッケージマネージャーの版をサポートしていない | [ツール版の選定](remediation-node-python-logic.md#tool-version-selection) |
| `work_program_mismatch` | 作業用コンテナ内のプログラムが、実行中のKestreLynxに付属するものと異なる | [更新を実行できない場合](remediation-troubleshooting.md#check-update-failure) |
| `work_environment_rejected` | 作業用コンテナがプログラムの実行要件を満たしていない | [実行時の制限](remediation-worker-logic.md#worker-restrictions) |
| `go_version_too_old` | `go.mod`に`go`の版の指定がない、または1.21より古い | [Goの依存ファイル](remediation-dependency-formats.md#go-inputs) |
| `go_toolchain_unsupported` | `go.mod`の`toolchain`の行が、公開されたGoの版ではない | [Goの依存ファイル](remediation-dependency-formats.md#go-inputs) |
| `go_runtime_unavailable` | 更新に必要な版以上の、サポート中のGoを選べない | [Goの選定](remediation-go-logic.md#go-runtime-selection)・[案内の概要](remediation-fix-hints.md#fix-hints) |
| `gradle_version_unsupported` | サポートしていないGradleの版を使っている | [Gradleの依存ファイル](remediation-dependency-formats.md#gradle-inputs) |
| `gradle_toolchain_unsupported` | サポートしていないJavaのtoolchainを指定している | [Gradleの実行設定](remediation-gradle-logic.md#gradle-worker-settings) |
| `runtime_eol` | プロジェクトの宣言などから更新用に選ぶランタイム、またはpipで検証する稼働イメージのPythonがサポート終了している | [実行環境の選定](remediation-package-logic.md#runtime-and-tool-versions) |
| `runtime_engines_mismatch` | 更新した依存が、プロジェクトの宣言する最小Node.js版をサポートしていない | [Node.jsの互換条件](remediation-node-python-logic.md#node-compatibility) |
| `requires_python_unsupported` | 必要なPython版の条件を満たせない、または条件がない・解釈できない | [uv用Pythonの選定](remediation-node-python-logic.md#uv-python-selection) |
| `pip_target_undecidable` | 稼働イメージのスキャン情報とパッケージの検出パスから、Python版やOS・CPUに合う検証対象環境を決められない | [pipの検証環境](remediation-node-python-logic.md#pip-target-environment) |
| `pip_target_mismatch` | 各パッケージの検出元から導いた検証環境で、Pythonの版・実装・プラットフォームタグ・ABIが一致しない | [pipの検証環境](remediation-node-python-logic.md#pip-target-environment) |
| `work_image_not_configured` | 更新用の作業環境が用意されていない | [更新を実行できない場合](remediation-troubleshooting.md#check-update-failure) |
| `work_namespace_not_configured` | KubernetesでのMaven以外の言語パッケージ更新に必要な作業用namespaceが未設定で、手動対応になる | [Kubernetesの作業用Podの設定](configuration.md#remediation-worker-kubernetes) |
| `work_runtime_class_unsupported` | 作業用Podに未対応のRuntimeClassが設定されていて、手動対応になる | [Kubernetesの作業用Podの設定](configuration.md#remediation-worker-kubernetes) |
| `work_cluster_too_old` | クラスタが作業用Podのポリシーに必要なKubernetes 1.30より古く、手動対応になる | [作業用Podの準備](remediation-setup-work-pods.md#kubernetes-language-updates) |
| `work_pod_limit` | 作業用Pod数またはnamespaceのクォータが上限で、更新を次のサイクルへ保留する | [Kubernetesの作業用Podの設定](configuration.md#remediation-worker-kubernetes) |
| `work_admission_unverified` | 作業用namespaceのPod作成規則が有効と確認できず、作業用Podを起動しない | [作業用Podの実行](remediation-worker-logic.md#kubernetes-work-pods) |
| `work_priority_class_missing` | 作業用Podに設定したPriorityClassが存在しない、または必要な設定と一致せず、手動対応になる | [作業用Podの準備](remediation-setup-work-pods.md#kubernetes-language-updates) |
| `work_pod_not_started` | 作業用Podが時間内に起動せず、更新を次のサイクルへ保留する | [更新を実行できない場合の確認](remediation-troubleshooting.md#check-update-failure) |
| `work_image_unavailable` | 作業用イメージを用意できなかった | [公式イメージの固定](remediation-worker-logic.md#worker-images) |

版の宣言が矛盾する例を示します。
パッケージマネージャーでは、`packageManager`・`devEngines.packageManager`・`engines`の宣言を照合します。

| 対象 | 矛盾する宣言の例 |
| --- | --- |
| Node.js | `.nvmrc`の`22`と、`package.json`の`engines.node: ">=24"`は同時に満たせない |
| Python | `.python-version`の`3.11`と、`pyproject.toml`の`requires-python = ">=3.12"`は同時に満たせない |
| パッケージマネージャー | `packageManager: "pnpm@10.34.4"`と、`devEngines.packageManager`の`name: "pnpm"`・`version: "^11"`は同時に満たせない |

## ツール取得の理由 {#tool-reasons}

ツール取得の理由は、パッケージマネージャーの配布物を取得し、検証して使えるかを表します。
取得設定、配布物の検証、待機、キャッシュに関する理由を示します。

| コード | 意味 | 詳しい説明 |
| --- | --- | --- |
| `tool_fetch_config_unsupported` | マネージャー自身によるツール取得や、未対応の依存解決設定が指定されている | [更新を実行できない場合](remediation-troubleshooting.md#check-update-failure) |
| `tool_version_unsupported` | パッケージマネージャーの版をサポートしていない | [ツール版の選定](remediation-node-python-logic.md#tool-version-selection) |
| `tool_version_not_found` | 指定したパッケージマネージャーの版が見つからない | [ツールの取得と照合](remediation-node-python-logic.md#tool-verification) |
| `tool_hash_mismatch` | ツールの配布物がチェックサムと一致しない | [ツールの取得と照合](remediation-node-python-logic.md#tool-verification) |
| `tool_hash_unsupported` | ツールの配布物のチェックサムを検証できない | [ツールの取得と照合](remediation-node-python-logic.md#tool-verification) |
| `tool_artifact_invalid` | ツールの配布物が不正である | [ツールの取得と照合](remediation-node-python-logic.md#tool-verification) |
| `tool_metadata_invalid` | ツールのリリース情報が不正である | [ツールの取得と照合](remediation-node-python-logic.md#tool-verification) |
| `tool_too_new` | ツールの公開から72時間経っていない、または公開日時が不明で72時間の経過を確認できない | [ツール公開後の待機](remediation-node-python-logic.md#tool-release-age) |
| `tool_fetch_failed` | ツールの取得に失敗した | [ツールの取得と照合](remediation-node-python-logic.md#tool-verification) |
| `tool_fetch_budget` | ツールの取得回数の上限に達した | [更新を実行できない場合](remediation-troubleshooting.md#check-update-failure) |
| `tool_cache_full` | ツールキャッシュに空きを確保できない | [ツールキャッシュの再利用](remediation-node-python-logic.md#tool-cache) |
| `tool_file_mismatch` | キャッシュ内のツール配布物が記録と異なる | [ツールキャッシュの再利用](remediation-node-python-logic.md#tool-cache) |

取得設定が未対応になる例を示します。

| ファイル | 設定の例 |
| --- | --- |
| `package.json` | `pnpm.configDependencies`・`pnpm.executionEnv`・`resolutions`が指定されている |
| `package.json` | `devEngines.runtime`または`engines.runtime`に`onFail: "download"`が指定されている |
| `pnpm-lock.yaml` | `runtime:`を使うランタイムの取得指定がある |
| `uv.toml` | uvが別ファイルから取得先や実行環境の設定を読む |
| `pyproject.toml` | `[tool.uv]`に、サポートしていない取得・依存解決の設定がある |

## 更新結果の理由 {#update-reasons}

更新結果の理由は、パッケージの候補選定、更新の実行、更新後の検査で得た判定を表します。

### 候補の選定 {#update-selection-reasons}

修正版を選べるかと、依存の版指定が修正版を許すかを示します。

| コード | 意味 | 詳しい説明 |
| --- | --- | --- |
| `update_candidate_in_source` | ソース内のパッケージに対応する修正版の更新候補がある | [修正版の下限](remediation-package-logic.md#fix-lower-bound) |
| `range_allows_fix` | 依存範囲が修正版を許し、再ビルドで入る見込みがある | [直接依存の版指定](remediation-node-python-logic.md#direct-dependencies) |
| `no_fixed_version_above_installed` | 稼働版より新しい修正版がない、または修正対象がない | [修正版の下限](remediation-package-logic.md#fix-lower-bound) |
| `constraint_excludes_fix` | 候補または更新後の版が依存の制約を満たさない | [直接依存の版指定](remediation-node-python-logic.md#direct-dependencies)・[推移的依存の更新範囲](remediation-node-python-logic.md#transitive-dependencies) |
| `constraint_not_evaluable` | 版の制約を評価できない、または修正版がpipで選ばれないプレリリースである | [直接依存の版指定](remediation-node-python-logic.md#direct-dependencies) |
| `packages_need_manual_update` | 自動更新できるパッケージがない | [更新を実行できない場合](remediation-troubleshooting.md#check-update-failure) |

### Go {#update-go-reasons}

Goのモジュール更新と、更新後に要求するGo版の判定を示します。

| コード | 意味 | 詳しい説明 |
| --- | --- | --- |
| `go_stdlib_needs_newer_go` | Goの標準ライブラリの脆弱性で、`go.mod`の更新ではなく、新しいGoでビルドし直すと直る | [Goの候補選定](remediation-go-logic.md#go-package-selection) |
| `fix_in_other_major_version` | 修正版が別のメジャー版にあり、Goでは別のモジュールパスになる | [Goの候補選定](remediation-go-logic.md#go-package-selection)・[案内の概要](remediation-fix-hints.md#fix-hints) |
| `go_release_retracted` | 目標版が撤回されていて代わりの修正版を選べない、または依存の要求で目標を超えた対象の版が撤回されている | [Goの候補選定](remediation-go-logic.md#go-package-selection)・[Goの更新結果の検査](remediation-go-logic.md#go-update-validation) |
| `go_line_raised_too_far` | `go.mod`の`go`・`toolchain`行の変更が、対象モジュールの稼働バイナリをビルドしたGo版の制限に反する | [Goの更新結果の検査](remediation-go-logic.md#go-update-validation)・[案内の概要](remediation-fix-hints.md#fix-hints) |
| `go_dependencies_uncheckable` | 更新後の依存の要求を確かめるためにたどるモジュールの版が多すぎる | [Goの更新結果の検査](remediation-go-logic.md#go-update-validation) |

行の変更の判定には、対象の`go.mod`のモジュールから作った稼働バイナリを、所見の有無にかかわらず使います。
ビルドに使ったGo版の確認結果によって、拒否する条件が異なります。

| ビルド版の確認結果 | 行の変更を拒否する条件 |
| --- | --- |
| 対象の全バイナリで判明している | 変更後の`go`・`toolchain`行の版が、ビルド版の最小値を超える |
| 対象のいずれかのバイナリで不明である | ビルド版が不明なまま`go`・`toolchain`行の版が変わる |

### Maven・Gradle {#update-java-reasons}

Maven・Gradleの版の出所、更新先、lockfileの検査結果を示します。

| コード | 意味 | 詳しい説明 |
| --- | --- | --- |
| `maven_fix_in_other_major` | 修正版が別のメジャー版にしかない | [Mavenの候補選定](remediation-maven-logic.md#maven-package-selection)・[Gradleの目標版](remediation-gradle-logic.md#gradle-target-versions)・[案内の概要](remediation-fix-hints.md#fix-hints) |
| `maven_version_source_unsupported` | 版が、プロジェクトのpomファイルの変更では変えられない方法で決まっている | [版の出所と書き換え](remediation-maven-logic.md#maven-version-sources)・[案内の概要](remediation-fix-hints.md#fix-hints) |
| `maven_release_not_found` | 更新で使える版がMaven Centralにない | [目標版とMaven Centralの版](remediation-maven-logic.md#maven-target-versions)・[Gradleの目標版](remediation-gradle-logic.md#gradle-target-versions)・[案内の概要](remediation-fix-hints.md#fix-hints) |
| `maven_bom_series_unreached` | 取り込んでいるBOMと同じメジャー・マイナー版の新しい正式版を最大20件調べても、条件を満たす版が見つからない | [版の出所と書き換え](remediation-maven-logic.md#maven-version-sources)・[Gradleの版の宣言と書き換え](remediation-gradle-logic.md#gradle-version-sources) |
| `maven_dependency_held_back` | 更新後も、新しい版が要求する依存が要求より低い版のまま残る | [Mavenの更新結果の検査](remediation-maven-logic.md#maven-update-validation) |
| `gradle_version_source_unsupported` | 版が、プロジェクトのファイルの変更では変えられない方法で決まっている | [版の宣言と書き換え](remediation-gradle-logic.md#gradle-version-sources)・[案内の概要](remediation-fix-hints.md#fix-hints) |
| `gradle_lock_entry_removed` | 更新で`gradle.lockfile`のエントリが削除された | [Gradleの更新結果の検査](remediation-gradle-logic.md#gradle-update-validation) |
| `gradle_lock_configurations_changed` | 更新で`gradle.lockfile`がlockする構成が変わった | [Gradleの更新結果の検査](remediation-gradle-logic.md#gradle-update-validation) |
| `gradle_lock_version_unsupported` | 更新後の`gradle.lockfile`にスナップショット版が含まれる | [Gradleの更新結果の検査](remediation-gradle-logic.md#gradle-update-validation) |

### 更新の実行 {#update-execution-reasons}

依存ファイルの更新を開始・実行・回収する段階の理由を示します。

| コード | 意味 | 詳しい説明 |
| --- | --- | --- |
| `update_job_limit` | 1サイクルで実行できる依存ファイル更新の数の上限に達した | [更新を実行できない場合](remediation-troubleshooting.md#check-update-failure) |
| `update_input_limit` | 更新に使うファイルがサイズ上限を超えている | [コンテナへの入力](remediation-worker-logic.md#worker-inputs) |
| `update_job_failed` | 更新の実行に失敗した | [更新を実行できない場合](remediation-troubleshooting.md#check-update-failure) |
| `update_result_invalid` | 更新処理の結果が不正である | [結果の回収](remediation-worker-logic.md#worker-results) |
| `update_job_timed_out` | 更新の実行がタイムアウトした | [実行時の制限](remediation-worker-logic.md#worker-restrictions) |
| `distribution_lookup_failed` | npm・PyPIなどのレジストリからパッケージの情報を読む処理に失敗した | [付随変更の検査](remediation-node-python-logic.md#change-validation) |
| `update_input_invalid` | KestreLynx本体で更新を準備・検査する際に、計画の対象版・ファイル情報、実行環境の設定、または作業用コンテナへ渡す実行データの不正を検出した | [コンテナへの入力](remediation-worker-logic.md#worker-inputs) |
| `update_job_input_rejected` | 作業用コンテナ内のプログラムが、実行指示や入力ファイルなどを検査して更新の入力を拒否した | [コンテナへの入力](remediation-worker-logic.md#worker-inputs) |
| `manifest_edit_required` | `package.json`や`pyproject.toml`の依存宣言に、自動では書き換えられない版指定などの変更が必要である | [直接依存の版指定](remediation-node-python-logic.md#direct-dependencies) |
| `input_modified` | 読み取り専用のはずの設定ファイルが変更された | [付随変更の検査](remediation-node-python-logic.md#change-validation) |
| `lockfile_inconsistent` | lockfileがプロジェクトと整合していない | [マネージャー別の更新処理](remediation-package-logic.md#manager-update-methods) |
| `no_wheel_for_version` | 対象の版に必要なプラットフォーム向けのwheelがない | [マネージャー別の更新処理](remediation-package-logic.md#manager-update-methods) |
| `release_yanked` | 対象のリリースが取り下げられている | [付随変更の検査](remediation-node-python-logic.md#change-validation) |
| `requirements_rewrite_unsupported` | 修正計画で使う更新方法ではrequirementsを書き換えられない | [マネージャー別の更新処理](remediation-package-logic.md#manager-update-methods) |
| `update_set_not_applied` | 同時に更新する別のパッケージを更新できなかった | [部分PRの成立条件](remediation-package-logic.md#partial-pr-selection) |
| `target_not_in_lockfile` | 更新対象のパッケージがlockfileに載っていない | [マネージャー別の更新処理](remediation-package-logic.md#manager-update-methods) |
| `no_reresolve_trigger` | pnpmに依存の版を選び直させるため、`pnpm-lock.yaml`の`importers['.']`から一時的に外せる直接依存がない | [マネージャー別の更新処理](remediation-package-logic.md#manager-update-methods) |
| `pnpm12_removal_unsupported` | 12.10.0より前のpnpm 12では、現在の更新方法を使えない | [マネージャー別の更新処理](remediation-package-logic.md#manager-update-methods) |
| `update_step_failed` | 更新中の処理に失敗した | [マネージャー別の更新処理](remediation-package-logic.md#manager-update-methods) |
| `registry_check_limit` | 更新時にnpm・PyPIなどのレジストリに問い合わせた回数が上限に達した | [更新を実行できない場合](remediation-troubleshooting.md#check-update-failure) |
| `update_package_limit` | 更新するパッケージ数が上限を超えている | [更新を実行できない場合](remediation-troubleshooting.md#check-update-failure) |

### 更新後の検査 {#update-validation-reasons}

出力ファイルと依存関係の変更が、許可した範囲に収まるかを示します。

| コード | 意味 | 詳しい説明 |
| --- | --- | --- |
| `post_update_check_failed` | 更新後の検査に失敗した | [付随変更の検査](remediation-node-python-logic.md#change-validation) |
| `unexpected_files` | 更新で想定外のファイルが変更された | [付随変更の検査](remediation-node-python-logic.md#change-validation) |
| `release_age_violation` | 依存のリリースが、プロジェクトの定める公開後の最低経過期間を満たさない | [付随変更の検査](remediation-node-python-logic.md#change-validation) |
| `manifest_changed` | 更新で依存の宣言ファイル（`package.json`など）に許可していない変更が入った | [付随変更の検査](remediation-node-python-logic.md#change-validation) |
| `output_files_invalid` | 出力ファイルが不正、または読み取れない | [結果の回収](remediation-worker-logic.md#worker-results) |
| `lockfile_format_changed` | 更新でlockfileの書き方が変わった | [付随変更の検査](remediation-node-python-logic.md#change-validation) |
| `target_not_updated` | 更新後の版が、Maven・Gradleで選定したMaven Centralの公開版など、検査で求める版に届かない | [部分PRの成立条件](remediation-package-logic.md#partial-pr-selection)・[案内の概要](remediation-fix-hints.md#fix-hints) |
| `target_removed` | 更新後に対象パッケージがなくなった、または依存関係から到達できなくなった | [部分PRの成立条件](remediation-package-logic.md#partial-pr-selection) |
| `fix_condition_not_met` | 更新後の版が脆弱性の修正条件を満たさない | [部分PRの成立条件](remediation-package-logic.md#partial-pr-selection) |
| `unexplained_dependency_diff` | 更新との関係を説明できない依存の変更、または更新したモジュールの要求と一致しないGoの`go`行の引き上げがある | [付随変更の検査](remediation-node-python-logic.md#change-validation)・[Goの更新結果の検査](remediation-go-logic.md#go-update-validation) |
| `distribution_mismatch` | パッケージがレジストリの公開内容やpipの解決結果と一致しない | [付随変更の検査](remediation-node-python-logic.md#change-validation) |
| `resolved_source_changed` | パッケージの取得元が変わった | [付随変更の検査](remediation-node-python-logic.md#change-validation) |
| `post_update_lockfile_unstable` | lockfileを再生成すると、さらに内容が変わる | [マネージャー別の更新処理](remediation-package-logic.md#manager-update-methods) |
| `drop_side_effect` | 再解決のために一時的に外した依存が元の状態に戻らなかった | [マネージャー別の更新処理](remediation-package-logic.md#manager-update-methods) |

Goで`go`行を引き上げる場合は、版を上げたモジュールと追加したモジュールが要求するGo版の最大値と一致する必要があります。
例えば、最大の要求がGo `1.25.0`なら、更新後の`go 1.23.0`は一致しません。

### スキャンの比較 {#update-scan-reasons}

更新前後の依存ファイルを比較し、対象の所見が解消したかを示します。

| コード | 意味 | 詳しい説明 |
| --- | --- | --- |
| `source_scan_failed` | 依存ファイルのスキャンに失敗した | [比較条件](remediation-logic.md#comparison-conditions) |
| `source_target_not_detected_before` | 更新前の依存ファイルで対象の脆弱性が検出されなかった | [比較条件](remediation-logic.md#comparison-conditions) |
| `source_target_not_analysed_after` | 更新後の依存ファイルで対象を解析できなかった | [比較条件](remediation-logic.md#comparison-conditions) |
| `source_target_still_detected` | 更新後も対象の脆弱性が検出される | [対象別の検証範囲](remediation-logic.md#verification-scope) |
| `source_introduced_findings` | 新しい所見、脆弱なパッケージの記録数・依存元の増加、または許可できない依存経路の分岐・合流などにより、依存ファイルの更新を拒否した | [比較条件](remediation-logic.md#comparison-conditions)・[採用しない変化](remediation-reresolution-logic.md#dependent-reresolution-rules) |
| `source_introduced_kev` | KEV掲載の脆弱性が、新しい所見、脆弱なパッケージの記録数・依存元の増加、または許可できない依存経路の分岐・合流などに関わるため、更新を拒否した | [比較条件](remediation-logic.md#comparison-conditions)・[採用しない変化](remediation-reresolution-logic.md#dependent-reresolution-rules) |
| `source_scan_incomplete` | 依存ファイルのスキャンが不完全だった | [比較条件](remediation-logic.md#comparison-conditions) |
| `update_verified` | 更新結果の検査と依存ファイルの更新前後のスキャンを通り、採用する更新対象の所見の解消を確認した | [対象別の検証範囲](remediation-logic.md#verification-scope) |

脆弱なパッケージの記録数はlockfile内の記録、依存元の増加は脆弱な版を要求する依存関係の数で確認します。
1つの旧版が複数の脆弱な新版へ分かれる場合や、経路の合流で比較する旧版を1つに決められない場合は、[採用しない変化](remediation-reresolution-logic.md#dependent-reresolution-rules)の図を参照してください。

依存ファイルの検証完了は、アプリケーションのビルドや、更新後の稼働イメージの脆弱性解消を確認したことを表しません。

### 依存元からの再解決 {#update-reresolution-reasons}

依存元のパッケージも更新して依存関係を解決し直した結果を示します。
Webhookでは、パッケージごとの`language_items[].packages[].reason`と、再解決全体の`language_items[].update.chain.reason`を併せて確認してください。

| コード | 意味 | 詳しい説明 |
| --- | --- | --- |
| `dependents_update_not_fixed` | 依存元を解決し直したが、今回の再解決では修正版に届かなかった | [依存元からの再解決](remediation-reresolution-logic.md#dependent-reresolution) |
| `no_resolution` | 修正版を指定した再解決は成立しなかった | [依存元からの再解決](remediation-reresolution-logic.md#dependent-reresolution) |
| `dependents_update_rejected` | 依存元の更新が検査を通らなかった、または公開後の待機が3回続いて再解決を停止した | [採用しない変化](remediation-reresolution-logic.md#dependent-reresolution-rules) |
| `dependents_update_unsupported` | 依存元を使用中のツールでは更新できない | [再解決の対応範囲と上限](remediation-reresolution-logic.md#dependent-reresolution-limits) |
| `dependents_update_limit` | 依存元の更新が上限、同じ上限による保留の繰り返し、または待機記録の保存失敗で停止した | [再解決の対応範囲と上限](remediation-reresolution-logic.md#dependent-reresolution-limits) |
| `dependents_hold_back` | 依存元が対象パッケージの版を制限している | [マネージャー別の更新処理](remediation-package-logic.md#manager-update-methods)・[案内の概要](remediation-fix-hints.md#fix-hints) |
| `release_too_new` | 更新で入る版の公開から72時間経っていない | [公開後の待機と再試行](remediation-reresolution-logic.md#dependent-reresolution-waits) |
| `chain_downgrade` | 更新でパッケージの版が下がる、または依存経路をたどって更新前後のパッケージと版を照合できない | [採用しない変化](remediation-reresolution-logic.md#dependent-reresolution-rules) |
| `chain_move_limit` | 更新で動くパッケージ数が上限を超える | [再解決の対応範囲と上限](remediation-reresolution-logic.md#dependent-reresolution-limits) |
| `chain_item_budget` | 更新に必要な作業が、1つの計画項目に許された上限を超える | [公開後の待機と再試行](remediation-reresolution-logic.md#dependent-reresolution-waits) |

依存元の更新が上限や待機記録の保存失敗で止まる条件を分けて示します。

| 原因 | 発生条件 |
| --- | --- |
| 再解決の上限 | 再解決する依存元の数や、確認に必要な照会回数などが上限を超える |
| 同じ上限による保留の繰り返し | 同じ入力で同種の処理上限による保留が3サイクル連続する |
| 待機記録の保存失敗 | 後のサイクルへ保留するために必要な待機記録を保存できない |

具体的な上限や停止理由は`language_items[].update.chain.reason`と`language_items[].update.chain.detail`、待機記録の保存失敗は`language_items[].packages[].detail`で確認してください。

再解決の実行や取得に失敗した場合は、通常更新と共通の失敗コードも使います。

## PR処理の理由 {#pr-reasons}

PR処理の理由は、PRを作成・照合・置換できるかと、GitHubへの書き込みを止めた原因を表します。
処理の上限、候補やファイルの変化、既存PRとの関係を次のコードで区別します。

| コード | 意味 | 詳しい説明 |
| --- | --- | --- |
| `pr_limit` | 1サイクルで作成するPR数の上限（`new_prs_per_cycle`）に達した | [PRを作れない場合](remediation-troubleshooting.md#check-missing-pr) |
| `open_pr_limit` | 設定したリポジトリ全体で開いているKestreLynxのPR数の上限（`open_prs`）に達した | [PRを作れない場合](remediation-troubleshooting.md#check-missing-pr) |
| `candidate_changed` | PR準備時の候補の再確認、またはDockerfileの新しい系列の確認で、同じ候補タグが異なる内容を指した | [PRを作れない場合](remediation-troubleshooting.md#check-missing-pr)・[新しい系列の確認](remediation-image-logic.md#newer-series-check) |
| `base_moved` | PRの準備中にベースブランチが進んだ | [PRを作れない場合](remediation-troubleshooting.md#check-missing-pr) |
| `github_rate_limited` | GitHubのレート制限に掛かった | [PRを作れない場合](remediation-troubleshooting.md#check-missing-pr) |
| `write_outcome_unknown` | GitHubへの書き込み結果を確認できない | [書き込みの停止](remediation-pr-logic.md#write-stops) |
| `reconciliation_failed` | 既存PRとの照合に失敗した | [既存PRとの照合](remediation-pr-logic.md#existing-pr-matching) |
| `repository_mismatch` | リポジトリがPR処理の記録と異なる | [書き込みの停止](remediation-pr-logic.md#write-stops) |
| `attempt_unsettled` | 前回のPR作成結果がまだ確定していない | [既存PRとの照合](remediation-pr-logic.md#existing-pr-matching) |
| `branch_not_ours` | 同名のブランチが存在し、KestreLynxが作成したものではない | [書き込みの停止](remediation-pr-logic.md#write-stops) |
| `pull_request_not_as_created` | PRが作成時の状態と異なることを表す定義済みコードで、現在のPR処理では設定されない | [書き込みの停止](remediation-pr-logic.md#write-stops) |
| `github_refused` | GitHubが書き込みを拒否した | [PRを作れない場合](remediation-troubleshooting.md#check-missing-pr) |
| `github_error` | GitHubがエラーを返した | [PRを作れない場合](remediation-troubleshooting.md#check-missing-pr) |
| `candidate_recheck_failed` | PR作成前に候補を再確認できなかった | [PRを作れない場合](remediation-troubleshooting.md#check-missing-pr) |
| `source_changed` | 計画の元にしたファイルが変更された | [PRを作れない場合](remediation-troubleshooting.md#check-missing-pr) |
| `artifact_content_missing` | 更新したファイルの内容が保持されていない | [PRを作れない場合](remediation-troubleshooting.md#check-missing-pr) |
| `artifacts_unusable` | 更新したファイルをそのままPRへ書き込めない | [PRを作れない場合](remediation-troubleshooting.md#check-missing-pr) |
| `open_pr_not_inherited` | 同じファイルの既存PRが修正する所見の一部を、新しい更新提案が修正しない | [古いPRの置き換え](remediation-pr-logic.md#pr-replacement) |
| `language_set_too_large` | 更新するパッケージが多すぎてPRの記録に収まらない | [PRを作れない場合](remediation-troubleshooting.md#check-missing-pr) |
| `update_already_proposed` | 対象の更新を提案するPRがすでにある | [既存PRとの照合](remediation-pr-logic.md#existing-pr-matching) |

候補タグの内容が変わったかを確認する相手は、処理によって異なります。

| 処理 | 比較する内容 |
| --- | --- |
| PRの準備 | 計画で検証した候補のdigestと、PR作成前に再取得した候補のdigestを比較する |
| Dockerfileの新しい系列の確認 | 各稼働イメージについて取得した同じ候補タグの内容を、最上位のdigestと同じプラットフォームのマニフェストdigestで比較する |

## 保存処理の理由 {#storage-reasons}

保存処理の理由は、`prs.json`にあるPR処理の記録を読めるか、新しい記録を保存できるかを表します。
ロック、書き込み失敗、記録の上限、照合不能を次のコードで区別します。

| コード | 意味 | 詳しい説明 |
| --- | --- | --- |
| `store_locked` | PR処理の記録が別のプロセスにロックされている | [記録を照合できない場合](remediation-troubleshooting.md#check-record-failure) |
| `storage_failed` | PR処理の記録を保存できなかった | [記録の保存順序](remediation-pr-logic.md#record-order) |
| `storage_full` | `prs.json`の操作イベント数の上限に対して、新しいイベントを保存する空きを確保できない | [書き込みの停止](remediation-pr-logic.md#write-stops) |
| `records_unverified` | 既存PRの記録を確認できない | [記録の復旧](remediation-pr-logic.md#record-recovery) |
| `proposal_not_found` | 対象の更新を提案していたPRの記録が見つからない | [既存PRとの照合](remediation-pr-logic.md#existing-pr-matching) |
