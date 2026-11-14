---
title: 依存ファイルと版宣言の対応形式
---

# 依存ファイルと版宣言の対応形式

依存ファイルと版宣言が、自動更新で扱える書き方かを確認するページです。
更新先の決め方は[言語パッケージの候補選定](remediation-package-logic.md#package-selection)、実行する版の決め方は[実行環境の選定](remediation-package-logic.md#runtime-and-tool-versions)を参照してください。

使っているファイルから、該当する節を選んでください。

| パッケージマネージャー・用途 | 主なファイル・宣言 | 参照先 |
| --- | --- | --- |
| npm | `package.json`・`package-lock.json` | [npmの依存ファイル](#npm-inputs) |
| pnpm | `package.json`・`pnpm-lock.yaml` | [pnpmの依存ファイル](#pnpm-inputs) |
| pip | `requirements.txt` | [pipの依存ファイル](#pip-inputs) |
| uv | `pyproject.toml`・`uv.lock` | [uvの依存ファイル](#uv-inputs) |
| Go | `go.mod`・`go.sum` | [Goの依存ファイル](#go-inputs) |
| Maven | `pom.xml` | [Mavenの依存ファイル](#maven-inputs) |
| Gradle | `gradle.lockfile`・ビルドスクリプト | [Gradleの依存ファイル](#gradle-inputs) |
| Gradleのビルド設定 | `build.gradle`・`build.gradle.kts`・settings・catalog | [ビルドスクリプトの書き方](#gradle-build-forms) |
| Gradleのプラグイン | ビルドスクリプト・settingsのプラグイン宣言 | [プラグインの許可](#gradle-plugins) |
| Node.js | `.nvmrc`・`.node-version`・`package.json` | [Node.jsの版宣言](#node-declarations) |
| Python | `.python-version`・`requires-python` | [Pythonの版宣言](#python-declarations) |
| パッケージマネージャーの版 | `packageManager`・`tool.uv.required-version` | [ツールの版宣言](#tool-declarations) |

未対応は、自動更新で扱えない書き方や設定を指します。

表の「依存ファイル全体」は、対応付けで指定した依存ディレクトリの依存ファイルを自動更新しない範囲です。
同じリポジトリ・ベースブランチ・依存ディレクトリを指す対応付けは、まとめて判定します。

Mavenでは、ルートの`pom.xml`から`modules`でたどる子モジュールも範囲に含みます。
同じリポジトリでも、別の依存ディレクトリは別に判定します。

「対象パッケージ」は、該当するパッケージを自動更新から外す範囲です。

ほかのパッケージでPRを作れる条件は[部分PRの成立条件](remediation-package-logic.md#partial-pr-selection)を参照してください。
理由コードの意味は[ソースの理由](remediation-image-reason-codes.md#source-reasons)と[実行環境の理由](remediation-update-reason-codes.md#runtime-reasons)にまとめています。

このページで使う用語は[用語](remediation.md#terms)を参照してください。

## npmの依存ファイル {#npm-inputs}

`package.json`と`package-lock.json`を読み、lockfileに記録された依存パッケージの版と、必要な依存宣言を更新します。
必要なファイルと、読み取れる内容は次のとおりです。

| 項目 | 対応範囲 |
| --- | --- |
| 必須ファイル | 単一プロジェクトの`package.json`と`package-lock.json` |
| lockfile | `lockfileVersion`が2または3で、`packages`にルートの記録がある書き方 |
| 取得元 | 公開npmレジストリの配布物 |
| 依存元からの再解決 | 対象パッケージを要求する依存元も更新し、依存関係を解決し直す処理（直接依存を含む[再解決を使う条件](remediation-reresolution-logic.md#dependent-reresolution-eligibility)を参照） |

次の書き方は手動対応になります。

| 条件 | 更新しない範囲 | 理由コード |
| --- | --- | --- |
| workspaceを使う | 依存ファイル全体 | `workspace_unsupported` |
| Git・URL・別名でインストールする | 対象パッケージ | `non_registry_source` |
| ローカル参照を使い、`packages`のルート以外の記録がすべて`node_modules/`内にある | 対象パッケージ | `non_registry_source` |
| ローカル参照などで、`packages`にルート以外の`node_modules/`外の記録がある | 依存ファイル全体 | `workspace_unsupported` |
| 配布物に依存を含めるパッケージ、その配下の依存、または配布物に含まれた依存を使う | 対象パッケージ | `non_registry_source` |
| 独自の`npm-shrinkwrap.json`を持つパッケージや、その配下の依存を使う | 対象パッケージ | `non_registry_source` |
| `package.json`の`overrides`で版を固定する | 対象パッケージ | `forced_by_override` |
| `.npmrc`で非公開レジストリを指定する | 依存ファイル全体 | `unsupported_source_settings` |

配布物に依存を含める指定は`bundleDependencies`・`bundledDependencies`で、lockfileでは`inBundle`も確認します。
独自の`npm-shrinkwrap.json`の有無は、lockfileの`hasShrinkwrap`で確認します。

## pnpmの依存ファイル {#pnpm-inputs}

`package.json`と`pnpm-lock.yaml`を読み、lockfileに記録された依存パッケージの版と、必要な依存宣言を更新します。
必要なファイルと、読み取れる内容は次のとおりです。

| 項目 | 対応範囲 |
| --- | --- |
| 必須ファイル | `package.json`と`pnpm-lock.yaml` |
| lockfile | `lockfileVersion: '9.0'`で、`importers`が`.`だけの書き方 |
| `package.json`との整合 | 直接依存の名前と版指定が、`importers['.']`の依存項目の名前と`specifier`に一致する構成 |
| 取得元 | 公開npmレジストリの配布物 |
| pnpm 12 | `12.10.0`以上 |
| 依存元からの再解決 | 対象パッケージを要求する依存元も更新し、依存関係を解決し直す処理（直接依存を含む[再解決を使う条件](remediation-reresolution-logic.md#dependent-reresolution-eligibility)を参照） |

整合の照合には、`dependencies`・`devDependencies`・`optionalDependencies`を使います。
`package.json`の`peerDependencies`にある依存が、lockfileのimporterに記録されることも許容します。

`package.json`の`pnpm`で許可するキーは、`allowBuilds`・`onlyBuiltDependencies`・`ignoredBuiltDependencies`・`neverBuiltDependencies`・`supportedArchitectures`です。
`pnpm.configDependencies`・`pnpm.executionEnv`を含む、それ以外のキーは未対応です。

次の書き方や版は手動対応になります。

| 条件 | 更新しない範囲 | 理由コード |
| --- | --- | --- |
| workspaceを使う | 依存ファイル全体 | `workspace_unsupported` |
| lockfileでcatalogやパッチ適用済み依存を使う | 依存ファイル全体 | `unsupported_lockfile` |
| 公開npmレジストリ以外から取得する | 対象パッケージ | `non_registry_source` |
| lockfileにruntimeの自動取得が記録されている | 依存ファイル全体 | `tool_fetch_config_unsupported` |
| `package.json`に`resolutions`がある | 依存ファイル全体 | `tool_fetch_config_unsupported` |
| `package.json`の`pnpm`に許可していないキーがある | 依存ファイル全体 | `tool_fetch_config_unsupported` |
| pnpm 12の版が`12.10.0`より前である | 依存ファイル全体 | `pnpm12_removal_unsupported` |

同じディレクトリの`pnpm-workspace.yaml`は、次のビルド許可とアーキテクチャの設定だけを読み取れます。
ファイルがあるだけではworkspaceと判断しません。

| キー・場所 | 読み取り条件・扱い |
| --- | --- |
| `allowBuilds` | パッケージの指定をキーとし、真偽値または文字列を値とする対応表 |
| `onlyBuiltDependencies`・`ignoredBuiltDependencies`・`neverBuiltDependencies` | パッケージ名の文字列リスト |
| `supportedArchitectures` | `os`・`cpu`・`libc`ごとの文字列リスト |
| `packages` | workspace宣言として依存ファイル全体を手動対応 |
| 許可したキー以外 | `workspace_settings_unsupported`で依存ファイル全体を手動対応 |
| 依存ディレクトリより上の`pnpm-workspace.yaml` | リポジトリのルートまで確認し、存在すれば依存ファイル全体を手動対応 |

読み取れるビルド許可設定があっても、更新時のスクリプト実行は無効です。

## pipの依存ファイル {#pip-inputs}

`requirements.txt`を読み、厳密に固定された依存の版と、既存のハッシュを更新します。
読み取れる書き方と、更新する内容は次のとおりです。

| 項目 | 対応範囲・更新内容 |
| --- | --- |
| 必須ファイル | UTF-8の`requirements.txt` |
| 厳密な固定版 | `name==1.2.3`の版を更新 |
| 範囲指定・版指定なし | 修正版を許す場合は修正計画に「再ビルド」（`rebuild_expected`）として表示 |
| extras | `name[extra]`の読み取り |
| コメント・継続行 | 読み取り |
| 既存の`--hash` | 固定版の更新時に、PyPIのwheel情報から更新 |

範囲指定・版指定なしの依存は固定版へ書き換えず、その依存を更新するPRも作りません。

次の書き方や配布物は、自動更新では扱えません。

| 条件 | 更新しない範囲 | 理由コード |
| --- | --- | --- |
| 環境マーカーがある | 自動評価せず対象パッケージを手動対応 | `marker_not_evaluated`・`invalid_marker` |
| `-r`・`-c`などで別ファイルを参照する | 依存ファイル全体 | `unsupported_requirements` |
| 取得元を変更するオプションがある | 依存ファイル全体 | `unsupported_requirements` |
| `name @ URL`のように名前を付けてGit・URL・ローカル参照を指定する | 対象パッケージ | `non_registry_source` |
| URLやパスだけの行、または`-e`を使う | 依存ファイル全体 | `unsupported_requirements` |
| 更新先の版にwheelがなく、ソース配布物しかない | 該当する依存ディレクトリのpipの更新全体を不採用 | — |

稼働イメージに合わせた検証条件は[pipの検証環境](remediation-node-python-logic.md#pip-target-environment)を参照してください。

## uvの依存ファイル {#uv-inputs}

`pyproject.toml`と`uv.lock`を読み、lockfileに記録された依存パッケージの版と、必要な依存宣言を更新します。
必要なファイルと、読み取れる内容は次のとおりです。

| 項目 | 対応範囲 |
| --- | --- |
| 必須ファイル | 単一プロジェクトの静的な`pyproject.toml`と`uv.lock` |
| lockfile | `version = 1`・`revision = 5` |
| プロジェクト | `[project]`があり、動的なメタデータを要求しない構成 |
| Pythonの要件 | `[project]`に`requires-python`がある構成 |
| 取得元 | 公開PyPI |
| `pyproject.toml`の`[tool.uv]` | `required-version`・`dev-dependencies`・`sources`・`package` |
| 依存元からの再解決 | 対象パッケージを要求する依存元も更新し、依存関係を解決し直す処理（直接依存を含む[再解決を使う条件](remediation-reresolution-logic.md#dependent-reresolution-eligibility)を参照） |

`[tool.uv]`のキーを読み取れる場合も、依存の取得元とプロジェクト構成が対応範囲内である必要があります。
次の書き方や依存は手動対応になります。

| 条件 | 更新しない範囲 | 理由コード |
| --- | --- | --- |
| workspaceを使う | 依存ファイル全体 | `workspace_unsupported` |
| Git・URL・ローカル参照を使う | 対象パッケージ | `non_registry_source` |
| ソースからのビルドが必要な依存を使う | 対象パッケージ | `sdist_only` |
| `[tool.uv]`に許可していないキーがある | 依存ファイル全体 | `tool_fetch_config_unsupported` |
| 依存ディレクトリからリポジトリのルートまでのいずれかに`uv.toml`がある | 依存ファイル全体 | `tool_fetch_config_unsupported` |

## Goの依存ファイル {#go-inputs}

設定した依存ディレクトリの`go.mod`と`go.sum`を読み、モジュールの依存指定とチェックサムを更新します。

読み取るファイルと、所見を照合する条件は次のとおりです。

| 項目 | 対応範囲 |
| --- | --- |
| 必須ファイル | `go.mod`と`go.sum` |
| 対象の所見 | Trivyが`gobinary`として検出した、稼働イメージのGoバイナリの所見 |
| バイナリとの照合 | メインモジュールのパスが`go.mod`の`module`と一致するバイナリ |
| 取得元 | 公開の`proxy.golang.org`と`sum.golang.org` |
| `go`の行 | 1.21以上 |
| `toolchain`の行 | 公開されたGoの版を表す`go1.N.M` |

メインモジュールが一致しないバイナリの所見は、計画に含めません。
ベースイメージに入っていたツールの所見も、同じ規則で判定します。

次の条件では自動更新を行いません。

| 条件 | 更新しない範囲 | 理由コード |
| --- | --- | --- |
| バイナリに入っているモジュールの版が`go.mod`の`require`と一致しない | 依存ファイル全体 | `go_binary_not_from_source` |
| スキャン結果のパッケージ一覧が切り詰められている | 依存ファイル全体 | `go_binary_not_from_source` |
| 非公開モジュールなど、更新に必要なモジュールを公開のproxyから取得できない | 該当する依存ディレクトリのGoの更新全体を不採用 | — |
| `replace`が1行でもある | 依存ファイル全体 | `go_replace_unsupported` |
| `exclude`が1行でもある | 依存ファイル全体 | `go_exclude_unsupported` |
| `go`の行がない、または1.21より古い | 依存ファイル全体 | `go_version_too_old` |
| `toolchain`が`default`・独自の接尾辞付き・RCである | 依存ファイル全体 | `go_toolchain_unsupported` |
| 依存ディレクトリからリポジトリのルートまでのいずれかに`go.work`がある | 依存ファイル全体 | `workspace_unsupported` |
| 依存ディレクトリに`vendor`がある | 依存ファイル全体 | `workspace_unsupported` |
| 修正版が別のメジャー版のモジュールパスにしかない | 対象パッケージ | `fix_in_other_major_version` |

別のメジャー版での修正は、確認できた最小の修正版と、直接指定か依存元による要求かを[案内の概要](remediation-fix-hints.md#fix-hints)に表示します。
標準ライブラリの`stdlib`についてはPRを作らず、ビルドに使うGoの版を上げる案内を修正計画に表示します。

候補と標準ライブラリの扱いは[Goの候補選定](remediation-go-logic.md#go-package-selection)、採用条件は[Goの更新結果の検査](remediation-go-logic.md#go-update-validation)を参照してください。

## Mavenの依存ファイル {#maven-inputs}

ルートと各モジュールの`pom.xml`を読み、KestreLynxが依存の版を決める宣言を書き換えます。
Mavenの更新では、作業用コンテナ・Podを使いません。

必要なファイルと、更新対象の条件は次のとおりです。

| 項目 | 対応範囲 |
| --- | --- |
| 必須ファイル | 設定した依存ディレクトリの`pom.xml`と、`modules`がたどる各モジュールの`pom.xml` |
| 対象の所見 | Trivyが`jar`として検出した、稼働イメージのJavaアーカイブの所見 |
| 対象の依存 | `compile`・`runtime`の依存 |
| 更新対象外の依存 | `test`・`provided`・`system`の依存 |
| 取得元 | Maven Centralのみ |
| モジュールのパス | 設定した依存ディレクトリの下にあるディレクトリへの相対パス |
| モジュール数 | ルートを含め100モジュール以下 |
| モジュールの深さ | `modules`の参照をたどり、ルートを0階層として8階層以下 |
| ルートの継承 | 更新時に全モジュールがルートの`pom.xml`を継承する構成 |
| 版の出所 | 直書き・プロパティ・親のプロパティの上書き・BOMの版のプロパティ・`dependencyManagement`での固定 |

モジュール構成について、次の条件では依存ファイル全体を手動対応にします。

| 条件 | 理由コード |
| --- | --- |
| モジュールのパスが絶対パス・`..`を含むパス・隠しディレクトリ・POMファイル名による指定である | `maven_reactor_unsupported` |
| モジュールの`pom.xml`がない | `maven_reactor_unsupported` |
| 同じ`groupId:artifactId`を複数のモジュールが宣言する | `maven_reactor_unsupported` |
| 親の参照が循環する | `maven_reactor_unsupported` |
| ルートを含め101モジュール以上ある | `maven_reactor_unsupported` |
| ルートから9階層以上のモジュールがある | `maven_reactor_unsupported` |
| ルートの`pom.xml`を継承しないモジュールがある | `maven_reactor_unsupported` |

親POMは、各POMの`parent.relativePath`の指定先と`../pom.xml`を確認します。
片方が正しい親POMでも、もう片方が次の表の手動対応条件に当てはまれば、依存ファイル全体を手動対応にします。

| 見つかった状態・指定 | 判定 |
| --- | --- |
| 親と同じ`artifactId`のPOMがある | `groupId`・`version`の一致と、読み取ったモジュールへの所属が必要 |
| 同じ`artifactId`だが`groupId`・`version`が一致しない | `maven_parent_mismatch`で依存ファイル全体を手動対応 |
| 同じ`artifactId`だが読み取ったモジュールに含まれない | `maven_parent_mismatch`で依存ファイル全体を手動対応 |
| `relativePath`がリポジトリの外を指す | `maven_parent_mismatch`で依存ファイル全体を手動対応 |
| POMがない、または`artifactId`が異なる | その場所では親の一致を確認できないものとして確認を続行 |

たとえば、`relativePath`のPOMが正しくても、`../pom.xml`のPOMが親と同じ`artifactId`で別の`version`なら、依存ファイル全体を手動対応にします。

直接依存の`optional`は省略または`false`を許します。
宣言内容による手動対応は、記述場所と影響範囲で確認してください。

| 記述場所・対象 | 手動対応になる条件 | 更新しない範囲 | 理由コード |
| --- | --- | --- | --- |
| `project/profiles/profile` | 依存・`dependencyManagement`・プロパティ・親・モジュール・リポジトリを変更する | 依存ファイル全体 | `maven_model_unsupported` |
| `project/repositories`・`project/pluginRepositories` | 取得先を宣言する | 依存ファイル全体 | `unsupported_source_settings` |
| ルートの`.mvn` | `maven.config`・`extensions.xml`がある | 依存ファイル全体 | `unsupported_source_settings` |
| `project/dependencies/dependency` | `optional`が`true`または真偽値として読めない値、版の範囲指定、依存宣言の重複のいずれかがある | 依存ファイル全体 | `maven_model_unsupported` |
| `project/dependencyManagement/dependencies/dependency` | `optional`・`exclusions`・版の範囲指定・管理する依存の重複がある | 依存ファイル全体 | `maven_model_unsupported` |
| `project/distributionManagement` | `relocation`がある | 依存ファイル全体 | `maven_model_unsupported` |
| 稼働版・対象の直接依存 | SNAPSHOTである | 対象パッケージ | `maven_model_unsupported` |
| 対象の直接依存の種類 | classifierがある、またはtypeがjar以外である | 対象パッケージ | `maven_model_unsupported` |
| 同じパッケージの稼働版 | 複数の版がある | 対象パッケージ | `multiple_versions` |
| 版の出所 | 変更する場所を決められない | 対象パッケージ | — |

候補と編集方法は[Mavenの候補選定](remediation-maven-logic.md#maven-package-selection)、採用条件は[Mavenの更新結果の検査](remediation-maven-logic.md#maven-update-validation)を参照してください。

## Gradleの依存ファイル {#gradle-inputs}

`gradle.lockfile`とビルド設定を読み、依存の版を決める宣言とlockfileを更新します。
設定した依存ディレクトリで読むファイルは、必要になる条件で分かれます。

| ファイル | 必要になる条件 |
| --- | --- |
| `gradle.lockfile` | 必ず必要 |
| `build.gradle`または`build.gradle.kts` | どちらか1つが必ず必要 |
| `settings.gradle`または`settings.gradle.kts` | どちらか1つが必ず必要 |
| `gradle/wrapper/gradle-wrapper.properties` | 必ず必要 |
| `gradle/libs.versions.toml` | catalogを参照する場合は必須、それ以外でもあれば読み取り |
| `settings-gradle.lockfile` | catalogがある場合は必須、それ以外でもあれば読み取り |
| `gradle.properties` | あれば読み取り |
| `buildscript-gradle.lockfile` | あれば読み取り |

更新対象と実行条件は次のとおりです。

| 項目 | 対応範囲 |
| --- | --- |
| 対象の所見 | Trivyが`jar`として検出した、稼働イメージのJavaアーカイブの所見 |
| 対象の依存 | `gradle.lockfile`の`compileClasspath`・`runtimeClasspath`・`productionRuntimeClasspath`に、所見の名前と稼働版が一致する依存 |
| 依存の取得元 | Maven Centralのみ |
| プラグインの取得元 | Gradle Plugin PortalとMaven Central |
| Gradleの版 | wrapperの`distributionUrl`が指す版と同じ版 |
| `distributionUrl` | `https://services.gradle.org/distributions/gradle-<version>-bin.zip`または`-all.zip` |
| JDK | `java.toolchain`の`languageVersion`で指定した版、宣言がなければ21 |
| 実行環境 | [対応する実行環境](remediation-reference.md#supported-runtimes)にあるGradleの版・JDK・platformの組み合わせ |

lockを有効にする設定と、lockfileに必要な記録は別々に確認します。
条件を満たさなければ、`gradle_locking_unenforced`で依存ファイル全体を手動対応にします。

| 確認する場所 | 必要な内容 |
| --- | --- |
| ビルドスクリプト | `dependencyLocking`ブロックがファイル全体で1回 |
| `dependencyLocking`の中 | `lockAllConfigurations()`と`lockMode = LockMode.STRICT`がそれぞれ1回 |
| `gradle.lockfile` | `compileClasspath`と`runtimeClasspath`のそれぞれが、依存のエントリまたは`empty=`に存在 |

単一プロジェクトが対象です。
次の構成では手動対応になります。

| 条件 | 更新しない範囲 | 理由コード |
| --- | --- | --- |
| `include`・`includeBuild`・`allprojects`・`subprojects`・`buildSrc`・`gradle/dependency-locks`がある | 依存ファイル全体 | `gradle_build_unsupported` |
| GroovyとKotlinのビルドスクリプトが同じディレクトリにある | 依存ファイル全体 | `ambiguous_dependency_files` |
| GroovyとKotlinのsettingsが同じディレクトリにある | 依存ファイル全体 | `ambiguous_dependency_files` |
| 同じパッケージが複数の版で稼働している | 対象パッケージ | `multiple_versions` |

### ビルドスクリプトの書き方 {#gradle-build-forms}

`build.gradle`・`build.gradle.kts`から、依存宣言と更新時に実行できる設定を読み取ります。
ビルドスクリプト・settings・`gradle.properties`・`gradle/libs.versions.toml`は、この節に列挙する書き方だけを受け付けます。

列挙した範囲外の文・引数・設定があれば、依存ファイル全体を手動対応にします。
ビルドスクリプトで受け付ける文と引数は次のとおりで、`<configuration>`は構成名を表します。

| 文 | 対応する書き方 |
| --- | --- |
| `plugins { }` | `java`・`java-library`・`application`は版なし、外部プラグインは[プラグインの許可](#gradle-plugins)のIDと版を直書き |
| `group`・`version`・`description` | 文字列の直書き |
| `java { }` | `toolchain { languageVersion = JavaLanguageVersion.of(N) }`と、`sourceCompatibility`・`targetCompatibility`への文字列・数値・`JavaVersion.VERSION_n`の代入 |
| `repositories { }` | `mavenCentral()`のみ |
| `configurations { }` | `compileOnly { extendsFrom(configurations.annotationProcessor.get()) }`、Groovyでは`compileOnly { extendsFrom annotationProcessor }`も可 |
| `dependencies { }` | `<configuration>("g:a:v")`・`<configuration>("g:a")`・`<configuration>(libs.x)`・`<configuration>(libs.bundles.x)`と、`constraints { }`内の同じ書き方 |
| `dependencyLocking { }` | `lockAllConfigurations()`と`lockMode = LockMode.STRICT`のみ |
| `extra`・`ext` | 名前と値を直書きした、Kotlinの`extra["p"] = "v"`、Groovyの`ext["p"] = "v"`・`ext.p = "v"` |
| `application { }` | `mainClass = "..."`、Kotlinでは`mainClass.set("...")`も可 |

テストタスクのブロックは、Groovy・Kotlinで次のように書けます。
ブロック内で受け付ける処理は`useJUnitPlatform()`だけです。

| 言語 | テストタスクのブロック |
| --- | --- |
| Groovy | `test { }`・`tasks.withType(Test) { }`・`tasks.named("test") { }` |
| Kotlin | `test { }`・`tasks.withType<Test> { }`・`tasks.named<Test>("test") { }`・`tasks.named("test") { }` |

Groovyでは、次の書き方も受け付けます。

| 記述対象 | 対応する書き方 |
| --- | --- |
| 依存宣言 | `implementation 'g:a:v'`のような括弧の省略 |
| `sourceCompatibility`・`targetCompatibility` | トップレベルでの直書き |

依存宣言と`constraints`で使える構成名は次のとおりです。

| 用途 | 構成名 |
| --- | --- |
| アプリケーションの依存 | `implementation`・`api`・`compileOnly`・`runtimeOnly` |
| テストの依存 | `testImplementation`・`testCompileOnly`・`testRuntimeOnly` |
| アノテーション処理 | `annotationProcessor`・`testAnnotationProcessor` |
| Spring Bootプラグインを使う場合の追加宣言 | `developmentOnly` |

直接依存かどうかは、ビルドスクリプトの宣言先の構成と、`gradle.lockfile`で稼働版が記録された構成を、Gradleの標準の構成の継承関係で照合して判定します。
`developmentOnly`の宣言は読み取れますが、標準の継承関係による照合ができないため、そこで宣言したパッケージは手動対応になります。

たとえば、`developmentOnly`で宣言したパッケージの稼働版が`runtimeClasspath`にあっても、そのパッケージは`gradle_build_unsupported`で手動対応になります。
判定条件は[Gradleの候補選定](remediation-gradle-logic.md#gradle-package-selection)を参照してください。

`settings.gradle`・`settings.gradle.kts`では、次の設定を読み取ります。

| 記述対象 | 対応する書き方・扱い |
| --- | --- |
| プロジェクト名 | `rootProject.name = "..."` |
| プラグインの取得先 | `pluginManagement { repositories { } }`内の`gradlePluginPortal()`・`mavenCentral()` |
| settingsのプラグイン | [プラグインの許可](#gradle-plugins)で判定し、許可するプラグインと版の組み合わせはなし |

`gradle.properties`で読み取れるキーと値は次のとおりです。

| キー | 対応する値 |
| --- | --- |
| `org.gradle.parallel`・`org.gradle.caching`・`org.gradle.daemon`・`org.gradle.configuration-cache` | `true`または`false` |
| `org.gradle.jvmargs` | `-Xmx`・`-Xms`・`-XX:MaxMetaspaceSize=`のメモリ指定と`-Dfile.encoding=UTF-8`を空白で区切った値 |
| `.version`で終わるキー | 使用するSpring BootのBOMが定義するプロパティの、版の直書き |

ビルドスクリプトの`extra`・`ext`も、更新時にSpring BootのBOMと親を読み、プロパティ名が定義されていることを確認します。
`gradle.properties`のほかのキー、Javaエージェント、許可したもの以外のJVM引数、行の継続・エスケープ・重複キーは、依存ファイル全体を手動対応にします。

catalogは`gradle/libs.versions.toml`から読み取ります。
読み取れる内容と編集の制限は次のとおりです。

| 項目 | 対応する書き方・扱い |
| --- | --- |
| セクション | `[versions]`・`[libraries]`・`[bundles]`・`[plugins]`のみ |
| ライブラリ | `"g:a:v"`、または`module`か`group`・`name`を持つ表 |
| ライブラリの版 | 文字列の直書き・`version.ref`・省略 |
| bundle | ライブラリの別名の一覧 |
| 別名の衝突 | 同じアクセサーになる別名が重複したら、依存ファイル全体を手動対応 |
| `[plugins]`が参照する`[versions]`の値 | 編集対象外 |
| `alias(libs.plugins.x)`によるプラグインの適用 | 依存ファイル全体を手動対応 |

主な未対応の書き方は次のとおりです。

| 対象 | 未対応の書き方 |
| --- | --- |
| 文・ブロック | `apply from`・`buildscript { }`・`dependencyManagement { }`・`dependencyResolutionManagement { }`・`resolutionStrategy`・`configurations.all` |
| 引数 | 文字列の補間・組み立て、動的な版・版の範囲、依存宣言の`platform(...)` |

### プラグインの許可 {#gradle-plugins}

ビルドスクリプトとsettingsのプラグイン宣言を読み、更新時に実行を許可するプラグインと版を判定します。
許可する組み合わせは次のとおりです。

| プラグイン | 許可する版 | Gradleの版 |
| --- | --- | --- |
| `java`・`java-library`・`application` | 版を指定しない | [対応する実行環境](remediation-reference.md#supported-runtimes)のGradle |
| `org.springframework.boot` | `4.1.2` | `9.8.2` |
| `io.spring.dependency-management` | `1.1.7` | `9.8.2` |
| `org.gradle.toolchains.foojay-resolver-convention`（settings） | 許可する版なし | 許可する組み合わせなし |

外部プラグインは、動作を確認したプラグイン・版・Gradleの版の組み合わせだけを許可します。
版の文字列が完全に一致しない場合や、表にない組み合わせは、`gradle_plugin_unsupported`で依存ファイル全体を手動対応にします。

Gradleの更新には作業用コンテナ・Podを使い、ビルドスクリプトと許可したプラグインのコードをその中で実行します。
候補と編集方法は[Gradleの候補選定](remediation-gradle-logic.md#gradle-package-selection)、採用条件は[Gradleの更新結果の検査](remediation-gradle-logic.md#gradle-update-validation)を参照してください。

## Node.jsの版宣言 {#node-declarations}

版ファイルと`package.json`の宣言を読み、npm・pnpmの更新に使うNode.jsを選びます。
版ファイルは、Node.js 22のようなmajor版の系列だけを選びます。

実際のminor・patch版には、KestreLynxに組み込まれた対応版の一覧である[対応する実行環境](remediation-reference.md#supported-runtimes)の版を使います。
たとえば、版ファイルの`22.14.0`はNode.js 22を選ぶ指定であり、実行版を`22.14.0`に固定する指定ではありません。

読み取れる宣言と、未対応の指定は次のとおりです。

| 宣言 | 対応する書き方・扱い |
| --- | --- |
| `.nvmrc`・`.node-version` | 最初の空でない行の`22`・`22.14`・`22.14.0`などの数値指定で、先頭の`v`も可 |
| `.nvmrc`のLTS指定 | `lts/*`と、次の一覧にある`lts/`で始まる系列名 |
| `package.json`の`engines.node` | 正確な版、比較演算子、`^`・`~`、ワイルドカードなどの解釈可能な範囲 |
| `package.json`の`devEngines.runtime`・`engines.runtime` | Node.jsを指定するオブジェクトまたは配列と、その版の範囲 |
| `system`・`current`などの指定 | 実行する系列を特定できないため、依存ファイル全体を手動対応 |
| プレリリースを境界に含む範囲 | 未対応のため、依存ファイル全体を手動対応 |
| runtime宣言の`onFail: download` | 未対応のため、依存ファイル全体を手動対応 |

`.nvmrc`から読み取れるLTS系列名とmajor版は次のとおりです。
名前を読み取れても、[対応する実行環境](remediation-reference.md#supported-runtimes)にあるサポート中の系列でなければ更新には使いません。

| LTS系列名 | major版 |
| --- | --- |
| `lts/argon` | 4 |
| `lts/boron` | 6 |
| `lts/carbon` | 8 |
| `lts/dubnium` | 10 |
| `lts/erbium` | 12 |
| `lts/fermium` | 14 |
| `lts/gallium` | 16 |
| `lts/hydrogen` | 18 |
| `lts/iron` | 20 |
| `lts/jod` | 22 |
| `lts/krypton` | 24 |

宣言の組み合わせ方は[Node.jsの選定](remediation-node-python-logic.md#node-selection)を参照してください。

## Pythonの版宣言 {#python-declarations}

`pyproject.toml`とPythonの版ファイルを読み、uvのlockfile生成に使うPythonを選びます。
`.python-version`は、Python 3.13のようなX.Yの系列だけを選びます。

実際のpatch版には、[対応する実行環境](remediation-reference.md#supported-runtimes)の版を使うため、記載したpatch版より新しい場合も古い場合もあります。
読み取れる宣言と、未対応の指定は次のとおりです。

| 宣言 | 対応する書き方・扱い |
| --- | --- |
| `pyproject.toml`の`[project].requires-python` | `>=3.12,<3.15`などの解釈可能なPython版の条件 |
| `.python-version` | 最初の空でない行の`3.13`・`3.13.5`などの指定 |
| CPythonの接頭辞 | `cpython-3.13`・`cpython@3.13`など |
| `.python-versions` | 複数版の指定は未対応のため、依存ファイル全体を手動対応 |
| PyPy・GraalPy・Pyodide・`system` | 未対応のため、依存ファイル全体を手動対応 |
| free-threaded版 | 未対応のため、依存ファイル全体を手動対応 |

`.python-version`と`requires-python`は整合している必要があり、実際に使うPythonの版も`requires-python`を満たす必要があります。
版ファイルがない場合の選び方を含む条件は[uv用Pythonの選定](remediation-node-python-logic.md#uv-python-selection)を参照してください。

## ツールの版宣言 {#tool-declarations}

`package.json`と`pyproject.toml`の宣言を読み、更新に使うパッケージマネージャーの版を選びます。
読み取れる宣言は次のとおりです。

| 宣言 | 対応する書き方 |
| --- | --- |
| `package.json`の`packageManager` | `npm@11.21.0`・`pnpm@11.28.5`などのマネージャー名と正確な版 |
| `packageManager`のハッシュ | `name@version+<algorithm>.<hex>` |
| ハッシュのアルゴリズム | `sha1`・`sha224`・`sha256`・`sha384`・`sha512` |
| `package.json`の`devEngines.packageManager` | マネージャー名と、正確な版または解釈可能な範囲 |
| `package.json`の`engines.npm`・`engines.pnpm` | 正確な版または解釈可能な範囲 |
| `pyproject.toml`の`tool.uv.required-version` | `==0.13.0`などの正確な版、または解釈可能な範囲 |
| プレリリース・ビルドメタデータ付きのツール版 | 未対応 |

既定の版は、プロジェクトに版の宣言がないときに使う版です。
範囲だけを宣言した場合の扱いは[ツール版の選定](remediation-node-python-logic.md#tool-version-selection)を参照してください。

| ツール | 扱える版 | 既定の版 |
| --- | --- | --- |
| npm | major版9〜12で、選んだNode.jsと互換性がある版 | `11.21.0` |
| pnpm | major版9〜12で、選んだNode.jsと互換性がある版（12は`12.10.0`以上） | `11.28.5` |
| uv | `0.12.22`以上で、プレリリース・ビルドメタデータ・接頭辞のない`X.Y.Z`の安定版（版番号の上限なし） | `0.13.0` |
| pip | 作業用の公式Pythonイメージに含まれる版 | Python 3.13の作業用イメージでは`26.2.2` |

版番号の条件を満たしても、[ツールの取得と照合](remediation-node-python-logic.md#tool-verification)と[ツール公開後の待機](remediation-node-python-logic.md#tool-release-age)の条件を満たす必要があります。
宣言版と既定版の選び方は[ツール版の選定](remediation-node-python-logic.md#tool-version-selection)を参照してください。
