---
title: 修正計画と修正PRの対応範囲
---

# 修正計画と修正PRの対応範囲

修正計画と修正PRを利用できる環境、更新対象、入力ファイル、実行環境を確認するページです。
有効化は[修正計画の有効化](remediation-setup.md#enable-fix-plans)を参照してください。

ファイルの種類から調べる場合は、[対応する入力形式](#supported-inputs)を入口にしてください。
調べたいことに応じて、次の節を参照してください。

| 調べたいこと | 節 |
| --- | --- |
| 環境と更新対象 | [対応範囲](#scope-and-requirements) |
| ファイルの書き方 | [対応する入力形式](#supported-inputs) |
| 実行環境の版 | [対応する実行環境](#supported-runtimes) |

このページで使う用語は[用語](remediation.md#terms)を参照してください。

## 対応範囲 {#scope-and-requirements}

修正計画で候補を確認できる対象と、修正PRでファイルを更新できる対象を示します。

### 利用環境 {#supported-environments}

動作条件と、作業用コンテナの条件を示します。

| 項目 | 条件 |
| --- | --- |
| コンテナ環境 | Docker・Kubernetesモードで計画とPR作成をサポート |
| ソースホスト | GitHub |
| 作業用コンテナのアーキテクチャ | Linuxの`amd64`・`arm64`（Gradleの制限は[対応する実行環境](#supported-runtimes)を参照） |
| 言語更新の実行環境 | [対応する実行環境](#supported-runtimes)に記載した版 |
| Sensor | 不要 |

環境ごとの対象と、指定できるファイルを示します。

| 稼働しているもの | `workload`の書き方 | 対応付けられるファイル |
| --- | --- | --- |
| Composeのサービス | `compose/<project>/<service>` | Compose（`compose`）、Dockerfile（`dockerfile`）、依存ディレクトリ（`dependencies`） |
| Composeを使わないDockerコンテナ | `container/<名前>` | Dockerfile（`dockerfile`）、依存ディレクトリ（`dependencies`） |
| Kubernetesのコンテナ | `<kind>/<namespace>/<name>/<container>` | マニフェスト（`manifest`）、Kustomize（`kustomize`）、Helmのvalues（`helm_values`）、Dockerfile（`dockerfile`）、依存ディレクトリ（`dependencies`） |

依存ディレクトリには、依存宣言やlockfileを置くディレクトリを指定します。
読み取るファイルと範囲は、[対応する入力形式](#supported-inputs)から各マネージャーの節を参照してください。

Kubernetesのイメージタグは、同じ`workload`を指定する対応付け全体で、`manifest`・`kustomize`・`helm_values`のうち1種類だけで管理します。
各値の書き方は[ソースの対応付け](configuration.md#remediation-mappings)を参照してください。

Kubernetesで計画に出る内容、PRで更新できるファイル、作業用Podの要否を示します。

| 更新対象 | 計画 | PR | 作業用Podの要否 |
| --- | --- | --- | --- |
| 配布イメージ | 更新候補 | 通常のマニフェストのイメージタグ | 不要 |
| 配布イメージ（Kustomize） | 更新候補 | `images[].newTag` | 不要 |
| 配布イメージ（Helmのvalues） | 更新候補 | valuesのイメージタグ | 不要 |
| Dockerfileのベースイメージ | 更新候補 | Dockerfileの`FROM` | 不要 |
| 浮動タグの再取得 | 再取得の案内 | 作成なし | 不要 |
| Mavenの依存パッケージ | 更新候補 | `pom.xml` | 不要 |
| npm・pnpm・pip・uv・Go・Gradleの依存パッケージ | 更新候補 | 各ツールの依存ファイル | 必要 |

作業用Podが必要な更新は、[作業用Podの準備](remediation-setup-work-pods.md#kubernetes-language-updates)を参照してください。

### docker runのコンテナ {#docker-run-containers}

`container/<名前>`の対応付けでは、Dockerfileのベースイメージと依存パッケージを更新できます。
起動時のイメージタグを変更するPRは作りません。

各サイクルでは、次の条件で対象を確認します。

- 各サイクルのコンテナ一覧取得時に稼働しているコンテナが対象
- `--rm`で短時間だけ動くジョブは対象にならない場合がある
- 改名・作り直しは次のサイクルから反映され、改名した場合は対応付けの`workload`も変更が必要

実行時刻は`schedule.daily_at`で指定し、未指定なら24時間ごとに実行します（[スケジュール](configuration.md#schedule)）。
同じタグを別のイメージに付け替えた後も動いている古いコンテナの扱いは、操作とイメージストアで異なります。

| 操作 | イメージストア | 古いコンテナの扱い |
| --- | --- | --- |
| 同じタグで`docker build`し直す | containerdのイメージストアを使用 | 古いイメージが消えるため、スキャン・修正計画の対象外 |
| 同じタグで`docker build`し直す | containerdのイメージストアを不使用（overlay2） | 古いイメージが残るため、スキャン・修正計画の対象 |
| `docker tag`でタグを付け替える | containerd・overlay2 | スキャン・修正計画の対象 |

containerdのイメージストアで古いイメージが消えた場合は、新しいイメージでコンテナを作り直すと対象になります。
設定例は[docker runのコンテナの対応付け](remediation-setup-docker.md#docker-run-mappings)を参照してください。

### 更新対象 {#supported-targets}

更新対象ごとに、取得元とソースの対応付けが必要になる段階を示します。

| 更新対象 | 指定箇所・対象ファイル | 取得元 | ソースの対応付け |
| --- | --- | --- | --- |
| 配布イメージ | コンテナの起動に指定するイメージ | 公開レジストリ・認証を設定した非公開レジストリ | PRに必要 |
| ベースイメージ | Dockerfileの`FROM`に指定するイメージ | 公開レジストリ・認証を設定した非公開レジストリ | 計画に必要 |
| npm・pnpmの依存パッケージ | 依存ディレクトリ | 公開npmレジストリ | 計画に必要 |
| pip・uvの依存パッケージ | 依存ディレクトリ | 公開PyPI | 計画に必要 |
| Goの依存モジュール | 依存ディレクトリ | 公開のGo module proxy（`proxy.golang.org`）・`sum.golang.org` | 計画に必要 |
| Mavenの依存パッケージ | `pom.xml` | Maven Central | 計画に必要 |
| Gradleの依存パッケージ | `gradle.lockfile` | Maven Central | 計画に必要 |

配布イメージの比較結果は対応付けなしで表示でき、PRにはCompose・Kubernetesマニフェスト・Kustomize・Helmのvaluesの対応付けが必要です。
ベースイメージの計画にはDockerfileまたはCompose、依存パッケージの計画には依存ディレクトリを対応付けます。

非公開npmレジストリ・非公開PyPI・非公開Goモジュールは更新対象にできません。
イメージレジストリの認証は、依存パッケージの取得には使いません。

## 対応する入力形式 {#supported-inputs}

ファイルの種類ごとに、読み取れる記述と更新できる範囲を説明している節を案内します。

| ファイル | 形式の説明 |
| --- | --- |
| Composeファイル | [Composeの形式](remediation-source-formats.md#compose-formats) |
| Kubernetesマニフェスト | [マニフェストの形式](remediation-source-formats.md#manifest-formats) |
| Kustomizeファイル | [Kustomizeの形式](remediation-source-formats.md#kustomize-formats) |
| Helmのvaluesファイル | [Helmのvaluesの形式](remediation-source-formats.md#helm-values-formats) |
| Dockerfile | [Dockerfileの形式](remediation-source-formats.md#dockerfile-formats) |
| `package.json`・`package-lock.json` | [npmの依存ファイル](remediation-dependency-formats.md#npm-inputs) |
| `package.json`・`pnpm-lock.yaml`・`pnpm-workspace.yaml` | [pnpmの依存ファイル](remediation-dependency-formats.md#pnpm-inputs) |
| `requirements.txt` | [pipの依存ファイル](remediation-dependency-formats.md#pip-inputs) |
| `pyproject.toml`・`uv.lock` | [uvの依存ファイル](remediation-dependency-formats.md#uv-inputs) |
| `go.mod`・`go.sum` | [Goの依存ファイル](remediation-dependency-formats.md#go-inputs) |
| `pom.xml` | [Mavenの依存ファイル](remediation-dependency-formats.md#maven-inputs) |
| `gradle.lockfile`・ビルドスクリプトなど | [Gradleの依存ファイル](remediation-dependency-formats.md#gradle-inputs) |
| `.nvmrc`・`.node-version`・`package.json` | [Node.jsの版宣言](remediation-dependency-formats.md#node-declarations) |
| `.python-version`・`pyproject.toml` | [Pythonの版宣言](remediation-dependency-formats.md#python-declarations) |
| `package.json`・`pyproject.toml` | [ツールの版宣言](remediation-dependency-formats.md#tool-declarations) |

## 対応する実行環境 {#supported-runtimes}

KestreLynxに組み込まれた対応版の一覧として、サポート中の系列と実行版、サポート終了日を示します。
依存パッケージの更新処理に使うNode.js・Python・Goは、一覧にあるサポート中の系列から選びます。

| 系列 | 実行版 | サポート終了日 | platform |
| --- | --- | --- | --- |
| Node.js 22 | `22.23.5` | 2027-04-30 | `linux/amd64`・`linux/arm64` |
| Node.js 24 | `24.22.3` | 2028-04-30 | `linux/amd64`・`linux/arm64` |
| Node.js 26 | `26.13.1` | 2029-04-30 | `linux/amd64`・`linux/arm64` |
| Python 3.11 | `3.11.18` | 2027-10-31 | `linux/amd64`・`linux/arm64` |
| Python 3.12 | `3.12.16` | 2028-10-31 | `linux/amd64`・`linux/arm64` |
| Python 3.13 | `3.13.18` | 2029-10-31 | `linux/amd64`・`linux/arm64` |
| Python 3.14 | `3.14.10` | 2030-10-31 | `linux/amd64`・`linux/arm64` |
| Python 3.15 | `3.15.2` | 2031-10-31 | `linux/amd64`・`linux/arm64` |
| Go 1.26 | `1.26.11` | 2027-02-10 | `linux/amd64`・`linux/arm64` |
| Go 1.27 | `1.27.4` | 2027-08-19 | `linux/amd64`・`linux/arm64` |
| Gradle 8 / JDK 21 | `8.14.6` | 終了日の設定なし | `linux/amd64` |
| Gradle 9 / JDK 17・21 | `9.8.2` | 終了日の設定なし | `linux/amd64` |

版と期限はKestreLynxが持つ情報であり、KestreLynxの更新に伴って変わります。
Gradleは、表に記載した実行版とJDKを使う`linux/amd64`だけをサポートします。

それ以外のGradleの版・JDK・platformでは、手動対応になります。
理由コードは`gradle_version_unsupported`または`gradle_toolchain_unsupported`です。

Gradleの統合テストはKestreLynxの開発者が実施し、合格したイメージのdigestを対応版の一覧に記録しています。
利用者が記録を追加・設定する必要はなく、KestreLynxは実行するplatformの記録があるイメージだけを使います。

用途ごとの既定の実行環境と、宣言に従って選ぶ場合を示します。

| 用途 | 既定の実行環境 |
| --- | --- |
| Node.jsの宣言がないnpm・pnpm更新 | LTSに入っている最新の系列（今はNode.js 26） |
| pip更新の作業用コンテナ | Python 3.13 |
| uv更新 | Pythonの宣言に従って選定 |
| Go更新 | [Goの選定](remediation-go-logic.md#go-runtime-selection)を参照 |
| Gradle更新 | wrapperと同じGradleの版と、toolchainで指定したJDK（宣言がなければ21） |

Node.jsの宣言がない場合、2026-10-28にLTSに入ったNode.js 26が現在の最初の候補です。
パッケージマネージャーとの互換条件を満たさない場合は、ほかのサポート中の系列を新しい順に調べます。

詳しい選定条件は[Node.jsの選定](remediation-node-python-logic.md#node-selection)を参照してください。

対応版の一覧に残っている、サポートが終わった系列を示します。

| サポートが終わった系列 | サポート終了日 |
| --- | --- |
| Node.js 20 | 2026-04-30 |
| Python 3.9 | 2025-10-31 |
| Python 3.10 | 2026-10-01 |

サポート期限を過ぎた系列は更新に使いません。
選定条件は[実行環境の選定](remediation-package-logic.md#runtime-and-tool-versions)を参照してください。
