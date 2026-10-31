# 他のツールとの比較 {#comparison}

- 脆弱性を直すための更新について、何を直せるか、どう更新するか、更新前後に何を確かめるかで比較する

## 比較ツール {#tools}

- 比較対象は、コンテナで使うイメージや依存パッケージの脆弱性を直すためにファイルやイメージを変更できるOSSとする
- 商用サービスは作者が機能を実際に確認できないため、比較対象に含めず紹介だけにとどめる

| ツール | 何をするツールか | ライセンス |
| --- | --- | --- |
| [KestreLynx](remediation.md) | 稼働中のコンテナのイメージで検出した脆弱性に対し、修正計画と更新PRで更新を提案する | [AGPL-3.0](https://github.com/kitsunetrail/kestrelynx/blob/main/LICENSE) |
| [Dependabot](https://github.com/dependabot/dependabot-core) | リポジトリのファイルに記録された依存パッケージを更新するPRを作るGitHubの機能 | [dependabot-core](https://github.com/dependabot/dependabot-core)はMIT |
| [Renovate](https://github.com/renovatebot/renovate) | リポジトリのファイルに記録された依存パッケージを更新するPRを作る | [AGPL-3.0](https://github.com/renovatebot/renovate) |
| [Copacetic](https://github.com/project-copacetic/copacetic) | コンテナイメージ内のパッケージにパッチを当てたイメージを作る | [Apache-2.0](https://github.com/project-copacetic/copacetic) |
| [OSV-Scanner](https://github.com/google/osv-scanner) | OSVの情報で既知の脆弱性を検出し、修正機能（`osv-scanner fix`）で依存ファイルを更新する | [Apache-2.0](https://github.com/google/osv-scanner/blob/main/LICENSE) |

- 比較表に入れない商用の選択肢
    - [Snyk Container](https://snyk.io/product/container-vulnerability-management/)はコンテナイメージの脆弱性をスキャンし、ベースイメージの更新を提案する
    - [Docker Scout](https://docs.docker.com/scout/)はイメージに含まれる構成要素を解析し、脆弱性データと照合する
    - [Socket](https://socket.dev/)はオープンソースの依存パッケージとその更新を解析し、悪意ある動作などを調べる

## 修正対象 {#fix-targets}

| ツール | 配布イメージのタグ | Dockerfileのベースイメージ（`FROM`） | イメージ内のOSパッケージへの直接パッチ | 言語パッケージ |
| --- | --- | --- | --- | --- |
| [KestreLynx](remediation-reference.md#supported-targets) | 同じメジャー・マイナー版内のみ：Compose・Kubernetes・Kustomize・Helm values | 同じメジャー・マイナー版内のみ | 対応なし：イメージやベースイメージを更新 | npm・pnpm・pip・uv・Goのみ |
| [Dependabot](https://docs.github.com/en/code-security/reference/supply-chain-security/supported-ecosystems-and-repositories) | 対応：Compose・Kubernetes・Helm | 対応 | 対応なし | npm・pnpm・pip・uv・Goほか、[対応一覧](https://docs.github.com/en/code-security/reference/supply-chain-security/supported-ecosystems-and-repositories)を参照 |
| [Renovate](https://docs.renovatebot.com/modules/manager/) | 対応：Compose・Kubernetes・Kustomize・Helm values | 対応 | 対応なし | npm・pnpm・pip・uv・Goほか、[対応一覧](https://docs.renovatebot.com/modules/manager/)を参照 |
| [Copacetic](https://project-copacetic.github.io/copacetic/website/faq) | 対応なし | 対応なし | 対応：DPKG・RPM・APK | npm・pip・Go・.NET（実験的） |
| [OSV-Scanner](https://google.github.io/osv-scanner/experimental/guided-remediation/) | 対応なし | 対応なし | 対応なし | npm・Mavenのみ（実験的）：npmの`package-lock.json`・`package.json`、Mavenの`pom.xml` |

- Dependabot・Renovateはリポジトリ内の記載を更新し、稼働イメージ内の有無は見ない
- KestreLynxは稼働イメージで脆弱性を検出したパッケージのGitHub依存ファイルを更新する
- KestreLynxは配布イメージの浮動タグ（`latest`など）を[再取得の案内（更新PRなし）](remediation-logic.md#published-image-tags)の対象として扱う

## 更新方法 {#update-methods}

最後の列は、更新後に稼働するイメージの確認を指します。
表は各ツール自体の処理を示し、外部スキャナや別の自動処理による確認は含めません。

| ツール | 処理のきっかけ | 変更するもの | 更新PR作成前の脆弱性確認 | 作成・通知するもの | 更新後の脆弱性確認 |
| --- | --- | --- | --- | --- | --- |
| [KestreLynx](remediation.md) | 稼働中のイメージで検出した脆弱性 | リポジトリ内のイメージ指定・言語パッケージの依存ファイル | 更新前後のスキャン結果を比較 | 修正計画・更新PR・通知 | 次の定期スキャンで確認 |
| [Dependabot](https://github.com/dependabot/dependabot-core) | 新しい版／GitHubの脆弱性警告 | リポジトリ内のイメージ指定・言語パッケージの依存ファイル | イメージの比較スキャンはしない | 更新PR | 適用後のイメージは確認しない |
| [Renovate](https://github.com/renovatebot/renovate) | 新しい版／パッケージの脆弱性情報 | リポジトリ内のイメージ指定・言語パッケージの依存ファイル | イメージの比較スキャンはしない | 更新PR | 適用後のイメージは確認しない |
| [Copacetic](https://github.com/project-copacetic/copacetic) | イメージとスキャン結果／パッケージ更新 | イメージ内のパッケージ | 対象外（更新PRを作らない） | パッチを当てたイメージ | 適用後のイメージは確認しない |
| [OSV-Scanner](https://google.github.io/osv-scanner/experimental/guided-remediation/) | 既知の脆弱性（OSVデータベース） | npmの`package-lock.json`・`package.json`、Mavenの`pom.xml` | 対象外（更新PRを作らない） | 更新した依存ファイル、解消した脆弱性と残りの件数の表示 | 適用後のイメージは確認しない |

- イメージ更新では、KestreLynxは[現在と更新先のイメージのスキャン結果を比較](remediation-logic.md#verification-scope)する
- 言語パッケージ更新では、KestreLynxは変更前後の依存ファイルのスキャン結果を比較する
- Dependabot・Renovateも対応するパッケージの更新に公開脆弱性情報を使うが、現在と更新先のイメージの比較スキャンはしない

## 例：nginxの脆弱性を直すまでの各ツールの動作 {#example}

`compose.yml`で`nginx:1.27.0`を指定して動かしているコンテナに、修正版のある脆弱性が見つかった場面を考えます。

以下は各ツールで必要な機能を有効にした場合の動きです。
KestreLynxの更新PR作成は設定で有効にした場合だけで、既定では無効です。

- KestreLynx
    - [デモの更新PR #1](https://github.com/kitsunetrail/kestrelynx-demo/pull/1)を作る前に、次の順で確認
        - 稼働中の`nginx:1.27.0`と更新先の`nginx:1.27.5`を、重大度がHIGH・CRITICALの脆弱性を対象にスキャン
        - 結果を比較し、更新で直す対象の脆弱性のうち17件が検出されなくなり、86件が残ることを確認
        - 確認した重大度の範囲で、更新先に新しく出る脆弱性が0件であることを確認
    - 比較結果を載せ、`compose.yml`の`services.proxy.image`を`nginx:1.27.5`へ書き換える更新PRを作成
    - その後、利用者が更新PRをマージし、稼働中の`proxy`コンテナをnginx 1.27.5に入れ替え
    - KestreLynxは次のスキャンで4パッケージの脆弱性の解消を通知
    - KestreLynxの作者がその結果を[デモの紹介](../index.md)に掲載
- Dependabot
    - [Composeファイル内のイメージの版を更新する設定](https://docs.github.com/en/code-security/reference/supply-chain-security/supported-ecosystems-and-repositories)にすると、新しいnginxの版を探し、`compose.yml`の`image:`を書き換える更新PRを作る
- Renovate
    - `compose.yml`の`image:`を読み、設定した更新範囲に入る[新しいnginxの版](https://docs.renovatebot.com/docker/)を探して更新PRを作る
- Copacetic
    - nginxのイメージと、その中のOSパッケージの脆弱性を特定したスキャンレポートを渡すと、[そのパッケージにパッチを当てたイメージを作る](https://project-copacetic.github.io/copacetic/website/quick-start)
    - できたイメージのスキャンと動作確認、`compose.yml`の`image:`の変更、稼働中のコンテナの入れ替えは利用者が行う
- OSV-Scanner
    - [`osv-scanner fix`](https://google.github.io/osv-scanner/experimental/guided-remediation/)は`compose.yml`のnginxのイメージタグを書き換えない
    - リポジトリにnpm・Mavenの依存ファイルがある場合は、`osv-scanner fix`がそのファイルを更新して依存パッケージの脆弱性を修正する

## KestreLynxの範囲と制約 {#scope-and-limits}

- Docker・Kubernetesで見つけた時点に稼働しているコンテナだけを監視し、詳しい対象は[スキャン範囲](scan-logic.md#scan-targets)に記載
- この監視は、CIでのスキャンの代わりにはならない
- 修正計画と更新PRは実験的な機能で既定では無効とし、有効化の方法は[設定手順](remediation-setup.md)に記載
- ファイルを書き換えるには稼働中のコンテナとGitHubリポジトリのファイルの対応付けを設定する必要があり、対応形式と条件は[リファレンス](remediation-reference.md)に記載
- 言語パッケージの取得元は公開npm・公開PyPI・公開Go module proxyと`sum.golang.org`のみ
- 更新前の比較では再ビルドしたアプリケーション全体のイメージや動作は確認せず、詳細は[更新先の確認範囲](remediation-logic.md#verification-scope)に記載

## 他のツールの補足 {#tool-notes}

- Dependabot
    - [Version updates](https://docs.github.com/en/code-security/concepts/supply-chain-security/dependabot-version-updates)はリポジトリのファイルを定期的に調べ、新しい版への更新PRを作る機能
    - [Security updates](https://docs.github.com/en/code-security/concepts/supply-chain-security/dependabot-security-updates)は、使用パッケージの既知の脆弱性を知らせるGitHubの警告「Dependabotアラート」を受けて更新PRを作る機能
    - Dockerfile・ComposeのDockerイメージはversion updatesに対応し、[security updatesは対象外](https://docs.github.com/en/code-security/reference/supply-chain-security/supported-ecosystems-and-repositories)
- Renovate
    - [`vulnerabilityAlerts`](https://docs.renovatebot.com/configuration-options/#vulnerabilityalerts)はGitHubのDependabotアラートを使う機能
    - [`osvVulnerabilityAlerts`](https://docs.renovatebot.com/configuration-options/#osvvulnerabilityalerts)はOSVの脆弱性情報を使う実験的な機能で、Dockerイメージは対象外
    - 対応形式と設定は[公式資料](https://docs.renovatebot.com/modules/manager/)に記載
- Copacetic
    - OSパッケージへのパッチは[DPKG・RPM・APK](https://project-copacetic.github.io/copacetic/website/faq)に対応する
    - [アプリケーションの依存パッケージへのパッチ](https://project-copacetic.github.io/copacetic/website/app-level-patching)は実験的な機能で、npm・pip・Go・.NETに対応する
    - Goの依存ファイルを更新するだけでは、既存の実行ファイルの脆弱性は直らない
    - [実験的なGo実行ファイルの再ビルド](https://project-copacetic.github.io/copacetic/website/app-level-patching#experimental-go-binary-rebuilding)には、取得可能な公開ソースコードが必要
    - pnpm・uvには対応しない
- OSV-Scanner
    - [guided remediation（`osv-scanner fix`）](https://google.github.io/osv-scanner/experimental/guided-remediation/)は実験的な修正機能
    - npmの[`in-place`](https://google.github.io/osv-scanner/experimental/guided-remediation/#in-place-lockfile-changes)は既存のバージョン制約内でロックファイルを更新する
    - npmの[`relock`](https://google.github.io/osv-scanner/experimental/guided-remediation/#relock-and-relax-direct-dependencies)は`package.json`から依存関係全体を再計算する
    - Mavenの[`override`](https://google.github.io/osv-scanner/experimental/guided-remediation/#override-dependency-versions)は`pom.xml`で直接依存のバージョンを更新するか、`<dependencyManagement>`で依存パッケージのバージョンを上書きする
    - [`node_modules`は入れ直さないため、利用者が別途`npm ci`を実行する](https://google.github.io/osv-scanner/experimental/guided-remediation/#basic-usage)

## 参照した公式資料 {#references}

確認日：2026-10-30

- KestreLynx
    - [概要](remediation.md)、[設定手順](remediation-setup.md)、[更新先の確認と更新PRの管理](remediation-logic.md)
    - [結果の読み方](remediation-results.md)、[対応する入力形式](remediation-reference.md)、[スキャン範囲](scan-logic.md)、[履歴と解消の判定](diff-logic.md)
    - [デモの更新PR #1](https://github.com/kitsunetrail/kestrelynx-demo/pull/1)、[コンテナ入れ替え後のデモ結果](../index.md)
    - [修正対象](remediation-reference.md#supported-targets)、[範囲と要件](remediation-reference.md#scope-and-requirements)、[対応するファイル形式](remediation-reference.md#supported-inputs)
    - [docker runのコンテナ](remediation-reference.md#docker-run-containers)、[Node.jsの版の指定ファイル](remediation-reference.md#node-declarations)、[ベースイメージとの対応](remediation-logic.md#base-layer-matching)、[Kubernetesの作業用Pod](remediation-setup.md#kubernetes-language-updates)
- Trivy
    - [コンテナイメージのスキャン](https://trivy.dev/docs/latest/guide/target/container_image/)
- Dependabot
    - [リポジトリとライセンス](https://github.com/dependabot/dependabot-core)、[Version updates](https://docs.github.com/en/code-security/concepts/supply-chain-security/dependabot-version-updates)、[Security updates](https://docs.github.com/en/code-security/concepts/supply-chain-security/dependabot-security-updates)
    - [対応範囲](https://docs.github.com/en/code-security/reference/supply-chain-security/supported-ecosystems-and-repositories)、[更新PRの管理](https://docs.github.com/en/code-security/how-tos/secure-your-supply-chain/manage-your-dependency-security/manage-dependabot-prs)、[更新PRのコメントコマンド](https://docs.github.com/en/code-security/reference/supply-chain-security/dependabot-pull-request-comment-commands)
    - [DockerとKubernetes](https://docs.github.com/en/code-security/reference/supply-chain-security/supported-ecosystems-and-repositories#docker)、[Docker Compose](https://docs.github.com/en/code-security/reference/supply-chain-security/supported-ecosystems-and-repositories#docker-compose)、[Helmチャートとイメージ](https://docs.github.com/en/code-security/reference/supply-chain-security/supported-ecosystems-and-repositories#helm-charts)
- Renovate
    - [リポジトリとライセンス](https://github.com/renovatebot/renovate)、[Dockerの更新](https://docs.renovatebot.com/docker/)
    - [GitHubの脆弱性警告の利用](https://docs.renovatebot.com/configuration-options/#vulnerabilityalerts)、[OSVの脆弱性情報の利用](https://docs.renovatebot.com/configuration-options/#osvvulnerabilityalerts)、[更新PRの照合と再作成](https://docs.renovatebot.com/key-concepts/pull-requests/)
    - [全体の対応一覧](https://docs.renovatebot.com/modules/manager/)、[Docker Compose](https://docs.renovatebot.com/modules/manager/docker-compose/)、[Dockerfile](https://docs.renovatebot.com/modules/manager/dockerfile/)
    - [Kubernetes](https://docs.renovatebot.com/modules/manager/kubernetes/)、[Kustomize](https://docs.renovatebot.com/modules/manager/kustomize/)、[Helm values](https://docs.renovatebot.com/modules/manager/helm-values/)
    - [npmとpnpm](https://docs.renovatebot.com/modules/manager/npm/)、[pip](https://docs.renovatebot.com/modules/manager/pip_requirements/)、[uvとPEP 621](https://docs.renovatebot.com/modules/manager/pep621/)、[Go modules](https://docs.renovatebot.com/modules/manager/gomod/)
- Copacetic
    - [リポジトリとライセンス](https://github.com/project-copacetic/copacetic)、[パッチと確認の手順](https://project-copacetic.github.io/copacetic/website/quick-start)、[アプリケーションの依存パッケージへのパッチ](https://project-copacetic.github.io/copacetic/website/app-level-patching)
    - [対応するOSパッケージ管理](https://project-copacetic.github.io/copacetic/website/faq)、[Goバイナリの再ビルド](https://project-copacetic.github.io/copacetic/website/app-level-patching#experimental-go-binary-rebuilding)、[.NETのパッチ](https://project-copacetic.github.io/copacetic/website/app-level-patching#net)
- OSV-Scanner
    - [リポジトリ](https://github.com/google/osv-scanner)、[ライセンス](https://github.com/google/osv-scanner/blob/main/LICENSE)、[guided remediation](https://google.github.io/osv-scanner/experimental/guided-remediation/)
- 商用サービス
    - [Snyk Container](https://snyk.io/product/container-vulnerability-management/)、[Docker Scout](https://docs.docker.com/scout/)、[Socket](https://socket.dev/)
