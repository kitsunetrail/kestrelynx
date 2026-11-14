# 外向きの通信

KestreLynxの通信先、外へ送る情報、認証情報の送付範囲、作業用コンテナのネットワークを説明します。

通信するプログラムの役割と実行場所は次のとおりです。

| 通信するプログラム | 役割 | 実行場所 |
| --- | --- | --- |
| KestreLynx | スキャンの管理、公開情報の取得、[修正計画](remediation.md#overview)の作成、通知 | KestreLynx本体のコンテナ |
| Trivy | イメージや依存ファイルの脆弱性を検査 | KestreLynx本体と同じコンテナ |
| 作業用コンテナ | パッケージマネージャーで依存ファイルを更新 | 対象のDockerホスト、またはKubernetesの作業用Pod |
| コンテナランタイム（Docker本体や、Kubernetesノードのcontainerdなど） | 作業用コンテナで必要となるイメージを取得 | Dockerホスト、またはKubernetesノード |

既定の公開データ取得先とGitHub・Slack APIのURLは、HTTPS（TCP 443）を使います。
ミラー・Webhook・レジストリ・メールの接続先やポートは設定で変わります。

## 通信先一覧 {#outbound-communication}

KEVは、CISAが公開する、悪用が確認された脆弱性の一覧です。
EPSSは、脆弱性について今後30日以内に悪用活動が観測される確率の推定値です。

有効な機能と各回に必要な処理に応じた通信の条件、および外へ送る利用者の環境の情報を示します。

| 通信 | 通信が起きる条件 | 外へ送る利用者の環境の情報 |
| --- | --- | --- |
| [KEVの取得](#kev-download) | [`triage.enabled`](configuration.md#triage)が有効（既定有効） | なし |
| [EPSSの取得](#epss-download) | [`triage.enabled`](configuration.md#triage)が有効（既定有効） | なし |
| [Node.jsのセキュリティ情報](#node-runtime-download) | [`scan.node_runtime.enabled`](configuration.md#scan)が有効（既定有効） | なし |
| [Pythonのセキュリティ情報](#python-runtime-download) | [`scan.python_runtime.enabled`](configuration.md#scan)が有効（既定有効） | なし |
| [Hacker Newsの検索](#hacker-news-search) | [`triage.enabled`・`triage.discussion_links`](configuration.md#triage)が有効（各既定有効） | 検索対象のCVE ID |
| [Trivyの取得通信](#trivy-downloads) | [スキャンを実行するたび](configuration.md#schedule) | 取得するイメージの名前・タグ・digest |
| [GitHubへの通信](#github-communication) | 読み取りは[修正計画](configuration.md#remediation-basics)が有効、書き込みは修正計画と修正PRの両方が有効（各既定無効） | リポジトリ・ソースの指定、PRの内容 |
| [イメージ候補の取得](#candidate-registry-communication) | [修正計画](configuration.md#remediation-basics)が有効（既定無効） | イメージ名・タグ・digest |
| [作業用イメージの取得](#worker-image-downloads) | [修正計画と修正PRの両方](configuration.md#remediation-basics)が有効で依存更新を実行（各既定無効） | 作業用イメージの名前・digest |
| [ツールの取得](#tool-downloads) | [修正計画と修正PRの両方](configuration.md#remediation-basics)が有効で依存更新を実行（各既定無効） | ツール名・版 |
| [依存パッケージの取得](#dependency-downloads) | [修正計画と修正PRの両方](configuration.md#remediation-basics)が有効で依存更新を実行（各既定無効） | パッケージ名・版 |
| [通知先への送信](#notification-delivery) | [通知先を設定](configuration.md#notify-destinations)し、送信条件を満たす（既定の通知先なし） | 脆弱性の検出結果、修正計画、PRの情報 |

### KEVの取得 {#kev-download}

トリアージは、悪用情報と深刻度から対応の優先度を決める処理です。

トリアージが有効で、フィードの取得・更新が必要な場合に、KestreLynxがKEVフィードを一括取得します。
取得先は既定で`www.cisa.gov`です。

検出したCVEとの照合はローカルで行い、検出したCVE一覧は取得先へ送りません。
取得先は[優先順位付けの設定](configuration.md#triage)、更新と失敗時の扱いは[脅威情報の更新](scan-logic.md#intel-cache)と[脅威情報を利用できない場合](scan-logic.md#degraded-triage)を参照してください。

### EPSSの取得 {#epss-download}

トリアージが有効で、フィードの取得・更新が必要な場合に、KestreLynxがEPSSフィードを一括取得します。
取得先は既定で`epss.empiricalsecurity.com`です。

検出したCVEとの照合はローカルで行い、検出したCVE一覧は取得先へ送りません。
取得先は[優先順位付けの設定](configuration.md#triage)、更新と失敗時の扱いは[脅威情報の更新](scan-logic.md#intel-cache)と[脅威情報を利用できない場合](scan-logic.md#degraded-triage)を参照してください。

### Node.jsのセキュリティ情報の取得 {#node-runtime-download}

Node.js本体の照合が有効で、データの取得・更新が必要な場合に、次の公開データを取得します。
表の「系列」は、`22.x`のような、同じメジャー版のまとまりです。

| 通信するプログラム | 通信先 | 取得する情報 |
| --- | --- | --- |
| KestreLynx | `raw.githubusercontent.com` | CVE・深刻度・影響範囲・修正範囲を含む`nodejs/security-wg`のNode.js本体の脆弱性索引全件 |
| KestreLynx | `nodejs.org` | セキュリティブログの記事一覧のRSS |
| KestreLynx | `raw.githubusercontent.com` | `nodejs/nodejs.org`にある記事本文のMarkdown |
| KestreLynx | `nodejs.org` | リリース日を含む`dist/index.json`全件 |
| KestreLynx | `raw.githubusercontent.com` | 系列ごとのサポート終了日を含む`nodejs/Release`の`schedule.json`全件 |

索引の更新はリリースから数週間以上遅れることがあるため、[Node.js本体の検出結果](scan-logic.md#node-runtime)に記載した条件でセキュリティブログの記事を使って補います。

公開データとの照合はローカルで行い、イメージの情報や検出したCVEは取得先へ送りません。
有効・無効は[スキャンの設定](configuration.md#scan)、更新は[脅威情報の更新](scan-logic.md#intel-cache)、失敗時は[言語ランタイムのセキュリティ情報の利用不能時の扱い](scan-logic.md#node-runtime-unavailable)を参照してください。

### Pythonのセキュリティ情報の取得 {#python-runtime-download}

Python本体の照合が有効な場合、Python Software Foundation（PSF）などの公開データを次の取得先から取得します。

| 通信するプログラム | 通信先 | 取得する情報 |
| --- | --- | --- |
| KestreLynx | `codeload.github.com` | アドバイザリー一覧を含むPSFの`advisory-database`の`tar.gz`全体 |
| KestreLynx | `raw.githubusercontent.com` | PSFの一覧にある全CVEの公式レコード（`CVEProject/cvelistV5`） |
| KestreLynx | `www.python.org` | 系列ごとの最終版を含むリリース一覧のAPIデータ全件 |
| KestreLynx | `peps.python.org` | 系列ごとのサポート終了状態を含むリリースサイクル全件 |

データの取得・更新が必要な場合に通信し、CVEレコードは取得・再検証が必要な場合に通信します。
公式レコードからは、PSFが記載したCPythonの版の範囲と対象OS、深刻度、`REJECTED`の状態を読み取ります。

公開データは全件を取得してローカルで照合し、イメージの情報や検出したCVEは取得先へ送りません。
CVEレコードの要求に含めるCVE IDはPSFの一覧で決まり、イメージの検出結果から選びません。

有効・無効は[スキャンの設定](configuration.md#scan)、更新は[脅威情報の更新](scan-logic.md#intel-cache)、失敗時は[言語ランタイムのセキュリティ情報の利用不能時の扱い](scan-logic.md#node-runtime-unavailable)を参照してください。

### Hacker Newsの検索 {#hacker-news-search}

Hacker Newsの検索では、KestreLynxが検出したCVE IDを`hn.algolia.com`へ検索クエリとして送り、議論のリンクを取得します。
KEV・EPSSの一括取得とは異なり、検索クエリに検出結果の一部が入ります。

送るのは、対応の優先度が最も高いCVEのIDだけです。
KEVで悪用が確認されたCVEや、EPSSで悪用の可能性が高いと判断されたCVEが該当します。

検索に成功したCVEは、検索から24時間が経過するまで検索し直しません。
[優先順位付けの設定](configuration.md#triage)で`triage.discussion_links`または`triage.enabled`を`false`にすると、検索しません。

### Trivyの取得通信 {#trivy-downloads}

Trivyは、通常のスキャンや、修正計画で更新前後を比べるスキャンのために、次のデータを取得します。
比較用のスキャンでは、更新後のイメージや依存ファイルを調べ直します。

| 取得する情報 | 通信先 | 通信が起きる条件 |
| --- | --- | --- |
| 脆弱性データベースなど | Trivyのデータベース取得先 | スキャン用データベースの準備が必要 |
| スキャン対象・比較用のイメージ | イメージ名で決まるレジストリと、レイヤーなどの配信先 | 必要なイメージをレジストリから取得する場合 |

データベースの取得先は、Trivyの`db.repository`・`db.java-repository`で決まります。
既定は`mirror.gcr.io`と`ghcr.io`で、変更方法は[Trivyのデータベース設定](https://trivy.dev/docs/latest/guide/configuration/db/)を参照してください。

イメージ取得の要求には、イメージのリポジトリ名・タグ・digestが含まれます。
レイヤーなどの配信先はレジストリの応答で決まり、ミラーを使う場合はTrivyのレジストリミラー設定も関係します。

比較の条件は[スキャンの比較条件](remediation-logic.md#comparison-conditions)、認証情報は[Trivyが使う環境変数](#trivy-environment-credentials)を参照してください。

### GitHubへの通信 {#github-communication}

修正計画は、脆弱性を解消するための更新案です。
[ソースの対応付け](configuration.md#remediation-mappings)で、稼働中のコンテナとGitHub上のリポジトリ・ファイルの関係を設定します。

KestreLynxは`api.github.com`へ、リポジトリ名・ブランチ・ファイルパスなどを指定して、次の読み取りや書き込みを行います。

| 処理 | 取得または送信する内容 | 通信が起きる条件 |
| --- | --- | --- |
| 読み取り | 設定したリポジトリ・ブランチ・ソースファイル | 修正計画でソースを確認する場合 |
| 読み取り | 既存PRと過去の操作結果の照合に使う情報 | PR処理が有効な場合 |
| 書き込み | コミット・ブランチ・PRの作成と古いPRの置き換え | PR処理が有効で、書き込み条件を満たした場合 |

古いPRの置き換えでは、置き換えを知らせるコメントを作り、条件を満たした古いPRをクローズします。
PRの内容には次の情報が含まれる場合があります。

- イメージ名とdigest、ワークロード名
- リポジトリ名、ソースのパス、変更内容
- パッケージ名と版、脆弱性ID、比較結果、処理の理由

あるパッケージを修正版に上げるために、古い版を要求している依存元も更新する処理を「再解決」と呼びます。
再解決のPRでは、依存元を更新する理由を示すため、依存元の名前・変更前後の版・更新を妨げていた版指定も送ります。

依存元と古い版に留められているパッケージの間にあるパッケージが古い版を指定している場合は、その名前も含めます。

管理の条件は[PRの管理](remediation-pr-logic.md#pr-management)、PRによるワークフローの起動は[PR作成の有効化](remediation-setup.md#enable-pr-creation)を参照してください。

### イメージ候補の取得 {#candidate-registry-communication}

修正計画では、レジストリで配布される実行用イメージや、ビルドの土台になるベースイメージの更新候補を調べます。
KestreLynxはイメージ名・タグ・digestを要求に指定し、タグ一覧、manifest、configなど、digestの確認に使う情報を取得します。

接続先は、イメージ名が示す公開または認証設定済みのレジストリです。
Docker Hubの場合は`registry-1.docker.io`へ接続します。

認証は[イメージレジストリの認証](configuration.md#registries)、候補の探索は[イメージ候補の選定](remediation-image-logic.md#image-selection)を参照してください。

### 作業用イメージの取得 {#worker-image-downloads}

作業用Podには、依存更新用コンテナと、入力ファイルを受け取るKestreLynxイメージのコンテナを使います。

言語パッケージの更新に使うイメージがローカルにない場合、コンテナランタイムが次の取得先から取得します。
取得要求には、作業用イメージの名前とdigestが含まれます。

| 通信するプログラム | 通信先 | 取得するイメージ |
| --- | --- | --- |
| DockerまたはKubernetesノードのコンテナランタイム | Docker Hubまたは設定したミラー | 公式Node.js・Python・Go（`golang`）・Gradle（`gradle`）イメージ |
| Kubernetesノードのコンテナランタイム | KestreLynxイメージ名のレジストリ | 作業用Podで入力ファイルを受け取るコンテナのイメージ |

イメージの固定と取得不能時の扱いは[公式イメージの固定](remediation-worker-logic.md#worker-images)を参照してください。

公式イメージのミラーは[`remediation.worker.registry`](configuration.md#remediation-worker)で指定し、実際の接続先にはコンテナランタイムのミラー設定も関係します。
入力用のイメージは[`remediation.worker.kubernetes.receiver_image`](configuration.md#remediation-worker-kubernetes)、未設定ならKestreLynx自身のPodのイメージで決まります。

### ツールの取得 {#tool-downloads}

KestreLynxはツール名や版を要求に指定し、版情報の確認や配布物の取得が必要な場合に、次の通信を行います。

| 通信するプログラム | 通信先 | 取得する情報 |
| --- | --- | --- |
| KestreLynx | `registry.npmjs.org` | npm・pnpmの版情報と配布物 |
| KestreLynx | `pypi.org`・`files.pythonhosted.org` | uvの版情報と配布物 |

ツール取得の要求とリダイレクトは、表に挙げたホストへのHTTPS（TCP 443）に制限します。
取得・照合は[ツールの取得と照合](remediation-node-python-logic.md#tool-verification)、再利用は[ツールキャッシュの再利用](remediation-node-python-logic.md#tool-cache)を参照してください。

### 依存パッケージの取得 {#dependency-downloads}

依存パッケージの取得要求には、パッケージ名と版が含まれます。
Goではモジュールパス、Maven・Gradleではパッケージを識別する`groupId`・`artifactId`を名前として使います。

依存ファイルはローカルで読み、取得要求として内容そのものをアップロードする処理はありません。

#### KestreLynxによる取得 {#dependency-kestrelynx}

KestreLynxは、更新に必要な版や依存関係、更新結果を確認するために、次の情報を取得します。

| 対象 | 通信先 | 取得する情報 | 取得する場面 |
| --- | --- | --- | --- |
| npm・pnpm | `registry.npmjs.org` | 版、依存関係、依存先の版指定、公開日時 | Node.jsの互換条件、更新結果、再解決の条件を確認 |
| pip・uv | `pypi.org` | パッケージ情報、配布物のURLやハッシュなどの情報、依存先の版指定、アップロード日時 | Pythonの更新結果やuvの再解決の条件を確認 |
| Go | `proxy.golang.org` | 版情報、`go.mod`、最新版、版一覧 | 目標版、利用撤回、必要なGoの版、依存の要求を確認 |
| Go | `sum.golang.org` | モジュールのzipと`go.mod`のハッシュ | 更新結果を照合し、`go.sum`を補完 |
| Maven | `repo.maven.apache.org` | 公開版一覧、親・BOM・依存のPOM | 版の出所、依存の要求、更新前後の解決結果を確認 |
| Gradle | `repo.maven.apache.org` | 公開版一覧とPOM | 公開版、BOMのプロパティ、追加・変更したパッケージの識別情報を確認 |

取得条件と、取得した情報の用途には次の補足があります。

- npm・pnpm・uvの再解決では、更新を妨げる版指定と、新たに入る版の[公開から72時間の待機](remediation-reresolution-logic.md#dependent-reresolution-waits)を確認する
- Goでは、公開元が利用を撤回した版の代わりを探す場合も版情報を取得する
- Goでは、版情報を`.info`、`go.mod`を`.mod`、最新版を`@latest`、版一覧を`@v/list`、ハッシュを`lookup`で取得する
- Maven・Gradleでは、公開版を`maven-metadata.xml`、依存関係や版の指定を`.pom`から読む
- Maven・Gradleの版やPOMを確認するとき、KestreLynxはMaven Centralへの要求の`User-Agent`に`kestrelynx`を付ける

npmの再解決では、対象パッケージに加えて依存元の情報を取得する場合があります。
たとえば、`minimist`の更新に`mkdirp`の更新が必要なら、`mkdirp`や新たに入る版の情報も取得します。

BOMは、依存パッケージの版をまとめて管理するものです。
Gradleで取得するPOMには、Spring BootのBOM、その親POM、Spring BootのBOMが取り込む別のBOM、依存パッケージのPOMが含まれます。

修正版に上げられない場合は、更新先を案内するために追加の確認を行います。
Mavenの親・BOMやSpring BootのBOMについて、公開版が指定する対象パッケージの版を調べます。

更新方法は[マネージャー別の更新処理](remediation-package-logic.md#manager-update-methods)、通信量などの上限は[再解決の対応範囲と上限](remediation-reresolution-logic.md#dependent-reresolution-limits)を参照してください。

#### 作業用コンテナによる取得 {#dependency-workers}

作業用コンテナは、依存関係を解決し、lockfileを生成・更新して検査するために、次の通信を行います。

| 対象 | 通信先 | 取得する情報 | 通信が起きる条件 |
| --- | --- | --- | --- |
| npm・pnpm・pip・uv | `registry.npmjs.org`・`pypi.org`・`files.pythonhosted.org` | 依存解決、lockfile生成、検査に必要な情報と配布物 | 依存更新を実行する場合 |
| Go | `proxy.golang.org`・`sum.golang.org` | モジュール情報、配布物、ハッシュの検証に必要な情報 | Goの依存更新を実行する場合 |
| Go | `storage.googleapis.com` | モジュールのzip | Goのproxyが配布物の取得先を転送する場合 |
| Gradle | Maven Central（`repo.maven.apache.org`） | 依存解決とlockfile更新に必要なメタデータ・配布物 | Gradleの依存更新を実行する場合 |
| Gradleのプラグイン | `plugins.gradle.org`・`plugins-artifacts.gradle.org`・`repo.maven.apache.org` | 許可されたプラグインと、その依存のメタデータ・配布物 | ビルドスクリプトでプラグインを適用する場合 |

Gradleは[`mavenCentral()`の取得先](https://docs.gradle.org/current/dsl/org.gradle.api.artifacts.dsl.RepositoryHandler.html)へ接続します。
Gradle Plugin Portalの配布物は[`plugins-artifacts.gradle.org`へのリダイレクト](https://plugins.gradle.org/docs/mirroring)で取得します。

利用できるプラグインは、KestreLynxの[プラグインの許可](remediation-dependency-formats.md#gradle-plugins)に記載された種類と版に限ります。

#### Trivyによる取得 {#dependency-trivy}

KestreLynxの依存ファイル検査で、Trivyが依存情報を取得するために通信するのはMavenの場合だけです。
Mavenでは、親の`pom.xml`や依存先が使うパッケージを調べるために、追加の`.pom`が必要です。

`package-lock.json`や`gradle.lockfile`などは、記録されたパッケージ名と版を読み取れるため、依存情報を取得する通信は不要です。

Mavenの更新前後の依存ファイルをTrivyで検査するとき、KestreLynx本体のコンテナ内にMaven Centralへの取り次ぎを用意します。
Trivyは、`127.0.0.1`の空きポートへHTTPで接続し、`groupId`・`artifactId`・版で指定した`.pom`を要求します。

Mavenの依存解決でTrivyが接続するのはローカルの取り次ぎだけで、Maven Centralには直接接続しません。
KestreLynxが`repo.maven.apache.org`へ取り次ぎ、要求の`User-Agent`に`kestrelynx`を付けます。

読み取ったプロジェクト内のモジュールの`.pom`を要求された場合は、Maven Centralへ転送しません。

### 通知先への送信 {#notification-delivery}

各通知の送信条件を満たすと、KestreLynxは脆弱性の検出結果、修正計画、判断の理由、PRのリンクや操作結果を送ります。
接続先は、通知方式に応じて次のように決まります。

| 通知方式 | 通信先 |
| --- | --- |
| Slack Incoming Webhook | `notify.slack_webhook_url`に設定したURL |
| Slack Bot | `slack.com`のAPI |
| 汎用Webhook | `notify.generic_webhook_url`に設定したURL |
| メール | `notify.email.host`・`notify.email.port`に設定したSMTPサーバー |

メールは、TLS必須（`starttls`または暗黙的な`tls`）のSMTPで送ります。
1回の送信には、接続から`QUIT`まで合計30秒の上限を設け、期限に達すると通信を打ち切ります。

通知には次の情報が含まれる場合があります。
再解決の結果は、再解決の通知に含めます。

| 通知先 | 内容の種類 | 含まれる情報 |
| --- | --- | --- |
| すべての通知方式 | 対象環境とソース | イメージ名とdigest、ワークロード名、リポジトリ名、ソースのパス |
| すべての通知方式 | 脆弱性と更新の比較 | パッケージ名と版、脆弱性ID、比較結果 |
| すべての通知方式 | 再解決の結果 | あわせて更新した依存元、更新の採用・見送り・待機と理由 |
| 汎用Webhook | 再解決の詳細 | 版指定、変更一覧、処理量、再試行可能な日時 |
| 汎用Webhook | 残る脆弱性や更新不採用の原因 | パッケージ名・版・依存元・脆弱性ID・使用箇所数・KEV掲載情報 |

共有できる範囲に合わせて通知先を設定してください。
設定は[通知先](configuration.md#notify-destinations)、送信条件は[通知の送信条件](notification-conditions.md#notification-conditions)、JSONは[Webhookのフィールド仕様](webhook-reference.md#generic-webhook)を参照してください。

## 認証情報の送付範囲 {#credential-destinations}

認証情報を送る先と、通信するプログラムごとの制限を説明します。

### GitHub token {#github-token-destinations}

KestreLynxは、[GitHubアクセスの設定](configuration.md#remediation-github)から次の規則でtokenを選びます。
所有者は、リポジトリ名`owner/name`の`owner`を指します。

- 対象リポジトリの所有者に該当する`remediation.github.tokens`のtokenを使う
- 所有者の項目がなければ、既定の`remediation.github.token`を使う
- 所有者のtokenも既定のtokenもなければ、tokenを付けない

tokenの送付先とリダイレクトには、次の規則を適用します。
`api.github.com`内の転送は、読み取りと書き込みで扱いが異なります。

- tokenはHTTPSの`api.github.com`だけへ送り、別ホストへのリダイレクトは拒否する
- 読み取りの要求で別の所有者へ転送する場合は、転送先の所有者に応じてtokenを選び直す
- 読み取りの要求では、所有者ごとのtokenがあり、転送する要求にtokenが付いている場合に、所有者を含まないURLへの転送を拒否する
- 読み取りの要求では、既定のtokenだけを設定した場合は、所有者を含まないURLへの転送にも従う
- 書き込みの要求では、tokenの設定にかかわらずリダイレクトに従わない

### イメージレジストリの認証情報 {#registry-credential-destinations}

[イメージレジストリの認証設定](configuration.md#registries)の`registries`に指定したユーザー名とパスワードを扱います。
KestreLynx自身とTrivyが使う場面と、送付先の制限を説明します。

認証情報を使うプログラムと場面は次のとおりです。

| 使うプログラム | 使う場面 | 送付先の制限のしかた |
| --- | --- | --- |
| KestreLynx | 修正計画で更新候補のタグやイメージの情報を読むとき | 自分で要求を送り、送付先を制限する |
| Trivy | イメージを取得してスキャンするとき | KestreLynxが送付先を事前確認してから認証情報を渡す |

#### 認証情報を送る先 {#registry-credential-targets}

`host`は、認証情報を使うレジストリのホストを指定します。
token serviceは、レジストリへアクセスするための一時的なtokenを発行するサーバーです。

token serviceは、レジストリとは別のホストにある場合があります。
たとえばDocker Hubでは、`host: docker.io`に対して`token_hosts: [auth.docker.io]`を指定します。

許可するtoken serviceは、レジストリと同じホストか、`token_hosts`に書いたホストです。
KestreLynx自身の送信と、Trivyへ渡す前の確認で、同じ送付先の規則を使います。

認証情報はHTTPSで送ります。
公開イメージでも、設定済みのレジストリがログインを求めれば認証情報を使う場合があります。

#### KestreLynxが読むとき {#registry-credential-kestrelynx}

KestreLynx自身が読むときの認証情報の扱いは次のとおりです。

| レジストリの状態 | 認証情報の扱い |
| --- | --- |
| `registries`に設定していない | 使わない（匿名でアクセス） |
| 設定済みで、レジストリがログインを求めない | 使わない |
| 設定済みで、レジストリ自身がログインを求める | レジストリへ送る |
| 設定済みで、許可したtoken serviceでの認証を求める | 指定されたtoken serviceへ送る |
| 設定済みで、許可していないtoken serviceでの認証を求める | 送らない |

レジストリ自身から一度ログインを求められると、KestreLynxはそのレジストリへの以後の要求に最初から認証情報を付けます。

KestreLynxは、リダイレクト先へ認証情報を引き継ぎません。

接続できるアドレスは、ホストの設定で決まります。

| 接続先のホスト | 接続できるアドレス |
| --- | --- |
| `host`または`token_hosts`に書いたホスト | 公開アドレス、プライベートアドレス、ループバック、通信事業者などの共有アドレス（CGNAT、`100.64.0.0/10`） |
| `host`にも`token_hosts`にも書いていないホスト | 公開アドレスだけ |

リンクローカルには接続しません。

#### Trivyがスキャンするとき {#registry-credential-trivy}

Trivyが設定済みの認証情報を使ってイメージを取得するまでの流れは、次のとおりです。

1. KestreLynxがスキャン前に認証情報を付けない要求をレジストリへ送り、どこで認証を求められるかを確かめる
2. 認証を求める先がすべて許可された送付先だと確認できた場合だけ、該当するレジストリの認証情報をTrivyへ渡す
3. Trivyがイメージを取得し、必要な認証情報を自分で送る

Trivyへ渡す認証情報は、スキャン前の確認結果で判断します。

| レジストリの状態 | 認証情報の扱い |
| --- | --- |
| `registries`に設定していない | 渡さない |
| 確認した認証の要求がすべて許可された送付先を指定 | 対象レジストリの認証情報だけを渡す |
| ログイン不要の応答 | 渡さない |
| 許可していない送付先 | 渡さない |
| 確認不能 | 渡さない |

事前確認とTrivyによるイメージ取得は別の要求で、認証情報を実際に送る先はTrivyが決めます。
そのため、次の限界があります。

- 確認の後にレジストリの応答が変わっても、KestreLynxは検知できない
- Trivyは同じレジストリホスト内のリダイレクトに認証情報を付ける場合があるが、別ホストへは引き継がない
- Trivyの接続には、KestreLynxが読むときのアドレス制限を適用しない

認証情報が確認時と異なる送付先へ送られる可能性があります。
KestreLynxは、Trivyによる実際の送付先を制御しません。

Trivyが自分で読む`TRIVY_USERNAME`・`TRIVY_PASSWORD`・`GITHUB_TOKEN`は`registries`の送付先制限の対象外で、[Trivyが使う環境変数](#trivy-environment-credentials)で説明します。

### Trivyが使う環境変数 {#trivy-environment-credentials}

Trivyが使う場合がある、KestreLynx本体のコンテナの環境変数を次に示します。

| 環境変数 | Trivyが使う場面と送付先 |
| --- | --- |
| `TRIVY_USERNAME`・`TRIVY_PASSWORD` | イメージやデータベースの取得で接続するレジストリと、その認証先 |
| `GITHUB_TOKEN` | `ghcr.io`からイメージやデータベースを取得するときの認証先 |

`TRIVY_USERNAME`・`TRIVY_PASSWORD`の[送付先は特定のレジストリに限定されません](https://trivy.dev/docs/latest/guide/advanced/private-registries/#passing-credentials)。
`GITHUB_TOKEN`は、`ghcr.io`からのデータベース取得の認証にも使われます（[Trivyのデータベース認証エラーの説明](https://trivy.dev/docs/latest/references/troubleshooting/#denied)）。

修正計画が有効な場合は、スキャンの前にTrivyの脆弱性データベースとJava用データベースを準備します。
データベースの準備処理では、環境変数から`TRIVY_*`を除きません。

準備に成功すると、直後に行う稼働イメージの通常スキャンと、それに続く修正計画の比較スキャンで同じデータベースを使います。
通常スキャンと比較スキャンでの環境変数の扱いは、スキャン前の状態によって変わります。

| スキャン前の状態 | 通常スキャンの`TRIVY_*` | 比較スキャンの`TRIVY_*` |
| --- | --- | --- |
| データベースの準備に成功 | 除く | 除く |
| データベースの準備に失敗 | 除かない | 比較スキャンを行わない |
| 修正計画が無効 | 除かない | 比較スキャンを行わない |

いずれの条件でも、`GITHUB_TOKEN`は環境変数から除きません。

### 作業用コンテナ {#worker-credentials}

GitHub tokenとイメージレジストリの認証情報は、作業用コンテナへ渡しません。

## 作業用コンテナのネットワーク {#worker-network}

Dockerの作業用コンテナはbridgeネットワークを使います。
通信先をネットワークの許可リストでは制限しません。

Kubernetesの作業用Podには、利用者がNetworkPolicyを適用します。
`deploy/kubernetes/work/40-networkpolicy.yaml`の例は受信を拒否し、送信をDNS（UDP・TCP 53）と、指定範囲を除くIPv4宛てTCP 443に限定します。

TCP 443の許可からは、プライベートアドレス（`10.0.0.0/8`・`172.16.0.0/12`・`192.168.0.0/16`）、リンクローカル（`169.254.0.0/16`）、CGNAT（`100.64.0.0/10`）を除きます。
公開HTTPSサイト全般への接続を許可する例で、npmやPyPIだけには限定しません。

NetworkPolicyを実施するネットワーク機能（CNI）が必要で、標準のNetworkPolicyではPodと実行ノードの通信は遮断しません。
CNIが新しいPodに制限を設定し終えるまでの数秒間は、送信が制限されない場合があります（K3sの既定のCNIで確認）。

導入時の調整は[Kubernetesの言語パッケージ更新](remediation-setup-work-pods.md#kubernetes-language-updates)、ネットワーク以外の制限は[実行時の制限](remediation-worker-logic.md#worker-restrictions)を参照してください。
