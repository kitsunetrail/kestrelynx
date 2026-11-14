---
title: 作業用コンテナの実行
---

# 作業用コンテナの実行

KestreLynxは、npm・pnpm・pip・uv・Go・Gradleの更新に作業用コンテナを使い、Kubernetesでは作業用Podとして実行します。

Mavenの更新では作業用コンテナを使いません。
Mavenの処理は[Mavenの候補選定](remediation-maven-logic.md#maven-package-selection)を参照してください。

1回の更新では、次の順に処理を進めます。

1. 使用するイメージを用意する
2. 作業用コンテナまたはPodを作成する
3. 入力ファイルを渡す
4. パッケージマネージャーで更新を実行する
5. 結果を回収し、採用前の検査へ進める
6. 作業用コンテナまたはPodの削除を試みる

このページで使う用語は[用語](remediation.md#terms)を参照してください。

## 作業用コンテナの実行 {#worker-execution}

KestreLynxは、使用するイメージと入力を確認し、権限や資源を制限した作業用コンテナで更新を実行します。
Kubernetes固有の作成前後の確認は[作業用Podの実行](#kubernetes-work-pods)を参照してください。

### 公式イメージの固定 {#worker-images}

作業用コンテナには、公式Node.js・Python・Go（`golang`）・Gradle（`gradle`）イメージを使います。
使用する内容は、KestreLynxに組み込まれた対応版の一覧である[対応する実行環境](remediation-reference.md#supported-runtimes)のdigest（イメージの内容を識別する値）で固定します。

同じタグの内容が変わっても追従しません。
固定する内容やサポートする実行環境の版は、KestreLynxの更新に伴って変わります。

イメージの取得と使用には、次の条件を適用します。

- 必要なイメージはDocker本体や、Kubernetesノードのcontainerdなどが取得する
- ミラーを使う場合も、対応版の一覧と同じdigestの内容を取得する
- GradleはGradleの版とJDKの組み合わせごとにdigestで固定し、実行するplatformで統合テストを通った組み合わせだけを使う

イメージを取得できない場合は言語パッケージの更新を保留（`deferred`）にし、後のサイクルへ回します。
取得に失敗しても、KestreLynx自身のコンテナ内で代わりにパッケージマネージャーを実行しません。

取得先の指定は[作業用コンテナの設定](configuration.md#remediation-worker)を参照してください。

### コンテナへの入力 {#worker-inputs}

更新の開始前に、対象の依存ファイルと関連する設定ファイル、KestreLynxの作業プログラム、取得・照合済みのツールを配置します。
作業プログラムはKestreLynxに付属し、コンテナ内でパッケージマネージャーを実行して結果をまとめます。

リポジトリ全体は渡さず、マネージャーごとに入力対象として認めたファイルだけを渡します。

渡す依存ファイルと設定ファイルの代表例は次のとおりです。

| マネージャー | 渡すファイルの例 |
| --- | --- |
| npm | `package.json`・`package-lock.json` |
| pnpm | `package.json`・`pnpm-lock.yaml`・存在する場合の`pnpm-workspace.yaml` |
| pip | `requirements.txt` |
| uv | `pyproject.toml`・`uv.lock` |
| Go | `go.mod`・`go.sum` |
| Gradle | `gradle.lockfile`・`build.gradle`または`build.gradle.kts`・`settings.gradle`または`settings.gradle.kts`・`gradle.properties`など |

catalogやwrapperの設定を含む入力一覧と条件は[Gradleの依存ファイル](remediation-dependency-formats.md#gradle-inputs)を参照してください。

入力対象に含まれない`.npmrc`や`pip.conf`は渡しません。
入力対象のファイルから、コメント内の秘密情報などを一律に除去する処理はありません。

作業プログラム・ツールと、KestreLynxが持つ認証情報などの扱いは次のとおりです。

| 入力の種類 | 扱い |
| --- | --- |
| 作業プログラムとツール | 配置する内容を照合して渡す |
| GitHub token・イメージレジストリの認証情報 | 渡さない |
| KestreLynxの設定ファイル・Docker socket | 渡さない |

ツールの検査は[ツールの取得と照合](remediation-node-python-logic.md#tool-verification)、認証情報を外部へ送る範囲は[認証情報の送付範囲](outbound-communication.md#credential-destinations)を参照してください。

### 実行時の制限 {#worker-restrictions}

作業用コンテナには、権限、資源、書き込み先、実行内容の制限を適用します。

DockerとKubernetesに共通する制限は次のとおりです。

- 非rootで実行し、Linux capabilitiesをすべて削除して`no-new-privileges`を設定する
- メモリ、CPU、出力量、実行時間を制限する
- 書き込み可能な場所を容量制限付きの一時領域に限定する
- 実行環境、ツール、作業プログラムが指定した内容に一致することを確認する

root filesystem（コンテナのルートファイルシステム）とプロセス数は、DockerとKubernetesで制限方法が異なります。

| 制限対象 | Docker | Kubernetes |
| --- | --- | --- |
| root filesystem | 設定自体は読み取り専用にせず、所有者・権限と一時領域のマウントで非rootの書き込み先を制限する | 読み取り専用にする |
| プロセス数 | コンテナのPID上限で制限する | ノード側のPID上限で制限する |

マネージャーごとに、更新時に実行する内容が異なります。

| マネージャー | 実行する内容 |
| --- | --- |
| npm・pnpm・pip・uv | パッケージのスクリプトとソースのビルドを無効にして依存を更新する |
| Go | 公式イメージの`go`コマンドで依存を更新する |
| Gradle | プロジェクトのビルドスクリプトと許可したプラグインのコードを実行し、`dependencies --update-locks`でlockfileを更新する |

実行するビルドスクリプトは、[ビルドスクリプトの書き方](remediation-dependency-formats.md#gradle-build-forms)で示す範囲に限ります。

Gradleで実行を許すプラグインは、KestreLynxの[プラグインの許可](remediation-dependency-formats.md#gradle-plugins)で定めます。
外部プラグインは、プラグインID・版・Gradleの版が許可された組み合わせに一致する必要があります。

個別の実行設定は[Goの実行設定](remediation-go-logic.md#go-worker-settings)と[Gradleの実行設定](remediation-gradle-logic.md#gradle-worker-settings)、処理量の設定は[処理の上限](configuration.md#remediation-limits)を参照してください。

Dockerはbridgeネットワークを使い、通信先をネットワークの許可リストでは制限しません。
Kubernetesでは利用者がNetworkPolicyを適用し、提供例では受信を拒否して送信をDNSと指定範囲を除くIPv4宛てTCP 443に限定します。

公開HTTPSサイト全般への接続を許す範囲、除外するアドレス、CNIの要件と制約は[作業用コンテナのネットワーク](outbound-communication.md#worker-network)を参照してください。

### 結果の回収 {#worker-results}

結果の回収では、更新後のファイルを取り出し、採用判定に使える内容かを検査します。

Dockerでは、暗号化していない結果を標準出力から回収します。
Kubernetesでは、実行ごとの鍵で暗号化した結果をPodのログから回収して復号します。

回収後に作業用コンテナまたはPodの削除を試み、KestreLynxで結果の内容を検査します。
Podのログには、結果の暗号文と定型の状態表示だけを出します。

回収対象はKestreLynxがマネージャーごとに決め、作業用コンテナへの実行指示に含めます。
利用者による出力ファイルの指定は不要です。

npm・pnpm・uv・Goでは[コンテナへの入力](#worker-inputs)にある依存ファイルを回収し、pnpmの`pnpm-workspace.yaml`は含めません。
pipでは`requirements.txt`と依存解決のレポートを回収します。

Gradleの回収対象は[Gradleの実行設定](remediation-gradle-logic.md#gradle-worker-settings)を参照してください。

採用判定の前に、次の点を確認します。

- 返されたファイル、サイズ、ハッシュ、実行内容、終了状態の整合を確認する
- KestreLynxが指定した回収対象以外のファイルや、結果の記録と矛盾する内容を受け入れない

削除のエラーとともに回収済みの結果が返された場合は、削除失敗を記録して検査を続けます。
削除失敗だけではPR作成を止めず、結果の内容と終了状態を通常どおり検査して採用を判定します。

削除に失敗したコンテナやPodは、後続の後片付けで削除を再試行します。

## 作業用Podの実行 {#kubernetes-work-pods}

Kubernetesでは、設定した作業用namespaceの使い捨てPodで言語パッケージの更新を実行します。
サポートするマネージャーの[依存元からの再解決](remediation-reresolution-logic.md#dependent-reresolution)にも作業用Podを使います。

必要なリソースは、利用者が[作業用Podの準備](remediation-setup-work-pods.md#kubernetes-language-updates)に従って適用します。
ValidatingAdmissionPolicyで、作成を許可するPodの仕様を制限します。

Pod内では、受信用コンテナが入力ファイルを先に配置し、その後に作業用コンテナが更新を実行します。

KestreLynxは次の順に確認と実行を進めます。

1. 言語パッケージを更新する各サイクルで、Podを保存しない試し作成（`dryRun`）により、規則に適合するPodが受け入れられ、違反するPodが拒否されることを確認する
2. 作業用Podを作成し、作成後のPodが要求した仕様と一致することを確認する
3. 確認したPodの受信用コンテナを通じて、[コンテナへの入力](#worker-inputs)に示すファイルを渡す
4. 制限された環境で更新を実行し、Podのログから[結果を回収する](#worker-results)
5. 処理後にPodの削除を試みる

残ったPodは、起動時と定期的な後処理で削除します。
権限と書き込み先の制限は[実行時の制限](#worker-restrictions)を参照してください。

確認できない条件や上限に応じて、更新を進めない理由と扱いを分けます。

| 状況 | 理由コード | 扱い |
| --- | --- | --- |
| Pod作成規則を確認できない | `work_admission_unverified` | 手動対応 |
| クラスタの版を取得できない | `work_admission_unverified` | 保留 |
| Pod数や資源の上限に達した | `work_pod_limit` | 保留 |

保留した更新は後のサイクルで再試行し、Pod作成規則も言語パッケージを更新する各サイクルで再確認します。
手動対応の場合は[作業用Podの準備](remediation-setup-work-pods.md#kubernetes-language-updates)で必要なリソースを確認し、Pod数などの設定は[Kubernetesの作業用コンテナ設定](configuration.md#remediation-worker-kubernetes)を参照してください。
