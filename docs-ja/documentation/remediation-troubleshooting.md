# 候補やPRが出ない場合

通知の表示や理由コードから、候補やPRが出ない原因を確認するページです。
状況に合う節を選び、通知やログの表示に合う行の対処を行ってください。

表にない理由コードの意味は[理由コード](remediation-reason-codes.md#reason-codes)で確認してください。

Slackの言語パッケージの「更新候補」は、次のいずれの場合にも表示されます。

- 依存更新をまだ実行していない（Webhookの`category`は`dependency_update_candidate`）
- 依存更新の検査を通ったが、PRがまだない（Webhookの`category`は`pr_candidate`）

「更新候補」の表示だけでは、依存更新とPR作成のどちらの段階の問題かを区別できません。
区別できない場合は、先に[更新を実行できない場合の確認](#check-update-failure)を確認してください。

このページで使う用語は[用語](index.md#terms)を参照してください。

状況に応じて、次の節へ進んでください。

| 状況 | 見る節 |
| --- | --- |
| 修正計画の通知が届かない・計画に目当ての項目がない | [計画が出ない場合の確認](#check-missing-plan) |
| 言語パッケージの`category`が`dependency_update_candidate`・更新の失敗理由がある | [更新を実行できない場合の確認](#check-update-failure) |
| イメージの更新候補がある・言語パッケージの`category`が`pr_candidate`なのにPRがない | [PRを作れない場合の確認](#check-missing-pr) |
| 「Pull Requestの作成を停止中」と出る・記録のエラーが出る | [記録を照合できない場合の確認](#check-record-failure) |

## 診断情報の取得 {#collect-diagnostics}

診断には、調べるワークロードとイメージについて、1回のサイクルで出た計画・通知・ログをそろえて使います。
次の順に確認してください。

1. 調べるワークロード、イメージ、通知の日時を控える
2. Slackの対象行の文、またはWebhookの対象項目の`category`・`reason`・`detail`から、分類・理由・詳細を確認する
3. PR処理の問題では、通知されたPRの状態・操作結果と、その通知と同じサイクルのKestreLynxのログを確認する

通知がない場合に読む`plan.json`と、PR処理の記録である`prs.json`の場所は[保存ファイル](remediation-pr-logic.md#stored-records)を参照してください。
理由の定義は[理由コード](remediation-reason-codes.md#reason-codes)、通知で省略された情報の確認先は[詳細な結果の確認先](remediation-results.md#detailed-results)を参照してください。

配布構成のコンテナ名と既定の保存先を使うDockerの取得例です。
コンテナ名や`remediation.storage_dir`を変更している場合は、実際の値に置き換えてください。

```sh
docker cp kestrelynx:/var/lib/kestrelynx/remediation/plan.json ./plan.json
docker cp kestrelynx:/var/lib/kestrelynx/remediation/prs.json ./prs.json
docker logs kestrelynx > kestrelynx.log 2>&1
```

配布構成のnamespace・Deployment名と既定の保存先を使うKubernetesの取得例です。
名前や保存先を変更している場合は、実際の値に置き換えてください。

```sh
kubectl -n kestrelynx exec deployment/kestrelynx -c kestrelynx -- cat /var/lib/kestrelynx/remediation/plan.json > plan.json
kubectl -n kestrelynx exec deployment/kestrelynx -c kestrelynx -- cat /var/lib/kestrelynx/remediation/prs.json > prs.json
kubectl -n kestrelynx logs deployment/kestrelynx -c kestrelynx > kestrelynx.log 2>&1
```

## 計画が出ない場合の確認 {#check-missing-plan}

計画は、稼働イメージの所見を基に更新対象を選びます。
`scan.severity`で指定した深刻度で、状態が`fixed`かつ修正版情報がある所見が対象です。

状態はTrivyのスキャン結果の`Results[].Vulnerabilities[].Status`で確認でき、`fixed`は脆弱性情報が修正済みの版の存在を報告していることを示します。
修正版情報は同じ所見の`FixedVersion`で確認できます。

通知が届かない場合や、計画に項目・イメージ候補がない場合は、次の表を確認してください。

| 表示または症状 | 対処 | 参照先 |
| --- | --- | --- |
| `container/<名前>`の項目がない | 対応付けの`workload`を、`container/`に`docker ps`の`NAMES`の値を続けた値に直す | [docker runのコンテナ](remediation-reference.md#docker-run-containers) |
| ログに`use the Compose key instead`を含む警告が出る（警告の原因となる状態が続く間は1回だけ表示） | 対応付けの`workload`を警告の`use`に示された`compose/<project>/<service>`に変える | [ワークロードキーの確認](remediation-setup-docker.md#identify-workload) |
| 同じタグでビルドし直した後、古いコンテナの項目がない | コンテナを新しいイメージで作り直す | [docker runのコンテナ](remediation-reference.md#docker-run-containers) |
| `plan.json`に計画があるが通知がない | KestreLynxのログの配信失敗と、通知の送信条件を確認する | [スキャン通知の送信条件](notification-conditions.md#notification-conditions)・[修正計画の再送](notification-conditions.md#remediation-redelivery) |
| `source_not_found`：「取得元のリポジトリまたはブランチが見つからない」 | 対応付けの`repository`・`base_branch`・`dependencies.directory`を実在する値に直す | [ソースの対応付け](configuration.md#remediation-mappings) |
| `source_access_denied`：「取得元のリポジトリにアクセスできない」 | GitHub tokenを対象リポジトリのContentsを読めるものにする | [GitHubアクセス](configuration.md#remediation-github) |
| `source_error`で、詳細に`names no repository owner to choose a token for`がある | 対応付けの`repository`を現在の`owner/name`に直す | [GitHubアクセス](configuration.md#remediation-github) |
| `dockerfile_file_not_found`：「設定したパスに Dockerfile がない」（対応付けに`dockerfile`を指定している場合） | 対応付けの`dockerfile.path`を実際のDockerfileのパスに直す | [ソースの対応付け](configuration.md#remediation-mappings) |
| `dockerfile_file_not_found`で、対応付けの`dockerfile`を省略し、Composeの`build`からDockerfileを決めている場合 | 対応付けの`compose.path`と指定したComposeファイルの`build`を実際のビルドに合わせて直す | [ソースの対応付け](configuration.md#remediation-mappings) |
| `compose_file_not_found`：「設定したパスに Compose ファイルがない」 | 対応付けの`compose.path`を実際のComposeファイルのパスに直す | [ソースの対応付け](configuration.md#remediation-mappings) |
| `manifest_file_not_found`：「設定したパスにマニフェストがない」 | 対応付けの`manifest.path`・`kustomize.path`・`helm_values.path`のうち設定したパスを直す | [ソースの対応付け](configuration.md#remediation-mappings) |
| `dependency_files_not_found`：「依存関係ファイルが見つからない」 | `dependencies.directory`を直すか、詳細に示された足りない依存ファイルを対象ブランチに足す | [ソースの対応付け](configuration.md#remediation-mappings) |
| Rustバイナリだけのイメージで依存の所見がない | cargo-auditableでビルドしてイメージを配置し直す | [Rustの候補選定](remediation-cargo-logic.md#cargo-package-selection) |
| `ambiguous_dependency_files`：「依存関係ファイルの候補が複数ある」 | 対象ブランチの`dependencies.directory`で指定したディレクトリから使っていないlockfileを取り除く | [ソースの対応付け](configuration.md#remediation-mappings) |
| `auth_required`：「レジストリへのログインが必要である」 | 最上位の`registries`の`host`・`username`・`password`・`token_hosts`を取得先に合わせて直す | [イメージレジストリの認証](configuration.md#registries) |
| Webhookの`reason`が`locally_built`で、イメージの更新候補が出ない（Slackには表示されない） | 対応付けに`dockerfile.path`や`dependencies.directory`を設定する | [ソースの対応付け](configuration.md#remediation-mappings) |
| `base_update_not_deployed`：「PR &lt;PR&gt;（ベースイメージ &lt;イメージ&gt; &lt;旧タグ&gt; → &lt;新タグ&gt;）はマージ済みだが、稼働中のイメージはまだ &lt;旧タグ&gt; から作られている」 | マージ後のDockerfileで作り直したイメージを配置する | [ベースレイヤーの照合](remediation-base-image-logic.md#base-layer-matching) |
| `base_layers_mismatch`：「稼働中のイメージが FROM の &lt;ベースイメージ&gt; から作られていない（Dockerfile を変えた後にイメージを作り直していないか、タグの中身が作成後に差し替わった）」 | 対応付けの`dockerfile.path`・`dockerfile.target`を実際のビルドに合わせ、設定が合っている場合は作り直したイメージを配置する | [ソースの対応付け](configuration.md#remediation-mappings) |

上限で止まった分は後のサイクルへ回るため、毎回上限に達する場合は[処理の上限](configuration.md#remediation-limits)に従って次の設定値を上げてください。

| 表示 | 上げる設定 |
| --- | --- |
| `candidate_scan_limit`：「1回の実行でスキャンできる候補数の上限に達した」 | `remediation.limits.candidate_scans_per_cycle` |
| `baseline_rescan_limit`：「稼働中のイメージを再スキャンできる数の上限に達した」 | `remediation.limits.baseline_rescans_per_cycle` |
| `registry_budget_exhausted`：「レジストリへのリクエスト数の上限に達した」 | `remediation.limits.registry_requests_per_cycle` |
| `tag_page_limit`：「タグ一覧の取得回数の上限に達した」 | `remediation.limits.tag_pages_per_repository` |
| `cycle_deadline`：「実行時間の上限に達した」 | `remediation.limits.cycle_timeout` |

## 更新を実行できない場合の確認 {#check-update-failure}

言語パッケージの更新は、候補を実際に更新し、変更後の依存ファイルを検査する処理です。

候補が更新されない場合は、次の表で通知の理由に合う行の対処を行ってください。

| 表示または症状 | 対処 | 参照先 |
| --- | --- | --- |
| 言語パッケージが「更新候補」のままで、Webhookの`category`が`dependency_update_candidate` | `remediation.pull_requests.enabled`を`true`にする | [基本設定](configuration.md#remediation-basics) |
| `tool_too_new`で、詳細に`it can be used from`がある | 詳細の`it can be used from`に続く時刻まで待つ | [作業用コンテナ](configuration.md#remediation-worker) |
| `tool_fetch_failed`で、詳細に`downloading`または`reading the registry's document`があり、`answered`がない | `registry.npmjs.org`・`pypi.org`・`files.pythonhosted.org`へHTTPSで接続できるようにする | [ツールの取得](outbound-communication.md#tool-downloads) |
| `tool_fetch_failed`で、詳細に`the tool cache could not be written`がある | `remediation.storage_dir`の書き込み権限と空き容量を確保する | [基本設定](configuration.md#remediation-basics) |
| `tool_hash_mismatch`で、詳細に`declared hash`がある | 対象ブランチの`package.json`の`packageManager`に書いたハッシュを直す | [ツールの版宣言](remediation-dependency-formats.md#tool-declarations) |
| `tool_cache_full`：「パッケージマネージャーのキャッシュが満杯である」 | `remediation.worker.tool_versions.cache_max_size`を上げる | [作業用コンテナ](configuration.md#remediation-worker) |
| `work_image_unavailable`で、詳細に`the work image could not be made ready`または`work image unavailable`がある | Docker Hubまたは`remediation.worker.registry`に指定したミラーから作業用イメージを取得できるようにする | [作業用イメージの取得](outbound-communication.md#worker-image-downloads) |
| `work_image_unavailable`で、詳細に`the work program is missing or is not the one this build was released with`がある | `remediation.worker.program_dir`の更新を実行するプログラムを、実行中のKestreLynxと同じビルドのものにする | [作業用コンテナ](configuration.md#remediation-worker) |
| `work_image_unavailable`で、詳細に`the instance id of the work containers could not be read or created`がある | `remediation.storage_dir`を書き込みできる場所にする | [基本設定](configuration.md#remediation-basics) |
| `work_image_not_configured`：「更新用の作業用イメージが設定されていない」 | 更新を実行するプログラムを含まない独自ビルドでは、プログラムを置いたディレクトリを`remediation.worker.program_dir`に指定する | [作業用コンテナ](configuration.md#remediation-worker) |
| `work_program_mismatch`：「作業用コンテナ内のプログラムがこのビルドのものと異なる」 | `remediation.worker.program_dir`の更新を実行するプログラムを差し替えた後は、KestreLynxを再起動する | [作業用コンテナ](configuration.md#remediation-worker) |
| `update_job_limit`：「1回の実行で行える更新の数の上限に達した」 | `remediation.limits.dependency_jobs_per_cycle`を上げる | [処理の上限](configuration.md#remediation-limits) |
| `update_job_timed_out`：「更新の実行がタイムアウトした」 | `remediation.limits.job_timeout`を上げる | [処理の上限](configuration.md#remediation-limits) |

Kubernetesで言語パッケージ更新が手動対応または保留になった場合は、理由ごとに次の項目を確認してください。

| 表示または症状 | 対処 | 参照先 |
| --- | --- | --- |
| `work_namespace_not_configured`：「Kubernetes での更新には作業用 Pod が要るが、作業用 namespace が設定されていない」 | `remediation.worker.kubernetes.namespace`に作業用namespaceを設定する | [作業用Podの準備](remediation-setup-work-pods.md#kubernetes-language-updates) |
| `work_cluster_too_old`：「クラスターが作業用 Pod のポリシーに必要な最低バージョンより古い」 | Kubernetesを1.30以上に更新する | [作業用Podの準備](remediation-setup-work-pods.md#kubernetes-language-updates) |
| `work_runtime_class_unsupported`：「作業用 Pod に RuntimeClass が設定されているが、まだ対応していない」 | `remediation.worker.kubernetes.runtime_class`を空にする | [Kubernetesの作業用コンテナ設定](configuration.md#remediation-worker-kubernetes) |
| `work_admission_unverified`で、詳細に`the policy allows none of the work images`がある | `52-policy-params.yaml`の`data.receiverRepository`と`data.workRepositories`を実際のリポジトリに合わせる | [作業用Podの準備](remediation-setup-work-pods.md#kubernetes-language-updates) |
| `work_admission_unverified`で、詳細に`the policy is not in force`がある | `50-validatingadmissionpolicy.yaml`と`51-validatingadmissionpolicybinding.yaml`を適用し直す | [作業用Podの準備](remediation-setup-work-pods.md#kubernetes-language-updates) |
| `work_priority_class_missing`で、詳細に`does not exist`がある | `remediation.worker.kubernetes.priority_class`に設定した名前のPriorityClassを作る | [Kubernetesの作業用コンテナ設定](configuration.md#remediation-worker-kubernetes) |
| `work_priority_class_missing`で、詳細に`is not one that never preempts, or is not the one the policy expects`がある | PriorityClassの`preemptionPolicy`を`Never`にし、`52-policy-params.yaml`の`data.priorityClass`を設定した名前に合わせる | [Kubernetesの作業用コンテナ設定](configuration.md#remediation-worker-kubernetes) |
| `work_pod_limit`：「作業用 namespace の Pod 数またはクォータが上限で、更新は次回に持ち越した」 | 作業用namespaceのPod数とクォータに空きを作る | [Kubernetesの作業用コンテナ設定](configuration.md#remediation-worker-kubernetes) |
| `work_pod_not_started`：「作業用 Pod が時間内に起動しなかった」 | Podのイベントに示された起動を妨げる原因を解消する | [作業用Podの準備](remediation-setup-work-pods.md#kubernetes-language-updates) |
| `update_result_invalid`で、詳細に結果ログの欠落がある | 実行ノードの`containerLogMaxSize`を`144Mi`以上にする | [作業用Podの準備](remediation-setup-work-pods.md#kubernetes-language-updates) |
| `update_job_failed`で、詳細に`workRepositories of its parameters must list`がある | `52-policy-params.yaml`の`data.workRepositories`に詳細のリポジトリを足す | [作業用Podの準備](remediation-setup-work-pods.md#kubernetes-language-updates) |

表のファイルは`deploy/kubernetes/work/`内にあり、`52-policy-params.yaml`を修正した後は[作業用Podの準備](remediation-setup-work-pods.md#kubernetes-language-updates)に従って適用し直してください。

作業用Podは処理が終わると削除されるため、`work_pod_not_started`の原因は更新の実行中に次の手順で確認してください。

1. 作業用namespaceで`io.kestrelynx.work=v1`ラベルの付いたPodを一覧し、作成時刻が失敗した更新の時刻に合うPodを選ぶ

    ```sh
    kubectl -n WORK_NAMESPACE get pods -l io.kestrelynx.work=v1 -o custom-columns=NAME:.metadata.name,CREATED:.metadata.creationTimestamp
    ```

2. 選んだPodのイベントを表示する

    ```sh
    kubectl -n WORK_NAMESPACE get events --field-selector involvedObject.name=POD_NAME
    ```

コマンドの`WORK_NAMESPACE`は`remediation.worker.kubernetes.namespace`の値、`POD_NAME`は選んだPod名に置き換えてください。

## PRを作れない場合の確認 {#check-missing-pr}

PR処理は、採用できる更新とソースの編集条件を確認し、既存PRとの重複を判定します。

修正版があるのにPRが無い理由は、脆弱性の通知のカードの[`対応:`行](slack-package-display.md#base-image-wait)で確認できます。

更新候補があるのにPRがない場合は、次の表を確認してください。

| 表示または症状 | 対処 | 参照先 |
| --- | --- | --- |
| 修正計画のイメージの「更新候補」にPRも理由もなく、`remediation.pull_requests.enabled`が`false` | `remediation.pull_requests.enabled`を`true`にする | [基本設定](configuration.md#remediation-basics) |
| 修正計画のイメージの「更新候補」にPRも理由もなく、Composeのサービスの対応付けに`compose`がない | 対応付けに`compose`を設定する | [ソースの対応付け](configuration.md#remediation-mappings) |
| 修正計画のイメージの「更新候補」にPRも理由もなく、Kubernetesのワークロードの対応付けに`manifest`・`kustomize`・`helm_values`のいずれもない | 対応付けに`manifest`・`kustomize`・`helm_values`のいずれかを設定する | [ソースの対応付け](configuration.md#remediation-mappings) |
| 修正計画のイメージの「更新候補」にPRも理由もなく、対象が`docker run`で起動したコンテナ（`container/<名前>`） | KestreLynxは`docker run`で起動したコンテナにはイメージタグを変更するPRを作らない | [docker runのコンテナ](remediation-reference.md#docker-run-containers) |
| `undeclared_affected_workload`：「列挙されていないコンテナが images の項目の値を宣言しており、編集の影響を受けうる」（詳細に示されたコンテナもタグの変更の対象にする場合） | 対応付けの`affects`に詳細に示されたコンテナを足す | [KustomizeのPR設定](remediation-setup-kubernetes.md#kustomize-pull-requests)・[HelmのvaluesのPR設定](remediation-setup-kubernetes.md#helm-values-pull-requests) |
| `undeclared_affected_workload`で、詳細に示されたコンテナをタグの変更の対象にしない場合 | 詳細に示されたコンテナが、対応付けた項目の値と同じイメージ参照を宣言しないようにマニフェストを変えて配置する | [KustomizeとHelmのvaluesのPR](remediation-kubernetes-logic.md#kustomize-and-helm-prs) |
| `init_container_unverified`：「列挙した init container が、稼働コンテナと同じイメージを動かしたことを確認できない」（詳細に`no running container of the set runs in the same Pod`がある） | init containerと同じPodで対象イメージを使う稼働コンテナを、対応付けの`affects`に追加する | [ソースの対応付け](configuration.md#remediation-mappings) |
| `init_container_unverified`で、詳細に`it ran the same image entity as`がある | init containerのマニフェストのイメージ参照を、詳細に示された稼働コンテナの参照に合わせてPodを作り直す | [KustomizeとHelmのvaluesのPR](remediation-kubernetes-logic.md#kustomize-and-helm-prs) |
| `kustomize_image_missing`：「kustomization に対応付けた名前の images の項目がない」 | 対応付けの`kustomize.path`と`kustomize.image`を更新する`images`の項目に合わせる | [ソースの対応付け](configuration.md#remediation-mappings) |
| `helm_key_missing`：「values ファイルに対応付けたキーの値がない」 | 対応付けの`helm_values.path`と`helm_values.key`をイメージを指定しているキーに合わせる | [ソースの対応付け](configuration.md#remediation-mappings) |
| `github_refused`：「GitHub が書き込みを拒否した」 | tokenにContentsとPull requestsのRead and writeを与える | [GitHubアクセス](configuration.md#remediation-github) |
| `github_refused`で、詳細がブランチ保護またはrulesetによる拒否を示す | リポジトリの規則を直す | [GitHubアクセス](configuration.md#remediation-github) |
| `pr_limit`：「1回の実行で作れる Pull Request の数の上限に達した」 | `remediation.limits.new_prs_per_cycle`を上げる | [処理の上限](configuration.md#remediation-limits) |
| `open_pr_limit`：「開いている KestreLynx の Pull Request の数が上限に達した」 | 開いているKestreLynxのPRをマージするか閉じる、または`remediation.limits.open_prs`を上げる | [処理の上限](configuration.md#remediation-limits) |
| Slackに「未マージでクローズ」と表示され、閉じたPRの更新が再提案されない（Webhookの`status`は`pr_suppressed`） | 更新をもう一度提案させるには、閉じたPRをGitHubで再オープンする | [閉じたPRの扱い](remediation-pr-logic.md#closed-prs) |
| `write_outcome_unknown`：「GitHub への書き込みの結果が分からない」 | 次のサイクルを待つ | [書き込みの停止](remediation-pr-logic.md#write-stops)・[PR操作イベントのフィールド](webhook-remediation-pr-reference.md#remediation-operation-fields) |

`undeclared_affected_workload`で`affects`を直す対応付けの範囲は、次のとおりです。

- 同じリポジトリ・ブランチ・ファイルの、同じKustomizeの項目またはHelmのキーを指す対応付けすべてが対象
- 各対応付けで、`workload`のコンテナと`affects`のコンテナを合わせた一覧をそろえる
- `workload`の値は対応付けごとに違ってよい

## 記録を照合できない場合の確認 {#check-record-failure}

記録の照合は、`prs.json`とGitHub上のPR・操作結果を確認し、GitHubへの書き込みを進められるか判定する処理です。
「Pull Requestの作成を停止中」や記録のエラーが出た場合は、次の表を確認してください。

| 表示または症状 | 対処 | 参照先 |
| --- | --- | --- |
| `storage_failed`：「Pull Request の記録を保存できなかった」、またはSlackの「修正計画を保存できませんでした。」 | `remediation.storage_dir`を、書き込みできて空き容量のある永続ボリュームに置く | [基本設定](configuration.md#remediation-basics) |
| `store_locked`：「Pull Request の記録が別のプロセスにロックされている」 | 同じ保存先を使う別のKestreLynxを停止する | [保存処理の理由](remediation-update-reason-codes.md#storage-reasons) |
| `records_unverified`：「既存の Pull Request の記録を確認できない」で、詳細に`kestrelynx marker`・`the marker is malformed`・`the marker's keys do not recompute`のいずれかがある | 対象PRの本文を編集した場合は、`<!-- kestrelynx:`で始まるHTMLコメントを編集前の内容に戻す | [記録の復旧](remediation-pr-logic.md#record-recovery) |
| `records_unverified`で、詳細に`github: authentication required`・`github: access forbidden`のいずれかがある | tokenを、対象リポジトリのContentsとPull requestsにRead and writeでアクセスできる有効なものにする | [GitHubアクセス](configuration.md#remediation-github) |
| `records_unverified`で、詳細に`github: not found`がある | 対応付けの`repository`を実在する`owner/name`に直し、実在する場合はtokenに対象リポジトリへのアクセスを与える | [GitHubアクセス](configuration.md#remediation-github) |
| `records_unverified`で、詳細に`github: rate limited`がある | GitHubの制限が解除された後のサイクルを待つ | [GitHubアクセス](configuration.md#remediation-github) |
| `records_unverified`で、詳細に`GitHub names the repository`がある | 対応付けの`repository`を詳細に示された名前に直す | [ソースの対応付け](configuration.md#remediation-mappings) |
| ログに`parse plan`・`parse pull request records`・`operation events are out of sequence`のいずれかが出る | `plan.json`または`prs.json`を手で編集した場合は、編集を取り消す | [書き込みの停止](remediation-pr-logic.md#write-stops) |
| `unsupported plan version`・`unsupported pull request record version`が出るか、詳細に`the marker has version`がある | KestreLynxを、ファイルやPRを作成した版へ戻す | [書き込みの停止](remediation-pr-logic.md#write-stops) |
| `storage_full`：「Pull Request の記録が満杯である」 | 次のサイクルを待つ | [書き込みの停止](remediation-pr-logic.md#write-stops)・[保存処理の理由](remediation-update-reason-codes.md#storage-reasons) |
| `storage_full`が続き、ログに`send notification`のエラーがある | 配信に失敗した通知先の`notify`設定のURL・認証情報や接続を直し、次のサイクルを待つ | [通知先](configuration.md#notify-destinations) |
| `storage_full`が続き、通知は届いている | `storage_full`が表示された通知にある、PRの作成や置き換えを止めているほかの理由の対処を行う | [PR処理の理由](remediation-update-reason-codes.md#pr-reasons) |

!!! warning "記録を保持する"

    再試行を強制するためにPR処理の記録を削除しないでください。
    閉じた更新の再作成を抑止し、過去の操作を照合するために必要です。
