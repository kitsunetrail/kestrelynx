# 候補やPRが出ない場合

通知の表示や理由コードから、候補やPRが出ない原因を確認するページです。
状況に合う節を選び、診断情報と表の「確認すること」を照合してください。

言語パッケージの「更新候補」だけでは、更新実行とPR作成のどちらで止まったか判別できません。
判別できない場合は、先に[更新を実行できない場合の確認](#check-update-failure)を確認してください。

このページで使う用語は[用語](remediation.md#terms)を参照してください。

| 状況 | 見る節 |
| --- | --- |
| 修正計画の通知が届かない・計画に目当ての項目がない | [計画が出ない場合の確認](#check-missing-plan) |
| 言語パッケージの`category`が`dependency_update_candidate`・更新の失敗理由がある | [更新を実行できない場合の確認](#check-update-failure) |
| イメージの更新候補がある・言語パッケージの`category`が`pr_candidate`なのにPRがない | [PRを作れない場合の確認](#check-missing-pr) |
| 「Pull Requestの作成を停止中」と出る・記録のエラーが出る | [記録を照合できない場合の確認](#check-record-failure) |

## 診断情報の取得 {#collect-diagnostics}

診断には、同じ対象・実行時刻の計画、通知、ログを使います。
次の順に確認してください。

1. 対象のワークロード、イメージ、スキャン時刻を控える
2. Slackの対象行の文、またはWebhookの対象項目の`category`・`reason`・`detail`から、分類・理由・詳細を確認する
3. PR処理の問題では、通知されたPRの状態・操作結果と、同じ実行時刻のKestreLynxのログを確認する

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
修正版情報は同じ所見の`FixedVersion`で確認でき、稼働環境への修正適用を示す値ではありません。

通知が届かない場合や、計画に項目・イメージ候補がない場合は、次の表を確認してください。

| 症状 | 確認すること | 参照先 |
| --- | --- | --- |
| 設定の読み込みで停止する | ログのエラーの文と該当する設定を照合する | [修正計画と修正PR](configuration.md#remediation) |
| 計画に対象の項目がない | 稼働イメージのスキャン結果が対象選定の条件を満たすか確認する | [イメージ候補の選定](remediation-image-logic.md#image-selection)・[言語パッケージの候補選定](remediation-package-logic.md#package-selection) |
| `container/<名前>`の項目がない | `docker ps`の`NAMES`と対応付けの名前が一致するか確認する | [docker runのコンテナ](remediation-reference.md#docker-run-containers) |
| `container/<名前>`がComposeのコンテナを指す | 警告に示された`compose/<project>/<service>`へ対応付けを変更する | [ワークロードキーの確認](remediation-setup-docker.md#identify-workload) |
| 同じタグでビルドし直した後、古いコンテナの項目がない | containerdのイメージストアから古いイメージが消えていないか確認する | [docker runのコンテナ](remediation-reference.md#docker-run-containers) |
| 稼働イメージとスキャンしたイメージのdigestが一致しない | ログのスキャン失敗と対象のイメージIDを確認する | [ソースの確認](remediation-logic.md#source-verification) |
| `plan.json`に計画があるが通知がない | 通知先と送信条件を確認する | [スキャン通知の送信条件](notification-conditions.md#notification-conditions)・[修正計画の再送](notification-conditions.md#remediation-redelivery) |
| ソースを取得できない・対象ファイルがない | 表の後の順序で対応付けを確認する | [ソースの対応付け](configuration.md#remediation-mappings)・[GitHubアクセス](configuration.md#remediation-github) |
| 所有者ごとのtokenで、名前変更・移管後のリポジトリを読めない | 対応付けの`repository`を現在の`owner/name`に直す | [GitHubアクセス](configuration.md#remediation-github) |
| 非公開イメージへアクセスできない | レジストリのホストと認証情報を確認する | [イメージレジストリの認証](configuration.md#registries) |
| `no_newer_tag`：「より新しいタグがない」 | major・minor・接頭辞・接尾辞が同じタグの範囲に新しい版があるか確認する | [イメージ候補の理由](remediation-image-reason-codes.md#image-reasons) |
| `same_content`：「新しいタグも中身が同じである」 | 候補と稼働イメージのdigestが同じか確認する | [配布イメージのタグ](remediation-image-logic.md#published-image-tags) |
| `candidate_does_not_resolve_targets`：「候補では対象の所見が解消しない」 | 稼働イメージと候補の比較で対象所見が解消したか確認する | [対象別の検証範囲](remediation-logic.md#verification-scope) |
| `declared_ref_mismatch`：「ワークロードのspecが指すイメージと稼働中のコンテナのイメージが一致しない」 | 同じ稼働イメージ名を使う全コンテナで、Podのspecの`image`と稼働イメージ名を照合する | [Kubernetesのイメージ名と再取得](remediation-kubernetes-logic.md#kubernetes-image-references) |
| `declared_ref_unavailable`：「ワークロードのspecが指すイメージを読み取れなかった」 | 同じ稼働イメージ名を使う各コンテナのPodのspecから`image`を読めるか確認する | [Kubernetesのイメージ名と再取得](remediation-kubernetes-logic.md#kubernetes-image-references) |
| `tag_listing_incomplete`：「タグ一覧を最後まで取得できなかった」 | 取得失敗のログと、通知に示された上限を確認する | [タグ一覧の探索](remediation-image-logic.md#tag-discovery)・[処理の上限](configuration.md#remediation-limits) |
| ローカルビルドとして扱われる | Composeの`build`と、Dockerfile・依存ファイルの対応付けを照合する | [ローカルビルドの除外](remediation-image-logic.md#local-builds) |
| ベースイメージを確認できない | Dockerfileの対象ステージの`FROM`で指定するイメージと、稼働イメージの照合結果を確認する | [ベースレイヤーの照合](remediation-base-image-logic.md#base-layer-matching)・[イメージ候補の理由](remediation-image-reason-codes.md#image-reasons) |

症状ごとの補足は次のとおりです。

- `container/<名前>`は一覧取得時に稼働していたコンテナが対象で、改名・作り直し後は次のサイクルの結果を確認する
- Composeの警告は同じ状態が続く間は1回だけ出るため、過去のログも確認する
- containerdから古いイメージが消えた場合は、コンテナを新しいイメージで作り直す
- 通知がない場合は配信失敗のログも確認する
- 非公開イメージでは取得権限とtoken serviceの許可も確認する
- タグ一覧ではタグ取得回数・レジストリ要求数・処理時間の上限を確認する

ソースを取得できない場合は、次の順に確認してください。

1. Composeのラベル、docker runのコンテナ名、またはKubernetesのワークロードキーを`workload`と照合する
2. `repository`が対象リポジトリを指すか確認する
3. `base_branch`が対象ブランチを指すか確認する
4. 指定したパスに対象ファイルがあるか確認する
5. GitHubへのアクセスと読み取り権限を確認する

所有者ごとのtokenでは、所有者を含まないリポジトリIDのURLへの転送は、tokenを選べないため拒否されます。

## 更新を実行できない場合の確認 {#check-update-failure}

言語パッケージの更新は、候補を実際に更新し、変更後の依存ファイルを検査する処理です。

KestreLynxはnpm・pnpm・uvを取得・照合して、作業用コンテナへ渡します。

候補が更新されない場合は、次の表で通知の理由と確認先を照合してください。

| 症状 | 確認すること | 参照先 |
| --- | --- | --- |
| 言語パッケージが候補のまま | PR作成の有効化と対象項目の理由を確認する | [基本設定](configuration.md#remediation-basics)・[計画とPRの実行範囲](remediation-logic.md#plan-and-pr-execution) |
| 入力形式や取得元が未対応と表示される | 理由が指す依存ファイルや設定を確認する | [対応する入力形式](remediation-reference.md#supported-inputs)・[ソースの理由](remediation-image-reason-codes.md#source-reasons) |
| 実行環境を選べない・互換条件を満たさない | プロジェクトの版宣言と依存パッケージの要件を照合する | [実行環境の選定](remediation-package-logic.md#runtime-and-tool-versions)・[実行環境の理由](remediation-update-reason-codes.md#runtime-reasons) |
| `pip_target_undecidable`：「パッケージが動く環境を判断できない」 | 稼働イメージから検証環境を判断できるか確認する | [pipの検証環境](remediation-node-python-logic.md#pip-target-environment) |
| `pip_target_mismatch`：「pip が解決する環境がパッケージの動く環境と異なる」 | 更新対象の各パッケージの検出元から導いた検証環境（Pythonの版・実装・プラットフォームタグ・ABI）が一致するか確認する | [pipの検証環境](remediation-node-python-logic.md#pip-target-environment) |
| `tool_too_new`：「パッケージマネージャーのリリースが新しすぎて使えない」 | 詳細に示された使用可能時刻を確認する | [作業用コンテナ](configuration.md#remediation-worker)・[ツール取得の理由](remediation-update-reason-codes.md#tool-reasons) |
| `tool_fetch_failed`：「パッケージマネージャーの取得に失敗した」 | 取得先への通信と通知の詳細を確認する | [ツールの取得](outbound-communication.md#tool-downloads) |
| `tool_fetch_budget`：「パッケージマネージャーの取得回数の上限に達した」 | 通知の詳細に示された取得の上限を確認する | [ツール取得の理由](remediation-update-reason-codes.md#tool-reasons) |
| `tool_hash_mismatch`：「パッケージマネージャーのアーカイブがチェックサムと一致しない」 | レジストリが示すハッシュとの不一致か、npm・pnpmの`packageManager`に指定したハッシュとの不一致かを、通知の詳細で確かめる | [ツールの版宣言](remediation-dependency-formats.md#tool-declarations)・[ツールの取得と照合](remediation-node-python-logic.md#tool-verification) |
| ツールキャッシュを利用できない | 保存先の書き込み権限と空き容量を確認する | [作業用コンテナ](configuration.md#remediation-worker)・[ツール取得の理由](remediation-update-reason-codes.md#tool-reasons) |
| Dockerの作業用コンテナを実行できない | Docker APIと作業環境の検査ログを確認する | [修正PRの有効化](remediation-setup.md#enable-pull-requests)・[作業用コンテナの実行](remediation-worker-logic.md#worker-execution) |
| `work_program_mismatch`：「作業用コンテナ内のプログラムがこのビルドのものと異なる」 | 利用中の配布物とログを確認する | [作業用コンテナ](configuration.md#remediation-worker) |
| 処理の上限や期限で止まる | 通知に示された上限と設定値を照合する | [処理の上限](configuration.md#remediation-limits)・[更新結果の理由](remediation-update-reason-codes.md#update-reasons) |
| 修正版に届かない・一部だけPRに入る | 除外されたパッケージと残った版を確認する | [部分PR](remediation-update-results.md#partial-pull-requests)・[更新結果の理由](remediation-update-reason-codes.md#update-reasons) |
| 更新後のファイルや付随変更の検査に失敗する | 通知の詳細で検査に失敗した変更を確認する | [付随変更の検査](remediation-node-python-logic.md#change-validation)・[更新結果の理由](remediation-update-reason-codes.md#update-reasons) |
| 更新前後を比較できない | スキャンのログと更新前後の比較条件を確認する | [スキャンの比較条件](remediation-logic.md#comparison-conditions) |
| `source_target_still_detected`：「更新後のファイルでも対象の脆弱性が検出される」 | 比較結果で更新後に残った対象所見を確認する | [比較結果の解消](remediation-pr-results.md#verification-results) |
| `source_introduced_findings`：「更新で依存関係ファイルに新たな所見が入る」 | 比較結果で更新前にはなかった所見を確認する | [比較結果の解消](remediation-pr-results.md#verification-results) |

実行環境と入力については、次の情報も確認してください。

- 未対応の入力では、依存ファイル・workspace・追加設定・パッケージの取得元を確認する
- Node.jsの版宣言は`.nvmrc`・`.node-version`と、依存を宣言する`package.json`の`engines.node`などを確認する
- Pythonの版宣言は`.python-version`と、依存を宣言する`pyproject.toml`の`requires-python`などを確認する
- Node.js 22やPython 3.13などの実行環境がサポート中か、[対応する実行環境](remediation-reference.md#supported-runtimes)で確認する
- pipの検証環境では、稼働イメージのPython版・OS・platformを確認する

取得・実行・検査については、次の情報も確認してください。

- ツールの待機では公開時刻と`remediation.worker.tool_versions.min_release_age`、キャッシュでは`remediation.worker.tool_versions.cache_max_size`も確認する
- Dockerでは作業用イメージの取得先も確認する
- 独自ビルドでは、コンテナ内で更新を実行する付属プログラムの配置（`remediation.worker.program_dir`）も確認する
- 上限や期限で止まった場合は次の実行予定も確認する
- 修正版に届かない場合は親パッケージの依存範囲も確認する
- 更新後の検査では、変更ファイル・lockfile形式・依存範囲・パッケージの配布物との照合結果を確認する

Kubernetesで言語パッケージ更新が手動対応または保留になった場合は、理由ごとに次の項目を確認してください。

| 症状 | 確認すること | 参照先 |
| --- | --- | --- |
| `work_namespace_not_configured`：「Kubernetes での更新には作業用 Pod が要るが、作業用 namespace が設定されていない」 | `remediation.worker.kubernetes.namespace`が設定されているか確認する | [作業用Podの準備](remediation-setup-work-pods.md#kubernetes-language-updates) |
| `work_cluster_too_old`：「クラスターが作業用 Pod のポリシーに必要な最低バージョンより古い」 | Kubernetesが1.30以上か確認する | [作業用Podの準備](remediation-setup-work-pods.md#kubernetes-language-updates) |
| `work_runtime_class_unsupported`：「作業用 Pod に RuntimeClass が設定されているが、まだ対応していない」 | `remediation.worker.kubernetes.runtime_class`が空か確認する | [Kubernetesの作業用コンテナ設定](configuration.md#remediation-worker-kubernetes) |
| `work_admission_unverified`：「作業用 namespace の admission policy が有効であると確認できず、作業用 Pod を起動しなかった」 | 詳細が指すPod作成規則の確認失敗を調べる | [作業用Podの準備](remediation-setup-work-pods.md#kubernetes-language-updates) |
| `work_priority_class_missing`：「作業用 Pod に設定した PriorityClass が存在しない」 | 指定したPriorityClassが存在し、`preemptionPolicy: Never`か確認する | [Kubernetesの作業用コンテナ設定](configuration.md#remediation-worker-kubernetes) |
| `work_pod_limit`：「作業用 namespace の Pod 数またはクォータが上限で、更新は次回に持ち越した」 | 作業用namespaceのPod数とクォータの空きを確認する | [Kubernetesの作業用コンテナ設定](configuration.md#remediation-worker-kubernetes) |
| `work_pod_not_started`：「作業用 Pod が時間内に起動しなかった」 | Podのイベントで起動を妨げた理由を確認する | [作業用Podの準備](remediation-setup-work-pods.md#kubernetes-language-updates) |
| `update_result_invalid`：詳細に結果ログの欠落がある | 実行ノードの`containerLogMaxSize`が`144Mi`以上か確認する | [作業用Podの準備](remediation-setup-work-pods.md#kubernetes-language-updates) |

`work_admission_unverified`では、詳細に従ってRBAC、Pod作成規則とパラメータ、クラスタの版の取得結果を確認してください。
`update_result_invalid`では、結果ログの切り詰めやローテーションも確認してください。

`work_pod_not_started`では、作業用namespace内の`io.kestrelynx.work=v1`ラベルが付いたPodを探し、作成時刻を失敗した更新の時刻と照合してください。
作業用Podは処理終了時に削除されるため、更新の実行中に確認してください。

次の例の`WORK_NAMESPACE`は`remediation.worker.kubernetes.namespace`の値、`POD_NAME`は確認するPod名に置き換えてください。

```sh
kubectl -n WORK_NAMESPACE get pods -l io.kestrelynx.work=v1 -o custom-columns=NAME:.metadata.name,CREATED:.metadata.creationTimestamp
kubectl -n WORK_NAMESPACE get events --field-selector involvedObject.name=POD_NAME
```

Podが残っていない場合は、同じ実行時刻のKestreLynxのログと通知の`reason`・`detail`を確認してください。

## PRを作れない場合の確認 {#check-missing-pr}

PR処理は、採用できる更新とソースの編集条件を確認し、既存PRとの重複を判定します。
更新候補があるのにPRがない場合は、次の表を確認してください。

| 症状 | 確認すること | 参照先 |
| --- | --- | --- |
| 候補はあるがPRがない | PR作成の有効化と対象ファイルが編集可能かを確認する | [基本設定](configuration.md#remediation-basics)・[対応する入力形式](remediation-reference.md#supported-inputs) |
| `undeclared_affected_workload`：「列挙されていないコンテナが images の項目の値を宣言しており、編集の影響を受けうる」 | 詳細に示されたコンテナがタグの変更で影響を受けるか確認する | [KustomizeのPR](remediation-kubernetes-logic.md#kustomize-prs)・[HelmのvaluesのPR](remediation-kubernetes-logic.md#helm-values-prs) |
| `init_container_unverified`：「列挙した init container が、稼働コンテナと同じイメージを動かしたことを確認できない」 | 表の後に示す同一Pod内の比較条件を確認する | [KustomizeのPR](remediation-kubernetes-logic.md#kustomize-prs)・[HelmのvaluesのPR](remediation-kubernetes-logic.md#helm-values-prs) |
| Kustomizeが`kustomize_*`で手動対応になる | 対象の`images[].name`と文字列の`newTag`を確認する | [Kustomizeの形式](remediation-source-formats.md#kustomize-formats) |
| `kustomize_image_automation`：「newTag の行に Flux image automation の目印がある」 | `newTag`の行に`$imagepolicy`を含むコメントがないか確認する | [Kustomizeの形式](remediation-source-formats.md#kustomize-formats) |
| Helmのvaluesが`helm_*`で手動対応になる | 指定したキーのイメージ名に文字列のタグが明示されているか確認する | [Helmのvaluesの形式](remediation-source-formats.md#helm-values-formats) |
| `helm_image_automation`：「イメージの行に Flux image automation の目印がある」 | イメージを指定する行に`$imagepolicy`を含むコメントがないか確認する | [Helmのvaluesの形式](remediation-source-formats.md#helm-values-formats) |
| HelmのvaluesのPRで最終的な値の確認を求められる | 指定したキーの値を上書きする設定がないか確認する | [HelmのvaluesのPR設定](remediation-setup-kubernetes.md#helm-values-pull-requests) |
| `github_refused`：「GitHub が書き込みを拒否した」 | tokenの対象リポジトリと書き込み権限を確認する | [GitHubアクセス](configuration.md#remediation-github)・[PR処理の理由](remediation-update-reason-codes.md#pr-reasons) |
| `pr_limit`：「1回の実行で作れる Pull Request の数の上限に達した」 | 今サイクルの新規PR数と`remediation.limits.new_prs_per_cycle`を照合する | [処理の上限](configuration.md#remediation-limits) |
| `open_pr_limit`：「開いている KestreLynx の Pull Request の数が上限に達した」 | 現在のPR数と`remediation.limits.open_prs`を照合する | [処理の上限](configuration.md#remediation-limits) |
| 既存PRに対応付けられる | 通知された既存PRが同じ更新を提案しているか確認する | [既存PRとの照合](remediation-pr-logic.md#existing-pr-matching) |
| 同じ更新を未マージで閉じた後にPRが出ない | 重複作成を抑止する対象の履歴を確認する | [閉じたPRの扱い](remediation-pr-logic.md#closed-prs) |
| PR準備中にソースが変わる | 通知の詳細を現在のファイルやベースブランチと照合する | [PR処理の理由](remediation-update-reason-codes.md#pr-reasons) |
| `candidate_changed`：「Pull Request の準備中に候補が変わった」 | 通知の詳細を現在の候補と照合する | [PR処理の理由](remediation-update-reason-codes.md#pr-reasons) |
| GitHub操作が失敗する | アクセス・通信の問題を操作結果の詳細で確認する | [PR操作イベントのフィールド](webhook-remediation-pr-reference.md#remediation-operation-fields)・[PR処理の理由](remediation-update-reason-codes.md#pr-reasons) |
| `write_outcome_unknown`：「GitHub への書き込みの結果が分からない」 | 次のサイクルで照合した操作結果を確認する | [書き込みの停止](remediation-pr-logic.md#write-stops)・[PR操作イベントのフィールド](webhook-remediation-pr-reference.md#remediation-operation-fields) |

症状ごとの補足は次のとおりです。

- 候補はあるがPRがない場合は、[計画が出ない場合の確認](#check-missing-plan)の順序でソースの対応付けも確認する
- Kustomizeでは未対応の構文・機能と、別の`images`の項目による影響も確認する
- Helmではイメージの書き方、YAMLのキーと構文も理由コードに沿って確認する
- Helmの最終値では、Flux HelmReleaseの`spec.values`、Argo CDの`parameters`・`valuesObject`・`valuesFrom`、CIの`--set`、ほかのvaluesファイルによる上書きと、タグの変更で影響を受けるコンテナを確認する
- GitHubが書き込みを拒否した場合はリポジトリの規則も確認する
- PR準備中にソースや候補が変わった場合は次のサイクルの結果を確認する

`undeclared_affected_workload`では、影響を受けるコンテナなら`affects`へ追加します。
確認対象は、同じリポジトリ・ブランチ・ファイルの同じKustomizeの項目やHelmのキーを指す対応付けです。

各対応付けで、`workload`のコンテナと`affects`のコンテナを合わせた一覧をそろえてください。
各対応付けの`workload`自体を同じ値にする必要はありません。

そのコンテナを更新対象に含めない場合は、Kustomizeの項目やHelmのキーが影響する範囲を変更します。
設定例は[KustomizeのPR設定](remediation-setup-kubernetes.md#kustomize-pull-requests)と[HelmのvaluesのPR設定](remediation-setup-kubernetes.md#helm-values-pull-requests)を参照してください。

`init_container_unverified`では、`workload`と`affects`に列挙したワークロードで観測した各Podを確認します。
通常のinit containerと、同じPod内で`workload`・`affects`に列挙した稼働コンテナを、次の条件で比較します。

| 比較するもの | 確認するフィールド | 一致条件 |
| --- | --- | --- |
| init containerの宣言と実行時のイメージ名 | `spec.initContainers[].image`と`status.initContainerStatuses[].image` | 同じコンテナ名の宣言と実行時の参照先が一致 |
| init containerと稼働コンテナのイメージ名 | Pod status内の各コンテナの`image` | 読み取った参照先が一致 |
| init containerと稼働コンテナのイメージの中身 | Pod status内の各コンテナの`imageID`とノードのplatform | 読み取ったdigestとplatformが一致 |

statusの`image`がイメージIDだけの場合は、`imageID`から読み取ったイメージ名を照合に使います。
比較条件に加えて、照合した稼働コンテナのスキャン結果が計画に含まれている必要があります。

Fluxのコメントの例は`# {"$imagepolicy": "flux:nginx:tag"}`で、対象行にあると自動編集を行いません。
Helmで確認する対象行は、`repository`・`registry`・`tag`または文字列でイメージを指定する行です。

結果不明のGitHub操作は、次のサイクルにKestreLynxが読み取りで照合します。
Webhookまたは`prs.json`の`operations[]`から、結果不明の操作と同じ`id`を持つイベントを探してください。

照合の完了と操作の成否は、次のフィールドで分けて確認します。

| フィールドと値 | 意味 |
| --- | --- |
| `phase: settled` | 照合後の扱いが確定した状態 |
| `result: ok` | 操作の成功を確認した状態 |
| `result: failed` | 操作の失敗または目的の変更が成立していないことを確認した状態 |
| `result: unknown` | 操作の成否を確定できない状態 |
| `error` | エラーまたは照合で確認した内容の説明 |

作成されたか不明なGitのファイル内容・ファイル構成・コミットを使わずにやり直す場合は、`phase: settled`でも`result: unknown`が残ります。
書き込みの停止が解消しない場合は、[記録を照合できない場合の確認](#check-record-failure)へ進んでください。

## 記録を照合できない場合の確認 {#check-record-failure}

記録の照合は、`prs.json`とGitHub上のPR・操作結果を確認し、GitHubへの書き込みを進められるか判定する処理です。
「Pull Requestの作成を停止中」や記録のエラーが出た場合は、次の表を確認してください。

| 症状 | 確認すること | 参照先 |
| --- | --- | --- |
| 計画やPR処理の記録を保存できない | ログに示された保存先と永続ボリュームのマウントを確認する | [基本設定](configuration.md#remediation-basics)・[保存処理の理由](remediation-update-reason-codes.md#storage-reasons) |
| `store_locked`：「Pull Request の記録が別のプロセスにロックされている」 | 同じ保存先を使う別のKestreLynxが動いていないか確認する | [保存処理の理由](remediation-update-reason-codes.md#storage-reasons) |
| `records_unverified`：「既存の Pull Request の記録を確認できない」 | PR本文末尾のHTMLコメントに識別マーカーが残っているか確認する | [記録の復旧](remediation-pr-logic.md#record-recovery) |
| `reconciliation_failed`：「既存の Pull Request との突き合わせに失敗した」 | GitHubへのアクセスと通知の詳細を確認する | [記録の復旧](remediation-pr-logic.md#record-recovery)・[PR処理の理由](remediation-update-reason-codes.md#pr-reasons) |
| 記録の読み取りで`parse plan`・`parse pull request records`が出る | エラー文末のJSON構文・型のエラーと、対象ファイルの該当箇所を照合する | [書き込みの停止](remediation-pr-logic.md#write-stops) |
| `unsupported plan version`・`unsupported pull request record version`が出る | ファイルの版を示す`has version`と、利用中のビルドが読む版を示す`this build reads`が一致するか確認する | [書き込みの停止](remediation-pr-logic.md#write-stops) |
| `operation events are out of sequence`が出る | `prs.json`の`operations[]`を、表の後に示す条件と照合する | [書き込みの停止](remediation-pr-logic.md#write-stops) |
| `storage_full`：「Pull Request の記録が満杯である」 | 未配信または未確定のため残っている操作履歴を確認する | [書き込みの停止](remediation-pr-logic.md#write-stops)・[保存処理の理由](remediation-update-reason-codes.md#storage-reasons) |

`operation events are out of sequence`では、`prs.json`の次の条件を確認してください。

- `operations[]`の`seq`が正の値で、配列の順に増加している
- 各`seq`が`next_seq`より小さい
- 各イベントの`id`が空でない

保存失敗では、保存先の権限と空き容量も確認してください。
既存PRを照合できない場合は、PR本文やリポジトリの変更履歴も確認してください。

識別マーカーは、PR本文の編集画面で確認できる`<!-- kestrelynx:`で始まり` -->`で終わるHTMLコメントです。
マーカーの欠落や変更がある場合の確認範囲は[記録の復旧](remediation-pr-logic.md#record-recovery)を参照してください。

原因を判断できない場合は、元の`plan.json`・`prs.json`、エラー全文、同じ実行時刻の通知とログを保持してください。
[診断情報の取得](#collect-diagnostics)で情報をそろえ、[書き込みの停止](remediation-pr-logic.md#write-stops)の停止条件と照合してください。

!!! warning "記録を保持する"

    再試行を強制するためにPR処理の記録を削除しないでください。
    閉じた更新の再作成を抑止し、過去の操作を照合するために必要です。
