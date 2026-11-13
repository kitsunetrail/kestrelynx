---
title: Webhookの修正計画のPR処理のフィールド
---

# Webhookの修正計画のPR処理のフィールド

このページでは、Webhookの修正計画に含まれるPR処理の結果、言語パッケージの更新内容、PR操作イベント、書き込みを停止する問題を説明します。
修正計画全体の構造は[修正計画の全体像](webhook-remediation-reference.md#remediation-overview)を参照してください。

PR作成が有効で修正計画がある場合、処理対象があれば`pull_request_summary`と`pull_requests`、未配信の操作イベントがあれば`operations`、書き込みを停止する問題があれば`problems`を出力します。
`operations`と`problems`は、`pull_requests`がない場合にも出力されます。

表のフィールド名は、表の前の文で示すオブジェクトからの相対パスです。
「値がないとき」の表記は、[レポートのフィールド](webhook-reference.md#report-fields)と同じです。

## PR処理のフィールド {#remediation-pr-fields}

`remediation`のPR処理に関するフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `pull_request_summary` | object | [状態別のPR処理の項目数](webhook-remediation-reference.md#remediation-summary-keys) | 処理対象がなければ省略 |
| `pull_requests` | objectの配列 | 更新対象ごとのPR処理結果 | 処理対象がなければ省略 |
| `operations` | objectの配列 | 未配信の[PR操作イベント](#remediation-operation-fields) | 省略 |
| `problems` | objectの配列 | PRの[書き込みを停止する問題](#remediation-problem-fields) | 省略 |

`pull_request_summary`のキーと件数の読み方、0件の扱いは、[件数の集計](webhook-remediation-reference.md#remediation-summary-keys)を参照してください。

状態値の定義は、[PRの状態値](remediation-reference.md#pr-status-values)を参照してください。

### 更新対象とPRの対応 {#pr-unit-fields}

`pull_requests[]`の1要素は、同じリポジトリ・ベースブランチ内で、まとめて更新する対象の処理結果です。
対象のまとめ方は`kind`によって異なります。

1要素には、作成したPRまたは同じ更新に対応するPRの情報が入ります。
PRを作成できなかった場合も要素が出力されるため、要素数は作成したPR数とは一致しません。

PRを識別するときは、`repo`と`number`を組み合わせます。

`pull_requests[]`の1要素のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `kind` | string | [更新対象の種類](#pr-unit-kinds) | Composeのタグ更新なら省略 |
| `key` | string | `pull_requests[]`の1要素を識別する値 | — |
| `repo` | string | 更新先リポジトリの`owner/name` | — |
| `base_branch` | string | PRの取り込み先となるブランチ | — |
| `path` | string | 更新対象を代表するリポジトリ内のファイルパス | — |
| `services` | stringの配列 | 更新対象のサービス名またはワークロードを表す一覧 | `[]` |
| `workloads` | stringの配列 | 更新対象の[ワークロードキー](webhook-diff-reference.md#reference-change-fields) | 省略 |
| `also_running` | objectの配列 | 同じイメージで稼働しているが更新対象に含まれない[サービスの情報](webhook-remediation-reference.md#remediation-services) | 省略 |
| `current_ref` | string | 更新前のイメージ名 | `""` |
| `candidate_tag` | string | 更新先イメージのタグ | 省略 |
| `candidate_digest` | string | 更新先イメージのmanifestまたはイメージインデックスのdigest | 省略 |
| `status` | string | [PR処理の状態](remediation-reference.md#pr-status-values) | — |
| `reason` | string | PR処理結果の[理由コード](remediation-reference.md#reason-codes) | 省略 |
| `detail` | string | PR処理結果を補足する説明文 | 省略 |
| `number` | integer | 対応するPRの番号 | `0`なら省略 |
| `url` | string | 対応するPRのURL | 省略 |
| `state` | string | 対応するPRについて記録された[状態](remediation-reference.md#pr-status-values) | 省略 |
| `user_modified` | boolean | 作成時の記録と異なる変更がPRに見つかったかどうか | `false`なら省略 |
| `target_key` | string | 編集するファイルと位置の組み合わせを識別する値 | 省略 |
| `update_key` | string | 同じ編集対象に対する更新内容を識別する値 | 省略 |
| `attempt_key` | string | 更新内容と作成するコミットの入力を識別する値 | 省略 |
| `fix_target_count` | integer | 切り詰め前の修正対象の件数 | `0` |
| `fix_targets` | objectの配列 | この更新で解消する[修正対象](#pr-fix-target-fields) | 省略 |
| `fix_targets_truncated` | boolean | 修正対象の一覧を100件に切り詰めたかどうか | `false`なら省略 |
| `replaced_by` | integer | このPRを置き換えた新しいPRの番号 | `0`なら省略 |
| `replacing` | objectの配列 | このPRが置き換える古いPRごとの[進行状況](#pr-replacing-fields) | 省略 |
| `replaced` | integerの配列 | このPRへの置き換えが完了した古いPRの番号 | 省略 |
| `item_key` | string | 対応する`language_items[]`の要素の`key` | 省略 |
| `language` | object | [言語パッケージ更新の内容](#pr-language-fields) | 省略 |

次のフィールドには補足があります。

- `key`
    - GitHubへの問い合わせ前から決まる識別子で、PR番号とは別の値
    - 通知間で同じ処理対象を照合するときに使い、`items[].key`や`dockerfile_items[].key`との一致は前提にしない
- `item_key`
    - `kind`が`language`の場合に、`language_items[].key`と照合する
- `target_key`
    - 更新の種類、リポジトリ、ベースブランチ、ファイル、編集位置を識別し、更新前後の版が変わっても編集対象が同じなら同じ値
    - 通知間の`pull_requests[].target_key`と照合して、同じ編集対象の提案を関連付ける
- `update_key`
    - イメージ更新では更新前の参照と更新先のタグ・digest、言語パッケージ更新では採用した版や依存ファイルの変更内容を区別する
    - Kubernetesマニフェストの更新では、[ソースの対応付け](configuration.md#remediation-mappings)の`workload`で指定したコンテナの組み合わせも区別する
    - Kustomize・Helmのvaluesの更新では、設定の`workload`と`affects`で指定したコンテナの組み合わせも区別する
    - 通知間の`pull_requests[].update_key`と照合して、同じ更新の提案を関連付ける
- `attempt_key`
    - 同じ更新でも、ベースコミットや変更前後のファイル内容が変わると別の値になる
    - 同じ入力から処理を再開する場合は同じ値になるため、実行回数を数える用途には使わない
    - `operations[].attempt_key`と照合して、そのPR作成に関係する操作をまとめる
- `target_key`・`update_key`・`attempt_key`
    - 値はSHA-256を表す64文字の16進文字列で、受信した文字列をそのまま比較する
    - 処理の途中で停止した場合は、まだ決まっていないキーを省略する
- `also_running`
    - Composeでは、対応付けがないサービスなどが入る
    - Kubernetesマニフェストの更新では、設定の`workload`で指定していないコンテナなどが入る
    - Kustomize・Helmのvaluesの更新では、設定の`workload`と`affects`で指定していないコンテナなどが入る
- `user_modified`
    - PRの先頭コミット、取り込み先、作成元リポジトリなどが作成時の記録と異なる場合に`true`
- `replaced_by`・`replacing`・`replaced`
    - PR番号は、この要素の`repo`内の番号
    - `replacing`と`replaced`には、Webhook出力時の件数による切り詰めを行わない

### 更新対象の種類 {#pr-unit-kinds}

`kind`の値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| 省略 | Composeのタグ更新で、同じファイル内で同じイメージ参照を使うサービスをまとめる |
| `kubernetes` | Kubernetesマニフェストのタグ更新で、同じファイル内で同じイメージ参照を使うコンテナをまとめる |
| `kustomize` | Kustomizeの`images`の1項目を更新する |
| `helm_values` | Helmのvaluesで設定した1つのキーを更新する |
| `dockerfile` | Dockerfileの1つの`FROM`を更新する |
| `language` | 1つの依存ファイルのディレクトリについて、パッケージをまとめて更新する |

`kind`ごとの`path`と`services`の値は次のとおりです。

| `kind` | `path`が示すファイル | `services`に入る値 |
| --- | --- | --- |
| 省略（Compose） | Composeファイル | 編集するComposeファイル内のサービス名 |
| `kubernetes` | Kubernetesマニフェスト | [ワークロードキー](webhook-diff-reference.md#reference-change-fields) |
| `kustomize` | kustomizationファイル | [ワークロードキー](webhook-diff-reference.md#reference-change-fields) |
| `helm_values` | valuesファイル | [ワークロードキー](webhook-diff-reference.md#reference-change-fields) |
| `dockerfile` | Dockerfile | 各ワークロードキーから取り出した名前を重複なく並べた一覧 |
| `language` | 更新対象を代表する依存ファイル | 各ワークロードキーから取り出した名前を重複なく並べた一覧 |

`kind`が`language`の場合、`path`が示す依存ファイルは次のとおりです。

| パッケージマネージャー | 依存ファイル |
| --- | --- |
| npm | `package-lock.json` |
| pnpm | `pnpm-lock.yaml` |
| uv | `uv.lock` |
| pip | `requirements.txt` |
| Go | `go.mod` |
| Maven | ルートの`pom.xml` |
| Gradle | `gradle.lockfile` |

言語パッケージのPRでは、`path`以外の依存ファイルも変更する場合があります。

`dockerfile`・`language`でワークロードキーから取り出す名前は次のとおりです。

| 対象 | 取り出す名前 |
| --- | --- |
| Compose | サービス名 |
| Kubernetes | ワークロード名 |
| 所属不明のDockerコンテナ | コンテナ名 |
| 所属不明のKubernetesコンテナ | Pod名 |

次のフィールドには補足があります。

- `current_ref`
    - Compose・`kubernetes`・`kustomize`・`helm_values`では、更新対象が使っている稼働イメージの参照
    - `dockerfile`では、更新対象の`FROM`に指定されたベースイメージの参照
    - `language`では`""`
- `candidate_tag`・`candidate_digest`
    - `language`では省略する

### 修正対象 {#pr-fix-target-fields}

`pull_requests[].fix_targets[]`の1要素は、ある位置のあるパッケージについて解消する脆弱性を表します。
フィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `location` | string | 修正対象が属する編集位置または依存ファイル内の位置 | — |
| `vuln_id` | string | 解消する脆弱性のID | — |
| `package` | string | 修正対象のパッケージ名 | — |
| `ecosystem` | string | 修正対象の[パッケージの種類](webhook-reference.md#package-fields) | 省略 |

次のフィールドには補足があります。

- `location`
    - Composeでは`services.<サービス名>.image`
    - `kubernetes`では`<Kind>/<namespace>/<name>/<container>`で、`Kind`と`name`は対応付けたファイル内のオブジェクト、`namespace`はワークロードの名前空間
    - `kustomize`では`images[<name>].newTag`
    - `helm_values`では設定した`helm_values.key`
    - `dockerfile`では0始まりのステージ番号を使う`stages[<番号>]`で、ステージ名があれば小文字にした名前を`:<名前>`として付ける
    - `language`では依存ファイル内で照合したパッケージの位置で、位置が得られなければ更新対象の依存ファイルのパス
- `package`
    - 言語パッケージでは、依存ファイルとの照合に使う正規化後の名前になる場合がある

一覧は最大100件です。
全件数は`pull_requests[].fix_target_count`で確認し、100件を超える場合は`pull_requests[].fix_targets_truncated`が`true`になります。

件数は脆弱性IDだけでまとめず、位置とパッケージの違いも区別します。
ベースイメージ更新では、検出されたレイヤーの集合が違う対象も別に数えます。

レイヤー情報はこの配列に出力しません。
Webhookを受け取るプログラムでは、見えているフィールドが同じ要素を重複として除かないでください。

### PRの置き換え {#pr-replacing-fields}

`pull_requests[].replacing[]`の1要素は、古いPRをこのPRで置き換える処理の進行状況を表します。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `old_number` | integer | 置き換える古いPRの番号 | — |
| `state` | string | 古いPRの置き換え処理の状態 | — |

`state`の値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `pending` | 置き換えを決め、まだ操作を送っていない |
| `commented` | 古いPRに置き換えを知らせるコメントがある |
| `closed` | クローズ操作を送ったが、結果の確認が済んでいない |
| `done` | 古いPRを置き換え済みとして記録した |
| `abandoned` | 置き換えの条件を満たさなくなり、処理を打ち切った |

`replacing[].state`が`closed`でも、クローズの完了確認を表すとは限りません。
`replaced[]`には、置き換え処理が`done`となり、古いPRの状態も`replaced`と確認された番号が入ります。

置き換えの条件は、[古いPRの置き換え](remediation-logic.md#pr-replacement)を参照してください。

### PR処理の例 {#pr-unit-examples}

次の例は、ベースイメージ更新のPRを作成した出力から、集計とPR処理結果を抜粋したものです。

```json
{
  "remediation": {
    "pull_request_summary": {
      "pr_created": 1
    },
    "pull_requests": [
      {
        "kind": "dockerfile",
        "key": "dockerfile|ex/app|main|docker/Dockerfile|stages[0]:runtime",
        "repo": "ex/app",
        "base_branch": "main",
        "path": "docker/Dockerfile",
        "services": ["app"],
        "workloads": ["compose/shop/app"],
        "current_ref": "python:3.12.3-slim",
        "candidate_tag": "3.12.5-slim",
        "status": "pr_created",
        "number": 7,
        "url": "https://github.com/ex/app/pull/7",
        "state": "open",
        "fix_target_count": 2,
        "fix_targets": [
          {
            "location": "stages[0]:runtime",
            "vuln_id": "CVE-2031-0001",
            "package": "libc"
          },
          {
            "location": "stages[0]:runtime",
            "vuln_id": "CVE-2031-0002",
            "package": "libc"
          }
        ]
      }
    ]
  }
}
```

次の例は、言語パッケージ更新の`pull_requests[]`の1要素から、対象を表すフィールドを抜粋したものです。

```json
{
  "kind": "language",
  "key": "language|ex/app|main|package-lock.json",
  "repo": "ex/app",
  "base_branch": "main",
  "path": "package-lock.json",
  "services": ["api", "web"],
  "workloads": ["compose/shop/api", "compose/shop/web"],
  "current_ref": ""
}
```

## 言語パッケージ更新の内容 {#pr-language-fields}

`pull_requests[].language`は、PRで更新するパッケージと依存ファイルの変更内容を表します。
フィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `manager` | string | 依存ファイルを扱うパッケージマネージャー | — |
| `root` | string | リポジトリ内の依存ファイルのディレクトリ | — |
| `packages` | objectの配列 | [更新するパッケージ](#pr-language-package-fields) | `[]` |
| `manifest_edits` | objectの配列 | [依存ファイルの版指定の変更](#pr-language-edit-fields) | 省略 |
| `chain` | objectの配列 | 再解決のために[あわせて更新する直接依存](#pr-language-chain-fields) | 省略 |
| `remaining` | objectの配列 | [PRの更新から除外したパッケージ](#pr-language-remaining-fields) | 省略 |

`manager`の値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `npm` | npm |
| `pnpm` | pnpm |
| `uv` | uv |
| `pip` | pip |
| `go` | Go modules |
| `maven` | Maven |
| `gradle` | Gradle |

`root`がリポジトリのルートを指す場合は、`.`です。
対応する依存ファイルの形式は、[対応する入力形式](remediation-reference.md#supported-inputs)を参照してください。

### 更新するパッケージ {#pr-language-package-fields}

`pull_requests[].language.packages[]`の1要素は、PRで更新するパッケージ1つを表します。
フィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `name` | string | 更新するパッケージ名 | — |
| `ecosystem` | string | 更新する[パッケージの種類](webhook-reference.md#package-fields) | — |
| `relation` | string | プロジェクトから見た依存関係の区分 | 省略 |
| `from` | string | 更新対象のパッケージの稼働版 | — |
| `to` | string | PRで採用した更新先の版 | — |
| `major` | boolean | `from`から`to`への変更がメジャー版の変更に当たるかどうか | `false`なら省略 |
| `through` | stringの配列 | このパッケージを更新するためにあわせて更新した直接依存の名前 | 省略 |

`relation`の値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `direct` | プロジェクトが直接要求する依存 |
| `transitive` | 別のパッケージを経由する依存 |
| `mixed` | 直接依存と別のパッケージを経由する依存が混在 |

次のフィールドには補足があります。

- `from`
    - 作成済みのPRに対応付けた回は、その回の計画で確認した稼働版
- `major`
    - `0.x`ではマイナー版の変更も`true`
    - 版を読み取れず比較できない場合も省略するため、省略だけで変更の安全性を判断しない
- `through`
    - 更新前後の版は、同じ名前の`pull_requests[].language.chain[]`で確認する

### 依存ファイルの版指定の変更 {#pr-language-edit-fields}

`pull_requests[].language.manifest_edits[]`の1要素は、依存ファイル内の版指定1つの変更を表します。
フィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `file` | string | 版指定を書き換えるリポジトリ内のファイルパス | — |
| `section` | string | 版指定がある依存宣言の区分 | — |
| `name` | string | 版指定を書き換えるパッケージ名 | — |
| `from` | string | 変更前の版指定 | — |
| `to` | string | 変更後の版指定 | — |
| `major` | boolean | 変更後の版指定が変更前に許していたメジャー版を許さなくなるかどうか | `false`なら省略 |

`section`には、`dependencies`や`project.dependencies`など、依存ファイル内の区分が入ります。
`from`と`to`は`^4.17.15`のような版指定で、実際に採用した版は`pull_requests[].language.packages[].to`で確認します。

### あわせて更新する直接依存 {#pr-language-chain-fields}

`pull_requests[].language.chain[]`の1要素は、対象パッケージを更新するためにあわせて更新した直接依存1つを表します。

次の図は、プロジェクトとパッケージA・B・Cの依存関係を示します。

```text
プロジェクト
└── A            1.0.0から1.1.0へ更新する
    └── B        Cの版を0.5.0と指定している
        └── C    更新したいパッケージ
```

各パッケージの名前が入るフィールドは次のとおりです。

| パッケージ | 名前が入るフィールド |
| --- | --- |
| A | `name` |
| B | `held_by` |
| C | `held` |

次は、Aの更新を表す`chain[]`の1要素です。

```json
{
  "name": "A",
  "from": "1.0.0",
  "to": "1.1.0",
  "held": "C",
  "held_range": "0.5.0",
  "held_by": "B"
}
```

`pull_requests[].language.chain[]`の1要素のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `name` | string | あわせて更新する直接依存の名前 | — |
| `from` | string | 直接依存の変更前の版 | `""` |
| `to` | string | 直接依存の変更後の版 | `""` |
| `held` | string | 古い版を指定されていたパッケージ名 | 省略 |
| `held_range` | string | 更新を妨げていた版指定 | 省略 |
| `held_by` | string | 直接依存と`held`の間で古い版を指定していたパッケージ名 | 省略 |

`held_by`は、直接依存自身が古い版を指定している場合には省略します。
再解決の条件は、[再解決の検査条件](remediation-reference.md#dependent-reresolution-rules)を参照してください。

### PRの更新から除外したパッケージ {#pr-language-remaining-fields}

`pull_requests[].language.remaining[]`の1要素は、更新を予定していたパッケージのうち、PRの更新から除外した1つを表します。
フィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `name` | string | PRの更新から除外したパッケージ名 | — |
| `ecosystem` | string | 除外した[パッケージの種類](webhook-reference.md#package-fields) | — |
| `relation` | string | [プロジェクトから見た依存関係の区分](#pr-language-package-fields) | 省略 |
| `from` | string | 除外したパッケージの稼働版 | — |
| `target` | string | 予定していた更新先の下限の版 | `""` |
| `reason` | string | 更新から除外した[理由コード](remediation-reference.md#reason-codes) | — |
| `detail` | string | 除外理由を補足する説明文 | 省略 |
| `maven_bom` | object | 更新先の下限に届く[BOMの情報](#pr-language-bom-fields) | 省略 |

作成済みのPRに対応付けた回は、`pull_requests[].language.remaining[]`から除外情報を補います。
補完先は、名前とパッケージの種類が一致する`language_items[].packages[]`の要素です。

`global_node_modules`を理由とするパッケージは、この補完の対象外です。
`language_items[].update_executed`と`language_items[].post_update_check_executed`が`false`でも補完します。

補完先のフィールドと入る値は次のとおりです。

| フィールド | 入る値 |
| --- | --- |
| `language_items[].packages[].left_out` | `true` |
| `language_items[].packages[].action` | `"manual"` |
| `language_items[].packages[].reason` | 除外理由 |
| `language_items[].packages[].detail` | 補足がある場合にその説明文 |
| `language_items[].packages[].maven_bom` | 該当するBOM情報がある場合にその情報 |

部分的な更新の読み方は、[部分PR](remediation-results.md#partial-pull-requests)を参照してください。

### 除外したパッケージのBOM情報 {#pr-language-bom-fields}

`pull_requests[].language.remaining[].maven_bom`は、除外したパッケージを更新先の下限以上で管理するBOMの候補情報です。
フィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `bom` | string | BOMの`groupId:artifactId` | — |
| `property` | string | BOMの版を指定するプロパティ名 | 省略 |
| `from` | string | プロジェクトが取り込んでいるBOMの版 | — |
| `to` | string | 対象パッケージを更新先の下限以上で管理するBOMの候補版 | — |
| `manages` | string | `to`のBOMが管理する対象パッケージの版 | — |

このオブジェクトは、`pull_requests[].language.remaining[].reason`が`maven_bom_series_unreached`で、BOMの候補情報がある場合に出力します。
BOMの版は`from`と`to`、対象パッケージの版は`manages`で区別してください。

候補の意味は、[版の出所と書き換え](remediation-logic.md#maven-version-sources)と[Gradleの版の宣言と書き換え](remediation-logic.md#gradle-version-sources)を参照してください。

### 言語パッケージ更新の例 {#pr-language-example}

次は、npmのlodashとminimistを更新するPRの`pull_requests[].language`の例です。
`packages`で更新前後の版、`manifest_edits`で`package.json`のlodashの版指定の変更を確認してください。

```json
{
  "manager": "npm",
  "root": ".",
  "packages": [
    {
      "name": "lodash",
      "ecosystem": "node-pkg",
      "relation": "direct",
      "from": "4.17.15",
      "to": "4.17.21"
    },
    {
      "name": "minimist",
      "ecosystem": "node-pkg",
      "relation": "transitive",
      "from": "1.2.5",
      "to": "1.2.6"
    }
  ],
  "manifest_edits": [
    {
      "file": "package.json",
      "section": "dependencies",
      "name": "lodash",
      "from": "4.17.15",
      "to": "4.17.21"
    }
  ]
}
```

### 部分PRの例 {#remediation-json-example}

[部分PR](remediation-results.md#partial-pull-requests)は、まとめて更新しようとしたパッケージの一部だけを更新したPRです。

次の例は、部分PRを含むペイロードから主要なフィールドだけを抜粋したものです。
更新できたパッケージと、更新から除外したパッケージの記録先を確認してください。

- 更新できた`example-a`は、この例では`language_items[].packages[]`だけに記録
- 更新から除外した`example-b`は、`language_items[].packages[]`に`left_out: true`付きで、`pull_requests[].language.remaining[]`にも記録

```json
{
  "remediation": {
    "language_items": [
      {
        "category": "pr_candidate",
        "update_executed": true,
        "post_update_check_executed": true,
        "packages": [
          {
            "name": "example-a",
            "ecosystem": "node-pkg",
            "installed": "1.0.0",
            "adopted_version": "1.0.1",
            "action": "update",
            "reason": "update_verified"
          },
          {
            "name": "example-b",
            "ecosystem": "node-pkg",
            "installed": "2.0.0",
            "selection_lower_bound": "2.0.1",
            "action": "manual",
            "reason": "target_not_updated",
            "left_out": true
          }
        ]
      }
    ],
    "pull_requests": [
      {
        "kind": "language",
        "language": {
          "remaining": [
            {
              "name": "example-b",
              "ecosystem": "node-pkg",
              "from": "2.0.0",
              "target": "2.0.1",
              "reason": "target_not_updated"
            }
          ]
        }
      }
    ]
  }
}
```

採用条件は、[部分PRの成立条件](remediation-logic.md#partial-pr-selection)を参照してください。

## PR操作イベントのフィールド {#remediation-operation-fields}

`operations[]`は、まだ配信済みとして記録されていないPR操作イベントを、連番の昇順で出力します。
1つの操作について、送信前の記録、操作結果、後から確認した結果は、それぞれ別のイベントです。

PR処理の記録は、`remediation.storage_dir`の下の`prs.json`に保存します。
保存する内容は、[保存ファイル](remediation-reference.md#stored-records)を参照してください。

`operations[]`の1要素のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `seq` | integer | 同じ`prs.json`内で増加するイベントの連番 | — |
| `id` | string | 同じ操作の各段階を関連付ける識別子 | — |
| `at` | string | イベントを記録したUTCのRFC 3339形式の時刻 | — |
| `phase` | string | 操作のどの段階を記録したイベントかを表す値 | — |
| `kind` | string | GitHubに対する書き込み操作の種類 | — |
| `repo` | string | 操作対象リポジトリの`owner/name` | — |
| `attempt_key` | string | 関係するPR作成の試行内容を識別する値 | 省略 |
| `number` | integer | 操作対象のPR番号 | `0`なら省略 |
| `result` | string | 操作の結果 | 省略 |
| `error` | string | エラーまたは結果の確認内容を補足する説明文 | 省略 |

`phase`の値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `intent` | 操作を送る前に、その操作を行う予定を記録した |
| `result` | 操作を送った後に、得られた結果を記録した |
| `settled` | 結果が不明だった操作を後の処理で確認し、扱いを確定した |

`kind`の値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `create_blob` | Gitのファイル内容を作成する |
| `create_tree` | Gitのファイル構成を作成する |
| `create_commit` | コミットを作成する |
| `create_ref` | PR用のブランチを作成する |
| `create_pull` | PRを作成する |
| `create_comment` | PRに置き換えを知らせるコメントを作成する |
| `close_pull` | 置き換え対象のPRをクローズする |

`result`の値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `ok` | 操作の成功を確認できた |
| `failed` | 操作の失敗または目的の変更が成立していないことを確認した |
| `unknown` | 操作の成否を確定できない |

次のフィールドには補足があります。

- `seq`
    - リポジトリごとではなく、同じ`prs.json`を使うPR処理全体で増加する
    - 再送された同じイベントは同じ値を持つ
- `id`
    - 最初のイベントの連番を使う`op-<連番>`形式
    - 同じ操作の`intent`・`result`・`settled`で共通するが、各イベントの`seq`は異なる
- `attempt_key`
    - `pull_requests[].attempt_key`と照合でき、1つの値に複数の操作の`id`が対応する
    - 過去の未配信イベントも含むため、その通知の`pull_requests[]`に照合先があるとは限らない
- `number`
    - コメント作成やクローズでは操作対象の番号で、PRを新規作成するイベントでは成功後も省略される場合がある
- `phase`
    - `intent`だけでは、GitHubへ操作を送ったことまでは確認できない
    - `settled`でも、作成されたか不明なGitのファイル内容・ファイル構成・コミットを使わずにやり直す場合は、`result`が`unknown`のままになる
- `error`
    - 固定コードではなく説明文で、`settled`では`result`が`ok`でも確認内容が入る場合がある

Webhookを受け取るプログラムでイベントの重複を除くときは、同じ送信元の同じ`prs.json`に属する`seq`を使います。
`id`や`attempt_key`だけで重複を除くと、同じ操作の結果や後から確認したイベントを取りこぼします。

`prs.json`を削除した場合や、`prs.json`のない保存先に変更した場合は、`seq`が1から始まります。
そのため、過去に使った`seq`と`id`が再び使われます。

Webhookには、送信元を一意に識別する値や、`prs.json`の作り直しを識別する値がありません。
`environment.kind`・`environment.name`の一意性も保証されません。

複数の送信元や`prs.json`の作り直し前後のイベントは、受信データだけでは確実に区別できません。
運用上の対応として、次の方法があります。

- 送信元ごとに受信URLを分ける
- `prs.json`を作り直す際に、Webhookを受け取るプログラムの重複判定の記録を切り替える

配信と再送の扱いは、[修正計画の再送](notification-conditions.md#remediation-redelivery)を参照してください。

## 書き込み停止のフィールド {#remediation-problem-fields}

`problems[]`は、PRの書き込みを停止する問題を表します。
問題が続く間は各回の計画に含まれ、同じ計画では`code`・`repo`・`target`の組み合わせごとに1件となります。

`problems[]`の1要素のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `code` | string | 書き込みを停止する問題の分類 | — |
| `repo` | string | 問題があるリポジトリの`owner/name` | 全リポジトリに関わる場合は省略 |
| `target` | string | 問題があるファイルと対象位置を表す表示用文字列 | 対象を限定しない場合は省略 |
| `reason` | string | 問題の具体的な原因を示す[理由コード](remediation-reference.md#reason-codes) | 省略 |
| `detail` | string | 問題の内容を補足する説明文 | 省略 |

`code`の値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `write_blocked` | 記録とGitHub上の状態の不一致や処理の準備失敗などにより、書き込みを停止した |
| `storage_failed` | 修正計画またはPR処理の記録を保存できず、書き込みを停止した |
| `storage_full` | 操作イベントの保存領域に空きを確保できず、新しい書き込みを停止した |
| `records_unverified` | PRの記録を確認できず、書き込みを停止した |

`code`は問題の大きな分類、`reason`はその原因です。
たとえば`code`が`write_blocked`のとき、`reason`で`branch_not_ours`や`attempt_unsettled`などの原因を区別します。

次のフィールドには補足があります。

- `repo`
    - 値があれば、`pull_requests[].repo`と照合する
- `target`
    - `<ファイルパス> (<対象位置>, <対象位置>)`の形式で、対象位置が1つなら括弧内も1つ
    - ファイルパスは`pull_requests[].path`、Compose・Kubernetes・Kustomize・Helmのvalues・Dockerfileの対象位置は`pull_requests[].fix_targets[].location`と照らし合わせる
    - 言語パッケージ更新の対象位置は依存ファイルのディレクトリで、`pull_requests[].language.root`に対応する
    - `pull_requests[].key`や`pull_requests[].target_key`と完全一致する照合キーではない
    - `fix_targets`の省略・切り詰めや処理対象の変化があるため、その通知だけで対応する`pull_requests[]`の要素を特定できない場合がある
    - `repo`があり`target`がなければ、そのリポジトリ全体に関わる問題

停止条件は、[書き込みの停止](remediation-logic.md#write-stops)を参照してください。
