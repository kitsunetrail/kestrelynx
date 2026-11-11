---
title: Webhookの修正計画のベースイメージのフィールド
---

# Webhookの修正計画のベースイメージのフィールド

このページでは、汎用Webhookの`remediation`に含まれるベースイメージの修正計画、稼働イメージごとの結果、再ビルドの見込みのフィールドを説明します。
修正計画全体の構造は[修正計画の全体像](webhook-remediation-reference.md#remediation-overview)を参照してください。

表の読み方は[レポートのフィールド](webhook-reference.md#report-fields)を参照してください。
JSON例は、出力の一部を抜粋したものです。

## ベースイメージのフィールド {#remediation-dockerfile-fields}

`remediation`のベースイメージに関するフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `dockerfile_summary` | object | [分類別のベースイメージの項目数](webhook-remediation-reference.md#remediation-summary-keys) | 項目がなければ省略 |
| `dockerfile_items` | objectの配列 | Dockerfileのベースイメージに関する修正計画の項目 | 項目がなければ省略 |

`dockerfile_summary`は、`dockerfile_items[]`を`category`ごとに数えます。
キーは`pr_candidate`・`pull_again`・`manual`・`not_comparable`・`deferred`・`no_candidate`・`excluded`・`failed`で、項目がある場合は0件のキーも出力します。

各分類の意味は[計画の分類値](remediation-reference.md#category-values)を参照してください。

```json
{
  "dockerfile_summary": {
    "deferred": 0,
    "excluded": 0,
    "failed": 0,
    "manual": 1,
    "no_candidate": 1,
    "not_comparable": 1,
    "pr_candidate": 1,
    "pull_again": 0
  }
}
```

### 項目の単位とフィールド {#dockerfile-item-fields}

`dockerfile_items[]`には、ベースイメージを更新するときに書き換える`FROM`の行1つにつき1項目を作ります。
リポジトリ・ブランチ・Dockerfileのパスでファイルを特定し、その中のステージで書き換える`FROM`の行を特定します。

項目をまとめる場合と分ける場合は次のとおりです。

- 同じ`FROM`の行からビルドされる複数のビルド対象やワークロードは1項目にまとめる
- 同じベースイメージ名でも、別の`FROM`の行なら別項目にする

Dockerfileの取得や解析に失敗して`FROM`を特定できない場合は、取得できたファイルやビルド対象などの単位で失敗を記録します。
受信側で項目を識別するときは`key`を使い、ベースイメージ名だけで統合しないでください。

次は、ベースイメージの更新候補となった項目の抜粋です。

```json
{
  "key": "dockerfile:ex/app@main:docker/Dockerfile#stages[0]:runtime",
  "kind": "dockerfile",
  "fix_class": "base_image",
  "verification": "base_image_comparison",
  "final_image_verified": false,
  "category": "pr_candidate",
  "reason": "adopted",
  "priority": "act_now",
  "workloads": [
    "compose/shop/app"
  ],
  "base_ref": "python:3.12.3-slim",
  "base_kind": "pinned"
}
```

`dockerfile_items[]`の1要素のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `key` | string | 修正計画内で項目を識別するキー | — |
| `kind` | string | 修正対象の種類 | — |
| `fix_class` | string | 修正の種類 | — |
| `verification` | string | 検証の対象 | — |
| `final_image_verified` | boolean | 再ビルド後の完成イメージを検証したかを示す値 | `false` |
| `category` | string | 項目全体の[計画の分類値](remediation-reference.md#category-values) | — |
| `reason` | string | 分類の根拠となる[理由コード](remediation-reference.md#reason-codes) | 省略 |
| `detail` | string | 分類や理由に関する補足の説明文 | 省略 |
| `priority` | string | 対象ワークロードの稼働イメージの修正可能な所見で最も高い[優先度](webhook-reference.md#priority-values) | 省略 |
| `workloads` | stringの配列 | 対象の[ワークロードキー](webhook-diff-reference.md#reference-change-fields)の一覧 | `[]` |
| `source` | object | Dockerfileと書き換える`FROM`の行を示す[ソース情報](#dockerfile-source-fields) | — |
| `base_ref` | string | `FROM`に書かれた現在のベースイメージの参照名 | 省略 |
| `base_kind` | string | 現在のベースイメージのタグの分類 | 省略 |
| `candidate` | object | 更新候補のベースの[イメージ情報](webhook-remediation-reference.md#remediation-image-state) | 省略 |
| `counts` | object | 稼働イメージごとの比較をまとめた[件数](#dockerfile-count-fields) | — |
| `rebuild_runtimes` | objectの配列 | 項目全体の[ランタイムの再ビルドの見込み](#dockerfile-rebuild-runtimes) | 省略 |
| `rebuild_check` | object | 項目全体の[現在のベースとの突き合わせ](#dockerfile-rebuild-check) | 省略 |
| `entities` | objectの配列 | [稼働イメージごとの結果](#dockerfile-entity-fields) | 省略 |
| `pull_request` | object | 項目に対応する[PR処理の結果](#dockerfile-pull-request-fields) | 省略 |
| `newer_series` | object | 稼働イメージ全体をまとめた[新しい系列の確認結果](webhook-remediation-reference.md#remediation-newer-series) | 省略 |
| `awaiting_deploy` | object | 稼働イメージへの反映を待つ[マージ済みPR](#dockerfile-awaiting-deploy-fields)の情報 | 省略 |

`dockerfile_items[].kind`の値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `dockerfile` | Dockerfileの変更に関する項目 |

`dockerfile_items[].fix_class`の値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `base_image` | ベースイメージの更新 |

`dockerfile_items[].verification`の値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `base_image_comparison` | 現在のベースイメージと候補のベースイメージの比較 |

`dockerfile_items[].base_kind`の値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `pinned` | `1.25.3`など、1つのリリースを指す固定タグ |
| `floating` | `1.25`や`latest`などの追従タグ |
| `excluded` | 候補探索の対象外となる参照 |

次のフィールドには補足があります。

- `priority`
    - 修正状態が`fixed`で、修正版の情報がある所見だけを対象とする
- `final_image_verified`
    - 完成イメージのビルドとスキャンは行わないため、常に`false`
    - 検証の範囲は[対象別の検証範囲](remediation-logic.md#verification-scope)を参照
- `candidate`
    - `dockerfile_items[].entities[]`の並び順で最初に見つかった`candidate_base`をコピーする
    - 候補の情報があっても、`category`が`pr_candidate`になるとは限らない
    - 項目全体の`category`が`pr_candidate`なら、すべての`entities[].candidate_base`の`tag`と`top_digest`は`candidate`と一致する
    - `platform`・`config_digest`・`manifest_digest`はプラットフォームによって異なることがあるため、個別の値は`dockerfile_items[].entities[].candidate_base`を参照
- `newer_series`
    - 項目全体の`dockerfile_items[].newer_series.candidates[]`には`comparison`と`scans`を付けない
    - 個別の比較とスキャン記録は`dockerfile_items[].entities[].newer_series`に含める

### ソース情報 {#dockerfile-source-fields}

`dockerfile_items[].source`のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `repository` | string | Dockerfileがあるリポジトリの`所有者/リポジトリ名` | — |
| `base_branch` | string | Dockerfileを読み取る基準ブランチ | — |
| `commit_sha` | string | Dockerfile側の基準ブランチで確認したコミットSHA | 省略 |
| `path` | string | リポジトリのルートからのDockerfileの相対パス | `""` |
| `targets` | stringの配列 | 対象ワークロードが指定するビルド対象のステージ名の一覧 | 省略 |
| `origin` | string | Dockerfileの場所を特定する情報の取得元 | 省略 |
| `compose_path` | string | 場所の特定に使ったComposeファイルのリポジトリ内の相対パス | 省略 |
| `files` | objectの配列 | 読み取った[ソースファイル](#dockerfile-source-file-fields)の一覧 | 省略 |
| `stage` | integer | 書き換える`FROM`の行が属するステージの0始まりの番号 | 未特定なら省略 |
| `platform` | string | 書き換える`FROM`の行に指定された固定の`--platform`の値 | 省略 |
| `stage_name` | string | 書き換える`FROM`の行が属するステージの`AS`名 | 省略 |
| `line` | integer | 書き換える`FROM`の行が始まる行番号（1始まり） | 未特定なら省略 |

`dockerfile_items[].source.origin`の値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `mapping` | 設定の対応付けから特定 |
| `compose_build` | Composeの`build`から特定 |
| `mapping_and_compose_build` | 設定の対応付けとComposeの`build`を参照 |

次のフィールドには補足があります。

- `targets`
    - 重複を除いて並べ替えた一覧で、要素の`""`はビルド対象を指定せず最後のステージを使うことを表す
    - ビルド対象のステージと、そのベースイメージを参照する`stage`は異なることがある
- `stage`
    - 最初のステージを表す`0`も出力する

#### ソースファイル {#dockerfile-source-file-fields}

`dockerfile_items[].source.files[]`の1要素のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `path` | string | ファイルがあるリポジトリのルートからの相対パス | — |
| `blob_sha` | string | 読み取ったファイルのGit blob SHA | — |
| `repository` | string | 項目のソースと異なる取得元のリポジトリ名 | 省略 |
| `base_branch` | string | 項目のソースと異なる取得元の基準ブランチ | 省略 |

`repository`と`base_branch`が省略されたファイルは、`dockerfile_items[].source`のリポジトリと基準ブランチに属します。

次は、Dockerfileの最初のステージの`FROM`の行を書き換える場合のソース情報の例です。

```json
{
  "repository": "ex/app",
  "base_branch": "main",
  "commit_sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "path": "docker/Dockerfile",
  "targets": [
    "runtime"
  ],
  "origin": "mapping",
  "files": [
    {
      "path": "docker/Dockerfile",
      "blob_sha": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    }
  ],
  "stage": 0,
  "stage_name": "runtime",
  "line": 3
}
```

### 修正対象と比較結果の件数 {#dockerfile-count-fields}

`dockerfile_items[].counts`は、`dockerfile_items[].entities[]`の対象と比較結果をまとめた件数です。
同じCVE ID・パッケージ名・エコシステム・パッケージ分類の組は、複数の稼働イメージにあっても1件に数えます。

`dockerfile_items[].counts`のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `targets` | integer | 稼働イメージ全体で重複を除いた修正対象の件数 | `0` |
| `resolved` | integer | その対象を持つすべての稼働イメージで解消した対象の件数 | `0` |
| `remaining` | integer | その対象を持つ稼働イメージのいずれかで残った対象の件数 | `0` |
| `introduced` | integer | 候補のベースイメージで新たに検出した所見の重複を除いた件数 | `0` |

次のフィールドには補足があります。

- `targets`
    - パッケージの版や出現場所が複数あっても、同じCVE ID・パッケージ名・エコシステム・分類の組は1件
    - `entities[].targets`の単純な合計ではない
- `resolved`・`remaining`
    - その対象を持たない稼働イメージは、その対象の集計に影響しない
    - 未比較や判定不能の対象は解消と残存のどちらにも数えない場合があるため、合計が`targets`より少なくなることがある
- `introduced`
    - 修正対象と同じCVE ID・パッケージ名・エコシステム・分類の組で重複を除く
    - 修正対象に含まれないパッケージの新規所見も数える

次は、対象の比較結果がない項目の件数の例です。

```json
{
  "targets": 0,
  "resolved": 0,
  "remaining": 0,
  "introduced": 0
}
```

### 反映待ちのマージ済みPR {#dockerfile-awaiting-deploy-fields}

`dockerfile_items[].awaiting_deploy`は、マージ済みで稼働イメージにまだ反映されていないベースイメージ更新のPRを表します。

出力する主な条件は次のとおりです。

- KestreLynxが作ったベースイメージ更新のPRがマージ済みである
- 項目の稼働イメージがすべて、そのPRを作ったときの稼働イメージのいずれかと同じである

マージ後のDockerfileでビルドしたイメージをデプロイすると、更新が反映されます。
この場合の`dockerfile_items[].reason`は`base_update_not_deployed`です。

`dockerfile_items[].awaiting_deploy`のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `number` | integer | マージ済みPRの番号 | — |
| `url` | string | マージ済みPRのURL | 省略 |
| `from` | string | PR前に`FROM`が指していた、稼働イメージの作成元のベースイメージ名 | — |
| `to` | string | PRが`FROM`に設定したタグ | — |

反映待ちの結果の読み方は[再ビルドの案内](remediation-results.md#rebuild-guidance)を参照してください。

### PR処理の結果 {#dockerfile-pull-request-fields}

`dockerfile_items[].pull_request`は、項目のベースイメージ更新に関するPR処理の結果を表します。

項目の更新に該当するPR処理がある場合に出力します。
PRを作成していない手動対応や保留などの処理結果も含みます。

`dockerfile_items[].pull_request`のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `status` | string | [PR処理の状態値](remediation-reference.md#pr-status-values) | — |
| `reason` | string | PR処理の結果に関する[理由コード](remediation-reference.md#reason-codes) | 省略 |
| `number` | integer | 対応するPRの番号 | 省略 |
| `url` | string | 対応するPRのURL | 省略 |
| `state` | string | 対応する[PR記録の状態値](remediation-reference.md#pr-status-values) | 省略 |

次は、PRを作成した結果の例です。

```json
{
  "status": "pr_created",
  "number": 7,
  "url": "https://github.com/ex/app/pull/7",
  "state": "open"
}
```

## 稼働イメージごとの結果 {#dockerfile-entity-fields}

`dockerfile_items[].entities[]`の1要素は、項目の対象のワークロードで動いているイメージ1つ分の結果です。
同じ`FROM`の行からビルドしたイメージでも、ワークロードによって動いているイメージが異なることがあるため、結果を分けます。

同じイメージかどうかは、`running_image.ref`と`running_image.content`の組で見分けます。
要素の分かれ方とまとまり方は次のとおりです。

- 同じイメージを複数のワークロードが使う場合は1要素にまとめ、各ワークロードの情報をその要素の`services[]`に並べる
- `running_image.content`がレジストリのdigestを使う場合は、イメージ名とdigestが同じでも、プラットフォームが違えば別の要素になる
    - `running_image.content`は内容の識別値で、この場合はプラットフォームも含む
- 内容を識別できない場合は`running_image.content`が`unconfirmed`となり、同じ`running_image.ref`の未確認のイメージを1要素にまとめる
    - この場合、同じ`ref`でも内容が同じとは確認できない

`dockerfile_items[].entities[]`の1要素のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `services` | objectの配列 | 稼働イメージを使う[サービスの情報](webhook-remediation-reference.md#remediation-services) | 省略 |
| `running_image` | object | 所見を検出した稼働中の[イメージ情報](webhook-remediation-reference.md#remediation-image-state) | — |
| `current_base` | object | `FROM`のタグが現在指すベースの[イメージ情報](webhook-remediation-reference.md#remediation-image-state) | 省略 |
| `candidate_base` | object | 更新候補のベースの[イメージ情報](webhook-remediation-reference.md#remediation-image-state) | 省略 |
| `layer_confirmation` | object | 稼働イメージと現在のベースの[レイヤーの照合結果](#dockerfile-layer-confirmation-fields) | — |
| `findings_by_layer` | object | 稼働イメージの[レイヤー別の所見件数](#dockerfile-layer-count-fields) | — |
| `category` | string | 稼働イメージごとの[計画の分類値](remediation-reference.md#category-values) | — |
| `reason` | string | 分類の根拠となる[理由コード](remediation-reference.md#reason-codes) | 省略 |
| `detail` | string | 分類や理由に関する補足の説明文 | 省略 |
| `targets` | integer | ベースに属する修正対象の件数 | `0` |
| `kev_targets` | integer | 修正対象のうちCISA KEVに掲載された対象の件数 | 0件なら省略 |
| `comparison` | object | 現在のベースと候補のベースを修正対象について比べた[比較結果](webhook-remediation-reference.md#remediation-comparison) | 省略 |
| `rebuild_runtimes` | objectの配列 | 稼働イメージごとの[ランタイムの再ビルドの見込み](#dockerfile-rebuild-runtimes) | 省略 |
| `rebuild_check` | object | 稼働イメージごとの[現在のベースとの突き合わせ](#dockerfile-rebuild-check) | 省略 |
| `scans` | objectの配列 | 現在のベースと候補のベースの[スキャンの記録](webhook-remediation-reference.md#remediation-scan-records) | 省略 |
| `newer_series` | object | 稼働イメージごとの[新しい系列の確認結果](webhook-remediation-reference.md#remediation-newer-series) | 省略 |

次のフィールドには補足があります。

- `targets`・`kev_targets`
    - CVE ID・パッケージ名・エコシステム・分類の組で重複を除いて数える
    - 修正対象の選定に到達していない場合も`targets`は`0`
- `comparison`
    - `verdicts[]`は稼働イメージの修正対象に絞った判定
    - 再ビルド後の完成イメージを比較した結果ではない
- `scans`
    - 現在のベースは`role: baseline`、候補のベースは`role: candidate`
    - 記録があるものだけを出力する

次は、稼働イメージごとの結果の抜粋です。

```json
{
  "running_image": {
    "ref": "shop-app:1",
    "content": "config:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "config_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "platform": "linux/amd64",
    "digest_kind_unverified": true
  },
  "layer_confirmation": {
    "status": "confirmed",
    "base_layers": 2,
    "image_layers": 3
  },
  "findings_by_layer": {
    "base": 3,
    "upper": 1,
    "unknown": 1
  },
  "category": "pr_candidate",
  "reason": "adopted",
  "targets": 3,
  "kev_targets": 1
}
```

### レイヤーの照合結果 {#dockerfile-layer-confirmation-fields}

`dockerfile_items[].entities[].layer_confirmation`のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `status` | string | レイヤーの照合状態 | — |
| `base_layers` | integer | 稼働イメージの先頭と一致したベースのレイヤー数 | 一致を確認できなければ省略 |
| `image_layers` | integer | 稼働イメージから取得したレイヤー数 | 0件なら省略 |
| `detail` | string | 照合状態に関する補足の説明文 | 省略 |

`dockerfile_items[].entities[].layer_confirmation.status`の値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `confirmed` | 現在のベースのレイヤー列が稼働イメージの先頭と一致 |
| `mismatch` | レイヤー情報を照合した結果、先頭と不一致 |
| `unusable` | レイヤー情報が不足または利用不能で照合できない |
| `not_checked` | レイヤーの照合に到達していない |

照合の範囲と判定条件は[ベースレイヤーの照合](remediation-logic.md#base-layer-matching)を参照してください。

### レイヤー別の所見件数 {#dockerfile-layer-count-fields}

`dockerfile_items[].entities[].findings_by_layer`のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `base` | integer | 現在のベースに属すると分類した所見の件数 | `0` |
| `upper` | integer | ベースより後のレイヤーに属すると分類した所見の件数 | `0` |
| `unknown` | integer | ベースと後のレイヤーのどちらにも分類できなかった所見の件数 | `0` |

所見の出現ごとに数えるため、CVE IDの重複を除いた件数ではありません。
修正対象に選ばれなかった所見も含みます。

分類に到達していない場合は3つとも`0`になるため、すべて`0`でも所見がないとは限りません。
結果を読むときは`dockerfile_items[].entities[].category`・`reason`・`layer_confirmation.status`も確認してください。

## ランタイムの再ビルドの見込み {#dockerfile-rebuild-runtimes}

`rebuild_runtimes[]`は、現在のベースのランタイムの版を引き継いだ場合に、稼働イメージで検出中のCVEがどう変わるかを表します。
稼働イメージごとの結果と、項目全体の集計の2か所にあります。

付く条件は次のとおりです。

- `dockerfile_items[].entities[].rebuild_runtimes`
    - 対応する`dockerfile_items[].entities[].reason`が`floating_base_unconfirmed`で、稼働イメージのランタイムの所見を現在のベースの版で確認できた場合に付く
    - 確認できたランタイムがなければ省略する
- `dockerfile_items[].rebuild_runtimes`
    - `dockerfile_items[].entities[]`が1要素以上あり、すべての`dockerfile_items[].entities[].reason`が`floating_base_unconfirmed`の場合に個別の結果をまとめる
    - 集計結果が空なら省略する
    - 別の理由の稼働イメージが混在する場合は項目全体を省略し、条件に該当する稼働イメージの個別の記録は残す

`dockerfile_items[].rebuild_runtimes[]`の1要素のフィールドは次のとおりで、`dockerfile_items[].entities[].rebuild_runtimes[]`の各要素も同じフィールドを持ちます。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `package` | string | ランタイム名 | — |
| `installed` | string | 稼働イメージのランタイムの版 | — |
| `base_version` | string | 現在のベースのランタイムの版 | — |
| `disappearing` | stringの配列 | 現在のベースの版を引き継げば出なくなる見込みのCVE ID | 省略 |
| `remaining` | stringの配列 | 現在のベースの版でも残るCVE ID | 省略 |

`dockerfile_items[].rebuild_runtimes[].package`の値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `Node.js` | Node.js本体 |
| `Python runtime` | Python本体 |

次のフィールドには補足があります。

- `disappearing`・`remaining`
    - 稼働イメージで検出中のCVEだけを対象とし、現在のベースの版で新たに増えるCVEは含めない
    - CVE IDの重複を除いて並べ替える
    - 項目全体では`package`・`installed`・`base_version`が同じ記録をまとめる
    - まとめた記録のいずれかで`remaining`にあるIDは、項目全体の`disappearing`に含めない

この結果はランタイムの版から求めた見込みで、完成イメージの検証ではありません。
条件と制約は[ベースレイヤーの照合](remediation-logic.md#base-layer-matching)と[再ビルドの案内](remediation-results.md#rebuild-guidance)を参照してください。

## 現在のベースとの突き合わせ {#dockerfile-rebuild-check}

`rebuild_check`は、稼働イメージと現在のベースをパッケージの場所・CVEで突き合わせた結果です。
完成イメージはビルドせず、`dockerfile_items[].final_image_verified`は`false`のままです。

突き合わせに使う所見は次のとおりです。

| イメージ | 突き合わせに使う所見 |
| --- | --- |
| 稼働イメージ | 比較する深刻度の範囲内で、修正状態が`fixed`かつ修正版の情報がある所見 |
| 現在のベース | 修正版のない所見も含め、比較する深刻度の範囲内のすべての所見（CVEが残っているかを確かめるため） |

場所の照合と未判定になる条件は[ベースレイヤーの照合](remediation-logic.md#base-layer-matching)を参照してください。

付く条件は次のとおりです。

- `dockerfile_items[].entities[].rebuild_check`
    - 対応する`dockerfile_items[].entities[].reason`が`floating_base_unconfirmed`で、突き合わせの処理結果がある場合に付く
    - 比較できなかった場合も`status: not_checked`として記録する
- `dockerfile_items[].rebuild_check`
    - `dockerfile_items[].entities[]`が1要素以上あり、すべての`dockerfile_items[].entities[].reason`が`floating_base_unconfirmed`の場合に個別の結果をまとめる
    - 別の理由の稼働イメージが混在する場合は項目全体を省略し、個別の記録は残す

`status`が`checked`で消える見込みの所見がなく、Slackとメールに何も表示しない場合も、Webhookには結果を出力します。

`dockerfile_items[].rebuild_check`のフィールドは次のとおりで、`dockerfile_items[].entities[].rebuild_check`も同じフィールドを持ちます。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `status` | string | 突き合わせの確認状態 | — |
| `reason` | string | 比較できなかった理由を表す[理由コード](remediation-reference.md#reason-codes) | 省略 |
| `detail` | string | 比較できなかった理由に関する補足の説明文 | 省略 |
| `gone` | objectの配列 | ベースの同じ場所に別の版があり、対象のCVEがない[パッケージの記録](#dockerfile-rebuild-package-fields) | 省略 |
| `remaining` | objectの配列 | ベースの同じ場所にも対象のCVEがある[パッケージの記録](#dockerfile-rebuild-package-fields) | 省略 |
| `not_in_base` | objectの配列 | ベースの同じ場所にないOSパッケージまたはグローバルな`node_modules`の[パッケージの記録](#dockerfile-rebuild-package-fields) | 省略 |
| `other_not_in_base` | integer | アプリの依存など、`not_in_base`の対象以外でベースの同じ場所にないパッケージの件数 | 0件なら省略 |
| `only_in_base` | objectの配列 | 現在のベースにだけ対応する修正可能な所見がある[パッケージの記録](#dockerfile-rebuild-package-fields) | 省略 |
| `undetermined` | integer | 判定できなかった所見の件数 | 0件なら省略 |
| `running_scan` | object | 稼働イメージの[スキャンの記録](webhook-remediation-reference.md#remediation-scan-records) | 省略 |
| `base_scan` | object | 現在のベースの[スキャンの記録](webhook-remediation-reference.md#remediation-scan-records) | 省略 |

`dockerfile_items[].rebuild_check.status`の値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `checked` | 対象の所見をすべて判定した |
| `partial` | 突き合わせを行ったが、未判定の所見がある |
| `not_checked` | 比較していない |

次のフィールドには補足があります。

- `not_in_base`
    - ベースから消えたパッケージとDockerfileの手順で足したパッケージを区別できない
- `other_not_in_base`
    - 稼働イメージごとの件数は、パッケージの分類・名前・版・パスの組で重複を除いて数える
- `only_in_base`
    - ベース側にある修正状態が`fixed`かつ修正版の情報がある所見のうち、稼働イメージの同じ場所に対応する所見がないものを含む
    - Dockerfileの手順で消す所見も含む
- `undetermined`
    - 言語ランタイム本体の所見は`rebuild_runtimes`で扱い、その記録で確認できない対象は`undetermined`に数える
- `running_scan`・`base_scan`
    - 稼働イメージごとの結果に記録し、項目全体の集計には付けない
    - どちらの記録も`role`は`baseline`なので、フィールド名で対象を区別する

### パッケージの記録 {#dockerfile-rebuild-package-fields}

`gone[]`・`remaining[]`・`not_in_base[]`・`only_in_base[]`の1要素は、1つの場所にあるパッケージの版と、その結果に該当するCVEをまとめた記録です。
CVEごとに結果が異なる場合は、同じパッケージが複数の配列に入ります。

`dockerfile_items[].rebuild_check.gone[]`の1要素のフィールドは次のとおりで、`remaining[]`・`not_in_base[]`・`only_in_base[]`と、稼働イメージごとの`rebuild_check`内の各配列の要素も同じフィールドを持ちます。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `name` | string | パッケージ名 | — |
| `version` | string | 記録の対象となるパッケージの版 | `""` |
| `class` | string | パッケージの分類 | — |
| `path` | string | スキャン結果にあるパッケージの場所を示す文字列 | 省略 |
| `owner` | string | グローバルな`node_modules`で、このパッケージを配下に持つパッケージ名 | 省略 |
| `base_version` | string | `gone`の記録に対応する現在のベースの同じ場所にある版 | 省略 |
| `vuln_ids` | stringの配列 | この記録の結果に該当するCVE IDの一覧 | — |

`dockerfile_items[].rebuild_check.gone[].class`の値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `os` | OSパッケージ |
| `lang` | 言語パッケージ |

次のフィールドには補足があります。

- `version`
    - `gone[]`・`remaining[]`・`not_in_base[]`では稼働イメージの版
    - `only_in_base[]`では現在のベースの版
- `path`
    - パッケージ自身のパスがあればその値を使い、得られなければ検出元のスキャン対象を示す文字列を使う
    - OSパッケージでは省略する
    - 出力する文字列は検出時の値で、場所の照合用に版を除いたパスではない
- `owner`
    - 例えば`usr/local/lib/node_modules/npm/node_modules/undici/package.json`にある依存では`npm`
- `base_version`
    - `gone[]`にだけ設定する
- `vuln_ids`
    - 重複を除いて並べ替えた1件以上のIDを含む

### 項目全体へのまとめ方 {#dockerfile-rebuild-check-reading}

稼働イメージごとの`rebuild_check`を`dockerfile_items[].rebuild_check`へまとめる決まりを説明します。

項目全体の`status`は、次の条件で決まります。

| 項目全体の`status` | 条件 |
| --- | --- |
| `not_checked` | 比較していない稼働イメージ（`not_checked`または結果のないもの）が1つでもある |
| `partial` | 比較していない稼働イメージがなく、`partial`が1つでもある |
| `checked` | すべての稼働イメージが`checked` |

フィールドごとのまとめ方は次のとおりです。

| フィールド | まとめ方 |
| --- | --- |
| `gone` | その所見を持つすべての稼働イメージで消えるものだけを含める |
| `gone`・`remaining`・`not_in_base`・`only_in_base` | パッケージの分類・名前・版・パス・`base_version`が同じ記録を1つにまとめ、CVE IDの重複を除く |
| `undetermined` | 稼働イメージごとの件数の合計 |
| `other_not_in_base` | 稼働イメージごとの件数の最大値 |

項目全体へのまとめ方には、次の補足があります。

- 項目全体が`not_checked`の場合は、確認できた稼働イメージのパッケージ一覧も項目全体には載せず、個別の結果に残す
- プラットフォームによって現在のベースの版が違う場合は、`base_version`ごとに別の記録にする

Dockerfileの手順の効果など、見込みの制約は[再ビルドの案内](remediation-results.md#rebuild-guidance)を参照してください。
