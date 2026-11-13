---
title: Webhookの修正計画の言語パッケージのフィールド
---

# Webhookの修正計画の言語パッケージのフィールド

このページでは、Webhookの`remediation`に含まれる言語パッケージの項目、パッケージごとの結果、修正版に上げられないときの案内を説明します。
修正計画全体の構造は[修正計画の全体像](webhook-remediation-reference.md#remediation-overview)を参照してください。

## 言語パッケージのフィールド {#remediation-language-fields}

`remediation`の言語パッケージに関するフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `language_summary` | object | [分類別の言語パッケージの項目数](webhook-remediation-reference.md#remediation-summary-keys) | 言語項目がなければ省略 |
| `language_items` | objectの配列 | 言語パッケージの修正計画の項目 | 省略 |

`language_summary`はパッケージ数ではなく、`language_items[]`の項目数を数えます。
出力するキーは`pr_candidate`、`dependency_update_candidate`、`rebuild_expected`、`manual`、`not_comparable`、`deferred`、`failed`で、該当項目がない分類も`0`で出力します。

次は、`language_summary`を抜粋した例です。

```json
{
  "language_summary": {
    "deferred": 1,
    "dependency_update_candidate": 1,
    "failed": 0,
    "manual": 1,
    "not_comparable": 0,
    "pr_candidate": 0,
    "rebuild_expected": 1
  }
}
```

### 項目の単位とフィールド {#language-item-fields}

`language_items[]`には、`package.json`や`go.mod`といった依存ファイルを置いているディレクトリ1つにつき、言語ごとに1項目を作ります。

このディレクトリは、[ソースの対応付け](configuration.md#remediation-mappings)の`remediation.mappings[].dependencies.directory`で指定したものです。
同じディレクトリに対応付けた複数のワークロードの所見は、言語ごとに1項目にまとめます。

次は、npmを特定できた項目の主要フィールドの抜粋です。

```json
{
  "key": "deps:ex/app@main:backend#npm",
  "category": "dependency_update_candidate",
  "reason": "update_candidate_in_source",
  "manager": "npm",
  "workloads": [
    "compose/shop/api"
  ],
  "update_executed": false,
  "post_update_check_executed": false,
  "package_count": 4
}
```

更新と検査を実行した項目の主要フィールドは、次のようになります。

```json
{
  "key": "deps:ex/app@main:backend#npm",
  "category": "pr_candidate",
  "reason": "update_verified",
  "update_executed": true,
  "post_update_check_executed": true
}
```

`language_items[]`の1要素のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `key` | string | [計画内の項目を識別するキー](#language-item-key) | — |
| `category` | string | 項目全体の[計画の分類値](remediation-reference.md#category-values) | — |
| `reason` | string | 分類の根拠となる[理由コード](remediation-reference.md#reason-codes) | 省略 |
| `detail` | string | 分類や理由を補足する説明文 | 省略 |
| `manager` | string | 依存ファイルを扱うパッケージマネージャー | 特定できなければ省略 |
| `priority` | string | 対象脆弱性の中で最も高い[優先度](webhook-reference.md#priority-values) | 省略 |
| `workloads` | stringの配列 | この依存ファイルのディレクトリに対応付けたワークロードキーの一覧 | `null`または`[]` |
| `source` | object | [依存ファイルの取得元](#language-source-fields) | — |
| `runtime_eol` | object | サポート終了により手動対応となる[実行環境](#language-runtime-eol-fields) | 該当なしなら省略 |
| `update_executed` | boolean | 最新の修正計画の処理で依存更新の操作を最後まで実行したかを示す | `false` |
| `post_update_check_executed` | boolean | 最新の修正計画の処理で更新結果を受け取り、検査したかを示す | `false` |
| `retry_after` | string | 公開後の待機が終わり、再試行できる日時をRFC 3339形式で示す | 省略 |
| `package_count` | integer | 一覧を省略する前のパッケージの総件数 | `0` |
| `packages` | objectの配列 | [パッケージごとの結果](#language-package-fields) | 省略 |
| `packages_truncated` | boolean | `packages`の一部を件数上限により省略した場合に`true`になる | 省略 |
| `update` | object | [更新の記録](webhook-remediation-update-reference.md#language-update-fields) | 記録がなければ省略 |
| `source_check` | object | [更新前後の依存ファイルの検査結果](webhook-remediation-check-reference.md#language-source-check-fields) | 記録がなければ省略 |
| `artifacts` | objectの配列 | [更新で生成したファイルの情報](webhook-remediation-check-reference.md#language-artifact-fields) | 省略 |
| `pull_request` | object | この項目に対応する[PR処理の結果](#language-pull-request-fields) | 対応する処理がなければ省略 |

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

次のフィールドには補足があります。

- `workloads`
    - 通常の計画では、設定で対応付けたワークロードキーを重複なく並べ替えて出力する
    - ワークロードキーの形式は[イメージ名の更新](webhook-diff-reference.md#reference-change-fields)を参照する
    - 一覧が設定されていない場合は`null`、空の一覧として保持されている場合は`[]`を出力する
    - `null`と`[]`に、対象不明と対象なしを区別する意味はない
- `post_update_check_executed`
    - 検査で不合格になった場合も`true`になり、検査の合格は`source_check.passed`で確認する
- `retry_after`
    - 待機中は、この日時だけを含み、`update.chain`を含まない場合がある
    - 待機と再試行の条件は[公開後の待機と再試行](remediation-reference.md#dependent-reresolution-waits)を参照する
- `packages`
    - 理由が`global_node_modules`のパッケージは、Slackとメールの「要判断」に出ない場合も含む

#### 項目の`key`の値 {#language-item-key}

`language_items[].key`は、計画内で項目を識別する値です。
`key`は`deps:<リポジトリ>@<基準ブランチ>:<ディレクトリ>#<末尾>`の形式で、リポジトリ名は小文字にそろえます。

上の1つ目の例の`key`は、リポジトリ`ex/app`の`main`ブランチにある`backend`ディレクトリを指します。
`key`の末尾が`#npm`になります。

`key`の末尾と項目に入る所見は次のとおりです。

| `key`の末尾 | 項目に入る所見 |
| --- | --- |
| `#npm`・`#pnpm` | Node.jsのパッケージの所見 |
| `#uv`・`#pip` | Pythonのパッケージの所見 |
| `#go` | Goバイナリに含まれるモジュールや標準ライブラリの所見 |
| `#maven`・`#gradle` | Javaアーカイブに含まれるパッケージの所見 |
| `#node-pkg` | パッケージマネージャーを特定できなかったNode.jsのパッケージの所見 |
| `#python-pkg` | パッケージマネージャーを特定できなかったPythonのパッケージの所見 |
| `#go-stdlib` | Goの標準ライブラリの所見 |
| `#unverified` | スキャンが稼働イメージの内容を確認できなかった所見 |

次の末尾には補足があります。

- `#npm`・`#pnpm`・`#uv`・`#pip`・`#go`・`#maven`・`#gradle`
    - 末尾は`manager`と同じ値になる
- `#node-pkg`・`#python-pkg`
    - マネージャーを特定する前に処理が止まった場合、または依存ファイルの組を特定できなかった場合に出力する
    - `manager`は省略する
- `#go-stdlib`
    - Goのモジュールと標準ライブラリの両方に所見がある場合に、標準ライブラリの所見だけを分ける
    - 標準ライブラリの所見だけの場合は分けずに`#go`の項目に入れる
- `#unverified`
    - 言語をまたいで1項目にまとめる
    - `category`は`not_comparable`、`reason`は`scan_not_pinned`になる
    - `manager`は省略する

項目の識別には`key`を使います。
同じディレクトリや同じパッケージ名でも、`key`が異なる項目をまとめないでください。

### 依存ファイルの取得元 {#language-source-fields}

`language_items[].source`のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `repository` | string | 依存ファイルを取得するリポジトリを`所有者/リポジトリ名`で示す | — |
| `base_branch` | string | 依存ファイルを取得する基準ブランチ | — |
| `directory` | string | リポジトリ内の依存ファイルのディレクトリを示し、ルートは`.` | — |
| `commit_sha` | string | 取得元として記録したコミットのSHA | 省略 |
| `files` | objectの配列 | [取得したファイル](#language-source-file-fields)の一覧 | 省略 |
| `absent` | stringの配列 | 入力の確認時に探したものの、存在しなかったファイルのリポジトリ内パス | 省略 |
| `origin` | string | 取得元の設定の由来 | `""` |
| `confidence` | string | 稼働イメージと取得元の対応付けの根拠 | `""` |

`origin`の値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `config` | 利用者の設定で指定した取得元 |

`confidence`の値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `asserted` | 利用者が明示した対応付け |

依存ファイルと稼働パッケージの名前や版が一致しても、そのファイルから稼働イメージをビルドしたことまでは確認していません。
確認する範囲は[ソースの確認](remediation-logic.md#source-verification)を参照してください。

`absent`には、後から追加されると入力条件が変わるファイルも含まれます。
たとえば、確認時に存在しなかった`pnpm-workspace.yaml`が該当します。

#### 取得したファイル {#language-source-file-fields}

`language_items[].source.files[]`の1要素のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `path` | string | ファイルのリポジトリ内パス | — |
| `blob_sha` | string | 取得したファイル内容を識別するGitのblobのSHA | — |
| `repository` | string | ファイルの取得元リポジトリ | 取得元のリポジトリとブランチが親の`source`と同じなら省略 |
| `base_branch` | string | ファイルの取得元ブランチ | 取得元のリポジトリとブランチが親の`source`と同じなら省略 |

Dockerfileの取得元にも、同じフィールドを持つファイル情報を使います。
`repository`と`base_branch`を省略した場合は、親の`source`の値を使います。

次は、ファイル一覧を含む`source`の例です。

```json
{
  "repository": "ex/app",
  "base_branch": "main",
  "directory": "backend",
  "commit_sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "files": [
    {
      "path": "backend/package.json",
      "blob_sha": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    },
    {
      "path": "backend/package-lock.json",
      "blob_sha": "cccccccccccccccccccccccccccccccccccccccc"
    }
  ],
  "origin": "config",
  "confidence": "asserted"
}
```

### サポート終了の実行環境 {#language-runtime-eol-fields}

`language_items[].runtime_eol`のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `id` | string | `node22`や`python3.8`のような実行環境の識別子 | — |
| `name` | string | `Node.js 22`や`Python 3.8`のような表示用の名前 | — |
| `eol` | string | サポート終了日を`YYYY-MM-DD`形式で示す | 不明なら省略 |

この情報は、項目の`reason`が`runtime_eol`の場合に付与します。
実行環境の選定は[実行環境の選定](remediation-logic.md#runtime-and-tool-versions)を参照してください。

### PR処理の結果 {#language-pull-request-fields}

`language_items[].pull_request`のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `status` | string | 対応するPR処理の[状態値](remediation-reference.md#pr-status-values) | — |
| `reason` | string | PR処理結果の[理由コード](remediation-reference.md#reason-codes) | 省略 |
| `detail` | string | PR処理結果を補足する説明文 | 省略 |
| `number` | integer | GitHubのPR番号 | 省略 |
| `url` | string | GitHubのPRのURL | 省略 |
| `state` | string | PR自体の[状態値](remediation-reference.md#pr-status-values) | 省略 |
| `target_key` | string | リポジトリ内の更新対象を識別するキー | 省略 |
| `update_key` | string | 対象に提案する更新内容を識別するキー | 省略 |
| `attempt_key` | string | 更新元のコミットと変更するファイル内容を含む、更新の試行を識別するキー | 省略 |

`pull_requests[]`のうち、`kind`が`language`で、`item_key`がこの言語項目の`key`と一致する処理の情報を載せます。
PRを作成できなかった処理も含むため、`pull_request`があっても`number`や`url`があるとは限りません。

識別キーによる照合は[既存PRとの照合](remediation-logic.md#existing-pr-matching)を参照してください。

## パッケージの結果 {#language-package-fields}

`language_items[].packages[]`の1要素は、稼働イメージで見つかったパッケージのうち、パッケージの種類・名前・版が同じもの1つ分の結果を表します。

依存ファイルから入れたパッケージとグローバルな`node_modules`にあるパッケージは、種類・名前・版が同じでも別の要素になります。
そのため、種類・名前・版が同じ要素が2つ出ることがあります。

グローバルな`node_modules`にあるパッケージの要素は、`reason`が`global_node_modules`になります。
Webhookを受け取るプログラムでは、種類・名前・版が同じ要素を重複として除かないでください。

次は、パッケージの主要フィールドを抜粋した例です。

```json
{
  "name": "express",
  "ecosystem": "node-pkg",
  "installed": "4.18.2",
  "selection_lower_bound": "4.19.2",
  "relation": "direct",
  "action": "update",
  "reason": "update_candidate_in_source",
  "occurrence_count": 1,
  "cve_count": 1,
  "kev_count": 1,
  "origin_count": 1
}
```

`language_items[].packages[]`の1要素のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `name` | string | 稼働イメージのスキャンで報告されたパッケージ名 | — |
| `normalized` | string | Pythonパッケージの名前を照合用に正規化した値 | Python以外なら省略 |
| `ecosystem` | string | 稼働イメージのスキャンで報告されたパッケージの種類 | — |
| `installed` | string | 稼働イメージで検出したパッケージの版 | — |
| `selection_lower_bound` | string | 更新候補の選定を始める修正版の下限 | 省略 |
| `adopted_version` | string | 更新後の依存ファイルにある対象パッケージの最も低い版 | 省略 |
| `relation` | string | プロジェクトから見た依存関係の区分 | 判定できなければ省略 |
| `action` | string | パッケージごとの[処理値](remediation-reference.md#action-values) | 省略 |
| `reason` | string | パッケージの処理の[理由コード](remediation-reference.md#reason-codes) | 省略 |
| `detail` | string | 処理や理由を補足する説明文 | 省略 |
| `left_out` | boolean | 計画した更新から除外された場合に`true`になる | 省略 |
| `through` | stringの配列 | 修正版に上げるために、あわせて更新した依存元の名前 | 省略 |
| `maven_bom` | object | 目標版に届く[BOMの案内](#language-maven-bom) | 該当する案内がなければ省略 |
| `fix_hint` | object | [修正版に上げられないときの案内](#language-fix-hint) | 該当する案内がなければ省略 |
| `occurrence_count` | integer | 一覧を省略する前の依存ファイル内の出現箇所の件数 | `0` |
| `occurrences` | objectの配列 | [依存ファイル内の出現箇所](#language-package-lists) | 省略 |
| `occurrences_truncated` | boolean | `occurrences`の一部を件数上限により省略した場合に`true`になる | 省略 |
| `cve_count` | integer | 一覧を省略する前の対象脆弱性の件数 | `0` |
| `kev_count` | integer | 対象脆弱性のうちCISA KEVに掲載された件数 | 0件なら省略 |
| `cves` | objectの配列 | [対象脆弱性](#language-package-cve-fields)の一覧 | 省略 |
| `cves_truncated` | boolean | `cves`の一部を件数上限により省略した場合に`true`になる | 省略 |
| `origin_count` | integer | 一覧を省略する前の検出元の件数 | `0` |
| `origins` | objectの配列 | パッケージの結果の元になった[稼働イメージでの検出元](#language-package-origin-fields) | 省略 |
| `origins_truncated` | boolean | `origins`の一部を件数上限により省略した場合に`true`になる | 省略 |

`ecosystem`の値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `node-pkg` | Node.jsのパッケージ |
| `python-pkg` | Pythonのパッケージ |
| `gobinary` | Goバイナリに含まれるモジュールや標準ライブラリ |
| `jar` | Javaアーカイブに含まれるパッケージ |

`relation`の値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `direct` | プロジェクトが直接要求する依存 |
| `transitive` | 別のパッケージを通じて要求する依存 |
| `mixed` | 直接依存と推移的依存の出現箇所を含む |

`normalized`は、名前を小文字にし、連続する`-`・`_`・`.`を1つの`-`にまとめた値です。
Pythonのパッケージは、名前の表記が違っても、この値と版が同じなら1要素にまとめます。

たとえば、`Foo_Bar..Baz`は`foo-bar-baz`になり、元の名前と同じ値になる場合も出力します。

一覧の件数上限は次のとおりです。

| 一覧 | 上限 | 省略前の件数 |
| --- | --- | --- |
| `language_items[].packages` | 1項目あたり100件 | `package_count` |
| `language_items[].packages[].occurrences` | 1パッケージあたり20件 | `occurrence_count` |
| `language_items[].packages[].cves` | 1パッケージあたり50件 | `cve_count` |
| `language_items[].packages[].origins` | 1パッケージあたり50件 | `origin_count` |

`cve_count`はパッケージ内で脆弱性IDを重複なく数え、`kev_count`も一覧の省略前に数えます。
`origin_count`はイメージ、パッケージ、脆弱性、検出箇所、ワークロードを含む検出元の組み合わせを重複なく数えるため、同じ脆弱性IDでも複数件になる場合があります。

`selection_lower_bound`と`adopted_version`の読み分けは[更新目標と採用版](remediation-results.md#target-and-adopted-version)を参照してください。
`action`が`update`でも、更新や検査を実行したとは限りません。

`mkdirp`の更新で`minimist`を修正版に上げる例では、`minimist`の`through`は`["mkdirp"]`です。
直接依存の版が変わらない場合は、途中で更新した依存元のうち、プロジェクトに最も近いものを載せます。

次のフィールドには補足があります。

- `through`
    - 再解決全体で求めた共通の一覧を、更新を妨げられていた各パッケージに設定する
    - 個々のパッケージの依存経路に絞らないため、ほかの対象の依存元も含む場合がある

`through`は、その項目に対応する作成済みのPRの情報から補う場合もあります。
最新の修正計画の処理で更新・検査を実行したかどうかは、`update_executed`と`post_update_check_executed`で確認します。

`left_out`と、その除外を示す`action`・`reason`・`detail`も、対応するPRの情報から補う場合があります。
部分PRの読み方は[部分PR](remediation-results.md#partial-pull-requests)を参照してください。

### 出現箇所・脆弱性・検出元 {#language-package-lists}

`language_items[].packages[].occurrences[]`の1要素のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `path` | string | 依存ファイル内の項目や記述箇所を識別する文字列 | 省略 |
| `version` | string | 更新前の依存ファイルから読み取った対象パッケージの版 | 省略 |
| `direct` | boolean | この出現箇所がプロジェクトの直接依存かを示す | `false` |
| `unpinned` | boolean | 単一の版に固定されていない要求の場合に`true`になる | 省略 |
| `constraint` | string | 要求する版の条件 | 省略 |
| `marker` | string | Pythonの依存宣言に付いている環境マーカー | 省略 |
| `extras` | stringの配列 | Pythonの依存宣言で指定した追加機能の名前 | 省略 |
| `matched` | boolean | 依存ファイルの記述を稼働パッケージに対応付けられた場合に`true`になる | 省略 |
| `manual_reason` | string | この出現箇所を自動更新できない[理由コード](remediation-reference.md#reason-codes) | 省略 |
| `detail` | string | 出現箇所や手動対応の理由を補足する説明文 | 省略 |

次のフィールドには補足があります。

- `path`
    - npmでは`node_modules/express`のようなlockfile内のパスを表す
    - pnpmではlockfile内のパッケージや依存宣言の識別子を表す
    - uvではパッケージ名と版を`名前==版`で表す
    - pipとGoでは、`source.directory`を基準とする`requirements.txt:3`や`go.mod:5`のようなファイル名と行番号を表す
    - Mavenでは`pom.xml`のパス、Gradleでは`gradle.lockfile`のパスを、リポジトリのルートを基準に表す
- `version`
    - 更新前の依存ファイルの版を保持し、稼働イメージの版は`installed`、更新後に採用した版は`adopted_version`で確認する
    - 版を固定していない要求や、依存ファイルだけでは版を読み取れない記述では省略する
- `matched`
    - Mavenでは、版を更新処理で確認する記述も対応付けられるため、`true`でも`version`がない場合がある

#### 対象脆弱性 {#language-package-cve-fields}

`language_items[].packages[].cves[]`の1要素のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `vuln_id` | string | 対象脆弱性のID | — |
| `severity` | string | 対象脆弱性の深刻度 | 省略 |
| `fixed_vers` | stringの配列 | 脆弱性情報が示す修正版を重複なく並べ替えた一覧 | 省略 |
| `priority` | string | 対象脆弱性の[優先度](webhook-reference.md#priority-values) | 省略 |
| `kev` | boolean | CISA KEVに掲載されている場合に`true`になる | 省略 |

`severity`の値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `CRITICAL` | 緊急 |
| `HIGH` | 高 |
| `MEDIUM` | 中 |
| `LOW` | 低 |
| `UNKNOWN` | 不明 |

#### 稼働イメージでの検出元 {#language-package-origin-fields}

`language_items[].packages[].origins[]`の1要素のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `entity` | string | 所見を検出したイメージ内容の識別子 | — |
| `ecosystem` | string | 検出元のパッケージの種類 | 省略 |
| `class` | string | 検出元のパッケージの分類 | 省略 |
| `name` | string | 検出元で報告されたパッケージ名 | — |
| `version` | string | 検出元で報告されたパッケージの版 | — |
| `vuln_id` | string | 検出した脆弱性のID | — |
| `target` | string | スキャナーが報告した検査対象の名前やパス | 省略 |
| `pkg_path` | string | スキャナーが報告したイメージ内のパッケージの所在 | 省略 |
| `workload` | string | この検出結果に対応する[ワークロードキー](webhook-diff-reference.md#reference-change-fields) | — |

`entity`は、`config:sha256:…`のようなdigestの種類と値に、判明している場合は`@linux/amd64`のようなプラットフォームを付けた文字列です。
有効なdigestを取得できない場合は`unconfirmed`になります。

`ecosystem`の値は[パッケージの結果](#language-package-fields)と同じです。
Pythonでは、`name`に正規化前の表記を保持するため、同じパッケージの検出元に異なる表記が入る場合があります。

`class`の値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `lang` | 言語パッケージ |
| `os` | OSパッケージ |

このページで扱う言語パッケージの検出元は通常`lang`です。
`origins`は稼働イメージでの検出記録で、更新前後の依存ファイルの検査結果は`language_items[].source_check`に入ります。

次は、同じパッケージの出現箇所・脆弱性・検出元を抜粋した例です。

```json
{
  "occurrences": [
    {
      "path": "node_modules/express",
      "version": "4.18.2",
      "direct": true,
      "matched": true
    }
  ],
  "cves": [
    {
      "vuln_id": "CVE-2032-0001",
      "severity": "HIGH",
      "fixed_vers": [
        "4.19.2"
      ],
      "kev": true
    }
  ],
  "origins": [
    {
      "entity": "config:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "ecosystem": "node-pkg",
      "class": "lang",
      "name": "express",
      "version": "4.18.2",
      "vuln_id": "CVE-2032-0001",
      "target": "Node.js",
      "pkg_path": "app/node_modules/express/package.json",
      "workload": "compose/shop/api"
    }
  ]
}
```

### BOMの案内 {#language-maven-bom}

`language_items[].packages[].maven_bom`のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `bom` | string | BOMの名前を`groupId:artifactId`で示す | — |
| `property` | string | BOMの版を指定するプロパティ名 | 省略 |
| `from` | string | プロジェクトが取り込んでいるBOMの版 | — |
| `to` | string | 対象パッケージを目標版以上で管理することを確認したBOMの版 | — |
| `manages` | string | `to`のBOMが管理する対象パッケージの版 | — |

この情報は、パッケージの`reason`が`maven_bom_series_unreached`で、案内を取得できた場合だけ付与します。

次のフィールドには補足があります。

- `to`
    - `from`と同じメジャー版で、`from`より後のマイナー版に属する正式版を示す
    - `language_items[].packages[].name`のパッケージを`selection_lower_bound`以上で管理することを確認できた中で、最も低いBOMの版を示す
    - 調査件数に上限があるため、公開済みのすべてのBOMを調べた結果とは限らない
- `manages`
    - BOM自体の版ではなく、そのBOMが設定する対象パッケージの版を示す

版の管理方法は[Mavenの版の出所と書き換え](remediation-logic.md#maven-version-sources)を参照してください。

### 修正版に上げられないときの案内 {#language-fix-hint}

`language_items[].packages[].fix_hint`のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `held_by` | objectの配列 | 対象の更新を妨げる、または対象を要求する[依存元](#language-fix-holder-fields)の一覧 | 省略 |
| `releases` | objectの配列 | 依存元や版を決めるPOMの[公開版の情報](#language-fix-hint-releases) | 省略 |
| `go_line` | object | 更新に必要な[Goの版と、その版を要求するモジュール](#language-go-line-fields) | 省略 |
| `fix` | object | [別のメジャー版の修正版](#language-fix-release-fields)の情報 | 省略 |
| `direct` | boolean | プロジェクト自身による対象パッケージの直接の要求を確認した場合に`true`になる | 省略 |
| `decided_by` | object | 対象の版を決める[プロジェクト外のPOM](#language-fix-decider-fields) | 省略 |
| `configuration` | string | Gradleで対象が目標版より低い版に残った構成名 | 省略 |

`fix_hint`を付ける`reason`は次のとおりです。

| `reason` | 意味 |
| --- | --- |
| `dependents_hold_back` | 依存元がこのパッケージの版を制限している |
| `go_line_raised_too_far` | `go`・`toolchain`の版が稼働バイナリのビルド時のGoの最も低い版を超えるか、ビルド時の版が不明なまま変わる |
| `go_runtime_unavailable` | 更新に必要な版以上の、サポート中のGoを選べない |
| `fix_in_other_major_version` | 修正版が別のメジャー版にあり、Goでは別のモジュールパスになる |
| `maven_version_source_unsupported` | プロジェクトのPOMファイルの変更では対象の版を変えられない |
| `gradle_version_source_unsupported` | プロジェクトのファイルの変更では対象の版を変えられない |
| `maven_release_not_found` | 更新に使える版がMaven Centralにない |
| `maven_fix_in_other_major` | 修正版が別のメジャー版にしかない |
| `target_not_updated` | 更新しても目標の版に上がらなかった |

`target_not_updated`に`fix_hint`を付けるのは、MavenとGradleの場合だけです。
対象の理由でも、情報を取得できなければ`fix_hint`やその子フィールドを省略します。

理由の意味は[理由コード](remediation-reference.md#reason-codes)、案内の読み方は[修正版に上げられないときの案内](remediation-results.md#fix-hints)を参照してください。

次のフィールドには補足があります。

- `direct`
    - Goの別メジャー版の案内では、プロジェクトの`go.mod`が対象を`// indirect`なしで要求する場合に`true`になる
    - Mavenの`target_not_updated`では、`held_by`に載せる依存元がなく、プロジェクト自身のモジュールが対象を直接宣言する場合に`true`になる
    - Gradleの`target_not_updated`では、`held_by`に載せる依存元がなく、対象の構成が対象を直接宣言する場合に`true`になる
- `configuration`
    - Gradleの`target_not_updated`で付与し、依存元も直接宣言も確認できなければ省略する

#### 対象を要求する依存元 {#language-fix-holder-fields}

`language_items[].packages[].fix_hint.held_by[]`の1要素のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `parent` | string | 対象パッケージを要求する依存元の名前 | — |
| `parent_version` | string | 確認した依存元の版 | — |
| `range` | string | 依存元が対象パッケージに指定する版の条件 | `""` |

`range`の読み方はマネージャーによって異なります。

| マネージャー・理由 | 意味 |
| --- | --- |
| pipの`dependents_hold_back` | 更新で固定しようとした版を許さない、有効な要求をまとめた指定範囲 |
| Goの`fix_in_other_major_version` | 依存元の`go.mod`が要求する対象モジュールの版 |
| Mavenの`target_not_updated` | 更新後に依存元が引き込む対象パッケージの版 |
| Gradleの`target_not_updated` | 依存関係の木で依存元が要求する対象パッケージの版 |

Maven・Gradleの`parent`は`groupId:artifactId`形式です。
Maven・Gradleの`held_by`は最大5件で、pip・Goにはこの5件の制限を適用しません。

#### 更新に必要なGoの版 {#language-go-line-fields}

`language_items[].packages[].fix_hint.go_line`のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `module` | string | 必要なGoの版を`go.mod`で宣言するモジュールのパス | — |
| `version` | string | その宣言を持つモジュールの版 | — |
| `go` | string | その`go.mod`の`go`行が宣言する版 | — |
| `built_with` | string | 比較に使った、稼働バイナリをビルドしたGoの版 | 省略 |
| `to` | string | 更新で要求した対象パッケージの版 | 省略 |

次のフィールドには補足があります。

- `built_with`
    - `go_line_raised_too_far`でビルド時の版が分かる場合に付与する
    - ビルド時の版が不明な場合や、`go_runtime_unavailable`の場合は省略する
- `to`
    - 更新対象の版であり、必要なGoの版を宣言したモジュールの`version`とは異なる場合がある

#### 別のメジャー版の修正版 {#language-fix-release-fields}

`language_items[].packages[].fix_hint.fix`のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `version` | string | 案内の条件を満たし、すべての対象脆弱性を直す最も低い版 | — |

`version`の読み方は、パッケージの`reason`によって異なります。

| 理由 | 意味 |
| --- | --- |
| Goの`fix_in_other_major_version` | 脆弱性情報が示す、別のメジャー版の修正版 |
| Maven・Gradleの`maven_fix_in_other_major` | 脆弱性情報が示す、稼働版と異なるメジャー版の正式な修正版 |
| Maven・Gradleの`maven_release_not_found` | Maven Centralの公開版のうち、目標版以上で、稼働版と異なるメジャー版の正式な修正版 |

Maven・Gradleの`maven_release_not_found`では、稼働版と同じ系統の版を使います。
`maven_fix_in_other_major`では、稼働版と同じ系統、または系統の指定がない版を使います。

版の系統と選定条件は[Mavenの目標版とMaven Centralの版](remediation-logic.md#maven-target-versions)を参照してください。

#### 対象の版を決めるPOM {#language-fix-decider-fields}

`language_items[].packages[].fix_hint.decided_by`のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `kind` | string | 対象の版を決めるPOMの種類 | — |
| `name` | string | POMの名前を`groupId:artifactId`で示す | — |
| `version` | string | 現在使っているPOMの版 | — |

`kind`の値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `parent_pom` | 親POM |
| `bom` | 取り込んでいるBOM |
| `spring_boot` | GradleのSpring Bootプラグインが使うBOM |

`kind`が`spring_boot`の場合、`name`は`org.springframework.boot:spring-boot-dependencies`、`version`はSpring Bootプラグインの版です。

### 依存元の公開版の情報 {#language-fix-hint-releases}

`language_items[].packages[].fix_hint.releases[]`は、対象パッケージを要求する依存元や、版を決めるPOMの公開版について確認した情報です。
`language_items[].update.chain.hints[]`の各要素も、この節で定義するフィールドを持ちます。

`language_items[].packages[].fix_hint.releases[]`の1要素のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `package` | string | 修正版への更新を確認する対象パッケージの名前 | — |
| `parent` | string | 確認した依存元または版を決めるPOMの名前 | — |
| `parent_version` | string | 確認の基準とした依存元またはPOMの現在の版 | — |
| `via` | stringの配列 | その依存元につながる、プロジェクトの直接依存の名前 | 省略 |
| `direct` | boolean | 依存元の直接依存としての扱いを示す値 | 省略 |
| `spec` | string | プロジェクトが直接依存に指定する版の範囲 | 省略 |
| `in_spec` | object | 指定範囲または同じメジャー・マイナー版の中で確認した[公開版](#language-hint-release-fields) | 確認できなければ省略 |
| `latest` | object | 最新として確認した[公開版](#language-hint-release-fields) | 確認できない、または`in_spec`と同じ版なら省略 |

次のフィールドには補足があります。

- `parent`と`parent_version`
    - Maven・Gradleでは、対象を引き込む依存元、または`decided_by`で示すPOMの名前と版を表す
- `via`
    - 依存元につながる直接依存を示し、案内に載せた公開版をどの直接依存の版が取り込むかまでは示さない
- `direct`
    - npm・pnpm・uvでは、`parent`がプロジェクトの直接依存の場合に`true`になる
    - Maven・Gradleでは、公開版の情報に常に`true`を付けるため、この値からプロジェクトの直接依存かどうかは判別できない
    - pip・Goの公開版の情報では省略する
- `spec`
    - npm・pnpmでは`package.json`、uvでは`pyproject.toml`の指定範囲を表す
    - 直接依存でない場合や、直接依存でも版の範囲を指定していない場合は省略する
    - Maven・Gradle・pip・Goの公開版の情報では省略する

`in_spec`と`latest`が示す版は、マネージャーによって異なります。

| マネージャー | `in_spec` | `latest` |
| --- | --- | --- |
| npm・pnpm・uv | 直接依存に指定した範囲内の最新の正式版 | 公開されている最新の正式版 |
| pip | 付与しない | 公開されている最新の正式版 |
| Go | 付与しない | モジュールプロキシの`@latest`で確認した版 |
| Maven・Gradle | `parent_version`と同じメジャー・マイナー版に属する最新の正式版 | 依存元またはPOMの最新の正式版 |

npm・pnpm・uvの`in_spec`は`direct`が`true`の場合だけ付与し、`spec`がなければ版の制限なしとして確認します。
Maven・Gradleの`in_spec`には、現在使っている`parent_version`と同じ版が入る場合もあります。

#### 確認した公開版 {#language-hint-release-fields}

`language_items[].packages[].fix_hint.releases[].in_spec`のフィールドは次のとおりで、同じ要素の`latest`と、`language_items[].update.chain.hints[]`内の`in_spec`・`latest`にも共通です。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `version` | string | 確認した依存元またはPOMの公開版 | — |
| `range` | string | その公開版が対象パッケージに指定する範囲または版 | 省略 |
| `fixes` | boolean | その公開版の指定が修正版を許す、または修正版を設定することを確認したかを示す | `false` |
| `dropped` | boolean | その公開版に対象の要求や版の設定がないことを確認した場合に`true`になる | 省略 |

`range`と`fixes`の読み方は次のとおりです。

| マネージャー | `range` | `fixes` |
| --- | --- | --- |
| npm・pnpm・uv・pip | 対象パッケージに指定する版の範囲 | すべての対象脆弱性を直す公開済みの正式版が範囲に含まれる場合に`true` |
| Go | `go.mod`が要求する対象モジュールの版 | 別メジャー版の案内では常に`false` |
| Maven・Gradle | 対象パッケージに設定する版 | 目標版以上で、すべての対象脆弱性を直す場合に`true` |

次のフィールドには補足があります。

- `range`
    - 版を制限しない要求など、範囲の文字列が空の場合は省略する
- `fixes`
    - 公開版の宣言についての確認結果であり、その版への更新による解消や動作を保証しない
    - Goでは同じモジュールパスへの要求を調べるため、`false`だけで依存元の公開版全体が脆弱だとは判断できない
- `dropped`
    - npm・pnpm・uv・pip・Goでは、その公開版が対象を直接の依存として宣言していない場合に`true`になる
    - Maven・Gradleの依存元では、POMが対象を`dependencies`に宣言していない場合に`true`になる
    - Maven・Gradleの版を決めるPOMでは、対象の版を設定していない場合に`true`になる
    - 別の依存経路から対象パッケージが入る可能性は残る

公開版の情報がないことは、修正可能な公開版が存在しないことを意味しません。
情報の読み方と調査の上限は[修正版に上げられないときの案内](remediation-results.md#fix-hints)を参照してください。
