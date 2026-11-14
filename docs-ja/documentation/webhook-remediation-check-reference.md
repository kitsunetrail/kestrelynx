---
title: Webhookの修正計画の更新前後の検査のフィールド
---

# Webhookの修正計画の更新前後の検査のフィールド

このページでは、言語パッケージの更新前後の検査と、更新ファイルのフィールドを説明します。
修正計画全体の構造は[修正計画の全体像](webhook-remediation-reference.md#remediation-overview)を参照してください。

`language_items[].source_check`は、依存ファイルの検査記録がある場合に含め、スキャンの失敗や検査の不合格でも記録があれば出力します。
`language_items[].artifacts`は、採用した更新ファイルの情報がある場合に含め、空なら省略します。

各表のフィールド名は、表の直前に示すオブジェクトからの相対名です。
「値がないとき」の読み方は、[レポートのフィールド](webhook-reference.md#report-fields)を参照してください。

## 更新前後の検査 {#language-source-check-fields}

`language_items[].source_check`のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `commit_sha` | string | 更新前の依存ファイルを取得したコミットのSHA | — |
| `before` | objectの配列 | [更新前に検査したファイル](#language-check-file-fields)の一覧 | `null` |
| `after` | objectの配列 | [更新後に検査したファイル](#language-check-file-fields)の一覧 | `null` |
| `conditions` | object | [スキャン条件](#language-check-condition-fields)の記録 | — |
| `counts` | integerの配列 | 解消・残存・新規検出の順に並ぶ3つの件数 | — |
| `truncated` | boolean | 脆弱性や再解決の比較結果の一覧を件数上限で省略したか | `false`なら省略 |
| `resolved` | objectの配列 | 更新前だけに検出された[脆弱性](#language-check-vulnerability-fields)の一覧 | 省略 |
| `remaining` | objectの配列 | 更新前後に検出された[脆弱性](#language-check-vulnerability-fields)の一覧 | 省略 |
| `introduced` | objectの配列 | 更新後だけに検出された[脆弱性](#language-check-vulnerability-fields)の一覧 | 省略 |
| `passed` | boolean | 更新前後の検査に合格したか | `false` |
| `basis` | string | [再解決のスキャン比較](#language-chain-scan-fields)に使った比較方法 | 追加の比較がなければ省略 |
| `chain_new_findings` | objectの配列 | 持ち越しを除き、更新後に新たに見つかった[パッケージの版ごとの脆弱性](#language-check-chain-new-fields) | 省略 |
| `chain_entry_growth` | objectの配列 | lockfile内で脆弱なパッケージの[使用箇所が増えた結果](#language-check-entry-growth-fields) | 省略 |
| `chain_edge_growth` | objectの配列 | 脆弱なパッケージを使う[依存関係が増えた結果](#language-check-edge-growth-fields) | 省略 |
| `chain_carried` | objectの配列 | 版が変わっても同じ依存関係に残る[脆弱性の持ち越し](#language-check-carried-fields) | 省略 |
| `chain_position_refusals` | objectの配列 | 依存関係の変化を確認して[不合格とした理由](#language-check-position-refusal-fields) | 省略 |

次のフィールドには補足があります。

- `counts`
    - パッケージ名と脆弱性IDの組を1件として数え、版や使用箇所が複数あっても同じ組は1件
    - Pythonのパッケージ名は、小文字化し、連続する`-`・`_`・`.`を1つの`-`にそろえて照合
    - 更新対象のパッケージだけでなく、対象のパッケージマネージャーについて依存ファイルから検出した脆弱性を集計
    - 一覧を件数上限で省略する前の件数を出力
    - 使用箇所数、依存関係数、`chain_*`の一覧の件数は含めない
    - 比較に到達する前にスキャンなどが失敗した場合も`[0, 0, 0]`になるため、0件だけでは検査の完了を判断できない
- `truncated`
    - `resolved`・`remaining`・`introduced`と、5つの`chain_*`の一覧は、それぞれ最大500件
    - いずれかの一覧が上限を超えると`true`
- `passed`
    - 検査の合否を示し、PRの作成済みを意味しない
    - 不合格や未完了の理由は、`language_items[].reason`と`language_items[].detail`も確認

次は、検査記録からコミット、ファイル一覧、件数、合否を抜粋した例です。

```json
{
  "commit_sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "before": [
    {
      "path": "package-lock.json",
      "sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    },
    {
      "path": "package.json",
      "sha256": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
    }
  ],
  "after": [
    {
      "path": "package-lock.json",
      "sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    },
    {
      "path": "package.json",
      "sha256": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
    }
  ],
  "counts": [
    2,
    0,
    0
  ],
  "passed": true
}
```

### 検査したファイル {#language-check-file-fields}

`language_items[].source_check.before[]`と`language_items[].source_check.after[]`の1要素のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `path` | string | `language_items[].source.directory`を基準とした検査対象ファイルの相対パス | — |
| `sha256` | string | 検査したファイル内容のSHA-256を表す16進文字列 | — |

各一覧は`path`の順に並びます。
検査対象のファイルと、PRに書き込む`artifacts[]`のファイルは一致するとは限りません。

### スキャン条件 {#language-check-condition-fields}

`language_items[].source_check.conditions`のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `TrivyVersion` | string | 検査に使ったTrivyの版 | `""` |
| `VulnerabilityDB` | object | [脆弱性データベースの情報](#language-check-database-fields) | — |
| `JavaDB` | object | [Javaデータベースの情報](#language-check-database-fields) | — |
| `Severities` | stringの配列 | 検出対象とした[深刻度](#language-check-severity-values)の一覧 | `null` |
| `AnalysisSettings` | string | スキャンに適用した解析設定を識別する文字列 | `""` |
| `VulnerabilityDBSHA` | string | 脆弱性データベースのファイル内容のSHA-256を表す16進文字列 | `""` |
| `JavaDBSHA` | string | Javaデータベースのファイル内容のSHA-256を表す16進文字列 | `""` |
| `TrivySHA` | string | Trivyの実行ファイルのSHA-256を表す16進文字列 | `""` |

次のフィールドには補足があります。

- `TrivyVersion`などのキー
    - `remediation.conditions`とは名前が異なり、大文字・小文字を含めて表のとおりに出力
    - 情報を記録できなかった場合も、`conditions`とその子フィールドは省略しない
- `Severities`
    - 大文字にそろえ、重複を除いて文字列順に出力
- `AnalysisSettings`
    - 固定の分類コードではなく、スキャン方法や解析設定を識別する文字列

#### データベース情報 {#language-check-database-fields}

`language_items[].source_check.conditions.VulnerabilityDB`と`language_items[].source_check.conditions.JavaDB`のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `Version` | integer | データベースのスキーマの版 | `0` |
| `UpdatedAt` | string | データベースが作成された日時（RFC 3339形式） | `"0001-01-01T00:00:00Z"` |

`Version`だけではデータベースの内容を識別できません。
内容の識別には、対応する`VulnerabilityDBSHA`または`JavaDBSHA`を使います。

次は、更新前後のスキャンが成功した場合の検査記録から、`conditions`を抜粋した例です。

```json
{
  "TrivyVersion": "0.71.2",
  "VulnerabilityDB": {
    "Version": 2,
    "UpdatedAt": "2026-10-09T03:00:00Z"
  },
  "JavaDB": {
    "Version": 1,
    "UpdatedAt": "2026-10-09T03:00:00Z"
  },
  "Severities": [
    "CRITICAL",
    "HIGH"
  ],
  "AnalysisSettings": "fs;scanners=vuln;pkg-types=default;ignore-unfixed=false;list-all-pkgs=true;dev-deps=included;config=none;ignorefile=none;vex=none;env=sanitized;workdir=isolated",
  "VulnerabilityDBSHA": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
  "JavaDBSHA": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  "TrivySHA": "1111111111111111111111111111111111111111111111111111111111111111"
}
```

更新前後のスキャンが完了する前に失敗した場合は、`conditions`全体が未記録のまま出力されます。
その場合、Trivyの版・解析設定・ハッシュは`""`、深刻度一覧は`null`、各データベースの版は`0`、日時は`"0001-01-01T00:00:00Z"`になります。

### 解消・残存・新規検出の脆弱性 {#language-check-vulnerability-fields}

`language_items[].source_check.resolved[]`、`language_items[].source_check.remaining[]`、`language_items[].source_check.introduced[]`の1要素のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `package` | string | 脆弱性が検出されたパッケージ名 | — |
| `version` | string | 脆弱性が検出されたパッケージの版 | `""` |
| `vuln_id` | string | 脆弱性ID | — |
| `severity` | string | 検出された脆弱性の[深刻度](#language-check-severity-values) | 省略 |
| `fixed_ver` | string | スキャンが報告した修正版情報 | 省略 |
| `kev` | boolean | CISA KEVへの掲載を確認したか | `false`なら省略 |

次のフィールドには補足があります。

- `version`
    - `resolved[]`は更新前、`remaining[]`と`introduced[]`は更新後の検出結果の版
    - 同じパッケージ名と脆弱性IDが複数の版で検出された場合は、版の文字列順で先頭になる検出結果を代表として出力
    - 代表の版は、バージョン番号として比較した最古の版とは限らない
- `fixed_ver`
    - スキャンが報告した文字列を出力するため、単一の版番号とは限らない
- `kev`
    - 未掲載の場合と、掲載を確認する情報がない場合は、どちらも省略

次は、`resolved[]`の1要素の例です。

```json
{
  "package": "minimist",
  "version": "1.2.5",
  "vuln_id": "CVE-2031-0100",
  "severity": "HIGH"
}
```

#### 深刻度 {#language-check-severity-values}

`severity`の主な値と、`conditions.Severities[]`の値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `CRITICAL` | 緊急 |
| `HIGH` | 高 |
| `MEDIUM` | 中 |
| `LOW` | 低 |
| `UNKNOWN` | 不明 |

`severity`はスキャンが返した文字列をそのまま出力します。

## 再解決のスキャン比較 {#language-chain-scan-fields}

依存元からの再解決では、パッケージの版ごとの脆弱性に加え、脆弱なパッケージの使用箇所や依存関係の変化を記録します。
`counts`と通常の3つの脆弱性一覧は、引き続きパッケージ名と脆弱性IDの組による比較結果です。

`language_items[].source_check.basis`の値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `package_version_vuln_edges_positions` | パッケージ名・版・脆弱性ID、使用箇所数、依存関係数に加え、変化した依存関係の位置を確認 |
| `package_version_vuln_edges` | パッケージ名・版・脆弱性ID、使用箇所数、依存関係数を比較 |

依存関係の位置の確認を行った場合は、`chain_carried[]`や`chain_position_refusals[]`に結果が入ることがあります。
一覧が省略されていても、位置を確認したかどうかは`basis`で区別できます。

### 新たに見つかった脆弱性 {#language-check-chain-new-fields}

`language_items[].source_check.chain_new_findings[]`の1要素のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `package` | string | 更新後に新たな脆弱性が見つかったパッケージ名 | — |
| `version` | string | 更新後に脆弱性が検出されたパッケージの版 | `""` |
| `vuln_id` | string | 新たに見つかった脆弱性ID | — |
| `severity` | string | 検出された脆弱性の[深刻度](#language-check-severity-values) | 省略 |
| `fixed_ver` | string | スキャンが報告した修正版情報 | 省略 |
| `kev` | boolean | CISA KEVへの掲載を確認したか | `false`なら省略 |

パッケージ名・版・脆弱性IDの組が更新前になく、持ち越しとして認められなかったものを出力します。
同じパッケージ名と脆弱性IDが更新前にもあっても、版が変わるとこの一覧に入ることがあります。

`fixed_ver`と`kev`の扱いは、[解消・残存・新規検出の脆弱性](#language-check-vulnerability-fields)と同じです。

### 使用箇所の増加 {#language-check-entry-growth-fields}

`language_items[].source_check.chain_entry_growth[]`の1要素のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `package` | string | 使用箇所が増えたパッケージ名 | — |
| `version` | string | 版ごとの増加を示す場合のパッケージの版 | 版をまとめる場合は省略 |
| `vuln_id` | string | 使用箇所が増えた版にある脆弱性ID | — |
| `before` | integer | 更新前のlockfile内の使用箇所数 | `0` |
| `after` | integer | 更新後のlockfile内の使用箇所数 | — |

次のフィールドには補足があります。

- `version`
    - 値がある場合は、その版の使用箇所数を比較した結果
    - 省略される場合は、その脆弱性があるパッケージの版をまとめた使用箇所数
    - 同じパッケージ名と脆弱性IDについて版ごとの増加を出力した場合は、版をまとめた増加を重ねて出力しない
- `before`・`after`
    - lockfile内のパッケージの記録を数え、プロジェクトからの経路の総数は数えない
    - pnpmではsnapshotごと、uvでは同じパッケージ名と版を1件として数える

### 依存関係の増加 {#language-check-edge-growth-fields}

`language_items[].source_check.chain_edge_growth[]`の1要素のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `package` | string | 依存関係が増えたパッケージ名 | — |
| `version` | string | 版を限定して数える場合のパッケージの版 | 現在の出力では省略 |
| `vuln_id` | string | 依存関係が増えた版にある脆弱性ID | — |
| `before` | integer | 脆弱性がある版を使う更新前の依存関係数 | `0` |
| `after` | integer | 脆弱性がある版を使う更新後の依存関係数 | — |

次のフィールドには補足があります。

- `version`
    - 現在はパッケージ名と脆弱性IDごとに該当する版をまとめて数えるため、出力しない
- `before`・`after`
    - プロジェクトからの直接依存と、パッケージ間の依存を数え、peer依存も含める
    - 同じ依存元から同じ名前で同じlockfile項目を参照する依存は、適用条件が同じなら1件にまとめる
    - 適用条件が異なる依存は別に数える

### 脆弱性の持ち越し {#language-check-carried-fields}

`language_items[].source_check.chain_carried[]`の1要素のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `package` | string | 脆弱性が残るパッケージ名 | — |
| `from` | string | 変更前の代表の版 | — |
| `to` | string | 変更後の版 | — |
| `vuln_id` | string | 残る脆弱性ID | — |
| `positions` | integer | 同じ脆弱性が残る依存関係の箇所数 | — |
| `kev` | boolean | CISA KEVへの掲載を確認したか | `false`なら省略 |

次のフィールドには補足があります。

- `from`
    - 変更前の版が複数ある場合は、版の文字列順で先頭になる1つを出力
- `positions`
    - プロジェクトから脆弱なパッケージまでの経路の総数とは異なる
- `kev`
    - 未掲載の場合と、掲載を確認する情報がない場合は、どちらも省略

`chain_carried[]`は、パッケージ名・変更後の版・脆弱性IDごとにまとめます。
持ち越した脆弱性は、この更新では解消していません。

### 依存関係の位置の検査で不合格とした理由 {#language-check-position-refusal-fields}

`language_items[].source_check.chain_position_refusals[]`の1要素のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `package` | string | 不合格の原因となるパッケージ名 | — |
| `version` | string | 不合格の原因となるパッケージの版 | — |
| `parent` | string | そのパッケージを使う依存元のパッケージ名 | 省略 |
| `check` | string | 依存関係の位置の検査で不合格とした理由 | — |
| `vuln_id` | string | 対応する旧版になかった脆弱性IDの1つ | `check`が`new_vuln`以外なら省略 |

次のフィールドには補足があります。

- `package`・`version`
    - `check`が`split`の場合は、分かれる前のパッケージ名と版
    - `split`以外では、更新後の依存先のパッケージ名と版
- `parent`
    - 依存元がプロジェクト自身の場合と、`check`が`split`の場合は省略
- `vuln_id`
    - 該当する脆弱性IDが複数ある場合は、文字列順で先頭になる1つを出力

`check`の値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `no_position` | 更新前の同じ位置に対応する依存関係を確認できない |
| `merged` | 複数の依存経路が合流し、比較する更新前のパッケージの記録を1つに決められない |
| `name` | 同じ位置の依存先のパッケージ名が変わる |
| `new_vuln` | 対応する旧版にはない脆弱性が新しい版にある |
| `split` | 更新前の1つのパッケージの記録が、更新後の複数の脆弱なパッケージの記録に分かれる |

持ち越しがあっても合格とは限らず、検査の合否は`language_items[].source_check.passed`で確認します。
再解決の採否は`language_items[].update.chain.outcome`で確認し、値の意味は[依存元からの再解決の結果](remediation-update-results.md#dependent-reresolution-results)を参照してください。

`language_items[].source_check`は、処理結果に残した1回分の検査記録です。
次のフィールドには補足があります。

- `language_items[].source_check`と`language_items[].artifacts`
    - 更新ファイルがある場合は、同じ採用した更新に対応
    - `language_items[].update.chain.outcome`が`adopted`なら再解決の結果で、再解決を不採用にして通常更新を採用した場合は通常更新の結果
- `language_items[].source_check`
    - 通常更新が失敗し、その後の再解決も不採用になった場合は、再解決の検査記録があればその記録を残す
    - その後、パッケージを外して通常更新を再実行し、その結果を採用または失敗として確定した場合は、再実行の検査記録に置き換える
    - 再実行が保留になった場合は、再実行前の検査記録を残すことがある

5つの一覧はそれぞれ最大500件で、省略がある場合は`language_items[].source_check.truncated`が`true`になります。
再解決のスキャン比較の合否は、省略前の全件で判定します。

検査条件は[再解決の検査条件](remediation-reresolution-logic.md#dependent-reresolution-rules)、持ち越しの例は[脆弱性の持ち越し](remediation-reresolution-logic.md#dependent-reresolution-carried-findings)を参照してください。

## 更新ファイル {#language-artifact-fields}

`language_items[].artifacts[]`の1要素のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `path` | string | 更新ファイルのリポジトリのルートからの相対パス | — |
| `sha256` | string | 更新後のファイル内容のSHA-256を表す16進文字列 | — |
| `size` | integer | 更新後のファイルのバイト数 | `0` |
| `mode` | string | 更新ファイルのGitのファイルモード | 省略 |

`mode`で使う値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `100644` | 実行権限のない通常ファイル |
| `100755` | 実行権限のある通常ファイル |

ファイルの内容は含めません。
`artifacts[]`があることだけでは、PRが作成されたかどうかは判断できません。

次は、`language_items[]`の1要素から更新ファイルを抜粋した例です。

```json
{
  "artifacts": [
    {
      "path": "package-lock.json",
      "sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
      "size": 30,
      "mode": "100644"
    }
  ]
}
```
