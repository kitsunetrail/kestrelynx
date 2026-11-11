---
title: Webhookの修正計画の全体と共通のオブジェクト
---

# Webhookの修正計画の全体と共通のオブジェクト

このページでは、修正計画の全体像を説明します。

配布イメージ・ベースイメージ・PR処理の項目に共通して出てくるオブジェクトについても、フィールドを説明します。
対象は、イメージ情報、比較結果、スキャンの記録、新しい系列の確認結果、サービスの5つです。

修正計画が有効な場合、full・diffの両方のペイロードに`remediation`を含めます。
レポート全体の構造は、[Webhookの基本のフィールド](webhook-reference.md#top-level)を参照してください。

| 内容 | ページ |
| --- | --- |
| 配布イメージの項目（`summary`・`items`） | [Webhookの修正計画の配布イメージのフィールド](webhook-remediation-image-reference.md) |
| ベースイメージの項目（`dockerfile_summary`・`dockerfile_items`） | [Webhookの修正計画のベースイメージのフィールド](webhook-remediation-dockerfile-reference.md) |
| 言語パッケージの項目（`language_summary`・`language_items`） | [Webhookの修正計画の言語パッケージのフィールド](webhook-remediation-language-reference.md) |
| 言語パッケージの更新の記録（`language_items[].update`） | [Webhookの修正計画の更新の記録のフィールド](webhook-remediation-update-reference.md) |
| 言語パッケージの更新前後の検査（`language_items[].source_check`・`artifacts`） | [Webhookの修正計画の更新前後の検査のフィールド](webhook-remediation-check-reference.md) |
| PR処理（`pull_request_summary`・`pull_requests`・`operations`・`problems`） | [Webhookの修正計画のPR処理のフィールド](webhook-remediation-pr-reference.md) |

## 修正計画の全体像 {#remediation-overview}

`remediation`の直下には、計画の状態、比較条件、処理件数と、対象ごとの結果が並びます。
省略されることがあるフィールドも含めた構造は次のとおりです。

```text
remediation
├── schema_version
├── status
├── unavailable_reason
├── not_saved
├── generated_at
├── conditions                    比較スキャンの条件
├── limits                        処理件数の上限
├── usage                         実際の処理件数
├── summary                       配布イメージの件数の集計
├── items[]                       配布イメージの項目の配列
├── dockerfile_summary            ベースイメージの件数の集計
├── dockerfile_items[]            ベースイメージの項目の配列
├── language_summary              言語パッケージの件数の集計
├── language_items[]              言語パッケージの項目の配列
├── pull_request_summary          PR処理の件数の集計
├── pull_requests[]               PR処理の項目の配列
├── operations[]                  PR操作の記録
└── problems[]                    PRの書き込みを止める問題
```

対象ごとに「件数の集計」と「項目の配列」が組になっています。
配布イメージだけは接頭辞がなく、`summary`と`items`を使います。

次は、計画を作れたものの、修正対象の項目が1件もなかった場合の`remediation`です。
修正対象がなくても、計画の生成時刻、処理の上限と件数、配布イメージの集計、空の`items`を出力します。

```json
{
  "remediation": {
    "schema_version": 1,
    "status": "ok",
    "generated_at": "2026-10-09T03:00:00Z",
    "conditions": {
      "trivy_version": "0.71.2",
      "trivy_sha256": "1111111111111111111111111111111111111111111111111111111111111111",
      "vulnerability_db_updated_at": "2026-10-09T00:00:00Z",
      "vulnerability_db_sha256": "2222222222222222222222222222222222222222222222222222222222222222",
      "java_db_updated_at": "2026-10-08T12:00:00Z",
      "java_db_sha256": "3333333333333333333333333333333333333333333333333333333333333333",
      "severities": [
        "CRITICAL",
        "HIGH"
      ],
      "analysis_settings": "image;scanners=default;pkg-types=default;ignore-unfixed=false;list-all-pkgs=true;env=sanitized;workdir=isolated"
    },
    "limits": {
      "max_candidate_scans": 10,
      "max_baseline_rescans": 10,
      "max_tag_pages": 20
    },
    "usage": {
      "candidate_scans": 0,
      "baseline_rescans": 0,
      "tag_pages": 0,
      "registry_requests": 0
    },
    "summary": {
      "deferred": 0,
      "excluded": 0,
      "failed": 0,
      "manual": 0,
      "no_candidate": 0,
      "not_comparable": 0,
      "pr_candidate": 0,
      "pull_again": 0
    },
    "items": []
  }
}
```

計画を作れなかった場合も、`remediation`と空の`items`を出力します。

```json
{
  "remediation": {
    "schema_version": 1,
    "status": "unavailable",
    "unavailable_reason": "databases_not_prepared",
    "items": []
  }
}
```

## 修正計画の共通フィールド {#remediation-fields}

表の読み方は、[レポートのフィールド](webhook-reference.md#report-fields)を参照してください。
各項目の`category`は[計画の分類値](remediation-reference.md#category-values)、`reason`は[理由コード](remediation-reference.md#reason-codes)を参照してください。

`remediation`の直下のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `schema_version` | integer | 修正計画のJSON形式の版で、現在は`1` | — |
| `status` | string | 計画を作成できたかを表す状態 | — |
| `unavailable_reason` | string | 計画を作成できなかった理由 | 計画を作成できた場合は省略 |
| `not_saved` | boolean | 作成した計画を保存できなかった場合は`true` | `false`なら省略 |
| `generated_at` | string | RFC 3339形式の計画生成時刻 | 計画がない場合は省略 |
| `conditions` | object | [比較スキャンの条件](#remediation-conditions) | 条件の情報がなければ省略 |
| `limits` | object | [計画作成時の上限](#remediation-limits) | 計画がない場合は省略 |
| `usage` | object | [計画作成時の処理件数](#remediation-usage) | 計画がない場合は省略 |
| `summary` | object | [配布イメージ](webhook-remediation-image-reference.md)の分類別の項目数 | 計画がない場合は省略 |
| `items` | objectの配列 | [配布イメージの項目](webhook-remediation-image-reference.md) | `[]` |
| `language_summary` | object | [言語パッケージ](webhook-remediation-language-reference.md)の分類別の項目数 | 対応する項目がなければ省略 |
| `language_items` | objectの配列 | [言語パッケージの項目](webhook-remediation-language-reference.md) | 空なら省略 |
| `dockerfile_summary` | object | [ベースイメージ](webhook-remediation-dockerfile-reference.md)の分類別の項目数 | 対応する項目がなければ省略 |
| `dockerfile_items` | objectの配列 | [ベースイメージの項目](webhook-remediation-dockerfile-reference.md) | 空なら省略 |
| `pull_request_summary` | object | [PR処理](webhook-remediation-pr-reference.md)の状態別の項目数 | 対応する項目がなければ省略 |
| `pull_requests` | objectの配列 | [PR処理の項目](webhook-remediation-pr-reference.md) | 空なら省略 |
| `operations` | objectの配列 | [PR操作の記録](webhook-remediation-pr-reference.md) | 空なら省略 |
| `problems` | objectの配列 | [PRの書き込みを止める問題](webhook-remediation-pr-reference.md) | 空なら省略 |

`status`の値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `ok` | 計画を作成できた |
| `unavailable` | 計画を作成できなかった |

`ok`は、個々の候補の確認やPR処理がすべて成功したことを表す値ではありません。
各項目の結果は、対象ごとの配列で確認してください。

`unavailable_reason`の値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `databases_not_prepared` | スキャン用データベースを準備できず、同じ条件で比較する計画を作成できなかった |
| `planner_not_built` | 計画を作成するための処理を準備できなかった |

### 件数の集計 {#remediation-summary-keys}

この節では、`summary`・`dockerfile_summary`・`language_summary`・`pull_request_summary`の中身を説明します。

次は、配布イメージの分類別の項目数を示す`summary`の例です。

```json
{
  "summary": {
    "deferred": 0,
    "excluded": 0,
    "failed": 0,
    "manual": 1,
    "no_candidate": 0,
    "not_comparable": 0,
    "pr_candidate": 2,
    "pull_again": 1
  }
}
```

キーの`pr_candidate`は分類の名前で、値の`2`は、`items[]`のうち`category`が`pr_candidate`の項目が2件あることを表します。
同じように、`manual`は1件、`pull_again`は1件です。

1つの項目に脆弱性やパッケージが複数含まれていても、項目数は`1`と数えます。

4つのフィールドの違いは次のとおりです。

| フィールド名 | 数える対象 | キー | 0件のキー | フィールド自体を省略する場合 |
| --- | --- | --- | --- | --- |
| `summary` | `items[]`の項目 | `category`の分類名（8種類） | `0`で出力 | 計画がない場合 |
| `dockerfile_summary` | `dockerfile_items[]`の項目 | `category`の分類名（8種類） | `0`で出力 | `dockerfile_items[]`が空の場合 |
| `language_summary` | `language_items[]`の項目 | `category`の分類名（7種類） | `0`で出力 | `language_items[]`が空の場合 |
| `pull_request_summary` | `pull_requests[]`の項目 | `status`の[PRの状態値](remediation-reference.md#pr-status-values) | 省略 | `pull_requests[]`が空の場合 |

計画があれば、`items[]`が空でも`summary`の8キーをすべて`0`で出力します。
`dockerfile_summary`では、`dockerfile_items[].entities[]`を個別に数えません。

`summary`と`dockerfile_summary`のキーは、`pull_again`・`pr_candidate`・`manual`・`not_comparable`・`deferred`・`no_candidate`・`excluded`・`failed`の8種類です。
`language_summary`のキーは、`pr_candidate`・`dependency_update_candidate`・`rebuild_expected`・`manual`・`not_comparable`・`deferred`・`failed`の7種類です。

### 比較スキャンの条件 {#remediation-conditions}

`conditions`のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `trivy_version` | string | 比較スキャンに使ったTrivyの版 | `""` |
| `trivy_sha256` | string | Trivy実行ファイルのSHA-256 | 省略 |
| `vulnerability_db_updated_at` | string | RFC 3339形式の脆弱性データベースの更新時刻 | 省略 |
| `vulnerability_db_sha256` | string | 脆弱性データベースのファイルのSHA-256 | 省略 |
| `java_db_updated_at` | string | RFC 3339形式のJavaデータベースの更新時刻 | 省略 |
| `java_db_sha256` | string | JavaデータベースのファイルのSHA-256 | 省略 |
| `severities` | stringの配列 | 比較スキャンの対象とした深刻度 | 空なら省略 |
| `analysis_settings` | string | 比較スキャンの解析設定を識別する文字列 | 省略 |

次のフィールドには補足があります。

- `conditions`
    - `trivy_version`が空でなければ出力する
    - `trivy_version`が空でも、`vulnerability_db_updated_at`に対応する更新時刻と、JSONには出力しない脆弱性データベースの形式の版（0以外）が記録されていれば出力する
    - `trivy_version`が空で、更新時刻がないか、形式の版が`0`ならオブジェクト自体を省略する
    - Javaデータベースや深刻度の情報だけではオブジェクトを出力しない
- `trivy_version`
    - 脆弱性データベースの情報だけが分かる場合は、`conditions`内に空文字列で出力する
- `trivy_sha256`・`vulnerability_db_sha256`・`java_db_sha256`
    - SHA-256を16進数で表し、`sha256:`の接頭辞は付けない
- `severities`
    - 通常の値は`UNKNOWN`・`LOW`・`MEDIUM`・`HIGH`・`CRITICAL`
- `analysis_settings`
    - 解析オプションや設定ファイルなどを識別する文字列で、ハッシュだけからなる値ではない

比較条件の詳細は、[スキャンの比較条件](remediation-logic.md#comparison-conditions)を参照してください。
次は、条件から版・更新時刻・深刻度を抜粋した例です。

```json
{
  "trivy_version": "0.71.2",
  "vulnerability_db_updated_at": "2026-10-09T03:00:00Z",
  "java_db_updated_at": "2026-10-09T03:00:00Z",
  "severities": [
    "CRITICAL",
    "HIGH"
  ]
}
```

### 計画作成時の上限 {#remediation-limits}

`limits`のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `max_candidate_scans` | integer | 1回の計画作成で実行できる候補イメージのスキャン件数の上限 | `0` |
| `max_baseline_rescans` | integer | 1回の計画作成で実行できる比較元の再スキャン件数の上限 | `0` |
| `max_tag_pages` | integer | 1リポジトリについて実行できるタグ一覧取得の要求回数の上限 | `0` |

上限の`0`は、その処理を実行できないことを表します。
`max_tag_pages`には、タグ一覧のページ取得と、同じ系列のタグを順に探す要求を数えます。

```json
{
  "max_candidate_scans": 10,
  "max_baseline_rescans": 10,
  "max_tag_pages": 20
}
```

### 計画作成時の処理件数 {#remediation-usage}

`usage`のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `candidate_scans` | integer | 実行した候補イメージのスキャン件数 | `0` |
| `baseline_rescans` | integer | 実行した比較元の再スキャン件数 | `0` |
| `tag_pages` | integer | タグ一覧取得の要求回数の合計 | `0` |
| `registry_requests` | integer | 計画作成で消費したレジストリへの要求回数 | `0` |

`tag_pages`はリポジトリをまたいだ合計なので、リポジトリごとの上限である`limits.max_tag_pages`を超えることがあります。

```json
{
  "candidate_scans": 2,
  "baseline_rescans": 0,
  "tag_pages": 0,
  "registry_requests": 7
}
```

## 共通のオブジェクト {#remediation-common-objects}

次のオブジェクトは、配布イメージの項目（`items[]`）やベースイメージの項目（`dockerfile_items[]`）、PR処理（`pull_requests[]`）に共通して出てきます。
フィールドの説明をこの節にまとめ、各項目のページから参照します。

| オブジェクト | 内容 | 出てくる項目 |
| --- | --- | --- |
| [イメージ情報](#remediation-image-state) | イメージ名やdigestなど、イメージを識別する情報 | 配布イメージ、ベースイメージ |
| [比較結果](#remediation-comparison) | 所見の解消・残存・新規検出の結果 | 配布イメージ、ベースイメージ |
| [スキャンの記録](#remediation-scan-records) | スキャンの対象・役割・検証結果 | 配布イメージ、ベースイメージ |
| [新しい系列の確認結果](#remediation-newer-series) | 新しい系列の候補と、その確認結果 | 配布イメージ、ベースイメージ |
| [サービス](#remediation-services) | イメージを使うサービスやワークロードの情報 | 配布イメージ、ベースイメージ、PR処理 |

### イメージ情報 {#remediation-image-state}

イメージ情報は、次のフィールドに出力します。

- `items[].current`・`items[].candidate`
- `items[].newer_series.candidates[].candidate`
- `dockerfile_items[].candidate`
- `dockerfile_items[].entities[].running_image`・`current_base`・`candidate_base`
- `dockerfile_items[].newer_series.candidates[].candidate`
- `dockerfile_items[].entities[].newer_series.candidates[].candidate`

`items[].current`などのイメージ情報のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `ref` | string | タグやdigestの指定を含むイメージ名 | `""` |
| `tag` | string | イメージのタグ | 省略 |
| `content` | string | 稼働イメージの内容を種類付きで識別する文字列 | 省略 |
| `config_digest` | string | イメージの構成情報を識別するdigest | 省略 |
| `manifest_digest` | string | 対象プラットフォームのイメージマニフェストを識別するdigest | 省略 |
| `top_digest` | string | タグなどの参照先であるイメージインデックスまたはマニフェストを識別するdigest | 省略 |
| `platform` | string | `linux/amd64`のような`OS/アーキテクチャ`形式のプラットフォーム | 省略 |
| `digest_kind_unverified` | boolean | 稼働イメージのdigestの種類を確認できていない場合は`true` | `false`なら省略 |

次のフィールドには補足があります。

- `content`
    - `items[].current`と`dockerfile_items[].entities[].running_image`にだけ出力する
    - 形式は`config:sha256:<64桁の小文字の16進数>`または`registry:sha256:<64桁の小文字の16進数>@<OS>/<アーキテクチャ>`
    - 有効なdigestを得られなかった場合は`unconfirmed`
- `config_digest`・`manifest_digest`・`top_digest`
    - 形式は`sha256:<64桁の小文字の16進数>`
    - `content`にある`config:`・`registry:`の接頭辞やプラットフォームは付けない
- `top_digest`
    - 複数プラットフォームを含むイメージでは、その一覧を持つイメージインデックスを識別する
    - 参照先が単一のイメージマニフェストなら、`manifest_digest`と同じ値になる
- `digest_kind_unverified`
    - `true`の場合、`content`の`config:`という表記や`config_digest`だけでは、その値が構成情報のdigestであると確認できない
    - コンテナの実行環境から得た値が、マニフェストやイメージインデックスのdigestである可能性もある

次は、現在のベースイメージの情報です。

```json
{
  "ref": "python:3.12.3-slim",
  "tag": "3.12.3-slim",
  "config_digest": "sha256:b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1",
  "manifest_digest": "sha256:b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2",
  "top_digest": "sha256:b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3",
  "platform": "linux/amd64"
}
```

### 比較結果 {#remediation-comparison}

比較結果は、`items[].comparison`、`dockerfile_items[].entities[].comparison`と、各稼働イメージの`newer_series.candidates[].comparison`で使います。
比較条件は[スキャンの比較条件](remediation-logic.md#comparison-conditions)、結果の解釈は[比較結果の解消](remediation-results.md#verification-results)を参照してください。

次は、対象の所見1件を解消した比較結果から、主要なフィールドを抜粋した例です。

```json
{
  "comparable": true,
  "decision": "adopt",
  "targets": 1,
  "resolved": 1,
  "remaining": 0,
  "unknown": 0,
  "undetected": 0,
  "introduced": 0,
  "verdicts": [
    {
      "vuln_id": "CVE-2031-0000",
      "package": "libc",
      "severity": "HIGH",
      "outcome": "resolved",
      "disposition": "version_changed"
    }
  ]
}
```

`items[].comparison`などの比較結果のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `comparable` | boolean | 比較できる結果の場合は`true` | `false` |
| `reason` | string | 比較できない理由を表す[理由コード](remediation-reference.md#reason-codes) | 省略 |
| `scope` | string | 比較した深刻度などの範囲を説明する英文 | 省略 |
| `decision` | string | 比較結果に基づく候補の採用判定 | 省略 |
| `targets` | integer | 判定対象の所見数 | `0` |
| `resolved` | integer | 解消した所見数 | `0` |
| `remaining` | integer | 候補に残っている所見数 | `0` |
| `unknown` | integer | 判定できなかった対象の所見数 | `0` |
| `undetected` | integer | 比較元で検出されなかった対象の所見数 | `0` |
| `introduced` | integer | 候補で新たに検出された所見数 | `0` |
| `verdicts` | objectの配列 | 比較元の所見に対する個別の判定 | 空なら省略 |
| `verdicts_truncated` | boolean | `verdicts`の一部を件数上限によって省略した場合は`true` | `false`なら省略 |
| `introduced_findings` | objectの配列 | 候補で新たに検出された所見の個別の判定 | 空なら省略 |
| `introduced_findings_truncated` | boolean | `introduced_findings`の一部を件数上限によって省略した場合は`true` | `false`なら省略 |

次のフィールドには補足があります。

- `scope`
    - 固定のコードではなく説明文なので、状態の判別には`comparable`・`reason`・`decision`を使う
- `resolved`・`remaining`・`unknown`・`undetected`
    - `decision`がある比較では、採用判定の対象の所見だけを数え、`verdicts[]`に含まれる対象外の所見は数えない
    - 新しい系列の候補では、その候補の`counts`と同じ件数を出力する
    - `decision`も候補の`counts`もない比較では、`resolved`と`remaining`は`verdicts[]`の件数上限を適用する前の結果から数え、`unknown`と`undetected`は`0`になる
    - `comparable`が`false`の場合、件数が`0`でも対象がないことや解消したことを表さない
- `verdicts`
    - 配布イメージの通常の比較では、採用判定の対象以外の所見を含むこともある
    - ベースイメージの比較と新しい系列の候補の比較では、判定対象の所見だけを含む
- `verdicts`・`introduced_findings`
    - それぞれ最大50件で、超えた場合は対応する`*_truncated`が`true`になる
    - 一覧を省略しても件数のフィールドは減らさないため、配列の長さから全体の件数を求めない

`decision`の値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `adopt` | 対象をすべて解消する候補として採用 |
| `adopt_partial` | 対象の一部を解消する候補として採用 |
| `not_resolving` | 解消する対象がない |
| `introduced` | 新しい所見がある |
| `new_kev` | 新たに検出された脆弱性にKEV掲載のものがある |
| `analysis_incomplete` | 対象を判断するための解析が不足している |
| `targets_not_detected` | 比較元で対象を検出できず、解消を判断できない |
| `not_comparable` | 比較できない |

`items[].comparison.verdicts[]`の1要素のフィールドは次のとおりです。
各`comparison`の`verdicts[]`と`introduced_findings[]`は、要素が同じフィールドを持ちます。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `vuln_id` | string | 脆弱性のID | — |
| `package` | string | 判定対象のパッケージ名 | — |
| `ecosystem` | string | パッケージの種類 | 省略 |
| `severity` | string | 脆弱性の深刻度 | 省略 |
| `outcome` | string | 所見の比較結果 | — |
| `disposition` | string | 解消した所見のパッケージが候補でどう変わったか | 省略 |
| `reason` | string | 個別の判定ができない理由を表す[理由コード](remediation-reference.md#reason-codes) | 省略 |
| `before_versions` | stringの配列 | 比較元で記録されたパッケージの版 | 空なら省略 |
| `after_versions` | stringの配列 | 候補でその脆弱性が検出された箇所のパッケージの版 | 空なら省略 |

次のフィールドには補足があります。

- `ecosystem`
    - `alpine`・`debian`・`node-pkg`・`python-pkg`など、スキャン結果のパッケージの種類を表す
- `severity`
    - 通常の値は`UNKNOWN`・`LOW`・`MEDIUM`・`HIGH`・`CRITICAL`
- `before_versions`・`after_versions`
    - 重複する版を除き、文字列順に並べる
    - パッケージのすべての導入箇所を列挙するフィールドではない
- `after_versions`
    - `outcome`が`resolved`なら省略し、修正後に入っているパッケージの版は示さない

`outcome`の値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `resolved` | 比較元にあった所見が、比較した範囲では候補にない |
| `remaining` | 候補にも所見がある |
| `introduced` | 比較元にはなく、候補で新たに検出された |
| `unknown` | 所見の解消や残存を判定できない |

`disposition`の値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `package_removed` | 候補にパッケージがない |
| `version_changed` | 候補には比較元と異なる版だけがある |
| `same_version` | 候補に比較元と同じ版があるが、所見は検出されなくなった |

### スキャンの記録 {#remediation-scan-records}

スキャンの記録は、配布イメージとベースイメージの`scans[]`、新しい系列の候補の`scans[]`で使います。
ベースイメージの`rebuild_check.running_scan`と`rebuild_check.base_scan`も同じフィールドを持ちます。

次は、比較元と候補の内容を確認でき、スキャン後のデータベースの照合にも成功した記録の例です。

```json
[
  {
    "role": "baseline",
    "ref": "python:3.12.3-slim",
    "requested": "registry:sha256:1111111111111111111111111111111111111111111111111111111111111111@linux/amd64",
    "confirmed": "registry:sha256:1111111111111111111111111111111111111111111111111111111111111111@linux/amd64",
    "db": "verified",
    "scanned_at": "2026-10-09T02:59:00Z"
  },
  {
    "role": "candidate",
    "ref": "python:3.12.5-slim",
    "requested": "registry:sha256:2222222222222222222222222222222222222222222222222222222222222222@linux/amd64",
    "confirmed": "registry:sha256:2222222222222222222222222222222222222222222222222222222222222222@linux/amd64",
    "db": "verified",
    "scanned_at": "2026-10-09T02:59:30Z"
  }
]
```

`items[].scans[]`などの1要素のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `role` | string | 比較におけるスキャンの役割 | — |
| `ref` | string | スキャンしたイメージ名 | `""` |
| `requested` | string | スキャンで確認するよう要求したイメージの識別文字列 | `""` |
| `confirmed` | string | スキャンで確認できたイメージの識別文字列 | `""` |
| `db` | string | スキャン後のデータベースの検証結果 | `""` |
| `scanned_at` | string | RFC 3339形式のスキャン時刻 | 記録がなければ省略 |
| `failure` | string | スキャン失敗の内容を説明する文字列 | 省略 |

`role`の値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `baseline` | 比較元のスキャン |
| `candidate` | 比較先の候補のスキャン |

`db`の値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `verified` | スキャン後のデータベースが、準備したデータベースと一致した |
| `changed` | スキャン後のデータベースが、準備したデータベースと異なった |
| `check_failed` | データベースを照合できなかった |
| `supplied_by_caller` | 計画作成時に渡されたスキャンと、そのスキャン条件を使った |
| `not_checked` | スキャンが失敗したため、データベースを照合していない |

次のフィールドには補足があります。

- `requested`・`confirmed`
    - [イメージ情報](#remediation-image-state)の`content`と同じ、種類付きの識別文字列を使う
    - 通常のスキャン処理では、対象を識別できなかった場合に`unconfirmed`を出力する
    - 記録に文字列が設定されていなければ、キーを省略せず空文字列を出力する
- `db`
    - データベースの更新時刻やハッシュは、[比較スキャンの条件](#remediation-conditions)を参照する
- `scanned_at`
    - 計画作成処理が実行したスキャンに付き、渡されたスキャンをそのまま使った場合は省略する

WebhookにはスキャンIDを出力しません。

### 新しい系列の確認結果 {#remediation-newer-series}

新しい系列の確認結果は、`items[].newer_series`、`dockerfile_items[].newer_series`、`dockerfile_items[].entities[].newer_series`で使います。
候補の選び方は[新しい系列の確認](remediation-logic.md#newer-series-check)、状態の意味は[新しい系列の状態値](remediation-reference.md#newer-series-status-values)を参照してください。

次は、新しい系列の候補と件数を抜粋した例です。

```json
{
  "status": "resolves",
  "shown": "2.0.1",
  "candidates": [
    {
      "tag": "2.0.1",
      "change": "major",
      "status": "resolves",
      "counts": {
        "targets": 2,
        "resolved": 2,
        "remaining": 0,
        "unknown": 0,
        "undetected": 0,
        "introduced": 0,
        "introduced_kev": 0
      }
    }
  ]
}
```

`items[].newer_series`などのフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `status` | string | 新しい系列を確認した結果の状態 | — |
| `shown` | string | 項目の確認結果として示す候補のタグ | 省略 |
| `reason` | string | 確認できない理由などを表す[理由コード](remediation-reference.md#reason-codes) | 省略 |
| `detail` | string | 理由の補足説明 | 省略 |
| `candidates` | objectの配列 | 候補を調べた順に並べた結果 | 空なら省略 |

`status`の値は[新しい系列の状態値](remediation-reference.md#newer-series-status-values)を参照してください。
`shown`は、対象の所見を解消する候補がなければ省略します。

`items[].newer_series.candidates[]`などの1要素のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `tag` | string | 確認する候補のタグ | — |
| `change` | string | 現在のタグに対する系列の変更の種類 | — |
| `status` | string | 候補を確認した結果の状態 | — |
| `reason` | string | 候補の結果を説明する[理由コード](remediation-reference.md#reason-codes) | 省略 |
| `detail` | string | 理由の補足説明 | 省略 |
| `candidate` | object | 候補の[イメージ情報](#remediation-image-state) | 情報がなければ省略 |
| `counts` | object | 対象の解消状況と新規検出の件数 | 集計できなければ省略 |
| `comparison` | object | 候補の[比較結果](#remediation-comparison) | 結果がなければ省略 |
| `scans` | objectの配列 | 比較に使った[スキャンの記録](#remediation-scan-records) | 空なら省略 |

候補の`status`は[新しい系列の状態値](remediation-reference.md#newer-series-status-values)のうち、`no_newer_series`を除く値です。

`change`の値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `minor` | 同じメジャー版の新しいマイナー系列 |
| `major` | 新しいメジャー系列 |

`items[].newer_series.candidates[].counts`などのフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `targets` | integer | 判定対象の所見数 | `0` |
| `resolved` | integer | 解消した対象の所見数 | `0` |
| `remaining` | integer | 候補に残っている対象の所見数 | `0` |
| `unknown` | integer | 判定できなかった対象の所見数 | `0` |
| `undetected` | integer | 比較元で検出されなかった対象の所見数 | `0` |
| `introduced` | integer | 候補で新たに検出された所見数 | `0` |
| `introduced_kev` | integer | 新規検出の所見に含まれるKEV掲載の脆弱性IDの数 | `0` |

次のフィールドには補足があります。

- `comparison`
    - `items[].newer_series`と`dockerfile_items[].entities[].newer_series`の候補では、`verdicts[]`に判定対象の所見だけを含む
    - 新しい系列の候補では`decision`を省略する
    - `verdicts[]`と`introduced_findings[]`の上限は、それぞれ50件
- `counts`
    - 候補の取得失敗や比較前の中断などでは、全フィールドを`0`にするのではなくオブジェクト自体を省略する
    - `introduced_kev`は脆弱性IDの重複を除いて数える
- `dockerfile_items[].newer_series`
    - ベースイメージの項目に属する稼働イメージ全体の結果を表す
    - `candidates[]`には`comparison`と`scans`を付けない
    - 候補の`candidate`には、得られた`ref`・`tag`・`top_digest`を入れる
    - 未確認の稼働イメージがある場合や、同じ候補タグの内容が稼働イメージ間で一致しない場合は、候補の`counts`を省略する
    - 所見は脆弱性IDとパッケージの組で重複を除き、その所見を持つすべての稼働イメージで解消した場合に`resolved`へ数える

新しい系列の候補タグが現在のイメージと同じ内容を指す場合、その候補のためのスキャンは行いません。
配布イメージの候補と、ベースイメージの稼働イメージごとの候補では、`status`が`not_resolving`、`reason`が`same_content`になります。

その場合の`comparison`は、`comparable`が`true`で、各対象の`outcome`が`remaining`になります。
`counts`と`comparison`の`remaining`は`targets`と同じ件数になり、解消・判定不能・比較元で未検出・新規検出の件数は`0`です。

`scope`には`the candidate is the content already in use; nothing was scanned`が入ります。

新しい系列の結果は、時刻や`detail`だけが変わっても、その変化を理由にWebhookを再送しません。
送信するJSONには、上の表の条件に従って`detail`や`scans[].scanned_at`も含めます。

詳細は、[修正計画の再送](notification-conditions.md#remediation-redelivery)を参照してください。

### サービス {#remediation-services}

サービスの情報は、`items[].services[]`、`dockerfile_items[].entities[].services[]`、`pull_requests[].also_running[]`で使います。

`items[].services[]`などの1要素のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `project` | string | Docker Composeのプロジェクト名 | 省略 |
| `service` | string | Docker Composeのサービス名 | 省略 |
| `container` | string | Dockerのコンテナ名 | 省略 |
| `workload` | string | Kubernetesのワークロードキー | 省略 |

次のフィールドには補足があります。

- `project`・`service`・`container`
    - Docker Composeでは、プロジェクト名・サービス名・コンテナ名を出力する
    - Composeに属さないDockerのコンテナでは、`container`を出力する
- `workload`
    - Kubernetesでは、このフィールドだけを出力し、`project`・`service`・`container`を省略する
    - 同じワークロードのレプリカを、Pod名ごとのサービス情報には分けない
    - 文字列の形式は[ワークロードキーの形式](webhook-diff-reference.md#reference-change-fields)を参照する

次は、Docker Composeのサービス情報です。

```json
{
  "project": "shop",
  "service": "web",
  "container": "shop-web-1"
}
```
