---
title: Webhookの差分のフィールド
---

# Webhookの差分のフィールド

このページでは、汎用Webhookのペイロードに含まれる`diff`のフィールドを説明します。
ペイロード全体の構造は[ペイロードの全体像](webhook-reference.md#payload-overview)、表の読み方と複数のフィールドで使う値は[レポートのフィールド](webhook-reference.md#report-fields)を参照してください。

`diff`はdiffモードのときだけ付き、保存している履歴と最新のスキャンを比べた変化を種類別に表します。

次の例は、パッケージの優先度昇格、修正可能化、解消を含む`diff`です。

```json
{
  "new": [
    {
      "image": "web:1.0",
      "package": "openssl",
      "kind": "escalated",
      "critical": 1,
      "high": 1,
      "priority": "act_now",
      "reason": "CVE-2031-0001 CRITICAL · CISA KEV (exploited in the wild) · EPSS 94% · 🧨 ransomware campaign",
      "ecosystems": [""]
    },
    {
      "image": "web:1.0",
      "package": "dpkg",
      "kind": "now_fixable",
      "critical": 0,
      "high": 1,
      "priority": "low",
      "ecosystems": [""]
    }
  ],
  "resolved": [
    {
      "image": "web:1.0",
      "package": "old-pkg"
    }
  ],
  "replaced": [],
  "new_eosl": [],
  "resolved_eosl": [],
  "oldest_open_days": 20,
  "new_eol_packages": [],
  "resolved_eol_packages": []
}
```

変化を判定する条件は、[差分と履歴の判定](diff-logic.md#comparison-baseline)を参照してください。

## 差分オブジェクト {#diff-fields}

`diff`のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `new` | objectの配列 | [通常のパッケージの変化](#new-fields) | `[]` |
| `resolved` | objectの配列 | [パッケージの解消](#resolved-fields) | `[]` |
| `replaced` | objectの配列 | [digestの変更](#image-replacement-fields) | `[]` |
| `reference_changes` | objectの配列 | [イメージ名の更新](#reference-change-fields) | 該当なしなら省略 |
| `new_eosl` | stringの配列 | [ベースOSが新たにEOLとして記録されたイメージ](#eol-base-fields) | `[]` |
| `resolved_eosl` | stringの配列 | [ベースOSがEOLとして記録されなくなったイメージ](#eol-base-fields) | `[]` |
| `new_eol_packages` | objectの配列 | [EOLパッケージの変化](#eol-change-fields) | `[]` |
| `resolved_eol_packages` | objectの配列 | [EOLパッケージの解除](#eol-resolved-fields) | `[]` |
| `oldest_open_days` | integer | [未解決の最長期間](#oldest-open-days) | `0` |

## 通常のパッケージの変化 {#new-fields}

`diff.new[]`は、[通常の検出結果](scan-logic.md#eol-package)の変化を表します。
1要素はイメージ名とパッケージ名の組み合わせに対応し、該当する[パッケージグループ](scan-logic.md#package-grouping)が複数あればまとめます。

`critical`から`unknown`までの件数は、最新のスキャンでのそのパッケージの件数で、まとめたパッケージグループの合計です。
追加されたCVEだけの件数ではありません。

`diff.new[]`の各要素のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `image` | string | イメージ名 | — |
| `package` | string | パッケージ名 | — |
| `kind` | string | 変化の種類 | — |
| `ecosystems` | stringの配列 | パッケージグループの種類を重複なく並べ替えた一覧 | — |
| `runtime_usage` | string | まとめたパッケージグループの[使用状況](webhook-reference.md#usage-values) | 稼働時の使用状況が無効なら省略 |
| `muted` | boolean | まとめたパッケージグループすべての[通知オフ](runtime-usage.md#muting-findings-without-a-fix)を示す値 | すべてが通知オフでなければ省略 |
| `new_cve_count` | integer | 追加されたCVEの件数 | `kind`が`new_cves`以外なら省略 |
| `new_cve_ids` | stringの配列 | 追加されたCVE IDを並べ替えた一覧 | `kind`が`new_cves`以外なら省略 |
| `critical` | integer | CRITICALの件数 | `0` |
| `high` | integer | HIGHの件数 | `0` |
| `medium` | integer | MEDIUMの件数 | 0件なら省略 |
| `low` | integer | LOWの件数 | 0件なら省略 |
| `unknown` | integer | 認識できない深刻度を含むUNKNOWNの件数 | 0件なら省略 |
| `priority` | string | まとめたパッケージグループの最も高い[優先度](webhook-reference.md#priority-values) | トリアージが無効なら省略 |
| `reason` | string | 優先度昇格の根拠または通知再開の理由 | `kind`が`escalated`・`unmuted`以外なら省略 |

`kind`の値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `new` | 保存した履歴にない組み合わせでの新規検出 |
| `escalated` | 検出済みのパッケージの優先度が上昇 |
| `new_cves` | 検出済みのパッケージにCVEが追加 |
| `now_fixable` | 修正版がなかったパッケージで修正版が利用可能になった |
| `unmuted` | [通知オフ](runtime-usage.md#muting-findings-without-a-fix)の条件を満たさなくなり、通知を再開 |

次のフィールドには補足があります。

- `ecosystems`
    - 認識できない種類を`""`として含める
- `runtime_usage`
    - まとめたパッケージグループで判定が分かれる場合は、`in_use`、`unavailable`、`not_observed`の順に、該当する判定があればその値を使う
- `new_cve_ids`
    - 要素数は`new_cve_count`と一致する
- `reason`
    - 通知の言語設定にかかわらず英語の説明文で、固定の値ではない
    - `escalated`の場合の例は`CVE-2031-0001 CRITICAL · CISA KEV (exploited in the wild) · EPSS 94% · 🧨 ransomware campaign`
    - `unmuted`の場合の例は`now in use`

次の例は、CVEが1件追加され、最新のスキャンではHIGHが2件あるパッケージの変化です。

```json
{
  "image": "api:2.0",
  "package": "libxml2",
  "kind": "new_cves",
  "new_cve_count": 1,
  "new_cve_ids": ["CVE-2031-0007"],
  "critical": 0,
  "high": 2,
  "priority": "act_now",
  "ecosystems": [""]
}
```

複数の変化がある場合の判定順は、[通常のパッケージの変化](diff-logic.md#normal-changes)を参照してください。

## パッケージの解消 {#resolved-fields}

`diff.resolved[]`は、通常の検出結果がなくなり、解消と判定したイメージ名とパッケージ名の組み合わせを表します。
通常の検出結果がEOLの検出結果へ移った場合は含めません。

`diff.resolved[]`の各要素のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `image` | string | イメージ名 | — |
| `package` | string | 解消したパッケージ名 | — |

通常の検出結果とEOLの検出結果の区別は、[パッケージのEOL](scan-logic.md#eol-package)を参照してください。
解消の意味は、[解消の判定](diff-logic.md#resolved-findings)を参照してください。

## digestの変更 {#image-replacement-fields}

`diff.replaced[]`は、同じイメージ名で、動いているイメージの内容が変わった場合に出力します。
各要素のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `ref` | string | イメージ名 | — |
| `prev_content_ids` | stringの配列 | 保存した履歴で確認済みの内容識別値を並べ替えた一覧 | — |
| `content_ids` | stringの配列 | 最新のスキャン時に確認できた内容識別値を並べ替えた一覧 | — |

次のフィールドには補足があります。

- `prev_content_ids`・`content_ids`
    - 要素は、イメージの内容を識別する値(config digest)で、イメージの[`content_id`](webhook-reference.md#image-identity)と同じ形式
    - 各配列に1つ以上の要素が入る

変更の判定条件は、[digestの変更](diff-logic.md#image-content-changes)を参照してください。

## イメージ名の更新 {#reference-change-fields}

`diff.reference_changes[]`は、同じワークロードが同じリポジトリの別のタグやdigestのイメージに変わり、検出履歴を引き継いだ場合に出力します。
各要素のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `repository` | string | 更新後のイメージ名からタグとdigestを除いたリポジトリ | — |
| `previous_ref` | string | タグやdigestを含む更新前のイメージ名 | — |
| `ref` | string | タグやdigestを含む更新後のイメージ名 | — |
| `workloads` | stringの配列 | 更新前後に共通するワークロードキーを並べ替えた一覧 | — |

次のフィールドには補足があります。

- `repository`
    - イメージ名に指定されたレジストリのポートも残す
- `workloads`
    - 1つ以上の要素が入る

ワークロードキーの形式は次のとおりです。

| 対象 | ワークロードキーの形式 |
| --- | --- |
| Compose | `compose/<project>/<service>` |
| Kubernetes | `<kind>/<namespace>/<name>/<container>` |
| 所属ワークロードが不明なDockerコンテナ | `container/<name>` |
| 所属ワークロードが不明なKubernetesコンテナ | `container/<namespace>/<pod>/<container>` |

形式の各部分は、次の意味です。

- `<project>`はComposeプロジェクト名
- `<service>`はComposeサービス名
- `<kind>`は`containers[].workload.kind`と同じ値
- `<namespace>`はnamespace
- `<name>`
    - Kubernetesの形式ではワークロード名
    - 所属ワークロードが不明なDockerコンテナの形式では`containers[].name`と同じ値
- `<pod>`はPod名
- `<container>`はPod内のコンテナ名

次の例は、Composeサービス`shop/web`のイメージ名が更新され、検出履歴を引き継いだ場合です。

```json
{
  "repository": "ghcr.io/acme/web",
  "previous_ref": "ghcr.io/acme/web:sha-aaaa",
  "ref": "ghcr.io/acme/web:sha-bbbb",
  "workloads": ["compose/shop/web"]
}
```

履歴を引き継ぐ条件は、[イメージ名の更新](diff-logic.md#reference-changes)を参照してください。

## ベースOSのEOL変化 {#eol-base-fields}

`diff.new_eosl`と`diff.resolved_eosl`は、ベースOSのEOLの記録が変わったイメージ名の配列です。
各配列の要素は次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `diff.new_eosl[]` | string | ベースOSが新たにEOLとして記録されたイメージ名 | — |
| `diff.resolved_eosl[]` | string | ベースOSがEOLとして記録されなくなったイメージ名 | — |

## EOLパッケージの変化 {#eol-change-fields}

`diff.new_eol_packages[]`は、[EOLの検出結果](scan-logic.md#eol-package)が新たに見つかったパッケージや、EOLの検出結果に変化があったパッケージの一覧です。
1要素はイメージ名とパッケージ名の組み合わせに対応します。

イメージのベースOSがEOLの場合、SlackはEOL区分でそのイメージのEOLパッケージを個別に表示しませんが、Webhookには含めます。

`critical`から`unknown`までの件数は、最新のスキャンでのそのパッケージの[EOLの検出結果](scan-logic.md#eol-package)の件数です。
該当するパッケージグループが複数あれば、件数を合計します。

`diff.new_eol_packages[]`の各要素のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `image` | string | イメージ名 | — |
| `package` | string | パッケージ名 | — |
| `kind` | string | EOLの変化の種類 | — |
| `ecosystems` | stringの配列 | パッケージグループの種類を重複なく並べ替えた一覧 | — |
| `runtime_usage` | string | まとめたパッケージグループの[使用状況](webhook-reference.md#usage-values) | 稼働時の使用状況が無効なら省略 |
| `new_cve_ids` | stringの配列 | 追加されたEOLのCVE IDを並べ替えた一覧 | `kind`が`eol_new_cves`以外なら省略 |
| `critical` | integer | CRITICALの件数 | `0` |
| `high` | integer | HIGHの件数 | `0` |
| `medium` | integer | MEDIUMの件数 | 0件なら省略 |
| `low` | integer | LOWの件数 | 0件なら省略 |
| `unknown` | integer | 認識できない深刻度を含むUNKNOWNの件数 | 0件なら省略 |
| `priority` | string | まとめたパッケージグループの最も高い[優先度](webhook-reference.md#priority-values) | トリアージが無効なら省略 |
| `reason` | string | 優先度昇格の根拠を示す説明文 | `kind`が`eol_escalated`以外なら省略 |

`kind`の値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `eol_new` | 新たなEOL検出 |
| `eol_new_cves` | 検出済みのEOLパッケージにCVEが追加 |
| `eol_escalated` | EOLパッケージの優先度が`act_now`に上昇 |

次のフィールドには補足があります。

- `ecosystems`
    - 認識できない種類を`""`として含める
- `runtime_usage`
    - [通常のパッケージの変化](#new-fields)と同じ決め方
- `new_cve_ids`
    - `new_cve_count`は出力しないため、追加件数は要素数で確認する
- `reason`
    - 通知の言語設定にかかわらず英語の説明文で、固定の値ではない

次の例は、EOLパッケージにCVEが1件追加された場合です。

```json
{
  "image": "legacy:1",
  "package": "zlib",
  "kind": "eol_new_cves",
  "new_cve_ids": ["CVE-2033-0007"],
  "critical": 1,
  "high": 1,
  "priority": "act_now",
  "ecosystems": [""]
}
```

変化の判定条件は、[EOLパッケージの変化](diff-logic.md#eol-package-changes)を参照してください。

## EOLパッケージの解除 {#eol-resolved-fields}

`diff.resolved_eol_packages[]`は、[EOLの検出結果](scan-logic.md#eol-package)がなくなったイメージ名とパッケージ名の組み合わせを表します。
各要素のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `image` | string | イメージ名 | — |
| `package` | string | EOLの検出結果がなくなったパッケージ名 | — |
| `still_open` | boolean | 通常の検出結果が残っているかどうか | `false` |

`still_open`が`true`なら、同じイメージ名の同じパッケージに[通常の検出結果](scan-logic.md#eol-package)が残っています。

次の例は、EOLの検出結果がなくなり、通常の検出結果が残っている場合です。

```json
{
  "image": "app:2.1",
  "package": "sqlite-libs",
  "still_open": true
}
```

## 未解決の最長期間 {#oldest-open-days}

`diff.oldest_open_days`は、対象となる記録の最も古い初回検出日から、`generated_at`の時点までの日数です。
1日未満は切り捨て、対象がない場合は`0`を出力します。

比べる対象と使う日付は次のとおりです。
`act_now`の意味は、[優先度の値](webhook-reference.md#priority-values)を参照してください。

| 対象 | 条件 | 比べる日付 |
| --- | --- | --- |
| [通常の検出結果](scan-logic.md#eol-package) | `low`・[通知オフ](runtime-usage.md#muting-findings-without-a-fix)・[保持中の記録](diff-logic.md#retained-findings)も対象 | 通常の検出結果の初回検出日 |
| ベースOSのEOL | ベースOSがEOLとして記録されている | ベースOSの初回EOL検出日 |
| [EOLの検出結果](scan-logic.md#eol-package) | イメージのベースOSがEOLでない場合 | パッケージの初回EOL検出日 |
| EOLの検出結果 | イメージのベースOSがEOLで、パッケージの優先度が`act_now`の場合 | パッケージの初回EOL検出日 |
| EOLの検出結果 | イメージのベースOSがEOLで、パッケージの優先度が`act_now`でない場合 | パッケージの初回EOL検出日は比べる対象に入れず、ベースOSの初回EOL検出日を使う |

Slackのトリアージ有効時の経過日数とは対象が異なります。
Slack側の定義は、[未解決の経過日数](slack-display.md#unresolved-age)を参照してください。
