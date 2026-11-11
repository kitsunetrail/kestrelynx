---
title: Webhookの基本のフィールド
---

# Webhookの基本のフィールド

## ペイロードの範囲 {#generic-webhook}

汎用Webhookは、現在のスキャン結果をJSONで送信します。
`diff`モードでは、現在の結果に加えて保存している履歴と最新のスキャンを比べた変化を含めます。

ペイロードには、Slackでは個別に表示しないものも含めます。

- 優先度が`low`の[パッケージグループ](scan-logic.md#package-grouping)
- [通知オフ](runtime-usage.md#muting-findings-without-a-fix)のパッケージグループ
- イメージのベースOSがEOLの場合も、そのイメージのEOLパッケージを含める
- イメージを使っているコンテナとワークロード

Slackと併用できますが、DiscordやTeams専用のメッセージ形式には変換しません。

送信時の動作は次のとおりです。

| 項目 | 動作 |
| --- | --- |
| HTTPメソッド | `POST` |
| Content-Type | `application/json` |
| 認証 | 送信先URLにユーザー名を含めた場合はパスワードの有無にかかわらずBasic認証の`Authorization`ヘッダーを付け、署名は付けない |
| 応答の扱い | HTTPステータスが`2xx`なら成功、それ以外は失敗 |
| 応答を待つ時間 | 15秒 |
| 失敗時の再送 | その場での再送は行わず、次回以降は[スキャン通知の再送](notification-conditions.md#scan-redelivery)に従う |

設定、通知の送信条件、各フィールドの詳細は、次のページを参照してください。

| 内容 | ページ |
| --- | --- |
| 送信先 | [設定](configuration.md) |
| 送信のタイミング | [通知の送信条件](notification-conditions.md#notification-conditions) |
| `diff`のフィールド | [Webhookの差分のフィールド](webhook-diff-reference.md) |
| トップレベルの`runtime`と`findings[].runtime`のフィールド | [Webhookの稼働時のフィールド](webhook-runtime-reference.md) |
| `remediation`のフィールド | [Webhookの修正計画の全体と共通のオブジェクト](webhook-remediation-reference.md) |

## ペイロードの全体像 {#payload-overview}

ペイロードには、レポート全体の情報と、イメージごとの検出結果を入れます。
省略されることがあるフィールドも含めて、主な入れ子の構造を次に示します。

```text
ペイロード
├── generated_at
├── environment
├── summary
├── eosl_images[]
├── actionable[]・watch[]・wont_fix[]・eol_packages[]   イメージ
│   ├── containers[]                                   コンテナ
│   │   └── workload
│   └── findings[]                                     パッケージグループ
│       ├── vulns[]                                    脆弱性
│       │   └── refs[]
│       └── runtime
│           └── containers[]
│               ├── process
│               └── instances[]
├── scan_errors[]
├── runtime_unchecked[]
├── diff
├── runtime
└── remediation
```

`actionable`・`watch`・`wont_fix`・`eol_packages`は、要素が同じフィールドを持つイメージ配列です。
同じイメージが複数の配列に入ることがあります。

次は、`web:1.0`のパッケージグループ1件と、`broken:1`のスキャン失敗を含む、`diff`モードのペイロードの例です。

```json
{
  "generated_at": "2026-06-24T09:00:00Z",
  "environment": {
    "kind": "docker"
  },
  "summary": {
    "images_total": 2,
    "images_affected": 1,
    "priority_counts": {
      "act_now": 1,
      "low": 0,
      "watch": 0
    },
    "intel": {
      "degraded": false,
      "kev_ok": true,
      "epss_ok": true,
      "stale_days": 0
    }
  },
  "eosl_images": null,
  "actionable": [
    {
      "image": "web:1.0",
      "severity_counts": {
        "CRITICAL": 1,
        "HIGH": 0
      },
      "findings": [
        {
          "package": "openssl",
          "installed": "3.0.7",
          "fixed": "3.0.11",
          "status": "fixed",
          "severity_counts": {
            "CRITICAL": 1,
            "HIGH": 0
          },
          "upgrade_risk": "distro_update",
          "priority": "act_now",
          "vuln_ids": [
            "CVE-2031-0001"
          ],
          "vulns": [
            {
              "id": "CVE-2031-0001",
              "severity": "CRITICAL",
              "url": "https://avd.example/CVE-2031-0001",
              "title": "openssl: buffer overread",
              "kev": true,
              "ransomware": true,
              "epss": 0.94321,
              "priority": "act_now",
              "refs": [
                {
                  "kind": "vendor",
                  "label": "vendor advisory",
                  "url": "https://vendor.example/advisory/1"
                }
              ]
            }
          ],
          "class": "os",
          "ecosystem": ""
        }
      ],
      "containers": [],
      "content_id": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
      "registry_digests": [],
      "identity_resolved": true,
      "scan_target_kind": "content_id"
    }
  ],
  "watch": [],
  "wont_fix": [],
  "eol_packages": [],
  "scan_errors": [
    {
      "image": "broken:1",
      "error": "pull failed",
      "cause": "unclassified"
    }
  ],
  "diff": {
    "new": [
      {
        "image": "web:1.0",
        "package": "openssl",
        "kind": "escalated",
        "critical": 1,
        "high": 0,
        "priority": "act_now",
        "reason": "CVE-2031-0001 CRITICAL · CISA KEV (exploited in the wild) · EPSS 94% · 🧨 ransomware campaign",
        "ecosystems": [
          ""
        ]
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
}
```

## レポートのフィールド {#report-fields}

各表のフィールド名は、表の前の文で示すオブジェクトからの相対パスです。
`a.b`は`a`の中の`b`、`a[]`は配列`a`の各要素を表します。

「値がないとき」の表記は、次のように読みます。

| 表記 | 意味 |
| --- | --- |
| 省略 | 値がない、該当がない、または取得できない場合はキーごと出力しない |
| 〜なら省略 | 記載した条件に当てはまる場合はキーごと出力しない |
| `[]`・`null`・`""`・`0`・`false` | 記載した値を出力する |
| — | 表の対象のオブジェクトがあれば必ず値がある |

### 複数のフィールドで使う値 {#common-values}

複数のフィールドで使う優先度、修正状態、深刻度ごとの件数、使用状況をここにまとめます。

#### 優先度 {#priority-values}

脆弱性と[パッケージグループ](scan-logic.md#package-grouping)の優先度の値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `act_now` | 今すぐ対応 |
| `watch` | 緊急性は低いが継続監視 |
| `low` | 低優先度としてまとめて対応 |

判定の条件は、[悪用情報による優先度](scan-logic.md#triage)を参照してください。

#### 修正状態 {#status-values}

[パッケージグループ](scan-logic.md#package-grouping)の[修正状態](scan-logic.md#status)の値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `fixed` | 修正版あり |
| `affected` | 影響あり・修正版なし |
| `will_not_fix` | 対象プラットフォームでは現時点で修正予定なし |
| `end_of_life` | サポート範囲外 |

`affected`には、Trivyの`fix_deferred`・`under_investigation`・`unknown`などもまとめます。

#### 深刻度ごとの件数 {#severity-count-fields}

イメージやパッケージグループにある`severity_counts`のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `CRITICAL` | integer | 深刻度が`CRITICAL`のCVE件数 | `0` |
| `HIGH` | integer | 深刻度が`HIGH`のCVE件数 | `0` |
| `MEDIUM` | integer | 深刻度が`MEDIUM`のCVE件数 | 0件なら省略 |
| `LOW` | integer | 深刻度が`LOW`のCVE件数 | 0件なら省略 |
| `UNKNOWN` | integer | 深刻度が不明、または認識できないCVEの件数 | 0件なら省略 |

次のフィールドには補足があります。

- `MEDIUM`・`LOW`・`UNKNOWN`
    - `scan.severity`に指定した深刻度が検出対象
    - 既定の`[HIGH, CRITICAL]`では検出対象外
    - 受け取ったJSONだけでは検出対象外と0件を区別できない

#### 使用状況 {#usage-values}

[稼働時の使用状況](runtime-usage.md)を表す値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `in_use` | 判定方法に従って使用を確認できた状態 |
| `not_observed` | 観測期間に使用を確認できなかった状態 |
| `unavailable` | 証拠が足りず判定できない状態 |

`not_observed`は、使われていないことを意味しません。

### トップレベル {#top-level}

トップレベルには、レポート全体の情報、検出結果、スキャン失敗、差分などを入れます。

`actionable`・`watch`・`wont_fix`・`eol_packages`は、[修正状態](scan-logic.md#status)ごとの区分です。
`watch`は修正状態を`affected`にまとめた結果の配列で、[優先度](#priority-values)の`watch`とは別です。

`not_affected`の検出結果は、4つの配列のどれにも含めません。

トップレベルのフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `generated_at` | string | レポートをまとめた時刻（RFC 3339形式） | — |
| `environment` | object | [環境](#environment) | — |
| `summary` | object | [サマリー](#summary) | — |
| `eosl_images` | stringの配列または`null` | ベースOSがEOLのイメージ名の一覧 | `null` |
| `actionable` | objectの配列 | 修正状態が`fixed`のパッケージグループを持つ[イメージ](#images) | `[]` |
| `watch` | objectの配列 | 修正状態が`affected`のパッケージグループを持つイメージ | `[]` |
| `wont_fix` | objectの配列 | 修正状態が`will_not_fix`のパッケージグループを持つイメージ | `[]` |
| `eol_packages` | objectの配列 | 修正状態が`end_of_life`のパッケージグループを持つイメージ | `[]` |
| `scan_errors` | objectの配列 | [スキャン失敗](#scan-errors)の一覧 | `[]` |
| `runtime_unchecked` | objectの配列 | [未照合の言語ランタイム](#runtime-unchecked)の一覧 | 省略 |
| `diff` | object | [差分](webhook-diff-reference.md) | `full`モードなら省略 |
| `runtime` | object | [Sensorの情報と使用状況の件数](webhook-runtime-reference.md) | 稼働時の使用状況が無効なら省略 |
| `remediation` | object | [修正計画とPR処理の結果](webhook-remediation-reference.md#remediation-fields) | 修正計画が無効なら省略 |

JSON全体の例は、[ペイロードの全体像](#payload-overview)を参照してください。

### 環境 {#environment}

`environment`は、スキャンした実行環境を表します。
`environment`のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `kind` | string | 実行環境の種類 | — |
| `name` | string | [設定](configuration.md)の`environment.name`で指定した環境名 | 未設定なら省略 |

`kind`の値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `docker` | Docker Engineのホスト |
| `kubernetes` | Kubernetesクラスタ |

### サマリー {#summary}

`summary`は、スキャンした対象と影響のあるイメージの件数、優先度ごとの件数、脅威情報の利用状況を表します。

`summary`のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `images_total` | integer | スキャンした対象の数で、同じイメージ名でもdigestが違えば別に数え、スキャンに失敗した対象も含む | `0` |
| `images_affected` | integer | 4つの検出結果の配列のどれかに含まれるか、ベースOSがEOLであるイメージ名の数 | `0` |
| `priority_counts` | object | [優先度](#priority-values)ごとの[パッケージグループ](scan-logic.md#package-grouping)件数 | トリアージが無効なら省略 |
| `priority_counts.act_now` | integer | 優先度が`act_now`の件数 | `0` |
| `priority_counts.watch` | integer | 優先度が`watch`の件数 | `0` |
| `priority_counts.low` | integer | 優先度が`low`の件数 | `0` |
| `intel` | object | KEVとEPSSの利用可否とデータの古さ | トリアージが無効なら省略 |
| `intel.degraded` | boolean | KEVとEPSSのどちらも利用できないか | `false` |
| `intel.kev_ok` | boolean | KEVを利用できるか | `false` |
| `intel.epss_ok` | boolean | EPSSを利用できるか | `false` |
| `intel.stale_days` | integer | 取得し直せず使っている保存済みデータのうち最も古いものの経過日数で、最新のデータなら`0` | `0` |

`priority_counts`の数え方は次のとおりです。

- 単位は[パッケージグループ](scan-logic.md#package-grouping)
- EOLパッケージは、優先度が`act_now`のものだけを数える
- EOLパッケージの集計対象が限られるため、3つの件数の合計は4つの配列に含まれるパッケージグループの合計と一致するとは限らない
- [通知オフ](runtime-usage.md#muting-findings-without-a-fix)のパッケージグループも数える

次は、トリアージが有効な場合の`summary`の例です。

```json
{
  "images_total": 3,
  "images_affected": 2,
  "priority_counts": {
    "act_now": 3,
    "low": 4,
    "watch": 1
  },
  "intel": {
    "degraded": false,
    "kev_ok": true,
    "epss_ok": true,
    "stale_days": 0
  }
}
```

### 未照合の言語ランタイム {#runtime-unchecked}

`runtime_unchecked`は、Node.jsまたはPythonの本体を見つけたものの、セキュリティ情報を取得できず照合しなかった対象の一覧です。
同じイメージ名と本体の組は1度だけ出力します。

`runtime_unchecked[]`のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `image` | string | 本体を照合しなかったイメージ名 | — |
| `package` | string | 照合しなかった本体のパッケージ名 | — |

`package`の値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `Node.js` | Node.js本体 |
| `Python runtime` | Python本体 |

通知と履歴の扱いは、[言語ランタイムのセキュリティ情報の利用不能時の扱い](scan-logic.md#node-runtime-unavailable)を参照してください。

### スキャン失敗 {#scan-errors}

`scan_errors`は、スキャンに失敗した対象とエラーを示します。
`scan_errors[]`のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `image` | string | スキャンに失敗したイメージ名 | — |
| `error` | string | Trivyなどが返したエラーの文面 | — |
| `cause` | string | スキャン失敗の原因 | — |
| `registry` | string | 取得元のレジストリのホスト | 省略 |

`cause`の値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `local_registry` | ローカルレジストリのイメージをKestreLynxから取得できない |
| `registry_auth` | レジストリのログイン情報が無い、または違うため、イメージを取得できない |
| `image_not_found` | レジストリにイメージが見つからない |
| `registry_rate_limited` | レジストリの取得回数の制限にかかり、イメージを取得できない |
| `registry_unreachable` | レジストリに接続できず、イメージを取得できない |
| `vulnerability_db` | 脆弱性データベースを取得できない |
| `image_mismatch` | スキャンしたイメージが、動いているイメージと一致しない |
| `unclassified` | 原因を分類できない |

`error`の文面は固定の値ではありません。

`cause`の値に対応する表示と条件は、[スキャンできなかったイメージの表示](slack-warnings-display.md#scan-failure-causes)を参照してください。

失敗時の結果の扱いは、[スキャン失敗時の扱い](scan-logic.md#scan-failures)を参照してください。

## イメージのフィールド {#images}

`actionable`、`watch`、`wont_fix`、`eol_packages`の1つの要素は、イメージ名と動いているイメージの内容を識別する値の組に対応し、その配列の[修正状態](scan-logic.md#status)に当たる[パッケージグループ](#findings)をまとめたものです。

レジストリのdigestで識別する場合はプラットフォームも含むため、同じイメージ名・同じdigestでもプラットフォームが違えば別の要素になります。

内容を識別する値を取得できなかったイメージも、該当するパッケージグループがあれば、各配列でイメージ名ごとに1つの要素にまとめて出力します。

同じイメージに修正状態の違うパッケージグループがあれば、複数の配列に同じ`image`の要素が入ります。

次は、`actionable`に入るイメージ1要素の例です。

```json
{
  "image": "api:2.0",
  "severity_counts": {
    "CRITICAL": 0,
    "HIGH": 1
  },
  "findings": [
    {
      "package": "setuptools",
      "installed": "53.0.0",
      "fixed": "78.1.1",
      "status": "fixed",
      "severity_counts": {
        "CRITICAL": 0,
        "HIGH": 1
      },
      "upgrade_risk": "caution",
      "priority": "low",
      "vuln_ids": [
        "CVE-2031-0008"
      ],
      "vulns": [
        {
          "id": "CVE-2031-0008",
          "severity": "HIGH",
          "kev": false,
          "epss": null,
          "priority": "low"
        }
      ],
      "class": "lang",
      "ecosystem": "python-pkg"
    }
  ],
  "containers": [],
  "content_id": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
  "registry_digests": [],
  "identity_resolved": true,
  "scan_target_kind": "content_id"
}
```

### イメージの要素 {#image-identity}

イメージの要素のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `image` | string | イメージ名 | — |
| `severity_counts` | object | この要素に属する各パッケージグループのCVE件数を[深刻度ごと](#severity-count-fields)に合計した値 | — |
| `findings` | objectの配列 | この要素に属する[パッケージグループ](#findings) | `[]` |
| `containers` | objectの配列 | この要素に対応する[コンテナ](#containers) | `[]` |
| `content_id` | string | イメージの内容を識別する値(config digest) | `scan_target_kind`が`content_id`以外なら省略 |
| `registry_digests` | stringの配列 | 同じイメージ名について集めたレジストリのdigestの一覧 | `[]` |
| `identity_resolved` | boolean | スキャン対象が動いているイメージと同じ内容だと確認できたか | `false` |
| `scan_target_kind` | string | スキャン対象の指定方法 | — |

`scan_target_kind`の値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `content_id` | 動いているイメージのconfig digestを指定してスキャン（Docker） |
| `registry_digest` | 動いているイメージのレジストリのdigestを指定してスキャン（Kubernetes） |
| `reference` | イメージ名でスキャンし、動いているイメージと同じ内容かは未確認 |

次のフィールドには補足があります。

- `identity_resolved`
    - `scan_target_kind`が`reference`以外のとき`true`
- `content_id`
    - `sha256:<64桁の小文字の16進数>`の形式
- `registry_digests`
    - スキャンに成功してdigestを確認できた結果から、同じイメージ名について集めた一覧で、この要素だけの値ではない
    - 要素はリポジトリ名を含み、例えば`debian@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251`の形式
- `image`
    - 同じイメージ名を指す差分の`image`や`ref`と同じ文字列で、イメージ名による照合に使える
- `containers`
    - Kubernetesでは`content_id`を出力せず、`registry_digests`は同じイメージ名で共通の一覧なので、digestでは各要素を区別できない
    - Kubernetesで同じイメージ名の要素が複数ある場合は、各要素に対応するコンテナを列挙した`containers`で区別する

### コンテナ {#containers}

`containers[]`は、そのイメージを使って動いているコンテナを表します。
同じイメージ名に複数のdigestがある場合も、各イメージの要素には、その要素とdigestが一致するコンテナだけを含めます。

digestを確認できなかった要素には、同じイメージ名でdigestを確認できなかったコンテナを含めます。

`containers[]`の1要素のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `name` | string | コンテナ名 | `""` |
| `workload` | object | コンテナが属する[ワークロード](#workloads) | — |

`name`の形式は、実行環境によって異なります。

| 実行環境 | `name`の形式 |
| --- | --- |
| Docker | 先頭のスラッシュを除いたコンテナ名 |
| Kubernetes | `<namespace>/<pod>/<container>` |

次は、所属するワークロードが分からないコンテナの例です。

```json
{
  "name": "web-1",
  "workload": {
    "kind": "unknown"
  }
}
```

### ワークロード {#workloads}

`containers[].workload`は、コンテナが属するサービスやKubernetesリソースを表します。
フィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `kind` | string | ワークロードの種類 | — |
| `group` | string | ワークロードが属するプロジェクトまたは名前空間 | 省略 |
| `name` | string | ワークロードの名前 | 省略 |

`kind`の値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `compose` | Docker Composeのサービス |
| `deployment` | KubernetesのDeployment |
| `statefulset` | KubernetesのStatefulSet |
| `daemonset` | KubernetesのDaemonSet |
| `job` | CronJobに属さないKubernetesのJob |
| `cronjob` | KubernetesのCronJob |
| `pod` | ほかのリソースに属さないKubernetesのPod |
| `unknown` | 所属が分からないコンテナ（単独で動かしているDockerコンテナなど） |

`group`と`name`には、実行環境に応じて次の値が入ります。

| 実行環境 | `group` | `name` |
| --- | --- | --- |
| Docker Compose | プロジェクト名 | サービス名 |
| Kubernetes | 名前空間 | リソース名 |

## 検出結果のフィールド {#findings}

`findings[]`の1要素を「パッケージグループ」と呼びます。
同じイメージの同じパッケージで見つかったCVEを、[修正状態](scan-logic.md#status)ごとにまとめたものです（[パッケージ単位の集約](scan-logic.md#package-grouping)）。

パッケージグループの`vulns[]`には、グループに含まれる脆弱性の詳細が1件ずつ入ります。

次は、`openssl`のパッケージグループ1つの例です。

```json
{
  "package": "openssl",
  "installed": "3.0.7",
  "fixed": "3.0.11",
  "status": "fixed",
  "severity_counts": {
    "CRITICAL": 1,
    "HIGH": 0
  },
  "upgrade_risk": "distro_update",
  "priority": "act_now",
  "vuln_ids": [
    "CVE-2031-0001"
  ],
  "vulns": [
    {
      "id": "CVE-2031-0001",
      "severity": "CRITICAL",
      "url": "https://avd.example/CVE-2031-0001",
      "title": "openssl: buffer overread",
      "kev": true,
      "ransomware": true,
      "epss": 0.94321,
      "priority": "act_now",
      "refs": [
        {
          "kind": "vendor",
          "label": "vendor advisory",
          "url": "https://vendor.example/advisory/1"
        }
      ]
    }
  ],
  "class": "os",
  "ecosystem": ""
}
```

### パッケージ {#package-fields}

パッケージグループを表す`findings[]`の1要素のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `package` | string | パッケージ名 | `""` |
| `class` | string | パッケージの分類 | — |
| `ecosystem` | string | パッケージの種類 | `""` |
| `installed` | string | インストール済みバージョン | `""` |
| `fixed` | string | 修正版のバージョン | `""` |
| `status` | string | パッケージグループの[修正状態](#status-values) | — |
| `severity_counts` | object | このパッケージグループの[深刻度ごとの件数](#severity-count-fields) | — |
| `upgrade_risk` | string | 修正版への更新の注意度 | `""` |
| `priority` | string | パッケージグループの[対応優先度](#priority-values) | トリアージが無効なら省略 |
| `vuln_ids` | stringの配列 | グループに含まれる脆弱性のID | `[]` |
| `vulns` | objectの配列 | [脆弱性ごとの詳細](#vulnerability-fields) | `[]` |
| `runtime` | object | [パッケージグループの使用状況](webhook-runtime-reference.md#finding-runtime) | 稼働時の使用状況が無効なら省略 |

`class`の値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `os` | OSパッケージ |
| `lang` | 言語パッケージ |

`upgrade_risk`の値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `""` | 修正版なし |
| `distro_update` | OSパッケージの修正版への更新 |
| `safe` | 言語パッケージでメジャーバージョンが増えない更新（パッチ・マイナーの更新など） |
| `caution` | 言語パッケージでメジャーバージョンが増える更新 |
| `unknown` | 言語パッケージでバージョンを比較できない更新 |

次のフィールドには補足があります。

- `class`
    - KestreLynxが追加するNode.js・Python本体の検出結果は`lang`
- `ecosystem`
    - Trivyが報告するパッケージの種類で、`debian`、`alpine`、`python-pkg`、`node-pkg`など
    - KestreLynxが追加する本体の検出結果には`node-runtime`と`python-runtime`を使う
    - 認識できない種類は`""`
- `fixed`
    - グループを作るときに最初に取り込んだ検出結果の修正版を出力
    - CVEごとに修正版が違う場合は、そのうちの1つの版であり、`fixed`の版ですべてのCVEが直るとは限らない
- `vuln_ids`
    - `vulns[].id`と同じ集合

更新の注意度の説明は[更新の注意度](slack-package-display.md#upgrade-risk)、優先度の判定は[悪用情報による優先度](scan-logic.md#triage)を参照してください。

### 脆弱性 {#vulnerability-fields}

`vulns[]`の1要素は、パッケージグループに含まれる脆弱性1件の詳細を表します。
フィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `id` | string | 脆弱性のID | `""` |
| `severity` | string | 脆弱性の深刻度 | `""` |
| `status` | string | Trivyが報告した[修正状態](scan-logic.md#status) | パッケージグループの`status`と同じなら省略 |
| `url` | string | 主要なアドバイザリーのURL | 省略 |
| `title` | string | 脆弱性の短い説明 | 省略 |
| `kev` | boolean | CISA KEVへの掲載が確認できれば`true` | `false` |
| `ransomware` | boolean | KEVがランサムウェアでの悪用を既知としていれば`true` | `false`なら省略 |
| `epss` | numberまたは`null` | EPSSのスコア | `null` |
| `priority` | string | 脆弱性の対応優先度 | トリアージが無効なら省略 |
| `refs` | objectの配列 | [追加参照](#reference-fields) | 該当なしなら省略 |

`status`に出る代表的な値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `fix_deferred` | 修正延期 |
| `under_investigation` | 調査中 |
| `unknown` | 修正状態不明 |

次のフィールドには補足があります。

- `status`
    - 省略されている場合は、パッケージグループの`status`と同じ値として読む
    - Trivyの修正状態が未指定または空の場合は`unknown`を出力
    - 上の表にない値をTrivyが返した場合、その値がそのまま出ることもある
- `severity`
    - Trivyが報告した値をそのまま出力し、`CRITICAL`、`HIGH`、`MEDIUM`、`LOW`、`UNKNOWN`などが入る
- `kev`
    - トリアージが無効のときやKEVのデータを使えないときも`false`
- `epss`
    - 0〜1の値で、悪用される確率を示す

次は、KEVとEPSSの情報を含む脆弱性1件の例です。

```json
{
  "id": "CVE-2031-0001",
  "severity": "CRITICAL",
  "url": "https://avd.example/CVE-2031-0001",
  "title": "openssl: buffer overread",
  "kev": true,
  "ransomware": true,
  "epss": 0.94321,
  "priority": "act_now",
  "refs": [
    {
      "kind": "vendor",
      "label": "vendor advisory",
      "url": "https://vendor.example/advisory/1"
    }
  ]
}
```

`priority`は[優先度の値](#priority-values)を参照してください。

### 追加参照 {#reference-fields}

`vulns[].refs[]`の1要素は、脆弱性に関する追加の参照先を表します。
フィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `kind` | string | 参照先の種類 | — |
| `label` | string | 参照先を表示するためのラベル | — |
| `url` | string | 参照先のURL | — |

`kind`の値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `vendor` | KEVに載っているベンダーのアドバイザリー |
| `discussion` | Hacker Newsの議論 |

`label`には、例えば`vendor advisory`が入ります。

## 受信側の実装で守ること {#compatibility}

受信側のプログラムは、次の決まりに従ってペイロードを読み取ってください。

- Webhookの各フィールド仕様ページに記載のないフィールドが増えても、そのフィールドを無視する
- 値の表にない値を受け取っても、処理全体を失敗させない
- 省略・`null`・`[]`・`""`を別の値として扱い、各表の「値がないとき」に従って読む
