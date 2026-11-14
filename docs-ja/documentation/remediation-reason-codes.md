---
title: 修正計画の結果の値と理由コード
---

# 修正計画の結果の値と理由コード

修正計画の値と理由コードから、候補の判定結果や処理を進められなかった理由を調べるページです。
Webhookでは`category`・`status`・`action`・`reason`などに値が入り、日本語のSlack通知では理由を日本語の文で表示します。

Webhookのフィールド経路は、以下では`remediation`の直下から記します。

調べたい値に応じて、次の節を参照してください。

| 調べるもの | 参照先 |
| --- | --- |
| 計画項目全体の判定 | [計画の分類値](#category-values) |
| 新しい系列の候補の確認結果 | [新しい系列の状態値](#newer-series-status-values) |
| 個々のパッケージの扱い | [パッケージの処理値](#action-values) |
| PR処理の結果とPR自体の状態 | [PRの状態値](#pr-status-values) |
| 候補の選定理由や処理を止めた理由 | [理由コード](#reason-codes) |

このページで使う用語は[用語](remediation.md#terms)を参照してください。

## 結果の値 {#result-values}

結果の値は、計画項目、候補、パッケージ、PR処理のそれぞれの状態を表します。

### 計画の分類値 {#category-values}

`category`は、イメージや依存ディレクトリなど、計画項目全体の判定を表します。

Webhookでは、次のフィールドに分類値が入ります。

| 対象 | フィールド |
| --- | --- |
| 配布イメージ | `items[].category` |
| ベースイメージの項目全体 | `dockerfile_items[].category` |
| ベースイメージを確認した稼働イメージごとの結果 | `dockerfile_items[].entities[].category` |
| 言語パッケージの依存ディレクトリ | `language_items[].category` |

分類値の意味は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `pr_candidate` | 検査を通り、PRでの変更を提案できる候補である |
| `dependency_update_candidate` | ソースと修正版情報から選んだ依存更新候補で、更新結果は未検証である |
| `pull_again` | 同じタグの内容を再取得することで改善が見込める、比較済みの候補である |
| `rebuild_expected` | 現在の依存範囲から、再ビルドで修正版が入る見込みがある |
| `manual` | 自動では更新せず、利用者の判断に任せる手動対応である |
| `not_comparable` | 情報や条件が不足し、更新前後のスキャン結果を比較できない |
| `deferred` | 上限、待機、取得の問題などにより、処理を後のサイクルへ保留する |
| `no_candidate` | 新しい候補がない、内容が同じ、または候補で対象の所見が解消しない |
| `excluded` | 自動で候補を探す対象ではない |
| `failed` | 処理に失敗した |

`not_comparable`は比較できない判定、`deferred`は処理の保留、`failed`は処理の失敗を表します。
具体的な原因は、同じ項目の`reason`で確認してください。

Slackの表示欄には、分類値と異なる名前を使う場合があります。

| Slackの表示欄 | 表示する内容 |
| --- | --- |
| 「再ビルド」 | `rebuild_expected`の項目と、`not_comparable`に分類された浮動タグのベースイメージの案内を表示する |
| 「要判断」 | 手動対応の内容を表示する |

通知全体の読み方は[Slackの修正計画](remediation-results.md#reading-results-in-slack-and-webhooks)を参照してください。

### 新しい系列の状態値 {#newer-series-status-values}

新しい系列の状態値は、現在と異なる版のまとまりで、対象の所見が解消するかを表します。
`1.24.1`に対する`1.27.3`は新しいminor系列、`2.0.1`は新しいmajor系列です。

Webhookでは、`items[].newer_series`、`dockerfile_items[].newer_series`、`dockerfile_items[].entities[].newer_series`に結果が入ります。
各オブジェクトの`candidates[].status`は候補ごとの結果で、`status`は候補の結果をまとめた判定です。

解消する候補を表示する場合、各`newer_series`の`shown`には、全体の判定に使う候補のタグが入ります。
全体の`status`は、同じ`newer_series`の`candidates[]`で`tag`が`shown`と一致する候補の状態になります。

新しい系列の結果によって、計画項目全体の`category`は変更しません。

配布イメージで`2.0.1`を表示する場合のフィールドの対応例を示します。

| Webhookのフィールド | 値の例 |
| --- | --- |
| `items[].newer_series.shown` | `2.0.1` |
| `items[].newer_series.status` | `resolves` |
| `items[].newer_series.candidates[].tag` | `2.0.1` |
| `items[].newer_series.candidates[].status` | `resolves` |

KEVは、悪用が確認された脆弱性を収録するCISAのKnown Exploited Vulnerabilities一覧です。
状態値の意味は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `resolves` | 対象の所見がすべて解消し、新しい所見の増加がない |
| `resolves_partially` | 対象の所見の一部が解消し、残りがあり、新しい所見の増加がない |
| `resolves_with_new` | 対象の所見が1件以上解消し、新しい所見またはKEV掲載の所見が増える |
| `not_resolving` | 解消した対象の所見が0件である |
| `not_checked` | 確認を完了できなかった |
| `no_newer_series` | 条件に合う新しい系列のタグがない |

`no_newer_series`は全体の`status`にだけ使います。
`not_checked`の原因は、全体または候補の`reason`で確認してください。

確認できない原因には、取得・スキャンの失敗、候補数などの上限、実行期限、判定不能な対象、比較元で検出されない対象があります。
候補の選び方と比較範囲は[新しい系列の確認](remediation-image-logic.md#newer-series-check)を参照してください。

### パッケージの処理値 {#action-values}

`action`は個々のパッケージの扱いを表し、Webhookの`language_items[].packages[].action`に入ります。
計画項目全体の`category`とは別に確認してください。

処理値の意味は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `update` | 依存ファイルを更新する対象である |
| `rebuild_expected` | 現在の依存範囲が修正版を許し、再ビルドによる解消を見込む対象である |
| `manual` | 手動対応が必要な対象である |

`update`だけでは、更新の実行や検証の完了を表しません。
実行と検査は、次のフィールドを併せて確認してください。

| フィールドと値 | 確認できること |
| --- | --- |
| `language_items[].update_executed: true` | 最新の修正計画の処理で、依存更新の操作を最後まで実行した |
| `language_items[].post_update_check_executed: true` | 最新の修正計画の処理で、更新結果を受け取って検査した |
| `language_items[].source_check.passed: true` | 更新前後の依存ファイルの検査に合格した |

検査を実行しても、不合格になる場合があります。
版の読み分けは[更新目標と採用版](remediation-update-results.md#target-and-adopted-version)を参照してください。

### PRの状態値 {#pr-status-values}

PRの状態値は、修正計画で行ったPR処理の結果と、対応するPR自体の状態を表します。
Webhookの`pull_requests[].status`には、次の処理結果が入ります。

| 値 | 意味 |
| --- | --- |
| `pr_created` | 最新の修正計画の処理でPRを作成した |
| `pr_open` | 同じ更新を提案するPRが開いている |
| `pr_merged` | 同じ更新のPRがマージ済みで、配置済みかは未確認である |
| `pr_suppressed` | 未マージで閉じた更新のため、再作成を抑止した |
| `manual` | 自動編集できず、手動対応が必要である |
| `deferred` | 上限や候補の変化などにより、後のサイクルへ処理を延期した |
| `failed` | GitHubへの書き込みなどに失敗した |
| `write_blocked` | PR処理の記録やGitHub上の状態などの問題により、書き込みを停止した |
| `write_disabled` | PR作成が無効であることを表す値で、通常のPR処理では生成しない |

Webhookの`pull_requests[].state`は、対応するPRについて`prs.json`に記録した状態です。
処理結果の`status`と区別して、次の値を読みます。

| 値 | 意味 |
| --- | --- |
| `open` | PRが開いている |
| `closed` | PRが未マージでクローズ済みである |
| `merged` | PRがマージ済みである |
| `replaced` | 新しいPRに置き換えるため、KestreLynxがPRをクローズ済みである |

## 理由コード {#reason-codes}

理由コードは、候補を選んだ理由や処理を進められなかった理由を表す、結果の`reason`に入る値です。
Webhookでは計画項目、候補、`language_items[].packages[]`、更新結果、`pull_requests[]`などで確認します。

調べたい理由の分類から、コードを掲載したページと節へ進んでください。

| 理由の分類 | どんなときに見るか | ページと節 |
| --- | --- | --- |
| イメージ候補 | イメージの比較や候補の採用を確認するとき | [イメージ候補の理由](remediation-image-reason-codes.md#image-reasons) |
| ソース | ファイルの取得・解釈・編集や稼働イメージとの照合を確認するとき | [ソースの理由](remediation-image-reason-codes.md#source-reasons) |
| 実行環境 | 言語ランタイムや作業用コンテナを使えないとき | [実行環境の理由](remediation-update-reason-codes.md#runtime-reasons) |
| ツール取得 | パッケージマネージャーの取得・検証・待機を確認するとき | [ツール取得の理由](remediation-update-reason-codes.md#tool-reasons) |
| 更新結果 | 依存更新の候補選定・実行・検査の結果を確認するとき | [更新結果の理由](remediation-update-reason-codes.md#update-reasons) |
| PR処理 | PRの作成・照合・置換や書き込み停止を確認するとき | [PR処理の理由](remediation-update-reason-codes.md#pr-reasons) |
| 保存処理 | PR処理の記録を読めない、または保存できないとき | [保存処理の理由](remediation-update-reason-codes.md#storage-reasons) |
