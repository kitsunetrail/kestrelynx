---
title: 修正計画の通知の読み方
---

# 修正計画の通知の読み方

このページでは、Slackに届いた修正計画の各行と件数、PRに含まれる更新と対応が残るパッケージを読み分けます。
版の読み分けや「再pull」「再ビルド」の案内は[更新結果の解釈](remediation-update-results.md#interpreting-updates)を参照してください。

PR本文は[修正PRの内容とマージ前の確認](remediation-pr-results.md)、更新できない理由の案内は[案内の概要](remediation-fix-hints.md#fix-hints)を参照してください。

このページで使う用語は[用語](index.md#terms)を参照してください。

## Slackの修正計画 {#reading-results-in-slack-and-webhooks}

Slackの修正計画は、対象のイメージやファイルごとに、提案された変更とPRの状態、進められなかった理由を示します。

### 表示例 {#slack-example}

次は、パッケージ更新とベースイメージ更新を提案する例です。
Slackではイメージ名が太字になり、PR番号はリンクになります。

```text
🔧 修正計画
Pull Request: 作成 1件 · オープン中 1件

イメージ: example/app:latest
修正するファイル: example/application の pnpm-lock.yaml
Pull Request: #12 (今回作成)
更新: package-a 1.2.3 → 1.2.4
要判断: package-b 2.1.1 を修正版の 2.3.0 に上げられない（原因は確かめられなかった）

イメージ: example/service:latest
修正するファイル: example/application の docker/Dockerfile
Pull Request: #13 (オープン中)
更新: ベースイメージ python 3.12.3-slim → 3.12.4-slim
```

PRに含まれる変更と残る対応は、次のように読み分けます。

| 行 | この例で分かること |
| --- | --- |
| `Pull Request: #12 (今回作成)`と直後の`更新` | 今回作ったPR #12に、`package-a`の`1.2.4`への更新が含まれる |
| `要判断: package-b …` | `package-b`の更新はPR #12に含まれず、別途対応が残る |
| `Pull Request: #13 (オープン中)`と直後の`更新` | ベースイメージを`3.12.4-slim`に上げるPR #13が開いている |

「原因は確かめられなかった」と表示された場合の確認の進め方は、[案内の概要](remediation-fix-hints.md#fix-hints)を参照してください。

### 表示項目 {#slack-fields}

修正計画は、`イメージ:`や`更新:`のように「ラベル: 内容」と書かれた行で、対象や更新内容を示します。

冒頭の`Pull Request: 作成 …件`のような件数の行は別に扱い、[件数の読み方](#reading-counts)で説明します。

`イメージ`・`サービス`・`修正するファイル`・`Pull Request`の行の意味は、次のとおりです。

| 表示 | 意味 |
| --- | --- |
| イメージ | 所見の元になった稼働イメージ |
| サービス | イメージ名で見出しを作れない場合に、対象のワークロードキーから取り出した名前 |
| 修正するファイル | 対応付けたリポジトリと変更対象のファイル |
| Pull Request | PRへのリンクと、今回作成・オープン中・マージ済み・未マージでクローズの状態 |

「サービス」に表示する名前は、実行環境によって異なります。
次は、名前の取得元と表示例です。

| 実行環境 | 名前の取得元 | 表示例 |
| --- | --- | --- |
| Compose | `compose/<project>/<service>`の`<service>` | `サービス: web` |
| Compose外のコンテナ | `container/<name>`の`<name>` | `サービス: api` |

`更新`・`更新候補`・`新しい系列`・`再pull`・`再ビルド`の行は、PRとの関係を次のように読み分けます。

| 表示 | 意味 | PRとの関係 |
| --- | --- | --- |
| 更新 | PRが提案するイメージタグやパッケージの変更 | 表示されたPRに含まれる変更 |
| 更新候補 | 提案されたイメージタグやパッケージの変更 | PR作成済みとは限らない候補 |
| 新しい系列 | minorやmajorが異なる版で所見の全部または一部が解消し、新しい所見が増えない結果 | 更新PRを作らない案内 |
| 再pull | 同じタグの新しい内容への更新を比較結果が支持している結果 | タグ更新PRを作らない案内 |
| 再ビルド | 依存の版指定による解消見込み、またはベースを再取得してビルドする案内 | 再ビルド自体を実行するPRではない案内 |

イメージの「更新候補」にPRが無い理由は、脆弱性の通知のカードの[`対応:`行](slack-package-display.md#action-same-series)で確認できます。

「新しい系列」の行の読み方は[新しい系列の行](#newer-series-lines)を参照してください。

`要判断`・`保留`・`比較不能`・`失敗`の行では、行に続く理由を確認します。

| 表示 | 意味 | 最初の確認先 |
| --- | --- | --- |
| 要判断 | ソース、版の条件、更新方法、比較結果などについて手動対応が必要 | 表示された理由と[更新を実行できない場合の確認](remediation-troubleshooting.md#check-update-failure) |
| 保留 | 上限、待機時間、取得の問題などで後のサイクルへ回した扱い（`deferred`） | 表示された上限、待機日時、取得の問題 |
| 比較不能 | 比較に必要な情報や条件がそろわなかった結果 | [スキャンの比較条件](remediation-logic.md#comparison-conditions) |
| 失敗 | スキャン、取得、更新などの処理に失敗した結果 | [診断情報の取得](remediation-troubleshooting.md#collect-diagnostics) |

「要判断」には、新しい系列で所見が解消しても、新しい所見やCISA KEV掲載の所見が増える場合を含みます。

CISA KEVは、実際の悪用が確認された脆弱性の一覧です。
所見の総数だけでは悪用が確認された脆弱性を含むか分からないため、KEV掲載の所見も別に確認します。

`⚠️`で始まる行は、変更の大きさやPRへの書き込み停止を知らせます。

| 表示 | 意味 |
| --- | --- |
| ⚠️ メジャーバージョンの変更 | majorが変わる更新、または0.xでminorが変わる更新 |
| ⚠️ Pull Requestの作成を停止中 | 記録やGitHub上の状態などの問題によるPRへの書き込み停止 |

Kubernetesの通知で変わる点は[Kubernetesの表示](#kubernetes-display)を参照してください。

#### 新しい系列の行 {#newer-series-lines}

新しい系列の確認は、固定タグで同じ系列の新しい版では所見が解消しないときに、新しいminor・majorの版を調べる処理です。

確認結果に応じて、次の行を1つ表示するか、行を出しません。
状態値は、Webhookなどの`newer_series.status`で確認できます。

| 確認の結果 | 状態値 | 出す行 |
| --- | --- | --- |
| 全部解消し、新しい所見が増えない | `resolves` | 新しい系列 |
| 一部解消し、新しい所見が増えない | `resolves_partially` | 新しい系列 |
| ベースの比較で全部解消し、新しい所見が増えない | `resolves` | 新しい系列 |
| 解消する所見があるが、新しい所見やKEV掲載の所見が増える | `resolves_with_new` | 要判断 |
| 解消した対象がない | `not_resolving` | 行を出さない |
| 確認や判定ができない | `not_checked` | 行を出さない |
| 条件に合う新しい系列がない | `no_newer_series` | 行を出さない |

表示例は、表の上から4つの結果と同じ順に並べています。

```text
新しい系列: nginx 1.24.1 → 1.27.3 (minor の更新、所見1件が解消、互換性は未確認)
新しい系列: nginx 1.24.1 → 1.27.3 (minor の更新、所見2件中1件が解消、互換性は未確認)
新しい系列: ベースイメージ python 3.11.9-slim → 3.13.1-slim (minor の更新、所見2件が解消、ベースの比較、再ビルド後は未確認、互換性は未確認)
要判断: 新しい系列の nginx 1.24.1 → 2.0.1 で所見1件が解消、新たな所見2件 (major の更新、互換性は未確認)
```

新しい系列の行が変わると、修正計画メッセージは変化として送られます。
確認範囲と候補の選び方は[新しい系列の確認](remediation-image-logic.md#newer-series-check)、値の定義は[新しい系列の状態値](remediation-reason-codes.md#newer-series-status-values)を参照してください。

### Kubernetesの表示 {#kubernetes-display}

Kubernetesの通知は、共通の行（[表示項目](#slack-fields)）に加えて、次の点が変わります。

| 違い | 内容 |
| --- | --- |
| 「サービス」の名前 | ワークロードキー全体を表示する（例：`サービス: deployment/shop/web/app`） |
| `pullポリシー`の行 | 再pull対象のイメージ取得方針と、ワークロードごとの再取得方法を表示する |
| `管理元(目印による推定)`の行 | Kubernetesリソースのラベルやアノテーションから推定した管理関係を表示する |

「サービス」の例はDeploymentのコンテナを指し、KubernetesのServiceリソース名ではありません。

次は、イメージタグの更新と再pullを提案する通知の例です。

```text
🔧 修正計画
Pull Request: 作成 1件

イメージ: docker.io/library/nginx:1.25.3
修正するファイル: ex/deploy の apps/web.yaml
Pull Request: #4 (今回作成)
更新: docker.io/library/nginx 1.25.3 → 1.25.5
管理元(目印による推定): deployment shop/web → Argo CDアプリ web-app

イメージ: ghcr.io/example/api:latest
再pull: 所見2件が解消
pullポリシー: Always: Podを再起動すると新しい中身を取得する (deployment/shop/api/app)
管理元(目印による推定): deployment shop/api → Helmリリース api (shop)
```

再取得方法と管理関係は、次のように読み分けます。

| 行 | この例で分かること |
| --- | --- |
| `pullポリシー: Always: …`の行 | `deployment/shop/api/app`の取得方針は`Always`で、Podを再起動すれば新しい内容を取得する |
| 1つ目の`管理元(目印による推定)`の行 | Deployment `shop/web`は、Argo CDアプリ`web-app`の管理下にあると推定された |
| 2つ目の`管理元(目印による推定)`の行 | Deployment `shop/api`は、namespace `shop`のHelmリリース`api`の管理下にあると推定された |

pullポリシーごとの再取得方法は[Kubernetesのイメージ名と再取得](remediation-kubernetes-logic.md#kubernetes-image-references)を参照してください。
管理元の推定に使うラベルとアノテーションは[管理元の推定](remediation-kubernetes-logic.md#management-markers)を参照してください。

### 件数の読み方 {#reading-counts}

冒頭の件数の行は、通知にPR番号があるかどうかで数え方が変わります。

| 通知の内容 | 冒頭の行の例 | 1件と数える単位 |
| --- | --- | --- |
| PR番号がある | `Pull Request: 作成 1件 · オープン中 1件` | 1つのPRにまとめる更新を、処理の状態ごとに1件 |
| PR番号がない | `更新候補 1件 · 要判断 1件` | 変更対象のファイルや再pull対象ごとのまとまり（項目）を、結果の種類ごとに1件 |

件数を読む際は、次の点に注意してください。

- 1つの依存ファイルの複数パッケージをまとめて更新しても、パッケージごとには数えない
- 1つのPRにまとめた更新が複数のイメージに関係しても、イメージの数だけ件数が増えるわけではない
- PR番号がある通知では、まだPRがない更新も「要判断」「延期」「停止・失敗」として数えるため、実在するPRの数と一致するとは限らない
- PR番号がある通知では、PRを作らない`再pull`・`再ビルド`・`新しい系列`の案内は冒頭の件数に入らない
- PR番号がない通知では、「要判断」「保留」「失敗」の理由に添えて表示する「更新候補」の行は、別の1件として数えない

新しい系列や所見に関する件数は、次のように読み分けます。

| 件数の表示 | 数える対象 |
| --- | --- |
| `新しい系列で解消 …件` | `resolves`・`resolves_partially`の項目数 |
| `所見…件が解消` | 比較で検出されなくなった対象の所見数 |
| `KEV …件` | 表示対象に含まれるCISA KEV掲載の脆弱性に関する件数 |

PR未作成の状態は、本文では次の表示になります。

| 冒頭の集計 | 本文の表示 |
| --- | --- |
| 要判断 | 要判断 |
| 延期 | 保留 |
| 停止・失敗 | 失敗 |

[表示例](#slack-example)の内訳は、PR #12の「作成」1件とPR #13の「オープン中」1件です。
PR #12に含まれなかった`package-b`を、冒頭のPR集計で別の1件には数えません。

次は、同じファイルで`package-a`を更新でき、`package-b`に手動対応が必要な場合の例です。
ほかの項目がない通知で、PRの有無による集計の違いを示します。

| 状態 | 冒頭の集計 | `package-b`の扱い |
| --- | --- | --- |
| PRがなく、`package-a`が更新候補 | `更新候補 1件 · 要判断 1件` | 同じ項目の要判断として1件 |
| `package-a`だけを含むPRを今回作成 | `Pull Request: 作成 1件` | 本文に要判断として残り、PR集計には別に加えない |

PR処理の件数は、脆弱性の数とも一致しません。
同じ項目に「要判断」のパッケージが複数あっても、「要判断」はパッケージごとの件数にはなりません。

イメージ候補の解消件数では、CVE ID・パッケージ名・パッケージの種類・分類が同じ所見を1件にまとめます。
同じCVEが複数の版や場所で検出されても、場所の数をそのまま件数にはしません。

要判断に並ぶパッケージには、次の表示規則があります。

- PRに含まれなかったパッケージには対応が残るが、理由をほかのパッケージの行で示す場合は個別の行を省く
- 更新を試す前に手動対応が必要と判断したパッケージも、同じファイルの候補やPRとは別に理由を表示する

次は、`A`と`B`をまとめて更新しようとして、`A`を更新できなかったために`B`もPRの更新対象から外れた例です。
`B`自身には更新を妨げる理由がない場合、通知は次のように理由をまとめます。

| パッケージ | 通知での表示 |
| --- | --- |
| 更新できなかった`A` | 要判断の行に、更新できなかった理由を表示 |
| `A`の更新失敗の影響で外れた`B` | `A`の行で理由が分かるため、個別の行を省略 |

更新目標があるパッケージは、パッケージごとの行で表示します。
目標がないパッケージは理由ごとにまとめ、その下に一覧を表示します。

### 省略された情報の確認先 {#omitted-details}

Slackでは、長いパッケージ一覧などを「ほか…件」として省略することがあります。
省略された内容の確認先は[詳細な結果の確認先](#detailed-results)を参照してください。

## 詳細な結果の確認先 {#detailed-results}

詳細な結果は、受け取ったWebhookの通知データと、KestreLynxが保存した`plan.json`・`prs.json`で確認できます。
通知とファイルでは、含まれる情報と記録時点が異なります。

Webhookを利用していない場合も、実際に提案された変更はPRの差分、計画時点のソースや検査結果は`plan.json`、PR処理の記録は`prs.json`で確認できます。
取得や実行に失敗した際の詳細は[診断情報の取得](remediation-troubleshooting.md#collect-diagnostics)を参照してください。

理由の定義は[理由コード](remediation-reason-codes.md#reason-codes)、対応の進め方は[候補やPRが出ない場合](remediation-troubleshooting.md)を参照してください。

### Webhookの確認先 {#webhook-details}

実際のデータはWebhookを受け取るプログラムで確認し、フィールドの意味を次のリンクで調べてください。

| 確認したい内容 | フィールド仕様 |
| --- | --- |
| 計画の状態、比較条件、処理上限と使用量 | [修正計画の共通フィールド](webhook-remediation-reference.md#remediation-fields) |
| 配布イメージの候補と比較結果 | [配布イメージのフィールド](webhook-remediation-image-reference.md#remediation-image-fields) |
| ベースイメージの候補とレイヤーの確認結果 | [ベースイメージのフィールド](webhook-remediation-dockerfile-reference.md#remediation-dockerfile-fields) |
| パッケージごとの版・処理・除外理由、実行環境、ツール、更新検査 | [言語パッケージのフィールド](webhook-remediation-language-reference.md#remediation-language-fields) |
| PRの状態と、PRに含まれず対応が残るパッケージ | [PR処理のフィールド](webhook-remediation-pr-reference.md#remediation-pr-fields) |
| PRの作成・照合などの操作結果 | [PR操作イベントのフィールド](webhook-remediation-pr-reference.md#remediation-operation-fields) |
| PRへの書き込みを止めた問題 | [書き込み停止のフィールド](webhook-remediation-pr-reference.md#remediation-problem-fields) |
| 部分PRを含む通知データの例 | [部分PRの例](webhook-remediation-pr-reference.md#remediation-json-example) |

### 保存ファイルの確認先 {#saved-details}

`plan.json`は計画時点の情報、`prs.json`は継続して管理するPR処理の記録です。
保存場所は`remediation.storage_dir`の下で、既定値は`/var/lib/kestrelynx/remediation`です。

実際の保存先は、KestreLynxが使用する設定の[基本設定](configuration.md#remediation-basics)を確認してください。
そのディレクトリの`plan.json`・`prs.json`を、次の記録時点に注意して確認します。

1. 計画を作り、依存更新を処理した後、PR処理前の情報を`plan.json`に保存する
2. PRの処理や照合、操作結果を`prs.json`に記録する
3. PR処理後の修正計画の結果を通知する

`plan.json`には、その回のPR作成の有効・無効を表す`pull_requests_enabled`を保存します。
PR処理後の`pr_items`と`pull_requests`は保存せず、PR処理後の結果を含めた再保存もしません。

最新の修正計画のPR処理結果は通知で確認し、継続して管理するPRの情報は`prs.json`で確認してください。

保存内容と記録時点は[保存ファイル](remediation-pr-logic.md#stored-records)、調査時に集める情報は[診断情報の取得](remediation-troubleshooting.md#collect-diagnostics)を参照してください。
