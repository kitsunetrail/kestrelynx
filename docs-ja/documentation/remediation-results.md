---
title: 修正計画の通知の読み方
---

# 修正計画の通知の読み方

このページでは、Slackに届いた修正計画の各行と件数、PRに含まれる更新と対応が残るパッケージを読み分けます。
版の読み分けや「再pull」「再ビルド」の案内は[更新結果の解釈](remediation-update-results.md#interpreting-updates)を参照してください。

候補の提示やPRのマージは、稼働中のコンテナで脆弱性が解消したことを意味しません。
PR本文は[修正PRの内容とマージ前の確認](remediation-pr-results.md)、更新できない理由の案内は[案内の概要](remediation-fix-hints.md#fix-hints)を参照してください。

このページで使う用語は[用語](remediation.md#terms)を参照してください。

## Slackの修正計画 {#reading-results-in-slack-and-webhooks}

Slackの修正計画は、対象のイメージやファイルごとに、提案された変更とPRの状態、進められなかった理由を示します。

### 表示例 {#slack-example}

次は、パッケージ更新とベースイメージ更新を提案する架空の例です。
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

「原因は確かめられなかった」は、更新を妨げる原因まで特定できなかったという意味です。
確認の進め方は[案内の概要](remediation-fix-hints.md#fix-hints)を参照してください。

### 表示項目 {#slack-fields}

各行の見出しは、対象、提案、進められなかったこと、警告を区別します。

対象を示す行は、次のとおりです。

| 表示 | 意味 |
| --- | --- |
| イメージ | 所見の元になった稼働イメージ |
| サービス | イメージ名で見出しを作れない場合に、対象のワークロードキーから取り出した名前 |
| 修正するファイル | 対応付けたリポジトリと変更対象のファイル |
| Pull Request | PRへのリンクと、今回作成・オープン中・マージ済み・未マージでクローズの状態 |

「サービス」に表示する名前は、実行環境によって異なります。
次は、名前の取得元と架空の表示例です。

| 実行環境 | 名前の取得元 | 表示例 |
| --- | --- | --- |
| Compose | `compose/<project>/<service>`の`<service>` | `サービス: web` |
| Compose外のコンテナ | `container/<name>`の`<name>` | `サービス: api` |
| Kubernetes | ワークロードキー全体 | `サービス: deployment/shop/web/app` |

Kubernetesの例はDeploymentのコンテナを指し、KubernetesのServiceリソース名ではありません。
提案を示す行は、PRとの関係を次のように読み分けます。

| 表示 | 意味 | PRとの関係 |
| --- | --- | --- |
| 更新 | PRが提案するイメージタグやパッケージの変更 | 表示されたPRに含まれる変更 |
| 更新候補 | 提案されたイメージタグやパッケージの変更 | PR作成済みとは限らない候補 |
| 新しい系列 | minorやmajorが異なる版で所見の全部または一部が解消し、新しい所見が増えない結果 | 更新PRを作らない案内 |
| 再pull | 同じタグの新しい内容への更新を比較結果が支持している結果 | タグ更新PRを作らない案内 |
| 再ビルド | 依存の版指定による解消見込み、またはベースを再取得してビルドする案内 | 再ビルド自体を実行するPRではない案内 |

同じ系列の更新は`1.27.2-alpine`から`1.27.3-alpine`、新しい系列の更新は`1.24.1`から`1.27.3`などです。
通知の読み方は[新しい系列の行](#newer-series-lines)を参照してください。

進められなかったことを示す行では、行に続く理由を確認します。

| 表示 | 意味 | 最初の確認先 |
| --- | --- | --- |
| 要判断 | ソース、版の条件、更新方法、比較結果などについて手動対応が必要 | 表示された理由と[更新を実行できない場合の確認](remediation-troubleshooting.md#check-update-failure) |
| 保留 | 上限、待機時間、取得の問題などで後のサイクルへ回した扱い（`deferred`） | 表示された上限、待機日時、取得の問題 |
| 比較不能 | 比較に必要な情報や条件がそろわなかった結果 | [スキャンの比較条件](remediation-logic.md#comparison-conditions) |
| 失敗 | スキャン、取得、更新などの処理に失敗した結果 | [診断情報の取得](remediation-troubleshooting.md#collect-diagnostics) |

「要判断」には、新しい系列で所見が解消しても、新しい所見やCISA KEV掲載の所見が増える場合を含みます。

CISA KEVは、実際の悪用が確認された脆弱性の一覧です。
所見の総数だけでは悪用が確認された脆弱性を含むか分からないため、KEV掲載の所見も別に確認します。

警告は、変更の大きさやPRへの書き込み停止を知らせます。

| 表示 | 意味 |
| --- | --- |
| ⚠️ メジャーバージョンの変更 | majorが変わる更新、または0.xでminorが変わる更新 |
| ⚠️ Pull Requestの作成を停止中 | 記録やGitHub上の状態などの問題によるPRへの書き込み停止 |

Kubernetesでは、再取得の方法や管理元も表示します。

| 表示 | 意味 |
| --- | --- |
| pullポリシー | 再pull対象のイメージ取得方針と、ワークロードごとの再取得方法 |
| `管理元(目印による推定)` | Kubernetesリソースのラベルやアノテーションから推定した管理関係 |
| 修正するファイル・Pull Request | マニフェスト・Kustomize・Helmのvaluesのタグ更新先とPRへのリンク |

管理元を推定できる場合は、マニフェスト・Kustomize・Helmのvalues・DockerfileのPRにも管理関係を表示します。
推定に使う情報には、次のものがあります。

- Helmでは、`app.kubernetes.io/managed-by: Helm`ラベルと、`meta.helm.sh/release-name`・`meta.helm.sh/release-namespace`アノテーション
- Argo CDでは、そのリソース自身を指す`argocd.argoproj.io/tracking-id`アノテーション
- Fluxでは、`kustomize.toolkit.fluxcd.io/`または`helm.toolkit.fluxcd.io/`の`name`・`namespace`ラベル

次は、DeploymentとArgo CDアプリの関係を示す架空の例です。

```text
管理元(目印による推定): deployment shop/web → Argo CDアプリ web-app
```

`shop/web`というDeploymentの管理元として`web-app`が示されています。
ラベルやアノテーションからの推定であり、実際の管理関係を確認済みという意味ではありません。

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

新しい系列の行は案内であり、その版へ更新するPRは作りません。

新しい系列の行が変わると、修正計画メッセージは変化として送られます。
確認範囲と候補の選び方は[新しい系列の確認](remediation-image-logic.md#newer-series-check)、値の定義は[新しい系列の状態値](remediation-reason-codes.md#newer-series-status-values)を参照してください。

### 件数の読み方 {#reading-counts}

冒頭の件数は、通知内にPR番号があればPR処理の状態別、なければ提案の種類別に集計します。
どちらも、パッケージやファイルの数をそのまま数えるものではありません。

提案の種類別集計では、変更対象のファイルや再pull対象ごとのまとまりを「項目」として数えます。
PR処理の集計では、1つのPRで提案する変更を1件とし、PRがまだない変更も処理状態に応じて数えます。

同じ依存ファイルの複数パッケージをまとめて更新する場合は、パッケージごとには数えません。
同じPRにまとめた更新が複数イメージに関係していても、イメージ数だけ件数が増えるわけではありません。

集計ごとに、数える対象が異なります。

| 集計 | 数える対象 |
| --- | --- |
| `Pull Request: 作成 …件 · オープン中 …件`など | 1つのPRにまとめる更新ごとの処理状態 |
| `更新候補 …件 · 要判断 …件`など | 項目ごとの表示の種類 |
| `新しい系列で解消 …件` | `resolves`・`resolves_partially`の項目数 |
| `所見…件が解消` | 比較で検出されなくなった対象の所見数 |
| `KEV …件` | 表示対象に含まれるCISA KEV掲載の脆弱性に関する件数 |

PR番号がある結果を含む場合、冒頭はPR処理の状態別集計になります。
まだPRがない更新の「要判断」「延期」「停止・失敗」も含むため、実在するPR数だけの集計ではありません。

PR未作成の状態は、本文では次の表示になります。

| 冒頭の集計 | 本文の表示 |
| --- | --- |
| 要判断 | 要判断 |
| 延期 | 保留 |
| 停止・失敗 | 失敗 |

[表示例](#slack-example)の内訳は、PR #12の「作成」1件とPR #13の「オープン中」1件です。
PR #12に含まれなかった`package-b`を、冒頭のPR集計で別の1件には数えません。

次は、同じファイルで`package-a`を更新でき、`package-b`に手動対応が必要な場合の架空の例です。
ほかの項目がない通知で、PRの有無による集計の違いを示します。

| 状態 | 冒頭の集計 | `package-b`の扱い |
| --- | --- | --- |
| PRがなく、`package-a`が更新候補 | `更新候補 1件 · 要判断 1件` | 同じ項目の要判断として1件 |
| `package-a`だけを含むPRを今回作成 | `Pull Request: 作成 1件` | 本文に要判断として残り、PR集計には別に加えない |

件数には、次の規則があります。

- PR処理の件数は、更新するパッケージ数や脆弱性数とは異なる
- 提案の種類別集計では、同じ項目に候補と要判断があれば、それぞれ1件と数える
- 同じ項目に要判断のパッケージが複数あっても、要判断はパッケージごとの件数にはならない
- 「新しい系列で解消」は、解消した所見数やPR数ではない

イメージ候補の解消件数では、CVE ID・パッケージ名・パッケージの種類・分類が同じ検出結果を1件にまとめます。
同じCVEが複数の版や場所で検出されても、場所の数をそのまま件数にはしません。

要判断に並ぶパッケージには、次の表示規則があります。

- PRに含まれなかったパッケージには対応が残るが、理由をほかのパッケージの行で示す場合は個別の行を省く
- 更新を試す前に手動対応が必要と判断したパッケージも、同じファイルの候補やPRとは別に理由を表示する

次は、`A`と`B`をまとめて更新しようとして、`A`を更新できなかったために`B`もPRの更新対象から外れた架空の例です。
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

Webhookのフィールド仕様は、Webhookを受け取っている場合に、受け取った通知データを読むための資料です。
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

`plan.json`は、PR処理後の結果を含めて再保存しません。
最新の修正計画のPR処理結果は通知で確認し、継続して管理するPRの情報は`prs.json`で確認してください。

保存内容と記録時点は[保存ファイル](remediation-pr-logic.md#stored-records)、調査時に集める情報は[診断情報の取得](remediation-troubleshooting.md#collect-diagnostics)を参照してください。
