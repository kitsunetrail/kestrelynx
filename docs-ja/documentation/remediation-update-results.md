---
title: 更新結果と再取得・再ビルドの案内の読み方
---

# 更新結果と再取得・再ビルドの案内の読み方

Slackの修正計画のうち、版の表示と「再pull」「再ビルド」の案内の読み方を説明します。
各行のラベルと件数は[修正計画の通知の読み方](remediation-results.md)、用語は[用語](index.md#terms)を参照してください。

## 更新結果の解釈 {#interpreting-updates}

「更新」「更新候補」「要判断」の行のうち、パッケージの版に関する表示を説明します。

### `→`の右に出る版 {#target-and-adopted-version}

KestreLynxがPRの作成を確認できた更新は「更新」、確認できていない更新は「更新候補」と表示されます。
`→`の右の版の意味も、表示によって違います。

次は、PRが作成された例です。

```text
Pull Request: #12 (今回作成)
更新: package-a 1.2.3 → 1.2.4
```

次は、PRの作成数の上限に達し、PRを作成できなかった例です。

```text
更新候補: package-b 2.1.1 → 2.3.0
保留: 1回の実行で作れる Pull Request の数の上限に達した
```

表示とPRの関係、版の意味、利用者が行う操作は、次のとおりです。

| 表示 | PR | `→`の右の版 | すること |
| --- | --- | --- | --- |
| `更新` | 作成済み | 採用版（更新後の依存ファイルで確認した版） | PRを確認してマージする（[PR本文の内容](remediation-pr-results.md#pr-body-and-checks)） |
| `更新候補`（`remediation.pull_requests.enabled`が`false`） | 作成しない | 更新目標（更新先を選ぶときの下限の版）で、更新はまだ実行していない | PRを作成させるには`remediation.pull_requests.enabled`を`true`に変える |
| `更新候補`（`remediation.pull_requests.enabled`が`true`） | 作成を確認できていない | 採用版（更新後の依存ファイルで確認した版） | すぐ下の行、または通知の警告に示された理由に[対処する](remediation-troubleshooting.md#check-missing-pr) |

理由が「GitHub への書き込みの結果が分からない」の場合は、GitHub側でPRが作成されていることがあり、次のサイクルでGitHubを読み直して確認した結果が表示されます。

版の決め方は[修正版の下限](remediation-package-logic.md#fix-lower-bound)、Webhookのフィールドは[パッケージの結果](webhook-remediation-language-reference.md#language-package-fields)を参照してください。

### PRに入らなかったパッケージ {#partial-pull-requests}

検査を通った一部のパッケージの更新だけを含むPRを「部分PR」と呼びます。
PRに入らなかったパッケージは「要判断」の行に出ます。

次は、`package-a`の更新だけがPRに入り、`package-b`は修正版に上がらなかった例です。

```text
Pull Request: #12 (今回作成)
更新: package-a 1.2.3 → 1.2.4
要判断: package-b 2.1.1 を修正版の 2.3.0 に上げられない（原因は確かめられなかった）
```

PRに含まれる更新と、含まれないパッケージの扱いは、次のとおりです。

| 表示 | 意味 | すること |
| --- | --- | --- |
| `更新` | PRに含まれる更新 | PRを確認してマージする（[PR本文の内容](remediation-pr-results.md#pr-body-and-checks)） |
| `要判断: … は…ため除外` | PRの更新から外したパッケージ | [表示された理由に合う対処](remediation-troubleshooting.md#check-update-failure)を行う |
| `要判断: … に上げられない（依存元の … が … の版を制限）`など、括弧内に原因を示す行 | 修正版に上がらなかった原因が分かっているパッケージ | [修正版に上げられないときの案内](remediation-fix-hints.md#fix-hints)に従う |
| `要判断: … に上げられない（原因は確かめられなかった）` | 修正版に上がらず、KestreLynxが原因を特定できなかったパッケージ | — |

PRをマージしても、「要判断」のパッケージの所見は残ります。
「除外」は、イメージからパッケージを削除したという意味ではありません。

「原因は確かめられなかった」の行には案内が付かず、対象パッケージの版を決めている依存は利用者がパッケージマネージャーで調べる必要があります。

成立条件は[部分PRの成立条件](remediation-package-logic.md#partial-pr-selection)を参照してください。

### 依存元もあわせて更新した結果 {#dependent-reresolution-results}

あるパッケージを修正版に上げるために、そのパッケージを使っているパッケージ（依存元）もあわせて更新することがあります。
結果は、次のように表示されます。

```text
更新: minimist 0.0.8 → 1.2.8（mkdirp 0.5.1 → 0.5.6 も更新）
```

依存元の更新結果と利用者が行う操作は、次のとおりです。

| 表示 | 意味 | すること |
| --- | --- | --- |
| `（… も更新）` | 対象を修正版に上げるために依存元も更新した | PRで依存元の変更も確認してマージする |
| `依存元の … が … の版を制限`・`今回の再解決では修正版に届かなかった` | 依存元を更新しても修正版に上がらなかった | [依存元が原因の場合](remediation-fix-hints.md#fix-hints-dependents)の案内に従う |
| `…ため採用しない` | 依存元の更新を、検査に通らないなどの理由で採用しなかった | [依存元が原因の場合](remediation-fix-hints.md#fix-hints-dependents)の案内に従う |
| `… の更新を試していない` | 扱える範囲や上限を超えるため、依存元の更新を見送った | — |
| `… 以降に再試行する` | 入る版の公開から72時間たっていない | 表示された日時以降のサイクルを待つ |

見送りの理由は[対応範囲と上限](remediation-reresolution-logic.md#dependent-reresolution-limits)を参照してください。

仕組みは[依存元からの再解決](remediation-reresolution-logic.md#dependent-reresolution)、行を出す条件は[通知に出す行](remediation-reresolution-logic.md#dependent-reresolution-notification)を参照してください。
PR本文の記載は[PR本文の内容](remediation-pr-results.md#pr-body-and-checks)を参照してください。

### 再pullの案内 {#repull-guidance}

「再pull」は、稼働イメージと同じタグが指す内容が新しくなり、取得し直すと所見が減ることを示します。
タグは変わらないのでPRは作りません。

次は、KubernetesでPodの再起動を案内する表示例です。

```text
再pull: 所見2件が解消
pullポリシー: Always: Podを再起動すると新しい中身を取得する (deployment/shop/api/app)
```

利用環境とpullポリシーに応じて、次の操作を行ってください。

| 環境 | すること |
| --- | --- |
| Compose・`docker run` | 稼働イメージと同じタグのイメージを取得し直し、コンテナを作り直す |
| Kubernetes（`pullポリシー`が`Always`） | Podを再起動する |
| Kubernetes（`IfNotPresent`） | イメージの指定を固定タグかdigestに変える |
| Kubernetes（`Never`） | 新しいイメージをノードへ取り込む |

「解消」は比較の結果で、稼働中のコンテナが新しい内容に置き換わったことは示しません。

pullポリシーごとの案内は[Kubernetesのイメージ名と再取得](remediation-kubernetes-logic.md#kubernetes-image-references)を参照してください。

### 再ビルドの案内 {#rebuild-guidance}

「再ビルド」の行はイメージの作り直しを案内し、所見が減る見込みを確認できていない場合にも出ます。

表示ごとの意味と操作は、次のとおりです。

| 表示 | 意味 | すること |
| --- | --- | --- |
| `再ビルドで … 以上が入る見込み` | pipの依存の指定が修正版を許している | イメージを再ビルドして配置する |
| `PR #…（ベースイメージ … … → …）はマージ済みだが、稼働中のイメージはまだ … から作られている` | ベースイメージ更新のPRが稼働イメージに反映されていない | マージ後のDockerfileでイメージを作り直して配置する |
| `稼働中のイメージの先頭のレイヤーが現在の … と一致しない` | 現在のベースイメージと稼働イメージの先頭のレイヤーが一致しない | 行に示されたコマンドでベースを取り直して再ビルドし、コンテナを作り直す |
| `要判断: … 新しい Go でビルドし直すと直る` | Goの標準ライブラリの所見で、PRでは直せない | 修正版が表示されている場合は、その版以上のGoでビルドし直して配置する |

次は、浮動タグの`node:24-alpine`を使うイメージの再ビルドを案内する例です。

```text
再ビルド: 稼働中のイメージの先頭のレイヤーが現在の node:24-alpine と一致しない。ベースを取り直して再ビルドし(`docker build --pull` など)、デプロイし直す
  • 現在のベースの版を引き継げば消える見込み: package-a 1.0.0 → 1.0.1
  • 現在のベースにも残る: package-b 2.0.0
  • 現在のベースで新しく出る: package-c 3.0.0
```

再ビルドの案内に続く行や注記の意味は、次のとおりです。

| 行 | 意味 |
| --- | --- |
| `現在のベースの版を引き継げば消える見込み` | 現在のベースには対象の所見がない別の版が入っていて、作り直すと所見が消える見込み |
| `現在のベースにも残る` | 現在のベースにも対象の所見があり、作り直しても残る見込み |
| `現在のベースにない` | 現在のベースの対応する場所にパッケージがなく、作り直しで変わるかは分からない |
| `現在のベースで新しく出る` | 稼働イメージの対応する場所にはない所見が現在のベースにあり、作り直すと増える見込み |
| `現在の … の Node.js は …。この版を引き継げば` | 現在のベースの実行環境の版を引き継ぐ場合の所見の見込み |
| `(一部の所見は確認できなかった)`・`(消える所見は確認できなかった)` | 所見の一部または消える所見を確かめられなかった |

見込みは、再ビルドした後のイメージを確かめた結果ではありません。
見込みが当てはまらない場合は[見込みの制約](remediation-base-image-logic.md#rebuild-check-limits)を参照してください。

行を出す条件は[通知に出す内容](remediation-base-image-logic.md#rebuild-check-notification)、ビルド方法ごとのコマンドは[再ビルドの手順の案内](remediation-base-image-logic.md#rebuild-commands)を参照してください。
Goの修正版が表示されない場合は[標準ライブラリの再ビルド案内](remediation-go-logic.md#go-stdlib-rebuild)を参照してください。
