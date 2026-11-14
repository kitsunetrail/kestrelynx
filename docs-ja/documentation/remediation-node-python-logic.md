---
title: npm・pnpm・uv・pipの更新
---

# npm・pnpm・uv・pipの更新

KestreLynxがnpm・pnpm・uv・pipの依存ファイルをどう更新し、更新結果を何と照合するかを説明します。
使うマネージャーに応じて、次の節を参照してください。

| マネージャー | 読む節 |
| --- | --- |
| npm・pnpm | [直接依存の版指定](#direct-dependencies)、[推移的依存の更新範囲](#transitive-dependencies)、[Node.jsの選定](#node-selection)と[互換条件](#node-compatibility)、[ツールの版と取得](#node-python-tools)、[直接依存の一時的な取り除き](#pnpm-temporary-removal)（pnpmのみ）、[付随変更の検査](#change-validation) |
| uv | [直接依存の版指定](#direct-dependencies)、[推移的依存の更新範囲](#transitive-dependencies)、[uv用Pythonの選定](#uv-python-selection)、[ツールの版と取得](#node-python-tools)、[付随変更の検査](#change-validation) |
| pip | [pipの検証環境](#pip-target-environment)、[pipの固定版の更新](#pip-pinned-updates) |

このページで使う用語は[用語](remediation.md#terms)を参照してください。

## 更新する範囲 {#node-python-update-scope}

npm・pnpm・uvで、更新目標に対して依存の版指定を変更できる範囲を説明します。
更新目標を決める規則は、[修正版の下限](remediation-package-logic.md#fix-lower-bound)を参照してください。

### 直接依存の版指定 {#direct-dependencies}

npm・pnpm・uvの直接依存は、プロジェクト自身が宣言する依存です。
依存の宣言ファイル（`package.json`・`pyproject.toml`）の指定が更新目標を許さない場合は、扱える書き方に限り、演算子を保って版の部分を編集します。

既存の指定が更新目標を許す場合は、その指定を維持します。
編集が必要でも書き方や記載箇所を扱えない場合は、手動対応（`manual`、Slackでは「要判断」）にします。

次の架空の例では、`package.json`の依存の更新目標を`1.2.6`とし、演算子と版の変化を比べます。

| 更新前の指定 | 更新後の指定 | 判断 |
| --- | --- | --- |
| `~1.0.0` | `~1.2.6` | 更新目標を許さないため、`~`を保って編集 |
| `^1.2.5` | `^1.2.5` | 更新目標を許すため、指定を維持 |

更新後は、宣言ファイルとlockfileに記録された指定の一致と、採用版が指定範囲内にあることを確かめます。

編集できる書き方と記載箇所は、[npmの依存ファイル](remediation-dependency-formats.md#npm-inputs)・[pnpmの依存ファイル](remediation-dependency-formats.md#pnpm-inputs)・[uvの依存ファイル](remediation-dependency-formats.md#uv-inputs)を参照してください。

### 推移的依存の更新範囲 {#transitive-dependencies}

npm・pnpm・uvの推移的依存は、ほかのパッケージを通じて使う依存であり、親パッケージが宣言する範囲内で更新します。
更新後の版は、公開レジストリが返す親パッケージの宣言と照合します。

通常の更新には、次の制限と検査があります。

- 修正版を入れるために、更新対象ではない親パッケージの版を上げない
- 修正版を強制するための`overrides`を追加しない
- 更新対象や付随する依存の変更で、依存元・依存先の版の条件が破られていないことを確認する

[マネージャー別の更新処理](remediation-package-logic.md#manager-update-methods)で更新目標に届かなければ、条件を満たす対象に[依存元からの再解決](remediation-reresolution-logic.md#dependent-reresolution)を試します。
その後に残った対象を踏まえて、[部分PRの成立条件](remediation-package-logic.md#partial-pr-selection)を判断します。

## 実行環境の選定 {#node-python-runtimes}

npm・pnpm・uv・pipで依存ファイルの更新に使うNode.js・Pythonと、依存の互換性を確かめる環境を選びます。

### Node.jsの選定 {#node-selection}

npm・pnpmでは、依存ファイルの更新を実行するためのNode.jsを、プロジェクトの版宣言とマネージャーの条件から選びます。
アプリケーションが使うNode.jsの版を変更する処理ではありません。

実行版は、KestreLynxに組み込まれた対応版の一覧から選びます。
一覧はKestreLynxの更新に伴って変わり、[対応する実行環境](remediation-reference.md#supported-runtimes)で確認できます。

版ファイルは`.nvmrc`・`.node-version`、範囲指定は`package.json`の`engines.node`と、Node.jsを指定する`devEngines.runtime`・`engines.runtime`です。
Node.jsの系列は`22`のようなmajor版の単位であり、宣言に応じて次の規則で選びます。

| 宣言の状態 | 選定規則 |
| --- | --- |
| 版ファイルがある | 指定されたmajor系列を使い、minor・patch版は対応版の一覧から選ぶ |
| 範囲指定だけがある | すべての範囲とマネージャーの条件を満たす、サポート中の最も古い系列を選ぶ |
| 宣言がない | その時点でLTSに入っている最新系列を優先し、ほかの系列は新しい順に適合する組み合わせを調べる |
| 版ファイルと範囲指定がある | 宣言同士の整合と、指定系列の実行版がすべての範囲を満たすことを確認する |

選定と更新の実行には、次の制限があります。

- サポート期限を過ぎた系列は、更新の実行に使わない
- 宣言が矛盾する場合や、条件を満たす実行版がない場合は、手動対応にする
- 選定後に更新が失敗しても、別のNode.js系列へ切り替えて更新を繰り返さない

読み取る宣言と書き方は、[Node.jsの版宣言](remediation-dependency-formats.md#node-declarations)を参照してください。

### Node.jsの互換条件 {#node-compatibility}

Node.jsとnpm・pnpmは、次の互換条件を満たす組み合わせだけを使用します。

- マネージャーの版が、プロジェクトの宣言した版や範囲を満たす
- マネージャー自身の`engines.node`が、作業用Node.jsを許す
- ツール取得時にも、取得したメタデータのNode.js要件を満たす

プロジェクトの最低Node.js版は、`.nvmrc`・`.node-version`と、`package.json`の`engines.node`・`devEngines.runtime`・`engines.runtime`の宣言をすべて満たす最も低い版です。
最低版が作業用Node.jsと異なる場合は、追加・変更した依存の`engines.node`を最低版とも照合します。

最低版を許さない依存や、要件を解釈できない依存があれば、手動対応にします。
Node.jsの宣言がない場合は、照合に使う最低版を設定しません。

例えば、`.nvmrc`が`22`、`engines.node`が`>=22.12`なら、最低版は`22.12.0`です。
作業用Node.jsが`22.23.5`の場合も、追加・変更した依存の要件は次のように最低版で判定します。

| 依存の`engines.node` | 最低版との照合結果 |
| --- | --- |
| `>=22.12` | `22.12.0`を許すため、互換条件を満たす |
| `>=22.13` | `22.12.0`を許さないため、手動対応にする |

版の宣言同士を照合する検査であり、最低Node.js版でアプリケーションを実行するテストではありません。

### uv用Pythonの選定 {#uv-python-selection}

uvでは、`requires-python`と版ファイルから、lockfileの生成に使うPythonを選びます。
Pythonの系列は`3.13`のようなX.Yの単位であり、次の規則で選びます。

| 宣言の状態 | 選定規則 |
| --- | --- |
| `requires-python`だけがある | 実行版が範囲を満たす、サポート中の最も古い系列を選ぶ |
| 版ファイルと`requires-python`がある | 版ファイルのX.Y系列を選び、宣言同士の整合と実行版の適合を確認する |
| `requires-python`がない | 版ファイルの有無にかかわらず、手動対応にする |

実際に使う版には、次の条件があります。

- 版ファイルのpatch版と作業用イメージのpatch版が異なることは許す
- 対応版の一覧にある実際のPython版が、`requires-python`を満たす必要がある
- 条件を満たすサポート中の系列がなくても、宣言を緩めて実行しない

読み取る書き方は、[Pythonの版宣言](remediation-dependency-formats.md#python-declarations)を参照してください。

### pipの検証環境 {#pip-target-environment}

pipを動かす作業用Pythonと、依存解決の検証対象は別に決めます。
作業には対応版の一覧の既定のPythonを使い、検証対象には稼働イメージから判断したPython X.Y・platform・ABIを指定します。

同じリポジトリ・ブランチ・依存ディレクトリの`requirements.txt`は、複数の稼働イメージで共有される場合があります。
KestreLynxは、更新対象パッケージを検出した各イメージのPython X.Y・platform・ABIが一致することを確認します。

次の架空の例では、同じ`requirements.txt`の更新対象パッケージが、二つの稼働イメージから検出されています。

| 検出元の稼働イメージ | Python | platform | ABI |
| --- | --- | --- | --- |
| イメージA | `3.12` | Debian・`linux/amd64` | `cp312` |
| イメージB | `3.11` | Debian・`linux/amd64` | `cp311` |

Python版とABIが一致しないため、その`requirements.txt`の更新全体を手動対応にします。

検証環境を決める条件は次のとおりです。

- Python X.Yは、スキャンで得たパッケージのパスなどから判断する
- Python版やplatformを判断できない場合は、手動対応にする
- 更新対象パッケージの検出元で検証環境が一致しない場合は、手動対応にする
- 検証対象のPythonがサポート終了なら、作業用Pythonがサポート中でも更新PRを作らない

## ツールの版と取得 {#node-python-tools}

ここでいうツールは、更新を実行するnpm・pnpm・uv自体です。
KestreLynxが取得して作業用コンテナへ渡す流れは、[作業用コンテナの実行](remediation-worker-logic.md#worker-execution)を参照してください。

### ツール版の選定 {#tool-version-selection}

npm・pnpm・uvの版は、プロジェクトの宣言を優先し、次の規則で選びます。

| 宣言の状態 | 選定規則 |
| --- | --- |
| 正確な版を指定 | サポートする版で、ほかの宣言とも整合する場合に使う |
| 範囲だけを指定 | 選んだ実行環境の既定版が、すべての範囲を満たす場合に使う |
| 宣言なし | KestreLynxが定めた既定版を使う |
| 宣言が矛盾、または既定版が範囲外 | 範囲内の別のツール版を自動検索せず、手動対応にする |

pipには、作業用の公式Pythonイメージに含まれる版を使います。
マネージャー自身による別のツール版への切り替えは抑止します。

読み取る宣言は[ツールの版宣言](remediation-dependency-formats.md#tool-declarations)、既定版は[対応する実行環境](remediation-reference.md#supported-runtimes)を参照してください。

### ツールの取得と照合 {#tool-verification}

KestreLynxは、選定済みのnpm・pnpm・uvを取得し、配布情報と取得した内容を照合してから作業用コンテナへ渡します。
取得時と受け渡し時に、次の内容を確かめます。

| 検査対象 | 確認する内容 |
| --- | --- |
| 配布情報 | 要求したツール・版に一致し、取得先とハッシュを確認できること |
| 配布物 | レジストリのハッシュに一致し、アーカイブの構造と実行対象を扱えること |
| `package.json`の`packageManager`のハッシュ | 宣言がある場合、照合対象の配布物が宣言値にも一致すること |
| コンテナへ渡すファイル | 記録したサイズとハッシュに一致すること |

ハッシュを付ける書き方の例は、`"packageManager": "pnpm@11.28.5+sha512.<hex>"`です（`<hex>`は実際のハッシュを省略した表記）。
[ツールの版宣言](remediation-dependency-formats.md#tool-declarations)のハッシュはツール自体の配布物に対する指定であり、依存パッケージのハッシュとは別です。

ハッシュ不一致や配布物の不整合を無視して実行しません。
通信先と認証情報の送付範囲は、[通信先一覧](outbound-communication.md#outbound-communication)を参照してください。

### ツール公開後の待機 {#tool-release-age}

npm・pnpm・uv自体が、公開時刻から設定された待機時間を経過したかを、次の規則で判定します。

- 待機時間に達していない版は、後のサイクルへ回す保留（`deferred`）にする
- 公開時刻を確認できない版も保留する
- 待機中に別のツール版へ置き換えて実行しない

待機の対象を区別するため、ツール・通常更新・再解決の条件を並べます。

| 待機の対象 | 判定する処理 | 待機条件 |
| --- | --- | --- |
| npm・pnpm・uv自体 | KestreLynxのツール取得・再利用 | [作業用コンテナ](configuration.md#remediation-worker)の`remediation.worker.tool_versions.min_release_age`（既定`72h`） |
| 通常更新のnpm・uv・pipの依存パッケージ | 各マネージャー | KestreLynxから追加の待機時間を指定しない |
| 通常更新のpnpmの依存パッケージ | pnpm | 使用するpnpm版の既定の公開後制限に従う |
| 再解決で新たに入るパッケージの版 | KestreLynxの再解決の検査 | 公開から72時間待つ（[公開後の待機と再試行](remediation-reresolution-logic.md#dependent-reresolution-waits)） |

通常更新でpnpmに適用される時間は、選定したpnpm版の既定値に依存します。
ツール自体の`min_release_age`を変更しても、依存パッケージの待機時間は変わりません。

### ツールキャッシュの再利用 {#tool-cache}

取得済みのnpm・pnpm・uvは、再利用時にも次の規則で内容と使用条件を検査し、容量を確保します。

- ファイルを読み直してハッシュを計算し、記録された内容との一致を確認する
- `packageManager`のハッシュ宣言、公開後の待機時間、Node.jsの要件を再確認する
- キャッシュの内容を検証できなければ、そのまま実行に使わない
- 使用中ではないキャッシュを整理しても必要な空きを確保できなければ、保留する

容量の設定は[作業用コンテナ](configuration.md#remediation-worker)、保存内容は[保存ファイル](remediation-pr-logic.md#stored-records)を参照してください。

## 更新と検査 {#node-python-update-checks}

npm・pnpm・uv・pipでは、次の方法で依存ファイルを更新し、検査します。

| マネージャー | 変更するファイル | 更新方法 | 主な検査 |
| --- | --- | --- | --- |
| npm | `package-lock.json`・必要時に`package.json` | 対象の記録を取り除いてlockfileを再生成 | 元の入力の再生成でパッケージが変わらないことと、更新後の整合 |
| pnpm | `pnpm-lock.yaml`・必要時に`package.json` | 対象の記録を取り除き、固定を解除してlockfileを再生成 | 更新前後にlockfileを固定して依存の整合を確認 |
| uv | `uv.lock`・必要時に`pyproject.toml` | パッケージごとに更新先を指定してlockfileを更新 | 更新前後のlockfileとプロジェクト宣言の整合 |
| pip | `requirements.txt` | 固定版を書き換え、既存のハッシュがあれば更新 | 稼働イメージの環境を対象に更新前後の依存解決をdry-runで確認 |

更新方法の詳細は、[マネージャー別の更新処理](remediation-package-logic.md#manager-update-methods)を参照してください。

### pnpmで一時的に取り除く直接依存 {#pnpm-temporary-removal}

pnpmの通常更新で推移的依存だけを更新する場合は、lockfileを解き直すために、作業用コピーから直接依存の記録も一時的に取り除くことがあります。
依存元の版も上げる[依存元からの再解決](remediation-reresolution-logic.md#dependent-reresolution)とは異なり、一時的に取り除いた直接依存自身の更新は認めません。

一時的に取り除いた直接依存は、更新後に次の条件で検査します。

- 版・指定・依存関係が元の状態に戻ることを確認する
- その直接依存まで変わった場合や、lockfileを解き直すために使える直接依存がない場合は、手動対応にする

### pipの固定版の更新 {#pip-pinned-updates}

pipでは、`requirements.txt`の`==`で固定した版の書き換え案を作り、更新前後の依存解決を検査します。
入力の条件は、[pipの依存ファイル](remediation-dependency-formats.md#pip-inputs)を参照してください。

固定版の更新では、次の順に処理します。

1. 元の`requirements.txt`を保ったまま、固定版を修正版へ書き換えた内容を用意する
2. 元の内容を使ったdry-runで依存解決を確認し、変更前のpip reportを取得する
3. 書き換えた内容を使ったdry-runで、更新後の依存解決を確認する

範囲指定が更新目標を許す対象は、ファイルを変更せず、その対象の更新PRも作りません。
確認しているのは版指定が更新目標を許すことであり、再ビルド後の解消を検証した結果ではありません。

利用者には「再ビルド」として解消見込みを示します。

更新後のdry-runが依存を解決できなければ、変更前のpip reportとPyPIの`requires_dist`から、固定先の版を許さない依存元を探します。
マーカー（要件を適用する環境の条件）は稼働イメージの環境で評価し、要件は次のように扱います。

- 同じ依存元が同じ対象に付ける有効な要件は、まとめて1つの範囲として判定する
- 更新対象パッケージ自身の要件は、変更前の版の要件しか分からないため、判定に使わない

依存元が見つかった対象パッケージは`dependents_hold_back`で手動対応にし、見つからなければ`post_update_check_failed`のままにします。
初回の検証で一部の対象だけに依存元が見つかった場合は、その対象を外し、元の入力から残りの更新を1回だけやり直します。

除外した対象の版を維持し、残りの更新が依存解決・差分・スキャンの検査と[部分PRの成立条件](remediation-package-logic.md#partial-pr-selection)を満たした場合に、部分PRの候補とします。
対象が残らない場合や、やり直し後の検査を通らない場合は、その`requirements.txt`の更新をPRの候補にしません。

依存元からの再解決は行わず、確認できた依存元の公開版について案内を表示します（[案内の概要](remediation-fix-hints.md#fix-hints)）。

### 付随変更の検査 {#change-validation}

npm・pnpm・uv・pipでは、更新したかったパッケージ以外の差分を公開レジストリの情報と照らし、次の条件で更新に必要な変更か確かめます。
作業用コンテナが返したlockfileや依存解決結果だけを根拠にはしません。

| 差分 | 許可する条件・扱い |
| --- | --- |
| 更新対象と、その更新に必要な依存の追加・変更・削除 | 依存関係、宣言範囲、配布物の参照と整合性情報の検査を通る場合に許可 |
| npmの`deprecated`注記の追加・変更・削除 | そのパッケージ版についてnpmレジストリが返す注記と一致する場合に許可 |
| 対象外パッケージの依存先の版変更 | 更新対象が使う同名パッケージの版へそろえる変更だけを条件付きで許可 |
| 読み取り用の設定ファイルの変更 | 許可せず、手動対応 |
| lockfileの書式変更や、説明できない付随変更 | 許可せず、手動対応 |

対象外パッケージの依存先をそろえる場合も、依存元の版とその他の内容は維持し、宣言範囲と配布情報の整合を確認します。
次の架空の例では、更新対象の`app`と対象外の`browsers`が使う`shared`の版に注目してください。

```text
Before                         After
project                        project
|-- app 1.0.0                  |-- app 1.1.0          更新対象
|   `-- shared 1.0.0            |   `-- shared 1.1.0   更新対象が使う依存先
`-- browsers 1.0.0             `-- browsers 1.0.0     依存元の版は維持
    `-- shared 1.0.0                `-- shared 1.1.0   依存先の版だけをそろえる
```

`browsers`が宣言する範囲と配布情報が整合すれば、`shared`を`1.1.0`へそろえる変更を許可します。
`browsers`自身を`1.0.1`へ上げる変更や、`browsers`の依存先だけを`shared 1.2.0`へ変える変更は許可しません。

依存パッケージの配布物は、参照先とハッシュなどを公開レジストリの情報と照合します。
配布物の内部を展開して、すべての内容を比較する検査ではありません。
