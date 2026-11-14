---
title: Webhookの修正計画の更新の記録のフィールド
---

# Webhookの修正計画の更新の記録のフィールド

このページでは、汎用Webhookの修正計画に含まれる`language_items[].update`のフィールドを説明します。
修正計画全体の構造は[修正計画の全体像](webhook-remediation-reference.md#remediation-overview)を参照してください。

`language_items[].update`は、更新処理や依存元からの再解決について記録がある場合に付き、記録がなければ省略します。
準備段階で停止して`{}`になる場合や、再解決の見送りだけを記録する場合もあります。

この回に更新や更新後の検査を実行したかは、[言語パッケージのフィールド](webhook-remediation-language-reference.md#remediation-language-fields)の`update_executed`・`post_update_check_executed`で確認します。
表の読み方は[レポートのフィールド](webhook-reference.md#report-fields)を参照してください。

## 更新の記録 {#language-update-fields}

`language_items[].update`のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `steps` | objectの配列 | [実行した操作の記録](#language-update-steps) | 省略 |
| `notes` | stringの配列 | 更新処理中の警告などの補足説明 | 省略 |
| `diff` | object | [依存関係の差分](#language-update-diff) | 省略 |
| `runtime` | object | [更新に使う実行環境の記録](#language-runtime-fields) | 省略 |
| `tool` | object | [更新に使うツールの記録](#language-tool-fields) | 省略 |
| `deprecated_changed` | integer | 非推奨注記が追加・削除・変更されたパッケージの名前と版の組み合わせの件数 | 0件なら省略 |
| `manifest_edits` | objectの配列 | [更新前に変更した直接依存の版指定](#language-update-manifest-edits) | 省略 |
| `chain` | object | [依存元からの再解決の結果](#language-chain-fields) | 省略 |
| `go` | object | [Goの更新の記録](#language-go-update) | 省略 |
| `maven` | object | [Mavenの更新の記録](#language-maven-update) | 省略 |
| `gradle` | object | [Gradleの更新の記録](#language-gradle-update) | 省略 |

次のフィールドには補足があります。

- `deprecated_changed`
    - 同じ名前・版がlockfileの複数箇所にあっても1件として数える
    - パッケージの項目ごと削除された注記は数えない

非推奨注記の変更件数はWebhookに含めますが、対象名の一覧は含めません。
対象名と注記の追加・削除・変更はPR本文で確認します。

次は、`language_items[].update`から操作の識別子と終了結果、差分、版指定の変更を抜粋した例です。

```json
{
  "steps": [
    {
      "id": "update",
      "exit_code": 0,
      "duration_ms": 0
    }
  ],
  "diff": {
    "changed": [
      "node_modules/minimist"
    ]
  },
  "manifest_edits": [
    {
      "file": "package.json",
      "section": "dependencies",
      "name": "lodash",
      "from": "^4.17.15",
      "to": "^5.0.0",
      "major_change": true
    }
  ]
}
```

### 実行した操作 {#language-update-steps}

`language_items[].update.steps[]`の1要素のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `id` | string | 操作が更新処理のどの段階に当たるかを示す識別子 | — |
| `op` | string | 実行した操作の種類 | — |
| `scratch` | boolean | 作業ファイルのコピーで実行し、その変更を後続の操作に引き継がない場合は`true` | `false`なら省略 |
| `exit_code` | integer | 操作の終了コードで、`0`は正常終了 | `0` |
| `duration_ms` | integer | 操作の実行時間をミリ秒で表した値 | `0` |

`id`の値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `baseline` | 更新前の依存ファイルの確認 |
| `update` | 依存ファイルの更新 |
| `check` | 更新後の依存ファイルの再確認 |

`op`の値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `npm.relock` | npmによるpackage-lock.jsonの再生成 |
| `pnpm.frozen_check` | pnpmによるlockfileを変更しない整合性確認 |
| `pnpm.relock` | pnpmによるlockfileの再生成 |
| `uv.check` | uvによるlockfileの整合性確認 |
| `uv.upgrade` | uvによる対象パッケージの更新 |
| `uv.upgrade_chain` | uvによる依存元を含む再解決 |
| `pip.dry_run` | pipによるインストールを伴わない依存解決の確認 |
| `go.get` | Goによる対象モジュールの更新 |
| `gradle.update_locks` | Gradleによる対象パッケージのlockfile更新 |

同じ段階を再実行する場合があるため、`id`を配列内で一意なキーとして扱わないでください。
各操作の範囲は[マネージャー別の更新処理](remediation-package-logic.md#manager-update-methods)を参照してください。

### 直接依存の版指定の変更 {#language-update-manifest-edits}

`language_items[].update.manifest_edits[]`の1要素のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `file` | string | リポジトリ内の変更対象ファイルのパス | — |
| `section` | string | 直接依存を宣言している節 | — |
| `name` | string | 版指定を変更したパッケージ名 | — |
| `from` | string | 変更前の版指定 | — |
| `to` | string | 変更後の版指定 | — |
| `major_change` | boolean | 版指定の変更がメジャー版の変更に該当する場合は`true` | `false`なら省略 |

`section`の値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `dependencies` | package.jsonの通常の依存 |
| `devDependencies` | package.jsonの開発用の依存 |
| `optionalDependencies` | package.jsonの任意の依存 |
| `project.dependencies` | pyproject.tomlのプロジェクトの依存 |

次のフィールドには補足があります。

- `from`・`to`
    - npm・pnpmでは`^4.17.15`のような版指定を表す
    - uvでは`urllib3==1.26.17`のようにパッケージ名を含む依存宣言を表す
- `major_change`
    - `0.x`ではマイナー版の変更をメジャー版の変更として扱う

変更する条件は[直接依存の版指定](remediation-node-python-logic.md#direct-dependencies)を参照してください。

### 依存関係の差分 {#language-update-diff}

`language_items[].update.diff`のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `added` | stringの配列 | 追加された依存関係の項目の識別子 | 省略 |
| `changed` | stringの配列 | 内容が変わった依存関係の項目の識別子 | 省略 |
| `removed` | stringの配列 | 削除された依存関係の項目の識別子 | 省略 |
| `truncated` | boolean | 差分の一覧を切り詰めた場合は`true` | `false`なら省略 |
| `followed` | objectの配列 | [依存先の版だけが変わった項目](#language-update-followed) | 省略 |

`added`・`changed`・`removed`の文字列は、次の単位を識別します。

| マネージャー | 識別するもの | 文字列の例 |
| --- | --- | --- |
| npm | package-lock.json内のパッケージの配置先 | `node_modules/minimist`、`node_modules/mkdirp/node_modules/minimist` |
| pnpm | pnpm-lock.yamlのsnapshots内の項目を比較用に整えたキー | `minimist@1.2.8`、`host@1.0.0(peer@2.0.0)` |
| uv | uv.lock内のパッケージ名と版の組み合わせ | `urllib3==1.26.18` |
| pip | インストールレポート内のパッケージ名を小文字にし、連続する`-`・`_`・`.`を1つの`-`に置き換えた名前 | `urllib3`、`typing-extensions` |

次のフィールドには補足があります。

- `added`・`changed`・`removed`
    - pnpmでは更新対象に関係するpeer依存の情報をキーから除くため、lockfileに書かれたキーと一致しない場合がある
    - pnpm・uvでは版が識別子に含まれるため、版の更新を旧項目の削除と新項目の追加として記録する場合がある
    - `changed`には、パッケージ自身の版が同じで依存先などの内容だけが変わった項目も入る
- `truncated`
    - 対応する一覧は`added`・`changed`・`removed`・`followed`で、切り詰める場合は各一覧を100件までにする
    - `followed[].moves`には、この100件の上限を適用しない
    - 差分の検査途中で不採用になった場合は、切り詰める前の一覧が記録されることがあるため、受信側で100件を固定の最大長としない

この差分は、npm・pnpm・uvでは更新前後のlockfile、pipでは更新前後のインストールレポートを対象とします。
Go・Maven・Gradleの変更は、それぞれの更新の記録を参照してください。

### 依存先の版だけが変わった項目 {#language-update-followed}

`language_items[].update.diff.followed[]`の1要素は、更新対象ではないのに依存先の版が変わったパッケージ1つを表します。
そのパッケージ自身の版は変わりません。

次は、プロジェクトがAとBを直接使い、AとBがどちらもCを使う場合の例です。
Aを更新する前と後の版は次のとおりです。

| 項目 | 更新前 | 更新後 |
| --- | --- | --- |
| Aの版 | `1.0` | `1.1` |
| Bの版 | `2.0` | `2.0` |
| Aが使うCの版 | `1.0` | `1.1` |
| Bが使うCの版 | `1.0` | `1.1` |

この例で各パッケージが`followed`に入るかどうかと、その理由は次のとおりです。

| パッケージ | `followed` | 理由 |
| --- | --- | --- |
| A | 入らない | 更新対象である |
| B | 入る | 自身の版は同じで、使うCの版だけが変わった |
| C | 入らない | Aの更新に伴って版が変わった |

次は、この例のBを表す`followed[]`の1要素です。

```json
{
  "entry": "B@2.0",
  "moves": [
    {
      "name": "C",
      "from": "1.0",
      "to": "1.1"
    }
  ]
}
```

`language_items[].update.diff.followed[]`の1要素のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `entry` | string | 依存先の版が変わった項目を`パッケージ名@版`で表した文字列 | — |
| `moves` | objectの配列 | その項目が参照する依存先の版の変更 | — |

一覧を切り詰める前は、`followed`に記録する項目は`changed`にも入ります。
`entry`はnpm・pnpm・uv・pipのいずれも`名前@版`の形式であり、`added`・`changed`・`removed`の識別子とは形式が異なります。

`language_items[].update.diff.followed[].moves[]`の1要素のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `name` | string | 参照先の版が変わった依存パッケージ名 | — |
| `from` | string | 変更前に参照していた版 | — |
| `to` | string | 変更後に参照する版 | — |

変更を認める条件は[付随変更の検査](remediation-node-python-logic.md#change-validation)を参照してください。

## 更新に使う実行環境 {#language-runtime-fields}

`language_items[].update.runtime`のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `id` | string | 選定した実行環境の識別子 | — |
| `version` | string | 実行環境に含まれるNode.js・Python・Go・Gradleの版 | — |
| `pip` | string | Pythonイメージに含まれるpipの版 | 省略 |
| `image` | string | リポジトリ名とイメージインデックスのdigestで固定した作業用イメージの参照 | 省略 |
| `platform` | string | 作業用イメージの実行プラットフォーム | 省略 |
| `digest` | string | 実行プラットフォームに対応するイメージマニフェストのdigest | 省略 |
| `support` | string | 実行環境のサポート状態 | 省略 |
| `eol` | string | `YYYY-MM-DD`形式のサポート終了日 | 省略 |
| `basis` | string | 実行環境の選定根拠 | 省略 |
| `declared` | objectの配列 | [選定根拠となった版宣言](#language-runtime-declared) | 省略 |
| `excluded` | objectの配列 | [選ばなかった低い系列の記録](#language-runtime-excluded) | 省略 |
| `engines_floor` | string | 依存パッケージの互換性を確認した最低Node.js版 | 省略 |

`id`の値の形式は次のとおりです。

| 値の形式 | 意味 |
| --- | --- |
| `node<メジャー版>` | `node22`のようなNode.jsの系列 |
| `python<メジャー版>.<マイナー版>` | `python3.13`のようなPythonの系列 |
| `golang<メジャー版>.<マイナー版>` | `golang1.26`のようなGoの系列 |
| `gradle<版>-jdk<JDKのメジャー版>` | `gradle9.8.2-jdk17`のようなGradleとJDKの組み合わせ |

使用できる系列とGradle・JDKの組み合わせは[対応する実行環境](remediation-reference.md#supported-runtimes)を参照してください。

`platform`の値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `linux/amd64` | LinuxのAMD64環境 |
| `linux/arm64` | LinuxのARM64環境 |

`support`の値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `lts` | Node.jsの長期サポート期間 |
| `maintenance` | Node.jsの保守期間 |
| `security` | Pythonのセキュリティ修正期間 |
| `bugfix` | Pythonのバグ修正期間 |
| `supported` | Goのサポート期間 |

`basis`の値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `declared_file` | `.node-version`・`.nvmrc`・`.python-version`の版宣言に基づく選定 |
| `lowest_in_range` | 版の範囲指定と実行条件を満たす最も低い系列の選定 |
| `default` | Node.jsの版宣言がない場合の既定の選定 |
| `go_lines` | プロジェクトと更新先モジュールのgo行が要求する版に基づく選定 |

次のフィールドには補足があります。

- `image`・`digest`
    - `image`は`node@sha256:…`のような参照で、`digest`は`sha256:…`の形式を使う
- `support`・`eol`
    - Gradleの実行環境では省略する
- `engines_floor`
    - プロジェクトの宣言が許す最低Node.js版と、選定した実行環境のNode.js版が異なる場合に記録する

選定方法は[実行環境の選定](remediation-package-logic.md#runtime-and-tool-versions)を参照してください。

### 選定根拠となった版宣言 {#language-runtime-declared}

`language_items[].update.runtime.declared[]`の1要素のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `source` | string | 版宣言を読んだファイル名または設定項目名 | — |
| `value` | string | 読み取った版宣言の値 | — |

`source`には、`.nvmrc`・`engines.node`・`requires-python`などが入ります。
`value`は長い場合に切り詰めるため、宣言の再現や設定ファイルの書き戻しには使わないでください。

### 選ばなかった系列 {#language-runtime-excluded}

`language_items[].update.runtime.excluded[]`の1要素のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `id` | string | 選ばなかった実行環境の識別子 | — |
| `why` | string | その系列を選ばなかった理由 | — |
| `eol` | string | `YYYY-MM-DD`形式のサポート終了日 | 省略 |
| `manager` | string | 実行条件が合わなかったパッケージマネージャー名 | 省略 |
| `manager_version` | string | 実行条件が合わなかったパッケージマネージャーの版 | 省略 |
| `engines` | string | パッケージマネージャーが宣言するNode.jsの対応版範囲 | 省略 |

`why`の値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `end_of_life` | サポートが終了しているか、使用できる作業用イメージがない |
| `manager_engines` | パッケージマネージャーのNode.js対応版範囲に合わない |
| `declarations` | プロジェクトの実行環境やツールの宣言に合わない |

`manager`の値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `npm` | npm |
| `pnpm` | pnpm |

次のフィールドには補足があります。

- `id`
    - 形式は[更新に使う実行環境](#language-runtime-fields)の`id`と同じで、`node20`や`python3.10`のようなサポート終了済みの系列も含む
- `eol`
    - `why`が`end_of_life`で、終了日が分かる場合に記録する
- `manager`・`manager_version`・`engines`
    - `why`が`manager_engines`の場合に記録する

## 更新に使うツール {#language-tool-fields}

`language_items[].update.tool`のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `name` | string | パッケージマネージャー名 | — |
| `version` | string | 選定したパッケージマネージャーの版 | — |
| `source` | string | ツール版の選定根拠 | — |
| `format` | string | 取得した配布物の形式 | 省略 |
| `size` | integer | 配布物のバイト数 | `0`なら省略 |
| `sha256` | string | 配布物のSHA-256を16進数で表した値 | — |
| `sha512` | string | 配布物のSHA-512を16進数で表した値 | 省略 |
| `published_at` | string | RFC 3339形式の配布物の公開日時 | `"0001-01-01T00:00:00Z"` |
| `registry_digest` | string | レジストリが示した配布物のdigest | 省略 |
| `spec_hash` | string | プロジェクトの宣言と配布物の照合に使ったハッシュ | 省略 |

`name`の値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `npm` | npm |
| `pnpm` | pnpm |
| `uv` | uv |

`source`の値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `declared` | プロジェクトが宣言した特定の版 |
| `default` | プロジェクトにツール版の宣言がない場合の既定の版 |
| `default_in_range` | プロジェクトが宣言した版の範囲に入る既定の版 |

`format`の値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `npm-tgz` | npm形式の圧縮アーカイブ |
| `wheel` | Pythonのwheel形式の配布物 |

次のフィールドには補足があります。

- `published_at`
    - 公開日時が未設定でもフィールドを省略せず、ゼロ時刻を出力する
- `registry_digest`
    - レジストリが示す表記を保持するため、`sha256`・`sha512`と同じ文字列形式とは限らない
- `spec_hash`
    - `sha512.<16進数>`のようにアルゴリズム名とハッシュ値を`.`でつないだ形式を使う

pip・Go・Gradleは作業用イメージに含まれるツールを使うため、このオブジェクトを出力しません。
Mavenの更新も、このオブジェクトを出力しません。

選定方法は[ツール版の選定](remediation-node-python-logic.md#tool-version-selection)、照合方法は[ツールの取得と照合](remediation-node-python-logic.md#tool-verification)を参照してください。

## 依存元からの再解決の結果 {#language-chain-fields}

`mkdirp 0.5.1`が`minimist 0.0.8`を指定する例では、`blocked`にこの指定、`tops`に選び直す`mkdirp`が入ります。
`language_items[].update.chain.outcome`で、再解決の結果を確認します。

`language_items[].update.chain`のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `outcome` | string | 再解決の結果 | — |
| `reason` | string | 結果の[理由コード](remediation-reason-codes.md#reason-codes) | 省略 |
| `detail` | string | 結果や理由についての補足説明 | 省略 |
| `source` | string | 見送りの場合も含む再解決の方法 | — |
| `blocked` | objectの配列 | [修正版への更新を妨げる版指定](#language-chain-blocked) | `[]` |
| `tops` | objectの配列 | [選び直す直接依存](#language-chain-moves) | `[]` |
| `moves` | objectの配列 | [更新対象と直接依存以外の変更](#language-chain-moves) | 省略 |
| `truncated` | boolean | `moves`の一覧が不完全な場合は`true` | `false`なら省略 |
| `usage` | object | [通常更新と再実行を含む処理量](#language-chain-usage) | — |
| `hints` | objectの配列 | [修正版に上げられない場合の依存元の公開版情報](webhook-remediation-language-reference.md#language-fix-hint-releases) | 省略 |

`outcome`の値は次のとおりです。

| 値 | 意味 | 例 |
| --- | --- | --- |
| `adopted` | 採用 | `mkdirp`を`0.5.6`、`minimist`を`1.2.8`に更新し、検査に合格 |
| `not_fixed` | 修正版に届かない（uvで修正版を指定した再解決が成立しない場合を含む） | 依存元を選び直しても、対象が修正版に上がらない |
| `rejected` | 不採用、または待機の繰り返しによる停止 | 更新によって別の脆弱性が新たに入る |
| `failed` | 処理に失敗 | パッケージマネージャーがエラーで終了 |
| `not_tried` | 見送り | 選び直す直接依存が5パッケージを超える |
| `deferred` | 保留 | 新たに入る版の公開から72時間が経過していない |

`source`の値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `chain_job` | 追加の更新による再解決で、実行前の見送りも含む |
| `first_run` | uvの最初の更新結果の再判定で、再判定前の見送りも含む |

`outcome`が`not_tried`でも、uvの最初の更新で再判定するlockfileを得ていれば`first_run`、それ以外は`chain_job`になります。
見送りを理由に`source`を省略したり、空文字列にしたりはしません。

次のフィールドには補足があります。

- `reason`
    - uvで修正版を指定した再解決が成立しない場合は、`outcome`が`not_fixed`、`reason`が`no_resolution`になる
- `hints`
    - npm・pnpm・uvで、`outcome`が`not_fixed`・`rejected`・`not_tried`の場合に確認する
    - 更新を妨げる依存元が分かり、その公開版について案内できる情報を取得できた場合に含める
- `truncated`
    - `moves`は最大100件で、超えた分を省略すると`true`になる
    - 元にした`update.diff`が切り詰められている場合も`true`になる
    - pnpmで差分の識別子を依存関係に対応付けられない場合は、`moves`を省略して`true`にする
    - `blocked`・`tops`・`hints`の省略を示すフラグではない
- `tops`
    - 選び直す直接依存は最大5パッケージで、上限を超える場合は切り詰めて実行せず、再解決を見送る
- `blocked`
    - 出力件数による切り詰めは行わない

`update.chain`には見送りも含むため、このフィールドがあるだけでは実行済み・採用済みとは判断できません。
実行有無と公開後の待機が終わる日時は、[言語パッケージのフィールド](webhook-remediation-language-reference.md#remediation-language-fields)の`update_executed`・`post_update_check_executed`・`retry_after`で確認します。

待機中は、`retry_after`だけを含み、`update.chain`を含まない回もあります。
待機や停止の条件は[公開後の待機と再試行](remediation-reresolution-logic.md#dependent-reresolution-waits)を参照してください。

### 更新を妨げる版指定 {#language-chain-blocked}

`language_items[].update.chain.blocked[]`の1要素のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `package` | string | 更新を妨げられているパッケージ名 | — |
| `version` | string | 更新を妨げられているパッケージの現在の版 | — |
| `parent` | string | 更新を妨げる版指定を持つ依存元のパッケージ名 | — |
| `parent_version` | string | その依存元の現在の版 | — |
| `range` | string | 依存元が対象パッケージに指定する版または版の範囲 | — |
| `proof` | string | 版指定が修正版への更新を妨げることを確認した根拠 | — |
| `via` | stringの配列 | その依存元につながるプロジェクトの直接依存の名前 | 省略 |

`proof`の値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `exact` | 修正版より古い特定の版に固定している |
| `upper_bound` | 指定範囲の上限が修正版に届かない |

`parent`自身がプロジェクトの直接依存の場合、`via`にはその名前が入ります。

### 直接依存と付随する変更 {#language-chain-moves}

`language_items[].update.chain.tops[]`と`language_items[].update.chain.moves[]`の各要素は同じフィールドを持ち、そのフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `name` | string | 変更を記録するパッケージ名 | — |
| `from` | string | 変更前の版 | 省略 |
| `to` | string | 変更後の版 | 省略 |
| `kind` | string | 変更対象の役割または変更の種類 | — |

`kind`の値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `top` | `tops`に入る、選び直す直接依存 |
| `ancestor` | `moves`に入る、対象パッケージへつながる依存元の変更 |
| `followed` | `moves`に入る、依存元以外の項目の変更 |
| `added` | `moves`に入る、項目の追加 |
| `removed` | `moves`に入る、項目の削除 |

次のフィールドには補足があります。

- `name`
    - `moves`ではパッケージ名を取得できない場合にlockfile内の識別子を入れる
- `from`・`to`
    - `tops`では版が変わらない場合に同じ値になり、再解決前の見送りなどで変更後の版が分からなければ`to`を省略する
    - `moves`では追加前の版がない場合に`from`を、削除後の版がない場合に`to`を省略する

### 更新と再解決の処理量 {#language-chain-usage}

`language_items[].update.chain.usage`のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `containers` | integer | 作業用コンテナの数 | `0` |
| `lookups` | integer | npm・PyPIなどのレジストリに問い合わせた回数 | `0` |
| `bytes` | integer | レジストリから受信したバイト数 | `0` |
| `elapsed_ms` | integer | その項目の処理開始から記録時点までの経過ミリ秒 | `0` |

処理量には、その回の通常更新、依存元からの再解決、必要になった再実行を含めます。
処理の上限は[再解決の対応範囲と上限](remediation-reresolution-logic.md#dependent-reresolution-limits)を参照してください。

## Goの更新の記録 {#language-go-update}

`language_items[].update.go`のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `collateral` | objectの配列 | 更新対象以外で版が上がった、または追加された依存モジュール | 省略 |
| `go_before` | string | 更新前のgo.modのgo行にある版 | 省略 |
| `go_after` | string | 更新後のgo.modのgo行にある版 | 省略 |
| `toolchain_before` | string | 更新前のgo.modのtoolchain行にある値 | 省略 |
| `toolchain_after` | string | 更新後のgo.modのtoolchain行にある値 | 省略 |
| `sum_added` | stringの配列 | チェックサムデータベースの情報からgo.sumに補完した行 | 省略 |

次のフィールドには補足があります。

- `go_before`・`go_after`
    - `1.25.0`のような版を表し、版が変わらない場合も記録する
- `toolchain_before`・`toolchain_after`
    - `go1.25.3`のような宣言値を表し、対応する行がなければ省略する
- `sum_added`
    - 各文字列は`モジュールパス 版 h1:ハッシュ`の形式で、go.modのチェックサムでは版に`/go.mod`が付く
    - Goコマンドが追加した行すべてではなく、更新結果に不足していたため補完した行を表す

`language_items[].update.go.collateral[]`の1要素のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `path` | string | 依存モジュールのパス | — |
| `from` | string | 更新前の依存モジュールの版 | 追加されたモジュールなら省略 |
| `to` | string | 更新後の依存モジュールの版 | — |

採用条件は[Goの更新結果の検査](remediation-go-logic.md#go-update-validation)を参照してください。

## Mavenの更新の記録 {#language-maven-update}

`language_items[].update.maven`のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `edits` | objectの配列 | pom.xmlの版指定の変更 | 省略 |
| `moves` | objectの配列 | 更新対象以外で解決された版が変わったパッケージ | 省略 |

`language_items[].update.maven.edits[]`の1要素のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `file` | string | リポジトリ内の変更対象のpom.xmlのパス | — |
| `kind` | string | 版指定の変更方法 | — |
| `package` | string | 変更の対象となる`groupId:artifactId`形式のパッケージ名 | 省略 |
| `property` | string | 変更したプロパティ名 | 省略 |
| `from` | string | 変更前の版指定 | 省略 |
| `to` | string | 変更後の版指定 | — |

`kind`の値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `version` | 依存宣言に直接書かれた版の変更 |
| `property` | プロジェクトが定義するプロパティの変更 |
| `property_override` | 親から継承するプロパティをプロジェクト側で上書き |
| `managed_pin` | dependencyManagementへの版指定の追加 |

`language_items[].update.maven.moves[]`の1要素のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `name` | string | `groupId:artifactId`形式のパッケージ名 | — |
| `from` | stringの配列 | 更新前に解決された版を重複なく並べ替えた一覧 | 省略 |
| `to` | stringの配列 | 更新後に解決された版を重複なく並べ替えた一覧 | 省略 |

`moves`の版は、更新前後の依存ファイルのスキャンで解決されたものです。
追加されたパッケージでは`from`を、なくなったパッケージでは`to`を省略します。

変更方法は[Mavenの版の出所と書き換え](remediation-maven-logic.md#maven-version-sources)、採用条件は[Mavenの更新結果の検査](remediation-maven-logic.md#maven-update-validation)を参照してください。

## Gradleの更新の記録 {#language-gradle-update}

`language_items[].update.gradle`のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `edits` | objectの配列 | プロジェクト内の版指定の変更 | 省略 |
| `moves` | objectの配列 | 更新対象以外でlockfileの版が変わった、または追加されたパッケージ | 省略 |
| `companions` | objectの配列 | プロパティやバージョンカタログの版指定を共有して変更されるパッケージの記録 | 省略 |
| `bom` | string | 変更するプロパティに対応するSpring Boot BOMの`groupId:artifactId:version`形式の識別子 | 省略 |

`language_items[].update.gradle.edits[]`の1要素のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `file` | string | リポジトリ内の変更対象ファイルのパス | — |
| `kind` | string | 版指定の変更方法 | — |
| `package` | string | 変更の対象となる`groupId:artifactId`形式のパッケージ名 | 省略 |
| `property` | string | 変更したプロパティ名またはバージョンカタログの版のキー | 省略 |
| `from` | string | 変更前の版指定 | 省略 |
| `to` | string | 変更後の版指定 | — |

`kind`の値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `catalog_version` | バージョンカタログの`[versions]`にある版の変更 |
| `catalog_library` | バージョンカタログのライブラリ定義に直接書かれた版の変更 |
| `declaration` | ビルドスクリプトの依存宣言に直接書かれた版の変更 |
| `property` | gradle.propertiesやビルドスクリプトで定義するプロパティの変更 |
| `property_override` | Spring Boot BOMのプロパティをgradle.propertiesで上書き |
| `constraint` | ビルドスクリプトへの依存制約の追加 |

`language_items[].update.gradle.moves[]`の1要素のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `name` | string | `groupId:artifactId`形式のパッケージ名 | — |
| `from` | stringの配列 | 更新前にlockfileで固定された版を重複なく並べ替えた一覧 | 追加されたパッケージなら省略 |
| `to` | stringの配列 | 更新後にlockfileで固定された版を重複なく並べ替えた一覧 | — |

`moves`は変更または追加を記録します。
lockfileからパッケージがなくなる更新は採用しないため、生成される各要素の`to`には更新後の版が入ります。

`language_items[].update.gradle.companions[]`の1要素のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `key` | string | 版を共有するプロパティ名またはバージョンカタログの版のキー | — |
| `value` | string | 共有する変更後の版 | — |
| `packages` | stringの配列 | その版指定を共有する`groupId:artifactId`形式のパッケージ名 | — |

次のフィールドには補足があります。

- `packages`
    - 各変更では、その変更の対象パッケージ自身を除いて、版指定を共有するパッケージを列挙する
    - 複数の更新対象が版指定を共有する場合、他の対象の変更に伴うパッケージとして、更新対象自身も含まれることがある

`companions`には、共有する変更後の版がMaven Centralに存在することを確認したパッケージを記録します。
変更方法は[Gradleの版の宣言と書き換え](remediation-gradle-logic.md#gradle-version-sources)、採用条件は[Gradleの更新結果の検査](remediation-gradle-logic.md#gradle-update-validation)を参照してください。
