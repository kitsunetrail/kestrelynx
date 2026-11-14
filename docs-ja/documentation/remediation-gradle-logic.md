---
title: Gradleの更新
---

# Gradleの更新

Gradleでは、KestreLynxが版の宣言を書き換え、作業用コンテナ・Podでlockfileを更新します。
Trivyで更新前後を調べ、所見を比較します。

Gradleの更新は、次の流れで進みます。

1. [Gradleの候補選定](#gradle-package-selection)で、更新する依存と版の宣言を決める
2. 宣言を書き換え、[Gradleの実行設定](#gradle-worker-settings)に従って作業用コンテナ・Podで`dependencies --update-locks`を実行する
3. [Gradleの更新結果の検査](#gradle-update-validation)で、返されたファイル・lockfile・所見を確認する
4. 更新できない対象があれば、[対象を外して残りを更新する条件](#gradle-update-exclusions)で更新を続けられるか判断する

このページで使う用語は[用語](remediation.md#terms)を参照してください。

## Gradleの候補選定 {#gradle-package-selection}

Gradleの候補選定では、稼働イメージの`jar`の所見を`gradle.lockfile`の`group:artifact`と版で照合します。
対応付けで指定した依存ディレクトリのファイルを読みます。

稼働版が`compileClasspath`・`runtimeClasspath`・`productionRuntimeClasspath`のいずれかにある依存を候補にします。
検出パスの末尾が対象自身の`artifactId-version.jar`でなければ、別のアーカイブ内の写しとして`jar_bundled_copy`で手動対応にします。

同じパッケージが複数の版で稼働している場合も、手動対応にします。

直接依存かどうかは、ビルドスクリプトの依存宣言とcatalogの参照から判断します。
Gradleの標準の構成の継承によって、宣言した構成から稼働版をlockした構成へ依存が入るかを調べます。

次の表は、標準の継承で判断できる場合と、判断できない場合の違いです。

| 宣言した構成 | 稼働版をlockした構成との関係 | 判定 |
| --- | --- | --- |
| `implementation` | 宣言した依存が`runtimeClasspath`に入る | 直接依存 |
| `developmentOnly`など | 標準の継承だけでは関係を決められない | `gradle_build_unsupported`で手動対応 |

`constraints`は直接依存の宣言に数えません。
サポートする書き方で`compileOnly`が`annotationProcessor`を継承する場合も、判定に含めます。

### 目標版 {#gradle-target-versions}

Gradleの更新目標の下限、Maven Centralから選ぶ公開版、別のメジャー版の修正版の案内は、[目標版とMaven Centralの版](remediation-maven-logic.md#maven-target-versions)にあるMavenと同じ規則で決めます。

### 版の宣言と書き換え {#gradle-version-sources}

版の宣言の検査では、対象の版を決める宣言を探し、書き換える場所を決めます。
方法は次の順に調べ、適用する方法で変更できなければ手動対応にします。

1. 対象の版を持つ依存宣言があれば、その宣言を変更する
2. 版を持つ依存宣言がなければ、Spring BootのBOMが対象の版を決めているか調べる
3. 対象の依存宣言もSpring BootのBOMによる指定もなければ、推移的依存への`constraints`を追記できるか調べる

依存宣言やBOMのプロパティを変更できない場合に、次の方法へ切り替えることはありません。
同じ対象について、版あり・版なしの依存宣言が混在する場合は手動対応にします。

版なしの直接依存は、Spring BootのBOMが版を指定していなければ手動対応にします。
`constraints`の追記を検討するのは、対象の依存宣言がなく、Spring BootのBOMも版を指定していない推移的依存です。

書き換える場所ごとの編集内容は次のとおりです。

| 宣言の場所 | 書き換え |
| --- | --- |
| catalogの`[versions]` | 版の値を変更する |
| catalogのライブラリの`version`・`"g:a:v"` | ライブラリの版を変更する |
| ビルドスクリプトの`"g:a:v"` | 文字列内の版を変更する |
| Spring BootのBOMのプロパティ | 設定済みの値を変更する |
| 未設定のSpring BootのBOMのプロパティ | `gradle.properties`に追記する |
| 対象の依存宣言がなく、Spring BootのBOMも版を指定していない推移的依存 | ビルドスクリプトの末尾に`constraints`を追記する |

書き換えの条件は、選んだ変更方法に応じて確認します。
変更方法を決められない対象は、`gradle_version_source_unsupported`で手動対応にします。

次の表の条件は、その変更方法を使う場合だけ適用します。

| 変更方法 | 条件 |
| --- | --- |
| catalogの版の変更 | 宣言した版が稼働版と一致し、`[plugins]`と共有されていない |
| ビルドスクリプトの版の変更 | 宣言した版が稼働版と一致し、変更する`"g:a:v"`の文字列がファイル全体で1回だけ現れる |
| BOMのプロパティの変更・追記 | `gradle.properties`かビルドスクリプトの`extra`・`ext`で1回だけ設定されているか、未設定である |
| `constraints`の追記 | 対象がlockされた全構成が`compileClasspath`・`runtimeClasspath`・`productionRuntimeClasspath`・`testCompileClasspath`・`testRuntimeClasspath`の範囲にある |

catalogの編集は、`[versions]`の`key = "value"`、1行のライブラリの`"g:a:v"`、インライン表の`version = "..."`をサポートします。
`constraints`の追記では`dependencies { constraints { implementation("g:a:v") } }`を使い、Groovyでは対応する書式を使います。

Spring BootのBOMのプロパティによる更新には、Spring Bootとdependency-managementの両プラグインが必要です。
Spring Bootプラグインと同じ版の`org.springframework.boot:spring-boot-dependencies`と親をMaven Centralから読み、対象の版を決めるプロパティを調べます。

BOM内の指定に応じて、次のように扱います。

| BOM内の指定 | 扱い |
| --- | --- |
| 対象の版が`${p}` | `p`を変更する |
| Spring BootのBOMが取り込むBOM（1段目）の版が`${p}`で、そのBOMが対象の版を直接指定 | `p`を変更してBOMの一式を更新する |
| 版の直書きや、プロパティを版の一部に使う式 | 変更するプロパティを決められないため手動対応にする |
| 複数のBOMが対象の版を指定するか、1段目のBOMがさらに取り込むBOM（2段目以降）を通して指定 | 変更するプロパティを決められないため手動対応にする |

対象の版やimportするBOMの版が、プロジェクトで設定できるプロパティでない場合は、Spring Bootプラグインと同じ版のBOMを版の決定元として記録します。
複数のBOMや別のBOMのimportを通す指定でも同じ記録を行い、[修正版に上げられないときの案内](remediation-fix-hints.md#fix-hints)に使います。

版を上げるBOMは、Spring BootのBOMがプロパティでimportするBOMです。
そのBOMの現在と同じメジャー・マイナー版の新しい正式版を、低い順に最大20件調べます。

対象をMaven Centralから選んだ公開版以上にする、最も低いBOMの版を選びます。
調べたBOMの中に条件を満たす版がなければ、`maven_bom_series_unreached`で手動対応にします。

importするBOMの後のマイナー版を案内する探索規則は、Mavenの[版の出所と書き換え](remediation-maven-logic.md#maven-version-sources)を参照してください。

どの書き換えにも、次の確認を適用します。

- 複数の対象が同じプロパティやcatalogの値を変更する場合は、必要な値のうち最も高い版にまとめる
- 同じ値で版が決まるほかのパッケージも、その版がMaven Centralにあることを確かめる
- 書式とコメントを保って編集し、同じ読み取りの規則で読み直す
- 依存宣言・catalog・プロパティ・`constraints`の変更が、予定した内容と一致することを確かめる
- Gradleの版・toolchain・プラグインなど、更新で変えない宣言も読み直して照合する

必要なファイルと手動対応になる入力は[Gradleの依存ファイル](remediation-dependency-formats.md#gradle-inputs)を参照してください。

## Gradleの実行設定 {#gradle-worker-settings}

Gradleの実行設定では、lockfileの更新に使うGradle・JDKと、作業用コンテナ・Podへ渡す環境を決めます。

使うGradleとJDKは、プロジェクトの指定から選びます。

| 項目 | 選定元 |
| --- | --- |
| Gradleの版 | `gradle/wrapper/gradle-wrapper.properties`の`distributionUrl` |
| JDKの版 | `java.toolchain`の`languageVersion` |
| toolchainの宣言がない場合のJDK | 21 |

Gradleの版・JDK・platformは、[対応する実行環境](remediation-reference.md#supported-runtimes)にある、KestreLynxに組み込まれた対応版の一覧から選びます。
使えるGradleがなければ`gradle_version_unsupported`、指定のJDKを使えなければ`gradle_toolchain_unsupported`で手動対応にします。

実行には公式イメージの`/opt/gradle/bin/gradle`を使い、`gradlew`・`gradle-wrapper.jar`は使いません。
起動時にGradleと実行するJDKの版を照合し、JDKの自動取得を無効にします。

対象の`group:artifact`をカンマで並べ、次のコマンドを実行します。

```sh
gradle --no-daemon --no-build-cache -q -Porg.gradle.java.installations.auto-download=false dependencies --update-locks g1:a1,g2:a2
```

環境変数とキャッシュの場所は、次の値にそろえます。

| 環境変数 | 値 |
| --- | --- |
| `JAVA_HOME` | `/opt/java/openjdk` |
| `GRADLE_USER_HOME` | `/tmp/kestrelynx-cache/gradle` |
| `HOME` | `/home/worker` |

子プロセスの環境は固定した一覧から作り、`GRADLE_OPTS`・`JAVA_OPTS`・プロキシ設定を引き継ぎません。
`GRADLE_USER_HOME`と`HOME`を一時領域に置き、イメージの利用者のinitスクリプトや設定を読み込まないようにします。

イメージが宣言する`VOLUME`の`/home/gradle/.gradle`には、実行環境ごとに次の処理を行います。

| 実行環境 | ボリュームの設定 |
| --- | --- |
| Docker | `/home/gradle/.gradle`をtmpfsで覆う |
| Kubernetes | `/home/gradle/.gradle`を容量上限1MiBの空のメモリボリュームで読み取り専用に覆う |

Dockerでは、匿名ボリュームが作られていないことを確認します。
Kubernetesの設定は、ノードのディスク上にボリュームが作られるのを防ぐためです。

Kubernetesでは、admission policyでボリュームの種類・マウント先・読み取り専用を制限します。
起動時にも、容量上限付きの読み取り専用メモリボリュームであることを確認します。

入力ファイルは、依存ディレクトリからの相対パスで渡します。
返すファイルは次のとおりです。

- 更新した`gradle.lockfile`
- 渡したビルドスクリプト・settings・properties・catalog・wrapperの設定・補助lockfile
- 構成ごとの依存の木を含む`gradle-dependencies.txt`

`gradle-dependencies.txt`は、`dependencies --update-locks`の標準出力の先頭8MiBまでから制御文字を除いたものです。
Gradleが作る`.gradle/`・`build/`は結果に含めません。

共通の実行制限は[作業用コンテナの実行時の制限](remediation-worker-logic.md#worker-restrictions)、通信先は[依存パッケージの取得](outbound-communication.md#dependency-downloads)を参照してください。

## Gradleの更新結果の検査 {#gradle-update-validation}

Gradleの更新結果の検査では、作業用コンテナ・Podから返されたファイルとスキャン結果から、更新を採用できるか判断します。
KestreLynxが書き換えたファイルを渡し、返された結果を次の条件で検査します。

| 検査対象 | 採用条件 |
| --- | --- |
| 返すファイル | 渡したファイルと`gradle-dependencies.txt`がそろっている |
| 作業用コンテナ・Podによる変更 | 入力ファイルのうち、変更されたのは`gradle.lockfile`だけである |
| ビルド定義と補助lockfile | 書き換えて渡したファイルと`settings-gradle.lockfile`・`buildscript-gradle.lockfile`が、渡した内容のままである |
| lockfileに記録した構成 | 更新前後で同じ構成が記録されている |
| `empty=`に列挙した構成 | 更新前後で同じ構成が列挙されている |
| エントリの削除 | 更新前の各構成にあったパッケージが残っている |
| 対象の版 | 対象があったすべての構成で、選んだMaven Centralの公開版以上になっている |
| 追加・変更した座標 | Maven Centralに、要求した座標と版の`.pom`がある |
| 追加・変更した版 | 大文字・小文字を区別せず`SNAPSHOT`を含まない |
| 新しいコメント | Gradleが生成する書式である |
| 同じ構成内の同じパッケージ | 複数の版が記録されていない |

次の変化は手動対応にします。

| 変化 | 理由コード |
| --- | --- |
| lockfileのエントリが削除された | `gradle_lock_entry_removed` |
| lockfileに記録した構成や`empty=`の構成が変わった | `gradle_lock_configurations_changed` |
| 追加・変更した版に`SNAPSHOT`を含む | `gradle_lock_version_unsupported` |

新しい版で不要になった依存でも、エントリの削除は手動対応にします。

スキャンでは、更新前後の`gradle.lockfile`だけを、同じTrivy・脆弱性データベース・重大度で調べます。
読み取った全エントリの名前と版が、それぞれのTrivyの`gradle`のパッケージ一覧にあることを確かめます。

パッケージ一覧に欠けがあれば、更新前後を比べられないため、`source_scan_incomplete`で「比較不能」とし、更新を採用しません。
更新前に対象の所見が確認でき、更新後はどの出現箇所にも残らず、対象外を含めて新しい所見がないことを確かめます。

更新後の対象がMaven Centralから選んだ公開版より低い版に残る構成があれば、`target_not_updated`とします。

案内のために、その構成の依存元を記録します。
その構成の依存の木から、その版の対象に依存する親パッケージを最大5件、`packages[].fix_hint.held_by`に記録します。

構成名は`fix_hint.configuration`に記録します。
依存元がなく、構成が対象を直接宣言している場合は、`fix_hint.direct`を`true`にします。

依存の木の読み取りは、8MiB・10万行・1行1024バイトを上限とし、読めない行でその木の読み込みを終えます。
依存の木は[修正版に上げられないときの案内](remediation-fix-hints.md#fix-hints)だけに使い、PRや更新の判定には使いません。

lockfileの読み取りには、次の制約があります。

- コメント、`group:artifact:version=configurations`、最大1行の`empty=`を読み取る
- 単独のCRや8192バイトを超える行を受け付けない
- 行長はLFを除き、CRLFのCRを含めて数える

PR本文の記載内容とマージ前の確認は[GradleのPRとCIでの確認](remediation-pr-results.md#gradle-pull-requests)を参照してください。

### 対象を外して残りを更新する条件 {#gradle-update-exclusions}

Gradleでは、書き換え前の対象ごとの検査で、残りの対象だけを更新できるか判断します。
公開版と版の宣言を調べる段階では、次の対象だけを外して、残りの更新を続けます。

- 使える公開版がない対象
- 版の宣言を変更できない対象
- BOMの現在と同じメジャー・マイナー版の新しい正式版を最大20件調べても、対象を選んだ公開版以上にできない対象

対象ごとの除外を終えた後は、共有する値の照合、書き換え後の読み直し、作業用コンテナ・Podの出力、スキャンの検査に進みます。
いずれかに失敗した場合は、残りの対象を含む更新結果全体を採用しません。

lockfileの更新後に選んだ公開版へ届かなかった対象を外して再実行する部分PRにはしません。

npm・pnpm・uvで行う依存元からの再解決は適用しません。
パッケージマネージャーごとの部分PRの条件は[部分PRの成立条件](remediation-package-logic.md#partial-pr-selection)を参照してください。
