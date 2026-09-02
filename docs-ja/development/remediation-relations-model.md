# 修正関係モデルの設計

- **状態:** モデル定義済み
- **開始日:** 2026-08-31
- **最終更新:** 2026-09-02

## 目的

データモデル(語彙と関係)の定義のみを行う。

KestreLynxは現在、稼働中のイメージから「修正可能で優先度の高い脆弱性」を検出して通知できる。
しかし通知を受け取った後、**どこを直せばそのCVEが消えるのか**は利用者に委ねられている。

この区間を埋める機能(修正対象の提示、Kubernetes対応、修正候補の検証)を作るには、その前に、検出結果と「修正の対象」を結び付ける関係が定義されている必要がある。

- そのイメージはどのリポジトリのどのファイルから作られたのか
- その脆弱性はOSパッケージとアプリ依存関係のどちらの問題なのか
- 現在動いているものはどこが管理しているのか(Composeファイルか、Git上のマニフェストか)
- 直した候補が本当に対象のCVEを解消したのか

今回はこれらを表す関係モデルを定義する。
モデルを利用する機能の実装は今後の開発で行う。

## モデルの全体像

検出結果から修正を検証するまでを、4つの領域に分ける。

この文書でPascalCaseのコード表記(`Digest`、`EntityKey`、`PackageRef`など)は、
特記がない限り**KestreLynxが定義する型・モデル名**とする。

| 領域 | KestreLynxの主な型・モデル | 表すもの |
| --- | --- | --- |
| イメージ実体 | `Digest`、`EntityKey`、`ImageSubject`、`ImageEntity` | 観測・スキャンしたイメージの識別 |
| 修正対象 | `PackageRef`、`FixClass`、`FixTarget`、`RuntimeEvidence` | 脆弱なパッケージと修正するファイル |
| ビルド・デプロイ元 | `SourceRef`、`SourceBinding`、`RepoFileRef`、`DeployBinding` | イメージのビルド元と稼働実体の管理元 |
| 修正と検証 | `Derivation`、`VerificationResult` | 修正前後の実体と、CVEが解消したかの検証結果 |

### KestreLynx独自の主な型・モデル

定義する主な型を示す。
`ContentID`は[イメージ実体識別モデル](image-identity-model.md)、
`Environment`、`Workload`、`Container`は[環境・ワークロードモデル](environment-workload-model.md)で定義済みの型である。

#### イメージ実体

| 型・モデル | 表すもの |
| --- | --- |
| `Digest` | 種類付きのdigest値。config digestとregistry digestを区別する |
| `Platform` | イメージのOS・アーキテクチャ・variant |
| `EntityKey` | 同じイメージ実体かを判定するための最小キー |
| `ImageSubject` | イメージ名を軸にした観測・スキャン対象。`EntityKey`は未解決でもよい |
| `ImageEntity` | 1つの実体について同時に確認できた識別情報のまとまり |

#### 修正対象

| 型・モデル | 表すもの |
| --- | --- |
| `PackageRef` | エコシステム・種別・名前・インストール版を含むパッケージ識別情報 |
| `FixClass` | 1件の検出結果を、OS更新・アプリ依存関係更新・上流待ちなどに分類した値 |
| `FixTarget` | 特定のイメージ実体にあるパッケージと、その修正元候補との関係 |
| `RuntimeEvidence` | 特定のEnvironment・Workload・Containerで観測した、パッケージの実行状況に関する証拠 |

#### ビルド元とデプロイ管理元

| 型・モデル | 表すもの |
| --- | --- |
| `Attribution` | 情報の出どころ・信頼度・観測時刻 |
| `SourceRef` | 1つのビルド元候補。Gitリポジトリ・revision・ビルドコンテキスト・Dockerfileを含む |
| `RepoFileRef` | Gitリポジトリ内の1ファイルの位置 |
| `SourceBinding` | イメージ実体と、0件以上のビルド元・ファイル候補との関係 |
| `DeployOwner` | Compose、Kubernetes、Helm、Argo CDなど、管理元の1要素 |
| `OwnerChain` | 直接の管理元から最終管理元までを並べた1本の経路と、その経路が宣言するイメージ |
| `DeployBinding` | Workload内のContainer・稼働イメージ・0件以上の`OwnerChain`を結ぶ関係 |

#### 修正と検証

| 型・モデル | 表すもの |
| --- | --- |
| `Mode` | 修正経路が恒久修正(`rebuild`)か緊急パッチ(`patch`)かを示す値 |
| `Derivation` | 修正前のイメージ実体と修正後の実体との関係 |
| `ScanConditions` | スキャナ・脆弱性DB・深刻度フィルタなど、比較の前提となる条件 |
| `VulnVerdict` | 1つのCVEとパッケージについて、修正前後の状態と判定をまとめたもの |
| `VerificationResult` | 修正前後の再スキャンを比較した検証結果全体 |

これらは独立した同義語ではなく、小さい型を組み合わせて関係を表す。

関係の流れは次のようになる。

1. 稼働イメージを`ImageSubject`として観測し、可能なら`EntityKey`を確定する。
2. 検出結果のパッケージを`PackageRef`で識別し、`FixClass`で修正方法を分類する。
3. `FixTarget`と`SourceBinding`から、修正するリポジトリとファイルの候補を得る。
4. `DeployBinding`から、稼働実体を管理するComposeやKubernetesの定義を得る。
5. 修正前後を`Derivation`で結び、`VerificationResult`で再スキャン結果を検証する。

## モデル定義

### イメージ実体

処理の流れは次のとおりである。

1. DockerやKubernetesから得たdigestを`Digest`へ変換する。
2. 実体を特定できる場合は`EntityKey`を組み立てる。
3. イメージ名と任意の`EntityKey`から`ImageSubject`を作り、観測・スキャンを行う。
4. pin済みスキャンで確認できた識別情報を`ImageEntity`にまとめる。

`EntityKey`は同一性の判定に使う最小のキーである。
一方、`ImageEntity`はそのキーに関連する複数の識別情報やイメージ名を保持するレコードであり、キーそのものではない。

#### イメージ実体の識別(identity型)

Docker Engineのみを対象にしていた場合は、[イメージ実体の正準識別子`ContentID`をOCI image configのdigestで定義する](image-identity-model.md)ことで問題なかったが、Kubernetesではこの前提が成立しなくなる。

- Kubernetesが報告するイメージ識別子(Podの`imageID`)は**registry側のdigest**であり、config digestではない
- registry digestはKubernetes APIからしか得られず、config digestは取得できない

Kubernetesのイメージ実体を`ContentID`と同じフィールドへ入れることはできないので、
KestreLynx独自の型`Digest`を定義し、digestの**種類(kind)**を持たせる。

- `config` — OCI image configのdigest(現在の`ContentID`の意味そのまま)
- `registry` — registryから参照できるdigest
- 未解決 — 検証に通らなかった、または取得できなかった状態

registry側のdigestが指す対象には、実際には2つある。

- 単一プラットフォームのイメージ定義(manifest)
- 複数プラットフォームのイメージをまとめた参照(index)

この2つは別の種類にせず1つの`registry`にまとめる。理由は以下の2点となる。

- どちらも`repo@sha256:...`という同じ形で現れ、参照だけを見てどちらを指すのかは判別できない。
- 判別にはregistryへの問い合わせが必要で、KestreLynxはregistryへアクセスしない。

#### 実体キー(EntityKey)とプラットフォーム

`EntityKey`はKestreLynx独自の型で、同じイメージ実体かを判定するキーである。

- config digest: digestのみ
- registry digest: digestとプラットフォーム(OS・アーキテクチャ)

registry digestは複数プラットフォームを指す場合があるため、digestだけでは実体を特定できない。
プラットフォームが不明な場合はキーを作らず、重複排除や結果の共有を行わない。

config digestとregistry digestの両方が有効な場合は、config digestをキーに使う。
リポジトリ名は取得元の情報であり、`EntityKey`には含めない。

#### 識別済みとpin済み

- **識別済み**: 観測から`EntityKey`を導出できた
- **pin済み**: そのキーを指定したスキャンが成功し、結果の実体も一致した

識別できても、そのdigestをスキャナが扱えるとは限らない。
そのため、キャッシュと他のイメージ名への結果複製はpin済みの場合だけ許可する。
pinできない結果は複製せず、通知では稼働実体との一致未確認として扱う。

`ImageSubject`はKestreLynx独自の型で、観測・スキャンの対象を表す。
常に存在するイメージ名と任意の`EntityKey`を組み合わせる。
これにより、実体を識別できない場合もイメージ名単位で観測を続けられる。

`Pinned`は、次の3条件がすべて成立した場合だけ真となる。

1. `EntityKey`を解決できた
2. スキャンが成功した
3. スキャン結果の実体が、指定した`EntityKey`と一致した

`Derivation`、`SourceBinding`、`FixTarget`、`VerificationResult`の生成には、識別済みではなく**pin済み**であることを要求する。

#### config digestとregistry digestの相関

`ImageEntity`はKestreLynx独自のレコード型で、1回の観測で得たconfig digest、registry digest、プラットフォーム、イメージ名を1つの実体にまとめる。
config digestとregistry digestの相関は、同じpin済みスキャンから両方を確認できた場合だけ記録する。
タグの一致から推測せず、永続化する場合は観測時刻も保持する。今回は永続化しない。

### 修正対象

検出結果から修正するファイルまでを、パッケージを介して結び付ける。

#### パッケージの識別(PackageRef)

`PackageRef`はKestreLynx独自の型で、パッケージの名前、バージョン、OS/アプリ分類、
**エコシステム**(debian、npm、python-pkgなど)をまとめる。
これを用いて、修正すべきmanifestやlockfileを特定する。

エコシステムは許容リストで正規化し、未知の値は推測せず`unknown`とする。

purl(Package URL)は生成規則を誤ると他ツールとの誤突合を招くため、今回は扱わない。

#### 修正の種類(FixClass)

`FixClass`はKestreLynx独自の分類型で、検出結果ごとの修正方法を表す。

- `os_package` — ベースイメージやdistroの更新で直す
- `app_dependency` — manifestやlockfileで直す
- `not_fixable` — 上流が「修正しない」と宣言している
- `not_yet_fixed` — 修正版がまだ確認できない(上流の対応待ち)
- `unknown` — 判定できない

`not_fixable`と`not_yet_fixed`は、上流の意思と修正版待ちを区別するため分ける。
同じパッケージでもCVEごとに状態が異なるため、分類はパッケージ単位ではなく検出結果単位で持つ。

分類は次の順に決定し、条件を満たさない場合は`unknown`とする。

1. `will_not_fix` → `not_fixable`
2. `affected` → `not_yet_fixed`
3. `fixed`かつ修正版あり、OSパッケージ → `os_package`
4. `fixed`かつ修正版あり、アプリ依存関係かつエコシステム既知 → `app_dependency`

#### 修正対象(FixTarget)とソース候補

`FixTarget`はKestreLynx独自の関係モデルで、特定のイメージ実体に含まれるパッケージをどこで直すかを表す。
同じパッケージでもイメージごとに修正元が異なるため、`EntityKey`と`PackageRef`の組を主体とする。

ファイル候補はソース候補に従属させ、リポジトリとの対応を保つ。
また、「未解決」と「解決したが候補なし」を区別し、ソース不明のパスは提示しない。
ファイルの役割はmanifest、lockfile、Dockerfile、デプロイmanifestに分類する。

検出結果とファイルを直接結ばず、検出結果から`EntityKey`と`PackageRef`を経由して`FixTarget`を参照する。
同じパッケージに属する複数のCVEは、この修正対象を共有する。

#### Runtime evidence

`RuntimeEvidence`はKestreLynx独自の観測モデルである。
プロセスや待受ポートなどのruntime evidenceは、イメージ実体ではなく
**Environment・Workload・Container**の組を観測単位とする。
同じイメージでもcontainerごとに実行状態が異なりうるためである。

`EntityKey`と`PackageRef`は`FixTarget`へ結び付けるためのキーとして使う。
複数containerの証拠を集約する規則と、証拠の具体的な内容はこの設計の対象外とする。

### ビルド元とデプロイ管理元

イメージの生成元と、稼働実体の管理元を別の関係として表す。

#### ビルド元(SourceBinding)

`SourceRef`はKestreLynx独自の型で、イメージのGitリポジトリ、revision、Dockerfileを表す。
候補ごとに出どころ、信頼度、観測時刻(`Attribution`)を持つ。

`SourceBinding`は、1つの`EntityKey`と複数のビルド元候補を結ぶ関係モデルである。
各候補は`SourceRef`と、そのリポジトリ内のファイル候補を持つ。
`SourceRef`が候補1件のビルド元を表すのに対し、`SourceBinding`は候補全体と衝突の有無を表す。

ビルド元の情報は次から得られる。

- 利用者が設定で明示したもの
- イメージ自身が申告しているもの(OCIラベル)
- ビルド時に生成された来歴情報(provenance)

`SourceRef`のパスはビルドコンテキストを表す。Git上の単一ファイルを指す`RepoFileRef`とは分ける。

信頼度は合成を前提としない順序付き列挙型とする。
ビルド元では「利用者設定 > provenance > OCIラベル」、デプロイ管理元では
「利用者設定 > runtime情報 > OCIラベル」の順に採用する。同順位の不一致は衝突として両方を残す。

revisionはcommit SHAだけを許可し、タグやブランチ名は推測で補わない。
リポジトリURLは形式だけを検証し、到達確認はしない。

ラベルやprovenanceの取得処理は今回の対象外とする。
生のラベルは共通モデルへ渡さず、adapterやパーサ内で`SourceRef`へ変換する。

#### デプロイ管理元(DeployBinding)

`DeployBinding`は、稼働実体の管理元を近い順の`OwnerChain`で表す。
たとえばPodからDeployment、Helm、Argo CDへ続く関係を保持できる。
管理元はCompose、Kubernetesリソース、Helm、Kustomize、Argo CD、Fluxなどに分類する。

管理経路が複数ある場合は候補ごとに別のchainとして保持する。
各chainは、その管理元が宣言するイメージ(意図)を持つ。
稼働実体(事実)は`DeployBinding`の`ImageSubject`として並記し、差の評価はこのモデルでは行わない。

`DeployOwner`が管理元1件、`OwnerChain`が1本の管理経路、`DeployBinding`が稼働実体を含む関係全体を表す。

`DeployBinding`はWorkloadとContainerも保持し、どのcontainerの稼働実体かを明確にする。

Composeも同じ型で表す。ComposeファイルのGit上の位置は利用者設定からのみ取得し、環境固有の絶対パスは使わない。
Kubernetes固有のUID、resourceVersion、生の`apiVersion`は共通モデルへ渡さず、正規化した種別・名前・名前空間・Git上の位置だけを保持する。
未知のカスタムリソースは、検証済みの`<kind>.<group>`を識別子として保持する。検証できないownerはchainに含めない。

### 修正と検証

#### 修正前後(Derivation)

`Derivation`は修正前後のイメージ実体を結ぶ。修正経路は`Mode`で区別し、関係の出どころも`Attribution`で保持する。

- `rebuild`(恒久修正) — ソース定義を直して通常のビルド経路で作り直したもの
- `patch`(緊急修正) — 稼働中のイメージへ直接パッチを当てて作った派生イメージ

`patch`はソースを直さない一時対応なので、`rebuild`と同一視しない。
関係は変動するタグではなく、修正前後の`EntityKey`で保持する。失効状態は保存せず、現在の実体との照合で判断する。

対象CVEは修正の**意図**を表す。解消の事実は`VerificationResult`だけが示す。

#### 再スキャン検証(VerificationResult)

`VerificationResult`は、修正前後の再スキャン結果を比較した記録である。
修正前後の`EntityKey`、検証対象CVE、検証時刻を保持し、対応する`Derivation`があれば関連付ける。

比較条件は`ScanConditions`、CVEとパッケージごとの判定は`VulnVerdict`で表す。
`VerificationResult`はそれらをまとめ、検証全体を表す。

両方のスキャン条件(スキャナ、脆弱性DB、深刻度フィルタなど)を保持し、既知かつ一致する場合だけ比較する。
条件が不明または不一致なら、判定は不明とし、CVEの増減も示さない。

対象CVEの解消と、新たなCVEの出現は事実として別々に記録し、「悪化した」などの評価は行わない。
比較キーはCVE IDと、エコシステム・種別・名前からなるパッケージ座標の組とする。
更新で変わるバージョンはキーから外し、前後の`PackageRef`にそれぞれ保持する。

`VerificationResult`は次の不変条件を持つ。

- 比較可能かどうかは両側のスキャン条件から導出し、独立に設定しない。
- 比較不能な場合、すべての判定を`unknown`とし、新規CVEも記録しない。
- 元から存在した検出結果と候補側だけに現れた検出結果は、重複しない別の集合にする。
- `Derivation`を添付する場合、その修正前後の実体は検証対象と一致しなければならない。
- 比較可能な場合、候補側にCVEがなければ`resolved`、あれば`persists`とする。

`VerificationResult`はスキャン履歴のstateに保存しない。
差分通知と修正候補の検証では、「解消」の意味が異なるためである。

## 制約

- 発見処理はread-onlyを維持する。
- 今回はモデルの定義のみで、コードの変更は行わない。
- stateのキー・フォーマット・通知の出力形式はいずれも変更しない。
- イメージ実体の識別子の意味(image configのdigest)は変えない。
- registry・Git・来歴情報サービスへのネットワークアクセスは追加しない。
- 不明・食い違いは推測で埋めず、その状態として表現する。
- Runtime固有・ツール固有の生の値を共通モデルへ漏らさない。

## 更新履歴

### 2026-09-02

- モデルを領域別に整理し、KestreLynx独自型の役割を明記した

### 2026-09-01

- 修正関係モデルの設計を確定した

### 2026-08-31

- 修正関係モデルの検討に着手

---

この記事は、KestreLynxの開発記録です。[KestreLynxについて](../index.md)
