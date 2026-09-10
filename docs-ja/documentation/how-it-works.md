# KestreLynxの仕組み

KestreLynxは、ある時点のTrivyスキャン結果を、次の2つの方針で通知へ
変換します。

- **前回のスキャンからの変化** — 既定の`diff`モードでSlackチャンネルへ
  投稿する内容です。
- **現在も未解決の脆弱性** — Slack Botを使用する場合のスレッドと、汎用Webhookの
  ペイロードで確認できます。

毎日すべてのCVEを繰り返すと新しいリスクを見落としやすくなります。一方、変化だけを
通知すると、現在の未解決項目が分かりにくくなります。KestreLynxはこの2つを分けて
扱います。

```text
Docker host or Kubernetes cluster
    │
    ▼
Discover running containers
    │
    ▼
Derive distinct images by identity
    │
    ▼
Scan each image with Trivy
    │
    ▼
Normalize and group findings by image, package, and fix status
    │
    ▼
Enrich CVEs with CISA KEV and EPSS, then assign priority
    │
    ▼
Compare the current groups with persisted state
    │
    ├── Slack summary: changes since the previous scan
    ├── Slack thread: current open findings
    └── Generic webhook: structured current state and diff
```

## 1. スキャンの流れ

### 実行中のイメージを特定する

Docker adapterは、設定されたDockerソケットを通して`GET /containers/json`を呼び出します。
実行中コンテナごとに、イメージ参照（`Image`）、image configのdigest（`ImageID`）、
名前（`Names`）、ラベル（`Labels`）を取得します。config digestとして受け付けるのは、
`sha256:`に64桁の16進数が続く形式だけです。

コンテナ名は`Names`から取得し、先頭のスラッシュを取り除き、リンクの別名を除外します。
`com.docker.compose.project`と`com.docker.compose.service`の両ラベルが存在し、
有効な場合は、ComposeのプロジェクトとサービスとしてコンテナのWorkloadを特定します。
それ以外の場合、Workloadは`unknown`です。

実行中コンテナからイメージ参照と実体の識別情報に基づいて重複を除去し、並べ替えます。
10個のコンテナが同じ参照とdigestを使用している場合、イメージのエントリーは1つです。
1つの参照で異なる2つのdigestが稼働している場合は、2つのエントリーになります。

KestreLynxインスタンス1つが監視する範囲は、Dockerホスト1台またはKubernetesクラスタ1つです。
停止中のコンテナと、ディスクに存在していても実行中コンテナが使用していないイメージは対象外です。

実行中コンテナの一覧を取得できなかった場合、そのスキャン回は終了し、保存済みの状態は
変更しません。次のスケジュールで再試行します。

### Kubernetesでの発見処理

`kubernetes.enabled: true`の場合、Kubernetes adapterはnodes、pods、replicasets、
jobsに対して、ページング付きの読み取り専用LISTリクエストを送ります。nodesは常に
クラスタ全体で取得します。pods、replicasets、jobsはすべてのnamespaceを対象に取得するか、
`kubernetes.namespaces`で選択したnamespaceごとに取得します。

対象となるのは、ステータスに`state.running`があるコンテナです。native sidecarである、
`restartPolicy: Always`付きで現在稼働中のinit containerも含みます。通常の
init containerとephemeral containerは対象外です。コンテナ名は
`<namespace>/<pod>/<container>`形式です。

イメージ参照は`containerStatus.image`から取得します。registry digestは
`containerStatus.imageID`から、`<repo>@sha256:<hex>`形式で読み取ります。
先頭に`docker-pullable://`が付く形式も受け付けます。プラットフォームはノードの
`status.nodeInfo.operatingSystem`と`architecture`から取得し、variantは推測しません。
`sha256:...`だけのimage IDではレジストリ上の実体を特定できないため、
参照によるスキャンへフォールバックします。

Workloadは`ownerReferences`をたどって解決します。

| 所有関係のチェーン | Workload |
| --- | --- |
| Pod → ReplicaSet → Deployment | Deployment |
| Pod → StatefulSet | StatefulSet |
| Pod → DaemonSet | DaemonSet |
| Pod → Job → CronJob | CronJob |
| Pod → 親の所有者がないJob | Job |
| 所有者がないPod | Pod |
| 解決できない、または未対応のチェーン | `unknown` |

コンテナとWorkloadの情報は汎用Webhookのペイロードにだけ含まれ、Slackには表示しません。

LISTリクエストは1ページ最大500オブジェクトで取得します。通信エラー、HTTP 429、
サーバーエラーでは、`Retry-After`に従い、指数バックオフで最大3回再試行します。
HTTP 410では一覧取得を最大2回最初からやり直します。ServiceAccountのトークンとCAは
スキャン回ごとに読み込み、HTTP 401のあとにはトークンを再読み込みします。
いずれかのLISTが失敗すると、そのスキャン回全体が失敗します。部分的な結果は破棄し、
保存済みの状態は更新しません。

### 一意な各イメージをスキャンする

KestreLynxは、一意なイメージ実体ごとにTrivy CLIを実行し、JSON形式の結果を取得します。
`scan.severity`で指定した深刻度をTrivyへ渡します。既定値は`HIGH,CRITICAL`です。

スキャン対象は、発見時に取得できた実体の識別情報によって決まります。

| 実体の識別情報 | スキャン対象 |
| --- | --- |
| Dockerのconfig digest | `--image-src docker`を使用し、config digestで指定したローカルのDockerイメージです。 |
| Kubernetesのregistry digestと既知のプラットフォーム | `--image-src remote`と`--platform`を使用し、digestで指定したレジストリ上のイメージです。 |
| 実体を特定できない場合 | イメージ参照によるスキャンへフォールバックします。 |

呼び出し形式は次の3種類です。

```text
trivy image --quiet --format json --severity <list> --image-src docker sha256:<config-digest>
trivy image --quiet --format json --severity <list> --image-src remote --platform <os>/<arch> <repo>@sha256:<hex>
trivy image --quiet --format json --severity <list> <ref>
```

digestを指定したスキャンのあと、KestreLynxは返されたメタデータを検証します。
Dockerのスキャンでは、`Metadata.ImageID`が指定したconfig digestと一致する必要があります。
レジストリのスキャンでは、指定したdigestが`Metadata.RepoDigests`に含まれ、
`Metadata.ImageConfig`が指定したOSとアーキテクチャに一致する必要があります。
一致しない場合は、稼働中イメージの結果として扱わず、スキャン失敗として報告します。

複数の参照が同じ実体を指す場合、スキャンで実体を確認できたときだけ、
それらの別名で結果を共有します。スキャンに失敗した場合や実体を確認できなかった場合は、
次の別名で再度スキャンします。
レジストリ上の実体の識別にはプラットフォームも含むため、異なるプラットフォームは
同じイメージとして扱いません。参照によるスキャンには
`identity unconfirmed: scanned by reference`という注釈を付けます。
参照単位のSlackラベルとサマリーでは、参照に属するすべての実体を発見時に
Dockerのconfig digestで識別できた場合だけ、スキャン結果にかかわらず確認済みとします。
この判定では、Kubernetesのregistry digestは未確認扱いになります。

1つのイメージでエラーが発生しても、ほかのイメージのスキャンは続行します。エラーは
通知の**Scan failures**（スキャン失敗）に表示します。また、そのイメージの前回の検出状態を今回も
引き継ぎます。スキャンできなかったイメージを安全とみなすと、誤った「解消」通知が
発生するためです。

1つの参照で複数の実体が稼働し、一部のスキャンだけが失敗した場合は、`content_id`を
空にして前回の検出結果を保持します。前回と今回で重複する検出結果は保守的に統合します。
CVE IDをまとめ、どちらかの結果に修正版があれば修正版が利用可能な状態を維持し、
優先度は高い方を保持します。その参照の解消判定は保留します。

Kubernetesモードでは、参照によるスキャンが成功した場合も、稼働中イメージの実体を
確認できないため、前回の検出結果を保持します。Slackには
`⏳ unconfirmed this cycle, holding previous findings — <refs>`と表示します。
実体未確認の参照について、以前に記録したパッケージの検出結果を保持している間は、
変化がなくても通知します。保持している履歴がEOLの記録だけの場合は、
それだけではこの通知の条件を満たしません。

### パッケージ単位に集約する

Trivyの各行を正規化し、次の単位でパッケージグループを作成します。

```text
(image reference + identity) + package + Trivy status
```

この単位に属するCVEの重複を除去してまとめます。グループには、インストール済み
バージョン、修正版がある場合はそのバージョン、CRITICALとHIGHの件数、参照URL、
グループ内で最も高い優先度が含まれます。

同じパッケージでも、あるCVEには修正版があり、別のCVEには修正版がない場合などは、
複数の修正状態グループに現れることがあります。

1つのタグが稼働中の2つのdigestを指す場合、Slackでは
`web:1.0 (3f2a9c1b7d4e)`や`web:1.0 (3f2a9c1b7d4e linux/amd64)`のように、
末尾に短いdigestを付けて区別します。状態と差分のキーは、引き続きイメージ参照と
パッケージの組み合わせです。

## 2. 3種類の分類

KestreLynxは、深刻度、修正状態、優先度を別々に扱います。それぞれが示す意味は異なり、
同じものではありません。

| 分類 | 情報源 | 判断する内容 |
| --- | --- | --- |
| 深刻度 | Trivyおよびアドバイザリー情報 | 影響がどの程度大きくなり得るか |
| 修正状態 | Trivy | 上流で利用可能な修正版があるか |
| 優先度 | KestreLynxのトリアージ | 悪用シグナルを踏まえて、どの程度急いで確認すべきか |

たとえばCRITICALのCVEでも、強い悪用シグナルがなければ**Watch**になる場合があります。
反対にHIGHのCVEでも、CISA KEVへ掲載されていれば**Act now**になります。

### 修正状態

KestreLynxは、Trivyのステータスを修正対応の基準となる状態として保持します。

| Trivyのステータス | KestreLynxでの意味 |
| --- | --- |
| `fixed` | 修正版が利用できます。 |
| `affected` | 影響を受けますが、まだ修正版がありません。 |
| `will_not_fix` | 上流が修正しないと判断しています。 |

この修正状態の分類は、汎用Webhookの構造化データにも保持されます。Slackでは通常、
緊急性の高い対応を先に確認できるよう、優先度順に組み替えて表示します。

### アップグレード時の注意度

`fixed`のパッケージには、提示されたバージョン変更の大きさや種類を表す注釈を付けます。

| 表示 | 判定方法 |
| --- | --- |
| ディストリビューションのセキュリティ更新 | OSパッケージのバージョンはSemVerではなく、ディストリビューションのリビジョンとして扱います。 |
| 比較的安全 | 言語パッケージのメジャーバージョンが同じ、または小さくなります。 |
| 注意が必要 | 言語パッケージのメジャーバージョンが大きくなります。 |
| 不明 | 言語パッケージのバージョンを確実に解析できません。 |

これは**変更規模の目安**であり、更新の安全性を保証するものではありません。実際の更新時は、
リリースノート、アプリケーションとの互換性、テスト結果も確認する必要があります。

### ベースOSのサポート終了

イメージのベースOSがサポート終了であるとTrivyが報告した場合、KestreLynxはCVEの
優先度とは別に、**EOL base**として最上部へ表示します。EOLはCVEの優先度では
ありません。通常のセキュリティ更新が今後提供されない可能性があるため、サポート中の
ベースイメージで再ビルドすることが基本的な対応になります。

## 3. 悪用情報に基づくトリアージ

トリアージは既定で有効です。KestreLynxは、Trivyが検出したCVE IDへ次の2種類の
情報を付加します。

- **CISA KEV**は、実際の悪用が確認された脆弱性を示します。
- **EPSS**は、今後30日以内に悪用活動が発生する確率を推定します。影響の大きさを
  示すものではなく、監視対象の環境で悪用可能であることを証明するものでもありません。

### CVEごとの優先度判定

既定のしきい値では、各CVEを次の順序で分類します。

| 優先度 | 条件 |
| --- | --- |
| **Act now** | CISA KEVに掲載されている、またはEPSSが`0.10`（10%）以上です。 |
| **Watch** | Act nowではなく、EPSSが`0.01`（1%）以上、または深刻度がCRITICALです。 |
| **Low** | 上記のどちらにも該当しません。KEVになく、EPSSがしきい値未満のHIGHも含まれます。 |

EPSSの2つのしきい値は、`triage.act_now_epss`と`triage.watch_epss`で変更できます。
EPSSにCVEのスコアがない場合は、0として扱うのではなく、EPSSに関する条件を
判定から除外します。

KEVのランサムウェアキャンペーン情報は根拠として表示しますが、それだけで別の
優先度を作ることはありません。

### 優先度と修正状態の関係

修正版がない場合でも、強い悪用シグナルを隠さないようにします。

- Act nowのCVEは、`fixed`、`affected`、`will_not_fix`のどの状態でもAct nowの
  ままです。修正版がなければ、通知で緩和策や置き換えの検討を促します。
- WatchのCVEが`will_not_fix`の場合、強い悪用シグナルのない修正不能項目を
  対応キューへ残し続けないようLowへ下げます。
- Lowは修正状態にかかわらずLowのままです。

パッケージグループの優先度は、そのグループに含まれるCVEのうち最も高い優先度です。
完全な優先度表示で**Act now**、**Watch**、**Low**の横に表示する件数は、CVE件数では
なくパッケージグループの件数です。diffのハートビートでは、同じイメージとパッケージの
修正状態グループをまとめ、現在の最も高い優先度で1件として数えます。

### フィードの取得、キャッシュ、プライバシー

KEVとEPSSのフィードは一括でダウンロードし、CVE IDとの照合はローカルで行います。
ホストで検出したCVEの完全な一覧を、これらのサービスへ送信することはありません。
フィードのキャッシュは、`state.path`と同じ場所にある`intel`ディレクトリへ保存します。

- フィードは約20時間経過すると更新します。
- 更新できない場合、検証済みのキャッシュを最大7日間使用できます。
- KEVとEPSSは別々に状態を管理します。片方だけ利用できる場合は、その情報を使って
  トリアージを続け、利用できない情報源を通知へ表示します。
- ダウンロードしたデータは検証してから既存のキャッシュと置き換えます。

どちらの情報源も利用できない場合は、**縮退トリアージ**になります。警告を表示し、
CRITICALをAct now、それ以外の選択済み深刻度をWatchとして扱います。悪用情報が
利用できない間は、何もLowへ分類しません。また、その回は優先度上昇の通知を抑止します。
これにより、フィード障害を大量のリスク上昇として誤通知することを防ぎます。

`triage.discussion_links`が有効な場合、Act nowと判定済みのCVE IDだけを
Hacker Newsの検索APIへ送信します。CVE IDが一致し、20ポイント以上の議論だけを
参照リンクとして追加します。このCVE IDの外部送信を避ける場合は`false`にします。

## 4. 差分状態と変化の判定

既定の`diff`モードでは、`state.path`へ履歴を保存します。既定のパスは
`/var/lib/kestrelynx/state.json`です。このディレクトリはDockerボリューム、
またはKubernetesの永続ボリュームで永続化する必要があります。

イメージとパッケージの組み合わせごとに、次の情報を保存します。

- 初めて検出した日時
- CVE IDの集合
- 1つ以上の修正版が利用可能か
- 前回のパッケージ最大優先度
- `content_id`として、確認済みの単一実体のconfig digestを保存します。参照が曖昧な場合や、
  一部のスキャンが失敗した場合は空にします。

トップレベルの`images`マップは参照をキーとし、並べ替え済みの`content_ids`、
`registry_digests`、`ambiguous`、`last_seen`を記録します。`environment.name`を
設定した場合、`environment`オブジェクトにその`name`とadapter由来の`kind`を記録します。

これらのフィールドを追加しても、状態ファイルの形式バージョンは`1`のままです。
古い状態ファイルは変換せずに読み込めます。環境名の設定、変更、削除によって、
履歴のキーを変えたり、初回検出日時をリセットしたり、既存の検出項目を再通知したり
することはありません。1つの状態ファイルが保持するのは1つの環境です。
2つのインスタンスで共有しないでください。

EOLを初めて検出した日時と、直近のSlack完全レポートスレッドへの参照は、別に保存します。
状態ファイルは一時ファイルへ書き込んだあと、アトミックに置き換えます。

### 変化として扱う条件

現在と前回のパッケージ状態を、次の優先順位で比較します。
イメージの置き換えは独立して検出します。

| 変化 | 条件 |
| --- | --- |
| 新規 | イメージとパッケージの組み合わせが前回の状態にありません。 |
| 優先度上昇 | 既知のパッケージの最大優先度が上昇しました。例：WatchからAct now。 |
| CVE追加 | 既知のパッケージに1つ以上の新しいCVE IDが加わりました。 |
| 修正版が利用可能 | 前回は修正版がなく、今回は1つ以上の修正版があります。 |
| 解消 | 前回保存されていたイメージとパッケージの組み合わせが、成功した今回のスキャン結果にありません。 |
| 置き換え | 参照の確認済みcontent-ID集合が前回と今回の両方で空ではなく、異なっています。`🔄 Image content changed`と表示します。 |

同じスキャン回で複数の条件が成立した場合、優先順位が最も高い理由だけを表示します。
優先度が下がった場合は変化として通知しませんが、新しい優先度は保存します。その後に
再び優先度が上がった場合は、保存した値を基準に上昇を検出できます。
優先度上昇の検出には保存済みの優先度が必要で、縮退トリアージ中は抑止します。

置き換えはイメージ単位の変化であり、パッケージ単位の優先順位とは独立しています。
パッケージの変化と同時に表示される場合があり、検出項目がないイメージでも通知します。
実体を初めて観測した場合は、置き換えとはみなしません。

「解消」は、KestreLynxの現在の対象から検出項目がなくなったことを意味します。
修正版の適用、イメージの変更、コンテナの停止、対象深刻度の変更、スキャナー側データの
変更など、複数の原因が考えられます。「解消」だけでは、パッチの適用を証明しません。
スキャンが全面的に失敗した参照、一部だけ失敗した参照、Kubernetesで実体未確認の参照では、
解消を通知しません。

初回実行時や利用可能な状態ファイルがない場合、現在のすべてのパッケージを新規として
通知します。状態ファイルが壊れている場合も同じ扱いになり、警告をログへ出力します。
状態ファイルの形式バージョンが一致しない場合は、互換性のない履歴を解釈せず、
新しい状態として開始します。

### 状態を更新するタイミング

通知が不要な場合は、計算した新しい状態をそのまま保存します。通知が必要な場合は、
設定したすべての通知先への送信が成功したあとにだけ保存します。送信に失敗した変化は
失われず、次のスキャン回で再通知されます。

複数の通知先を設定した場合は、すべてへの送信を試みます。一部だけ失敗すると、成功した
通知先にも次の回で同じ変化が届く可能性があります。これは厳密な1回限りの配信よりも、
通知を失わないことを優先した動作です。

## 5. 通知を送信する条件

### diffモード（既定）

| 現在の結果 | `notify_on_clean: false`の場合の動作 |
| --- | --- |
| 検出項目があり、変化もある | 変化と現在の未解決件数を通知します。 |
| 検出項目があるが、変化はない | 短いハートビートを送り、チャンネルには詳細一覧を繰り返しません。 |
| 最後の検出項目が解消した | 解消した内容と、未解決項目がないことを通知します。 |
| 検出項目がなく、前回から変化もない | 通知しません。 |
| 1つ以上のイメージでスキャンが失敗した | 脆弱性の検出項目がなくても、失敗を通知します。 |
| イメージの実体が変わった | 検出項目がないイメージでも、置き換えを通知します。 |
| Kubernetesの参照によるスキャンで実体が未確認で、その参照について以前に記録したパッケージの検出結果を保持している | 変化がなくても、検出結果を保持している状態を通知します。保持している履歴がEOLの記録だけの場合は、それだけではこの通知の条件を満たしません。 |

EOL、Act now、Watchのいずれかで最も古い項目が14日を超えると、ハートビートへ
経過日数と時計マークを表示します。Lowは緊急の滞留とはみなさないため、
ハートビートの経過日数には使用しません。

`notify.full_report_day`の曜日（既定は月曜日）には、その回が通知対象であれば、
Slackへ現在の完全レポートも含めます。`never`で週次レポートを無効化できます。
`notify_on_clean`が`false`の場合、週次レポートの曜日であっても、検出項目も変化もない
スキャンについて通知を強制することはありません。

### fullモード

`notify.mode: full`では差分状態を使用しません。検出項目またはスキャン失敗があれば、
スキャンのたびに現在のレポートを送ります。何も検出されなかった場合の通知は、
`notify_on_clean`が`true`のときだけです。

## 6. Slackでの表示

SlackメッセージはBlock Kitではなく、通常の`mrkdwn`テキストで作成します。Slackでいう
「完全レポート」は、全CVEをそのまま列挙するという意味ではなく、現在の状態を示す
レポートです。Act nowとWatchは展開しますが、Lowは件数だけにまとめます。省略のない
データは汎用Webhookで取得できます。

トリアージが有効な場合、現在のレポートは次の順に表示します。

1. EOLのベースイメージ
2. Act now — パッケージの詳細と、最も強いCVEのKEVおよびEPSSの根拠
3. Watch — 簡潔なパッケージ情報と最も強いシグナル
4. Low — 件数のみ
5. スキャン失敗と、脅威情報の鮮度に関する警告
6. 該当する場合、実体未確認と前回の検出結果の保持に関する注釈

Act nowの参照先には、Trivyの主要アドバイザリー、KEVのnotesにあるベンダー情報、
任意のHacker News議論リンクが含まれる場合があります。Lowの詳細はSlackでは省略し、
完全な一覧は構造化された汎用Webhookで確認できます。

Slackの判定根拠の行、Watchの理由、スレッドの`also:`一覧にあるCVE IDは、
それぞれのNVDレコードへのリンクです。以下の例では、リンクのマークアップを省略し、
表示されるIDだけを記載しています。GHSAやDLAのIDなど、ほかの識別子は通常のテキストです。

### 共通ヘッダー

すべてのSlackチャンネル通知は、スキャン時刻と2種類のイメージ件数から始まります。

```text
🛡️ *KestreLynx* — scan results for 2026-08-16 09:00
4 images scanned, 3 affected
```

`environment.name: prod-vps`を設定した場合、ヘッダーは次のようになります。

```text
🛡️ *KestreLynx* [prod-vps] — scan results for 2026-08-16 09:00
4 images scanned, 3 affected
```

環境名はチャンネルのヘッダーにだけ表示し、スレッドには表示しません。

- `images scanned`は、その回で検出した一意な参照と実体の組み合わせの数です。
  スキャンに失敗したイメージも含みます。1つの参照で2つのdigestが稼働していれば2件と数え、
  2つの参照で1回のスキャンを共有する場合も2件と数えます。
- `affected`は、対象の脆弱性またはEOLのベースOSがある一意なイメージ数です。
  スキャン失敗しかないイメージはaffectedに含めず、**Scan failures**へ表示します。
- 時刻にはプロセスのローカルタイムゾーンを使用します。コンテナでは`TZ`環境変数で
  指定します。

### チャンネルの差分通知

既定のチャンネル通知は、現在の完全レポートの複製ではなく、変化のレポートです。
該当する項目がある場合、次の順序で表示します。

1. 共通ヘッダー
2. イメージ実体の変更
3. 新たに検出したEOLベースイメージ
4. 脆弱性情報源に関する警告
5. 新規または変化したパッケージ
6. 解消したEOLイメージとパッケージ
7. 週次の現在状態レポート、またはスキャン失敗と**Open now**
8. 実体未確認と前回の検出結果の保持に関する注釈
9. Bot使用時のみ、今回のスレッドレポートまたは前回のレポートへのリンク

省略した表示例は次のとおりです。

```text
🛡️ *KestreLynx* — scan results for 2026-08-16 09:00
4 images scanned, 3 affected

*🔄 Image content changed (1)*
• ghcr.io/example/worker:latest: image updated (111111111111 → 222222222222)

*🆕 New since last scan (1)*
🚨 ghcr.io/example/api:latest
   • openssl 3.0.13 → 3.0.14 (CRITICAL 1 / HIGH 0)  🟢 upgrade: distro security patch — ⬆️ escalated to ACT NOW
     ↳ CVE-2026-12345 CRITICAL · CISA KEV (exploited in the wild) · EPSS 12%

*✅ Resolved since last scan (1)*
• ghcr.io/example/worker:latest: libxml2

📌 Open now: 🚨 1 act-now / 👀 2 watch / 🔕 8 low — oldest act-now/watch unresolved 4 day(s)
_Details in the generic webhook payload, or in the weekly full report._

_📊 Full report in this message's thread ↓_
```

`New since last scan (N)`のNはCVE件数ではなく、変化したイメージとパッケージの
組み合わせ件数です。新規・変化項目は、優先度、イメージ名、パッケージ名の順で
並べ替えます。

変化がない場合は、次のような本文になります。

```text
No changes since last scan.
📌 Open now: 🚨 1 act-now / 👀 2 watch / 🔕 8 low
_Details in the generic webhook payload, or in the weekly full report._
🔗 Last full report → thread
```

該当する場合は、スキャン失敗と実体の識別に関する注釈も含みます。
EOLイメージが未解決のまま残っている場合、**Open now**の件数は`⛔ N EOL base`から始まります。

未解決項目がない場合、**Open now**は次の表示になります。

```text
🎉 Open now: none — all clear
```

現在のレポートに検出結果またはEOLイメージが1つでもあれば、通常の件数を表示します。
Kubernetesのスキャンで実体が未確認のため前回の検出結果を保持しており、
現在のレポートに検出結果もEOLイメージも1つもない場合は、次の表示になります。

```text
📌 Open now: unconfirmed — holding previous findings until re-confirmed
```

### 現在状態レポートのレイアウト

fullモード、diff通知内の週次レポート、Bot APIのスレッドは、そのスキャン時点で
未解決の内容を表します。チャンネルへ表示する形式は次のようになります。

```text
*Priority:* ⛔ 1 EOL base · 🚨 1 act now · 👀 2 watch · 🔕 8 low

*⛔ Base OS end-of-life (top priority)*
• ghcr.io/example/legacy:latest — base OS is EOL (no more security updates coming)

*🚨 Act now (1) — exploited or likely to be*
• ghcr.io/example/api:latest
   • openssl 3.0.13 → 3.0.14 (CRITICAL 1 / HIGH 0)  🟢 upgrade: distro security patch
     ↳ CVE-2026-12345 CRITICAL · CISA KEV (exploited in the wild) · EPSS 12%
       📎 advisory · vendor advisory · 💬 HN (120 pts)

*👀 Watch (2) — not urgent, keep an eye on*
• ghcr.io/example/frontend:latest
   • zlib 1.2.13 (no fix available) (CRITICAL 1 / HIGH 0) — CVE-2026-23456 · EPSS 0.4%

*🔕 Low priority (8)* — 8 finding(s) across 3 image(s), no exploitation signal (not in KEV, EPSS below threshold).
_Details in the generic webhook payload or the weekly full report._
```

件数が0の優先度と空のセクションは表示しません。Priority行では、修正状態ごとに分かれた
パッケージグループを数えます。そのため、同じパッケージのCVEが異なる修正状態で
報告された場合、同じパッケージが複数件として数えられることがあります。

### パッケージ行の読み方

修正版があるパッケージ行の形式は次のとおりです。

```text
package installed-version → fixed-version (CRITICAL N / HIGH N) upgrade-label [lang] change-label
```

修正版がない場合、矢印と修正版の代わりに`(no fix available)`を表示します。
CRITICALとHIGHは、そのパッケージと修正状態のグループに含まれる、重複を除いた
CVE IDの件数です。`[lang]`は言語パッケージを示し、通常、付いていないものは
OSパッケージです。

パッケージの後ろに表示するラベルの意味は次のとおりです。

| 実際の表示 | 意味 |
| --- | --- |
| `🟢 upgrade: distro security patch` | OSパッケージの修正です。ディストリビューションのバージョンをSemVerとして比較しません。 |
| `🟢 upgrade: low-risk` | 言語パッケージのメジャーバージョンが増えません。安全性を保証する表示ではありません。 |
| `🟠 upgrade: major version bump — needs care` | 言語パッケージのメジャーバージョンが増えるため、互換性を壊す可能性があります。 |
| `⚪ upgrade: risk unknown` | バージョンを確実に解析できません。 |
| `[lang]` | TrivyがOSパッケージではなく言語依存パッケージとして分類しています。 |
| `⬆️ escalated to ACT NOW/WATCH` | 前回から、既知パッケージの最大優先度が上昇しました。 |
| `N new CVE(s)` | 既知のイメージとパッケージに、新しいCVE IDが追加されました。 |
| `fix now available` | 前回は修正版がなく、今回は1つ以上の修正版があります。 |

緑色の更新アイコンは、提示されたバージョン変更の種類を示します。イメージ、
パッケージ、脆弱性が安全であるという意味ではありません。

### 判定根拠と参照URLの行

Act nowのパッケージには、最も強いCVEの判定根拠を続けて表示します。

```text
↳ CVE-2026-12345 CRITICAL · CISA KEV (exploited in the wild) · EPSS 12%
```

最も強いCVEは、優先度、EPSSが取得済みか、EPSSの高さ、CVE IDの順で決まります。
同じパッケージにほかのCVEもある場合、チャンネルではCVEごとに展開せず、
`(+N more CVE(s) in this package)`と表示します。

縮退トリアージ中は、判定根拠の行を次のように表示します。

```text
↳ CVE-2026-12345 CRITICAL · severity only (intel unavailable)
```

判定根拠のラベルには次の意味があります。

| ラベル | 意味 |
| --- | --- |
| `CISA KEV (exploited in the wild)` | 利用可能な現在のKEVカタログにCVEが掲載されています。 |
| `EPSS N%` | 現在のEPSS確率です。スコアがない場合は`n/a`、非常に小さい値は`<0.1%`、非常に大きい値は`>99%`と表示します。 |
| `🧨 ransomware campaign` | CISAがランサムウェアキャンペーンでの使用を確認しています。別の優先度ではなく、判定根拠です。 |
| `severity only (intel unavailable)` | どちらの脅威情報源も利用できないため、深刻度に基づいて優先度を決定しています。 |
| `no fix yet, consider mitigation` | `affected`グループに修正版がないため、緩和策の検討が必要です。 |
| `upstream won't fix, consider replacing` | `will_not_fix`のため、置き換えなど別の対応が必要な可能性があります。 |
| `📎 advisory` | Trivyが提供する主要アドバイザリーURLです。 |
| `vendor advisory` | KEVのnotesから取得したベンダーまたはCISAの参照URLです。 |
| `💬 HN (N pts)` | 条件を満たした任意のHacker News議論とポイント数です。 |

Watchでは、通常は最も強いCVEとEPSS値だけをパッケージ行の後ろへ簡潔に表示します。
LowはSlackでパッケージごとの詳細を表示しません。

### セクション、状態、警告ラベル

| ラベル | 意味 |
| --- | --- |
| `⛔ EOL base` | ベースOSがサポート終了です。CVE優先度とは別に管理します。 |
| `🚨 Act now` | 悪用が確認済み、またはEPSSがAct nowのしきい値以上です。 |
| `👀 Watch` | Act nowより弱いシグナルですが、確認・監視する対象です。 |
| `🔕 Low` | 設定したしきい値へ達するシグナルがありません。「脆弱ではない」という意味ではありません。 |
| `🔄 Image content changed` | 参照の確認済みcontent-ID集合が変わりました。パッケージの変化とは独立しており、検出項目がないイメージでも表示する場合があります。 |
| `🆕 New since last scan` | 新しいパッケージと、内容が変化した既知パッケージを含みます。 |
| `✅ Resolved since last scan` | 現在の対象から消えました。パッチ適用済みを証明する表示ではありません。 |
| `📌 Open now` | 最新スキャン後の未解決項目を件数でまとめたものです。 |
| `📌 Open now: unconfirmed — holding previous findings until re-confirmed` | 現在のレポートに検出結果もEOLイメージも1つもなく、Kubernetesの実体未確認スキャン後に前回のパッケージの検出結果を保持しています。現在の検出結果またはEOLイメージが1つでもあれば、通常の件数を表示します。 |
| `⏰ oldest ... unresolved` | 最も古いEOL、Act now、Watchが14日以上残っています。 |
| `<ref> — identity unconfirmed: scanned by reference` | 参照単位の表示では、発見時にDockerのconfig digestで識別できなかった実体を含む参照に付けます。スキャン結果には依存せず、Kubernetesのregistry digestはこの判定では未確認扱いになります。 |
| `<ref> (<12hex>)`または`<ref> (<12hex> linux/amd64)` | 短いdigestと、該当する場合はプラットフォームで、1つの参照に属する複数の実体を区別します。 |
| `⚠️ identity unconfirmed: scanned by reference — a, b` | 発見時にDockerのconfig digestで識別できなかった実体を含む参照の一覧です。スキャン結果には依存しません。この判定ではKubernetesのregistry digestは未確認扱いになるため、すべてのKubernetes参照が並ぶ場合があります。 |
| `⏳ unconfirmed this cycle, holding previous findings — a, b` | 今回のリモートスキャンが成功したものの、実体を固定できなかったスキャン対象を含むKubernetes参照の一覧です。スキャン失敗だけの参照は対象外です。前回の検出結果の有無にかかわらず表示するため、履歴のない初回スキャンでも表示する場合があります。 |
| `⚠️ Scan failures` | その回でスキャンできなかったイメージです。digestやプラットフォームの検証に失敗した場合も含みます。 |
| `⚠️ Vulnerability intel (KEV/EPSS) unavailable — severity-only triage, nothing demoted to low` | どちらの悪用情報源も利用できません。 |
| `⚠️ CISA KEV data unavailable — act-now detection may be incomplete` | KEVを利用できないため、EPSSと深刻度でトリアージしています。 |
| `⚠️ EPSS data unavailable — triage is using KEV and severity only` | EPSSを利用できないため、KEVと深刻度でトリアージしています。 |
| `_Intel data is N day(s) old (feeds unreachable)._` | 更新に失敗したため、検証済みの古いキャッシュを使用しています。 |
| `📋 Weekly full report` | 設定した曜日に追加する現在状態のレポートです。 |
| `📊 Full report in this message's thread` | Bot APIが、このチャンネルメッセージのスレッドへ現在状態を投稿しました。 |
| `🔗 Last full report` | 新しいスレッドは不要だったため、直近の成功済みレポートを参照します。 |

`✅ Actionable now (fixed)`は、トリアージを無効にしたレイアウトだけに表示します。
この場合の「actionable」は修正版が存在するという意味で、トリアージ優先度の
**Act now**とは異なります。

### Slackスレッドの形式

Bot APIのスレッドは`📊 *Full report — YYYY-MM-DD HH:MM*`から始まり、EOL、ACT NOW、
WATCH、LOWの順に表示します。Act nowとWatchのパッケージは詳細を展開します。

```text
📊 *Full report — 2026-08-16 09:00*

*🚨 ACT NOW (1) — exploited or likely to be*
• ghcr.io/example/api:latest
   • openssl 3.0.13 → 3.0.14 (CRITICAL 1 / HIGH 0)  🟢 upgrade: distro security patch
     ↳ CVE-2026-12345 CRITICAL · CISA KEV (exploited in the wild) · EPSS 12%
       Short title supplied by Trivy
       📎 advisory · vendor advisory · 💬 HN (120 pts)
     also: CVE-2026-20001, CVE-2026-20002
     ⏱ open 4 day(s) — first seen 2026-08-12

*🔕 LOW (8)* — no exploitation signal; details in the weekly full report or the webhook payload
```

完全な判定根拠とタイトルを表示するのは、最も強いCVEだけです。追加のCVE IDは
`also:`の後ろへ最大8件表示し、残りは`(+N more)`にまとめます。検出当日は経過日数の
代わりに`first seen today`を表示します。レポートがメッセージの上限を超える場合、
連続する複数の返信へ分割し、継続するセクション見出しには`(cont.)`を付けます。

該当する場合、スレッドの末尾にも同じ実体未確認の一覧を表示します。

```text
⚠️ identity unconfirmed: scanned by reference — legacy:1
```

現在のSlackのLowフッターは週次レポートも参照先として案内しますが、週次レポートでも
Lowは件数のみです。LowのCVEごとの完全な一覧は汎用Webhookで確認します。

### Incoming WebhookとBot APIの違い

| 機能 | Slack Incoming Webhook | Slack Bot API |
| --- | --- | --- |
| チャンネルへサマリーを投稿 | 可能 | 可能 |
| スレッドへ現在のレポートを投稿 | 不可 | 可能 |
| 変化がない日に前回レポートへのリンクを表示 | 不可 | 可能 |

`slack_bot_token`と`slack_channel`を設定すると、チャンネルは変化を確認する場所になります。
検出結果に変化があった日と週次レポートの日は、そのチャンネルメッセージのスレッドへ
現在の状態を投稿します。変化がない日はスレッドを作り直さず、チャンネルの
ハートビートから直近の完全レポートへリンクします。

スレッドではEOL、Act now、Watchを展開します。パッケージごとに、最も強いCVE、
Trivyが提供する場合はタイトル、判定根拠、参照URL、ほかのCVE ID、初回検出からの
経過日数を表示します。Lowは件数だけです。長いレポートはイメージまたは行の境界で
複数の返信に分割します。Slack APIの呼び出しは最大3回試行し、レポートの投稿が
完了した場合だけ新しいスレッド参照を保存します。

Bot APIで初めて通知する場合、通知先チャンネルを変更した場合、または前回の有効な
パーマリンクがない場合は、新しい完全レポートスレッドを作成します。これにより、
次回以降のハートビートが参照できる通知先を確保します。

## 7. 汎用Webhook

`notify.generic_webhook_url`は構造化JSONを受け取るHTTPエンドポイントです。どちらの
Slack通知方式とも併用できます。Discord、Teamsなど、特定サービス用のメッセージへ
整形する機能ではありません。

通知を送る回では、サマリー件数、環境、EOLイメージ、修正状態ごとのセクション、
イメージ実体の識別情報、コンテナとWorkload、パッケージバージョン、更新時の注意度と
優先度、CVE IDと判定根拠、スキャン失敗を含む現在の完全なレポートを送ります。
diffモードの場合は、今回の差分も含みます。コンテナとWorkloadの情報は
このペイロードにだけ含まれ、Slackには表示しません。

### トップレベルのフィールド

| JSONフィールド | 型 | 内容 |
| --- | --- | --- |
| `generated_at` | string | RFC 3339形式のスキャン時刻です。 |
| `environment` | object | 常に含まれます。adapterの種別と、設定されている場合は環境名です。 |
| `summary` | object | イメージ件数です。トリアージ有効時は優先度件数と脅威情報の鮮度も含みます。 |
| `eosl_images` | 文字列の配列または`null` | ベースOSがEOLのイメージです。該当するものがない場合は`null`になることがあります。 |
| `actionable` | イメージオブジェクトの配列 | Trivyのステータスが`fixed`の現在のパッケージグループです。 |
| `watch` | イメージオブジェクトの配列 | Trivyのステータスが`affected`の現在のパッケージグループです。 |
| `wont_fix` | イメージオブジェクトの配列 | Trivyのステータスが`will_not_fix`の現在のパッケージグループです。 |
| `scan_errors` | オブジェクトの配列 | イメージごとのスキャン失敗です。各オブジェクトに文字列フィールド`image`と`error`を含みます。 |
| `diff` | object | 前回のスキャンからの変化です。fullモードでは省略します。 |

### 環境

| JSONフィールド | 型 | 内容 |
| --- | --- | --- |
| `kind` | string | 使用中のadapterに基づく`docker`または`kubernetes`です。 |
| `name` | string | 設定した`environment.name`です。名前のない既定の状態では省略します。 |

### サマリー

| JSONフィールド | 型 | 内容 |
| --- | --- | --- |
| `images_total` | integer | 一意な参照と実体の組み合わせの数です。スキャン失敗も含みます。 |
| `images_affected` | integer | 対象の脆弱性またはEOLのベースOSがあるイメージ数です。 |
| `priority_counts` | object | トリアージ有効時だけ含まれます。`act_now`、`watch`、`low`という整数値のパッケージグループ件数です。 |
| `intel` | object | トリアージ有効時だけ含まれます。脅威情報の利用可否と鮮度です。 |
| `intel.degraded` | boolean | どちらの脅威情報源も利用できないかを示します。 |
| `intel.kev_ok` | boolean | KEVのデータが利用可能かを示します。 |
| `intel.epss_ok` | boolean | EPSSのデータが利用可能かを示します。 |
| `intel.stale_days` | integer | 使用中の古い脅威情報の経過日数です。 |

### イメージオブジェクト

`actionable`、`watch`、`wont_fix`の各エントリーは、その修正状態のセクションに属する
イメージ参照と実体を表します。

| JSONフィールド | 型 | 内容 |
| --- | --- | --- |
| `image` | string | 表示用の参照です。 |
| `severity_counts` | object | `CRITICAL`と`HIGH`という整数値の件数です。 |
| `findings` | 検出結果オブジェクトの配列 | このイメージと修正状態に属するパッケージグループです。 |
| `containers` | コンテナオブジェクトの配列 | このイメージ実体に一致する稼働中コンテナです。該当するものがない場合は空配列で、`null`にはなりません。 |
| `content_id` | string | 実体を確認できたDockerのconfig digest指定スキャンにおける、`sha256:<hex>`形式のconfig digestです。registry digest指定と参照によるスキャンでは省略します。 |
| `registry_digests` | 文字列の配列 | スキャンが成功し、実体を確認できた結果だけから集めた、参照ごとのTrivyの`RepoDigests`の和集合です。`null`にはなりません。 |
| `identity_resolved` | boolean | このエントリーのスキャンで、稼働中イメージの実体を確認できたかを示します。 |
| `scan_target_kind` | string | `content_id`、`registry_digest`、`reference`のいずれかです。 |

コンテナとWorkloadのフィールドは次のとおりです。

| JSONフィールド | 型 | 内容 |
| --- | --- | --- |
| `containers[].name` | string | Dockerでは先頭のスラッシュを取り除き、リンクの別名を除外したコンテナ名です。Kubernetesでは`<namespace>/<pod>/<container>`形式です。 |
| `containers[].workload` | object | Workloadとの対応付けです。常に含まれます。 |
| `containers[].workload.kind` | string | `unknown`、`compose`、`deployment`、`statefulset`、`daemonset`、`job`、`cronjob`、`pod`のいずれかです。常に含まれます。 |
| `containers[].workload.group` | string | Composeのプロジェクト、またはKubernetesのnamespaceです。不明な場合は省略します。 |
| `containers[].workload.name` | string | Composeのサービス、解決したKubernetesのWorkload名、または単独Podの名前です。不明な場合は省略します。 |

参照が曖昧な場合、各イメージエントリーには、その実体に一致するコンテナだけを含めます。
`registry_digests`は参照全体の和集合である一方、`identity_resolved`は個々のエントリーの
状態を示します。

### 検出結果

| JSONフィールド | 型 | 内容 |
| --- | --- | --- |
| `package` | string | パッケージ名です。 |
| `installed` | string | インストール済みバージョンです。 |
| `fixed` | string | 修正版のバージョンです。利用可能な修正版がない場合は`""`です。 |
| `status` | string | `fixed`、`affected`、`will_not_fix`のいずれかです。 |
| `severity_counts` | object | `CRITICAL`と`HIGH`という整数値の件数です。 |
| `upgrade_risk` | string | `""`、`distro_update`、`safe`、`caution`、`unknown`のいずれかです。 |
| `priority` | string | `act_now`、`watch`、`low`のいずれかです。トリアージ無効時は省略します。 |
| `vuln_ids` | 文字列の配列 | 並べ替え済みの脆弱性IDです。 |
| `vulns` | 脆弱性オブジェクトの配列 | 脆弱性ごとの詳細です。 |

### 脆弱性

`vulns`の各オブジェクトには、次のフィールドがあります。

| JSONフィールド | 型 | 内容 |
| --- | --- | --- |
| `id` | string | Slackのリンクマークアップを含まない脆弱性IDです。 |
| `severity` | string | Trivyの深刻度です。 |
| `url` | string | 主要アドバイザリーURLです。取得できない場合は省略します。 |
| `title` | string | Trivyが提供する短いタイトルです。取得できない場合は省略します。 |
| `kev` | boolean | 利用可能なKEVカタログに脆弱性が掲載されているかを示します。 |
| `ransomware` | boolean | KEVのランサムウェアキャンペーンのフラグです。falseの場合は省略します。 |
| `epss` | numberまたは`null` | EPSS確率です。スコアが不明な場合は`null`です。 |
| `priority` | string | `act_now`、`watch`、`low`のいずれかです。トリアージ無効時は省略します。 |
| `refs` | 参照オブジェクトの配列 | 追加の参照情報です。空の場合は省略します。 |
| `refs[].kind` | string | `vendor`または`discussion`です。 |
| `refs[].label` | string | 表示用のラベルです。 |
| `refs[].url` | string | 参照URLです。 |

### 差分

`diff`オブジェクトはdiffモードだけに含まれます。配列が空の場合は`null`ではなく`[]`です。

| JSONフィールド | 型 | 内容 |
| --- | --- | --- |
| `new` | 変化オブジェクトの配列 | 新規または変化したイメージとパッケージのエントリーです。 |
| `resolved` | オブジェクトの配列 | 解消したエントリーです。各オブジェクトに文字列フィールド`image`と`package`を含みます。 |
| `replaced` | 置き換えオブジェクトの配列 | 確認済みcontent-ID集合が変わった参照です。 |
| `new_eosl` | 文字列の配列 | 新たにEOLを検出したイメージ参照です。 |
| `resolved_eosl` | 文字列の配列 | EOLとして記録されなくなったイメージ参照です。 |
| `oldest_open_days` | integer | Lowを含む保持中のすべてのパッケージ検出結果と、保持中のすべてのEOLイメージのうち、最も古い初回検出日からの経過日数です。1日未満は切り捨てます。このフィールドと異なり、トリアージ有効時のSlackハートビートの経過日数はLowを除外します。 |

`new`の各オブジェクトには、次のフィールドがあります。

| JSONフィールド | 型 | 内容 |
| --- | --- | --- |
| `image` | string | イメージ参照です。 |
| `package` | string | パッケージ名です。 |
| `kind` | string | `new`、`escalated`、`new_cves`、`now_fixable`のいずれかです。 |
| `new_cve_count` | integer | 追加されたCVE IDの件数です。`kind`が`new_cves`の場合だけ設定します。ほかの`kind`では、CVE IDが追加されていても省略します。 |
| `critical` | integer | CRITICALの件数です。 |
| `high` | integer | HIGHの件数です。 |
| `priority` | string | `act_now`、`watch`、`low`のいずれかです。利用できない場合は省略します。 |
| `reason` | string | 優先度上昇の判定根拠を示すプレーンテキストです。それ以外の場合は省略します。 |

`replaced`の各オブジェクトには、次のフィールドがあります。

| JSONフィールド | 型 | 内容 |
| --- | --- | --- |
| `ref` | string | イメージ参照です。 |
| `prev_content_ids` | 文字列の配列 | 並べ替え済みの、前回の確認済みcontent-ID集合です。 |
| `content_ids` | 文字列の配列 | 並べ替え済みの、今回の確認済みcontent-ID集合です。 |

互換性を維持するため、トップレベルの検出セクションは修正状態を表します。
`actionable`はTrivyの`fixed`、`watch`は`affected`、`wont_fix`は`will_not_fix`です。
これらは、各パッケージに含まれるトリアージの`priority`フィールドとは別のものです。
特に、Webhookのトップレベルにある`watch`配列と、トリアージ優先度の**Watch**は
同じ意味ではありません。

完全なペイロードを送るのは、前述の通知条件を満たすスキャン回だけです。
`notify_on_clean: false`によって省略された、検出項目も変化もないスキャンでは、
Webhookを呼び出しません。イメージの置き換えがあった場合や、Kubernetesで実体未確認の
参照について以前に記録したパッケージの検出結果を保持している場合も、通知条件を
満たします。保持している履歴がEOLの記録だけの場合は、それだけでは保持に伴う
通知の条件を満たしません。

## 8. トリアージを無効にした場合

`triage.enabled: false`にすると、KEV、EPSS、議論リンクの取得を停止します。
Act now、優先度としてのWatch、Lowという分類は行いません。Slackは修正状態に基づく
次の表示へ切り替わります。

1. EOLのベースイメージ
2. 修正版あり
3. 影響あり、上流の修正待ち
4. 上流では修正予定なし

差分では引き続き、新規、CVE追加、修正版が利用可能、解消を検出します。優先度の
基準を作らないため、優先度上昇の検出は行いません。

## 9. 複数回のスキャン例

あるイメージの`openssl`に、EPSS 0.4%でKEVにはないHIGHのCVEが1件あるとします。

1. 初回スキャンでは、パッケージを**新規**、優先度を**Low**として通知します。
2. 翌日に結果が変わっていなければ、Slackには未解決件数のハートビートだけを送ります。
3. 修正版が公開されると、**修正版が利用可能**としてバージョン変更の注釈とともに
   通知します。
4. 更新を適用する前にCVEがCISA KEVへ追加されると、既知のパッケージであっても
   **Act nowへ優先度上昇**として通知します。
5. コンテナイメージを更新し、そのパッケージが検出されなくなると**解消**として
   通知します。

この流れがKestreLynxの中心です。意味のある変化を通知できるだけの履歴を保持しながら、
調査時に必要な現在の状態も残します。
