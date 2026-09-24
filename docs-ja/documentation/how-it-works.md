# KestreLynxの仕組み

KestreLynxは、稼働中イメージのTrivyスキャン結果から、前回との差分と現在の未解決項目を通知する。

- Slackチャンネルでは、既定の`diff`モードで前回からの変化を確認する
- Slack Botのスレッドでは現在の状態、汎用Webhookでは全検出結果と差分を確認する
- 設定方法は[設定](configuration.md)を参照する

スキャン全体の流れは次のとおり。

```text
Dockerホスト / Kubernetesクラスタ
    │
    ▼
実行中のコンテナを取得する（1章）
    │
    ▼
実体ごとに一意なイメージを決める（1章）
    │
    ▼
各イメージをTrivyでスキャンする（1章）
    │
    ▼
イメージ・パッケージ・修正状態ごとに集約する（2章）
    │
    ▼
CISA KEVとEPSSで優先度を判定する（3章）
    │
    ▼
保存済みの状態と比べて変化を判定する（4章）
    │
    ├── Slackサマリー：前回からの変化（5・6章）
    ├── Slackスレッド：現在の未解決項目（6章）
    └── 汎用Webhook：現在の状態と差分の構造化データ（7章）
```

## 1. スキャンの流れ

スキャンの対象は、実行中のコンテナが使うイメージである。1インスタンスでDockerホスト1台、またはKubernetesクラスタ1つを対象とし、停止中コンテナと実行中コンテナが使っていないイメージは対象外とする。

同じ参照と実体の組み合わせは1件にまとめ、同じ参照でもdigestが異なれば別件として扱う。各イメージをTrivyでスキャンし、検出結果をパッケージ単位にまとめる。

対象深刻度は`scan.severity`で指定し、既定値は`HIGH,CRITICAL`である。

### イメージとコンテナの特定

DockerとKubernetesでは、取得できる識別情報に応じてスキャン対象を決める。Dockerへの接続には`docker.socket`を使い、Kubernetesを対象にする場合は`kubernetes.enabled: true`を設定する。

Kubernetesでは、実行中のコンテナと稼働中の`restartPolicy: Always`付きinit containerが対象である。通常のinit containerとephemeral containerは対象外であり、`kubernetes.namespaces`で対象のnamespaceを絞れる。

コンテナとWorkloadの情報は、汎用Webhookだけに含める。対応するWorkloadを特定できない場合は`unknown`として扱う。

### 発見処理の再試行

コンテナ一覧の取得に失敗した回は、保存済み状態を変更せず終了し、次のスケジュールで再試行する。Kubernetesでは一覧取得の一部が失敗した場合も部分結果を使わず、その回の状態を更新しない。

### スキャン対象と実体の検証

実体を特定できるイメージは、その実体を指定してスキャンする。指定したdigestやプラットフォームと結果が一致しない場合は、スキャン失敗として扱う。

実体を特定できない場合はイメージ参照でスキャンし、`identity unconfirmed: scanned by reference`の注釈を付ける。

### 失敗・実体未確認時の扱い

スキャンに失敗した対象は前回の検出状態を保持し、確認できない結果から解消を判定しない。1イメージのスキャンに失敗しても残りのスキャンは続け、失敗はSlackのScan failuresに表示する。

同じ参照の一部だけが失敗した場合も、前回のCVE ID、修正版ありの状態、高い方の優先度を保持する。Kubernetesでは参照によるスキャンが成功しても前回の検出結果を保持し、通常のパッケージもEOLパッケージも解消・解除しない。

### パッケージ単位の集約

検出結果は、イメージ参照と実体、パッケージ、正規化した修正状態ごとにまとめる。同じパッケージでも修正状態が異なれば別グループである。

各グループではCVE IDの重複を除き、バージョン、CRITICAL・HIGH件数、参照URL、グループ内の最高優先度を保持する。状態と差分は、イメージ参照とパッケージの組み合わせで管理する。

同じ参照に複数の実体がある場合は、Slackで`web:1.0 (3f2a9c1b7d4e)`や`web:1.0 (3f2a9c1b7d4e linux/amd64)`のように区別する。

??? note "技術的な詳細"

    スキャン結果はTrivy CLIからJSONで取得する。

    | 項目 | Docker | Kubernetes |
    | --- | --- | --- |
    | コンテナ一覧の取得 | `GET /containers/json`：`Image`、`ImageID`、`Names`、`Labels` | nodes・pods・replicasets・jobsの読み取り専用LIST。`kubernetes.namespaces`の適用はnodes以外 |
    | コンテナ名・実行判定 | `Names`から先頭スラッシュとリンクの別名を除外 | 通常コンテナの実行判定：`state.running` |
    | イメージの実体の識別 | config digest：`ImageID`（`sha256:`＋64桁の16進数のみ） | 参照：`containerStatus.image`。registry digest：`containerStatus.imageID`の`<repo>@sha256:<hex>`（先頭の`docker-pullable://`も許容）。`sha256:...`のみなら参照スキャン |
    | プラットフォーム | — | ノードの`status.nodeInfo.operatingSystem`と`architecture`。variantの推測なし。実体の識別にも使用 |
    | Workload の判定 | 有効な`com.docker.compose.project`と`com.docker.compose.service`の両方でCompose | `ownerReferences`からDeployment・StatefulSet・DaemonSet・CronJob・Job・単独Podへ解決 |
    | Trivy でのスキャン方法 | config digest指定：`--image-src docker`でローカルイメージ | registry digest・プラットフォーム既知：`--image-src remote`と`--platform <os>/<arch>`で`<repo>@sha256:<hex>` |
    | スキャン結果の照合 | `Metadata.ImageID`と指定config digestの一致 | `Metadata.RepoDigests`への指定digestの包含、`Metadata.ImageConfig`のOS・アーキテクチャの一致 |

    - KubernetesのLISTは1ページ最大500オブジェクト、ページ単位で再試行。通信エラー・HTTP 429・サーバーエラーは`Retry-After`と指数バックオフで最大3回、HTTP 410は一覧取得を最初から最大2回やり直し、HTTP 401後はServiceAccountのトークンを再読み込み
    - ServiceAccountのトークンとCAはスキャン回ごとに読み込み
    - 同じ実体を指す別名間では、実体を確認できた結果だけを共有。失敗・未確認なら次の別名で再スキャン
    - 同じ参照の一部だけが失敗した場合は`content_id`を空にし、CVE IDの和集合を保持
    - Slackの参照単位の確認済み判定は、発見時に全実体をDockerのconfig digestで識別できた場合のみ。スキャン結果には非依存、Kubernetesのregistry digestは未確認扱い

## 2. 深刻度・修正状態・EOL

深刻度、修正状態、優先度は、それぞれ異なる意味を持つ情報である。

- 深刻度はTrivyとアドバイザリーが示す影響の大きさ
- 修正状態はTrivyが示す修正版やサポートの状態
- 優先度は悪用情報を踏まえた確認の緊急性

### Statusの扱い

修正状態はTrivyの`Status`で決まり、修正版の有無からは推測しない。`Status`がない場合や空の場合は`unknown`として扱い、未定義のステータスも除外せず`affected`へまとめる。

元のステータスが集約先と異なる場合は、Webhookの`vulns[].status`で確認できる。

| Trivyのステータス | 扱い |
| --- | --- |
| `fixed` | 修正版あり、`fixed`へ集約 |
| `affected` | 影響あり・修正版なし、`affected`へ集約 |
| `will_not_fix` | 上流に修正予定なし、`will_not_fix`へ集約 |
| `fix_deferred` | 修正延期、`affected`へ集約 |
| `end_of_life` | このリリースでは対象CVEがサポート対象外、EOL packageへ集約 |
| `unknown` | 修正状態不明、`affected`へ集約 |
| `under_investigation` | 調査中、`affected`へ集約 |
| `not_affected` | 集約・通知・優先度判定から除外 |

### EOL baseとEOL package

EOLはサポート状態を示し、CVEの優先度とは別に扱う。ベースOSとパッケージでは、次のように表示する。

- EOL baseはTrivyが報告したベースOSのサポート終了で、最上部に表示する
- EOL packageは`end_of_life`のパッケージで、トリアージの有効・無効にかかわらずEOL baseの次に表示する

EOL baseへの基本対応は、サポート中のベースイメージでの再ビルドである。ベースOSもEOLなら、その参照のEOLパッケージをベースOSの行へ畳み込み、`includes N end-of-life package(s)`を付ける。

Act nowのEOLパッケージは、縮退トリアージの場合も含め、畳み込みの有無にかかわらずAct nowに詳細を表示する。畳み込まれていない場合はEOL区分に`🚨 see Act now`を表示し、EOL packageとAct nowの件数が重なる場合がある。

EOL側のWatch・Lowは専用区分だけに表示し、通常のWatch・Lowへ重ねて表示しない。

??? note "技術的な詳細"

    - 同じグループの同じCVE IDに複数の元ステータスがある場合は、集約先と同じ値を優先し、なければ辞書順で先の値を採用する

## 3. 悪用情報に基づくトリアージ

トリアージは、悪用情報を踏まえて確認の優先度を示す機能であり、既定で有効である。パッケージグループには、含まれるCVEの最も高い優先度を付ける。

- CISA KEVは実際の悪用が確認された脆弱性を示す
- EPSSは今後30日以内の悪用活動の確率を示す

EPSSは、影響の大きさや監視環境での悪用可能性を保証するものではない。

### 優先度の規則 {#cve}

通常のトリアージでは、KEVへの掲載、EPSS、深刻度に基づいて次の優先度を付ける。しきい値は`triage.act_now_epss`と`triage.watch_epss`で変更できる。

| 優先度 | 既定の条件 |
| --- | --- |
| **Act now** | KEVに掲載、またはEPSSが`0.10`（10%）以上 |
| **Watch** | Act nowではなく、EPSSが`0.01`（1%）以上、またはCRITICAL |
| **Low** | 上記以外で、KEVになくEPSSがしきい値未満のHIGHも含む |

EPSSスコアがない場合は0として扱わず、EPSS条件を判定から除外する。KEVのランサムウェア情報は判定根拠として表示するが、別の優先度は作らない。

修正状態による優先度の扱いは次のとおりである。

| 修正状態 | 優先度との関係 |
| --- | --- |
| 通知対象の全状態 | Act nowは維持し、修正版がなければ緩和・置き換え・サポート中バージョンを検討 |
| `will_not_fix` | 通常のトリアージではWatchをLowへ下げる |
| `affected`、`fix_deferred`、`under_investigation`、`unknown` | 同じ規則で判定 |
| `end_of_life` | WatchからLowへの引き下げを適用しない |
| 通知対象の全状態 | Lowは修正状態にかかわらず維持 |
| `not_affected` | 判定対象外 |

### フィードと縮退動作

脅威情報を更新できない場合も、検証済みキャッシュを最大7日間使用して判定を続ける。キャッシュは`state.path`と同じ場所の`intel`に保存し、約20時間で更新する。

利用できる情報源が限られる場合は、次のように扱う。

- 片方だけ利用できる場合は、その情報で判定を続け、利用できない情報源を通知する
- 両方利用できない場合は縮退トリアージとなり、CRITICALをAct now、それ以外の選択済み深刻度をWatchにする

縮退中はLowへ分類せず、通常とEOLの優先度上昇通知を抑止する。

`triage.discussion_links`が有効なら、Act nowのCVEに関するHacker Newsの議論を追加する。対象はCVE IDが一致する20ポイント以上の議論であり、議論検索のCVE ID送信は`triage.discussion_links: false`で止められる。

フィード照合でホストの全CVE一覧を外部送信することはない。

??? note "技術的な詳細"

    - KEVとEPSSは一括取得し、CVE IDとの照合はローカルで行う
    - 通常のトリアージは、優先度の表を上から順に判定する
    - 議論検索では、Act nowのCVE IDだけをHacker News検索APIへ送る

## 4. 差分状態と変化の判定

`diff`モードでは、前回から何が変わったかを`state.path`の履歴と今回の結果から確認できる。既定の状態ファイルは`/var/lib/kestrelynx/state.json`であり、保存先ディレクトリを永続化する。

1状態ファイルは1環境用とし、複数インスタンスでは共有しない。`environment.name`を追加・変更・削除しても、履歴や初回検出日はリセットしない。

通常とEOLのパッケージ状態は、同じイメージ参照とパッケージの組み合わせで共存できる。古い状態ファイルも変換せず読めるが、`eol_packages`がない場合は今回のEOLパッケージを初回EOL検出として通知する。

### 差分になる変化

通常のパッケージでは、新規検出、優先度上昇、CVE追加、修正版が利用可能になった変化を通知する。複数の変化が同時に成立した場合は、1つの理由だけを通知する。

- 新規は、前回にイメージ参照とパッケージの組み合わせがない場合
- 優先度上昇は、保存済みの最大優先度より高くなった場合
- CVE追加は、既知のパッケージに新しいCVE IDが加わった場合
- 修正版が利用可能は、前回は修正版がなく、今回は1つ以上ある場合

優先度低下は通知せず保存し、その後の上昇は保存した値を基準に判定する。EOLから通常へ戻っただけでは、新規やCVE追加として扱わない。

EOLパッケージの変化は、通常側とは独立して通知する。

- 新たなEOL検出は、前回のEOL記録がない場合で、通常側からの移動や解除後の再検出も含む
- EOLのAct nowへの上昇は、保存済みのEOL側優先度からAct nowになった場合で、優先度未保存・縮退中・LowからWatchへの上昇は対象外
- EOLのCVE追加は、既知のEOLパッケージに新しいEOLのCVE IDが加わった場合

パッケージの「解消」は、現在の対象から検出項目がなくなったことを意味し、パッチ適用を証明するものではない。前回の組み合わせが、スキャンに成功した今回の通常側にもEOL側にもない場合に解消とする。

通常側の検出結果がすべてEOLへ移っただけでは解消とせず、両側から消えた同じ組み合わせはSlackで1件と数える。EOL解除後も通常側に検出結果が残る場合は、`no longer end-of-life`と表示し、脆弱性の解消とは扱わない。

ベースOSについても、新たなEOL検出と、EOLとして記録されなくなった変化を通知する。

イメージの置き換えはパッケージの変化と独立した差分であり、検出項目がないイメージでも通知する。前回と今回の確認済みcontent-ID集合が両方とも空でなく、異なる場合が対象であり、初回観測は含めない。

全面・一部スキャン失敗やKubernetesの実体未確認で前回の状態を保持する場合は、解消やEOL解除を通知しない。

### 状態の保存と再通知

通知が必要な回は、設定した全通知先への送信に成功してから状態を保存する。一部の通知先だけが失敗した場合も全通知先への送信を試みるため、次回は成功済みの通知先にも同じ変化が届く場合がある。

通知が不要な回は、新しい状態をそのまま保存する。

初回、状態ファイルがない場合、破損、形式バージョン不一致では、新しい状態として開始し、現在のパッケージを新規として通知する。状態ファイルが破損している場合は、警告をログへ出力する。

??? note "技術的な詳細"

    - 通常のパッケージ状態には、初回検出日時、CVE ID集合、修正版の有無、最大優先度、確認済みの単一実体の`content_id`を保存する
    - 参照が曖昧な場合や一部スキャン失敗時は、パッケージ状態の`content_id`を空にする
    - 状態ファイルの`images`マップは参照をキーに、並べ替え済みの`content_ids`、`registry_digests`、`ambiguous`、`last_seen`を記録する
    - ベースOSのEOL初回検出日時は、通常のパッケージ状態とは別に保存する
    - EOLパッケージの初回EOL検出日時・CVE ID集合・最大優先度は、通常のパッケージ状態とは別に保存する
    - 状態ファイルの形式バージョンは`1`のままとする
    - 通常のパッケージの変化は、新規、優先度上昇、CVE追加、修正版が利用可能の順に判定し、同時成立なら最上位の理由だけを通知する
    - 通常側の比較には前回のEOL履歴も使う
    - EOLパッケージの変化は、新たなEOL検出、Act nowへの上昇、EOLのCVE追加の順に判定する
    - 全面・一部スキャン失敗やKubernetesの実体未確認による保持は、通常側とEOL側の移動処理より優先する
    - 状態は一時ファイルへ書いたあとアトミックに置き換える

## 5. 通知を送る条件

既定の`notify.mode: diff`では、変化と現在の未解決件数を通知する。脆弱性がない回も通知するかどうかは、`notify_on_clean`（`notify.notify_on_clean`）で指定する。

- 検出項目と変化があれば、変化と未解決件数を送る
- 検出項目があり変化がなければ、短いハートビートを送る
- 最後の検出項目が解消した回は、解消内容と未解決なしを送る
- 検出項目も変化もなければ、`notify_on_clean: false`では送らない

スキャン失敗やイメージ置き換えは、脆弱性の検出項目がなくても通知する。

Kubernetesの実体未確認で以前のパッケージ検出結果を保持中の場合は、EOLパッケージも含め、変化がなくても通知する。保持履歴がベースOSのEOLだけの場合は、それだけでは実体未確認による保持通知の条件を満たさない。

`notify.full_report_day`で指定した曜日は、通知対象の回にSlackの完全レポートを加える。既定は月曜日で、`never`で無効化できる。週次レポートの曜日でも、`notify_on_clean: false`で検出項目も変化もない回の通知は強制しない。

`notify.mode: full`では差分状態を使わず、検出項目かスキャン失敗があれば毎回現在のレポートを送る。何もない場合は、`notify_on_clean: true`のときだけ送る。

## 6. Slackでの表示

Slackのチャンネルでは変化を、Botのスレッドでは現在の詳細を確認できる。空の区分は表示せず、完全レポートでもLowは件数だけを示す。CVEごとの全データは汎用Webhookで確認する。

ヘッダーのイメージ件数は、次の意味である。

- `images scanned`は失敗も含む一意な参照と実体の組み合わせ数で、別参照がスキャンを共有しても別件として数える
- `affected`は対象脆弱性またはEOLベースOSがあるイメージ数で、失敗だけのイメージは含めない

時刻はプロセスのローカルタイムゾーンを使い、コンテナでは`TZ`で指定する。`environment.name`はチャンネルのヘッダーだけに表示する。

### 区分の順序

差分通知では前回からの変化を、現在状態レポートではEOLと優先度別の未解決項目を確認できる。各通知の表示順は次のとおりである。

- 差分通知は、共通ヘッダー → 実体変更 → 新規EOL base → EOL packageの変化 → 脅威情報源の警告 → 通常の新規・変化 → 解消・EOL解除 → 週次レポートまたはスキャン失敗とOpen now → 実体未確認・保持の注釈 → Botのレポートリンク
- 現在状態レポートは、EOL base → 畳み込まれていないEOL package → Act now → Watch → Low → スキャン失敗・情報鮮度の警告 → 実体未確認・保持の注釈
- Botスレッドは、EOL base → EOL packages → ACT NOW → WATCH → LOWの順

脅威情報源が利用できない警告は、現在状態レポートのPriority行直後、EOL区分より前に表示する。

通常の新規・変化項目は、優先度、イメージ名、パッケージ名の順に並ぶ。`New since last scan (N)`は、通常側で変化したイメージ参照とパッケージの組み合わせ数である。

EOLのAct nowの変化は個別に表示し、それ以外は既存のEOLベースOS参照ごとに件数へまとめる。ベースOSとパッケージが同時に新規EOLとなった場合、Act now以外はベースOSの行へ畳み込み、EOLパッケージの差分見出し件数から除外する。

### Open nowと件数

Open nowは最新スキャン後の未解決状態を示し、保持中の記録も含める。EOL件数を優先度件数より先に表示し、次の単位で数える。

- EOL baseは保持するEOLベースイメージの参照数
- EOL packageはベースOSへ畳み込まれないイメージ参照とパッケージの組み合わせ数
- Act now・Watch・Lowは同じ参照とパッケージを1件とし、通常側かEOL側がAct nowならAct now、それ以外は通常側の優先度で数える

EOL側のWatch・Lowは優先度件数へ加算しない。EOL packageとAct nowの件数は重なる場合がある。

現在状態レポートのPriority行は、修正状態別のパッケージグループ数を示すため、同じパッケージが複数件になる場合がある。

Open nowの表示は、今回の検出結果と保持状態によって異なる。

- 今回のレポートに検出結果かEOLベースイメージがあれば、件数を表示する
- 今回も保持状態にも検出項目がなく、実体未確認による保持もない場合だけ、`🎉 Open now: none — all clear`と表示する
- 今回の検出結果もEOLベースイメージもなく、Kubernetesの実体未確認でパッケージを保持中なら、未確認による保持を表示する
- 上記以外で今回の検出項目がなく保持記録があれば、次の成功スキャンまでの保持を表示する

### 未解決の経過日数

ハートビートの経過日数は、対象項目の最も古い初回検出日から数える。1日以上で日数、14日以上で時計マークを表示し、保持中の記録も対象に含める。

- トリアージ有効時は、通常のAct now・Watch、EOL base、畳み込まれていないEOL package、畳み込まれていてもAct nowのEOL packageが対象
- トリアージ無効時は、通常の全パッケージとEOLが対象

トリアージ有効時は通常のLowを除外し、EOLを含む場合も`oldest act-now/watch unresolved N day(s)`と表示する。無効時は`oldest unresolved N day(s)`と表示する。

EOLパッケージには初回EOL検出日を使う。ベースOSへ畳み込んだAct now以外のEOLパッケージはベースOSの初回EOL検出日で数え、Act nowなら畳み込まれていてもパッケージの初回EOL検出日を対象に含める。

### ラベルの意味

ラベルから、変更内容、対応の優先度、結果を確認できなかった理由を読み取れる。緑色の更新アイコンはバージョン変更の種類を示すだけで、安全性を保証するものではない。

CRITICAL・HIGHは、パッケージと修正状態のグループ内で重複を除いたCVE ID件数である。

| ラベル | 意味 |
| --- | --- |
| `⛔ EOL base` | ベースOSのサポート終了 |
| `⛔ EOL package` | このリリースでは対象CVEがサポート対象外 |
| `⛔ N EOL base` | Priority行のEOLベースイメージ件数 |
| `⛔ N EOL package` | Priority行のEOLグループ件数で、ベースOSへ畳み込んだ分を除外 |
| `🚨 N act now` | Priority行のAct nowグループ件数で、Act nowのEOLグループも含む |
| `⛔ Package end-of-life (N) — vendor reports these CVEs as out of support for this release` | 現在状態のEOLパッケージ区分 |
| `⛔ New: package end-of-life (N) — vendor reports these CVEs as out of support for this release` | EOLパッケージの新規検出・Act nowへの上昇・CVE追加 |
| `⛔ EOL packages (N) — vendor reports these CVEs as out of support for this release` | スレッドのEOLパッケージ区分 |
| `🚨 Act now` | 悪用確認済み、またはEPSSがしきい値以上で、縮退時はCRITICALも対象 |
| `👀 Watch` | 確認・監視する対象 |
| `🔕 Low` | しきい値に達するシグナルがない状態で、脆弱性がない意味ではない |
| `🔄 Image content changed` | 確認済みcontent-ID集合の変更 |
| `🆕 New since last scan` | 新規パッケージと変化した既知パッケージ |
| `✅ Resolved since last scan` | パッケージ・EOL baseの解消、EOL packageの解除 |
| `📌 Open now` | 最新スキャン後の未解決状態 |
| `📌 Open now: unconfirmed — holding previous findings until re-confirmed` | 今回は検出項目がなく、Kubernetesの実体未確認で前回の通常・EOLパッケージを保持中 |
| `📌 Open now: not re-scanned — holding previous findings until the next successful scan` | 今回は検出項目がなく、実体未確認の表示条件以外で前回の記録を保持中 |
| `⏰ oldest ... unresolved` | 対象項目が14日以上未解決 |
| `<ref> — identity unconfirmed: scanned by reference` | 発見時にDockerのconfig digestで識別できない実体を含む参照 |
| `<ref> (<12hex>)`、`<ref> (<12hex> linux/amd64)` | 同じ参照の複数実体をdigestとプラットフォームで区別 |
| `⚠️ identity unconfirmed: scanned by reference — a, b` | 発見時にDockerのconfig digestで識別できない実体を含む参照の一覧で、スキャン結果に依存せず、Kubernetes参照がすべて並ぶ場合もある |
| `⏳ unconfirmed this cycle, holding previous findings — a, b` | リモートスキャン成功でも実体を固定できない対象を含むKubernetes参照で、失敗だけの参照は除外し、履歴なしでも表示する場合がある |
| `⚠️ Scan failures` | スキャン失敗で、digest・プラットフォーム検証失敗も含む |
| `⚠️ Vulnerability intel (KEV/EPSS) unavailable — severity-only triage, nothing demoted to low` | 両情報源が利用不能で、深刻度だけで判定しLowへ下げない |
| `⚠️ CISA KEV data unavailable — act-now detection may be incomplete` | EPSSと深刻度で判定し、Act now検出が不完全な可能性 |
| `⚠️ EPSS data unavailable — triage is using KEV and severity only` | KEVと深刻度で判定 |
| `_Intel data is N day(s) old (feeds unreachable)._` | 更新できず検証済みの古いキャッシュを使用中 |
| `📋 Weekly full report` | 設定曜日の現在状態レポート |
| `📊 *Full report — YYYY-MM-DD HH:MM*` | Botスレッドの現在状態レポートの見出し |
| `📊 Full report in this message's thread` | Botが今回のスレッドへ現在状態を投稿済み |
| `🔗 Last full report` | 直近の成功済みレポートへのリンク |
| `✅ Actionable now (fixed)` | トリアージ無効時の修正版あり区分で、Act nowとは別 |

| パッケージ・変化のラベル | 意味 |
| --- | --- |
| `🟢 upgrade: distro security patch` | OSパッケージの更新で、ディストリビューションのリビジョンとして扱いSemVer比較しない |
| `🟢 upgrade: low-risk` | 言語パッケージのメジャーバージョンが増えない変更 |
| `🟠 upgrade: major version bump — needs care` | 言語パッケージのメジャーバージョンが増え、互換性を壊す可能性がある変更 |
| `⚪ upgrade: risk unknown` | バージョンを確実に解析できない状態 |
| `[lang]` | Trivyが言語依存パッケージと分類した項目 |
| `(no fix available)` | 通常の修正状態で修正版なし |
| `⬆️ escalated to ACT NOW/WATCH` | 既知パッケージの最大優先度が上昇 |
| `new: CVE-…, CVE-… (+N more)` | 追加CVEのリンクを1行最大3件、残りは件数で表示 |
| `fix now available` | 前回は修正版なし、今回は1つ以上あり |
| `(end-of-life: no fix planned for this release)` | このリリースでは対象CVEがサポート対象外 |
| `🚨 see Act now` | EOLパッケージの詳細はAct now区分に表示 |
| `includes N end-of-life package(s)` | ベースOSの行へ畳み込んだEOLグループ件数 |
| `includes N newly end-of-life package(s)` | 新規EOL baseへ畳み込んだAct now以外の新規EOLパッケージ件数 |
| `N package(s) newly end-of-life (base OS already EOL)` | 既存EOL baseのAct now以外の新規EOLパッケージ件数 |
| `N end-of-life package(s) with new CVEs (base OS already EOL)` | 既存EOL baseのAct now以外のEOLパッケージでCVEが増加 |
| `no longer end-of-life` | EOL解除後も通常側に検出結果あり |

| 判定根拠・参照のラベル | 意味 |
| --- | --- |
| `CISA KEV (exploited in the wild)` | 利用可能なKEVカタログに掲載 |
| `EPSS N%` | EPSS確率で、スコアなしは`n/a`、非常に小さい値は`<0.1%`、非常に大きい値は`>99%` |
| `🧨 ransomware campaign` | CISAがランサムウェアキャンペーンでの使用を確認 |
| `severity only (intel unavailable)` | 両情報源が利用不能で深刻度のみを使用 |
| `no fix yet, consider mitigation` | `affected`グループに修正版がなく緩和策を検討 |
| `upstream won't fix, consider replacing` | `will_not_fix`のため置き換えなどを検討 |
| `end-of-life: no fix planned for this release, consider a supported version` | EOLパッケージのサポート中バージョンを検討 |
| `📎 advisory` | Trivyの主要アドバイザリー |
| `vendor advisory` | KEVのnotesにあるベンダーまたはCISAの参照 |
| `💬 HN (N pts)` | 条件を満たすHacker Newsの議論とポイント数 |

### 詳細とスレッド

Act nowには最も強いCVEの根拠を示し、Watchは簡潔に表示する。チャンネルでは他のCVEを`(+N more CVE(s) in this package)`にまとめる。

Act now以外の変化には`CVE-ID · KEV/EPSS`を付け、情報を使えない場合は`CVE-ID SEVERITY`を付ける。新規ID一覧の行では、この表記を省略する。

判定根拠、Watchの理由、`also:`のCVE IDはNVDへのリンクである。GHSAやDLAなどは通常のテキストで表示する。

スレッドでは、最も強いCVEのタイトル・根拠・URL・経過日数を確認できる。他のIDは`also:`に最大8件を示し、残りは`(+N more)`にまとめる。

検出当日は`first seen today`と表示する。長いレポートは複数返信へ分け、継続見出しに`(cont.)`を付ける。

通知方式と送信先は、次の設定で指定する。

- `notify.slack_webhook_url`はチャンネル通知だけに対応する
- `slack_bot_token`（`notify.slack_bot_token`）はBot通知を有効にし、`slack_channel`と組み合わせてスレッド投稿と前回レポートへのリンクを使えるようにする
- `slack_channel`（`notify.slack_channel`）はBotの通知先チャンネルを指定する

Botは変化があった日と週次レポートの日に現在状態をスレッドへ投稿し、変化がない日は直近のレポートへリンクする。初回通知、チャンネル変更、有効な前回パーマリンクがない場合も、新しいスレッドを作る。

変化がない日の代表例は次のとおりである。

```text
No changes since last scan.
📌 Open now: 🚨 1 act-now / 👀 2 watch / 🔕 8 low
_Details in the generic webhook payload, or in the weekly full report._
🔗 Last full report → thread
```

Act nowの判定根拠は次のように読む。

```text
↳ CVE-2026-12345 CRITICAL · CISA KEV (exploited in the wild) · EPSS 12%
```

??? note "技術的な詳細"

    - Slackは通常の`mrkdwn`テキストを使う
    - 最も強いCVEは、優先度、EPSS取得済みか、EPSSの高さ、CVE IDの順で決める
    - Slack APIは最大3回試行する
    - 新しいスレッド参照は、レポート投稿完了後だけ保存する

## 7. 汎用Webhook

汎用Webhookでは、現在の完全なレポートを構造化JSONで取得できる。`notify.generic_webhook_url`へ通知条件を満たした回だけ送り、`diff`モードでは差分も含める。

Low、Slackで畳み込むEOLパッケージ、コンテナ、Workloadも確認できる。Slackのどちらの方式とも併用できるが、DiscordやTeams専用のメッセージ形式には変換しない。

トップレベルの`watch`は修正状態の区分であり、優先度のWatchとは別である。`not_affected`は、どの検出セクションにも含めない。

### トップレベル・環境

トップレベルでは、スキャン時刻、環境、修正状態別の検出結果、失敗、差分を確認できる。`environment`は常に含み、環境名がない場合は`name`だけを省略する。

| フィールド名 | 型 | 意味 |
| --- | --- | --- |
| `generated_at` | string | RFC 3339形式のスキャン時刻 |
| `environment` | object | adapter種別と任意の環境名 |
| `environment.kind` | string | `docker`または`kubernetes` |
| `environment.name` | string | `environment.name`の値で、未設定なら省略 |
| `summary` | object | 件数と脅威情報の状態 |
| `eosl_images` | 文字列の配列または`null` | EOLベースイメージで、該当なしなら`null`の場合あり |
| `actionable` | イメージオブジェクトの配列 | `fixed`の現在のグループ |
| `watch` | イメージオブジェクトの配列 | `affected`へ正規化した現在のグループ |
| `wont_fix` | イメージオブジェクトの配列 | `will_not_fix`の現在のグループ |
| `eol_packages` | イメージオブジェクトの配列 | 全`end_of_life`グループで、空なら`[]` |
| `scan_errors` | オブジェクトの配列 | イメージごとのスキャン失敗 |
| `scan_errors[].image` | string | イメージ参照 |
| `scan_errors[].error` | string | エラー内容 |
| `diff` | object | 今回の差分で、fullモードでは省略 |

### サマリー

`summary`ではイメージ件数を確認でき、トリアージ有効時は優先度件数と脅威情報の状態も確認できる。

`priority_counts`は、EOLパッケージをAct nowの場合だけ加算する。そのため`eol_packages`と件数が重なり、3値の合計は全グループ数とは限らない。

| `summary`のフィールド名 | 型 | 意味 |
| --- | --- | --- |
| `images_total` | integer | スキャン失敗を含む一意な参照と実体の組み合わせ数 |
| `images_affected` | integer | 対象脆弱性またはEOLベースOSがあるイメージ数 |
| `priority_counts` | object | トリアージ有効時だけ含む、整数値の`act_now`、`watch`、`low`によるパッケージグループ件数 |
| `intel` | object | トリアージ有効時だけ含む脅威情報の利用可否と鮮度 |
| `intel.degraded` | boolean | 両情報源が利用不能か |
| `intel.kev_ok` | boolean | KEVを利用可能か |
| `intel.epss_ok` | boolean | EPSSを利用可能か |
| `intel.stale_days` | integer | 使用中の古い脅威情報の経過日数 |

### イメージとコンテナ

`actionable`、`watch`、`wont_fix`、`eol_packages`の各エントリーは、修正状態ごとの参照と実体を表す。参照が曖昧でも、`containers`にはその実体に一致するコンテナだけを含める。

`registry_digests`は参照全体の和集合であり、`identity_resolved`は各エントリーの状態を示す。

| フィールド名 | 型 | 意味 |
| --- | --- | --- |
| `image` | string | 表示用の参照 |
| `severity_counts` | object | 整数値の`CRITICAL`・`HIGH`件数 |
| `findings` | 検出結果オブジェクトの配列 | このイメージと修正状態のパッケージグループ |
| `containers` | コンテナオブジェクトの配列 | 一致する稼働中コンテナで、該当なしは`[]` |
| `content_id` | string | 実体を確認できたDockerのconfig digest指定スキャンの`sha256:<hex>`で、registry digest指定・参照スキャンでは省略 |
| `registry_digests` | 文字列の配列 | 成功して実体確認できた結果の`RepoDigests`を参照ごとに集めた和集合で、`null`にはならない |
| `identity_resolved` | boolean | このスキャンで稼働中イメージの実体を確認できたか |
| `scan_target_kind` | string | `content_id`、`registry_digest`、`reference` |
| `containers[].name` | string | Dockerは先頭スラッシュ・リンク別名を除いた名前、Kubernetesは`<namespace>/<pod>/<container>` |
| `containers[].workload` | object | 常に含むWorkload対応情報 |
| `containers[].workload.kind` | string | 常に含む`unknown`、`compose`、`deployment`、`statefulset`、`daemonset`、`job`、`cronjob`、`pod`のいずれか |
| `containers[].workload.group` | string | Composeプロジェクトまたはnamespaceで、不明なら省略 |
| `containers[].workload.name` | string | Composeサービス、解決したWorkload名、単独Pod名で、不明なら省略 |

### 検出結果と脆弱性

`findings`ではパッケージグループを、`vulns`では個々の脆弱性を確認できる。検出結果と脆弱性の`priority`は、トリアージ無効時に省略する。

`vulns[].status`が省略されている場合は、検出結果の`status`と同じ値として読む。

| 検出結果のフィールド名 | 型 | 意味 |
| --- | --- | --- |
| `package` | string | パッケージ名 |
| `installed` | string | インストール済みバージョン |
| `fixed` | string | 修正版バージョンで、なければ`""` |
| `status` | string | `fixed`、`affected`、`will_not_fix`、`end_of_life` |
| `severity_counts` | object | 整数値の`CRITICAL`・`HIGH`件数 |
| `upgrade_risk` | string | `""`、`distro_update`、`safe`、`caution`、`unknown` |
| `priority` | string | `act_now`、`watch`、`low` |
| `vuln_ids` | 文字列の配列 | 並べ替え済み脆弱性ID |
| `vulns` | 脆弱性オブジェクトの配列 | 脆弱性ごとの詳細 |

| 脆弱性のフィールド名 | 型 | 意味 |
| --- | --- | --- |
| `id` | string | Slackリンク表記を含まない脆弱性ID |
| `severity` | string | Trivyの深刻度 |
| `status` | string | 集約先と異なる元のTrivyステータスだけを含み、元の`Status`なしは`unknown` |
| `url` | string | 主要アドバイザリーURLで、取得できなければ省略 |
| `title` | string | Trivyの短いタイトルで、取得できなければ省略 |
| `kev` | boolean | 利用可能なKEVカタログに掲載されているか |
| `ransomware` | boolean | KEVのランサムウェアフラグで、`false`なら省略 |
| `epss` | numberまたは`null` | EPSS確率で、不明なら`null` |
| `priority` | string | `act_now`、`watch`、`low` |
| `refs` | 参照オブジェクトの配列 | 追加参照で、空なら省略 |
| `refs[].kind` | string | `vendor`または`discussion` |
| `refs[].label` | string | 表示ラベル |
| `refs[].url` | string | 参照URL |

### 差分

`diff`では、前回からの変化を種類別に確認できる。diffモードだけに含み、空の配列は`null`ではなく`[]`を返す。

| `diff`のフィールド名 | 型 | 意味 |
| --- | --- | --- |
| `new` | 変化オブジェクトの配列 | 通常側の新規・変化 |
| `resolved` | オブジェクトの配列 | 解消した組み合わせ |
| `resolved[].image` | string | イメージ参照 |
| `resolved[].package` | string | パッケージ名 |
| `replaced` | 置き換えオブジェクトの配列 | 確認済みcontent-ID集合が変化した参照 |
| `new_eosl` | 文字列の配列 | 新規EOLベースイメージ参照 |
| `resolved_eosl` | 文字列の配列 | EOLとして記録されなくなった参照 |
| `new_eol_packages` | EOL変化オブジェクトの配列 | Slackで畳み込むものも含むEOLの新規・変化 |
| `resolved_eol_packages` | EOL解除オブジェクトの配列 | EOL区分からなくなったパッケージ |
| `oldest_open_days` | integer | 通常の全パッケージ、EOL base、畳み込まれていないEOL package、畳み込まれていてもAct nowのEOL packageの最古の初回検出日からの日数で、1日未満は切り捨て |

`oldest_open_days`は保持中の記録と通常のLowも含むため、Slackのトリアージ有効時の経過日数とは対象が異なる。EOLパッケージには初回EOL検出日を使い、畳み込まれたAct now以外はベースOSの初回EOL検出日で数える。

| `new[]`のフィールド名 | 型 | 意味 |
| --- | --- | --- |
| `image` | string | イメージ参照 |
| `package` | string | パッケージ名 |
| `kind` | string | `new`、`escalated`、`new_cves`、`now_fixable` |
| `new_cve_count` | integer | `new_cves`の場合だけ含む追加CVE件数 |
| `new_cve_ids` | 文字列の配列 | `new_cves`の場合だけ含む追加IDで、Slackリンク表記なし、長さは`new_cve_count`と同じ |
| `critical` | integer | CRITICAL件数 |
| `high` | integer | HIGH件数 |
| `priority` | string | `act_now`、`watch`、`low`で、利用できなければ省略 |
| `reason` | string | 優先度上昇の根拠を示すプレーンテキストで、それ以外は省略 |

| `new_eol_packages[]`のフィールド名 | 型 | 意味 |
| --- | --- | --- |
| `image` | string | イメージ参照 |
| `package` | string | パッケージ名 |
| `kind` | string | 新規EOLの`eol_new`、CVE追加の`eol_new_cves`、Act nowへの上昇の`eol_escalated` |
| `new_cve_ids` | 文字列の配列 | `eol_new_cves`の場合だけ含む並べ替え済み追加EOL IDで、Slackリンク表記なし |
| `critical` | integer | 今回のEOLグループのCRITICAL件数 |
| `high` | integer | 今回のEOLグループのHIGH件数 |
| `priority` | string | `act_now`、`watch`、`low`で、トリアージ無効時は省略 |
| `reason` | string | `eol_escalated`の場合だけ含む判定根拠 |

EOL変化には`new_cve_count`がないため、追加件数は`new_cve_ids`の長さで確認する。

| `resolved_eol_packages[]`のフィールド名 | 型 | 意味 |
| --- | --- | --- |
| `image` | string | イメージ参照 |
| `package` | string | パッケージ名 |
| `still_open` | boolean | 同じ参照とパッケージに通常側の検出結果が残れば`true`で、`false`でも省略しない |

| `replaced[]`のフィールド名 | 型 | 意味 |
| --- | --- | --- |
| `ref` | string | イメージ参照 |
| `prev_content_ids` | 文字列の配列 | 並べ替え済みの前回の確認済みcontent-ID集合 |
| `content_ids` | 文字列の配列 | 並べ替え済みの今回の確認済みcontent-ID集合 |

### 後方互換

既存のフィールドと修正状態別の構造は維持する。修正状態の区分と`priority`は分けて扱う。

- `actionable`は`fixed`を表す
- `watch`は`affected`への集約を表す
- `wont_fix`は`will_not_fix`を表す
- `eol_packages`は`end_of_life`を表す

`diff.new[].kind`は、`new`、`escalated`、`new_cves`、`now_fixable`のまま変更しない。

EOL変化は別配列と別の`kind`で表し、`diff.new_eol_packages`と`diff.resolved_eol_packages`は空でも`[]`を返す。EOL対応は既存フィールドを維持し、新しい配列と省略可能な`vulns[].status`の追加で表す。

## 8. トリアージを無効にした場合

`triage.enabled: false`では、優先度の分類を停止し、Slackで修正状態別に結果を確認する。KEV・EPSS・議論リンクの取得も停止する。

Slackの表示順は、EOL base → EOL package → 修正版あり → 上流の修正待ち → 上流では修正予定なしである。EOL区分とベースOSへの畳み込みは有効時と同じであり、上流の修正待ちには`affected`、`fix_deferred`、`under_investigation`、`unknown`を含む。

Open nowは、保持中の記録を含むEOL件数を先に表示する。続くCRITICAL・HIGH・影響イメージ数は今回の検出結果から数え、今回の検出項目がなく保持だけがある場合は、有効時と同じ保持表示を使う。

新規、CVE追加、修正版が利用可能、解消、EOLの新規・CVE追加・解除は引き続き検出する。通常の優先度上昇とEOLパッケージのAct nowへの上昇は検出しない。
