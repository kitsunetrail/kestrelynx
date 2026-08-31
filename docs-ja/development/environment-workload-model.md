# Environment / Workloadモデルの開発

- **状態:** 実装済み(Environmentの識別・Workload/containerの共通モデル・stateへの記録・通知まで。単一stateファイル=単一環境という構造は維持したまま、複数環境の統合は今後の課題)
- **開始日:** 2026-08-25
- **最終更新:** 2026-08-29

## 目的

[イメージ識別モデル](image-identity-model.md)の開発で保留とした機能を実装する。

- スキャン履歴の連続性の単位となるEnvironmentの識別子
- containerとサービス(Workload)の対応付け
- 複数ホストのスキャン履歴を1つのstateで扱えるように改修

## 各モデルの役割

実装の前提として、それぞれのモデルが何のために存在するかを整理する。

### Environment

Environmentは、KestreLynxのインスタンス1つが観測している範囲(現在はDockerホスト1台ぶん、将来はKubernetesクラスタ1つぶん)に人が付ける名前で、**スキャン履歴を束ねる単位**である。ホストの識別情報ではない。hostnameやIPアドレスから導出せず、それらを識別する役割も持たない。

役割は2つある。

- **履歴の連続性を人が宣言する**: サーバーを作り直したり移設したりしても、同じ名前を使い続ければ同じ環境の履歴として連続する
    - 別の環境として扱いたければ名前を変える
    - 「同じ環境かどうか」はhostnameやIPの一致から機械的に判定できる事柄ではなく、運用者の意図なので、設定値として人が与える
- **通知の区別**: 複数のインスタンスが同じSlack channelへ通知している場合に、どの環境の報告かをヘッダで見分けられる

「実際にどのマシンで動いているか」(hostname・IPアドレスなど)は、これとは別の観測事実であり、Environmentの名前が肩代わりするものではない。

### Workload

Workloadは、containerが**どのサービスの一部として動いているか**という役割の対応付けである。脆弱性はイメージ単位で検出されるが、運用者が対応を判断する単位はサービスであり、「このイメージのCVEはどのサービスに影響するのか」に答えるために存在する。同じイメージを複数のサービスが使っていれば、それぞれに影響することが分かる。

Composeで起動されたcontainerはprojectとserviceのラベルからWorkloadが分かる。対応付けが存在しない場合(`docker run`での直接起動など)は推測せず`unknown`として扱う。

### Container

Containerは、**実際に動いている個体**の観測事実である。同じイメージ(あるいは同じWorkload)を複数のcontainerが走らせているとき、それぞれを区別して報告するために存在する。役割(Workload)が不明でも、個体の名前は観測事実として報告できる。

なお、スキャンと履歴の単位はいずれもイメージ実体([ContentID](image-identity-model.md))のままである。WorkloadとContainerは検出結果を読む人のための関連付けレイヤであり、スキャン回数や履歴のキーには影響しない。

## 実装内容

- **Environmentの識別子**
    - 目的
        - スキャン履歴を束ねる単位(Environment)に、再起動・再作成・移設をまたいで安定する識別子を与える
    - 実装
        - 設定で与える`environment.name`をEnvironmentの識別子とした
            - hostname、Docker daemon ID、machine-idといったRuntime由来の値は、コンテナ内からの取得可否や再インストールでの変化があり、再起動やcontainer再作成をまたいで安定しないため識別子には使わない(イメージ識別モデルの検討で確認済み)
        - `environment.name`はDNS-1123 label形式(小文字英数字とハイフン、1-63バイト、英数字で開始・終了)で検証する
            - 空文字列は「無名デフォルト環境」であり、バリデーション失敗とは別の正当な状態として扱う
            - 大文字・ドット・アンダースコア・空白・制御文字は正規化せず拒否する
            - 正規化しない理由: `"Prod"`を`"prod"`へ自動的に寄せてしまうと、2つの設定値が同じ履歴を共有すべきかどうかをツール側が勝手に決めることになるため、その判断は設定を直せる人に委ねる
        - Kind(現状は`docker`固定)は設定項目にしない
            - 設定で持たせると、実際に組み立てたRuntime Adapterとズレた値を記録できてしまうため、コンポジションルート(`main.go`)が実際に採用したadapterに応じて機械的に決める
- **Workload / containerの共通モデル**
    - 目的
        - 「このイメージのCVEはどのサービスに影響するか」に答えるためのcontainer⇔サービス対応付けを、Docker固有の表現(ラベル等)に依存しない共通の型で持てるようにする
    - 実装
        - Compose起動のcontainerは`com.docker.compose.project`(project)と`com.docker.compose.service`(service)の両ラベルが揃って有効な場合のみWorkloadを解決する
            - 片方が欠けている、または値が不正(空・253バイト超・制御文字を含む)な場合は「部分的に分かった」扱いにせず丸ごと`unknown`とする
            - イメージ識別モデルで採った「canonical=falseなのにContentIDだけ非空、のような中間状態を許さない」方針をそのまま踏襲した
        - containerの表示名(`Container.Name`)はWorkloadへ昇格させない
            - Compose serviceのような対応付けの単位ではなく、運用者がcontainerごとに自由に付ける表示名であり、Workloadとは別の観測事実として`Container`にトップレベルで保持する
        - Docker固有の情報(container ID、Compose以外の生ラベル、`Names`配列そのもの)はDocker adapterの内部に留め、共通モデルへは`Container{Name, Workload, Image}`だけを渡す
- **adapter境界: 一次データをimageからcontainerへ**
    - 目的
        - 今回追加する「webhookにcontainerとWorkloadを載せる」機能を実現するために必要な作り替え
            - 従来のDocker adapterはcontainerを列挙した後「動いているイメージの一覧」に要約してから共通部分へ渡しており、containerの情報は境界で捨てていた
            - これまではその情報を使う機能がなかったので捨てても問題なかったが、今回からは通知を組み立てる共通部分がcontainerとWorkloadを必要とするため、要約する前のcontainer単位のまま渡す形へ変えた
    - 実装
        - Docker adapterの`RunningImages`を`RunningContainers`へ置き換えた
            - container単位の観測(どのcontainerが何を実行しているか)を一次データとし、スキャン対象となる distinct image集合(`inventory.DistinctImages`)はそこから導出する派生データにした
        - 追加のDocker API呼び出しは発生しない
            - `/containers/json`の同一レスポンスに含まれる`Names`/`Labels`からWorkloadと表示名を組み立てている
- **stateへの組み込み: キー空間は変更しない**
    - 目的
        - どの環境の履歴かをstateファイル自身が記述できるようにしつつ、命名・改名・命名解除・バージョンの上げ下げのどの操作でも再通知と履歴喪失を起こさない(中心価値「既に知っているものを再通知しない」を壊さない)
    - 実装
        - EnvironmentはFindings/EOSLのキーには加えず、`State.Environment`という自己記述用の追加フィールド(`environment`)として保持するに留めた
            - 検討時点では「scopeキーは履歴の主体そのものに関わるため、イメージ識別モデルと同じ手法(キー不変・フィールド追加のみ)が使えるかは要検討」としていたが、実装では同じ手法をそのまま適用できた
            - `Compute`とdiffルールはこのフィールドを一切読まない
        - この決定の理由は、旧バイナリとの後方互換を保つため
            - ダウングレードしても`environment`フィールドは単に無視されるだけで、再通知は発生しない
            - 命名・改名・命名解除のいずれでも履歴のキーが変化しないため、既存findingsの`FirstSeen`は保持され続け、再通知はゼロになることが構造的に成り立つ
        - 無名環境(`environment.name`未設定)は`Environment`フィールド自体を出力しない(`omitempty`+nilポインタ)
            - これにより、未設定ユーザーのstateファイルはEnvironment導入前とバイト単位で完全に一致する
        - **単一stateファイル=単一環境という構造は変えていない**
            - 複数環境の履歴を1つのstateファイルへ統合することは、本フェーズのスコープ外のまま今後の課題として残っている
            - 将来、複数環境を1つのstateへ束ねる形でキー空間そのものを変える場合は、今回のような「フィールド追加のみ」では済まず、明示的なフォーマット移行と、切替時にダウングレードしても安全に振る舞うための方針を別途設計する必要がある
- **通知: Slackは要約、webhookは全量**
    - 目的
        - 追加した環境・workloadの情報を、人向け(Slack)には要約の密度を壊さない範囲で、機械向け(webhook)には全量、それぞれの出口へ届ける
        - 設定を変えていない既存利用者の出力は変えない
    - 実装
        - Slackの製品ヘッダには、環境名が設定されている場合のみメッセージの先頭に1回だけ挿入する(`🛡️ *KestreLynx* [prod] — ...`)
            - 未設定時は導入前と完全に同じ文言
            - ヘッダを持たないレンダラ(スレッドレポート)には影響しない
        - Workloadやcontainerの情報はSlackには出さず、generic webhookにのみ載せる
            - 「Slack=要約、webhook=全量」という既存方針の延長線上にある
        - webhookペイロードはadditiveに拡張した
            - トップレベルに`environment {kind, name}`(`kind`は常に出力、無名時は`name`のみ省略)を追加し、各imageエントリに`containers`配列(名前+workload)を追加した
            - workloadが不明な場合も`"kind": "unknown"`と明示し省略しない
            - 明示する理由: 旧バージョンのペイロード(containersフィールド自体が存在しない)と、workloadが判定できなかった今回のペイロードを、受信側が区別できるようにするため
            - 既存フィールドは一切変更していない

## 制約

- 発見処理はread-onlyを維持する。
- 既存のDocker利用者(単一ホスト)は、設定追加なしで現在と同じ基本的なセットアップと通知動作を継続できる必要がある。
- 識別子を取得できない、または対応付けが不明な場合は、推測せずその状態を表現する。
- Runtime固有の識別子を共通解析モデルへ漏らさない。
- 本フェーズではイメージ実体の識別子の意味(image configのdigest)は変えない
    - EnvironmentとWorkloadはその外側の階層として追加する

## 更新履歴

### 2026-08-29

- Environment/Workloadモデルを実装した
    - `inventory`パッケージ(新設)にEnvironment/Workload/Container/RunningImageの共通語彙を定義し、Docker adapterの観測単位を`RunningImages`から`RunningContainers`へ切り替えた
    - 設定に`environment.name`(DNS-1123 label形式、任意)を追加し、`analyze.Build`・stateの記録・Slack/webhookの通知まで、Environmentとcontainerの情報を一貫して受け渡すようにした
- stateは既存のキー・versionを変えず、`Environment`フィールドを自己記述用の追加情報として記録するに留めた
    - 既存のstateファイル(本番稼働中のものから作成した複製)が変換なしで読み込めること、無名環境でのSlack出力とstateファイルの出力がバイト単位で不変であることをテストと合わせて確認した
    - 命名・改名・命名解除のいずれの操作でも再通知が発生しないことも確認した
- 複数環境の履歴を1つのstateファイルへ統合することは行っていない
    - 単一stateファイル=単一環境という構造を維持したまま今後の課題として残した

### 2026-08-25

- Environment/Workload モデルの実装内容を整理した

---

この記事は、KestreLynxの開発記録です。[KestreLynxについて](../index.md)
