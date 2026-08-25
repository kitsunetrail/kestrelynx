# Environment / Workloadモデルの開発

- **状態:** 検討中
- **開始日:** 2026-08-25
- **最終更新:** 2026-08-26

## 目的

[イメージ識別モデル](image-identity-model.md)の開発で保留とした機能を実装する。

- 複数の実行環境(Dockerホスト、将来のKubernetesクラスタなど)を区別する識別
- containerとサービス(Workload)の対応付け
- 複数ホストのスキャン履歴を1つのstateで扱えるように改修

## 実装内容

- **Environmentの安定した識別子**
    - hostname、Docker daemon ID、machine-idといったRuntime由来の値は、コンテナ内からの取得可否や再インストールでの変化があり、再起動やcontainer再作成をまたいで安定しない(イメージ識別モデルの検討で確認済み)。
    - このため、Runtime由来の値ではなく設定で与える安定したscopeキーをEnvironmentの識別子とする方針で設計する。名前の付け方、変更・改名時の扱い、Runtime Adapter種別(Docker / Kubernetes等)との対応付けを決める。
- **Workload / containerの共通モデル**
    - Composeで起動したcontainerはラベルから所属サービスが分かるが、`docker run`等で直接起動したcontainerには対応付け情報がそもそも存在しない。存在しない場合は推測せず「不明」として表現する。
    - 現在、Composeラベルやcontainer IDなどRuntime固有の情報はDocker adapterの内部に留めている。Workloadを表現するために共通モデルへ何を渡すか、その境界を再定義する。
- **スキャン履歴(state)への組み込みと移行**
    - EnvironmentやWorkloadを履歴の主体へ加えると、stateのキー空間の変更または拡張が必要になる。
    - イメージ識別モデルでは「キー不変・フィールド追加」により移行処理なし・再通知なしを実現したが、scopeキーは履歴の主体そのものに関わるため、同じ方法が使えるかを含めて検討する。既存利用者のstateを壊さず、切替時に不要な再通知を起こさない移行方式を設計してからキーを追加する。

## 制約

- 発見処理はread-onlyを維持する。
- 既存のDocker利用者(単一ホスト)は、設定追加なしで現在と同じ基本的なセットアップと通知動作を継続できる必要がある。
- 識別子を取得できない、または対応付けが不明な場合は、推測せずその状態を表現する。
- Runtime固有の識別子を共通解析モデルへ漏らさない。
- 本フェーズではイメージ実体の識別子の意味(image configのdigest)は変えない。EnvironmentとWorkloadはその外側の階層として追加する。

## 更新履歴

### 2026-08-25

- Environment/Workload モデルの実装内容を整理
