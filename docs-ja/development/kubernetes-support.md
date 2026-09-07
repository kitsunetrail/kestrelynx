# Kubernetes対応の開発

- **状態:** 開発中(K3s + containerdの実クラスタでエンドツーエンド検証済み)
- **開始日:** 2026-09-06
- **最終更新:** 2026-09-07

## 目的

KubernetesのWorkloadを、Dockerホスト向けに実装済みの「スキャン → 優先順位付け → 差分通知」へつなぐ。稼働中のイメージをTrivyでスキャンし、CISA KEV・EPSSで検出結果に優先順位を付け、変化をSlack・webhookへ通知する。

このページは、着手時点の計画、確定したadapter設計、実環境での検証結果を記録する。検証で分かったことと、未検証の構成も併記する。

この取り組みに先立つ調査は、[Kubernetes向け脆弱性スキャンツールの調査](kubernetes-scanning-landscape.md)にまとめている。このログでは実装計画と検証結果を扱う。

## 実装予定の範囲

| 領域 | 実装予定の内容 |
| --- | --- |
| 発見処理 | `kube-apiserver`への読み取り専用アクセスでPod・Workloadを取得する。Deployment・StatefulSet・DaemonSet・Job・CronJobを対象とする。管理元を特定できないPodは`unknown`とし、推測で補わない。 |
| 観測情報 | Podの`imageID`・`OwnerReference`を取得し、稼働イメージをWorkloadへ対応付ける。 |
| デプロイ管理元 | 通常のマニフェストとHelm・Argo CD・Fluxのマーカーに基づく検出を対象とし、共通の関係モデルを使って管理元候補を解決する。対応方式は検証できたものから記録する。 |
| イメージ処理 | `imageID`を正規化・検証し、後述の識別規則に従って同一digestの重複スキャンを抑止する。 |
| 導入 | クラスタ内配置と読み取り専用ServiceAccountを第一候補にする。 |
| 優先順位付け・通知 | 発見したイメージとWorkloadを、既存のKEV・EPSSによる優先順位付けと、新規・悪化・解消の差分通知へつなぐ。 |

**初期計画の訂正(9月7日):** デプロイ管理元の検出対象からKustomizeを除外する。Kustomizeはクライアント側のテンプレート処理であり、適用後のオブジェクトにマーカーを残さないため、検出の根拠がない。Helm・Argo CD・Fluxはマーカーに基づく検出対象として維持する。

## 今回の対象外

- Workloadの変更(発見処理は読み取り専用を維持する)
- ノード上のRuntime観測や、特権エージェントの配置
- KestreLynx本体への直接のregistryアクセスの追加(既存の動作と同様に対象外とし、adapterのリモートスキャン経路ではTrivyがイメージ取得を担当する)

## イメージ実体の識別

- digestの種類を区別し、種類を区別しない1つの識別子へ混在させない
- [修正関係モデル](remediation-relations-model.md)で定義する種類付きの`Digest`を共通inventoryモデルに実装済み
    - **`config`**
        - 既存のDocker経路でイメージ実体の識別に使っている**OCI image configのdigest**
    - **`registry`**
        - KubernetesのPodが`imageID`で報告する**registry側のdigest**
- OS・アーキテクチャ・variantを表す`Platform`、実体の識別キーである`EntityKey`、参照と任意のキーから成る観測対象である`ImageSubject`も共通inventoryモデルに実装済み
- registry digestによる同一性の判定には、digestとプラットフォーム(OS・アーキテクチャ)の両方が必要となる(registry digestは複数プラットフォームを指すindexの場合がある)
    - `EntityKey`にプラットフォームが関与するのはregistry digestの場合だけとし、config digestは単独で実体を識別する
    - プラットフォームが不明な場合は実体キーを作らず、それに基づく重複排除や結果の共有は行わない
- 稼働イメージ型の`RunningImage`は型のない文字列に代えて種類付きのconfig digestを保持し、Docker経路の境界検証を`ParseDigest`に集約済み
    - Docker利用者向けの動作に変更がないことを既存テストで確認済み
- 比較規則の詳細と、スキャン対象が観測したイメージ実体に一致することを確認する条件は、リンク先のモデルに記載している

## 初期正式サポートの予定構成

最初の正式サポート対象は**K3s + containerd**とする。用意可能な構成であることを理由で、以下の表は初期の検証計画を残したものであり、実際に確認できた範囲は後述の検証結果に記録する。未検証の構成の対応を保証するものではない。

| 項目 | 初期方針 |
| --- | --- |
| OS・CPU | 初期の検証済みサポートをlinux/amd64に限定し、Ubuntu LTSを基準候補として具体的な版は検証時に確定する。他のプラットフォームも同じコード経路を使うが、未検証と明記する。arm64は実機で継続検証できる場合に検証済みサポートへ追加する。 |
| Kubernetes | 初期の検証済みサポートはKubernetes 1.29以降を対象とする。各コンポーネントの具体的な版は検証時に確定する。 |
| Workload種別 | Deployment・StatefulSet・DaemonSet・Job・CronJob。管理元不明のPodは`unknown`として扱う。 |
| 導入 | クラスタ内配置と読み取り専用ServiceAccount。 |
| レジストリ | 公開イメージに加え、少なくとも1種類の認証付き非公開レジストリのイメージを検証する。 |
| 管理元の対応付け | 共通の関係モデルを維持し、たとえばHelmから始めるなど、実際に検証した方式で対応表を整備する。 |
| 検証 | kindクラスタをAPI fixtureの記録元とし、CIの回帰テストは実クラスタを使わずにそのfixtureで行う。K3s実環境で運用上の動作を確認する。テスト環境での成功だけで、他の配布形態を正式対応とはしない。 |

**初期計画の訂正(9月7日):** 「kindで回帰テストを行う」という記述は、CIでkindを直接動かすのではなく、kindをAPI fixtureの記録元として使う方針を指す。上の検証方針でこの役割を明確にする。

EKS・GKE・AKSは、現時点では継続検証できないため、初期サポート一覧に含めない。実装は共通Kubernetes APIを使い、実環境で認証・権限・レジストリ接続・スキャンを継続検証できる体制が整ってから追加できるようにする。

CRI-Oは未検証の後続候補とする。今後のバージョンと検証結果は、検証の進行に合わせて記録する。

## adapter設計での確定事項

以下にadapterの動作と初期サポートの条件を定める確定事項を記録する。実クラスタでの検証結果は後述する。

- **Kubernetes APIクライアント**
    - ServiceAccountのトークンとCAを使って`kube-apiserver`へ接続する最小限の読み取り専用HTTPクライアントを実装する
    - 必要なAPI操作はGAリソースのページング付きLISTに限られるため、ページング付きLISTのみを行う
    - client-go依存は追加しない(計測では最小限のclient-go Pod一覧取得プログラムが約26.6 MB、現行の全機能入りバイナリが約7.7 MB)
- **スキャン経路**
    - Trivyが`--image-src remote`でレジストリからイメージ内容を取得する
    - digestで固定し、明示的な`--platform`を指定する
    - containerdソケット経由のスキャンは採用しない(対象外としている特権付きホストアクセスとノードごとのエージェントが必要)
- **レジストリの条件**
    - スキャナPodからレジストリへ到達でき、認証できることを前提とする
    - K3sの`registries.yaml`によるミラー・書き換えは初期対応に含めない
    - ノード上に事前ロードされたものしか存在しないイメージは初期対応に含めない
    - レジストリから削除されたdigestは初期対応に含めない
    - エアギャップ環境のクラスタは初期対象外とする
- **リポジトリ部分のないimageID**
    - リポジトリ部分のない`sha256:...`だけのimageIDは、通常の構成として扱い、エラーではなく識別未確定とする(事前ロード・インポートしたイメージで生じ得る)
    - 該当イメージは参照でスキャンし、「イメージ実体未確認」と報告する
    - 検出結果を誤って解消済みとする根拠には使わない
    - このフォールバックでもノード上にしかないイメージは対応対象外とする
- **解消判定の正しさ**
    - イメージ実体を確認できないスキャン結果によって、過去の検出結果を解消済みと報告しない
    - 既存の保守的な保持処理を適用する
    - 通知では「問題なし」とせず、過去の検出結果を保持していることを伝える
- **コンテナの対象**
    - native sidecarである`restartPolicy: Always`付きinit containerをスキャン対象に含める
    - 通常のinit containerは対象外とする
- **初期サポートの目標**
    - linux/amd64とKubernetes 1.29以降を対象とし、実環境での検証済み版は現時点ではKubernetes 1.36のみ
    - 他のプラットフォームも同じコード経路を使うが、未検証と明記する
- **設定**
    - 明示的な`enabled`によるオプトインを必須とする`kubernetes`セクションを追加する
    - Kubernetes adapterとDocker adapterは排他とし、両方を明示的に設定した場合は起動エラーとする

## K3s実環境での検証結果

### 検証環境

- クラスタ構成: 単一ノードのK3s v1.36 (Kubernetes 1.36)
- コンテナランタイム: containerd 2.3
- OS・プラットフォーム: Ubuntu・linux/amd64
- 配置した検証用Workload: Deployment・StatefulSet・DaemonSet・単独Pod・digest固定Pod・Helmリリース・Flux Kustomization管理のDeployment

### 検証済み

- **Nodeのプラットフォーム表記**
    - Nodeの`status.nodeInfo`が`architecture: amd64`・`operatingSystem: linux`を報告し、スキャン側のプラットフォーム比較と同じ語彙になる想定を確認
- **PodのimageID形式**
    - タグ指定とdigest指定のpullの両方で`<normalized repository>@sha256:<hex>`形式を報告し、実装済みのパーサがそのまま受理することを確認(例: `docker.io/library/nginx@sha256:…`)
    - containerd 2.xでは`docker-pullable://`接頭辞を観測せず
- **registry digestによるスキャンと実体確認**
    - Trivyが`--image-src remote --platform linux/amd64 repo@sha256:…`でdigest固定イメージをレジストリから取得してスキャン
    - レポートの`RepoDigests`では`docker.io/library/nginx`が`nginx@…`のように短縮される場合があるが、設計どおりdigestのhex部分での比較により差異を吸収
    - `ImageConfig.{os,architecture}`が指定プラットフォームと一致し、実レジストリに対するスキャン結果の検証(pinning)が成立
- **ServiceAccountとRBAC**
    - 提供する`deploy/kubernetes/`のServiceAccount・読み取り専用RBACマニフェストをそのまま適用して動作を確認
- **エンドツーエンドの動作**
    - 発見処理 → registry digestによるスキャン → 優先順位付き通知が7イメージで成功し、全件で実体確認済み・スキャンエラー0件
    - 通知出力で環境種別`kubernetes`、解決したWorkload種別(ReplicaSetの所有関係をたどったDeployment・StatefulSet・単独Pod・Flux管理のDeployment)、`<namespace>/<pod>/<container>`形式のコンテナ名を確認
- **Helmのマーカー**
    - 実際のHelm 3.19リリースで、検出に使う3条件と一致するラベル`app.kubernetes.io/managed-by: Helm`と2つの`meta.helm.sh/*`アノテーションを確認
- **Flux Kustomizationのマーカー**
    - Fluxのkustomize-controllerが名前・namespaceの組をラベルとして付与し、ラベルに基づく検出方針を確認
    - 実オブジェクトのアノテーションは空

### 検証で分かったこと

- **digest固定Podの表示参照**
    - Podの`status`のimageフィールドは`sha256:…`だけの文字列となり、`imageID`には完全な`repo@sha256:…`が残る
    - 実体の解決とスキャンは`imageID`を通じて動作し、短い文字列が現れるのはそのPodの表示名と履歴キーのみ
    - 既知の挙動として記録
- **接続不備の発見と修正**
    - adapterの取得先とソース種別がスキャンパイプラインからスキャナへ渡されていない不具合が検証で発覚
    - registry digestの実体が参照ベースのスキャンへフォールバックし、実体未確認のスキャンに対する過去の検出結果の保持も効いていなかった
    - パッケージ単体のユニットテストでは検出できなかった(不備はパッケージ間の境界に存在)
    - 不具合を修正し、パッケージをまたぐ回帰テストで固定
    - 実環境検証で見つけるべき種類の不具合に該当

### 未検証

- Argo CDの実際のマーカーキーとtracking-id形式(Argo CDは未導入)
- FluxのHelmRelease側のマーカー(helm-controllerは未導入)
- 認証付き非公開レジストリ
- 長時間稼働するプロセスでのServiceAccountトークンのローテーション
- containerdへ直接事前ロード・インポートしたイメージと、ローカル参照削除後の`imageID`形式
- 複数ノード・混在アーキテクチャのクラスタとlinux/amd64以外のプラットフォーム

## 実装時に検証する課題

以下は[先行調査](kubernetes-scanning-landscape.md)から引き継ぐ4つの課題であり、実クラスタ検証で得られた確認結果を追記する。

- タグが変わった場合や、タグが同じまま参照先の内容が変わった場合に、イメージ実体をどう追跡するか
    - タグ指定とdigest指定のpullでregistry digestを解析でき、実クラスタでregistry digestによるスキャン対象の実体一致を確認した
- 同じdigestを使う複数のWorkloadを、影響を受ける各Workloadの情報を保ちながらイメージへどう関連付けるか
    - エンドツーエンドの通知で、解決したWorkload種別と`<namespace>/<pod>/<container>`形式のコンテナ名を確認した
- 複数のWorkloadやイメージ名が同じ確認済みのイメージ実体を指す場合、スキャンと通知それぞれの重複をどう抑止するか
- ローリング更新などでWorkload集合が変化する場合、何をもって`resolved`と判定し、修正を確認できた状態とイメージやWorkloadが観測できなくなった状態をどう区別するか
    - イメージ実体未確認のスキャンでは過去の検出結果を保持する設計とし、実際の動作は今後検証する

## 次の作業

1. 残る環境依存の挙動を検証する
    - Argo CDのマーカーキーとtracking-id形式
    - FluxのHelmRelease側のマーカー
    - 認証付き非公開レジストリへのアクセス
    - 長時間稼働するプロセスでのServiceAccountトークンのローテーション
    - containerdへ事前ロード・インポートしたイメージとローカル参照削除後の`imageID`形式
2. 実環境で継続検証できる範囲から、複数ノード・混在アーキテクチャのクラスタと他のプラットフォームへ検証済みサポートを広げる
3. kindで記録したAPI fixtureによる回帰テストとK3s実環境での動作確認を通じて残る課題を検証し、確認できた対応構成・管理元の対応方式・制約をこのページへ記録する

## 更新履歴

### 2026-09-07

- デプロイ管理元のマーカー検出まで実装を完了
- K3s + containerdの実クラスタでエンドツーエンドの動作を検証
- 検証中にスキャンパイプラインの接続不備を発見・修正し、パッケージをまたぐ回帰テストを追加
- 共通inventoryの識別モデルの実装、adapter設計の確定、管理元検出からのKustomize除外とkindをAPI fixtureの記録元とする検証方針への訂正

### 2026-09-06

- 実装範囲、イメージ識別の方針、初期サポート対象、検証課題を含む初期計画を作成

---

この記事は、KestreLynxの開発記録です。[KestreLynxについて](../index.md)
