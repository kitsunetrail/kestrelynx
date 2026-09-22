# ランタイム探索リファレンス

[English](REFERENCE.md) | **日本語**

- 目的、必要な環境、自動実行コマンド、ケースの選択は [README](README.ja.md) を参照
- この文書のコマンドはリポジトリのルートから実行する
- 手動実行の例では生成データを Git の追跡対象外である `./out/` に保存する
- 自動実行の保存先は `experiments/runtime-discovery/out/`
- 観測、ログ、スキャン、結果はコミットしない

## 入出力

### 収集する入力

- `collect` は実行時の観測と、ファイルからパッケージへの対応付けに使う補助入力を保存する
- procfs の読み取り対象は `/proc/<pid>/exe`、`maps`、`fd`、`status`、`net/tcp`、`net/tcp6`
- プロセスの識別情報、名前空間の識別情報、cgroup のメタデータも読み取る
- コンテナのファイルは `/proc/<pid>/root` 経由で読み取る
- パッケージメタデータの対象は dpkg、distroless の `status.d`、apk
- Docker API にはコンテナの列挙、詳細情報の取得、`top` の GET リクエストだけを送る
- `collect` が GET だけを使う場合も、Docker ソケットへのアクセス自体はコンテナ制御を許可し得る
- ケースヘルパーは別途コンテナのビルド、起動、詳細情報の取得、削除を行う
- フィクスチャチェックと事前チェックは Docker が報告する PID を使ってホスト procfs を読む
- これらのチェックは `docker exec` を使わないため distroless でも動作する
- ケース 4 の準備完了チェックでは別途 `docker exec` で `pg_isready` を実行する

### 補助入力とファイル記述子

- `-aux-inputs=true` では対応付け用の入力を各観測の `auxiliary_inputs` に保存する
- 入力には Python の検索ディレクトリ、`.dist-info/RECORD` の一覧、`.egg-info` を使うディストリビューションを含む
- Python と `node_modules` の構成、シンボリックリンクの参照先、OS パッケージのパス索引、`/usr` 統合に伴うリンク、プロセスごとの生の `mountinfo` も含む

- `symlinks` にはモジュールツリー内、`/etc/localtime`、`/etc/alternatives` と一般的な bin/sbin ディレクトリの直下、OS パッケージデータベースのファイル一覧にあるリンクを記録する
- 対象の一般的なディレクトリは `/bin`、`/sbin`、`/usr/bin`、`/usr/sbin`、`/usr/local/bin`、`/usr/local/sbin` で、再帰せず直下のエントリを調べる
- 各リンクはパスと生の `readlink` 結果を保持し、参照先が相対か絶対かも保存する
- `owned_paths[].is_dir` は観測時点でそのパス自体がディレクトリだったかを示し、末尾要素のシンボリックリンクをたどらない `lstat` の結果を使う
- パスと所有者の索引をキャッシュから取得した場合も、ディレクトリ属性とパッケージデータベース由来のリンク先は補助入力の読み取りごとに調べ直す
- ディレクトリ属性は補助入力の世代の指紋に含め、パッケージデータベースが変わらなくてもディレクトリからファイルへの変化を別世代として識別できるようにする
- 追加リンクの収集枠は `/etc/localtime`、`/etc/alternatives`、一般的な bin/sbin の直下、パッケージデータベース由来のリンクで共有し、この順で調べる
- 追加リンクの収集枠を使い切ると `extra_symlinks` の切り詰めを記録し、ディレクトリ属性の調査は継続する
- ディレクトリ構成に保存するのはパスであり、モジュールの内容は含まない
- Python の検索ディレクトリはコンテナのインタープリターを起動せず、ファイルシステムの調査で特定する
- 各読み取りはマウントビュー、補助入力の世代、パッケージデータベースの世代、収集時刻、最初と最後の検出時刻、サンプル ID、読み取りに使った PID を記録する
- 言語パッケージの構成は OS パッケージデータベースとは独立に変化するため、サンプリング時に再読み取りする
- 補助入力の世代が同じ場合は保存済みの読み取り結果を共有する
- 変化した構成は別途保持する
- OS のパス索引はパッケージデータベースの世代ごとにキャッシュする
- OS パッケージデータベースが存在しない場合も補助入力を収集する
- 上限付きの読み取りでは切り詰めとエラーを記録する
- 不完全な入力にパスがないことだけでは、そのパスを所有するパッケージがないとは確定できない
- プロセスの `file_descriptors` には通常のファイルシステム記述子も含む
- 各記述子は番号、パス、削除済みマーカー、解決済みパス、解決エラーを記録する
- パス解決レコードは記述子による証拠を `fd` とし、`exe` や `maps` と区別する
- ソケット記述子はソケット inode を提供する
- パイプと匿名 inode の参照先はファイルとパッケージの照合対象から除外する
- アーカイブの記述子は `opened` の観測を裏付けるが、特定のクラスの実行を証明しない

### 保存ファイルと実行キー

- 次のスキャン・照合・CSV のファイル名は `case-run.sh` の出力で、手動例では `trivy.json`、`match.json`、`csv/` を使う

| ファイル | 内容 |
| --- | --- |
| `collect/<container>__<run-key>.json` | コンテナごとの観測 |
| `collect/manifest.json` | コンテナの観測ファイル名と収集全体のエラー |
| `collect/ready.json` | 既定の登録準備完了レポート |
| `case.json` | 保存したケース定義と正解データの宣言範囲 |
| `trivy_hc.json` / `trivy_all.json` | 稼働中のイメージ ID を指定したスキャン（HIGH/CRITICAL と全重大度） |
| `gtb.json` | JSON オブジェクト形式の独立した正解データ |
| `events.jsonl` | 変換済みのイベントヘッダー、イベント、トレーラー |
| `intel.json` | 分類に使った脆弱性情報のスナップショット |
| `match_hc.json`（HIGH/CRITICAL）と`match_all.json`（全重大度） | 照合結果と詳しい証拠 |
| `csv_hc/` / `csv_all/` | スキャンごとの 14 本の結果表 |
| `record.md` | `tools/record.py` が作る個別の run 記録 |
| `experiments/runtime-discovery/out/AGGREGATE-events.md` | `tools/aggregate.py` が作る run 横断の集計表 |

| `<case>-truth-r<replicate>/image_id.txt`、`container_id.txt` | 正解 run のイメージとコンテナの識別情報 |
| `<case>-truth-r<replicate>/ready_at.txt`、`fired_at.txt`、`stopped_at.txt` | 正解 run の準備完了、開始通知、停止通知の時刻 |
| `<case>-truth-r<replicate>/varlog/` | 正常停止後にコピーした使用、発生、操作、内省、プロセス別 strace のログ |
| `<case>-truth-r<replicate>/truth.json` | `truth.py` が作る独立した同梱一覧と使用の正解データ |
| `<measurement-run>/coverage.json`、`coverage.md` | パッケージの網羅性指標、または理由付きの集計保留 |

- 観測ファイル名の例は `case9__9_root_i30_w300_p0_r1_attach_running_none.json`
- 実行キーは `case_variant`、`permission`、`interval`、`window`、`phase`、`replicate`、`sync`、`config_id` で構成する
- `sync` はワークロードとの開始順序を区別する
- `config_id` はイベント収集設定を区別する
- 観測には識別情報、時刻情報、ホストアーキテクチャ、プロセスの証拠、ファイルの帰属、リスナー、権限、負荷計測値、失敗、対象登録、補助入力、記述子を含む
- コマンドが正常終了した場合も観測内容の確認が必要
- 照合 JSON にはイメージの同一性検証、使用状況の判定、証拠、確認率、露出、順位比較、GT-B の精度指標を含む
- 同じ保存先への再実行はファイルを上書きする
- run ごとに別のディレクトリを使う
- 集約は `match` とは別に行う

### イベント入力

- `match -events` は GT-B の使用ログや発生ログとは別にイベント JSONL を読む
- イベントレコードの識別情報がない使用ログはイベント入力として拒否する
- イベント JSONL の各行は `record` で種類を区別する
- `events_header` は設定、開始順序、手法、フィルター、バッファ、時計変換、起動とアタッチの確認状態を記述する
- `event` は時刻、プロセスとスレッドの識別情報、生のパスと解決済みパス、成否、cgroup 情報、コンテナへの帰属を保持する
- `events_trailer` は収集の終了と欠落を記述する
- 報告された欠落を変換に含めるため、トレーサーの標準エラー出力も保存する
- トレーシング、時計変換、cgroup 対応表は [runtime-events の説明](../runtime-events/REFERENCE.ja.md)を参照
- 観測とイベントヘッダーの空でない `sync` または `config_id` が異なる場合は拒否する
- 観測が `none` 以外の設定を指定しているのにイベントの設定 ID がない場合も拒否する
- 古い入力では条件の項目を省略でき、省略値は通常、不一致とは扱わない

## コマンドのフラグ

### collect

| フラグ | 意味 |
| --- | --- |
| `-socket` | Docker Engine の UNIX ソケットで、通常は `/var/run/docker.sock` |
| `-containers` | 観測する稼働済みコンテナの名前または ID のカンマ区切り一覧 |
| `-case-variant` | `9` や `7a` などの実行キーのケース識別子 |
| `-permission` | 権限条件のラベル |
| `-interval` | サンプル開始間隔の秒数 |
| `-window` | 観測期間の秒数 |
| `-phase` | `-phase-base` からのサンプリングオフセットの秒数 |
| `-phase-base` | オフセットの基準となる RFC3339 時刻 |
| `-replicate` | 実行キーの反復番号 |
| `-ps-args` | Docker `top` の引数で、既定値は `-eo pid,ppid,user` |
| `-out-dir` | 観測と manifest の保存先 |
| `-cgroup-path` | `/proc/self/cgroup` から導出するパスを上書きするコレクターの cgroup v2 ディレクトリ |
| `-docker-cgroup-path` | デーモンの cgroup ディレクトリで、既定値は `/sys/fs/cgroup/system.slice/docker.service` |
| `-expect` | ワークロード開始前に登録する対象の名前または ID のカンマ区切り一覧 |
| `-expect-poll-ms` | 登録時のポーリング間隔で、既定値は `200` ミリ秒、正の値が必要 |
| `-expect-timeout` | すべての対象の受け入れを待つ時間で、既定値は `120` 秒、正の値が必要 |
| `-ready-file` | 登録状態の変化時に更新する準備完了レポートで、既定値は `<out-dir>/ready.json` |
| `-sync` | `startup` または `attach_running` で、既定値は `-expect` 指定時が `startup`、それ以外が `attach_running` |
| `-config-id` | 手法、スクリプト／ビルド、フィルター、バッファを区別する設定 ID で、既定値は `none` |
| `-aux-inputs` | 補助入力を保存する設定で、既定値は `true` |
| `-aux-max-dir-entries` | ディレクトリツリーごとのモジュール構成パス数の上限で、既定値は `200000` |
| `-aux-max-record-lines` | Python ディストリビューションごとのインストール済みファイル一覧の行数上限で、既定値は `100000` |
| `-aux-max-owned-paths` | パッケージデータベースのパス索引の件数上限で、既定値は `400000` |

| `-aux-max-extra-symlinks` | `/etc/localtime`、`/etc/alternatives`、一般的な bin/sbin ディレクトリ、OS パッケージのファイル一覧で共有する読み取りごとのリンク件数上限で、既定値は `20000` |
| `-aux-scan-depth` | 一般的なインストール先のルート配下を検索する深さで、既定値は `8` |

- 標準のサンプリング条件は root、300 秒の観測期間、30 秒間隔、オフセット 0、反復番号 1
- この条件では 10 回のサンプリングを予定する
- 権限と反復の条件は明示して記録する
- `-permission` はラベルを記録するだけで権限を付与しない
- ラベルは `root`、`ptrace`、`ptrace_dac`、`none`
- `ptrace` は `CAP_SYS_PTRACE` を持つ非 root
- `ptrace_dac` はさらに `CAP_DAC_READ_SEARCH` を持つ非 root
- `none` はケーパビリティを持たない非 root
- ケーパビリティは `go run` ではなくビルド済み実行ファイルに付与する
- ソケットへのアクセス、ディレクトリ権限、ホストのセキュリティ制御も成否に影響する
- `-containers` と `-expect` の両方を省略すると、最初の列挙時に稼働しているコンテナを選ぶ
- `-expect` だけでは指定した対象だけを待つ
- `-containers` を追加すると稼働済みの対象も選べる
- `-ps-args` を変更する場合も `pid,ppid,user` の列順を維持する
- 通常の途中参加では `-phase-base` を省略すると収集開始時刻を使う
- 対象登録を待つ場合は待機後に既定の基準時刻を設定し直す
- 基準時刻とその出所を記録する
- ワークロードの周期に対する比較では、その周期の基準時刻を `-phase-base` に指定する
- モジュールツリーの一覧取得中に収集するシンボリックリンクの参照先には、1 回の読み取りにつき 100,000 件という別の固定上限がある
- このシンボリックリンクの上限を変更するフラグはない
- 登録、検索、切り詰めの設定は run の条件とともに保存する

### match

| フラグ | 意味 |
| --- | --- |
| `-observation` | 必須のコンテナ観測 JSON |
| `-trivy` | 必須の計測対象イメージのスキャン JSON |
| `-case` | 期待値と GT-B の対象範囲を含む必須のケース定義 |
| `-gtb` | 任意の独立した正解データ JSON |
| `-events` | 任意の変換済みイベント JSONL |

| `-all-packages` | Trivy の `Packages` から Finding 0 件のパッケージ判定を追加し、`--list-all-pkgs` のスキャン結果を必要とする既定値 `false` のフラグ |
| `-occurrence-tolerance-ms` | 対応付けの許容誤差で、既定値は `500` ミリ秒 |
| `-intel-cache` | KEV/EPSS のキャッシュディレクトリ |
| `-intel-snapshot` | KEV/EPSS を再参照せずに使う保存済み脆弱性情報 JSON |
| `-out-intel-snapshot` | この照合で使った脆弱性情報の保存先 |
| `-act-now-epss` | `act_now` の EPSS しきい値で、標準例では `0.10` |
| `-watch-epss` | `watch` の EPSS しきい値で、標準例では `0.01` |
| `-out-json` | 照合結果 JSON の保存先 |
| `-out-csv-dir` | 14 本の CSV の保存先 |

- `match` は稼働中のコンテナやルートファイルシステムを必要としない
- 独立した GT-B を省略すると FP/FN は判定不能のままになる
- `-intel-snapshot` がない場合はキャッシュを使い、更新された KEV/EPSS を取得することがある
- `-out-intel-snapshot` は実際に使った脆弱性情報を保存する
- 以前の結果の `intel` オブジェクトもスナップショットとして使える
- 再現には保存済み入力、しきい値、脆弱性情報スナップショットを揃える必要がある
- スナップショットを使う run は KEV/EPSS を参照しない
- 分類を再現できるよう脆弱性情報を十分に固定できるのはスナップショットを使う run だけ
- 自動実行ツールでは `KL_INTEL_SNAPSHOT` でスナップショットのパスを指定する
- 対応付けの許容誤差は計測前に固定し、比較の間も維持する

### 網羅性検証の実行・集計ツール

| コマンド | 引数と既定値 |
| --- | --- |
| `tools/case-run.sh` | `<case> [replicate] [startup\|attach_running] [64\|256\|512\|none] [interval] [window]` で、既定値は反復 `1`、`startup`、`64`、`30`、`300` |
| `tools/case-batch.sh` | `<plan file>` で、各行は `<case> <replicate> <sync> <pages> [interval] [window]` |
| `tools/truth-run.sh` | `<case> [replicate] [window seconds]` で、対象はケース 26〜28、既定値は反復 `1` と窓 `900` |
| `tools/truth.py` | `<truth run dir> <case json> [measurement run dir]` で、`<truth run dir>/truth.json` を出力 |
| `tools/coverage.py` | `<measurement run dir> <truth.json>` で、計測ディレクトリに `coverage.json` と `coverage.md` を出力 |
| `cases/run.sh build` | `<case>` で、独立したイメージビルド処理があるケースをコンテナ起動なしでビルド |
| `cases/run.sh fire-when-ready` | `<case> [timeout seconds]` で、実際の開始通知を再試行し、既定のタイムアウトは `900` 秒 |
| `cases/run.sh wait-after-lazy-phase` | `<case> [timeout seconds]` で、内省ログの `after_lazy` を待ち、既定のタイムアウトは `60` 秒 |

- `case-run.sh` の第 5・6 引数はサンプル開始間隔と観測窓の長さを表す正の整数秒
- 計画行の第 5・6 欄も同じ意味を持ち、省略時は `30` と `300`
- ケース 23・24、`23+24`、`23+host` の計画行は帰属検証ランナーへ渡し、網羅性検証の間隔と窓は適用しない
- `coverage-main.txt` はケース 26〜28 を 30 秒間隔・900 秒窓、両方の開始条件、各 2 反復で計 12 run 実行する
- `coverage-rest.txt` は残りの間隔・窓の組 `(10, 900)`、`(30, 300)`、`(10, 300)` を両方の開始条件で各 1 反復、計 18 run 実行する
- 両方の網羅性検証計画はイベントバッファに `512` ページを使う
- `case-run.sh` はトレーサーとコレクターの開始前にイメージをビルドし、キャッシュのないビルドが観測窓を消費することを防ぐ
- ケース 26〜28 の `startup` はコレクターの開始時刻を `-phase-base` に渡し、対象登録が完了する前のコンテナ起動も観測窓に含める
- 同じケースの `attach_running` は `fire-when-ready` を 900 秒、`wait-after-lazy-phase` を 120 秒のタイムアウトで実行してから観測を始める
- 同じケースは両方の重大度スキャンで Trivy の `--list-all-pkgs` を使い、両方の照合で `match -all-packages` を使う
- `truth-run.sh` は新しいコンテナを strace 下で起動し、準備完了と開始通知、指定窓の待機、正常停止、`/var/log` のコピーを順に行う
- 任意の計測ディレクトリを渡すと `truth.py` が正解作成時に同等性を確認し、`coverage.py` は集計する計測ごとに確認し直す
- `truth.py` は保存済みイメージ ID を調べるため Docker へのアクセスを必要とし、`coverage.py` は `truth.json` が参照する正解 run のディレクトリとログを必要とする
- `coverage.py` は解析と操作対応のヘルパーを共有するため、`truth.py` と同じチェックアウトから実行する

## 手動での計測手順

### 計測の順序

1. ホストを準備する
2. ケースを起動する
3. 準備完了とフィクスチャの妥当性を確認する
4. 実際に稼働しているイメージ ID を指定してスキャンする
5. 観測を収集する
6. 独立した正解データを収集する
7. 観測、スキャン、ケース定義、正解データを照合する
8. ケースを削除する

- 通常の `attach_running` 計測はこの順序で進める
- ケース 13〜24 の `startup` では後述の登録手順が必要
- 準備完了、フィクスチャ、事前チェックのいずれかが失敗したら run を中止する

### ホストの準備とビルド

- 専用ホストを使うことで競合ワークロードの影響を減らせる
- ほかのランタイムのネットワーク設定が残っていると計測に影響することがある
- CLI、イメージスキャン、コレクターは同じネイティブの Docker エンドポイントを使う
- 別の VM を介する Docker Desktop では必要なホスト PID を取得できない
- Docker Desktop の WSL 連携はソケットを乗っ取るため利用不可
- 標準の収集とホスト procfs のチェックには root が必要
- 同等の読み取りを行う非 root 条件では `CAP_SYS_PTRACE` と `CAP_DAC_READ_SEARCH` を使う
- イベント計測には [runtime-events の README](../runtime-events/README.ja.md) にある環境も必要
- bpftrace は v0.25.0 での計測実績があり、動作する最低版は未確定
- Go 1.26 が必要で、リポジトリの指定は Go 1.26.4
- Trivy はイメージスキャン、Bash と curl はヘルパー、jq はこの文書の例に使う
- ケースヘルパーは python3 があれば使用ログの解析に使う
- フォールバックの正規表現は空白の違いを許容する
- 自動実行の Python コマンドには python3 が必要
- ケースで使うポートを空けておく
- イメージビルド、Trivy データ、ケース 9/13/23/24 のリクエスト、スナップショットなしの KEV/EPSS 取得にはネットワークアクセスが必要

```sh
mkdir -p ./out
unset DOCKER_CONTEXT
export DOCKER_HOST=unix:///var/run/docker.sock
docker context show
docker info --format '{{.ServerVersion}} {{.Driver}} {{.DockerRootDir}} {{.CgroupVersion}}'
uname -r
cat /proc/sys/kernel/yama/ptrace_scope
findmnt -no OPTIONS /proc

go build -o ./out/runtime-discovery ./experiments/runtime-discovery
go run ./experiments/runtime-discovery collect -h
go run ./experiments/runtime-discovery match -h
```

- ホスト準備時の出力とエラーを run の記録に残す
- 公開した HTTP ポートは curl で確認する
- ホスト上に待ち受けソケットがないことだけでは Docker NAT の公開失敗とはいえない
- 権限比較にはビルド済みの固定した実行ファイルを使う

### サンプリングの例：ケース 9

```sh
run_dir=./out/9-root-30-300-offset0-rep1
mkdir -p "$run_dir"
sudo bash experiments/runtime-discovery/cases/run.sh up 9
sudo bash experiments/runtime-discovery/cases/run.sh fixture-check 9
cp experiments/runtime-discovery/cases/9.json "$run_dir/case.json"
image_id=$(docker inspect --format '{{.Image}}' case9)
trivy image --format json --output "$run_dir/trivy.json" "$image_id"

sudo systemd-run --scope --unit=runtime-discovery-collect \
  -p CPUAccounting=yes -p MemoryAccounting=yes \
  "$(pwd)/out/runtime-discovery" collect \
  -socket /var/run/docker.sock -containers case9 \
  -case-variant 9 -permission root \
  -interval 30 -window 300 -phase 0 -replicate 1 \
  -out-dir "$run_dir/collect"
```

- このスコープはコレクターを専用の cgroup v2 に分離する
- 明示する `-cgroup-path` の例は `/sys/fs/cgroup/system.slice/runtime-discovery-collect.scope`
- systemd がないホストでは cgroup v2 を手動で作成してその中で実行し、`-cgroup-path` で渡す
- 初回のパッケージデータベース読み取りコスト、コレクターの cgroup 使用量、デーモンの cgroup 使用量を記録する
- デーモンの cgroup 計測には `docker top` が起動する `ps` プロセスも含む
- `memory.peak` は観測期間だけでなく cgroup の存続期間全体のピーク
- 取得できない計測値は失敗として記録する
- ケース 1/2/6 の権限比較は標準結果と分ける
- サンプリング比較にはケース 9/10 を使う
- サンプリング間隔は 10/30/60 秒とし、観測期間を 300 秒固定またはサンプル数を 10 回固定にする
- オフセット比較には 0/3/7 秒を使う
- 比較ごとに条件と保存先を分けて保持する

### ケース定義とヘルパーの動作

- サンプリングのケース 1〜12 は、ケース 7 の `7a` と `7b` を含めて 13 バリアント
- `run.sh` は番号または番号と英字のバリアントを受け取る
- Docker のコンテナ名は `case1` や `case7a` のような `case<番号>`
- 収集フラグにはコンテナ名または ID を渡す
- `cases/*.json` は `expected_usage` と `expected_verdict` を分ける
- GT-A の使用宣言は `used` または `not_used`
- `expected_factor` は任意
- `gap_class_hint` と `gap_class_rationale` は宣言されたギャップを説明する
- `gt_b_scope` は独立した正解データの対象パッケージ範囲を宣言する
- ケース 5 は cryptography の使用を宣言する一方、従来の言語パッケージ規則での期待判定は `unobserved`
- ケース 13〜24 の言語パッケージ期待値も従来の規則を表す
- 期待判定が `unobserved` のパッケージでも、追加の評価系列では使用を確認できる場合がある
- ケース 16 の定義は `case_id` と `image` を除いてケース 15 と同じ
- ケース 23/24 の定義は `case_id` を除いて同じ

| ケース | イメージまたはベース | 詳細な条件 |
| --- | --- | --- |
| 1 | `nginx:1.27` | Debian の帰属情報、マスター／ワーカー、全インターフェースへの公開 |
| 2 | `redis:7-alpine` | apk の帰属情報、非 root サービス、ループバックへの公開 |
| 3 | `nginx:1.27` | ホストネットワークとリスナーの帰属 |
| 4 | `postgres:16` | ポートを公開しない複数のデータベースプロセス |
| 5 | `python:3.12-slim` ベースの `kl-case5` | cryptography 拡張のマッピングと言語パッケージのギャップ |
| 6 | distroless `cc-debian12` ベースの `kl-case6` | 動的 C サーバーと `status.d` による帰属 |
| 7a / 7b | `debian:12-slim` 上の `kl-case7a` と distroless `static-debian12` 上の `kl-case7b` | メタデータの有無が異なる環境での同じ静的 Go サーバー |
| 8 | `debian:12-slim` ベースの `kl-case8` | 実行ファイルとライブラリの削除、ロード済みライブラリのアトミックな置換 |
| 9 | `debian:12-slim` ベースの `kl-case9` | 反復間に 5 秒のスリープを挟む短命な curl/git |
| 10 | `debian:12-slim` ベースの `kl-case10` | SQLite の 7 秒間ロードと 7 秒間アンロード |
| 11 | `nginxinc/nginx-unprivileged:1.27-alpine` | 非 root サービスと実効権限 |
| 12 | `nginx:1.27` | `NET_ADMIN` の追加と `NET_RAW` の削除 |
| 13 | `kl-case13` | 個別に識別する curl/git の実行とローダーが解決したライブラリ |
| 14 | `kl-case14` | SQLite の `dlopen`／`dlclose`、7 秒ずつのロード／アンロード、ロード区間、maps によるアンロード確認 |
| 15 | `kl-case15` | cryptography のインポート、拡張のマッピング、インストール済みファイル一覧、コンパイル済みキャッシュパス |
| 16 | `kl-case16` | ビルド時のキャッシュ削除と実行時のキャッシュ書き込み無効化を行った同じインポート |
| 17 | `kl-case17` | 標準の `node_modules` 構成での Lodash の `require` |
| 18 | `kl-case18` | pnpm のリンク構成での同じ依存パッケージ |
| 19 | `kl-case19` | クラスパス上の個別 Log4j アーカイブ、保持される記述子、`startup_open` |
| 20 | `kl-case20` | `/app/fat.jar` 内の Log4j クラスと入れ子のアーカイブ、外側のファイルの証拠、`startup_open` |
| 21 | `kl-case21` | クラスパス外の Log4j、通知時に作るローダー、`load_open` |
| 22 | `kl-case22` | `golang.org/x/text` を含む静的な `/server` と、そのバイナリパスによる照合 |
| 23 / 24 | `kl-case13` | 別コンテナ内の同一プログラムとパス、およびホストとの対照実験 |

- ヘルパーはケース 7 の両バリアントを含むケース 5〜10 をビルドする
- ほかのサンプリングケースは上流のイメージを使う
- イベントケースのイメージはすべてヘルパーがビルドし、23/24 は `kl-case13` を再利用する
- `up-all` はケース 1〜12 だけを起動する
- `down-all` はケース 1〜24 のコンテナを削除する
- サンプリングケースの起動は HTTP 200、サービスの準備完了ログ、`pg_isready` のいずれかを待つ
- ケース 5/6 は追加で `open` レコードを待つ
- ケース 8 は 3 件の `stage` レコードを待つ
- ケース 9 は `exit` を待つ
- ケース 10 は maps でアンロードを確認した `dlclose` を待つ
- JSON 解析では同じレコードの空白の違いを同等に扱う
- `fixture-check` は別途実行する
- ケース 8/10 はサンプリング前に対応する事前チェックも必要
- `preflight-10` は固定時刻を仮定せず、アンロードされた期間をポーリングで確認する

```sh
sudo bash experiments/runtime-discovery/cases/run.sh fixture-check 8
sudo bash experiments/runtime-discovery/cases/run.sh preflight-8
sudo bash experiments/runtime-discovery/cases/run.sh fixture-check 10
sudo bash experiments/runtime-discovery/cases/run.sh preflight-10
```

### イベントケースの開始通知と確認

- ケース 13〜24 は `/run/fire/fire` で待機する
- ヘルパーは `$FIRE_ROOT/case<番号>/fire` を作り、そのディレクトリを `/run/fire` にバインドマウントする
- `FIRE_ROOT` の既定値は `experiments/runtime-discovery/out/fire`
- 手動計測を整理する場合は `./out/` 配下の絶対パスを指定できる
- 動作開始前に共有の `container-id` ファイルへ完全なコンテナ ID を書き込む
- `fire <case>` はホストから FIFO に `go` を書き込む
- FIFO のブロッキング待機によりポーリングを避け、コンテナ内で追加のコマンドを起動しない
- `fire` 自体はコレクターの準備完了を検証しない
- イベントケースの `up` はワークロードが待機した状態で戻る
- 動作開始後、必要な発生が完了してからフィクスチャを確認する
- ケース 13/23/24 は少なくとも 1 件の実行レコードが必要
- ケース 14〜21 は少なくとも 2 件のロードレコードが必要
- ケース 15〜21 はメモリ内キャッシュヒットを記録するため意図的にロードを繰り返す
- ケース 14 はロード／アンロードを繰り返し、直前のアンロード確認から `cache_hit` を決める
- ケース 14 はヘルパーのロード件数に加えて `maps_unloaded` の確認が必要
- ケース 22 は実行レコードがあり、共有ライブラリのマッピングがないことが必要
- `dump-logs <case> <directory>` はコンテナのルートファイルシステム経由で取得可能なログをコピーする
- コピー先の名前は `<case>.usage.jsonl` と `<case>.occurrences.jsonl`
- `host-run <log> [iterations] [interval seconds]` はホスト側の帰属対照実験を実行する
- 既定値は 10 回の反復、5 秒間隔、`/usr/bin/curl`
- `HOST_PROGRAM` で別の実行ファイルを選べる
- ホストの発生は `container_id:"host"` を使う
- ケース 23/24 は発生 ID の接頭辞を分ける

### ワークロード開始前の対象登録

1. [runtime-events の手順](../runtime-events/REFERENCE.ja.md#計測の順序)で時計変換と初期 cgroup 対応表を準備する
2. 起動時のオープンを測る場合はコンテナ起動前にトレーサーを開始する
3. `-expect case13`、`-sync startup`、予定した `-config-id`、新しい準備完了ファイルのパスを指定して `collect` をバックグラウンドで起動する
4. `run.sh up 13` で待機状態のコンテナを起動する
5. `ready-run-id` で今回のコレクターの実行 ID を取得する
6. `wait-ready` でその実行の準備完了を待つ
7. `register-cgroups` で cgroup 対応表を更新する
8. `attach-check` で既知のイベントが届くことを確認する
9. ワークロードに開始通知を送り、その時刻を記録する
10. 正確なイメージ ID を保存してスキャンし、動作開始後のフィクスチャを確認する
11. 予定した観測期間の終了までワークロードとトレーサーを動かす
12. cgroup 対応表を更新し、コンテナ削除前に独立ログをコピーする
13. トレーサーの両出力を保存して変換し、イベント JSONL を `match` に渡す

| ヘルパーのコマンド | 引数と動作 |
| --- | --- |
| `ready-run-id` | `<ready file> [timeout seconds] [collector start, RFC3339]` で、既定の待機時間は `60` 秒 |
| `wait-ready` | `<ready file> <expected run id> [timeout seconds]` で、実行 ID は必須、既定の待機時間は `120` 秒 |
| `register-cgroups` | `<table path> [runtime-events binary]` で、以前の対応関係をマージする |
| `attach-check` | `<trace file> [timeout seconds]` で、既知の実行を確認する |
| `fire` | `<case>` で、待機中のワークロードに通知する |
| `dump-logs` | `<case> <directory>` で、取得可能な独立ログを保存する |
| `host-run` | `<log> [iterations] [interval seconds]` で、ホストの実行を記録する |

- これらは `sudo bash experiments/runtime-discovery/cases/run.sh` 経由で実行する
- `-expect` にはケース番号ではなく `case13` などのコンテナ名を渡す
- `-expect-timeout` にはイメージのビルドと対象準備に十分な時間を確保する
- 準備完了レポートは一意の `run_id`、条件、遷移時刻、対象の状態、エラーを記録する
- 対象の状態は `registered_not_started`、`start_detected_preparing`、`accepted` の順に進む
- 詳細情報の取得とマウントビューおよび有効な補助入力の準備後に対象を受け入れる
- 準備に失敗した場合は再試行する
- 受け入れがタイムアウトに間に合わなかった対象は `not_started` になる
- 受け入れ済みの対象にもエラーや切り詰めが残る場合がある
- `wait-ready` は期待する実行 ID が一致し、すべての対象を受け入れた場合だけ成功する
- `ready-run-id` にコレクターの開始時刻を渡すと、それ以前のレポートを拒否する
- 開始時刻を省略すると、今回の実行に属すると証明できない旨の警告とともに識別子を返す
- cgroup 対応表はコンテナが存在してから動作開始通知までの間に更新する
- 対応表のマージにより以前の対応関係も保持する
- `attach-check` は一意の名前を付けたホスト側のプローブを実行し、トレースのマーカーを待つ
- トレーサーの起動メッセージだけではアタッチを確認できない
- 計測対象の処理は予定した観測期間内に収まる必要がある
- ケース 19/20 の `startup_open` を含めるにはコンテナ起動前からトレースする
- ケース 13/14 は準備完了後の開始と、進行中の実行・ロード周期への途中参加を比較する
- ケース 15〜18 と 21 は観測期間内の開始通知と、インポート、require、ロード後のアタッチを比較する
- ケース 22 は `/server` の実行開始の観測と、常駐サーバーへのアタッチを比較する
- ケース 23/24 は片方ずつ、同時実行、独立に記録するホスト動作との条件を比較する
- `attach_running` ではワークロードを先に起動して動作させ、その後 `-containers case13 -sync attach_running` で収集する
- イベントヘッダーにも同じ開始順序のラベルを使う
- アタッチ前に完了した一度きりのロードはその観測期間の外になる

### 照合と後片付け

- 次のコマンドは後述の手順で `gtb.json` を準備してから実行する
- イベントを使う run では `-events "$run_dir/events.jsonl"` を追加し、その run に対応する観測ファイル名を指定する

```sh
go run ./experiments/runtime-discovery match \
  -observation "$run_dir/collect/case9__9_root_i30_w300_p0_r1_attach_running_none.json" \
  -trivy "$run_dir/trivy.json" -case "$run_dir/case.json" \
  -gtb "$run_dir/gtb.json" -intel-cache ./out/intel-cache \
  -out-intel-snapshot "$run_dir/intel.json" \
  -act-now-epss 0.10 -watch-epss 0.01 \
  -out-json "$run_dir/match.json" -out-csv-dir "$run_dir/csv"
sudo bash experiments/runtime-discovery/cases/run.sh down 9
```

## 正解データ(GT-B)

### 形式と独立性

- GT-B は使用ログまたは常駐プロセスの確認と、独立に検証したパッケージ情報を組み合わせる
- `-gtb` は生の JSONL ではなく 1 つの JSON オブジェクトを受け取る
- GT-A の期待値とコレクターの出力は独立した正解データではない
- run ごとに新しいログを用意する
- 宣言する範囲の根拠は計測前に確立する
- GT-B ラベルが付くのは `gt_b_scope` 内のパッケージだけ

| フィールド | 意味 |
| --- | --- |
| `case_id` | ケース識別子 |
| `kind` | `usage_log` または `limited` |
| `usage_log` | 解析したワークロードの使用レコード |
| `path_packages` | 独立に検証したファイルとパッケージの対応 |
| `resident_packages` | 限定的な正解データで使用を確認した常駐プロセスのパッケージ |
| `occurrences` | 個々の実行とロードの独立した記録 |
| `pid_map` | 独立に確立したコンテナとホストのプロセス／スレッド対応 |
| `clock_base` | 発生時刻の時計とイベント時刻との関係の説明 |
| `real_opens` | 用意できる場合の、実際のファイルオープンシステムコールの独立した記録 |

### 使用ログによる正解データ

- コレクターは最後のサンプル取得後、予定した観測期間の終了前に戻ることがある
- GT-B をコピーする前に観測期間の終了までワークロードを動かす
- 標準のサンプリング例では追加で 30 秒待つ

```sh
sleep 30
docker cp case9:/var/log/usage.jsonl "$run_dir/usage.jsonl"
jq -sr '[.[] | .path? | select(. != null and . != "")] | unique[]' \
  "$run_dir/usage.jsonl" > "$run_dir/usage-paths.txt"
docker exec case9 dpkg-query -S /usr/bin/curl /usr/bin/git
```

- ケース 5/6/8/9/10 は `/var/log/usage.jsonl` を出力する
- 自前でビルドするサンプリングケースのうち使用ログがないのは 7a/7b だけ
- ケース 5/6 は起動時と定期的な maps スナップショットを記録する
- ケース 9 は実行に加えて動的ローダーが解決したライブラリを記録する
- 使用ログは 1 行に 1 つの JSON オブジェクトを含む

```json
{"ts":"2026-09-11T00:00:00Z","pid":42,"starttime":12345,"event":"exec","path":"/usr/bin/git","ok":true}
```

- `ts` は RFC3339 で、小数秒を含む場合がある
- `pid` とプロセス開始時の tick 数でプロセスの世代を識別する
- 使用イベントの名前は `exec`、`open`、`dlopen`、`dlclose`、`exit`
- 終了レコードの `ok:true` は終了を観測したことを示す
- コマンドの終了コードは別の `status` に記録する
- ケース 8 は `meta` と `stage` も記録する
- ケース 10 は `dlclose` に `maps_unloaded` を追加する
- これらの追加フィールドは保存ログに残す
- 観測期間より前のレコードも、そこから始まる区間が観測期間と重なる場合は残す

1. ライブラリを含むすべての使用パスの所有パッケージを独立に検証する
2. シンボリックリンクによる別名と稼働中イメージのパッケージメタデータを考慮する
3. 検証済みの対応を `$run_dir/path-packages.json` に保存する
4. 解析したログと対応表を GT-B オブジェクトにまとめる

```json
[
  {"path":"/usr/bin/curl","package":"curl"},
  {"path":"/usr/bin/git","package":"git"}
]
```

- この配列は形式の例であり、すべてのパスの検証を置き換えるものではない
- `/usr` 統合イメージではパッケージの `.list` に記録された表記で所有パッケージを問い合わせる
- `/lib/...` として記録されたパスを `/usr/lib/...` で問い合わせると「no path found」になる場合がある
- `.list` を直接調べることでも別名を解決できる
- 対応表は `gt_b_scope` の内側だけでなく外側のライブラリパスも網羅する
- 所有パッケージがないことを独立に確認したパスは `unowned:true` で表す
- 解決できなかったパスを `unowned` にしてはいけない
- 独立に確認した所有パッケージが複数ある場合は `packages` を使える
- 単一の `package` と任意の `version` による形式も使える
- 未対応のパスがあると、使用を示す証拠がないパッケージについて未使用を確定できない
- 独立に確認された使用の証拠は引き続き有効
- イベントがないことから未使用を確定できるのは、ログの網羅性を独立に確認した範囲だけ

```sh
jq -s --slurpfile mappings "$run_dir/path-packages.json" '{
  case_id: "9", kind: "usage_log", usage_log: .,
  path_packages: $mappings[0]
}' "$run_dir/usage.jsonl" > "$run_dir/gtb.json"
```

### 常駐プロセスによる限定的な正解データ

- 公式イメージでは観測期間後の限定的な常駐プロセス確認を使える
- `docker top` を保存し、常駐プロセスの実行ファイルとライブラリを調べ、所有パッケージとバージョンを独立に検証する
- 使用を確認した観測は次の形式で記録する

```json
{"case_id":"1","kind":"limited","resident_packages":[{"package":"nginx","used":true}]}
```

- 保存するケース定義では計測前に根拠のある範囲を宣言する
- `gt_b_scope` がない定義ではカバレッジがゼロのままになる
- 限定的なチェックでは未使用を確定できない
- `used:false` のエントリは無視する

### 発生レコード

- ケース 13〜24 は `/var/log/usage.jsonl` と `/var/log/occurrences.jsonl` の両方を書く
- 使用ログはパッケージの使用を確立する
- 発生ログは個々の実行とロードを識別する
- ログはコンテナが動いている間にコピーする

```sh
sudo bash experiments/runtime-discovery/cases/run.sh dump-logs 13 "$run_dir"
```

- 解析した発生レコードは GT-B の `occurrences` 配列に入れる
- 独立に収集したプロセスの対応は `pid_map` に入れる
- `clock_base` は時刻の基準を記述する
- `real_opens` は評価対象のイベントコレクターとは独立に実際の呼び出しを記録した場合だけ有効
- 同梱のイベントケースは独立した `real_opens` を生成しない
- 実行の発生はタイムスタンプ付きの時点
- ロードの発生は開始と終了を持つ区間

```json
{"id":"13-exec-000001","kind":"exec","pid":42,"tid":42,"starttime":12345,"pid_ns":4026531836,"ts":"2026-09-11T00:00:00.100000000Z","ok":true,"path":"/usr/bin/curl","container_id":"<full-container-id>"}
{"id":"17-load-000001","kind":"load","pid":1,"tid":1,"starttime":12346,"start":"2026-09-11T00:00:01.100000000Z","end":"2026-09-11T00:00:01.120000000Z","ok":true,"cache_hit":false,"files":["/app/node_modules/lodash/lodash.js"],"container_id":"<full-container-id>"}
```

- `id` はケース内の発生を識別する
- コンテナとホストのログを結合する場合は発生 ID を重複させない
- `pid` と任意の `tid` はワークロードのプロセス番号とスレッド番号
- `starttime` はプロセス世代を表す tick 数
- `pid_ns` はその番号が属する PID 名前空間の識別子
- ホストの発生では発生レコードとイベントの両方に `pid_ns` が必要
- `path` は実行したファイルを示す
- `files` はロード時に解決したファイルを列挙する
- `cache_hit:true` はロードの分母から除外するメモリ内の反復を示す
- 失敗した操作と観測期間外の発生は別に数える
- ケース 19〜21 は `open_condition` を保持する
- 同梱アーカイブの条件では `note` の留保事項も保持する
- ケース 19〜21 は OS のスレッド識別情報を確立しないためスレッド ID を省略する
- ホストの対照実験は `container_id:"host"` を宣言する
- 帰属の評価には参加するすべてのコンテナとホストの独立ログを結合する
- 使用ログの `open` は maps スナップショットやランタイムのモジュール管理情報に由来する場合がある
- そのようなエントリは独立したシステムコール単位の正解データではない

### ケース 26〜28 の使用正解データ(truth.py)

#### 同梱一覧 I

- `truth.py` は保存済みイメージ ID からコンテナを作り、使用ログと独立して `docker export` した rootfs を列挙する
- 探索対象は `/proc`、`/sys`、`/dev` を除くエクスポート済み rootfs 全域で、除外範囲も記録する
- OS パッケージと版はコピーした OS パッケージ DB から取得し、そのメタデータでファイルの所有関係を解決する
- Python はエクスポート済みファイルシステム全域で distribution を探し、インストールメタデータと `RECORD` から版とファイルの所有関係を得る
- Node はイメージ全域にある名前と版を読める `package.json` を対象とし、`node_modules` 外のパッケージや同梱ツールも含める
- Java はイメージ全域の jar を対象とし、パッケージ座標と読み取れる版のメタデータを使う
- 同梱一覧は Finding のないパッケージも含む Trivy の `--list-all-pkgs` と同じ母集団を対象とする
- 同梱一覧と正解のキーは `(ecosystem, name, version)` で、同名パッケージの異なるインストール済み版を区別する
- `coverage_plan` は意図した群の宣言と宣言差分の確認に使い、実測の同梱一覧や使用判定を定義しない

#### 使用 U・未使用 N・不明 X

- strace の `-f -ff -tt` による成功した `execve`・`execveat` と `open`・`openat`・`openat2` を独立した使用証拠にする
- `clone`・`clone3`・`fork`・`vfork` から親子関係を復元し、別プログラムを実行しない子にも生成時の主体を引き継ぐ
- 運用処理の curl・git・openssl と主体を引き継いだヘルパーを短命主体とし、常駐プログラムと運用処理のスケジューラーを常駐主体とする
- Python の `sys.modules`、Node.js の `require.cache`、Java のクラスロードログから解決したファイルを内省証拠として加える
- 内省で同じパスを初めて見た記録だけを新たな使用証拠にし、後続の出現は `held_evidence` に分ける
- 絶対・相対 symlink と途中のディレクトリリンクは、エクスポート済み rootfs 内で解決する
- ディレクトリのオープンは `O_DIRECTORY` とエクスポート済み rootfs のディレクトリ判定の両方で除外する
- 失敗した呼び出しは使用証拠にせず、解決できない相対パスは不足として明示する
- `U` は版まで解決できた使用キーのうち `I` に含まれるものとし、`I` にない版付き使用証拠は `ledger_gaps` に分ける
- 使用側または同梱一覧側で版を確定できないエントリは、版を推測せず `version_unknown` に記録する
- `I` のうち正の使用証拠がないものは、完全性判定を通過した場合だけ `N` に入れ、それ以外は `X` に入れる
- 完全性判定はトレースの存在、空でない記録、破損・解析不能なシステムコール記録の不在、復元できない中断呼び出しの不在、生成されたプロセスのトレース欠落の不在を必要とする
- 完全性判定は strace と内省証拠のパス解決、所有関係を解決できない壊れた symlink 列の不在、操作の同等性確認の成功も必要とする
- 計測ディレクトリを省略すると操作の整合性は `unchecked` となり、残りの同梱一覧は最初は `X` に入る
- 完全性判定が失敗しても正の使用証拠は `U` に残し、版付き同梱一覧では互いに素な集合として `I = U ∪ N ∪ X` を保つ
- `inventory_scan` はエクスポート、探索、メタデータ読み取りの診断を使用証拠の完全性判定とは別に記録する

#### 証拠の帰属と run の同等性

- 証拠は開始通知前の起動時、名前付き操作インスタンス、停止通知後、帰属不能の期間に分ける
- 短命主体の証拠はトレースの PID と復元した親子関係をたどり、発生ログが識別する操作インスタンスへ帰属させる
- 常駐主体の証拠は復元した操作区間と時刻で対応させ、近傍への帰属を `operations_nearest` に分けて残す
- 対応する操作インスタンスがない短命主体の証拠は、近い時刻へ振り替えず帰属不能にする
- 操作オフセットは対応する操作またはインスタンスの開始から最初の使用までの時間を記録する
- 停止通知後の証拠と時間的に帰属できない証拠は、それだけでは起動時または操作範囲内の使用を確立しない
- 同等性はイメージ ID、固定操作の名前と順序、成否、利用可能な `detail`、内省で解決したファイル集合を比較する
- 周期的な `osops_` 操作は種類が一致し、両 run が到達した共通範囲で混在順序、成否、利用可能な `detail` が一致する必要がある
- 周期処理の反復回数の違いは許容し、共通範囲を超えた末尾のインスタンスは未対応として明示する
- 正解 run に利用可能な内省ログがある場合、計測側の内省ログの欠落や利用不能は同等性の不成立になる

#### 展開の失敗と一時領域

- `truth.py` はイメージの rootfs を一時ディレクトリへ展開し、docker export・アーカイブの展開・ファイル書き込みのいずれかが失敗したら `truth.json` を書かずに非ゼロで終了する
- 展開前に `docker image inspect` が返すイメージサイズの 2 倍以上の空き容量を要求し、不足していれば非ゼロで終了する
- `KL_TRUTH_TMPDIR` で展開先のディレクトリを指定でき、`KL_TRUTH_KEEP_TMP=1` を付けると展開した内容を実行後に削除せず残す

#### truth.json のフィールド

| フィールド | 意味 |
| --- | --- |
| `image_id`、`truth_run_dir`、`fired_at`、`stopped_at` | イメージ識別情報、保持する入力ディレクトリ、正解 run の時刻 |
| `used`、`unused`、`unknown` | 版付きの U・N・X と、不明エントリの理由 |
| `inventory_size`、`inventory_scan` | 同梱数、探索範囲、除外、エクスポート状態、発見したメタデータ、読み取り失敗 |
| `ledger_gaps`、`identification_gaps` | 同梱一覧にない版付きの正の証拠と、その識別情報だけの要約 |
| `version_unknown` | 版を確定できない同梱一覧側または使用側のエントリ |
| `completeness` | トレースの検査、操作整合性の状態、全体の判定、理由 |
| `unresolved` | 未解決のトレースパス、内省モジュール、対応付け不能パス、所有関係の symlink 解決失敗 |
| `declaration_gaps` | 宣言にあるが同梱一覧にないパッケージと、宣言した群にない同梱パッケージ |
| `operation_consistency` | 比較した計測ディレクトリ、整合性の詳細、イメージと内省の確認、周期操作インスタンスの対応 |
| `used[].evidence`、`evidence_types`、`subjects`、`paths` | 証拠源、使用の種類、主体区分、解決したパッケージのパス |
| `used[].first_seen_s`、`last_seen_s`、`hold_seconds`、`exec_hold_seconds_min` | 正解 run の証拠時刻と記録された短命実行の長さ |
| `used[].used_at_startup`、`used_during_operations` | 起動時使用のフラグと使用に対応する操作名 |
| `used[].operation_instances` | 使用証拠を帰属させた具体的な操作 ID |
| `used[].operation_offsets_s`、`operation_instance_offsets_s` | 操作名と具体的なインスタンス ID ごとの最初の使用のオフセット |
| `used[].evidence_periods` | 起動時、操作、近傍操作、停止後、帰属不能の証拠数 |
| `used[].held_evidence` | 継続して存在した証拠として保持する後続の内省記録 |

## 照合規則

### 検出結果の使用確認

- 3 系列は同じスキャンと保存済み観測を使う
- `S0` は従来のサンプリング規則を再現する
- `S1` はスキャンされた Go バイナリ、開かれたアーカイブの記述子、モジュールツリー内のファイル、マッピングされた Python 拡張、インストール済みファイル一覧、保存済み OS パス索引を追加する
- `S2` は観測期間内に計測対象コンテナへ帰属した成功した実行とオープンを追加する
- イベントのパスは保存済みの対応付け入力で解決する
- `S0` → `S1` と `S1` → `S2` の増分は別々に報告する
- 証拠源ごとに入力状態と使用確認数を保持する
- ある証拠源の入力欠落は別の証拠源の有効な証拠を消さない
- 証拠は出所と粒度を保持する
- Go バイナリの使用確認はバイナリとそれに対応するスキャンの検出結果を対象とする
- 組み込まれた個々のモジュールの実行は証明しない
- 外側のアーカイブの観測は特定の入れ子のアーカイブの独立したロードを証明しない

### 識別情報と帰属

| 利用できる正解データ | 規則と解釈 |
| --- | --- |
| 独立した利用可能な `pid_map` | `container_generation_and_thread` がコンテナ、プロセス世代、ホストのプロセス／スレッド対応を使い、イベントが主張する帰属先とは独立に照合 |
| 利用できる対応表がない場合 | `container_namespace_pid_and_thread` が cgroup から得たコンテナ、名前空間内 PID/TID、プロセス世代の一致を要求 |
| ホストの発生 | コンテナへの帰属とは独立に `pid_ns`、名前空間内 PID/TID、`starttime` の一致を要求 |
| 必要な識別情報の欠落 | 対応付けは判定不能 |

- 名前空間内のプロセス番号は別コンテナで重複し得る
- イベントの `ns_pid` と `ns_tid` をワークロード内のプロセス番号とスレッド番号に照合する
- プロセス開始時の tick 数だけではコンテナをまたぐ同一性を確立できない
- コンテナ間誤帰属には `container_generation_and_thread` で使える独立した対応関係が必要
- その対応関係がなければ `cross_container_evaluable=false`
- この場合は分母が正でも `misattribution_rate` は N/A
- ホスト照合、`host_correct_rate`、`correct_attribution_rate` はそれぞれ別に評価する
- ホスト実行がコンテナに帰属しなかったことは、コンテナ間の正しさを確立しない
- 帰属の出力には正帰属、誤帰属、ホストの結果、帰属不明イベント、判定不能数を含む

### 発生の対応付けと分母

- 対応付けにはファイルパス、時刻、コンテナ識別情報、プロセス世代を使う
- 独立したホスト PID／スレッド対応があれば利用する
- 既定の許容誤差は 500 ミリ秒
- 許容誤差がイベントの時計変換誤差以下の場合は注記を残す
- 注記によって許容誤差を自動的に広げることはない
- 実行の捕捉には 1 件の発生とちょうど 1 件のイベントの対応が必要
- 1 対多と多対 1 の曖昧さは別に報告する
- ロードの捕捉は、列挙されたファイルに一致するイベントが少なくとも 1 件ある対象区間を数える
- 複数のロードに対応するイベントは、そのすべてのロードから除外する
- 実オープンの捕捉には独立した `real_opens` が必要
- キャッシュヒット、失敗、観測期間外の発生は除外して別々に数える
- 観測期間内の未捕捉、識別情報の判定不能、原因不明は区別する
- 捕捉率の分母にはそれぞれの判定可能数を使う
- 分母がゼロの場合は N/A
- 実オープンの記録がない場合も N/A
- 検出結果の使用確認と発生の捕捉率は異なる問いに答える

### 全パッケージの照合

- `-all-packages` は Finding がないパッケージも Trivy の `Packages` から登録する
- 追加グループは同じ S0・S1・S2 の評価処理を通り、`finding_count: 0` の `PackageVerdict` を出力する
- OS の版は Trivy の分離されたフィールドから `epoch:version-release` に復元し、ゼロの epoch と空の release を省略する
- Finding 0 件のグループは、追加のパッケージ名、ファイル、配置を含む独立した `widened` 索引を使う
- Finding があるグループは元の索引と判定を維持し、Finding 数、順位、優先度区分を変えない
- 追加の判定は既存の集計が完了した後に `packages` へ加える
- `-all-packages` を指定しても `Packages` が 1 件もないスキャン結果はエラーにする
- `gobinary` は追加パッケージの母集団と網羅性集計から除外する
- match のグループキーは `(class, package, installed_version)` のままで、言語エコシステム間の同名同版を区別できない

### シンボリックリンク、ディレクトリ、アプリのマニフェスト

- 保存済みの symlink 連鎖はパスの構成要素ごとに解決し、絶対参照はコンテナのルート起点、相対参照はリンクの親ディレクトリ起点でたどる
- リンクをたどる回数は最大 40 hop とし、循環などで上限を超えた場合は途中まで置換したパスを採用しない
- OS の照合では `/usr` 統合を正規化した元パスと symlink 解決後のパスの所有者を別々に照会する
- 両方のパスの所有者がそれぞれ単独で互いに異なる場合は、正解データと同じく両方のパッケージに使用確認を付ける
- 解決によって変わった参照先のパスから対応付けた場合は `Via` に `symlink:<解決後のパス>` を記録する
- どちらか一方のパス自体に複数の所有者がある場合は、他方の所有者が単独でも `Conflict` とする
- open イベントでは全パッケージ照合ルールより前にディレクトリ判定を行い、保存済みの `is_dir` が元パスまたは解決後のパスをディレクトリと示す場合は使用の証拠から除外する
- この除外は `missDirectoryOpen` (`directory_open`) とし、`outside_scan_events` とは別の `directory_open_events` に数える
- ディレクトリ open の除外は open イベントに適用し、実行イベントやサンプルのパスには適用しない
- `node_project_manifest` は解決後と元のどちらのパスにも `node_modules` のパッケージ境界がない場合だけ、スキャンに記録された最も近い祖先の `package.json` を探す
- この規則はアプリ自身のマニフェストを対象に含めつつ、リンク先が `node_modules` の外にあるという理由だけで依存パッケージをアプリに帰属させない
- 最初の配置読み取りより前など、イベントの瞬間をカバーする保存済みの読み取りがない場合は、観測パスとスキャン索引だけで解決する
- この fallback では後の読み取りから過去の配置の不変性を証明できないため、保存済みの OS 所有者や symlink 表を使わない

## 網羅性の集計(coverage.py)

### 評価範囲と集合

- 利用可能な `match_hc.json` と `match_all.json` を別々に集計し、確認済みの `(ecosystem, name, installed_version)` キーで S0・S1・S2 を評価する
- 区分は `resident_os`、`short_lived_os` と、該当する言語区分の `python`・`node`・`java`
- 使用済み OS パッケージは両方の主体区分に属する場合があり、未使用または不明の OS パッケージは両方の OS 区分に含める
- `U_main` は起動時の使用と、計測窓終了までに完了した操作を通じて確立した使用を含める
- `attach_running` でもアタッチ前を含む起動時の使用を主指標の分母に残す
- 周期処理の使用は同名の別インスタンスではなく、対応を検証できた操作インスタンスに結び付ける
- 窓終了をまたぐ操作は、保持される証拠があり、最初の使用のオフセットを対応する計測インスタンスへ移した時刻が窓終了以前になる場合に主指標へ含める
- 未対応、未記録、終了後だけ、停止後だけ、帰属不足の正解使用は `N` ではなく `X_main` に入れる
- `N` は確定した未使用を保ち、操作比較だけが障害だった `X` は新たな同等性確認の成功後に `N` へ戻す
- `U_window` は補助指標で、窓内で完了した操作に対応する使用と、窓内へ保持され得る実行ファイル・共有ライブラリの起動時使用を含める
- 窓境界をまたぐ操作や未記録の操作の使用は `X_window` に残し、窓外で完結したと記録された操作だけに結び付く使用は `N_window` に入れられる
- 主指標の範囲設定には計測側の操作区間と窓終了が必要で、窓内集計には窓開始も必要になる
- 主指標の範囲を設定できない場合は利用可能フラグを false にし、正解 run 全体の使用集合で集計する

| 数量 | 集合式 |
| --- | --- |
| 同梱一覧 | `I = U ∪ N ∪ X` |
| 系列 s の確認集合 | `C_s` |
| 主指標の真陽性 | `TP_s = C_s ∩ U_main` |
| 主指標の偽陰性 | `FN_s = U_main \ C_s` |
| 主指標の偽陽性 | `FP_s = C_s ∩ N` |
| 主指標の真陰性 | `TN_s = N \ C_s` |
| 主指標の再現率 | `\|TP_s\| / \|U_main\|` |
| 主指標の FPR | `\|FP_s\| / \|N\|` |
| 窓内指標 | `U_window` と `N_window` を使った同じ式 |
| 識別誤確認 | `C_s \ I` |
| 正解不明の同梱パッケージへの確認 | `C_s ∩ X` |

- 区分別の件数は各集合を対応する区分に限定して求める
- 分母がゼロなら JSON では `null`、Markdown では N/A
- `identification_misconfirmations` は同梱一覧外の確認キーを通常の TP・FP・FN と別に報告する
- 誤った版への確認は、その版が `N` なら FP、`U_main` なら TP、`I` の外なら識別誤確認になる
- 正しい版が `U_main` にあり未確認なら、その版の FN は独立して残る
- `confirmed_in_x` は残った正解不明の同梱一覧への確認を示し、`x_main_confirmed` と `confirmed_in_x_window` は各評価範囲の不明分も含める

### 見逃しの主因

- 各 FN に次の優先順で主因を 1 つ割り当て、主因別件数の合計を FN と一致させる
- 主因を確定できない場合の可能性は候補タグに残す

| 主因 | 判定材料 |
| --- | --- |
| `used_before_window` | 正解の時刻付き証拠がすべて開始通知基準の窓開始より前にあり、窓内へ保持され得る実行ファイル・共有ライブラリの証拠がない |
| `short_lived_use` | S0 で、計測側の全ての確認済み保持区間が実際の連続サンプル時刻の間に収まり、保持終了が未確認の使用がない |
| `mapping_not_supported` | S2 で計測窓内のイベントにパッケージのパスがあるのに未確認、または任意の系列で判定自体がないか factor が対応付け不足を示す |
| `insufficient_permission` | パッケージのパスを含む失敗の step が `proc_denied`、`rootfs_denied`、`prepare_proc_denied` |
| `other` | パッケージのパスを含む失敗に、権限拒否でも `proc_gone` でもない識別可能な原因がある |
| `lost_events` | S2 でイベント欠落が報告され、特定できたイベントの空白区間が計測側の該当パッケージの操作区間と重なる |
| `unknown` | 先行する条件のいずれでも原因を確定できない |

- 対応付け不足の factor は `lang_pkg_unmappable`、`no_file_list`、`db_absent`、`db_error`、`mapping_input_missing`、`event_path_unresolved`
- `proc_gone` だけでは権限不足や `other` を確定しない
- `unknown` には欠落報告に対する `lost_events_candidate` と、S0 の保持証拠不足に対する `short_lived_use_candidate` を付ける場合がある

- `read_event_state` は `lost_events`、`lost_notifications`、`map_overflow` の正の値だけをイベント欠落のカウンターとして扱い、`event_state=degraded` の場合も run 全体の欠落候補の判定を有効にする
- `path_read_failures` のような捕捉済みイベントの属性取得失敗や、`events_before_filter` と `events_after_filter` のような通常の件数だけではイベント欠落とみなさない
- 正解 run の保持時間を計測 run の保持区間の代わりに使わない

### 短命主体の直接確認数と出力

- `short_lived_direct_confirmations` は計測側の短命主体から独立に確認できた TP パッケージ数
- S0 は確認のサンプル ID とパスから主体を調べ、追加の対応付けとイベント証拠は確認情報とプロセス情報を使う
- 件数は S0 = P、S1 = P ∪ A、S2 = P ∪ A ∪ E と系列に沿って累積する
- 主体を解決できない確認はこの補助件数に加えず、区分の TP 件数も置き換えない
- `coverage.json` は区分×系列の TP・FN・FP・TN、再現率、FPR、窓内指標、不明への確認、識別誤確認、見逃しの詳細、直接確認数を保持する
- `coverage.md` は両スキャンの区分×系列の指標、識別誤確認、S2 の見逃し表を示す

### 集計保留の条件

- 集計のたびに計測のイメージ ID と `truth.json` を照合し、保持された正解ログと当該計測のログを新たに比較する
- イメージ ID の欠落・不一致、正解の入力ログの利用不能、操作・内省の同等性確認の失敗では `hold: true` と `hold_reason` を出力する
- 保留時はコマンドが正常終了しても再現率と偽陽性の指標を算出せず、両方の出力ファイルに保留を記録する
- トレースの不完全性は該当する未使用候補を `X` に残し、それだけでは同等性に関する集計保留を起こさない

### 順位差の集計(coverage_rank.py)

- `tools/coverage_rank.py [out-dir]` は保存済みの `g4` の順位を網羅性の集計結果と照合し、ディレクトリの既定値は `experiments/runtime-discovery/out`
- 選択したディレクトリに `AGGREGATE-rank.md` と `AGGREGATE-rank.csv` を出力する
- baseline は実行時情報なしの基準順位で、優先度、深刻度、パッケージ、脆弱性 ID で決まる
- `series=none` は run × スキャン種別 × 優先度ごとに 1 行の基準順位を表す
- 順位比較の対象は照合が出力する S0 と S2 の 2 系列、および `act_now` と `watch` の 2 優先度に限る
- S0 はサンプリングの証拠を使い、S2 はサンプリング、追加の対応付け、イベントの証拠を組み合わせる
- 詳細表は run × スキャン種別 × 系列または基準順位 × 優先度ごとに 1 行を持つ
- Markdown の要約は replicate 以外が同じ条件をまとめ、数値列の一致を `consistent=yes` または `no` で示し、異なる値に `DIFFERS:` を付ける
- 見逃しパッケージの列は各スキャン種別の `coverage.json` にある S2 の見逃しを使い、どの順位系列でもパッケージ名とインストール済みの版で照合する

| 列 | 意味 |
| --- | --- |
| `total_findings` | 対象優先度の Finding 総数 |
| `rank_changed_count` | 調整後の上位 20 件のうち、調整後順位が基準順位と異なる Finding 数 |
| `vs_no_runtime_rank_changed` | 実行時情報なしとの比較を明示する列で、値は `rank_changed_count` と同じ |
| `top20_promoted` | 調整後の上位 20 件のうち、`adjusted_rank < baseline_rank` の Finding 数 |
| `labeled_count` | 対象優先度の全 Finding のうち、使用確認・全世界への公開・特権実行の複合ラベルを満たす件数 |
| `missed_pkg_findings` | S2 の見逃しパッケージが対象優先度に持つ Finding の合計 |
| `missed_pkg_in_top20` | その見逃しパッケージの Finding のうち、当該系列の調整後の上位 20 件に入る件数 |
| `missed_pkg_rank_unchanged` | `missed_pkg_in_top20` のうち、`adjusted_rank == baseline_rank` の件数 |
| `missed_pkg_not_promoted` | `missed_pkg_in_top20` のうち、`adjusted_rank >= baseline_rank` の件数で、順位不変と他の Finding に押し下げられたものを含む |
| `missed_pkg_outside_top20` | `missed_pkg_findings - missed_pkg_in_top20` で、調整後順位を取得できない件数 |
| `false_promotions` | 当該系列の FP を対象優先度に Finding があるパッケージへ絞り、パッケージ名と版を照合した、調整後の上位 20 件で順位が上がった Finding 数 |

- 対象優先度に Finding を持つ FP パッケージがなければ `false_promotions` は 0
- 該当する FP パッケージがその優先度の保存済み上位 20 件に 1 つでも現れなければ、順位が上がったか判断できないため `false_promotions` は N/A
- 保存された上位 20 件の外にある Finding は順位変動を取得できないため、`missed_pkg_not_promoted` に含めない
- 基準順位の行では順位変動と順位上昇を 0 とし、ラベル、見逃しの順位、偽の順位上昇の欄を N/A とする

### 新収集器による確認結果

- ケース 26・27・28 の確認 run は新収集器を使い、`startup`・300 秒窓で実行した
- ケース 27 の Node の再現率は 100% (72/72、アプリ自身の `package.json` を含む)、常駐 OS の再現率は 100% (8/8)
- ケース 26 の常駐 OS の再現率は 94% (17/18)、ケース 28 は 91% (10/11)
- ケース 26 と 28 に残った常駐 OS の見逃し各 1 件はいずれも `tzdata` で、`/etc/localtime` の open がコンテナ起動直後の最初の配置読み取りより前に発生した
- 保存済み symlink 表はケース 26 が 438 件、ケース 28 が 917 件で、ケース 28 の `IsDir` が真のエントリは 2,822 件
- これらの確認 run では打ち切りがなく、偽陽性は 0 件

## 観測状態

| イベントの状態 | 意味 |
| --- | --- |
| `not_attempted` | イベント収集を試みていない |
| `failed` | トレーサーの起動またはアタッチを確認できていない |
| `observed` | 起動とアタッチを確認でき、観測期間の不完全性を示す項目がない |
| `degraded` | 確認済みの収集に不完全性または欠落項目の未計測がある |

- イベントログが空でも `observed` になる場合がある
- イベント件数だけでは起動、アタッチ、完全性を確立できない
- 起動とアタッチの確認後、`lost_events`、`lost_notifications`、`convert_failures`、`map_overflow`、観測期間内の `enter_exit_unmatched` のいずれかが正なら `degraded` になる
- `stopped_early:true` または空でない `unmeasured` がある場合も `degraded` になる
- `partial_events` は `path_read_failures`、`path_truncations`、`enter_exit_unmatched_boundary`、`identity_unavailable` を別に合計する
- これらの不完全なイベントの件数は収集状態を変えない
- したがって `observed` は全イベントのパスや識別情報が利用可能であることを意味しない
- CSV の集計に加えてイベントの注記と JSON の欠落詳細も必要
- 未計測の項目は計測済みのゼロではない

### 境界の残片

- 境界の残片を分類するには変換時に `-window-start` と `-window-end` の両方が必要
- 観測期間は両端の時刻を含む
- 対応する終了がない開始レコードは、その開始時刻が観測期間外なら境界の残片
- 開始時刻を持つ未対応の終了レコードは、その開始時刻が観測期間外なら境界の残片
- 開始時刻がない未対応の終了レコードは、終了時刻が観測開始前の場合だけ境界の残片
- それ以外の未対応レコードは観測期間内の `enter_exit_unmatched` に数える
- 開始時刻がない観測終了後の終了レコードもこの扱いに含む
- 観測期間の両フラグがなければすべての未対応レコードを `enter_exit_unmatched` に数える
- 境界の残片は `enter_exit_unmatched_boundary` として報告する

## CSV ファイル

- すべての表に `case_id` と実行キーの 8 列を含む
- 実行キーの列は `case_variant`、`permission`、`interval`、`window`、`phase`、`replicate`、`sync`、`config_id`

| CSV | 列と読み方 |
| --- | --- |
| `case_summary.csv` | 従来規則の検出結果／パッケージの確認数と確認率、FPR/FNR、GT カバレッジ、`guess_dependency_rate`、`guess_dependency_lower`、`guess_dependency_upper`、`intel_condition`、`intel_source`、イメージの同一性検証、露出の判定 |
| `classification.csv` | 従来規則の全体、優先度別、パッケージクラス別、脆弱性情報が劣化した条件での検出結果数と確認率 |
| `factors.csv` | 判定／要因別の内訳、パッケージ数、全検出結果数、今すぐ対応、要監視、低優先度の件数 |
| `gap_classes.csv` | E1〜E4／未分類の確認ギャップ、回復可能性、パッケージ／検出結果数、今すぐ対応／要監視の件数 |
| `path_resolution.csv` | `ownership`、`trivy_match`、重複を除いた `paths` の集計 |
| `permissions.csv` | `operation`、`result`、`occurrences`、`message` と、`target_finding`、`confirmed`、`unconditional_rate`、`conditional_rate`、`state_observation_failed` |
| `gt_b.csv` | 従来規則の母集団、判定不能数、カバレッジ、TP/FP/TN/FN、FPR/FNR、上限／下限 |
| `g4.csv` | 従来規則とイベント系列の順位比較、優先度、N/A 状態、全検出結果数、上位 20 件の順位変動、ラベル付き件数、`exposure_stages_in_top20`、ラベル付き／ラベルなしの例 |
| `series.csv` | 3 系列の全体、優先度別、パッケージクラス別、エコシステム別、証拠の粒度別の確認指標、観測したバイナリ／ファイル数、収集の完全性、全体の GT-B 精度、系列間の個別増分 |
| `source_inputs.csv` | 証拠源ごとの入力状態、使用確認したパッケージ数、入力欠落や失敗の理由 |
| `mapping.csv` | エコシステム別のスキャン内ファイル、対応したファイル／パッケージ、観測したバイナリ／ファイル数、対応付け不能の理由、候補の競合、未解決・対応付け不能・スキャン範囲外を区別したパス／イベント数 |
| `occurrence_capture.csv` | 対応付け規則、許容誤差、時計の基準、実行／ロード／実オープンの件数と割合、`exec_decidable`、`load_decidable`、`real_open_decidable`、曖昧さ、`exec_undecidable`、`load_undecidable`、除外、未捕捉の理由 |
| `event_drops.csv` | イベント状態、収集設定、全体／帰属済み／観測期間内のイベント数、フィルタリング前後の件数、欠落イベント、欠落通知、マップのオーバーフロー、変換失敗、早期停止の空白期間、不完全なイベントの詳細 |
| `attribution.csv` | `match_rule`、`cross_container_evaluable`、誤帰属と正帰属の件数／割合、別コンテナとホストの誤帰属、ホストの非帰属と未観測数、`host_correct_rate`、帰属不明イベント、`undecidable` |

- `permissions.csv` は失敗した操作がなくても行を含む
- 発生単位の割合は対応する `exec_decidable`、`load_decidable`、`real_open_decidable` を使う
- その分母がゼロの場合は N/A
- 独立した実オープン入力がない場合も実オープン捕捉率は N/A
- `event_drops.csv` は `enter_exit_unmatched` と `enter_exit_unmatched_boundary` を分ける
- `identity_unavailable` と `unmatched_identity_unavailable` も記録する
- `partial_events` の合計はイベント状態を変えない
- `unmeasured` の詳しい説明は JSON と注記に残る
- 帰属の割合はそれぞれの分母がゼロの場合に N/A
- `cross_container_evaluable=false` の場合は `misattribution_rate` も N/A
- ホストの指標と正帰属の指標は分けて扱う
- `tools/record.py` は個別の run 記録を作る
- `tools/aggregate.py` は保存済み run を実験配下の `out/AGGREGATE-events.md` に集約する
- `tools/case-post.sh` は保存済み run を再処理する
- `RECONVERT=1` はトレース変換も再処理に含める

## Docker なしでの動作確認

- `testdata/` の手書き入力を使うと Docker、root、Trivy の実行ファイルなしで `match` を動かせる

```sh
go run ./experiments/runtime-discovery match \
  -observation experiments/runtime-discovery/testdata/synthetic_observation.json \
  -trivy experiments/runtime-discovery/testdata/synthetic_trivy.json \
  -case experiments/runtime-discovery/testdata/synthetic_case.json \
  -gtb experiments/runtime-discovery/testdata/synthetic_gtb.json \
  -intel-cache ./out/intel-cache \
  -out-intel-snapshot ./out/dry-run/intel.json \
  -out-json ./out/dry-run/match.json -out-csv-dir ./out/dry-run/csv
```

- 結果は照合 JSON と 14 本の CSV
- `testdata/` には脆弱性情報スナップショットがない
- そのため初回はネットワークアクセスが必要になる場合がある
- 報告された脆弱性情報の状態とエラーを確認する
- 以後の再現可能な実行では `-intel-snapshot ./out/dry-run/intel.json` を追加する
- 合成データの限定的な GT-B は使用を確認できたものだけを扱う
- イベント捕捉率にはイベントログと独立した発生レコードが必要

## 詳細な制限と注意

- 最初の配置読み取りより前のイベントは過去の配置の不変性を証明できないため、OS の所有者や symlink 表を使わずスキャン索引だけで解決する
- ディレクトリを開いただけではパッケージの使用とみなさず、その除外には保存済み入力のディレクトリ情報が必要になる
- リンクとリンク先の所有者がそれぞれ単独で異なる場合は正解データと同じく両方を使用確認し、どちらかのパス自体に複数の所有者があれば競合として扱う
- 照合の実装上、順位比較は S0 と S2 の 2 系列だけに存在し、保存された上位 20 件から範囲外の Finding の順位変動は確定できない

- 網羅性検証のフィクスチャは apt パッケージの版を固定せず、後日の再ビルドを正解取得時のイメージと同等とはみなさない
- 集計は正解と計測の同一イメージ ID を必要とし、毎回新しいコンテナを作って以前の run の書き込み層を持ち越さない
- 正解と網羅性集計はエコシステムを含む 3 要素のキーを使うが、match の `(class, package, installed_version)` によって異なる言語の同名同版が先に統合される場合がある
- strace は時間とスケジューリングを変えるため、正解と計測は同じ経過時間ではなく操作列と検証済みインスタンスで対応させる
- 操作名が同じだけでは未対応の周期操作インスタンスの同等性を確立できない
- Go 静的バイナリと組み込みモジュールの使用は、この網羅性評価の母集団に含めない
- `coverage_plan` の群は意図した動作であり、推移的なロードによって実測の使用と異なる場合がある
- `completeness.ok` は実装された使用証拠の完全性判定であり、同梱一覧の全入力を正常に読めた保証ではないため、`inventory_scan`、`ledger_gaps`、`version_unknown` も確認する

- このハーネスは製品のバイナリとコンテナイメージから独立している
- デーモンモードと Kubernetes/containerd の観測には対応しない
- `collect` 自体は eBPF イベントを収集しない
- イベント計測には別の [runtime-events ツール](../runtime-events/README.ja.md)を使う
- アドレスのデコードにはホストのネイティブなバイトオーダーを使う
- 観測にはホストアーキテクチャを記録する
- ケース 10/14 は `/usr/lib/x86_64-linux-gnu/libsqlite3.so.0` を固定で使う
- パーサーは手書きフィクスチャで確認している
- 記録された実機計測は開発環境の Linux 6.6 カーネル上で root として行った 300 秒 × 43 run
- その計測は `startup`、`attach_running`、64/256/512 ページのバッファを対象とする
- 初期の 6 秒の動作確認は通常の `open` プローブ追加前の 7 プローブによるもの
- 現行スクリプトは 7 つのトレースポイントと `BEGIN`、`END` を合わせた 9 プローブ
- カーネル 7.0 の本番ホストでの `attach_running` 計測は未実施
- `CAP_BPF` と `CAP_PERFMON` だけを使う収集は未実施
- イベント観測の負荷計測と CO-RE の最小実装は未実施
- 反復番号が 2 以上の計測があるのはケース 13 だけ
- サンプリングは短命な動作を見逃すことがある
- マッピングされた言語拡張が Trivy のパッケージパスと一致するとは限らない
- 追加の対応付けはスキャンのファイル情報と保存済みの補助入力に依存する
- 上限付きの検索は一般的なインストール先のルートを対象とする
- 構成の欠落や切り詰めは後の解決範囲を制限する
- 対象の受け入れは登録準備の完了を示し、完全な対応付けやトレーサーのアタッチを示さない
- イベント観測はアタッチ前に完了した処理を復元できない
- `startup` と `attach_running` の結果は分けて扱う
- Python のモジュール一覧はコンパイル済みキャッシュを読んだ場合もソースファイルを示すことがある
- ケース 15/16 は実際に開いたパス表記を独立に確立しない
- ケース 17/18 の時刻は小数桁が多くても実質的にミリ秒精度
- ケース 19〜21 の Java ロードは開いてあるアーカイブを再度開かずに読むことがある
- `startup_open` と `load_open` は区別して保持する
- ロード時のオープンがないことは未使用を示さない
- これらの Java ケースは独立した OS スレッド識別情報がなく、報告する発生単位の捕捉率から除外する
- 外側の jar の観測は同梱依存の独立したロードや実行を確立しない
- 静的 Go バイナリの観測は個々の組み込みモジュールの実行を確立しない
- 独立した `real_opens` がなければ実際のファイルオープンシステムコールの捕捉率は算出不能
- 同梱のケース 13〜24 が提供するのは使用ログと発生ログであり、そのシステムコール記録ではない
- これらのケースで報告する実オープン捕捉率は N/A
- 記録された帰属対照実験はケース 23 単独、ケース 24 単独、両方同時、ケース 23 とホスト動作を対象とする
- 計測したホスト条件ではコンテナと並行して `/usr/bin/curl` を 5 秒ごとに 50 回実行した
- 評価対象のホスト実行は 41/41 件と 48/48 件でコンテナへの非帰属を確認した
- そのホスト照合では PID 名前空間、名前空間内 PID/TID、プロセス世代を使った
- 記録された規則の下で 4 条件の正帰属率は 1.0
- これらの run は `pid_map` なしの `container_namespace_pid_and_thread` を使った
- コンテナ間誤帰属率は N/A のまま
- ホストの結果はコンテナ間帰属の正しさを確立しない
- 証拠は優先順位を上げるためだけに使う
- 証拠がないことは安全性も優先順位を下げる根拠も示さない
- リスナーの存在はインターネットからの到達可能性を証明しない

## 負荷と権限の計測

### supervise

`supervise` は指定したコマンドを子プロセスとして直接起動し、専用の cgroup v2 への配置、実際の実行ファイルと権限の確認、停止要求への対応、終了時の計測を行う。

```sh
sudo experiments/runtime-discovery/out/runtime-discovery supervise \
  -cgroup /sys/fs/cgroup/runtime-discovery-example \
  -record experiments/runtime-discovery/out/supervise.json \
  -stop-request experiments/runtime-discovery/out/supervise-stop.txt \
  -grace 10 -deadline 30 -- /usr/bin/sleep 20
```

| フラグ | 意味 |
| --- | --- |
| `-cgroup` | 新しく作る cgroup v2 ディレクトリで、既存のディレクトリは使用不可 |
| `-record` | 必須の監督記録 JSON の保存先 |
| `-user` | exec 前に切り替える既存ユーザーの UID/GID で、UID 0 に解決される指定は拒否 |
| `-expect-exe` | 起動後の `/proc/<pid>/exe` と完全一致を確認するパス |
| `-expect-capeff` | 実プロセスの `CapEff` と比較する 16 進値で、英字の大小は区別しない |
| `-unset-env` | 子プロセスの環境から除く変数名のカンマ区切り一覧 |
| `-stop-request` | 1 秒ごとに読むファイルで、空でない内容を停止理由として使用 |
| `-grace` | SIGINT 後と SIGTERM 後にそれぞれ待つ秒数で、既定値は `10` |
| `-deadline` | 起動から停止を要求するまでの上限秒数で、既定値の `0` は期限なし |
| `-allow-unmeasured` | memory コントローラーの利用可能性を確認できなくても続行し、メモリを理由付き未計測として記録 |
| `-keep-cgroup` | 終了後も cgroup とカウンターを残し、呼び出し側による最終読み取りと削除を可能にする |
| `-no-cgroup` | 専用 cgroup を作らずに監督し、cgroup 由来の項目を未計測にする指定で、`-cgroup` とは併用不可 |
| `-- cmd [args...]` | 直接起動するコマンドとその引数 |

- cgroup を使う場合は `/sys/fs/cgroup` 配下に新しいディレクトリを作り、祖先の階層で利用可能な cpu と memory コントローラーの有効化を試みる
- `clone3` の `CLONE_INTO_CGROUP` が使える場合は最初の命令から cgroup 内で実行し、`cgroup_method=clone3_cgroup_fd` と `placement_atomic.value=true` を記録する
- フォールバックでは起動直後に実 PID を `cgroup.procs` に書き、`cgroup_method=post_start_write_fallback` と `placement_atomic.value=false` を記録する
- フォールバックのカウンターには起動直後の CPU と初期メモリの一部が含まれないため、負荷比較では不完全な計測として扱う
- 停止ファイル、監督プロセスへの SIGINT/SIGTERM、実行期限のいずれからも SIGINT、SIGTERM、SIGKILL の順に停止を試みる
- SIGKILL 後の最終待機は 5 秒で、子の終了を確認できない場合は `status=stop_unconfirmed` とし、終了時刻や終了コードを補わない
- 子を回収できても cgroup に子孫タスクが残れば `status=exited_residual_tasks` になる
- `-no-cgroup` では子孫タスクの不在を確認できず、子を回収できても `termination_confirmed` は未計測になる
- `supervise` 自体の終了コードは監督処理の結果であり、子が失敗しても監督が完了すれば 0 になる場合がある

#### supervise.json の主な項目

記録は起動後の確認時に一度書き、停止処理後に最終状態で書き直す。個別に取得成否を持つ値は `measured`、`value`、必要に応じて `reason` を持つオブジェクトで表し、`measured=false` の `value` を計測値として扱わない。

| 項目 | 意味 |
| --- | --- |
| `command`、`pid`、`actual_exe` | 起動したコマンド、実際の子 PID、procfs で読んだ実行ファイル |
| `real_uid`、`effective_uid`、`saved_uid`、`filesystem_uid` | 実プロセスから読み取った 4 種類の UID |
| `cap_eff`、`attr_current`、`limits` | 実プロセスの実効ケーパビリティ、LSM 属性、リソース制限 |
| `exe_verified`、`uid_verified`、`capeff_verified`、`verification_error` | 実行ファイル、UID、CapEff の確認結果と確認不能の理由 |
| `cgroup`、`cgroup_method`、`placement_atomic` | 配置先、配置方法、最初の命令から配置されたか |
| `controllers_enabled`、`controller_warnings` | コントローラー有効化の記録と警告 |
| `started_at_wall`、`started_at_monotonic_s` | 起動時刻と、その起動を 0 とする単調時計の基準 |
| `exited_at_wall`、`exited_at_monotonic_s` | 子の終了を確認した時刻と起動からの経過秒数 |
| `exit_code`、`exit_signal`、`wait_error` | 子の終了コード、終了シグナル、待機処理のエラー |
| `status` | `setup_failed`、`running`、`exited`、`exited_residual_tasks`、`stop_unconfirmed` の状態 |
| `stop_requested`、`stop_reason`、`deadline_exceeded` | 停止要求の有無、理由、実行期限への到達 |
| `termination_confirmed`、`residual_tasks` | 子の回収と残存タスク不在の確認、および cgroup の残存タスク状態 |
| `baseline_cpu_usage_usec`、`final_cpu_usage_usec` | 起動前と停止処理後の累積 CPU 使用量 |
| `baseline_memory_peak_bytes`、`final_memory_peak_bytes` | 起動前と停止処理後の cgroup のメモリピーク |
| `cgroup_removed` | cgroup の削除結果または保持・削除不能の理由 |

`exit_code` は終了を観測していなければ `null` になり、シグナル終了では `-1` と `exit_signal` を記録する。`termination_confirmed` が計測済みの真になるのは、子を回収し、cgroup の `populated=0` も確認できた場合である。

### cgroup-stat と cgroup-remove

`cgroup-stat` は指定した cgroup の CPU、メモリピーク、残存タスク状態を JSON として標準出力へ書く。

```sh
experiments/runtime-discovery/out/runtime-discovery cgroup-stat "<cgroup v2 directory>"
```

- 必須の位置引数は読み取る cgroup v2 ディレクトリ 1 つ
- 出力は `path`、`cpu_usage_usec`、`memory_peak_bytes`、`populated` を含む
- CPU は `cpu.stat` の `usage_usec`、メモリは `memory.peak`、残存タスク状態は `cgroup.events` の `populated` から読む
- 各項目の取得成否は独立しており、コマンドが正常終了してもすべてを計測できたとは限らない

`cgroup-remove` は cgroup のタスクがなくなるのを待ち、ディレクトリを削除して結果を JSON として標準出力へ書く。

```sh
sudo experiments/runtime-discovery/out/runtime-discovery cgroup-remove \
  -wait 30 "<cgroup v2 directory>"
```

- 必須の位置引数は削除する cgroup v2 ディレクトリ 1 つで、`-wait` の既定値は `30` 秒
- 出力は `path`、`populated`、`removed`、`waited_s` を含む
- 空であることは `cgroup.events` の `populated=0` で確認し、`cgroup.procs` のファイルサイズから推測しない
- すでに存在しないディレクトリは理由付きの削除済みとして扱う
- 読み取り不能、待機期限後もタスクが残る場合、削除に失敗した場合は理由を記録して非ゼロで終了する
- `-keep-cgroup` で保持した階層は最終読み取り後に子 cgroup から削除し、最後に親を削除する

### optime と運用処理の時間

`optime -- cmd [args...]` はコマンドを子として起動し、起動処理から回収までの経過時間を `CLOCK_MONOTONIC` で測って JSON 1 行を標準出力へ書く。子コマンドの標準出力と標準エラーは破棄する。

- `cases/run.sh` の `stage_optime` は `CGO_ENABLED=0 GOOS=linux GOARCH=amd64` で静的バイナリをビルドする
- ビルド先は各ケースの `cases/images/*/optime` で、ケース 26〜28 の Dockerfile が `/usr/local/bin/optime` へコピーする
- 配置済みの実行ファイルが `cmd/optime/main.go` より新しければ再ビルドを省略する
- 各イメージの `os-ops.sh` は curl、git、openssl をこのヘルパー経由で実行する
- `optime` の `pid` と `starttime` は実際に包んだ子コマンドの識別情報で、`starttime` を読めない場合は 0 を記録する
- 所要時間は単調時計の差をマイクロ秒へ切り捨て、壁時計の開始・終了時刻とは別に保存する

| 出力先 | 項目と意味 |
| --- | --- |
| `optime` の標準出力 | `pid`、`starttime`、`start_wall`、`end_wall`、`duration_us`、`exit_code`、`clock_source` |
| `operations.jsonl` の既存項目 | `id`、`ts`、`op`、`ok` を維持し、`op` は `osops_curl`、`osops_git`、`osops_openssl` |
| `operations.jsonl` の追加項目 | `end_ts`、`duration_ms`、`exit_code`、`clock_source`、`clock_resolution_ms` |
| `duration_ms` | `optime` の `duration_us` を 1000 で割り、小数点以下 3 桁で記録したミリ秒値 |
| `clock_source`、`clock_resolution_ms` | `CLOCK_MONOTONIC` と `0.001` |
| `exit_code` | 子コマンドの終了コードで、`ok` はこの値が 0 かどうかを示す |

`duration_us` は `optime` の出力項目であり、現在の `operations.jsonl` に直接保存する項目ではない。既存項目を置き換えずに追加するため、従来の操作列を読む処理は引き続き使える。時間項目を持たない古い `operations.jsonl` の所要時間は理由付き未計測になる。

### load-run.sh と load.json

`tools/load-run.sh <case> [replicate] [config] [interval] [window]` は root で実行し、ケース 26〜28 を `attach_running` で計測する。既定値は反復 `1`、設定 `procfs`、間隔 `30` 秒、窓 `300` 秒である。

| 設定 | 実行する観測 |
| --- | --- |
| `none` | コレクターもトレーサーも起動せず、observation を生成しない |
| `procfs` | コレクターを起動する |
| `events` | コレクターと 512 ページの nofilter トレーサーを起動する |

すべての設定で同じワークロードとホスト側 Web リクエストを動かす。ワークロードの開始通知と遅延処理の完了を待ち、監視を開始し、イベント設定ではアタッチ確認と cgroup 対応表の登録を行ってから窓開始時刻を決める。コレクターにはその時刻を `-phase-base` として渡す。

保存先は `experiments/runtime-discovery/out/<case>-load-<config>-<interval>-<window>-r<replicate>-attach_running/` である。

| ファイル | 内容 |
| --- | --- |
| `run.log`、`case.json`、`clock.json` | 実行ログ、ケース定義、時計変換 |
| `container_id.txt`、`image_id.txt`、`fired_at.txt` | コンテナとイメージの識別情報、開始通知後の記録時刻 |
| `collector_supervise.json`、`tracer_supervise.json` | 起動した各プロセスの監督記録 |
| `cgroup-<target>-wstart.json`、`cgroup-<target>-wend.json` | `collector`、`tracer`、`docker` のうち該当する対象の窓開始・終了時の読み取り |
| `cgroup-remove-<target>.json` | `collector`、`tracer`、`parent` の削除記録 |
| `collect/` | コレクターを動かす設定の observation と manifest |
| `trace.txt`、`trace.err`、`events.jsonl`、`cgroup-map.json` | イベント設定のトレース、時刻付き標準エラー、変換済みイベント、cgroup 対応表 |
| `trace-stdout-wstart-bytes.txt`、`trace-stdout-wend-bytes.txt`、`trace-stderr-wstart-bytes.txt`、`trace-stderr-wend-bytes.txt` | 窓開始・終了時のトレース出力バイト数 |
| `gtb-raw/` | `usage.jsonl`、`occurrences.jsonl`、`operations.jsonl`、`runtime-modules.jsonl`、`docker-top.txt` |
| `web_timing.jsonl`、`web_timing.err` | ホスト側 Web リクエストの応答記録とエラー |
| `watch_targets.txt`、`watch.jsonl`、`watch.log` | 監視対象、監視サンプル、監視プロセスのログ |
| `stop_request.txt`、`termination_confirmed.txt`、`stop_failures.txt` | 該当する場合の停止要求、終了確認、停止確認失敗の理由 |
| `load.json` | `load_run_assemble.py` が生の記録から作る run の負荷要約 |

`stop_request.txt` は早期停止に加えて、監督対象がある run の通常の窓終了時にも停止処理のために作成される。早期停止の判定には `load.json` の `stopped_early` と `stop_reason` を使う。

#### 4 つのチェックポイント

| チェックポイント | 読み取り元と意味 |
| --- | --- |
| `before_start` | `supervise` の `baseline_*` で、子の起動前 |
| `window_start` | ランナーの `cgroup-stat` で、共通の観測窓が開く時点 |
| `window_end` | ランナーの `cgroup-stat` で、停止処理を要求する前に窓を閉じる時点 |
| `process_exit` | `supervise` の `final_*` で、子の終了待機・停止処理後 |

- コレクターとトレーサーの CPU は `prep`、`window`、`drain`、`total` に分ける
- `prep` は起動前から窓開始、`window` は窓開始から終了、`drain` は窓終了から最終読み取り、`total` は起動前から最終読み取りの差分
- JSON の項目名は `collector_cpu_usage_delta_<segment>_us` と `tracer_cpu_usage_delta_<segment>_us`
- コレクターが全予定サンプルを取得して窓終了前に退出しても、`-keep-cgroup` により窓終了時のカウンターを読み取れる
- `collector_memory_peak_bytes` と `tracer_memory_peak_bytes` は cgroup の存続期間全体のピークで、窓内だけのピークではない
- `docker_daemon_cpu_usage_delta_window_us` は全設定で同じデーモン cgroup を窓開始・終了時に直接読み取った差分
- 読めない値や減少したカウンターの差分は理由付き未計測とする

#### 観測窓と計測完了

| 項目 | 意味 |
| --- | --- |
| `run_id`、`case`、`config`、`interval`、`window`、`replicate`、`sync` | run の条件 |
| `container_id`、`image_id`、`fired_at` | ワークロードの識別情報と開始通知後の記録時刻 |
| `window_start_wall`、`window_end_wall`、`window_end_planned_wall` | 窓開始、実際に閉じた時刻、予定終了時刻 |
| `tracer_exited_at_wall` | トレーサーの監督記録から得た終了時刻または未計測理由 |
| `window_established`、`window_start_drift_s` | 予定どおりの窓開始が成立したかとランナーの開始ずれ |
| `collector_first_sample_delay_s` | コレクターの最初のサンプルが予定時刻から遅れた秒数 |
| `stopped_early`、`stop_reason` | 早期停止の有無と停止理由 |
| `measurement_complete`、`measurement_incomplete_reasons` | 監督・観測の完了判定と不成立の理由 |
| `collector_valid_samples`、`collector_invalid_samples` | コレクターの collection results にある有効・無効件数 |
| `cgroup_cleanup`、`stop_failures`、`notes` | cgroup 削除結果、停止確認の失敗、解釈のための注記 |
| `dump_logs_ok`、`watch_samples`、`watch_stop_reason` | ワークロードログ取得の成否、監視サンプル数、停止理由 |

窓開始までの余裕は `KL_WINDOW_LEAD_S` の既定値で 5 秒、開始ずれの許容値は `KL_WINDOW_START_TOLERANCE_S` の既定値で 2 秒である。ランナーの開始ずれ、またはコレクターの最初のサンプルの遅れが許容値を超えると `window_established=false` になる。

`measurement_complete=false` の理由には次のものがある。

- 監督記録の欠落、cgroup 配置の非 atomic または確認不能、終了確認の不成立
- 記録された cgroup 削除の失敗やランナーの停止確認失敗
- コレクターの終了コードの欠落または非ゼロ終了
- observation やサンプル時刻の欠落、予定サンプル数未満の試行、対象の inspect 失敗
- collection results の欠落、または有効な観測が 1 件もない状態
- トレーサーのアタッチ未確認、またはイベント収集が `failed` の状態
- トレーサー終了時刻の欠落、または予定窓終了より前の退出

予定サンプル数は `max(1, window // interval)` である。全サンプルを試行したコレクターが窓終了より前に退出すること自体は未完了の理由にならない。`measurement_complete`、`window_established`、`stopped_early` は独立した項目であり、個々の未計測値やイベントの劣化状態も別に確認する。

`comparison_blocker` は `load.py` の比較判定関数で、`load.json` の項目名ではない。同じケース、間隔、窓、反復番号の `none` 対照を探し、次の理由があれば比較を止める。

- 対応する `none` 対照がない
- 比較するいずれかの run が早期停止した
- いずれかの `window_established` が真と記録されていない
- いずれかの `measurement_complete` が真と記録されていない
- 予定した窓の長さが異なる
- イメージ ID が欠落しているか一致しない

判定は集計表の `comparable_to_none` と `not_comparable_because` に出力する。比較できない場合も取得済みの絶対値を残し、中央値の差分を理由付き未計測にする。`none` 行は自分自身を対照とするためこの比較判定を適用せず、取得済み中央値の自己差分は 0 になる。

#### イベント、出力増分、ワークロード

- `events_total` と `events_attributed` は実際に開いていた窓に `ts` が入るイベントの全件数と対象コンテナへの帰属件数
- `events_total_per_second` と `events_attributed_per_second` はそれぞれの件数を実際の窓の秒数で割った値
- `events_outside_window` は窓内として数えなかったイベント数
- `drops` は変換トレーラー由来の欠落情報であり、窓内イベント件数と同じ方法で再抽出した値ではない
- `drops` には `lost_events`、`lost_notifications`、`map_overflow`、`convert_failures`、`enter_exit_unmatched`、`enter_exit_unmatched_boundary`、`path_read_failures`、`path_truncations`、`identity_unavailable`、`unmatched_identity_unavailable`、`events_before_filter`、`events_after_filter` を保存する
- `partial_events` は従来のルールと同じくパス読み取り失敗、パス切り詰め、境界の未対応片、識別情報不足を合計する
- `malformed_lines` は変換済み JSONL の解析不能行数で、トレーラーがあればその `convert_failures` にも加える
- トレーラーがない場合は欠落項目をゼロで補わず、解析不能行を実際に数えた場合の `convert_failures` を除いて未計測にする
- `event_state` は `not_attempted`、`failed`、`observed`、`degraded` を使い、トレーラー欠落、解析不能行、早期停止、欠落や未計測項目を劣化判定に含める
- `trace_stdout_bytes` と `trace_stderr_bytes` はトレース全体のサイズで、対応する `*_bytes_per_second` は窓開始・終了時のバイト数の増分を実際の窓の秒数で割る
- `*_bytes_per_second_whole_lifetime` はトレーサーの存続期間全体を分母とする別項目
- `run_dir_growth_bytes` は空の状態から開始した run ディレクトリにあるファイルサイズの合計

`workload.curl`、`workload.git`、`workload.openssl` は `operations.jsonl` の開始・終了がともに窓内にある運用処理を集計する。境界をまたぐ処理と時刻不明の処理は `boundary_crossing`、完全に窓外の処理は `outside_window` に分ける。

- 各統計は `n`、成功した処理の `median_ms`、`p95_ms`、`max_ms`、失敗数の `failures` を持つ
- 中央値と p95 は nearest-rank で求め、値の補間は行わない
- 該当処理がない場合は `state` に未計測理由を記録し、すべて失敗した場合は所要時間の統計を未計測にする
- `workload.web` はホスト側の 5 秒ごとの予定に基づくリクエストを集計する
- Web リクエストは接続タイムアウト 2 秒、全体の上限 4 秒で、curl が正常終了した HTTP 2xx/3xx を成功とする
- `web_timing.jsonl` は `planned_ts`、`ts`、`seq`、`status`、`latency_ms`、`ok`、`curl_exit`、`timeout_type` を記録する
- Web 統計には `success_count`、`timeout_count`、`failure_count` を加え、`operation_timeout` だけをタイムアウトに分類する
- 接続失敗、名前解決失敗、空応答、HTTP の不成功などはタイムアウト以外の失敗に数える

### watch-run.sh の停止条件と上限

`tools/watch-run.sh <run dir> <out root dir> <targets file> <stop file>` は通常 `load-run.sh` が起動する。必須引数は run の保存先、共有出力先、監視対象ファイル、共有停止要求ファイルの順である。

| 環境変数 | 既定値と停止条件 |
| --- | --- |
| `KL_WATCH_INTERVAL` | 監視間隔 `10` 秒 |
| `KL_WATCH_CPU_CORES` | トレーサー CPU が `1` コア相当を超える状態が 3 サンプル連続 |
| `KL_WATCH_RUN_BYTES` | run が `1073741824` バイトを超過 |
| `KL_WATCH_ROOT_BYTES` | 共有出力先が `4294967296` バイトを超過 |
| `KL_WATCH_FREE_BYTES` | 空き容量が `21474836480` バイト未満 |
| `KL_WATCH_WEB_FAILURES` | 記録順に Web 応答が `3` 回連続で失敗 |

- 欠落通知件数の 3 サンプル連続増加も停止条件で、この連続回数を変更する環境変数はない
- CPU のコア相当値は cgroup CPU の差分を `/proc/uptime` の単調な経過時間で割り、固定の監視間隔を分母にしない
- CPU の読み取りに失敗すると前回値を破棄し、次の正常な読み取りを新しい基準にする
- Web の連続失敗は応答ごとに判定し、同じ監視サンプル内の後続成功で到達済みのしきい値を取り消さない
- 監視スクリプトは対象へ直接シグナルを送らず、停止理由を共有ファイルへ書く
- すでに空でない停止理由があれば上書きしない
- 停止要求後も監視を続け、各読み取りを `watch.jsonl`、停止要求と監視上限到達を `run.log` に記録する

#### targets ファイル

| キー | 意味 |
| --- | --- |
| `tracer_pid`、`collector_pid` | ランナーが通知する監視用 PID で、現在のランナーでは各 `supervise` の PID |
| `tracer_cgroup`、`trace_err`、`web_timing` | CPU、欠落通知、Web 応答の読み取り先 |
| `expect_tracer`、`expect_collector` | 起動前も含め、その run が各監督対象を持つ予定かを表す `0` または `1` |
| `min_until_epoch` | 監視を続ける観測窓の予定終了 epoch 秒 |
| `termination_confirmed_file` | ランナーが全監督対象の終了を確認してから書くファイルのパス |
| `residual_unconfirmed` | ランナーが終了確認不能と判定した場合の `1` |
| `watch_until_epoch` | 監視プロセス自身が待つ絶対上限の epoch 秒 |

targets ファイルは各サンプルで読み直す。通常終了には、予定した監視用 PID が通知されて退出したこと、窓の予定終了への到達、空でない `termination_confirmed_file` が必要になる。`residual_unconfirmed=1` の場合は終了確認済みと扱わない。`expect_*` のない従来形式では、通知された PID がすべて退出したかを使う。

`watch_until_epoch` に到達すると終了確認不能として `WATCH_EXIT` を記録し、終了コード 3 で監視を終える。`load-run.sh` は窓終了予定時刻に `KL_RESIDUAL_WATCH_S` の既定値 1800 秒を加えてこの上限を設定し、準備中や終了確認失敗時にも有限の上限を通知する。全監督対象の終了を確認できた場合は確認ファイルを書いて監視を停止し、cgroup を削除する。確認できない場合は監視と cgroup を残して非ゼロで終了する。監督対象のない `none` も容量と Web を監視し、窓終了・停止処理後にランナーが監視を止める。

監督対象の実行期限は `supervise -deadline` が別に管理する。`load-run.sh` はトレーサーに準備予算、窓開始までの余裕、窓長、期限猶予の合計を渡し、コレクターには準備予算を除く合計を渡す。準備予算は `KL_PREP_BUDGET_S=180`、期限猶予は `KL_WATCH_HARD_DEADLINE_GRACE_S=120` が既定値である。

### privilege-run.sh の操作と判定

`tools/privilege-run.sh <condition>` は root で実行する。非 root 条件の対象は `KL_PRIV_USER` が指定する既存ユーザーで、ユーザーの作成は行わない。

| 条件 | 実行ユーザーとコピーに付けるケーパビリティ |
| --- | --- |
| `root` | root として実行し、コピーにはケーパビリティを付けない |
| `bpf_perfmon` | 非 root で `cap_bpf,cap_perfmon=ep` |
| `bpf_perfmon_dac` | 非 root で `cap_bpf,cap_perfmon,cap_dac_read_search=ep` |
| `sysadmin` | 非 root で `cap_sys_admin=ep` |

ケーパビリティは `/var/tmp` の専用ディレクトリに置いた bpftrace と `runtime-events` の両コピーへ付ける。システムの実行ファイルと sysctl は変更しない。結果は `out/privilege-<condition>.json` と `.md`、生の証拠は `out/privilege-<condition>-artifacts/` に保存する。ここでの `out/` は `experiments/runtime-discovery/out/` を指す。

| 操作キー | 確認内容と判定 |
| --- | --- |
| `bpf_program_load` | nofilter スクリプトの `--dry-run -v` でロード段階を調べ、ロード完了を成功、ロード段階のエラーを失敗、段階不明を未到達とする |
| `tracepoint_attach` | 通常起動したトレーサーに対する `attach-check` の既知イベント確認を成功とし、ロード未完了・段階不明を未到達、それ以外のアタッチ未確認を失敗とする |
| `buffer_create_and_read` | アタッチ確認後に一時コンテナ内の固有マーカーを実行し、トレースに届けば成功、届かなければ失敗、アタッチ未確認なら未到達とする |
| `cgroup_id_map` | `runtime-events cgroup-map` の子終了コード 0 に加え、空でない `entries`、空の `errors`、各 entry の `handle_error` 不在、当該操作の cgroup の存在を確認して成功とする |

- `result=success` は当該操作の確認条件を満たしたことを示す
- `result=failure` は権限条件が成立した上で当該操作の確認に失敗したことを示す
- `result=unreached` は準備失敗、権限条件不成立、前段階未完了、到達段階不明などで当該操作を評価できないことを示す
- 未実施の条件や記録のない実行に成功・失敗を補わず、現行ツールは未実施専用の第 4 の `result` 値を生成しない
- 要約作成時に操作結果ファイルがない場合も、既定値は理由付きの `unreached`
- 操作の `exit_code` と `exit_signal` は子の結果で、`supervisor_exit_code` は監督処理の結果

#### 段階判定と condition_established

bpftrace の段階判定は v0.25.0 の自由記述ログに対する発見的規則である。機械可読の段階報告ではないため、次の順序で判定する。

1. `--dry-run` の子終了コードが 0 ならロード成功とする
2. `Attached N probes` があればロード完了とする
3. `cannot attach probe` などのアタッチ時エラーは `attach_failed` とし、ロード自体は完了したものとする
4. コンパイル、verifier、プログラムロードのエラーは `load_failed` とする
5. それ以外は `unknown` とし、終了コードだけで段階を推測しない

各操作の `condition_established` は操作結果と別に記録する。実行ファイルの一致を確認し、非 root 条件では実 UID と実効 UID が指定ユーザーに一致して実効 UID が非ゼロであること、CapEff が要求したビット集合と一致することも確認する。`root` 条件は root として起動したランナーから実行し、条件判定では実行ファイルの一致を確認する。

- 確認できれば `condition_established=true`、確認に失敗すれば `false` と理由を `condition_detail` に記録する
- 条件確認まで到達しなければ `condition_established=null` になる
- 条件不成立は `condition_not_established` の理由を持つ未到達とし、その条件での操作失敗と混同しない
- `errno` はログに明示された数値だけを採用し、記述がなければ `unknown`
- `denying_layer` はログの語句から `perf_bpf_check`、`tracefs_dac`、`lsm`、`unknown` に分類する発見的な情報
- 要約には要求ケーパビリティ、バイナリの SHA-256、3 種類の sysctl、lockdown、取得できた操作の procfs 情報を残す
- `log_excerpt` は末尾最大 4000 文字で、完全なログと監督記録は artifacts に保持する
- 未到達操作の要約は理由と条件確認状態を中心に保存し、起動済み操作の詳細は artifacts の監督記録でも確認する

作業ディレクトリの削除は、開始した全操作の監督記録で終了を確認し、証拠を保存できた後に行う。監督記録の欠落、残存タスク、監督プロセスの待機失敗、証拠の保存失敗があれば元の作業ディレクトリを残し、理由とパスを報告して非ゼロで終了する。

### AGGREGATE-load の列

`tools/load.py [out dir]` は対象ディレクトリ直下の負荷 run の `load.json` を読み、run ごとに 1 行を持つ `AGGREGATE-load.md` と `AGGREGATE-load.csv` を作る。省略時のディレクトリは `experiments/runtime-discovery/out` である。

| 列 | 意味 |
| --- | --- |
| `run`、`case`、`config`、`interval`、`window`、`replicate` | run 名と計測条件 |
| `stopped_early`、`stop_reason` | 早期停止とその理由 |
| `window_established`、`measurement_complete` | 窓の成立と計測完了 |
| `comparable_to_none`、`not_comparable_because` | 対応する対照との比較可否と理由 |
| `collector_cpu_prep_s`、`collector_cpu_window_s`、`collector_cpu_drain_s`、`collector_cpu_total_s` | コレクターの区間別・全体 CPU 使用秒数 |
| `collector_memory_peak_bytes` | コレクター cgroup のメモリピーク |
| `tracer_cpu_prep_s`、`tracer_cpu_window_s`、`tracer_cpu_drain_s`、`tracer_cpu_total_s` | トレーサーの区間別・全体 CPU 使用秒数 |
| `tracer_memory_peak_bytes` | トレーサー cgroup のメモリピーク |
| `dockerd_cpu_window_s` | Docker デーモンの窓内 CPU 使用秒数 |
| `events_total`、`events_total_per_second`、`events_attributed`、`events_attributed_per_second` | 窓内の全イベント・帰属イベントの件数と毎秒件数 |
| `event_state`、`partial_events`、`malformed_lines` | イベント状態、不完全なイベント数、解析不能行数 |
| `lost_events`、`lost_notifications`、`map_overflow`、`convert_failures`、`enter_exit_unmatched` | 集計表に載せる欠落・変換失敗・窓内未対応片 |
| `trace_stdout_bytes`、`trace_stdout_bytes_per_second`、`trace_stderr_bytes`、`trace_stderr_bytes_per_second` | トレース全体のサイズと窓内の出力増加速度 |
| `run_dir_growth_bytes` | run ディレクトリのファイルサイズ合計 |
| `<kind>_n`、`<kind>_median_ms`、`<kind>_p95_ms`、`<kind>_max_ms`、`<kind>_failures` | `<kind>` が `curl`、`git`、`openssl`、`web` の各統計 |
| `<kind>_median_delta_ms` | 各中央値から対応する `none` 対照の中央値を引いた値 |
| `web_success_count`、`web_timeout_count`、`web_failure_count` | Web の成功、タイムアウト、それ以外の失敗件数 |

CPU は `load.json` のマイクロ秒から秒へ変換し、小数点以下 3 桁に丸める。比較差分の列は運用処理と Web の中央値に限られる。未計測値は `n/a (<reason>)` と表示し、`load.json` の詳細な欠落項目、境界処理、監督記録も併せて読む。

## 稼働中コンテナの観測

`prod-precheck.sh` で観測先の要件を確認し、`prod-observe.sh` で稼働中コンテナを `attach_running` として観測する。観測結果は世代ごとに照合し、`prod_summary.py` で HIGH/CRITICAL Finding の証拠を 3 区分に集計する。

### collect の再起動追跡

| フラグ | 意味 |
| --- | --- |
| `-track-restarts` | 対象の再起動・再作成を検出し、世代ごとに記録を分割する指定で、既定値は `false` |
| `-restarts-file` | 世代イベントを追記する JSONL のパスで、既定値は `<out-dir>/restarts.jsonl`、`-track-restarts` がない場合は未使用 |
| `-load-unmeasured` | cgroup 由来の負荷を読み取らずに未計測とする理由文字列で、空でなければ有効 |

再起動追跡はサンプルごとの Docker API 確認で行う。

- 同一コンテナ ID の空でない `StartedAt` が以前の値から変わると `restart` を記録する
- 旧 ID への `docker top` が失敗した場合は稼働中コンテナを再取得し、同じ名前の別 ID が見つかれば `recreate` を記録する
- `StartedAt` の欠落だけを再起動とせず、一覧取得失敗や同名の置き換えが見つからない場合は次のサンプルで再確認する
- 変更を検出したサンプルの失敗記録は旧世代に残し、新世代ではパッケージ索引のキャッシュ、証拠の重複管理、追加入力の索引を引き継がずにレイアウトを読み直す

`restarts.jsonl` の各行は次の項目を持つ。

| 項目 | 意味 |
| --- | --- |
| `kind` | `restart` または `recreate` |
| `container_name` | 追跡対象の名前 |
| `old_container_id`、`new_container_id` | 変更前後のコンテナ ID |
| `image_id_before`、`image_id_after` | 変更前後のイメージ ID |
| `started_at_before`、`started_at_after` | 変更前後の開始時刻 |
| `detected_at` | 変更または補正を検出した時刻 |
| `sample_id` | 変更を検出したサンプルの ID で、補正イベントでは省略される |

#### 世代の観測窓と保留・補正

旧世代の `window.scheduled_end` は、変更検出時に新世代の確定を待たずに閉じる。境界には解析可能な新世代の `StartedAt` を優先し、取得できなければ `detected_at` を使い、run 全体の予定窓の範囲内に収める。旧世代の終端がすでに狭められている場合は、再試行や保留中の追加変更で後ろへ延ばさない。

新しい ID の一覧取得や inspect に失敗した場合は、新世代への切り替えを保留して次のサンプルで再試行する。保留中も旧世代の窓は閉じたままになる。新世代の開始は確定時の識別情報から計算し、その世代の `StartedAt`、または検出時刻を run 全体の窓に収めて `window.scheduled_start` とする。終端は run 全体の予定終了時刻になる。保留中にさらに変更が起きた場合、旧世代の終端と確定した新世代の開始が一致するとは限らない。

確定時の inspect で検出時の情報との差が分かった場合は、元イベントを残して補正イベントを追記する。

- 検出時の `started_at_after` が空で、確定時に取得できた場合は、元の `kind` と前後の ID を保ったまま開始時刻を補う
- 検出時にも開始時刻があり、確定時に別の開始時刻になっていた場合は、さらに世代が変わったものとして検出時の新 ID から確定した ID へのイベントを追加する
- 追加変更の `kind` は補正イベント自身の前後の ID で決まり、同じ ID なら `restart`、異なる ID なら `recreate` になる

確定した新世代ではレイアウト取得を試み、失敗した場合は `generation_prepare_failed` をその記録に残す。観測できなかった中間世代の証拠を補って作ることはない。

#### 世代ごとの記録ファイル

世代が 1 つなら `<name>__<run-key>.json`、複数なら `<name>__<run-key>__gen1.json`、`__gen2.json` のように観測順の番号を付ける。`<name>` はファイル名用に整形したコンテナ名で、名前が空なら ID を使う。`<run-key>` にはケース種別、権限、間隔、窓長、位相、反復番号、同期条件、収集構成を含める。manifest には各世代のコンテナ ID・名前・ファイル名を記録する。

過去の世代のサンプルや証拠を新世代へ混ぜない。初回パッケージ DB 読み取りの負荷は各世代に保持するが、定常観測と Docker デーモンの負荷はコレクターのサンプルループ全体を測った同じ値が各世代に入るため、世代間で加算しない。

### 負荷の未計測と途中保存

`-load-unmeasured "<reason>"` を指定すると、コレクター自身と Docker デーモンの cgroup 読み取りを省略し、定常観測と Docker デーモンの負荷を `measured=false` と理由付きで保存する。メモリピークも未計測になる。専用 cgroup のないプロセスが継承先の共有 cgroup を読み、他のプロセスの負荷を自身の負荷として扱うことを防ぐ。初回パッケージ DB 読み取りの計測は別に保持する。

サンプルループで SIGTERM または SIGINT を受けると、次のサンプルを開始せず、取得済みの観測と負荷、世代ごとのファイル、manifest を保存する。これはサンプルループで受けた停止要求の処理であり、準備中の終了や SIGKILL による保存を保証するものではない。

- manifest の `errors` に受信シグナルと実施済み・予定サンプル数を記録する
- 各対象の最後の世代に `collector_stopped_early` の failure を追加する
- 未実施の予定サンプルごとに `proc_observe=top_failed`、`pkgdb_read=error`、`valid=false` の collection result を追加する
- すでに終了した旧世代には、その後のシグナルによる未実施サンプルを追加しない

この無効な collection result により、`match` は短縮された記録を通常完了した小さな窓と区別できる。有効な観測が残っていれば `observation_state=partially_observed`、有効な観測がなければ `observation_failed` となり、未実施分を含む収集は `collection_complete=false` として扱われる。

### prod-precheck.sh

```sh
sudo bash experiments/runtime-discovery/tools/prod-precheck.sh \
  /var/tmp/runtime-discovery-prod/precheck 512
```

必須の `<out dir>` と、省略可能な `[64|256|512|none]` を受け取り、ページ数の既定値は `512` である。`precheck.json` と `precheck.md`、確認に使った生データを `raw/` に保存する。

| precheck.json の項目 | 内容 |
| --- | --- |
| `generated_at`、`selected_pages` | 作成時刻と選択したページ数 |
| `kernel`、`btf` | カーネル情報と BTF の存在・詳細 |
| `tracepoints` | 各 tracepoint の `present` と `required` |
| `bpftrace_version`、`bpftool_version` | ツールのバージョンまたは未導入の記録 |
| `cgroup2`、`procfs_mount_options` | cgroup v2 の確認結果と procfs マウントオプション |
| `sysctls` | `kernel/unprivileged_bpf_disabled`、`kernel/perf_event_paranoid`、`kernel/yama/ptrace_scope` |
| `lockdown`、`apparmor` | lockdown、AppArmor の有効化状態と実行シェルのプロファイルなど |
| `docker` | サーバーバージョン、OS、cgroup driver と version |
| `running_containers` | 稼働中コンテナの `name`、`id`、`image_id`、`started_at` |
| `free_bytes_on_output_filesystem` | 出力先の空きバイト数で、取得不能なら `null` |
| `dry_run` | 64・256・512 ページの各スクリプトの dry-run 結果 |
| `hard_failures`、`ok` | 必須要件の失敗一覧と総合判定 |

BTF、cgroup v2、ネイティブ Docker Engine への到達性、`open`・`openat`・`openat2` の enter/exit と `sched_process_exec` の tracepoint を必須として扱う。`sys_enter_execve` は存在を記録するが必須ではない。

bpftrace があれば全 3 スクリプトを確認するが、必須判定に使う dry-run は選択したページ数のものだけである。`none` は bpftrace の存在と選択スクリプトの成功を必須にしないが、BTF や必須 tracepoint など他の確認を解除する指定ではない。bpftool、空き容量、sysctl や AppArmor の記録自体には、追加のしきい値判定を設けていない。`hard_failures` が空でなければ終了コード 1、引数や実行ユーザーなどのエラーは終了コード 2 になる。

コンテナ操作と sysctl の変更は行わない。

### prod-observe.sh の run

```sh
sudo KL_PROD_PAGES=512 bash experiments/runtime-discovery/tools/prod-observe.sh \
  /var/tmp/runtime-discovery-prod/run-001 300 api worker
```

引数は `<out dir> <window seconds> [container names...]` で、root と到達可能なネイティブ Docker Engine を必要とする。省略したコンテナ名は開始時の稼働中一覧から決める。新しく別名で現れたコンテナを継続的に対象へ追加する指定ではない。

| 環境変数 | 既定値と用途 |
| --- | --- |
| `KL_RD_BIN`、`KL_RE_BIN` | `experiments/runtime-discovery/out/runtime-discovery` と `experiments/runtime-discovery/out/runtime-events` |
| `KL_PROD_PAGES` | `512` で、`64`・`256`・`512`・`none` から選択 |
| `KL_PROD_INTERVAL`、`KL_PROD_MAX_SECONDS` | サンプル開始間隔 `30` 秒と観測窓の上限 `1800` 秒 |
| `KL_PROD_ALLOW_UNMEASURED_LOAD` | `0` で、`1` にすると両観測プロセスで専用 cgroup を使わない |
| `KL_TRIVY_CMD` | `trivy` で、空白で引数に分割したコマンドからスキャン結果を標準出力で取得 |
| `KL_INTEL_SNAPSHOT` | 指定すると保存済み KEV/EPSS スナップショットを使用 |
| `KL_PROD_CGROUP_REFRESH_SECONDS` | cgroup 表の定期更新間隔 `60` 秒 |
| `KL_PROD_RESTART_POLL_SECONDS` | 世代イベントの追記を確認する間隔 `5` 秒 |
| `KL_WINDOW_LEAD_S`、`KL_WINDOW_START_TOLERANCE_S` | 窓開始までの余裕 `5` 秒と開始遅延の許容値 `2` 秒 |
| `KL_STOP_TIMEOUT_S`、`KL_SUPERVISE_WAIT_S` | 各停止シグナル段階の猶予 `15` 秒と監督プロセスの待機時間 `90` 秒 |
| `KL_PREP_BUDGET_S`、`KL_WATCH_HARD_DEADLINE_GRACE_S` | 準備予算 `180` 秒と実行期限の猶予 `120` 秒 |
| `KL_CGROUP_REMOVE_WAIT_S` | 各 cgroup の削除待機 `30` 秒 |
| `KL_PROD_LOG_BYTES` | `run.log` の末尾保持に使う上限 `52428800` バイト |
| `KL_ROOT` | 配置を変更した場合のリポジトリルートで、既定値はスクリプトから 3 階層上 |

観測窓は上限を適用した後もサンプル開始間隔以上である必要がある。トレーサーのアタッチ確認と初回 cgroup 登録後に run 全体の予定窓を決め、コレクターに同じ開始時刻を `-phase-base` として渡す。`run_window.json` の `scheduled_start` と `scheduled_end` は世代分割で変更せず、イベント変換もこの窓を使う。

イベント収集時は cgroup 表を定期更新し、`restarts.jsonl` の行数増加を検出した際にも更新する。各世代は自身のイメージ ID をスキャンし、同じ ID のスキャン結果は再利用する。`match` は HIGH/CRITICAL Finding を対象とし、正解データは宣言しない。

#### ディレクトリ構成

| ファイル・ディレクトリ | 内容 |
| --- | --- |
| `run.log`、`collect.log` | ランナーとコレクターのログ |
| `targets_initial.json` | 開始時の対象名、コンテナ ID、イメージ ID・参照名、開始時刻 |
| `clock.json`、`cgroup-map.json` | 時計換算情報と cgroup 表 |
| `run_window.json` | run 全体の予定観測窓 |
| `timeline.jsonl`、`restarts.jsonl` | 処理の経過と、検出時に追記する世代イベント |
| `collect/` | 世代ごとの観測、manifest、登録状態の `ready.json` |
| `collector_supervise.json`、`tracer_supervise.json` | 起動した観測プロセスの監督記録 |
| `cgroup-<target>-wstart.json`、`cgroup-<target>-wend.json` | 専用 cgroup 使用時の `collector`・`tracer` の窓開始・終了時点の読み取り |
| `cgroup-remove-<target>.json` | `collector`・`tracer`・`parent` の削除記録 |
| `watch_targets.txt`、`watch.jsonl`、`watch.log` | 監視対象、サンプル、監視ログ |
| `stop_request.txt`、`termination_confirmed.txt` | 停止要求と、条件を満たした後の終了確認 |
| `trace.txt`、`trace.err`、`convert.log`、`events.jsonl` | イベント収集時のトレース、時刻付き stderr、変換ログ、変換結果 |
| `scans/<image-key>.json`、`scans/<image-key>.err` | イメージ ID から `:` を除いたキーごとの Trivy 結果と stderr |
| `case/<base>.json` | 世代ごとの照合用ケース定義 |
| `match/<base>.match_hc.json`、`match/<base>.log` | 世代ごとの照合結果とログ |
| `csv_hc/<base>/` | 世代ごとの照合 CSV |
| `intel.json` | 保存済みスナップショットを指定しない場合の補足情報スナップショット |

該当する段階に到達していないファイルや、無効にした機能のファイルは生成されない。世代イベントがなければ `restarts.jsonl` も生成されない。`prod_summary.md` と `prod_summary.csv` は、別途 `prod_summary.py` を実行して作る。

#### timeline.jsonl の項目

各行は `ts` と `event` を持つ JSON で、イベントごとの追加項目を持つ。ランナーが書く追加値は通常文字列であり、世代イベントなどの転記行とは型が異なる場合がある。

| `event` | 主な追加項目 |
| --- | --- |
| `run_start`、`window_clamped` | 要求・実効窓長、ページ数、間隔、上限 |
| `target_snapshot` | `container`、`container_id`、`image_id`、`started_at` |
| `monitor_started` | `pid` |
| `attach_check` | `attached`、アタッチ確認時刻の `at` |
| `collector_start` | 監督プロセスの `pid` とコレクター開始時刻の `at` |
| `effective_observation_start` | `mode` と集計に使う `at` |
| `target_registration_result` | `ready.json` 由来の `attached` と `at` |
| `run_window_decided`、`window_established` | 予定 `start`・`end`、成立を表す `value`、`drift_s` |
| `cgroup_refresh` | `reason` と `result` |
| `stop_reason`、`tracer_stop`、`run_actual_end` | 停止理由、`stopped_early`、終了時刻、監督記録のパスなど |
| `convert_done`、`scan_done`、`match_done` | 成否と対象ファイル、イメージ、コンテナ、世代の識別情報 |
| `first_evidence_summary` | `container`、`record`、`first_layout_reading`、`first_language_package_evidence` |
| `generation_change` | `restarts.jsonl` の世代イベントの項目 |
| `run_end` | 観測記録数と失敗・警告数、または空の対象集合を示す `population=empty` |

`first_evidence_summary` は有効な追加入力の最初の取得時刻と、言語パッケージの confirmations にある最初の証拠時刻をまとめる。取得できない値は `null` になる。この行の `ts` は世代の予定終了時刻である。`generation_change` は照合処理後にまとめて転記するため、timeline の行順は時刻順とは限らない。

#### 停止条件と終了確認

監視はトレーサー起動前から始まり、`KL_WATCH_INTERVAL` の既定値 10 秒ごとに確認する。

| 条件 | 設定と既定値 |
| --- | --- |
| トレーサー CPU がしきい値を 3 回連続で超過 | `KL_WATCH_CPU_CORES=1` |
| `Lost N events` 通知件数が 3 回連続で増加 | 連続回数は 3 |
| run ディレクトリの容量超過 | `KL_WATCH_RUN_BYTES=1073741824` |
| run の親ディレクトリ全体の容量超過 | `KL_WATCH_ROOT_BYTES=4294967296` |
| 出力先ファイルシステムの空き容量不足 | `KL_WATCH_FREE_BYTES=21474836480` |

開始時点の空き容量が下限を下回る場合も観測を開始しない。Web 計測はなく、`KL_WATCH_WEB_FAILURES` は適用されない。トレーサーなしでは CPU と欠落通知の条件は適用されず、専用 cgroup なしでは CPU の条件を評価できない。

予定窓の終了、SIGINT/SIGTERM、監視からの要求、観測プロセスが動いている間の監視プロセス消失は共通の停止経路に入る。監督対象の実行期限は `supervise -deadline` が別に管理し、トレーサーには準備予算・開始余裕・窓長・期限猶予の合計、コレクターには準備予算を除く合計を渡す。

停止理由を `stop_request.txt` に保存し、`supervise` の SIGINT、SIGTERM、SIGKILL の順の停止処理を待つ。監督プロセスの待機が時間切れになった場合はその監督プロセスへ TERM を送り、再度待機する。監督プロセス自体へ SIGKILL は送らない。

| 実行方法 | 終了確認 |
| --- | --- |
| 専用 cgroup | 監督記録が `status=exited` で、`termination_confirmed.measured=true` かつ `value=true` であることを要求 |
| `-no-cgroup` | `status=exited` により直接の子の回収だけを確認し、子孫タスクの不在は未計測として理由を残す |

監督プロセス自身の退出だけを子の終了証拠にしない。終了の事実とは別に、トレーサーには停止要求に応じた正常終了を要求し、自発終了、シグナル終了、非ゼロ終了を失敗として記録する。コレクターは予定サンプルを終えて窓終了前に正常終了しても、それだけでは失敗にしない。

全対象の終了を確認して `termination_confirmed.txt` を書けた後に監視を止め、最終読み取り済みの専用 cgroup を削除する。終了確認不能なら監視と cgroup を残し、非ゼロで終了する。終了確認または後始末が完了しなければ、変換と照合を行わない。監視自身にも有限の待機上限を設け、上限到達は終了確認として扱わない。

コレクター、トレーサー、cgroup 登録・更新、イベント変換、イメージスキャン、世代の照合などの必要な処理が失敗した場合は非ゼロで終了し、完了済みの結果は残す。開始時の対象集合が空で観測記録がない場合は、空であることを記録して正常終了する。

### prod_summary.py の分類と出力

```sh
sudo python3 experiments/runtime-discovery/tools/prod_summary.py \
  /var/tmp/runtime-discovery-prod/run-001 \
  --container api
```

引数は `<run dir> [--before <RFC3339 ts>] [--after <RFC3339 ts>] [--container <name>]` である。`match/*.match_hc.json` と同じ基底ファイル名の `collect/*.json` を組にして読み、JSON 内のコンテナ名と開始時刻から世代を整理する。世代の並びは開始時刻順であり、ファイル名や `restarts.jsonl` から推測しない。

#### 判定系列と有効な観測開始

分類にはイベント証拠込みの判定を優先し、その判定欄が空の場合だけ読み取り専用の追加手法込み、さらに従来のルールへ戻る。`unobserved`、`unresolved`、`not_determined` は空ではないため、これらを理由に別の系列へ戻らない。下位理由には選んだ系列自身の factor を使う。

有効な観測開始は、timeline の最初の `effective_observation_start` の `at` を読む。

- トレーサーのアタッチを確認できた run は、その確認時刻を `mode=events` で記録する
- アタッチ未確認またはイベント収集なしの run は、コレクターの監督記録の `started_at_wall` を `mode=procfs` で記録する
- ランナーがコレクター開始時刻を取得できなかった場合は、予定窓開始を代用して timeline に記録する
- 集計時にこのイベントまたは時刻がなければ開始は不明とし、別の時刻から補わない

| 優先順 | 区分 | 条件 |
| --- | --- | --- |
| 1 | 確認済み `confirmed` | 選んだ系列が `confirmed` |
| 2 | 判定不能（観測開始前に起動） `undeterminable_started_before_observation` | 未確認の `class=lang` で、世代開始と有効な観測開始が分かり、前者が厳密に早い |
| 3 | 証拠なし `no_evidence` | 上記以外 |

開始時刻が不明な場合に「観測開始前に起動」とは判定しない。確認済みの言語パッケージは、起動が観測開始より前でも確認済みのままである。

#### 証拠なしの下位理由

次の順序で最初に該当した理由を使う。

| 下位理由 | 条件 |
| --- | --- |
| `permission_failure` | factor が `proc_denied` または `rootfs_denied` |
| `no_observation` | factor が `no_observation`、`top_failed`、`proc_gone`、`event_no_observation`、または `observation_state=observation_failed` |
| `mapping_unsupported` | factor が `no_file_list`、`lang_pkg_unmappable`、`db_absent`、`db_error`、`mapping_input_missing`、`event_path_unresolved` |
| `mapping_unsupported` | 従来のルールを選んだ場合に限り、`confirmation_gap_class=E2` |
| `drops` | 上記に該当しない言語パッケージで、その世代の `event_state` が `degraded` または `failed`、かつ所定の欠落カウンターが正 |
| `drops_candidate` | 同じ言語パッケージの条件で、所定の欠落カウンターに正の値がない |
| `unclassified` | どれにも該当しない |

欠落の判定に使う `event_drops` の項目は `lost_events`、`lost_notifications`、`map_overflow`、`path_read_failures`、`path_truncations`、`convert_failures`、`enter_exit_unmatched`、`identity_unavailable`、`unmatched_identity_unavailable` である。境界の未対応片とフィルター前後の件数は欠落の証拠に使わず、自由記述の `event_notes` も使わない。イベント状態の劣化だけでは実測された欠落とせず、`drops_candidate` にとどめる。対応付け不能が判明している場合は、欠落よりもその理由を優先する。

#### 集計表と CSV の列

`prod_summary.md` は世代ごとの件数、証拠なしの下位理由別件数、複数世代がある場合の前後比較を出力する。Finding 数は各パッケージの `finding_count` を加算し、3 区分の合計が HIGH/CRITICAL Finding 数になる。パッケージ数は別に数え、Finding 数へ加算しない。

| 出力 | 列 |
| --- | --- |
| 世代別件数表 | コンテナ名、世代番号、イメージ ID、開始時刻、HIGH/CRITICAL Finding 総数、3 区分の Finding 数、3 区分のパッケージ数 |
| 下位理由表 | 下位理由、HIGH/CRITICAL Finding 数 |
| 前後比較表 | コンテナ名、分類、パッケージ名、前後のバージョン、共通・追加・削除、前後の世代番号と状態、後の世代の最初の証拠時刻・種類、残る理由 |
| `prod_summary.csv` の識別列 | `container`、`generation`、`image_id`、`container_started_at`、`package`、`version`、`class` |
| `prod_summary.csv` の判定列 | `finding_count`、従来のルール・読み取り専用の追加手法込み・イベント証拠込みの各判定、`verdict_tier_used` |
| `prod_summary.csv` の状態列 | `event_state`、`observation_state`、`state`、`subreason` |

CSV は Finding を持つパッケージごとに 1 行で、元の各系列の判定を分類結果で上書きしない。前後比較表は Markdown に出力し、CSV は世代ごとの行を保持する。

前後比較は既定で最初と最後の世代を使う。`--before` と `--after` は、それぞれ指定時刻までに開始した最新の世代を選び、候補がなければ既定の選択を保持する。同じ世代が選ばれた場合や世代が 1 つの場合は比較表の行を作らない。

比較キーは分類・名前・インストール済みバージョンの組で、両側にあれば `common`、後だけなら `added`、前だけなら `removed` になる。この所属は HIGH/CRITICAL Finding を持つパッケージ集合に対するもので、Finding がなくなっただけでも比較上の削除になり得る。片側にない状態は `not_present` と表示する。最初の証拠は後の世代の同じ比較キーの confirmations から時刻が最も早いものを選び、`observed_at` と `source` を表示する。
