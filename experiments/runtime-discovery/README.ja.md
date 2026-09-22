# ランタイム探索の実験

[English](README.md) | **日本語**

- 実行中コンテナで実際に使われているパッケージを、procfs と eBPF の証拠から突き止める実験用ハーネス
- 得られた証拠を Trivy の検出結果に紐づける
- 製品のバイナリとは別物で、コンテナイメージにも含まれない
- 経緯は公開開発ログの[ランタイム優先順位付け](../../docs-ja/development/runtime-prioritization.md)と[イベント証拠](../../docs-ja/development/runtime-event-evidence.md)に記録

## できること

- プロセス、マッピングされたファイル、リスナー、実効権限の定期サンプリング
- 隣接する [runtime-events ツール](../runtime-events/README.ja.md)による実行とファイルオープンのイベント収集
- 独立した正解データとの照合による確認数、個々の発生の捕捉率、コンテナへの帰属の評価

## 必要な環境

- BTF と runtime-events が使う実行・ファイルオープンのトレースポイントを備えた Linux
- bpftrace は v0.25.0 での計測実績があり、動作する最低版は未確定
- cgroup v2 を使うネイティブの Docker Engine と、その UNIX ソケットおよびホスト procfs へのアクセス
- Docker Desktop の WSL 連携はソケットを乗っ取るため利用不可で、ツールは接続先が Docker Desktop の場合に開始時に中断する
- sudo による root 権限
- Trivy、Go 1.26 系のリポジトリ指定版 1.26.4、Bash、curl、jq、python3
- ケースで使う空きポートと、ビルド、スキャンデータ、ワークロードのリクエスト、脆弱性情報取得用のネットワークアクセス

## 試し方

コマンドはリポジトリのルートから実行する。

### 準備

計測結果とバイナリの保存先ディレクトリを作成する。

```sh
mkdir -p experiments/runtime-discovery/out
```

サンプリングと照合に使う `runtime-discovery` バイナリをビルドする。

```sh
go build -o experiments/runtime-discovery/out/runtime-discovery ./experiments/runtime-discovery
```

イベント収集の補助処理とトレース変換に使う `runtime-events` バイナリをビルドする。

```sh
go build -o experiments/runtime-discovery/out/runtime-events ./experiments/runtime-events
```

`check-tracing.sh` を sudo で実行し、トレーシングスクリプトのロードと既知イベントの収集・変換を確認する。

```sh
sudo bash experiments/runtime-discovery/tools/check-tracing.sh
```

確認結果は `experiments/runtime-discovery/out/check-tracing/` の `smoke.log` と `events.jsonl` に保存される。

### 1 ケースの計測

1 ケースの計測には `case-run.sh` を使い、収集から正解データの作成、照合まで実行する。

```sh
sudo bash experiments/runtime-discovery/tools/case-run.sh 13 1 startup 512 30 300
```

引数は次のとおりである。

- 第 1 引数の `13` は `<case>` で、対象のケース番号を `13`〜`22` または `26`〜`28` から選ぶ必須引数
- 第 2 引数の `1` は `<replicate>` で、同じ条件の反復を区別する番号として保存先名の `r<replicate>` に使われ、省略時は `1`
- 第 3 引数の `startup` は `<sync>` で、対象の処理より先に観測を開始する `startup` と、動作中の処理に途中から参加する `attach_running` を選べ、省略時は `startup`
- 第 4 引数の `512` は `<pages>` で、イベントバッファのページ数を `64`・`256`・`512` から選ぶか、イベント収集なしの `none` を指定でき、省略時は `64`
- 第 5 引数の `30` は `<interval>` で、サンプリング間隔を正の整数の秒数で指定し、省略時は `30`
- 第 6 引数の `300` は `<window>` で、観測窓を正の整数の秒数で指定し、省略時は `300`

保存先は `experiments/runtime-discovery/out/<case>-root-<interval>-<window>-p0-r<replicate>-<sync>-<tag>/` になる。`<tag>` は `<pages>` の `64`・`256`・`512`・`none` に対応して、それぞれ `nofilter64p`・`nofilter256p`・`nofilter512p`・`noevents` になる。

保存先では最初に `record.md`、`match_hc.json`、`csv_hc/series.csv` を読む。続けて `csv_hc/occurrence_capture.csv`、`csv_hc/attribution.csv`、`csv_hc/event_drops.csv` を確認する。生成データはコミットしない。

### 複数ケースの計測

複数ケースの計測には `case-batch.sh` を使い、計画ファイルに書かれた条件を順に実行する。

```sh
sudo bash experiments/runtime-discovery/tools/case-batch.sh experiments/runtime-discovery/tools/plans/example.txt
```

引数は次のとおりである。

- 第 1 引数の `experiments/runtime-discovery/tools/plans/example.txt` は `<plan file>` で、実行するケースと計測条件を記載した計画ファイルのパス

各計測の結果は個別の run ディレクトリに保存され、バッチのログは `experiments/runtime-discovery/out/case-batch-<UTC 時刻>.log` に保存される。

### 計画ファイル

計画ファイルは 1 行が 1 回の計測を表し、欄は `<case> <replicate> <sync> <pages> [interval] [window]` の順に並べる。各欄は `case-run.sh` の引数にそのまま渡される。`#` 始まりの行と空行は無視され、末尾 2 欄を省略した場合は `<interval>` が `30`、`<window>` が `300` になる。

ただし、`<case>` が `23`・`24`・`23+24`・`23+host` の行は `attribution-control-run.sh` に回される。この場合は `<case>`、`<replicate>`、`<pages>` が渡され、`<sync>` 欄は無視される。`<interval>` と `<window>` も渡されず、30 秒間隔・300 秒窓で計測される。

`plans/example.txt` の内容は次の 3 行である。

```text
13 1 startup 256
14 1 startup 256
15 1 startup 256
```

各欄の意味は次のとおりである。

- 第 1 欄の `13`・`14`・`15` は `<case>` で、各行で計測するケース番号
- 第 2 欄の `1` は `<replicate>` で、各ケースの同じ条件での反復を区別する番号
- 第 3 欄の `startup` は `<sync>` で、対象の処理より先に観測を開始する指定
- 第 4 欄の `256` は `<pages>` で、イベントバッファを 256 ページにする指定
- 省略された第 5 欄は `<interval>` で、既定の 30 秒間隔を使用
- 省略された第 6 欄は `<window>` で、既定の 300 秒窓を使用

ケース 26〜28 には、`experiments/runtime-discovery/tools/plans/` に次の計画ファイルを同梱している。いずれもイベントバッファは 512 ページを使う。

- `coverage-main.txt` は 3 ケースを 30 秒間隔・900 秒窓で、`startup` と `attach_running` の両開始条件で 2 回ずつ計測する計 12 run
- `coverage-rest.txt` は残りの組み合わせである 10 秒間隔・900 秒窓、30 秒間隔・300 秒窓、10 秒間隔・300 秒窓を、3 ケースと両開始条件で 1 回ずつ計測する計 18 run
- `coverage-symlink-check.txt` は 3 ケースを `startup`・30 秒間隔・300 秒窓で 1 回ずつ計測する計 3 run で、`<replicate>` は `4`

### 帰属の検証

ケース 23・24 の帰属の検証には `attribution-control-run.sh` を使い、単独実行、同時実行、ホストとの対照実験でイベントの帰属先を確認する。

```sh
sudo bash experiments/runtime-discovery/tools/attribution-control-run.sh 23+24 1 512
```

引数は次のとおりである。

- 第 1 引数の `23+24` は `<condition>` で、`23` はケース 23 単独、`24` はケース 24 単独、`23+24` は両方を同時、`23+host` はケース 23 を動かしながらホストでも同じプログラムを実行する条件
- 第 2 引数の `1` は `<replicate>` で、同じ条件の反復を区別する番号として保存先名の `r<replicate>` に使われ、省略時は `1`
- 第 3 引数の `512` は `<pages>` で、イベントバッファのページ数を `256` または `512` から選び、省略時は `256`

この例の保存先は `experiments/runtime-discovery/out/23+24-root-30-300-p0-r1-startup-nofilter512p/` になる。コンテナ別の照合結果は `match_hc-case23.json` と `match_hc-case24.json`、CSV は `csv_hc-case23/` と `csv_hc-case24/` に保存される。他のケースの帰属は `case-run.sh` の結果に含まれる。

### 再処理と集計

保存済みの計測結果から正解データの作成と照合をやり直すには、`case-post.sh` を使う。

```sh
bash experiments/runtime-discovery/tools/case-post.sh "<run dir>"
```

引数は次のとおりである。

- 第 1 引数の `"<run dir>"` は再処理する run ディレクトリのパスに置き換え、複数を空白で区切って指定でき、省略時は `experiments/runtime-discovery/out/` 内のケース 13〜24 のうち collect 記録がある全 run が対象

トレースの変換からやり直す場合は、コマンドの `bash` の前に環境変数の指定 `RECONVERT=1` を置く。

脅威情報は既定で `experiments/runtime-discovery/out/intel-cache` を使って取得し、使用した情報を run ごとの `intel.json` に書き出す。環境変数 `KL_INTEL_SNAPSHOT` に保存済み JSON のパスを指定すると、同じ入力としきい値で分類を再現できる。ただし、run ごとの `intel.json` はその run の CVE 分しか含まないため、他の run の再処理には使わない。

ケース 13〜24 のイベント証拠に関する結果を集計するには、`aggregate.py` を使う。

```sh
python3 experiments/runtime-discovery/tools/aggregate.py
```

集計表は `experiments/runtime-discovery/out/AGGREGATE-events.md` に出力される。

個別の run の記録を作り直すには、`record.py` を使う。

```sh
python3 experiments/runtime-discovery/tools/record.py "<run dir>"
```

引数は次のとおりである。

- 第 1 引数の `"<run dir>"` は記録を作成する run ディレクトリのパスに置き換える必須引数

記録は `<run dir>/record.md` に保存され、標準出力にも表示される。

### 正解データと網羅性の集計(ケース 26〜28)

#### 正解データの取得

独立した正解データの元になるログを取得するには、`truth-run.sh` で計測と同じイメージを strace 下で動かす。このコマンドに sudo は不要である。

```sh
bash experiments/runtime-discovery/tools/truth-run.sh 26 1 900
```

引数は次のとおりである。

- 第 1 引数の `26` は `<case>` で、正解データを作るケース番号を `26`・`27`・`28` から選ぶ必須引数
- 第 2 引数の `1` は `<replicate>` で、正解 run の反復を区別する番号として保存先名の `r<replicate>` に使われ、省略時は `1`
- 第 3 引数の `900` は `<window>` で、正解 run の観測窓を秒数で指定し、省略時は `900`

出力先は `experiments/runtime-discovery/out/<case>-truth-r<replicate>/` になる。strace は処理の時間やスケジューリングに影響するため、これは正解データ取得専用の run とし、計測には再利用しない。ケース 27・28 では第 1 引数をそれぞれ `27`・`28` に置き換える。

#### 計測の実行

網羅性を評価する計測は `case-run.sh` で別に実行し、次の例ではケース 26 を 30 秒間隔・900 秒窓で計測する。

```sh
sudo bash experiments/runtime-discovery/tools/case-run.sh 26 1 startup 512 30 900
```

引数は次のとおりである。

- 第 1 引数の `26` は `<case>` で、計測するケース番号
- 第 2 引数の `1` は `<replicate>` で、同じ条件の反復を区別する番号
- 第 3 引数の `startup` は `<sync>` で、対象の処理より先に観測を開始する指定
- 第 4 引数の `512` は `<pages>` で、イベントバッファを 512 ページにする指定
- 第 5 引数の `30` は `<interval>` で、サンプリング間隔を 30 秒にする指定
- 第 6 引数の `900` は `<window>` で、観測窓を 900 秒にする指定

この例の保存先は `experiments/runtime-discovery/out/26-root-30-900-p0-r1-startup-nofilter512p/` になる。

ケース 26〜28 の主な条件をまとめて計測するには、`case-batch.sh` に `coverage-main.txt` を渡す。

```sh
sudo bash experiments/runtime-discovery/tools/case-batch.sh experiments/runtime-discovery/tools/plans/coverage-main.txt
```

引数は次のとおりである。

- 第 1 引数の `experiments/runtime-discovery/tools/plans/coverage-main.txt` は `<plan file>` で、30 秒間隔・900 秒窓を両開始条件で 2 回ずつ計測する計 12 run の計画ファイル

残りの間隔と観測窓の組み合わせを計測するには、`case-batch.sh` に `coverage-rest.txt` を渡す。

```sh
sudo bash experiments/runtime-discovery/tools/case-batch.sh experiments/runtime-discovery/tools/plans/coverage-rest.txt
```

引数は次のとおりである。

- 第 1 引数の `experiments/runtime-discovery/tools/plans/coverage-rest.txt` は `<plan file>` で、残りの組み合わせを両開始条件で 1 回ずつ計測する計 18 run の計画ファイル

symlink の解決とアプリ自身のパッケージを確認する短い計測には、第 1 引数を `experiments/runtime-discovery/tools/plans/coverage-symlink-check.txt` に置き換える。

#### 正解データの作成

イメージの同梱パッケージ一覧と独立ログから `truth.json` を作るには、`truth.py` を使う。

```sh
python3 experiments/runtime-discovery/tools/truth.py \
  experiments/runtime-discovery/out/26-truth-r1 \
  experiments/runtime-discovery/cases/26.json \
  experiments/runtime-discovery/out/26-root-30-900-p0-r1-startup-nofilter512p
```

引数は次のとおりである。

- 第 1 引数の `experiments/runtime-discovery/out/26-truth-r1` は `<truth run dir>` で、`truth-run.sh` が出力した正解 run ディレクトリ
- 第 2 引数の `experiments/runtime-discovery/cases/26.json` は `<case json>` で、正解 run に対応するケース定義の JSON ファイル
- 第 3 引数の `experiments/runtime-discovery/out/26-root-30-900-p0-r1-startup-nofilter512p` は省略可能な `<measurement run dir>` で、指定すると正解 run と計測 run の操作の同等性も確認する対象ディレクトリ

`truth.json` は正解 run ディレクトリに書き出される。rootfs の展開先は環境変数 `KL_TRUTH_TMPDIR` で変更できる。詳細は [REFERENCE.ja.md](REFERENCE.ja.md) を参照する。

#### 網羅性の評価

計測結果を同じケースの正解データと照合し、パッケージ利用状況の網羅性を評価するには、`coverage.py` を使う。

```sh
python3 experiments/runtime-discovery/tools/coverage.py \
  experiments/runtime-discovery/out/26-root-30-900-p0-r1-startup-nofilter512p \
  experiments/runtime-discovery/out/26-truth-r1/truth.json
```

引数は次のとおりである。

- 第 1 引数の `experiments/runtime-discovery/out/26-root-30-900-p0-r1-startup-nofilter512p` は `<run dir>` で、評価する計測 run ディレクトリ
- 第 2 引数の `experiments/runtime-discovery/out/26-truth-r1/truth.json` は `<truth.json>` で、同じケースの正解 run から作成した正解データのパス

評価結果は計測 run ディレクトリの `coverage.json` と `coverage.md` に出力される。ケース 27・28 と他の計測条件では、`truth.py` と `coverage.py` に渡すケース定義、正解 run、計測 run のパスを対応するものに置き換える。

#### 集計と順位比較

各計測の網羅性評価をまとめるには、`coverage_aggregate.py` を使う。

```sh
python3 experiments/runtime-discovery/tools/coverage_aggregate.py experiments/runtime-discovery/out
```

引数は次のとおりである。

- 第 1 引数の `experiments/runtime-discovery/out` は `<out dir>` で、計測 run を探す親ディレクトリと集計結果の出力先を兼ね、省略時も `experiments/runtime-discovery/out`

集計結果は `<out dir>/AGGREGATE-coverage.md` と `<out dir>/AGGREGATE-coverage.csv` に出力される。

網羅性の評価後に run を横断する優先順位の変化を比較するには、`coverage_rank.py` を使う。

```sh
python3 experiments/runtime-discovery/tools/coverage_rank.py experiments/runtime-discovery/out
```

引数は次のとおりである。

- 第 1 引数の `experiments/runtime-discovery/out` は `<out dir>` で、計測 run を探す親ディレクトリと順位比較の出力先を兼ね、省略時も `experiments/runtime-discovery/out`

順位比較は `<out dir>/AGGREGATE-rank.md` と `<out dir>/AGGREGATE-rank.csv` に出力される。

### 負荷と権限の計測（ケース 26〜28）

#### 負荷の計測

負荷の計測には `load-run.sh` を使い、動作中のワークロードに途中から参加する `attach_running` で、コレクターとトレーサーの負荷、運用処理の所要時間、Web の応答時間を記録する。

```sh
sudo bash experiments/runtime-discovery/tools/load-run.sh 26 1 procfs 30 300
```

引数は次のとおりである。

- 第 1 引数の `26` は `<case>` で、計測するケース番号を `26`・`27`・`28` から選ぶ必須引数
- 第 2 引数の `1` は `<replicate>` で、同じ条件の反復を区別する番号として保存先名の `r<replicate>` に使われ、省略時は `1`
- 第 3 引数の `procfs` は `<config>` で、観測なしの `none`、コレクターだけの `procfs`、コレクターと 512 ページのイベントバッファを使うトレーサーを動かす `events` から選び、省略時は `procfs`
- 第 4 引数の `30` は `<interval>` で、サンプル開始間隔を正の整数の秒数で指定し、省略時は `30`
- 第 5 引数の `300` は `<window>` で、観測窓を正の整数の秒数で指定し、省略時は `300`

保存先は `experiments/runtime-discovery/out/<case>-load-<config>-<interval>-<window>-r<replicate>-attach_running/` になる。生の計測値とログから `load.json` が作成され、後述の `load.py` で `AGGREGATE-load.md` と `AGGREGATE-load.csv` に集計する。イベント収集を含める場合は第 3 引数を `events` に置き換える。

観測による差を比較する対照 run は、同じケース、反復番号、間隔、観測窓で `none` を指定して実行する。

```sh
sudo bash experiments/runtime-discovery/tools/load-run.sh 26 1 none 30 300
```

引数は次のとおりである。

- 第 1 引数の `26` は `<case>` で、比較する計測と同じケース番号
- 第 2 引数の `1` は `<replicate>` で、比較する計測と同じ反復番号
- 第 3 引数の `none` は `<config>` で、コレクターとトレーサーを起動せず、ワークロードとホスト側の Web リクエストを動かす指定
- 第 4 引数の `30` は `<interval>` で、サンプリングには使わないが、比較する計測との対応付けに使う値
- 第 5 引数の `300` は `<window>` で、比較する計測と同じ観測窓の秒数

この例の保存先は `experiments/runtime-discovery/out/26-load-none-30-300-r1-attach_running/` になる。対照 run は observation を生成せず、運用処理、Web、Docker デーモンの CPU 使用量などを `load.json` に記録する。同じ条件への再実行は run ディレクトリを作り直すため、反復を残す場合は `<replicate>` を変える。

`load-run.sh` はトレーサーとコレクターの起動前に `watch-run.sh` を開始する。監視は既定で 10 秒ごとに行い、各サンプルを `watch.jsonl` に保存する。次の条件で停止を要求する。

- トレーサーの CPU 使用量が 1 コア相当を超える状態が 3 サンプル連続する
- `Lost N events` の欠落通知件数が 3 サンプル連続で増える
- run ディレクトリが 1 GiB を超える
- 出力先全体が 4 GiB を超える
- 出力先のファイルシステムの空き容量が 20 GiB を下回る
- Web の応答が記録順に 3 回連続で失敗する

環境変数 `KL_WATCH_INTERVAL`、`KL_WATCH_CPU_CORES`、`KL_WATCH_RUN_BYTES`、`KL_WATCH_ROOT_BYTES`、`KL_WATCH_FREE_BYTES`、`KL_WATCH_WEB_FAILURES` で、それぞれ監視間隔、CPU しきい値、run の容量上限、出力先全体の容量上限、空き容量の下限、Web の連続失敗回数を変更できる。容量はバイト単位で指定する。`KL_WATCH_HARD_DEADLINE_GRACE_S` は監視対象の実行期限に加える猶予秒数で、既定値は `120` である。

停止要求は `stop_request.txt` に記録され、ランナーと `supervise` が停止処理を行う。監視は停止要求後も続き、終了確認と監視自体の上限を区別する。観測窓が開いた後の早期停止でも `load.json` に取得済みの計測値と理由を残す。詳細は [REFERENCE.ja.md](REFERENCE.ja.md#負荷と権限の計測) を参照する。

#### 権限条件の確認

イベント収集に必要な操作を権限条件ごとに確認するには、`privilege-run.sh` を使う。非 root 条件では、`KL_PRIV_USER` に既存の非特権ユーザーを指定する。

```sh
sudo KL_PRIV_USER=kltest bash experiments/runtime-discovery/tools/privilege-run.sh bpf_perfmon
```

引数は次のとおりである。

- 第 1 引数の `bpf_perfmon` は `<condition>` で、root の `root`、`CAP_BPF` と `CAP_PERFMON` を付ける `bpf_perfmon`、さらに `CAP_DAC_READ_SEARCH` を付ける `bpf_perfmon_dac`、`CAP_SYS_ADMIN` を付ける `sysadmin` から選ぶ必須引数

出力先は `experiments/runtime-discovery/out/privilege-<condition>.json` と `privilege-<condition>.md` で、操作ごとの生ログと `supervise.json` などは `privilege-<condition>-artifacts/` に保存される。

例の `kltest` は既存の非特権ユーザー名に置き換える。スクリプトはユーザーを作成せず、非 root 条件を UID 0 で実行することも認めない。`root` 条件では `KL_PRIV_USER` の指定は不要である。準備済みの両バイナリに加えて、bpftrace、setcap、ネイティブの Docker Engine が必要になる。

ケーパビリティは `/var/tmp` の専用作業ディレクトリに置く bpftrace と `runtime-events` のコピーへ付ける。システムの bpftrace、ビルド済みの `out/runtime-events`、sysctl は変更しない。全操作の終了と証拠の保存を確認できた場合に作業ディレクトリを削除し、確認できない場合は保存先を報告して非ゼロで終了する。

#### 集計

保存済みの負荷計測をまとめるには、`load.py` を使う。

```sh
python3 experiments/runtime-discovery/tools/load.py experiments/runtime-discovery/out
```

引数は次のとおりである。

- 第 1 引数の `experiments/runtime-discovery/out` は省略可能な `<out dir>` で、負荷計測の run を探す親ディレクトリと集計結果の出力先を兼ね、省略時も `experiments/runtime-discovery/out`

集計結果は `<out dir>/AGGREGATE-load.md` と `<out dir>/AGGREGATE-load.csv` に出力される。各 run の計測値に加えて、同じケース、間隔、観測窓、反復番号の `none` 対照との運用処理・Web の中央値の差を示す。

対照の欠落、早期停止、観測窓の不成立、計測の未完了、イメージ ID の欠落や不一致などで比較が成立しない場合は、差分を理由付きの未計測として表示する。個々の計測値が取得できない場合もゼロで代用せず、`load.json` では `not_measured: <reason>`、集計表では `n/a (<reason>)` と表示する。

### 稼働中コンテナの観測

稼働中のコンテナに途中から参加する `attach_running` で観測し、再起動や同じ名前での再作成をまたいだ場合も、世代ごとに証拠を分けて保存する。`runtime-discovery` と `runtime-events` のバイナリは開発機でビルドして観測先へ転送しておく。

#### 事前確認

観測先の環境を確認するには、`prod-precheck.sh` を root で実行する。

```sh
sudo bash experiments/runtime-discovery/tools/prod-precheck.sh \
  /var/tmp/runtime-discovery-prod/precheck 512
```

引数は次のとおりである。

- 第 1 引数の `/var/tmp/runtime-discovery-prod/precheck` は必須の `<out dir>` で、確認結果の保存先として使われ、存在しなければ作成される
- 第 2 引数の `512` は省略可能な `[pages]` で、`64`・`256`・`512`・`none` から選び、省略時は `512`

カーネル、BTF、tracepoint、bpftrace と bpftool のバージョン、cgroup v2、procfs のマウントオプション、sysctl、lockdown、AppArmor、Docker のバージョンと cgroup driver、稼働中コンテナの識別情報、出力先の空き容量を記録する。結果は `<out dir>/precheck.json` と `precheck.md`、生の確認結果は `raw/` に保存する。

bpftrace があれば、選択値にかかわらず 64・256・512 ページの全スクリプトを `--dry-run` で確認する。BTF、必須 tracepoint、cgroup v2、到達可能なネイティブ Docker Engine などの必須要件が欠けていれば非ゼロで終了する。イベント収集を選んだ場合は、bpftrace の存在と選択したスクリプトの dry-run 成功も必須になる。bpftool の欠落は記録するが、それだけでは失敗にしない。

このスクリプトはコンテナの作成・起動・停止・変更や sysctl の変更を行わない。

#### 稼働中コンテナへの途中参加

`prod-observe.sh` は既存コンテナを観測し、観測できた各世代のイメージを Trivy でスキャンして、HIGH/CRITICAL の Finding を対象とする `match` を実行する。

```sh
sudo KL_PROD_PAGES=512 bash experiments/runtime-discovery/tools/prod-observe.sh \
  /var/tmp/runtime-discovery-prod/run-001 300 api worker
```

引数は次のとおりである。

- 第 1 引数の `/var/tmp/runtime-discovery-prod/run-001` は必須の `<out dir>` で、この run の記録と結果を保存するディレクトリ
- 第 2 引数の `300` は必須の `<window seconds>` で、要求する観測窓を正の整数の秒数で指定する値
- 第 3 引数以降の `api worker` は省略可能な `[container names...]` で、省略すると開始時に稼働中のコンテナを対象にする指定

コンテナ名は観測対象に置き換える。観測窓は `KL_PROD_MAX_SECONDS` の既定値 1800 秒を上限とし、超過する要求は記録した上で短縮する。サンプル開始間隔は `KL_PROD_INTERVAL` で変更でき、既定値は 30 秒である。上限適用後の観測窓は、この間隔以上にする。

主な環境変数は次のとおりである。

- `KL_PROD_PAGES` は `64`・`256`・`512`・`none` から選び、既定値は `512`、`none` はトレーサーとイベント収集を使わない指定
- `KL_TRIVY_CMD` はイメージスキャンに使うコマンドで、既定値は `trivy`、空白で引数に分割され、スキャン結果は標準出力から保存される
- `KL_RD_BIN` と `KL_RE_BIN` は転送済みバイナリのパスで、既定値はそれぞれ `experiments/runtime-discovery/out/runtime-discovery` と `experiments/runtime-discovery/out/runtime-events`
- `KL_PROD_ALLOW_UNMEASURED_LOAD=1` はトレーサーとコレクターの両方を `supervise -no-cgroup` で実行し、専用 cgroup 由来の負荷を理由付き未計測にする明示的な指定

ネイティブ Docker Engine、Python 3、Trivy、両バイナリと関連スクリプトを用意し、イベント収集時は bpftrace も用意する。`runtime-events` はイベント収集を無効にしても時計と cgroup 表の取得に使う。

監視はトレーサーの起動前に開始する。既定では 10 秒ごとに確認し、トレーサーの CPU が 1 コア相当を超える状態が 3 サンプル連続した場合、`Lost N events` の通知件数が 3 サンプル連続で増えた場合、run が 1 GiB を超えた場合、親ディレクトリ全体が 4 GiB を超えた場合、空き容量が 20 GiB を下回った場合に停止を要求する。

`KL_WATCH_INTERVAL`、`KL_WATCH_CPU_CORES`、`KL_WATCH_RUN_BYTES`、`KL_WATCH_ROOT_BYTES`、`KL_WATCH_FREE_BYTES` で監視間隔と各しきい値を変更でき、容量はバイト単位で指定する。`KL_WATCH_HARD_DEADLINE_GRACE_S` は監督対象の実行期限に加える猶予秒数で、既定値は `120` である。Web リクエストは発行しないため、`KL_WATCH_WEB_FAILURES` による停止条件は適用されない。専用 cgroup を使わない場合はトレーサー CPU を計測できず、そのしきい値による停止判定も行えない。

主な出力は次のとおりである。

- `collect/` に世代ごとの観測記録と manifest を保存する
- `match/` と `csv_hc/` に世代ごとの `match` 結果を保存する
- `scans/` にイメージ ID ごとの Trivy 結果を保存する
- `timeline.jsonl` に観測開始、登録結果、停止理由、スキャンと照合結果などを保存する
- `restarts.jsonl` に検出した再起動・再作成と補正イベントを追記する
- `run_window.json` に世代分割とは独立した run 全体の予定観測窓を保存する
- `collector_supervise.json` と、トレーサーを使う場合の `tracer_supervise.json` に起動・停止・終了確認と負荷の記録を保存する
- `watch.jsonl`、`watch.log`、`stop_request.txt` に監視結果と停止要求を保存する

同じ ID の `StartedAt` 変更を再起動、同じ名前の別 ID への置き換えを再作成として検出し、新世代では対応付け用の入力を読み直す。旧世代と新世代の観測窓と証拠を分け、各世代のイメージ ID に対応するスキャン結果で照合する。

スクリプトは対象コンテナを作成・起動・停止・変更せず、ワークロードも発行しない。停止処理は自身の観測プロセスに対して行う。必要な処理が失敗した場合は、完了済みの世代の結果を残して非ゼロで終了する。詳細は [REFERENCE.ja.md](REFERENCE.ja.md#稼働中コンテナの観測) を参照する。

#### 証拠の 3 区分の集計

保存済みの run は、`prod_summary.py` で集計する。

```sh
sudo python3 experiments/runtime-discovery/tools/prod_summary.py \
  /var/tmp/runtime-discovery-prod/run-001
```

引数は次のとおりである。

- 第 1 引数の `/var/tmp/runtime-discovery-prod/run-001` は必須の `<run dir>` で、観測結果を読み込むディレクトリと集計結果の保存先を兼ねる
- `--before <RFC3339 ts>` と `--after <RFC3339 ts>` は再起動前後の比較に使う世代を選ぶ省略可能な時刻指定で、それぞれ指定時刻までに開始した最新の世代を選ぶ
- `--container <name>` は指定したコンテナ名だけを集計する省略可能な指定

結果は `<run dir>/prod_summary.md` と `prod_summary.csv` に保存する。イベント証拠込みの判定を優先し、その系列が実行されていない場合に読み取り専用の追加手法込み、従来のルールの順に判定を選ぶ。未確認という判定だけを理由に、別の系列へ切り替えることはない。

| 区分 | 定義 |
| --- | --- |
| 確認済み | 選んだ系列の判定が `confirmed` |
| 判定不能（観測開始前に起動） | 未確認の言語パッケージで、その世代の開始時刻が有効な観測開始より前 |
| 証拠なし | 上記以外で、権限不足、観測なし、対応付け不能、欠落などの下位理由も記録 |

有効な観測開始には、run の timeline に記録したアタッチ確認時刻を使い、アタッチ未確認またはイベント収集なしの場合はコレクターの開始時刻を使う。「判定不能」は観測開始前の条件を示す区分であり、それ以前の利用を確認したことにはならない。

世代ごとの HIGH/CRITICAL Finding 数を 3 区分に分け、パッケージ数は別に表示する。複数世代のあるコンテナには、既定で最初と最後の世代を比較する再起動前後の表を作る。表にはパッケージの分類・名前・バージョン、前後の状態、共通・追加・削除の区別、後の世代で最初に記録された証拠の時刻と種類、残る理由を示す。バージョンが変わったパッケージは、旧バージョンの削除と新バージョンの追加として分ける。

## ケース一覧

次の表は、各ケースのコンテナの動作と確認する内容を示す。ケース 1〜12 は[手動のサンプリング手順](REFERENCE.ja.md#手動での計測手順)を使い、ケース 13〜22 と 26〜28 は `case-run.sh`、ケース 23・24 は `attribution-control-run.sh` で実行する。ケース 13〜24 はイベント証拠と追加のパッケージ対応付けを調べ、ケース 26〜28 は正解データと網羅性の集計の対象とする。

| 番号 | どんなコンテナか | 何を確かめるか |
| --- | --- | --- |
| 1 | マスターとワーカーが常駐する Web サーバー | パッケージへの帰属と全インターフェースへのポート公開 |
| 2 | 非 root のキーバリューサービス | apk の帰属情報とループバックへのポート公開 |
| 3 | ホストネットワークを使う Web サーバー | リスナーの帰属 |
| 4 | ポートを公開しない複数プロセスのデータベース | 常駐プロセスの観測 |
| 5 | コンパイル済み拡張を使う Python サービス | 言語パッケージの対応付けの不足 |
| 6 | 最小構成のイメージ上で動的リンクする C サーバー | `status.d` によるファイルの帰属 |
| 7a / 7b | 異なるベースイメージ上の同じ静的 Go サーバー | パッケージメタデータの有無による違い |
| 8 | 削除・置換されたファイルを保持するプロセス | 実行ファイルとライブラリの削除、アトミックな置換 |
| 9 | 短命コマンドの反復実行 | 5 秒のスリープを挟む動作のサンプリング漏れ |
| 10 | 共有ライブラリを 7 秒ずつロード・アンロード | 一時的なマッピングの捕捉 |
| 11 | 非 root の Web サーバー | 実効権限 |
| 12 | ケーパビリティを変更した Web サーバー | `NET_ADMIN` の追加と `NET_RAW` の削除 |
| 13 | 短命コマンドの反復実行 | 個々の実行とローダーが解決したライブラリの使用 |
| 14 | 共有ライブラリの反復ロード・アンロード | ロードごとの捕捉とアンロードの確認 |
| 15 | コンパイル済みキャッシュがある Python のインポート | 拡張、インストール済みファイル、キャッシュパスの対応付け |
| 16 | コンパイル済みキャッシュがない同じインポート | キャッシュ条件による違い |
| 17 | 標準的なディレクトリ構成の Node.js 依存パッケージ | ロード中に開かれて閉じられるファイル |
| 18 | リンクされたディレクトリ構成の同じ依存パッケージ | リンクと実体パスから同じパッケージへの対応付け |
| 19 | クラスパス上の個別 jar をロードする Java | 起動時のオープンと保持される記述子 |
| 20 | 依存を同梱した jar をロードする Java | 外側のアーカイブ単位の証拠 |
| 21 | 遅延ローダーで jar を開く Java | ロードによって発生するオープン |
| 22 | 依存を組み込んだ静的 Go サーバー | バイナリのパスとスキャン結果の対応付け |
| 23 / 24 | 同じプログラムとパスを持つ別々のコンテナ | 単独、同時、ホストとの対照実験による帰属 |
| 26 | コンテナ内で OS 運用処理を周期実行する Python Web アプリ | 起動時・遅延・未使用の群に対するパッケージ利用状況の網羅性 |
| 27 | コンテナ内で OS 運用処理を周期実行する Node.js Web アプリ | 起動時・遅延・未使用の群に対するパッケージ利用状況の網羅性 |
| 28 | コンテナ内で OS 運用処理を周期実行する Java アプリ | 起動時・遅延・未使用の jar 群に対するパッケージ利用状況の網羅性 |

ケース 26〜28 は、開始通知と独立してコンテナ内で curl・git・openssl を周期実行する。`coverage_plan` の群はフィクスチャの意図を表し、実際の使用・未使用は独立した証拠で判定する。

## 結果の読み方

### 最初に読むファイル

最初に各 run の `record.md` と、run を横断する `out/AGGREGATE-events.md` を読む。

### イベント証拠の 3 つの数

次の表は、分けて確認する 3 つの数と、詳細な件数を確認する CSV の保存先を示す。

| 数 | 意味 | 詳細の保存先 |
| --- | --- | --- |
| 利用を確認できた検出結果の数 | 「従来のルール」「読み取り専用の追加手法込み」「イベント証拠込み」の 3 系列で使用と結び付いた検出結果 | `csv_hc/series.csv` |
| 個々の実行・ロードの捕捉率 | 独立ログの評価対象から判定不能分を除いた実行・ロードの捕捉割合 | `csv_hc/occurrence_capture.csv` |
| コンテナへの帰属 | 正帰属、ホスト実行の非帰属、誤帰属を評価できる範囲 | `csv_hc/attribution.csv` |

### 観測状態

`csv_hc/event_drops.csv` で `event_state` と観測期間の不完全性を確認する。

- `event_state=observed` は、起動とアタッチを確認でき、観測期間の不完全性を示す項目がない状態を表す
- `event_state=degraded` は、起動とアタッチを確認できた収集に欠落、中断、欠落項目の未計測があり、発生を捕捉できたことだけでは完全性を示せない状態を表す

### 網羅性の評価(ケース 26〜28)

ケース 26〜28 では `coverage.md` を読み、区分と証拠系列ごとのパッケージ再現率と偽陽性率を確認する。証拠系列は「従来のルール」「読み取り専用の追加手法込み」「イベント証拠込み」の 3 通りである。

- 再現率は使用済みパッケージのうち使用を確認できた割合で、使用済みパッケージがなければ N/A になる
- 偽陽性率(FPR)は未使用と確定したパッケージのうち使用を確認した割合で、未使用と確定したパッケージがなければ N/A になる
- 主指標は起動から計測窓終了までの使用を含み、`window` は補助指標として読む
- 「イベント証拠込み」の見逃し表では、各見逃しの主因と候補タグを確認する
- `HOLD` はイメージの同一性または操作の同等性を確認できず集計を保留した状態を表すため、記載された理由を確認する

### 順位比較

`out/AGGREGATE-rank.md` で、実行時情報なしの基準順位からの変動を `act_now` と `watch` ごとに確認する。照合の実装上、順位比較は「従来のルール」と「イベント証拠込み」の 2 通りに限る。

- run × 系列 × 優先度の詳細と、replicate 間の一致の要約を確認する
- 保存された上位 20 件の外にある見逃し Finding と、記録された順位が変わらなかったものを区別する

## 制限

- 証拠は優先順位を上げるためだけに使い、証拠がないことを安全性や優先順位を下げる根拠にしない
- サンプリングは短命な動作を見逃すことがあり、`attach_running` はアタッチ前に完了した一度きりのロードを復元できない
- jar のオープンや Go バイナリの実行は、同梱された個々の依存の実行を証明しない
- Java のケースは独立ログにスレッド識別情報がないため、報告する発生単位の捕捉率の対象外
- 独立したプロセス対応表がなければ、コンテナ間誤帰属率は評価不能
- トレーシングの最小権限、イベント観測の負荷、本番相当環境での動作は未検証
- 追加ケースの apt パッケージの版は固定せず、比較は同一イメージ ID で担保する
- match の評価グループのキーでは、異なる言語エコシステムに属する同名同版の言語パッケージを区別できない
- 正解 run は strace 下で時間が伸びるため、run 間の経過時間を同一視せず操作とそのインスタンスを対応させる
- Go 静的バイナリとその組み込みモジュールは、この網羅性評価の対象外

- 最初の配置読み取りより前のイベントは配置の不変性を証明できないため、OS の所有者や symlink 表を使わずスキャン索引だけで解決する
- ディレクトリを開いただけではパッケージの使用とみなさない
- リンクとリンク先の所有者がそれぞれ単独で互いに異なる場合は、正解データと同じく両方のパッケージを使用とみなす

## 詳細

- [入出力とフラグ](REFERENCE.ja.md#入出力)には保存ファイル、実行キー、コマンドのオプションを記載
- [手動での計測手順](REFERENCE.ja.md#手動での計測手順)にはサンプリングケース、開始順序、ヘルパーのコマンドを記載
- [正解データと照合](REFERENCE.ja.md#正解データgt-b)には独立ログ、識別情報、帰属の照合規則を記載
- [観測状態と CSV](REFERENCE.ja.md#観測状態)には完全性、算出不能な割合、14 本の表の説明を記載
- [動作確認と制限](REFERENCE.ja.md#docker-なしでの動作確認)には合成入力と証拠の詳しい限界を記載
