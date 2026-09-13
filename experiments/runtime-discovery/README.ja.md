# ランタイム探索の実験

[English](README.md) | **日本語**

## 目的

procfsとDocker Engine APIから得られる実行時の証拠を、説明可能な精度でTrivyの検出項目に結び付けられるかを検証する、独立した計測ハーネスです。

- 製品機能ではなく、実験
- `kestrelynx`バイナリとは別のもので、コンテナイメージには組み込まれていない
- 動機と調査状況は、[公開開発ログ](../../docs-ja/development/runtime-prioritization.md)を参照

## 概要

- `collect`は実行時の観測を保存する
- `match`は観測を、イメージスキャン、期待される使用状況と判定、任意の独立した正解データと照合する
- 以下のコマンドは、リポジトリのルートから実行する
- 生成ファイルは、Gitの追跡対象から除外されている`./out/`に保存する
- 観測、ログ、スキャン、結果はコミットしない

## 必要な環境

計測には、次のホスト環境、ツール、権限が必要です。

- ネイティブのDocker Engineが動作し、そのUNIXソケットにアクセスできるLinuxホスト
  - 別のVMを介するDocker Desktopでは、必要なホストPIDを取得できない
- Go 1.26（リポジトリでは現在Go 1.26.4を指定）
- イメージスキャン用のTrivy、ケースヘルパー用のBashとcurl、例の実行用のjq
  - ヘルパーはpython3があれば使用ログの読み取りに使い、なければ空白の違いを許容する正規表現にフォールバックする
- 標準条件での収集とホストprocfsを使うヘルパーチェックのためのroot権限
  - 同等の読み取りアクセスを持つ非root条件では、`CAP_SYS_PTRACE`と`CAP_DAC_READ_SEARCH`を使う
- 各ケースで使用する空きポート
- イメージビルド、Trivyデータの取得、R9のcurlリクエスト、保存済みスナップショットを使わない場合のKEV/EPSS取得に必要なネットワークアクセス

## 入出力

`collect`はホストとコンテナの情報を読み取り、観測を保存します。

- procfsからは、`/proc/<pid>/exe`、`maps`、`fd`、`status`、`net/tcp`、`net/tcp6`を読み取る
- プロセスの識別情報、名前空間、cgroupのメタデータも読み取る
- コンテナのルートファイルシステムは、`/proc/<pid>/root`経由で読み取る
- パッケージメタデータは、dpkg、distrolessの`status.d`、apkを対象に含める
- Docker APIには、コンテナの列挙、詳細情報の取得、`top`のGETリクエストだけを発行する
- `collect`はGETだけを使うが、Dockerソケット自体はコンテナの制御を許可し得る
- ケースヘルパーは別途、コンテナのビルド、起動、詳細情報の取得、削除を行う
- フィクスチャチェックと事前チェックは、Dockerが報告するPIDを使ってホストの`/proc/<pid>/...`を読み取る
  - `docker exec`を使わないため、distrolessでも動作する
- R4の準備完了チェックでは、別途`docker exec`で`pg_isready`を実行する

## ビルドと実行

専用の計測ホストを準備し、同じDockerエンドポイントを使ってビルドと計測を行います。

- リソースを競合するワークロードを停止する
- ほかのランタイムのネットワーク設定が残っていないか確認する
- Dockerが動作していることを確認し、CLI、イメージスキャン、コレクターで同じネイティブエンドポイントを使う

```sh
mkdir -p ./out
unset DOCKER_CONTEXT
export DOCKER_HOST=unix:///var/run/docker.sock
docker context show
docker info --format '{{.ServerVersion}} {{.Driver}} {{.DockerRootDir}} {{.CgroupVersion}}'
uname -r
cat /proc/sys/kernel/yama/ptrace_scope
findmnt -no OPTIONS /proc
```

- 上記の出力とエラーを記録する
- 公開したHTTPポートはcurlで確認する
- ホスト上に待ち受けソケットがないことだけでは、DockerのNATによるポート公開が失敗したとはいえない
- 負荷を分離して計測するには、ビルドしたコレクターを専用のcgroup v2内で実行する
- 初回のパッケージデータベース読み取りコスト、コレクター自身のcgroup使用量、Dockerデーモンのcgroup使用量を記録する
- 取得できない計測値は失敗として記録される
- 権限比較のために固定したバイナリが必要な場合は、実行ファイルをビルドする

```sh
go build -o ./out/runtime-discovery ./experiments/runtime-discovery
go run ./experiments/runtime-discovery collect -h
go run ./experiments/runtime-discovery match -h
```

## ケース一覧

ケースは1〜12の12種類で、ケース7の2つのバリアントを含めて13バリアントがあります。表の番号は、コマンドとファイル名では`r`を付けて指定します（例: 1は`r1`、7aは`r7a`）。

- `cases/*.json`では、`expected_usage`（GT-A：`used`または`not_used`）と`expected_verdict`を分けて指定する
- `expected_factor`は任意で指定する
- R5ではcryptographyの使用を宣言しているが、現在のパス照合ロジックでは言語パッケージの検出項目を対応付けられないため、期待する判定は`unobserved`
- ケース単位の`gap_class_hint`と`gap_class_rationale`は、宣言されたギャップを説明する
- `gt_b_scope`がある場合は、独立した正解データの対象パッケージ範囲を宣言する

| 番号 | イメージ | 検証内容 |
| --- | --- | --- |
| 1 | `nginx:1.27` | Debianパッケージへのファイルの帰属、マスター／ワーカー、全インターフェースでのポート公開。 |
| 2 | `redis:7-alpine` | apkパッケージへのファイルの帰属、非rootサービス、ループバックでのポート公開。 |
| 3 | `nginx:1.27` | ホストネットワークとリスナーの帰属。 |
| 4 | `postgres:16` | ポートを公開しない複数のPostgreSQLプロセス。 |
| 5 | `python:3.12-slim`をベースにした`kl-r5` | ロードされたcryptography拡張と、言語パッケージの照合ギャップ。 |
| 6 | `gcr.io/distroless/cc-debian12`をベースにした`kl-r6` | 動的リンクされたCサーバーと、`status.d`のファイル帰属メタデータ。 |
| 7 | `debian:12-slim`上の`kl-r7a`；`gcr.io/distroless/static-debian12`上の`kl-r7b` | パッケージメタデータの有無が異なる環境での、同じ静的リンクされたGoサーバー。 |
| 8 | `debian:12-slim`をベースにした`kl-r8` | 削除済み実行ファイル、削除済みライブラリ、ロード済みライブラリのアトミックな置き換え。 |
| 9 | `debian:12-slim`をベースにした`kl-r9` | 反復間に5秒のスリープを挟む、短時間で終了するcurl/gitの呼び出し。 |
| 10 | `debian:12-slim`をベースにした`kl-r10` | SQLiteライブラリを7秒間ロードし、その後7秒間アンロードする動作。 |
| 11 | `nginxinc/nginx-unprivileged:1.27-alpine` | 非rootのnginxと実効権限。 |
| 12 | `nginx:1.27` | `NET_ADMIN`の追加、`NET_RAW`の削除、実効ケーパビリティのチェック。 |

- R9のビルドと起動には`sudo bash experiments/runtime-discovery/cases/run.sh up r9`、削除には`down r9`を使う
- ヘルパーはR7の両バリアントを含むR5–R10をビルドし、それ以外は上流のイメージを使う
- ヘルパーは`up-all`と`down-all`も受け付ける
- 起動時はケースに応じて、HTTP 200、Redisの準備完了ログ、または`pg_isready`を待つ
- R5/R6はさらに`open`イベント、R8は3つの`stage`イベント、R9は`exit`を待つ
- R10は、自身のmaps読み取りでアンロードを確認した`dlclose`を待つ
- ヘルパーはこれらのログをJSONとして解析するため、同じレコードは空白の入れ方が異なっても同じように読み取られる
- `fixture-check <case>`は別途実行する
- R8とR10では、サンプリング前に`preflight-r8`または`preflight-r10`も実行し、削除済みマッピングやアンロード後の消失を確認する
- `preflight-r10`は、固定時刻にアンロード済みと仮定せず、アンロードされた状態をポーリングで確認する
- 準備完了チェック、フィクスチャチェック、事前チェックは、失敗すると非ゼロの終了コードを返す
- チェックに失敗した場合は、その計測を中止する

## 計測の手順

各計測は、次の順序で進めてください。

1. ホストを準備する
2. ケースを起動する
3. 準備完了とフィクスチャの妥当性を確認する
4. タグを再解決せず、実際に稼働しているイメージのIDを指定してスキャンする
5. 観測を収集する
6. 正解データを収集する
7. 観測、スキャン、ケース定義、正解データを照合する
8. ケースを削除して後片付けする

- R9の起動から観測の収集までは、次のコマンドで実行する

```sh
run_dir=./out/R9-root-30-300-offset0-rep1
mkdir -p "$run_dir"
sudo bash experiments/runtime-discovery/cases/run.sh up r9
sudo bash experiments/runtime-discovery/cases/run.sh fixture-check r9
cp experiments/runtime-discovery/cases/r9.json "$run_dir/case.json"
image_id=$(docker inspect --format '{{.Image}}' r9)
trivy image --format json --output "$run_dir/trivy.json" "$image_id"

sudo systemd-run --scope --unit=runtime-discovery-collect \
  -p CPUAccounting=yes -p MemoryAccounting=yes \
  "$(pwd)/out/runtime-discovery" collect \
  -socket /var/run/docker.sock -containers r9 \
  -case-variant R9 -permission root \
  -interval 30 -window 300 -phase 0 -replicate 1 \
  -out-dir "$run_dir/collect"
```

- このスコープにより、コレクターに専用のcgroupを割り当てる
- `-cgroup-path`は、`/proc/self/cgroup`から導出されるディレクトリを上書きする
  - 例は`/sys/fs/cgroup/system.slice/runtime-discovery-collect.scope`
- systemdがない場合は、専用のcgroup v2を手動で作成してその中で実行し、そのディレクトリを渡す
- `-docker-cgroup-path`はデーモンのcgroupを選択し、既定値は`/sys/fs/cgroup/system.slice/docker.service`
  - このcgroupの計測には、`docker top`が起動する`ps`プロセスも含まれる
- `memory.peak`は、サンプリング期間だけでなく、コレクターのcgroupの存続期間全体におけるピーク
- 計測キーを構成する6つのフラグは、`-case-variant`（ケースのバリアント）、`-permission`（権限ラベル）、`-interval`（秒単位の間隔）、`-window`（秒単位の計測期間）、`-phase`（秒単位のサンプリング位相オフセット）、`-replicate`（反復番号）
- `-phase`は、RFC3339形式の時刻である`-phase-base`を基準に測る
- `-phase-base`を省略するとcollectの開始時刻が基準になり、基準時刻とその出所の両方が記録される
- 標準条件はroot、計測期間300秒、間隔30秒、位相オフセット0、反復番号1で、10回のサンプリングが予定される
- `-permission`はラベルを記録するもので、権限を付与するものではない
  - `root`、`ptrace`（`CAP_SYS_PTRACE`を持つ非root）、`ptrace_dac`（さらに`CAP_DAC_READ_SEARCH`も持つ非root）、`none`（ケーパビリティを持たない非root）を使う
- ケーパビリティは`go run`ではなく、ビルド済みの実行ファイルに付与する
- ソケットへのアクセス、ディレクトリの権限、ホストのセキュリティ制御も成否に影響する
- `-containers`を省略すると、稼働中の全コンテナを選択する
- `-ps-args`の既定値は`-eo pid,ppid,user`で、上書きする場合もこの列順を維持する
- 計測ごとに別の出力ディレクトリを使う
- R1/R2/R6での権限条件の比較と、R9/R10でのサンプリング条件の比較は、標準条件の結果とは分けて行う
- サンプリングの比較では、間隔を10/30/60秒、計測期間を300秒固定またはサンプル数を10回固定とし、位相オフセットを0/3/7秒に設定する
- ワークロードの周期に対する相対的なオフセットを比較する場合は、`-phase-base`をその周期の基準時刻に設定する

## 正解データ(GT-B)の作り方

GT-Bは、使用ログや常駐プロセスの確認結果を、独立に検証したパッケージ情報と組み合わせて作成します。

- コレクターは最後のサンプルを取得すると終了するため、予定した計測期間の終了前に戻ることがある
- GT-Bをコピーする前に、予定した計測期間の終了時刻までワークロードを動かし続ける
- 上記の標準条件では、さらに30秒待てば十分

```sh
sleep 30
docker cp r9:/var/log/usage.jsonl "$run_dir/usage.jsonl"
jq -sr '[.[] | .path? | select(. != null and . != "")] | unique[]' \
  "$run_dir/usage.jsonl" > "$run_dir/usage-paths.txt"
docker exec r9 dpkg-query -S /usr/bin/curl /usr/bin/git
```

- `/usr`が統合されたイメージでは、`.list`ファイルに記録されている形式（`/lib/x86_64-linux-gnu/...`）で`dpkg-query -S`を実行するか、`.list`ファイルを直接grepする
- パッケージが`/lib/...`として記録しているパスを`/usr/lib/...`の形式で問い合わせると、「no path found」が返される
- R5、R6、R8、R9、R10は`/var/log/usage.jsonl`を出力する
- 自前でビルドするバリアントのうち、使用ログを出力しないのはR7a/R7bだけ
- R5/R6は、起動時と定期的なmapsスナップショットを記録する
- R9は、プロセスの実行に加えて、動的ローダーが特定したライブラリを記録する
- 共通のイベント形式は、1行につき1つのJSONオブジェクト

```json
{"ts":"2026-09-11T00:00:00Z","pid":42,"starttime":12345,"event":"exec","path":"/usr/bin/git","ok":true}
```

- `ts`はRFC3339形式で、小数秒を含む場合がある
- `pid`とプロセス開始時のtick数で、プロセスの世代を識別する
- 使用イベントは`exec`、`open`、`dlopen`、`dlclose`、`exit`
- `exit`には終了の観測を示す`"ok":true`を付け、コマンドの終了コードは別の`status`フィールドに記録する
- R8は`meta`行と`stage`行も書き込み、R10は`dlclose`に`maps_unloaded`を追加する
- これらのフィールドは保持する
- 計測期間より前のイベントでも、そのイベントから始まる区間が計測期間と重なる場合は保持する
- `match -gtb`は、生のJSONLではなくJSONオブジェクトを受け取る

1. 稼働中イメージのパッケージメタデータを使い、ライブラリも含めて、`usage-paths.txt`内のすべてのパスの帰属を独立に検証する
   - 帰属を問い合わせる際は、シンボリックリンクによる別名も考慮する
2. 検証済みの対応関係を、`{"path":"/usr/bin/curl","package":"curl"}`のようなエントリを含むJSON配列として、`$run_dir/path-packages.json`に保存する
3. 次のコマンドでログをラップする

```sh
jq -s --slurpfile mappings "$run_dir/path-packages.json" '{
  case_id: "R9", kind: "usage_log", usage_log: .,
  path_packages: $mappings[0]
}' "$run_dir/usage.jsonl" > "$run_dir/gtb.json"
```

- `path_packages`は、`gt_b_scope`の範囲外にあるライブラリも含め、ログ内のすべての使用イベントのパスを網羅する必要がある
- 対応付けられていないパスがあると、どのパッケージについても未使用を確定できず、使用を示す証拠のないパッケージはすべて判定不能になる
- 独立に確認された使用の証拠は引き続き有効
- GT-Bラベルが付くのは、`gt_b_scope`内のパッケージだけ
- 計測ごとに新しいログを収集する
- イベントがないことを未使用と解釈する前に、ログがその範囲を網羅していることを確認する
- GT-Aの期待値とコレクターの出力は、独立した正解データではない
- 公式イメージでは、計測期間の終了後に限定的な常駐プロセスのチェックを行う
  - `docker top`を保存し、常駐プロセスの実行ファイル／ライブラリを調べ、パッケージの帰属とバージョンを独立に検証する
- 使用を確認できた観測は、`{"case_id":"R1","kind":"limited","resident_packages":[{"package":"nginx","used":true}]}`として記述する
- 計測前に、根拠のある対象範囲を、保存するケース定義内で宣言する
- 同梱の公式イメージ用定義では対象範囲を省略しており、範囲がなければカバレッジはゼロのまま
- 限定的なチェックでは未使用を確定できないため、`used:false`は無視される
- 正解データを用意したら、次のコマンドで照合と後片付けを行う

```sh
go run ./experiments/runtime-discovery match \
  -observation "$run_dir/collect/r9__R9_root_i30_w300_p0_r1.json" \
  -trivy "$run_dir/trivy.json" -case "$run_dir/case.json" \
  -gtb "$run_dir/gtb.json" -intel-cache ./out/intel-cache \
  -out-intel-snapshot "$run_dir/intel.json" \
  -act-now-epss 0.10 -watch-epss 0.01 \
  -out-json "$run_dir/match.json" -out-csv-dir "$run_dir/csv"
sudo bash experiments/runtime-discovery/cases/run.sh down r9
```

- 独立した正解データがない場合は`-gtb`を省略し、FP/FNは判定不能のままにする
- `match`には、稼働中のコンテナやルートファイルシステムは不要
- `-intel-snapshot`がない場合は、脅威情報キャッシュを通じてKEV/EPSSを参照し、更新されたフィードを取得することがある
- `-out-intel-snapshot`は、その実行で使った脅威情報を保存する
- 分類を再現するには、ほかの入力としきい値を固定したまま、`-intel-snapshot "$run_dir/intel.json"`で保存したファイルを渡す
- 以前の照合結果から`intel`オブジェクトを抽出することもできる
- スナップショットを使う実行では、KEV/EPSSの参照を行わない
- 分類を再現できるよう脅威情報を十分に固定できるのは、スナップショットを使う実行だけ

## 出力の見方

収集結果は観測JSONと`manifest.json`、照合結果はJSONと8つのCSVで確認します。

- 各収集ディレクトリには、コンテナごとに1つの観測JSONが含まれる
- `manifest.json`には、コンテナのファイル一覧と収集全体のエラーが記載される
- 観測ファイル名には、`r9__R9_root_i30_w300_p0_r1.json`のようにコンテナ名と計測キーが含まれる
- 観測には、識別情報、時刻情報、ホストアーキテクチャ、プロセスの証拠、ファイルの帰属、リスナー、権限、負荷計測値、失敗が含まれる
- 正常終了した場合でも、観測の内容を確認する
- 照合結果のJSONには、イメージの同一性検証、使用状況の判定、証拠、確認率、露出、順位の比較、GT-Bの精度指標が含まれる

| CSV | 内容 |
| --- | --- |
| `case_summary.csv` | 検出項目／パッケージの確認数と確認率、FPR/FNRとGTカバレッジ、`guess_dependency_rate`、`guess_dependency_lower`、`guess_dependency_upper`、`intel_condition`、`intel_source`、イメージの同一性検証、露出の判定。 |
| `classification.csv` | 全体、優先度別、パッケージクラス別、および脅威情報が劣化した条件での検出項目数と確認率。 |
| `factors.csv` | 判定／要因別の内訳。パッケージ数と、検出項目の総数、今すぐ対応、要監視、低優先度の件数。 |
| `gap_classes.csv` | E1–E4／未分類の確認ギャップ、回復可能性、パッケージ数／検出項目数、今すぐ対応／要監視の検出項目数。 |
| `path_resolution.csv` | `ownership`、`trivy_match`、重複を除いた`paths`の集計。 |
| `permissions.csv` | `operation`、`result`、`occurrences`、`message`に加え、その計測の`target_finding`、`confirmed`、`unconditional_rate`、`conditional_rate`、`state_observation_failed`。失敗した操作がない場合も行を含みます。 |
| `gt_b.csv` | 母集団、判定不能数、カバレッジ、TP/FP/TN/FN、FPR/FNR、上限／下限。 |
| `g4.csv` | 優先度、N/A状態、検出項目の総数、上位20件の順位変動、ラベル付き件数、`exposure_stages_in_top20`、ラベル付き／ラベルなしの例。 |

- すべてのCSVに、`case_id`と計測キーの6列（`case_variant`、`permission`、`interval`、`window`、`phase`、`replicate`）が含まれる
- 再実行するとファイルは上書きされる
- 集約は外部で行う

## Docker なしでの動作確認

`testdata/`内の手書きの入力を使うと、Docker、root権限、Trivyのインストールなしで`match`を試せます。

- 次のコマンドで、合成データを使った照合を実行する

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

- 照合結果のJSONと8つのCSVファイルを確認する
- `testdata/`には脅威情報のスナップショットが含まれていないため、初回実行ではネットワークアクセスが必要になることがある
- 報告された脅威情報の状態とエラーを確認する
- 以後、再現可能な実行にするには、`-intel-snapshot ./out/dry-run/intel.json`を追加する
- 合成データの限定的なGT-Bでは、使用されていることだけを確認する

## 制限

対応範囲と観測結果の解釈には、次の制限があります。

- デーモンモード、Kubernetes/containerd対応、eBPFによる収集はない
- アドレスのデコードにはホストのネイティブなバイトオーダーを使い、観測にはホストアーキテクチャを記録する
- R10のワークロードには、現在もamd64のライブラリパス`/usr/lib/x86_64-linux-gnu/libsqlite3.so.0`がハードコードされている
- パーサーには手書きのフィクスチャがあるが、実ホストでの計測は引き続き必要
- サンプリングでは、短時間の動作を見逃すことがある
- メモリにマッピングされた言語拡張が、Trivyのパッケージパスと一致するとは限らない
- 証拠がないことは、安全性や優先度を下げる根拠にはならない
- リスナーの存在は、インターネットから到達可能であることを証明しない
