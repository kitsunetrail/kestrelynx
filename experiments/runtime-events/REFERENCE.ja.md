# ランタイムイベントリファレンス

[English](REFERENCE.md) | **日本語**

- 目的、必要な環境、試すコマンド、スクリプト、結果の読み方は [README](README.ja.md) を参照
- この文書のコマンドはリポジトリのルートから実行する
- 手動実行の例では生成ファイルを Git の追跡対象外である `./out/` に保存する
- 自動計測の保存先は `experiments/runtime-discovery/out/`
- トレース、観測、結果はコミットしない
- 動機、計測計画、証拠の限界は[公開開発ログ](../../docs-ja/development/runtime-event-evidence.md)に記録

## 入出力

### 生トレースの行書式

- スクリプトは標準出力に行単位のテキストを書く
- フィールドの区切りは `|`
- パスは最後のフィールドに置き、パス内の `|` を保持する
- 現行スクリプトの書式版数は `3`

```text
V|<format version>|<string buffer length>|<buffer pages>|<variant>
E|<monotonic ns>|<pid>|<tid>|<ns pid>|<ns tid>|<pid ns inum>|<cgroup id>|<leader start ns>|<comm>|<raw path>
O|<monotonic ns>|<pid>|<tid>|<ns pid>|<ns tid>|<pid ns inum>|<cgroup id>|<leader start ns>|<dirfd>|<raw path>
X|<monotonic ns>|<pid>|<tid>|<ns pid>|<ns tid>|<pid ns inum>|<return value>|<entry's monotonic ns>
```

| レコード | 意味 |
| --- | --- |
| `V` | 書式版数、文字列長、バッファのページ数、スクリプトの variant |
| `E` | 成功した実行 |
| `O` | パスを伴うファイルオープンの開始 |
| `X` | 戻り値と記録された開始時刻を伴うファイルオープンの結果 |

| 書式版数 | 識別情報 | 変換時の指定 |
| --- | --- | --- |
| `1` | 名前空間内の PID／TID と PID 名前空間の識別子がない形式 | `-script-version 1` |
| `2` | 名前空間内の PID／TID を持ち、PID 名前空間の識別子がない形式 | `-script-version 2` |
| `3` | 名前空間内の PID／TID と、その PID 名前空間の識別子を持つ形式 | `-script-version 3` |

- 現行の `X` は対応する開始を識別するため、開始時の単調増加時計のナノ秒値を含む
- 旧形式の 5 フィールドの終了レコードは、プロセスの識別情報と結果の時刻が開始時刻以降であることを使う
- カウンターマップは終了時に `@<name>: <value>` として出力する
- 標準出力と合わせて標準エラー出力も保存する
- `Lost 17 events` のようなメッセージは欠落の集計に使う
- レコード区切り文字を含まない通常の起動バナーや警告は無視する
- コンバーターは次の任意レコードも受け付ける

```text
C|<monotonic ns>|<Unix wall-clock ns>
M|<counter name>|<value>
```

- 同梱スクリプトは `C` も `M` も出力しない
- ラッパーは対にして読み取った時計の値を `C` として先頭に付加できる
- `C` はそれ以降のイベントについて指定済みのエポックを上書きする
- 時計のレコードは対応するイベントより前に置く

### イベント JSONL

- 変換結果は `events_header`、イベントレコード、`events_trailer` の順に書く
- 各行は `record` で種類を区別する

| ヘッダーのフィールド | 意味 |
| --- | --- |
| `record` | `events_header` |
| `config_id`, `sync` | 収集設定とワークロードとの開始順序 |
| `method`, `version`, `variant`, `filter` | 収集手法、トレースの書式、スクリプトの variant、フィルターのメタデータ |
| `buffer_pages`, `path_buffer_len` | 記録バッファのページ数と文字列バッファ長 |
| `tracepoints` | 記録されたアタッチ先 |
| `started_at` | 記録された開始のメタデータ |
| `attached_at` | 取得できた場合のアタッチ完了時刻 |
| `boot_epoch`, `clock_source`, `clock_error_ns`, `clock_note` | 時計変換と記録された誤差 |
| `started`, `attached` | 起動とアタッチの確認 |
| `container_id` | 任意の計測対象 |

| イベントのフィールド | 意味 |
| --- | --- |
| `record`, `event` | `record` は `event`、`event` は `exec` または `open` |
| `ts`, `monotonic_ns` | 変換後の UTC 時刻と元の単調増加時計のナノ秒値で、オープンには開始時刻を使う |
| `pid`, `tid` | 現行スクリプトでは初期 PID 名前空間のプロセス番号とスレッド番号 |
| `starttime` | プロセス開始時の tick 数を表す文字列に変換したリーダーの開始時刻 |
| `ns_pid`, `ns_tid` | 各タスク自身の PID 名前空間のプロセス番号とスレッド番号で、該当フィールドのない旧入力ではゼロ |
| `pid_ns` | `ns_pid` と `ns_tid` が属する名前空間の識別子で、取得できない場合は省略 |
| `raw_path`, `path` | 記録されたパスと正規化または結合したパスで、未解決の場合は `path` を省略 |
| `path_resolved`, `path_truncated` | 解決の成否と文字列バッファを満たしたか |
| `ok` | 実行は常に true、オープンは戻り値が非負の場合に true |
| `ret` | 戻り値で、ゼロの場合は省略 |
| `cgroup_id`, `container_id`, `cgroup_depth`, `attribution` | 対応表による帰属情報で、状態は `container` または `unattributed` |
| `comm`, `source` | 実行のコマンド名と出所ラベルで、現在は 3 つのオープンシステムコールすべてに `sys_enter_openat` を使う |

| 末尾のフィールド | 意味 |
| --- | --- |
| `record` | `events_trailer` |
| `ended_at` | 終了のメタデータ |
| `drops` | 後述のカウンターと完全性の情報 |
| `detach_confirmed`, `detach_note` | 形式上のデタッチ情報で、このコンバーターはデタッチを確認しない |

- 失敗したオープンは `ok:false` で JSONL に残る
- 対応する相手がないオープンの開始または結果は、イベントを出力せずに数える
- 絶対パスは文字列として正規化する
- ファイルシステムのシンボリックリンクは解決しない
- CWD からの相対パスには一致する `-cwd-map` エントリが必要
- 別のディレクトリ記述子からの相対パスは未解決のまま残る
- プロセス世代の情報がないイベントには作業ディレクトリのエントリを使わない
- 名前空間内の番号は別の名前空間で重複し得る
- 番号は名前空間の識別情報と組み合わせて照合する
- ホスト発生の照合にはイベントと独立した発生レコードの両方に `pid_ns` が必要
- 名前空間内の番号は、ホスト自身が子 PID 名前空間にある環境でのコンテナ内ログとの照合にも使う

## コマンドのフラグ

- 実環境での計測前に実行ファイルをビルドする
- 時計の出力先は事前に親ディレクトリを作る

```sh
mkdir -p ./out
go build -o ./out/runtime-events ./experiments/runtime-events
./out/runtime-events clock -h
./out/runtime-events cgroup-map -h
./out/runtime-events convert -h
```

### clock

| フラグ | 既定値 | 用途 |
| --- | --- | --- |
| `-out` | 標準出力 | 時計の JSON をファイルに書く |

### cgroup-map

| フラグ | 既定値 | 用途 |
| --- | --- | --- |
| `-root` | `/sys/fs/cgroup` | 走査する階層のルート |
| `-out` | `./out/cgroup-map.json` | 出力する対応表 |
| `-merge` | 空 | 履歴を保持して更新する既存の対応表 |

### convert

| フラグ | 既定値 | 用途 |
| --- | --- | --- |
| `-in` | 必須 | トレース入力で、`-` は標準入力 |
| `-out` | `./out/events.jsonl` | 出力するイベントログ |
| `-cgroup-map` | 空 | 帰属判定用の対応表で、省略すると全イベントが帰属不明 |
| `-config-id` | 必須 | 手法、スクリプト、フィルター、バッファ設定の識別子 |
| `-sync` | 必須 | 開始順序のラベルで、`startup` または `attach_running` |
| `-method` | `bpftrace` | 収集手法のメタデータ |
| `-script-version` | `3` | `V` の第 2 フィールドと照合する書式版数で、空ならトレースの値を採用 |
| `-variant` | 空 | `V` の第 5 フィールドと照合する variant で、空ならトレースの値を採用 |
| `-filter` | 空 | フィルターの説明のメタデータ |
| `-buffer-pages` | 必須 | `V` と一致する実際のバッファのページ数で、正の値が必要 |
| `-tracepoints` | 空 | アタッチ先のメタデータをカンマ区切りで指定 |
| `-container-id` | 空 | 意図した対象のメタデータで、イベントの絞り込みや帰属の強制はしない |
| `-boot-epoch` | 空 | 単調増加時計がゼロの時点の実時刻を RFC3339 形式で指定し、ナノ秒は任意 |
| `-clock-error-ns` | `0` | 対にした時計の読み取りの誤差上限 |
| `-clock-source` | `CLOCK_MONOTONIC` | トレースの時刻とエポック変換で共用する時計 |
| `-clock-ticks` | `100` | プロセス世代の変換に使う 1 秒あたりの tick 数 |
| `-path-buffer` | トレースの `V` の値、なければ `256` | 切り詰め検出用の文字列長で、明示した値はトレースとの一致が必要 |
| `-window-start` | 空 | 予定した観測開始時刻を RFC3339 形式で指定 |
| `-window-end` | 空 | 予定した観測終了時刻を RFC3339 形式で指定 |
| `-stopped-at` | 空 | ラッパーが観測した実際の停止時刻を RFC3339 形式で指定 |
| `-stop-reason` | 空 | 停止理由の説明 |
| `-started` | `true` | トレーサーが起動したかを表し、起動失敗時は `-started=false` |
| `-attached` | `false` | 既知イベントでアタッチを確認したか |
| `-attached-at` | 空 | 時刻付き標準エラーに記録がない場合のアタッチ完了時刻を RFC3339 形式で指定し、ナノ秒は任意 |
| `-cwd-map` | 空 | カンマ区切りの `<pid>@<starttime>[@<from>-<to>]=<dir>` エントリ |

- 入力に有効な `C` レコードがない場合は `-boot-epoch` が必須

- `-cwd-map` にはプロセス世代の開始時刻が必須
- RFC3339 形式の有効期間は任意
- プロセス番号は再利用されるため番号だけでは不十分
- PID 名前空間の識別子がないトレースには `-script-version 2` を使う
- 名前空間内の番号もない旧トレースには `-script-version 1` を使う
- 境界の残片の分類には観測期間の両フラグが必要
- アタッチ完了時刻は参照用のメタデータで、観測期間の代わりにはならない
- `-attached-at` と時刻付き標準エラーの両方にアタッチ時刻がある場合は同じ時点を示す必要がある
- アタッチ時刻が矛盾する場合は変換に失敗する
- 変換フラグは完了した収集の内容を記述する
- 動作中のトレーサーの設定は変更しない
- バッファサイズまたは文字列長がトレースの `V` と異なる場合は変換を拒否する
- 環境変数による上書きも含めて実際に使った設定を記録する
- スクリプトの設定、バージョン行、設定識別子の整合性を保つ

### スクリプトの設定

- フィルタなしの 3 本は成功した実行と観測したすべての `open`、`openat`、`openat2` を収集する
- 文字列バッファ長は `256`
- 全 6 本の観測対象はホスト全体の動作
- コンテナへの帰属判定は変換時に行う
- 関連パスの絞り込みは変換後にユーザー空間で行う

| 収集スクリプト | バッファのページ数 | variant | 設定 ID |
| --- | --- | --- | --- |
| `bpftrace/runtime-events-nofilter.bt` | `64` | `nofilter` | `bpftrace-v2-nofilter-64p` |
| `bpftrace/runtime-events-nofilter-256p.bt` | `256` | `nofilter-256p` | `bpftrace-v2-nofilter-256p` |
| `bpftrace/runtime-events-nofilter-512p.bt` | `512` | `nofilter-512p` | `bpftrace-v2-nofilter-512p` |

- 設定 ID の `v2` は名前の一部
- トレースの書式版数 `2` を選ぶ指定ではない
- `runtime-events-nofilter.bt` の書式版数は `3` で、`V|3|256|64|nofilter` を出力する
- 同スクリプトの設定は次のとおり

```text
config = {
    max_strlen = 256;
    perf_rb_pages = 64;
}
```

- 変換時のメタデータには `-config-id bpftrace-v2-nofilter-64p`、`-filter runtime-events-nofilter.bt`、`-variant nofilter` を使う
- フィルタ付きの試行記録は `runtime-events.bt`、`runtime-events-filtered-a.bt`、`runtime-events-filtered-b.bt` の 3 本
- 判定対象は `/node_modules`、`site-packages`、`dist-packages`、`/lib`、`/app`、`.so`、`.jar`、`.py`、`.js`、`.mjs`、`.cjs`、`package.json` の 12 個の部分文字列
- `filtered-b` の文字列バッファ長は `160`
- `filtered-a` は `str(args->filename, 96)` で取得した先頭部分で判定し、出力には 256 バイト設定の文字列を使う
- フィルタ付き 3 本の出力バッファはすべて 64 ページ
- 3 本とも Linux 6.6.114 WSL2 と bpftrace v0.25.0 で `Error code: -28` により `--dry-run` に失敗した
- 12 個の `strcontains` による比較が検証器の条件分岐列の上限 8192 を超えた
- 失敗の原因はスタック超過ではない
- 他のカーネルでのフィルタ付きスクリプトのロード可否は未確認

## 計測の順序

- `startup` ではワークロードを動作させる前に観測を開始する
- 必要なチェックに失敗した場合は手順を中止する
- 計測全体は次の 9 ステップで進める

1. **時計:** トレーシングを行うホストで `./out/runtime-events clock -out ./out/clock.json` を実行する
2. **cgroup 対応表:** `sudo ./out/runtime-events cgroup-map -out ./out/cgroup-map.json` を実行する
3. **bpftrace の起動:** 標準出力、標準エラー出力、トレーサーのプロセス識別情報を保持する
4. **アタッチの確認:** `bash experiments/runtime-discovery/cases/run.sh attach-check ./out/trace.txt` で一意の名前を付けた `/bin/true` のコピーを実行し、そのトレースマーカーを待つ
5. **準備完了の待機:** `-expect` で対象を登録して runtime-discovery の収集を開始し、待機するケースを起動して cgroup 対応表を更新し、現在のコレクター実行の準備完了を待つ
6. **動作開始:** 登録、cgroup 対応表の更新、準備完了が成功してから `fire <case>` を実行し、予定した観測期間の終了までワークロードと観測を継続する
7. **停止:** トレーサーを停止してカウンターを出力させ、観測した終了時刻を記録して cgroup 対応表を更新し、コンテナ削除前にワークロードのログをコピーする
8. **変換:** 標準出力と標準エラー出力を結合し、時計の対応、アタッチの確認結果、設定、予定した観測期間、観測した停止時刻を指定する
9. **照合:** JSONL を観測、スキャン、ケース定義、独立した正解データとともに runtime-discovery の `match -events` に渡す

- ステップ 3 では収集スクリプトを次のように起動する

```sh
sudo bpftrace experiments/runtime-events/bpftrace/runtime-events-nofilter.bt \
  > ./out/trace.txt \
  2> >(while IFS= read -r line; do
    printf '%s %s\n' "$(date -u +%FT%T.%NZ)" "$line"
  done > ./out/trace.err) &
```

### ケースヘルパーのコマンド

| コマンド | 引数と動作 |
| --- | --- |
| `register-cgroups` | `<table> [runtime-events binary]` で読み取り可能な対応表をマージし、なければ作成する形式で、バイナリの既定値は `runtime-events` |
| `attach-check` | `<trace> [timeout seconds]` で既知の実行の受信を確認し、タイムアウトの既定値は `30` |
| `ready-run-id` | `<ready file> [timeout seconds] [collector start, RFC3339]` で空でない実行識別子を待って出力し、タイムアウトの既定値は `60` |
| `wait-ready` | `<ready file> <expected run id> [timeout seconds]` で準備完了と実行の同一性を確認し、実行 ID は必須、タイムアウトの既定値は `120` |
| `fire` | `<case>` で指定した待機中ワークロードの通知用パイプに書き込む |
| `dump-logs` | `<case> <directory>` で取得可能な `usage.jsonl` と `occurrences.jsonl` をホスト procfs 経由でコピーする |
| `host-run` | `<log> [iterations] [interval seconds]` で帰属の対照実験用のホストワークロードを実行する |

- ヘルパーは `bash experiments/runtime-discovery/cases/run.sh` 経由で呼び出す
- ホストファイルへのアクセスに必要な場合は root を使う
- コンテナが存在してから動作開始を通知するまでに対応表を更新する

```sh
sudo bash experiments/runtime-discovery/cases/run.sh \
  register-cgroups ./out/cgroup-map.json ./out/runtime-events
```

- 準備完了ファイルには新しいパスを使う
- コレクターの開始後に `ready-run-id` でその `run_id` を取得する
- 取得した ID を `wait-ready` の必須の第 2 引数に渡す
- `ready-run-id` の第 3 引数にコレクターの開始時刻を指定すると、それ以前のレポートを拒否する
- 開始時刻を省略すると、現在の実行に属すると証明できない旨の警告とともに識別子を返す
- `attach-check` が確認するのは実行イベントの配信だけ
- 最初の実環境での実行ではオープンの開始と結果の配信も別途検証する
- 起動メッセージだけではアタッチを確認できない

### 変換と照合

- 次の例では予定した開始と終了をラッパーが `$window_start` と `$window_end` に保存済み
- `$stop_instant` はラッパーがトレーサーの終了を観測した時刻
- `-attached` は既知イベントの確認に成功した場合だけ指定する

```sh
cat ./out/trace.txt ./out/trace.err |
  ./out/runtime-events convert -in - \
    -cgroup-map ./out/cgroup-map.json \
    -config-id bpftrace-v2-nofilter-64p -script-version 3 \
    -filter runtime-events-nofilter.bt -variant nofilter \
    -sync startup -buffer-pages 64 -path-buffer 256 -attached \
    -boot-epoch "$(jq -r .boot_epoch ./out/clock.json)" \
    -clock-error-ns "$(jq -r .error_ns ./out/clock.json)" \
    -stopped-at "$stop_instant" \
    -window-start "$window_start" -window-end "$window_end" \
    -out ./out/events.jsonl
```

- [runtime-discovery の照合コマンド](../runtime-discovery/REFERENCE.ja.md#照合と後片付け)に `-events ./out/events.jsonl` を追加する
- イベント JSONL は観測入力
- その評価に使う独立した正解データの作成には使わない
- 稼働中のワークロードに途中から参加する場合は `-sync attach_running` を使う
- その開始順序は `startup` と分けて記録する

## カウンターと欠落

### 末尾のカウンター

| `drops` のフィールド | 意味 |
| --- | --- |
| `lost_events` | 欠落として報告されたイベントの総数 |
| `lost_notifications` | 欠落メッセージの件数 |
| `enter_exit_unmatched` | 境界の残片に分類されなかった未対応のオープンの開始と結果 |
| `enter_exit_unmatched_boundary` | 後述の境界規則で分類した未対応のオープンの開始と結果 |
| `map_overflow` | 計測された挿入失敗を含む、報告されたマップのオーバーフロー |
| `unmeasured` | 計測していない欠落項目の説明 |
| `path_read_failures` | 失敗報告の合計で、ゼロの場合は空の出力パス件数 |
| `path_truncations` | 文字列バッファを満たしたパス |
| `convert_failures` | 不正な形式のレコード |
| `identity_unavailable` | 利用可能なプロセスまたはスレッドの識別情報がないイベント |
| `unmatched_identity_unavailable` | プロセスまたはスレッドの識別情報がない未対応の残片で、未対応の合計に含まれる内数 |
| `events_before_filter`, `events_after_filter` | 両方に実行件数を加えたスクリプトのカウンター |
| `stopped_early`, `stopped_at`, `gap_seconds`, `stop_reason` | 観測した停止と予定終了までの空白期間 |

- 1 件の欠落通知が多数の欠落イベントを表す場合がある
- `lost_events` と `lost_notifications` は分けて扱う
- カウンターと欠落メッセージを保持するためトレースの両出力を保存する
- 停止時刻の欠落を最後のイベントから補うことはできない
- ラッパーによる終了の観測を保持する

### マップ挿入失敗

- 現行スクリプトはキーの存在確認でスレッドごとのマップ挿入失敗を計測する
- `END` ではゼロを含めて `@map_insert_failed` を明示出力する
- 変換時にこの件数を `map_overflow` に加算する
- この項目が未計測になるのは入力にカウンターがない場合だけ
- `map_insert_failed` の重複報告は加算せず最大値を採用する
- `events_after_filter` の集計値がゼロの場合は出力イベント件数を採用する
- `-window-end` を指定して `-stopped-at` を省略すると、予定終了まで収集したか不明として unmeasured に記録する
- トレースにレコードが全くない場合も unmeasured に記録する
- カウンターがない場合は `unmeasured` に項目を追加する
- 起動とアタッチが確認済みの観測期間も、その場合は `degraded` になる
- 明示されたゼロはこの失敗項目だけの計測結果
- すべての欠落項目がゼロであることは証明しない

### 境界の残片

- 分類には `-window-start` と `-window-end` の両方が必要
- 観測期間は開始と終了の両時刻を含む
- 未対応の開始レコードは自身の時刻が観測期間外なら境界の残片
- 記録された開始時刻を持つ未対応の終了レコードは、その開始時刻が観測期間外なら境界の残片
- 開始時刻がない未対応の終了レコードは、自身の時刻が観測開始前の場合だけ境界の残片
- それ以外の未対応の残片は `enter_exit_unmatched` に数える
- 開始時刻がない観測終了後の終了レコードもこの扱いに含む
- 観測期間の両フラグがなければすべての未対応の残片を `enter_exit_unmatched` に数える
- 境界の残片は `enter_exit_unmatched_boundary` に数える
- アタッチ完了時刻はこれらの観測期間の規則の代わりにはならない

### 不完全なイベントと観測状態

- ハーネスは観測状態と不完全なイベントの件数を分けて報告する

| 状態 | 意味 |
| --- | --- |
| `not_attempted` | イベント収集を試みていない |
| `failed` | 起動またはアタッチを確認できていない |
| `observed` | 起動とアタッチを確認でき、観測期間の不完全性が報告されていない |
| `degraded` | 確認済みの収集に不完全性または欠落項目の未計測がある |

- 確認済みの収集で `lost_events`、`lost_notifications`、`convert_failures`、`map_overflow`、`enter_exit_unmatched` のいずれかが正なら `degraded` になる
- `stopped_early:true` または空でない `unmeasured` がある場合も `degraded` になる
- `partial_events` は `path_read_failures`、`path_truncations`、`enter_exit_unmatched_boundary`、`identity_unavailable` を別に合計する
- これらの不完全なイベントの件数は観測状態を変えない
- `path_read_failures` はスクリプトの失敗報告を集計し、その合計がゼロの場合だけ空の出力パス件数を採用する
- `observed` は全イベントのパスや識別情報が利用可能であることを意味しない
- イベントログが空でも `observed` になる場合がある
- イベント件数だけでは起動、アタッチ、完全性を確認できない
- ハーネスの CSV の合計と合わせて JSON の欠落詳細とイベントの注記を読む
- 未計測の項目は計測済みのゼロではない

## 時計

- `clock` は単調増加時計と実時刻の対応を記録する

| 時計 JSON のフィールド | 意味 |
| --- | --- |
| `boot_epoch` | 単調増加時計がゼロの時点の実時刻 |
| `error_ns` | 対にした読み取りの間隔の上限 |
| `clock_source` | `CLOCK_MONOTONIC` |
| `note` | 時計の読み取りについての説明 |

- イベントのタイムスタンプは `CLOCK_MONOTONIC` を使う
- 変換にも同じ時計が必要
- `CLOCK_BOOTTIME` はサスペンド中の時間を含むため、この変換で代わりに使うことはできない[^clock]
- `error_ns` は対にした読み取りの間隔の上限
- その後の実時刻の変化は含まない
- 照合時の許容誤差は変換誤差より大きくする必要がある
- トレース内の `C` レコードは、それ以降のイベントについて指定済みのエポックを上書きする

## cgroup 対応表と有効期間

| 対応表のフィールド | 意味 |
| --- | --- |
| `generated_at`, `root` | 対応表の生成時刻と階層のルート |
| `snapshots`, `updated_at` | スナップショット数と更新時刻 |
| `calibration` | 識別子の較正結果 |
| `entries` | 記録した cgroup の対応 |
| `errors` | 任意の収集エラー |

| エントリのフィールド | 意味 |
| --- | --- |
| `cgroup_id`, `path` | cgroup の識別子と階層内のパス |
| `container_id`, `depth` | 任意のコンテナ識別情報と、そのグループからの深さ |
| `generation` | グループの世代 |
| `first_seen`, `last_seen`, `expired_at` | 検出、最後の観測、有効期間終了の時刻 |
| `inode`, `handle_id`, `handle_error`, `id_agreement` | 識別子の較正の根拠 |

- 読み取り可能なファイルハンドル識別子が inode と異なる場合は、ファイルハンドル識別子を優先する
- 独自の親グループ配下でも Docker のスコープ名と接頭辞などのない 64 文字のコンテナ ID を認識する
- 子グループは最も近いコンテナの識別情報を継承する
- `-merge` は過去のエントリを保持する
- 消失または置き換えられたグループの有効期間は更新時に変化を検出した時点で終了する
- 有効期間は検出時に始まり、更新時に終わる
- その境界は独立に観測したライフサイクルの遷移ではない
- コンテナ作成後、計測対象の動作を開始する前に更新する
- 収集後にも過去の対応を保持して更新する
- 未知の cgroup は帰属不明のまま残す
- 帰属がないことはホストの出来事であることを示さない

## Docker なしでの動作確認

- 保存済み入力を使うと実環境の bpftrace や Docker なしで変換を確認できる

```sh
mkdir -p ./out
go test ./experiments/runtime-events -run '^TestConvert' -v
go run ./experiments/runtime-events convert \
  -in experiments/runtime-events/testdata/trace-sample.txt \
  -config-id recorded-sample -script-version 1 -sync startup -buffer-pages 64 \
  -boot-epoch 2026-09-13T00:00:00Z \
  -out ./out/sample-events.jsonl
```

- 固定のエポックはフィクスチャの基準時刻
- 現在のホストで計測した値ではない
- テスト対象は成功と失敗のオープン、順序が入れ替わった配信、プロセスの識別情報、相対パス、切り詰め、欠落の集計、時計、cgroup による帰属
- サンプルは 1 件の通知で 17 件のイベント欠落を報告する
- カウンターの合計はフィルタリング前が 4,823 件、フィルタリング後が 9 件
- この変換には cgroup 対応表もアタッチの確認結果も渡さない
- そのためイベントは帰属不明で、`attached` は false のまま残る

## 詳細な制限と注意

### 環境と互換性

- サードパーティーの Go 依存ライブラリを使わない単独の実験
- 製品のバイナリとコンテナイメージとは独立している
- Linux の BTF は `curtask->group_leader->start_boottime` を公開する必要がある
- README に挙げた 7 つのトレースポイントがすべて必要
- x86_64 では C ライブラリの `open()` が `openat(AT_FDCWD, ...)` ではなく従来の `open` を発行する場合がある
- `openat` 系だけの観測では従来の呼び出しを取りこぼす
- bpftrace にはスクリプトの `config` ブロック、`nsecs(monotonic)`、設定した文字列長への対応が必要
- フィルタ付きスクリプトは追加で `strcontains` を使う
- インストール済みの bpftrace のバージョンを記録する
- 実環境での計測に使った版は v0.25.0
- 動作する最低版は未確定
- config ブロック非対応の版ではコピーを修正し、トレーサーの環境に `BPFTRACE_MAX_STRLEN=256` と `BPFTRACE_PERF_RB_PAGES=64` を設定する[^bpftrace]
- その変更だけで互換性を確認したことにはならない
- root またはトレーシングとファイル読み取りに必要なケーパビリティが必要
- 最小限のケーパビリティは評価中
- 権限による失敗とホストのセキュリティ制限を記録する
- root でもトレーシングの成功は保証されない
- コンテナへの帰属には cgroup v2 を使うネイティブの Docker Engine とホスト階層へのアクセスが必要[^docker]
- ビルドにはリポジトリ指定の Go 1.26.4 を使う
- 例では Bash と jq を使う
- 観測の収集とスキャンの照合には [runtime-discovery の環境](../runtime-discovery/README.ja.md#必要な環境)も必要

### 計測実績

- 初期の 6 秒の確認は通常の `open` プローブ追加前にコンテナ 1 つで行った
- アタッチしたプローブは 7、実行イベントは 42 件、オープンは 2672 件、欠落は 0 件
- 現行スクリプトは 7 つのトレースポイントと `BEGIN`、`END` を合わせた 9 プローブ
- 最終計測は開発環境の Linux 6.6 カーネル上で root として行った 300 秒 × 43 回
- 対象は `startup`、`attach_running`、64／256／512 ページのバッファ
- カーネル 7.0 の本番ホストでの計測は未実施
- `CAP_BPF` と `CAP_PERFMON` のみでの収集は未実施
- 負荷計測は未実施
- 反復番号が 2 以上の計測があるのはケース 13（短命プロセス）のみ
- 保存済み入力の確認だけでは実環境での収集の信頼性や製品としての対応を確認できない
- 検証済みのアーキテクチャは amd64 のみ
- 他のアーキテクチャのシステムコール番号のエントリがあっても対応を確認したことにはならない

### パスと証拠

- 255 バイト以上のパスは設定された 256 バイトの文字列バッファを満たす
- そのようなパスは切り詰められた未解決のパスとして扱う
- 収集時にはカーネル側のパスフィルターを使わない
- 関連するマーカーより前で切り詰められたパスは後のユーザー空間での絞り込みでも除外され得る
- 収集するのは成功した実行と `open`、`openat`、`openat2` 系の呼び出し
- `creat` と io_uring 経由のオープンは対象外
- ファイルを開いたことは内容の読み取りや依存関係のコードの実行を証明しない
- 証拠は優先順位を上げるためだけに使う
- 証拠がないことは未使用、安全性、優先順位を下げる根拠を示さない

[^bpftrace]: [bpftrace の設定変数と config ブロック](https://bpftrace.org/docs/release_023/language)
[^docker]: [Docker Engine のランタイムメトリクスと cgroup v2](https://docs.docker.com/engine/containers/runmetrics/)
[^clock]: [Linux マニュアル: clock_gettime(2)、CLOCK_MONOTONIC、CLOCK_BOOTTIME](https://man7.org/linux/man-pages/man2/clock_gettime.2.html)
