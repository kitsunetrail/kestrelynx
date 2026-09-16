# ランタイムイベントの実験

[English](README.md) | **日本語**

- bpftrace で「実行された」「ファイルを開いた」という出来事を記録する実験用ツール
- 出来事がどのコンテナに属するかを付け、runtime-discovery ハーネスが読める JSONL に変換する
- 製品のバイナリとは別物で、コンテナイメージにも含まれない
- 動機、計測、証拠の限界は[公開開発ログ](../../docs-ja/development/runtime-event-evidence.md)に記録

## できること

- トレーシングに使う時計と実時刻の対応を記録する
- cgroup とコンテナの対応表を有効期間付きで作成・更新する
- 出来事を収集して JSONL に変換し、帰属と取りこぼしも記録する

## 必要な環境

- BTF と必要な 7 つのトレースポイントを備えた Linux
- トレースポイントは `sched:sched_process_exec` と `syscalls:sys_enter_open`、`sys_exit_open`、`sys_enter_openat`、`sys_exit_openat`、`sys_enter_openat2`、`sys_exit_openat2`
- bpftrace は v0.25.0 での計測実績があり、動作する最低版は未確定
- cgroup v2 を使うネイティブの Docker Engine とホストの cgroup 階層へのアクセス
- sudo による root 権限
- Go 1.26.4、Bash、jq と、自動計測で使う [runtime-discovery の追加要件](../runtime-discovery/README.ja.md#必要な環境)

## 試し方

- コマンドはリポジトリのルートから実行する
- いちばん簡単な道は runtime-discovery のツールを使うこと
- `check-tracing.sh` はスクリプトのロードと既知イベントの収集・変換を確認する
- `case-run.sh` は収集、独立した正解データの作成、照合まで実行する

```sh
mkdir -p experiments/runtime-discovery/out
go build -o experiments/runtime-discovery/out/runtime-discovery ./experiments/runtime-discovery
go build -o experiments/runtime-discovery/out/runtime-events ./experiments/runtime-events
sudo bash experiments/runtime-discovery/tools/check-tracing.sh
# ケース 13: 短命プロセスの反復実行
sudo bash experiments/runtime-discovery/tools/case-run.sh 13 1 startup 512
```

- `experiments/runtime-discovery/out/check-tracing/` の `smoke.log` と `events.jsonl` を確認し、続けて計測結果の `record.md` と `csv_hc/event_drops.csv` を読む

### 単体で使う

- `<running-container>` は `sh`、`/bin/true`、`/etc/os-release` がある稼働中のコンテナに置き換える
- この例は稼働中のコンテナに途中から参加し、`attach_running` として短い観測期間を記録する
- 生成ファイルは Git の追跡対象外である `./out/` に保存し、トレース、観測、結果はコミットしない

```sh
mkdir -p ./out
go build -o ./out/runtime-events ./experiments/runtime-events
sudo bash -s -- '<running-container>' <<'SH'
set -euo pipefail
./out/runtime-events clock -out ./out/clock.json
./out/runtime-events cgroup-map -out ./out/cgroup-map.json
bpftrace experiments/runtime-events/bpftrace/runtime-events-nofilter.bt \
  > ./out/trace.txt \
  2> >(while IFS= read -r line; do
    printf '%s %s\n' "$(date -u +%FT%T.%NZ)" "$line"
  done > ./out/trace.err) &
tracer_pid=$!
trap 'kill -INT "$tracer_pid" 2>/dev/null || true; wait "$tracer_pid" 2>/dev/null || true' EXIT
bash experiments/runtime-discovery/cases/run.sh attach-check ./out/trace.txt
window_start=$(date -u +%FT%T.%NZ)
window_end=$(date -u -d "$window_start + 6 seconds" +%FT%T.%NZ)
docker exec "$1" sh -c '/bin/true; cat /etc/os-release >/dev/null'
sleep 6
kill -INT "$tracer_pid"
wait "$tracer_pid" || true
stop_instant=$(date -u +%FT%T.%NZ)
trap - EXIT
./out/runtime-events cgroup-map \
  -merge ./out/cgroup-map.json -out ./out/cgroup-map.json
cat ./out/trace.txt ./out/trace.err |
  ./out/runtime-events convert -in - -out ./out/events.jsonl \
    -cgroup-map ./out/cgroup-map.json \
    -config-id bpftrace-v2-nofilter-64p -script-version 3 \
    -filter runtime-events-nofilter.bt -variant nofilter \
    -sync attach_running -buffer-pages 64 -path-buffer 256 -attached \
    -boot-epoch "$(jq -r .boot_epoch ./out/clock.json)" \
    -clock-error-ns "$(jq -r .error_ns ./out/clock.json)" \
    -window-start "$window_start" -window-end "$window_end" \
    -stopped-at "$stop_instant"
SH
```

## スクリプト

| ファイル | 用途 | バッファ |
| --- | --- | --- |
| `bpftrace/runtime-events-nofilter.bt` | パスを絞り込まずに実行とオープンを収集 | 64 ページ |
| `bpftrace/runtime-events-nofilter-256p.bt` | バッファを増やして収集 | 256 ページ |
| `bpftrace/runtime-events-nofilter-512p.bt` | バッファを増やして収集 | 512 ページ |
| `bpftrace/runtime-events.bt` | パスフィルター付き収集の試行 | 64 ページ |
| `bpftrace/runtime-events-filtered-a.bt` | 判定に使うパスを短くした試行 | 64 ページ |
| `bpftrace/runtime-events-filtered-b.bt` | 文字列バッファを短くした試行 | 64 ページ |

- `runtime-events.bt`、`runtime-events-filtered-a.bt`、`runtime-events-filtered-b.bt` は計測環境で検証器に通らなかったフィルタ付きの試行の記録として残す

## 結果の読み方

| `events.jsonl` の行 | 意味 |
| --- | --- |
| ヘッダー: `events_header` | 収集設定、時計の情報、起動とアタッチの確認 |
| 出来事: `event` | 実行またはオープンと、その成否、パス、コンテナへの帰属 |
| 末尾: `events_trailer` | 終了のメタデータと取りこぼしの記録 |

- 取りこぼしたイベントの件数と、取りこぼしを知らせる通知の件数を分けて確認する
- オープンの開始と結果が対応しない記録は、観測期間内の不一致と境界の残片を分けて読む
- 出来事にコンテナへの帰属と利用可能なパスがあるかを確認する
- `observed` はハーネスが起動とアタッチを確認でき、観測期間の不完全性が報告されていない状態
- `degraded` は起動とアタッチを確認済みで、取りこぼし、予定終了前の停止、欠落項目の未計測によって観測期間に制限がある状態

## 制限

- ファイルオープンの対象は `open`、`openat`、`openat2` で、`creat` と io_uring 経由のオープンは対象外
- ファイルを開いたことは、その内容の読み取りや依存関係のコードの実行を証明しない
- 証拠は優先順位を上げるためだけに使い、証拠がないことを未使用、安全性、優先順位を下げる根拠にしない
- 検証済みのアーキテクチャは amd64 のみ
- PID 名前空間が入れ子の環境では観測側とワークロード側でプロセス番号が異なり得るため、照合には番号と名前空間の識別情報が必要

## 詳細

- [入出力](REFERENCE.ja.md#入出力)には生トレースの版数と JSONL のフィールドを記載
- [コマンドのフラグ](REFERENCE.ja.md#コマンドのフラグ)には全オプションと収集設定の確認事項を記載
- [計測の順序](REFERENCE.ja.md#計測の順序)には起動、準備完了、ヘルパー、変換、照合の手順を記載
- [カウンターと欠落](REFERENCE.ja.md#カウンターと欠落)には境界の残片、不完全なイベント、観測状態の説明を記載
- [時計](REFERENCE.ja.md#時計)と [cgroup 対応表と有効期間](REFERENCE.ja.md#cgroup-対応表と有効期間)には時刻変換と帰属期間の扱いを記載
- [動作確認と制限](REFERENCE.ja.md#docker-なしでの動作確認)には保存済み入力、計測実績、詳しい注意事項を記載
