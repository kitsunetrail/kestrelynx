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

- コマンドはリポジトリのルートから実行する
- トレーシングの確認ではスクリプトのロードと既知イベントの収集・変換を確認する
- 確認結果は experiments/runtime-discovery/out/check-tracing/ の smoke.log と events.jsonl に保存する
- ケース 13 は短命プロセスを起動し、収集、正解データの作成、照合まで通す

```sh
mkdir -p experiments/runtime-discovery/out
go build -o experiments/runtime-discovery/out/runtime-discovery ./experiments/runtime-discovery
go build -o experiments/runtime-discovery/out/runtime-events ./experiments/runtime-events
sudo bash experiments/runtime-discovery/tools/check-tracing.sh
sudo bash experiments/runtime-discovery/tools/case-run.sh 13 1 startup 512
# 保存先: experiments/runtime-discovery/out/<case>-root-30-300-p0-r<replicate>-<sync>-<tag>/
# 最初に読む: record.md、match_hc.json、csv_hc/series.csv
# 続けて確認: csv_hc/occurrence_capture.csv、csv_hc/attribution.csv、csv_hc/event_drops.csv
```

- 引数は `<case> [replicate] [startup|attach_running] [64|256|512|none]`
- このコマンドの対象はケース 13〜22 で、`none` はイベント収集なし
- `startup` は計測対象の処理より先に観測を開始し、`attach_running` は動作中の処理に途中から参加する
- 条件ごとに別の保存先を使い、生成データはコミットしない

### 複数ケースを流す

- 計画ファイルの各行は `<case> <replicate> <sync> <pages>`

```sh
sudo bash experiments/runtime-discovery/tools/case-batch.sh experiments/runtime-discovery/tools/plans/example.txt
```

### 帰属の検証

- 第 1 引数は条件で、`23` はケース 23 を単独、`24` はケース 24 を単独、`23+24` は両方を同時、`23+host` はケース 23 を動かしながらホストでも同じプログラムを実行
- 引数は `<23|24|23+24|23+host> [replicate] [256|512]`
- このコマンドの対象はケース 23 と 24 の組だけで、他のケースの帰属は `case-run.sh` の結果に含まれる

```sh
sudo bash experiments/runtime-discovery/tools/attribution-control-run.sh 23+24 1 512
```

- この例の保存先は experiments/runtime-discovery/out/23+24-root-30-300-p0-r1-startup-nofilter512p/
- コンテナ別の結果は match_hc-case23.json と match_hc-case24.json、CSV は csv_hc-case23/ と csv_hc-case24/

### 再処理と集計

- `<run-dir>` は保存済みの run ディレクトリに置き換える
- `case-post.sh` は複数のディレクトリを受け付け、`RECONVERT=1` でトレースの変換からやり直す
- `KL_INTEL_SNAPSHOT` に保存済みの脆弱性情報 JSON を指定すると、同じ入力としきい値で分類を再現できる

```sh
bash experiments/runtime-discovery/tools/case-post.sh "<run-dir>"
RECONVERT=1 bash experiments/runtime-discovery/tools/case-post.sh "<run-dir>"
python3 experiments/runtime-discovery/tools/aggregate.py
python3 experiments/runtime-discovery/tools/record.py "<run-dir>"
# 集計表: experiments/runtime-discovery/out/AGGREGATE-events.md
# 個別記録: <run-dir>/record.md
```

## ケース一覧

- ケース 1〜12 は[手動のサンプリング手順](REFERENCE.ja.md#手動での計測手順)を使う
- ケース 13〜24 はイベント証拠と追加のパッケージ対応付けを調べる
- 13〜22 は `case-run.sh` に番号を渡し、23/24 は帰属検証コマンドを使う

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

## 結果の読み方

- 最初に各 run の `record.md` と、run を横断する `out/AGGREGATE-events.md` を読む
- 次の 3 つの数を分けて確認し、詳細な件数は CSV を見る

| 数 | 意味 | 詳細の保存先 |
| --- | --- | --- |
| 利用を確認できた検出結果の数 | 従来ルール、追加の対応付け、イベント証拠の 3 系列で使用と結び付いた検出結果 | `csv_hc/series.csv` |
| 個々の実行・ロードの捕捉率 | 独立ログの評価対象から判定不能分を除いた実行・ロードの捕捉割合 | `csv_hc/occurrence_capture.csv` |
| コンテナへの帰属 | 正帰属、ホスト実行の非帰属、誤帰属を評価できる範囲 | `csv_hc/attribution.csv` |

- `event_state=observed` は起動とアタッチを確認でき、観測期間の不完全性が報告されていない状態で、詳細は `csv_hc/event_drops.csv` を確認する
- `event_state=degraded` は欠落、中断、欠落項目の未計測によって観測期間に制限がある状態で、発生を捕捉できたことだけでは完全性を示せない

## 制限

- 証拠は優先順位を上げるためだけに使い、証拠がないことを安全性や優先順位を下げる根拠にしない
- サンプリングは短命な動作を見逃すことがあり、`attach_running` はアタッチ前に完了した一度きりのロードを復元できない
- jar のオープンや Go バイナリの実行は、同梱された個々の依存の実行を証明しない
- Java のケースは独立ログにスレッド識別情報がないため、報告する発生単位の捕捉率の対象外
- 独立したプロセス対応表がなければ、コンテナ間誤帰属率は評価不能
- トレーシングの最小権限、イベント観測の負荷、本番相当環境での動作は未検証

## 詳細

- [入出力とフラグ](REFERENCE.ja.md#入出力)には保存ファイル、実行キー、コマンドのオプションを記載
- [手動での計測手順](REFERENCE.ja.md#手動での計測手順)にはサンプリングケース、開始順序、ヘルパーのコマンドを記載
- [正解データと照合](REFERENCE.ja.md#正解データgt-b)には独立ログ、識別情報、帰属の照合規則を記載
- [観測状態と CSV](REFERENCE.ja.md#観測状態)には完全性、算出不能な割合、14 本の表の説明を記載
- [動作確認と制限](REFERENCE.ja.md#docker-なしでの動作確認)には合成入力と証拠の詳しい限界を記載
