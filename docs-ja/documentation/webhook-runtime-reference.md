---
title: Webhookの稼働時のフィールド
---

# Webhookの稼働時のフィールド

このページでは、汎用Webhookのペイロードに含まれるトップレベルの`runtime`と`findings[].runtime`のフィールドを説明します。
ペイロード全体の構造は[ペイロードの全体像](webhook-reference.md#payload-overview)、表の読み方と複数のフィールドで使う値は[レポートのフィールド](webhook-reference.md#report-fields)を参照してください。

稼働時のフィールドは、次の3か所に出力します。

| 場所 | 内容 |
| --- | --- |
| トップレベルの`runtime` | Sensorの状態と使用状況の件数 |
| `findings[].runtime` | パッケージグループごとの使用状況 |
| [差分の`runtime_usage`](webhook-diff-reference.md) | 変化があったパッケージの使用状況 |

稼働時の使用状況が無効の場合は、これらのフィールドをすべて省略します。
判定方法と観測の限界は、[稼働時の使用状況](runtime-usage.md)を参照してください。

## Sensorの情報 {#sensor-fields}

トップレベルの`runtime`は、Sensorの状態、使用中と判定する条件、使用状況の件数を示します。
フィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `sensor_status` | string | Sensor全体の状態 | — |
| `heartbeat_at` | string | RFC 3339形式のSensorの最終報告時刻 | 報告時刻がなければ省略 |
| `interval_seconds` | integer | 秒単位のサンプリング間隔 | `0`なら省略 |
| `rules` | object | 使用中と判定する条件を示す固定の値 | — |
| `rules.os_packages` | string | OSパッケージの判定条件 | — |
| `rules.lang_packages_binary` | string | 実行ファイルに組み込まれた言語パッケージの判定条件 | — |
| `rules.lang_packages_runtime` | string | ランタイムが読み込む言語パッケージの判定条件 | — |
| `events_status` | string | eBPFによるイベント観測の状態 | Sensorの報告を読めなければ`""` |
| `events_reason` | string | eBPFによるイベント観測を利用できない理由 | 理由がなければ省略 |
| `counts` | object | [使用状況の件数](#runtime-counts) | — |

`sensor_status`の値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `ok` | Sensorが正常に動作している |
| `degraded` | 処理の停滞などにより、観測や結果の保存に支障がある |
| `stale` | Sensorの最後の報告から時間が経ち、観測結果の新しさを確認できない |
| `not_reporting` | Sensorの観測結果を保存したファイルがまだない |
| `permission_denied` | Sensorがコンテナのプロセス情報などを読み取る権限を利用できない |
| `evidence_invalid` | KestreLynxが観測結果のファイルを読み取れないか、内容の検証を通らない |
| `isolation_failed` | 読み取り以外の操作の制限を設定できず、Sensorが観測を始めていない |
| `isolation_degraded` | Sensorによる読み取り以外の操作の制限が一部効いていない |

`rules`の各フィールドの固定値は次のとおりです。

| フィールド名 | 値 | 意味 |
| --- | --- | --- |
| `os_packages` | `executed_or_loaded_by_running_process` | パッケージのファイルの実行やライブラリとしての読み込みを、定期的な確認またはeBPFのイベントで確認した場合に使用中と判定 |
| `lang_packages_binary` | `in_running_binary` | パッケージを組み込んだ実行ファイルが動いていることを定期的な確認で見つけた、またはeBPFでその起動を観測した場合に使用中と判定 |
| `lang_packages_runtime` | `runtime_process_running` | パッケージに対応するランタイムのプロセスが動いていることを定期的な確認で見つけた、またはeBPFでその起動を観測した場合に使用中と判定 |

`events_status`は、`sensor_status`とは別にeBPFによるイベント観測の状態を示します。
値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `ok` | eBPFによるイベント観測を利用できる |
| `unavailable` | eBPFによるイベント観測を利用できず、サンプリングだけで観測する |

`events_reason`の値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `kernel_unsupported` | カーネルがイベント観測に対応していない |
| `btf_missing` | イベント観測に必要な、カーネルの型情報を読み取れない |
| `permission` | eBPFによる観測に必要な権限を利用できない |
| `attach_failed` | イベント観測の準備や開始に失敗した |
| `cgroup_v1` | ホストのコンテナ管理の仕組みが、観測に必要なcgroup v2ではない |

次の例は、Sensorが正常に動作している場合のトップレベルの`runtime`です。

```json
{
  "sensor_status": "ok",
  "heartbeat_at": "2026-06-24T09:00:00Z",
  "interval_seconds": 30,
  "rules": {
    "os_packages": "executed_or_loaded_by_running_process",
    "lang_packages_binary": "in_running_binary",
    "lang_packages_runtime": "runtime_process_running"
  },
  "events_status": "ok",
  "counts": {
    "in_use": 2,
    "not_observed": 2,
    "unavailable": 1,
    "muted": 0
  }
}
```

## 使用状況の件数 {#runtime-counts}

`runtime.counts`は、`actionable`、`watch`、`wont_fix`、`eol_packages`に含まれるすべてのパッケージグループを、使用状況ごとに数えます。
フィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `in_use` | integer | 使用中のパッケージグループ数 | `0` |
| `not_observed` | integer | 使用が確認されないパッケージグループ数 | `0` |
| `unavailable` | integer | 使用状況を判定できないパッケージグループ数 | `0` |
| `muted` | integer | [通知オフ](runtime-usage.md#muting-findings-without-a-fix)のパッケージグループ数 | `0` |

`muted`は、使用が確認されないパッケージグループだけを数えるため、`not_observed`の内数です。

使用状況の意味は、[使用状況の値](webhook-reference.md#usage-values)を参照してください。

## パッケージグループの使用状況 {#finding-runtime}

`findings[].runtime`は、パッケージグループの使用状況と、その判定に使った観測結果を示します。
フィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `usage` | string | パッケージグループの使用状況 | — |
| `reason` | string | [使用状況を判定できない理由](#runtime-reasons) | `usage`が`unavailable`以外なら省略 |
| `evidence_kinds` | stringの配列 | 使用を確認した観測の種類 | `usage`が`in_use`以外なら省略 |
| `events_coverage` | string | eBPFによるイベント観測の範囲 | `usage`が`in_use`、対象のコンテナがない、またはSensorの報告を使えない場合は省略 |
| `exposure` | string | 使用を確認したプロセスのポートの公開範囲 | Sensorの報告を使えない場合、または`usage`が`in_use`で`containers[0].process`がない場合は省略 |
| `high_privilege` | boolean | 高い権限で動いている場合に`true` | 該当しなければ省略 |
| `containers` | objectの配列 | [コンテナごとの観測結果](#container-evidence) | 対象のコンテナがないか、Sensorの報告を使えなければ省略 |
| `muted` | boolean | [通知オフ](runtime-usage.md#muting-findings-without-a-fix)の場合に`true` | 通知オフでなければ省略 |
| `muted_reason` | string | [通知オフ](runtime-usage.md#muting-findings-without-a-fix)の理由 | 通知オフでなければ省略 |

`evidence_kinds`のうち、OSパッケージに使う値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `exe` | 定期的な確認で、パッケージのファイルが実行中だった |
| `mapped_library` | 定期的な確認で、パッケージのライブラリを読み込んだプログラムが動いていた |
| `exec_event` | eBPFで、パッケージのファイルが実行される出来事を捉えた |
| `library_load_event` | eBPFで、パッケージのライブラリが読み込まれる出来事を捉えた |

`evidence_kinds`のうち、言語パッケージに使う値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `binary_running` | 定期的な確認で、パッケージを組み込んだ実行ファイルが動いていた |
| `binary_executed` | eBPFで、パッケージを組み込んだ実行ファイルが起動する出来事を捉えた |
| `runtime_running` | 定期的な確認で、パッケージに対応する実行環境が動いていた |
| `runtime_executed` | eBPFで、パッケージに対応する実行環境が起動する出来事を捉えた |

`events_coverage`の値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `since_start` | コンテナの起動前からeBPFによるイベント観測を開始し、イベントの欠落を記録していない |
| `partial` | コンテナの起動後にイベント観測を開始した、またはイベントの一部が欠落した |
| `none` | eBPFによるイベント観測なし |

`exposure`の値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `host_published_all` | ホストのすべてのインターフェースに公開 |
| `host_published_loopback` | ホストのループバックだけに公開 |
| `container_listening` | 待ち受けているがホストには公開していない |
| `unknown` | 公開範囲を判定できない、または使用中でない |

`muted_reason`の値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `no_fix_not_in_use_7d` | 修正版がなく、7日以上使用が確認されない |

次のフィールドには補足があります。

- `usage`
    - コンテナや言語パッケージの場所ごとの判定に、次の条件を上から順に適用
        1. 1つでも使用中なら`in_use`
        2. 判定できないものがあれば`unavailable`
        3. 判定対象がすべて使用未確認なら`not_observed`
- `events_coverage`
    - コンテナや言語パッケージの場所ごとの値を、`none`、`partial`、`since_start`の順で優先し、最も観測が不十分な値を採用
- `high_privilege`
    - 次のいずれかに該当すると`true`
        - privilegedコンテナで実行
        - [危険なcapability](#container-evidence)を持つ
        - user namespaceの外で実効UID 0として実行
    - `usage`が`in_use`の場合、`exposure`とともに先頭の`containers[0]`の観測から採用
    - `exposure`と同じプロセスについての値で、採用したプロセスの情報は`containers[0].process`に出力
- `containers`
    - このイメージを動かしている観測対象のコンテナごとに1要素を含める
    - そのパッケージを使用中でないコンテナも含める

次の例は、使用中のパッケージグループの`runtime`です。

```json
{
  "usage": "in_use",
  "evidence_kinds": [
    "exe"
  ],
  "exposure": "host_published_all",
  "high_privilege": true,
  "containers": [
    {
      "name": "web-1",
      "container_id": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
      "generation_started_at": "2026-06-24T08:00:00Z",
      "usage": "in_use",
      "last_seen": "2026-06-24T09:00:00Z",
      "ports": [
        "0.0.0.0:443/tcp"
      ],
      "process": {
        "exe": "/usr/sbin/nginx",
        "effective_uid": 0,
        "userns": false,
        "privileged": false
      }
    }
  ]
}
```

`usage`の意味は、[使用状況の値](webhook-reference.md#usage-values)を参照してください。
通知オフの条件は、[修正版がない所見の通知オフ](runtime-usage.md#muting-findings-without-a-fix)を参照してください。

## コンテナの証拠 {#container-evidence}

`findings[].runtime.containers[]`は、コンテナごとの使用状況と、観測したプロセスや言語パッケージの場所ごとの判定を示します。
コンテナは次の順に並べます。

1. 使用中のコンテナが先
2. 使用中のコンテナ同士は、全インターフェースに公開、ループバックだけに公開、ホストに公開せず待ち受け、公開範囲不明の順
3. 公開範囲が同じ使用中のコンテナ同士は、高い権限のものが先
4. 使用状況、公開範囲、権限で順序が決まらない場合は、コンテナIDの順

コンテナ自体のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `name` | string | コンテナ名 | `""` |
| `container_id` | string | 64桁の16進数のコンテナID | `""` |
| `generation_started_at` | string | Sensorが、今動いているそのコンテナを最初に観測した時刻 | 省略 |
| `usage` | string | このコンテナでのパッケージの使用状況 | — |
| `reason` | string | [使用状況を判定できない理由](#runtime-reasons) | `usage`が`unavailable`以外なら省略 |
| `last_seen` | string | 最後に観測した時刻 | 省略 |
| `ports` | stringの配列 | コンテナ側で`process`のプロセスが待ち受けるアドレスとポート | 省略 |
| `kinds_ambiguous` | boolean | OSパッケージの観測の種類を個々のプロセスに対応付けられない場合に`true` | `false`なら省略 |
| `process_exes` | stringの配列 | 観測した実行ファイルの重複を除いた一覧 | `kinds_ambiguous`が`false`なら省略 |
| `process` | object | 使用の根拠となったプロセスの情報 | プロセスの観測がなければ省略 |
| `instances` | objectの配列 | 言語パッケージの場所ごとの使用状況 | OSパッケージなら省略 |

`process`のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `exe` | string | 実行ファイルのパス | 省略 |
| `effective_uid` | integer | プロセスの実効UID | — |
| `userns` | boolean | user namespaceを使用している場合に`true` | `false` |
| `dangerous_caps` | stringの配列 | プロセスが持つ危険なcapabilityの一覧 | 省略 |
| `privileged` | boolean | privilegedコンテナで動いている場合に`true` | `false` |

`instances[]`の各要素のフィールドは次のとおりです。

| フィールド名 | 型 | 意味 | 値がないとき |
| --- | --- | --- | --- |
| `type` | string | パッケージの種類 | 省略 |
| `target` | string | 検出対象のファイルのパスやランタイム名 | 省略 |
| `pkg_path` | string | 個々のパッケージの所在を示すファイルのパス | 省略 |
| `usage` | string | この場所でのパッケージの使用状況 | — |
| `reason` | string | [使用状況を判定できない理由](#runtime-reasons) | `usage`が`unavailable`以外なら省略 |

次のフィールドには補足があります。

- `generation_started_at`
    - RFC 3339形式の時刻
- `last_seen`
    - RFC 3339形式の時刻
    - 使用中なら、出力した使用の根拠を最後に観測した時刻
    - 使用中でなければ、コンテナを最後に確認した時刻
- `ports`
    - `アドレス:ポート/プロトコル`の形式で、例は`0.0.0.0:443/tcp`
    - ホスト側の公開アドレスや公開ポートへの変換はしない
- `kinds_ambiguous`
    - `true`のときは、`evidence_kinds`の種類と`process.exe`・`process_exes`の実行ファイルを1対1に対応させて読まない
- `process`
    - 複数のプロセスを観測した場合は、公開範囲が最も広く、公開範囲が同じなら権限が最も高いプロセス1つの情報
- `process.dangerous_caps`
    - 対象は`CAP_SYS_ADMIN`、`CAP_SYS_PTRACE`、`CAP_SYS_MODULE`、`CAP_NET_ADMIN`、`CAP_DAC_READ_SEARCH`、`CAP_DAC_OVERRIDE`、`CAP_SETUID`、`CAP_SETGID`
- `instances`
    - 同じ言語パッケージがコンテナの中の複数の場所にある場合の、場所ごとの判定
    - 場所には、パッケージを組み込んだ実行ファイルや、パッケージのパスがある
- `instances[].type`
    - `python-pkg`や`node-pkg`などのパッケージの種類
- `instances[].target`・`instances[].pkg_path`
    - Trivyの値の先頭に`/`がある場合、その1文字を取り除いて出力
    - KestreLynxが追加するNode.js・Python本体の検出結果では、KestreLynxが求めた本体の実行ファイルのパスを両方のフィールドに出力

次の例は、Pythonの言語パッケージを使用中と判定したコンテナ1つの情報です。

```json
{
  "name": "api-1",
  "container_id": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
  "generation_started_at": "2026-06-24T08:00:00Z",
  "usage": "in_use",
  "last_seen": "2026-06-24T09:00:00Z",
  "process": {
    "exe": "/usr/bin/python3.11",
    "effective_uid": 1000,
    "userns": false,
    "privileged": false
  },
  "instances": [
    {
      "type": "python-pkg",
      "usage": "in_use"
    }
  ]
}
```

コンテナと`instances[]`の`usage`の意味は、[使用状況の値](webhook-reference.md#usage-values)を参照してください。

## 判定できない理由 {#runtime-reasons}

パッケージグループ、コンテナ、言語パッケージの場所ごとの`reason`は、`usage`が`unavailable`のときに出力します。
使用状況を判定できない理由を、次の値で示します。

Sensorからの情報の取得と、観測の準備・継続に関する値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `sensor_not_reporting` | Sensorの観測結果のファイルがまだない |
| `sensor_stale` | Sensorの報告や対象コンテナの確認から時間がたち、使用が確認されないと判断できない |
| `evidence_invalid` | Sensorの観測結果を読み取り、内容を検証する処理に失敗している |
| `isolation_failed` | Sensorに読み取り以外の操作を制限する設定ができず、観測を始めていない |
| `permission_denied` | Sensorがコンテナのプロセス情報やファイルを読む操作を拒否されている |
| `initializing` | パッケージとファイルを対応付けるための準備ができていない |
| `stalled` | 対象コンテナを調べる処理が制限時間内に終わっていない |
| `truncated` | 読み取り量などの上限に達し、観測に必要な情報の一部を取得できていない |
| `incomplete` | 観測結果の一部を利用できず、その部分での使用を確認できない |

コンテナと観測結果の対応に関する値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `generation_unverified` | 観測結果が、現在のコンテナの起動状態とスキャン対象のイメージに対応するか確認できない |
| `container_not_observed` | 対象コンテナについて、判定に使える観測結果がない |

パッケージの管理情報や、そのファイルとの対応に関する値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `parse_failed` | コンテナのパッケージ管理情報を解析する処理が失敗している |
| `db_absent` | コンテナ内に、利用できるパッケージ管理情報が見つかっていない |
| `db_error` | 対応するパッケージ管理情報は見つかったが、読み取りまたは解析に失敗している |
| `db_unsupported` | コンテナ内のパッケージ管理情報が、Sensorの対応していない形式 |
| `no_file_list` | パッケージ管理情報から、そのパッケージに属するファイルの一覧を取得できない |
| `attribution_ambiguous` | 観測したファイルが複数のパッケージに属し、どのパッケージの使用か特定できない |
| `file_replaced` | 観測したファイルが削除・置換され、パッケージとの対応を確定できない |
| `version_mismatch` | Sensorが使用を確認したパッケージの版が、スキャンで検出した同名のパッケージの版と異なる |

言語パッケージとの対応に関する値は次のとおりです。

| 値 | 意味 |
| --- | --- |
| `ecosystem_unmapped` | その言語パッケージの種類について、使用判定に使う実行環境が対応付けられていない |
| `binary_path_unknown` | パッケージの使用判定に必要な実行ファイルの場所が、スキャン結果にない |

次の例は、Sensorからの報告がなく、使用状況を判定できないパッケージグループの`runtime`です。

```json
{
  "usage": "unavailable",
  "reason": "sensor_not_reporting"
}
```
