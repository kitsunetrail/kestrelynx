# 稼働時の使用状況

Dockerホストに任意のSensorコンテナを追加すると、使用中のパッケージの所見に印が付き、
そのパッケージと、それを含むイメージが同じ優先度の中で先に並びます。
優先度そのものは変わりません。

Sensorは稼働中のプログラムが使っているパッケージを観測し、本体がその結果を
SlackとWebhookの通知に反映します。トリアージが無効の場合も使用状況は表示しますが、
並べ替えは行いません。

## 使用状況の意味

| 使用状況 | 意味 |
| --- | --- |
| `in_use` | 以下の判定方法で使用を確認できた状態です。 |
| `not_observed` | 観測期間に使用を確認できなかった状態です。使われていないことは意味しません。 |
| `unavailable` | 証拠が足りず判定できない状態です。理由を付けて表示します。 |

| パッケージの種類 | 使用中とみなす条件 |
| --- | --- |
| OSパッケージ | 稼働中のプロセスが、そのパッケージのファイルを実行した、またはライブラリとして読み込んだことを、サンプリングまたはeBPFによる短命なプロセスの実行・読み込みのイベントで確認した場合です。 |
| Go・Rustなど実行ファイルに組み込まれる言語パッケージ | Trivyの検出対象（Target）の実行ファイルが、稼働中のプロセスとして動いている場合です。 |
| Python・Node.js・Javaなど実行環境が読み込む言語パッケージ | そのコンテナで`python`・`node`・`java`など対応する実行環境のプロセスが動いている場合です。そのエコシステムのパッケージをすべて使用中とみなします。 |

関数の呼び出しやモジュールの読み込みは判定しません。
データファイルの読み取りは使用の根拠にしません。

Slackでは、観測した動作とともに`▶ in use`を表示します。スレッドでは
`▷ not observed`や`▷ runtime evidence unavailable (<理由>)`も表示します。
通知の文言、並び順、Webhookのフィールドは[KestreLynxの仕組み](how-it-works.md)に記載しています。

## 動作要件

Dockerとcgroup v2が必要です。Kubernetesでは利用できません。
`runtime.enabled`と`kubernetes.enabled`の両方を有効にすると設定エラーになります。

配布のComposeファイルでは、Sensorは非rootのUID 65532で、次の設定で動作します。

- `pid: host`
- `cgroup: host`
- `network_mode: none`
- `read_only: true`
- `cap_drop: [ALL]`
- `cap_add: [SYS_PTRACE, DAC_READ_SEARCH, BPF, PERFMON]`
- 配布のseccompプロファイル

短命なプロセスを観測するeBPFには、BTFのあるカーネルが必要です。
BPF・PERFMONがない場合、BTFがない場合、cgroup v1のホストでは、
警告してサンプリングだけで動き続けます。この場合、短命なプロセスは観測できません。

| 環境 | 確認状況 |
| --- | --- |
| Ubuntu 26.04 | Linux 7.0、AppArmor有効、Docker 29.5.1で確認済みです。x86_64、cgroup v2のsystemdドライバです。 |
| WSL2 | Linux 6.6、Docker Engine 29.1.3で確認済みです。x86_64、cgroup v2のsystemdドライバです。 |
| arm64、cgroupfsドライバ、userns-remap | 未確認です。 |

AppArmor有効のホストでは、unconfined・privilegedのコンテナのファイルの読み取りが
拒否され、そのコンテナは`permission denied`になります。
`docker-default`のコンテナのファイルは読み取れます。

## Sensorの導入

### Sensorの起動

リポジトリの`deploy/docker/`にある
[`docker-compose.sensor.yml`](https://github.com/kitsunetrail/kestrelynx/blob/main/deploy/docker/docker-compose.sensor.yml)と
[`sensor-seccomp.json`](https://github.com/kitsunetrail/kestrelynx/blob/main/deploy/docker/sensor-seccomp.json)を
同じディレクトリに置き、そのディレクトリで起動します。

```bash
docker compose -f docker-compose.sensor.yml up -d
```

Sensorは本体と同じイメージ`ghcr.io/kitsunetrail/kestrelynx`を、
`kestrelynx-sensor`という別のentrypointで動かします。
証拠ボリュームの名前は`kestrelynx-runtime`に固定しています。
Sensorは自身のコンテナを観測しないため、本体がそのコンテナを使用状況の判定から外すよう、
Sensorのコンテナには`io.kestrelynx.runtime.exclude: "true"`のラベルが付いています。

### 証拠ボリュームのマウント

本体のComposeファイルに、Sensorの証拠ボリュームを読み取り専用で追加します。

```yaml
services:
  kestrelynx:
    volumes:
      - kestrelynx-runtime:/var/lib/kestrelynx-runtime:ro
volumes:
  kestrelynx-runtime:
    external: true
```

### 使用状況の有効化

本体の`config.yml`に次の設定を追加します。

```yaml
runtime:
  enabled: true
```

本体のComposeディレクトリでコンテナを作り直します。

```bash
docker compose up -d
```

`runtime.evidence_dir`の既定値は`/var/lib/kestrelynx-runtime`です。
変更する場合は絶対パスを指定し、Sensorの`--evidence-dir`と一致させます。
Sensorを置かない場合は`runtime.enabled`を`false`のままにします。
本体は証拠ディレクトリを開かず、通知に稼働時の情報を追加しません。
設定項目は[設定](configuration.md)に記載しています。

本体を再起動した直後のスキャンでは、Sensorがまだ新しいコンテナを観測していないため、
そのイメージが一時的に`container not observed`になることがあります。
次のスキャンで解消します。

### 観測のオプション

SensorのComposeの`command`には、次のオプションを指定できます。

| オプション | 既定値 | 説明 |
| --- | --- | --- |
| `--interval` | `30s` | サンプリングの間隔です。`10s`〜`5m`で指定します。 |
| `--exclude-id` | — | コンテナIDの先頭12文字以上で、観測しないコンテナを指定します。繰り返し指定できます。 |
| `--evidence-dir` | `/var/lib/kestrelynx-runtime` | 証拠ディレクトリです。 |

`io.kestrelynx.runtime.exclude=true`のラベルを持つコンテナは、使用状況の判定から外します。
値は小文字の`true`だけが該当します。

使用状況が有効な場合、本体はDocker APIの`GET /containers/json`に加えて
`GET /containers/{id}/json`も使用します。

## Sensorの状態

Sensorに問題がある場合は、通知の先頭に警告を表示します。
Webhookでは`runtime.sensor_status`で状態を確認できます。

| 状態 | 意味 |
| --- | --- |
| `ok` | 正常に動作しています。 |
| `not_reporting` | 証拠ファイルがまだありません。Sensorの未起動時や起動直後などが該当します。 |
| `stale` | 最後の報告から、intervalの10倍と5分の大きい方を超えています。 |
| `evidence_invalid` | 証拠ファイルが検証を通りません。 |
| `permission_denied` | Sensorの読み取りが拒否されています。 |
| `isolation_failed` | 読み取り以外の操作の制限の設定に失敗し、観測を始めていません。 |
| `isolation_degraded` | 読み取り以外の操作の制限の一部が効いていない状態で動いています。 |
| `degraded` | Sensorの処理が詰まっているなど、一部の観測ができていません。 |

Sensor全体が`isolation_failed`または`permission_denied`の場合は、
確認済みの使用中を除き、判定できない状態にします。
報告が古い場合は、`not_observed`を理由が`sensor_stale`の`unavailable`にします。

## 権限

### 読み取りの権限

Sensorは、ホストのすべてのコンテナのプロセス情報と、コンテナ内の設定ファイルなどを含む
ファイルを読み取れます。

`SYS_PTRACE`と`DAC_READ_SEARCH`は、他のコンテナの`/proc/<pid>/`から、
実行ファイル、読み込んだライブラリ、開いているファイルの一覧、待ち受けているソケットを
読むために使います。コンテナのファイルシステムにあるパッケージのデータベースも読み取ります。

`BPF`と`PERFMON`は、起動時にeBPFのプログラムを読み込むときだけ使い、
読み込んだ後に捨てます。

### 読み取り以外の操作の制限

- ネットワーク、Dockerソケット、`config.yml`なし
- ルートファイルシステムは読み取り専用で、書き込み先はSensor自身の証拠ボリュームのみ
- 起動時にno-new-privilegesとdumpableの解除を自身で設定
- 配布のseccompプロファイルで、書き込みのためのファイルのオープン、ptrace、他のプロセスのメモリの読み書き、ソケットの作成などを拒否
- 他のコンテナのパッケージのデータベースは、Landlockとseccompで書き込み・ネットワーク・execのできない子プロセスで解析

Composeでno-new-privilegesを付けないのは、イメージのfile capabilityを
起動時に有効にするためです。AppArmor有効のホストでは、
確認した危険な操作25件がすべて拒否されました。

### 証拠ファイル

本体は証拠ファイルを読むだけで、形式・上限・値の集合の検証を通らないファイルは使いません。
証拠はSensorのボリューム内の`procfs.json`に保存します。
所有者はSensorのUID、パーミッションは`0644`です。

## 観測の限界

- 観測はSensorの起動後からで、それより前に終了した短命なプロセスは対象外
- Sensorの起動より前から動いていたコンテナは、使用が確認されない表示に`short-lived programs not fully observed`の注記を付加
- Sensorが一度も見つけないまま終了した、ごく短時間のコンテナは観測の対象外
- データファイルの読み取りは使用の根拠の対象外
- 実行環境による言語パッケージの判定はエコシステム全体が対象で、関数の呼び出しやモジュールの読み込みは未判定

