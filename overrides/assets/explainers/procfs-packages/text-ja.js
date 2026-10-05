window.KLX_TEXT = {
  ui: {
    play: '再生',
    pause: '一時停止',
    prev: '前へ',
    next: '次へ',
    reset: '最初から',
    counter: 'ステップ {i} / {n}',
    back: '元記事の説明：',
    backSep: ' · ',
  },
  cols: {
    proc: 'ホストから見たプロセス',
    maps: '読み込まれたファイル（maps）',
    dpkg: 'コンテナ内の dpkg の記録',
    match: 'Trivy の結果との照合',
  },
  legend: {
    pid: 'PID',
    path: 'パス',
    pkg: 'パッケージ名',
    ver: 'バージョン',
  },
  proc: {
    master: 'マスター',
    worker: 'ワーカー',
    followed: 'この図で追うワーカー',
    moreWorkers: '… ワーカーは計14個（一覧は抜粋）',
    hostPid: '1列目がホスト側PIDです。このPIDで `/proc/<pid>` を読みます。収集プログラムは全PIDを同じ手順で調べます。',
    followedLabel: '追うプロセスのPID：',
    starttime: '`/proc/2479938/stat` の22番目のフィールド `starttime`',
    startedAt: 'Docker の `State.StartedAt`',
    before: '収集前',
    after: '収集後',
    same: 'どちらも収集前後で同じ値なので、このサンプルを採用します。',
  },
  maps: {
    waiting: '次に、このワーカーの `maps` を読みます。',
    excerpt: '抜粋：アドレス範囲とオフセットの列は省略',
    rule: '権限に `x` があり、パスが `/` で始まり、inode が0でない行を残します。',
    kept: '残ったファイル（8件）',
  },
  dpkg: {
    waiting: 'ファイルのパスを取り出した後、コンテナ内の dpkg の記録を読みます。',
    where: '読む場所',
    rootNote: 'このプロセスの `root` 経由で、コンテナ内の `/var/lib/dpkg` を読みます。ホストの `/var/lib/dpkg` はホストのパッケージの記録です。',
    listTitle: '`info/libssl3:amd64.list`（抜粋）',
    indexTitle: '作った索引（パス → パッケージ）',
    indexMore: '… 全パッケージの `.list` から作った索引の一部',
    statusTitle: '`status` の `libssl3` の段落（抜粋）',
  },
  match: {
    waiting: '所有元とバージョンを調べ、サンプルを採用した後、Trivy の結果と照合します。',
    trivyTitle: 'Trivy の検出結果（libssl3 の32件から1件を抜粋）',
    observed: '観測側のパッケージ名とバージョン',
    result: 'パッケージ名とバージョンが、どちらも一致しています。',
    recordTitle: '読み込みの確認を記録した結果',
  },
  steps: {
    1: {
      title: 'docker top でマスターとワーカーのホスト側PIDを得る',
      body: [
        ['`docker top nginx -eo pid,ppid` で、コンテナ `nginx` のマスター（PID 2479853）と14個のワーカーのホスト側PIDを取得する', [
          '収集プログラムは一覧の全PIDを同じ手順で調べる',
        ]],
        'この図ではワーカー PID 2479938 を追い、ホストの `/proc/2479938` を読む',
      ],
      back: [
        ['コンテナのホスト側PIDを取得する', '../procfs-process-to-package-mapping-ja/#pid'],
      ],
    },
    2: {
      title: 'maps から実行可能なファイルのパスを取り出す',
      body: [
        '`/proc/2479938/maps` には、同じ `libssl.so.3` について `r--p`・`r-xp`・`rw-p` の行がある',
        ['権限に `x` があり、パスが `/` で始まり、inode が0でない行だけを残す', [
          '`[heap]` や匿名の行は除かれ、このワーカーでは `nginx` や `libssl.so.3` など8つのファイルが残る',
        ]],
      ],
      back: [
        ['実行ファイルとマッピングされたライブラリ', '../procfs-process-to-package-mapping-ja/#_3'],
      ],
    },
    3: {
      title: 'プロセスの root 経由でコンテナ内の dpkg の記録を読む',
      body: [
        '`maps` にあるのはコンテナ内のパスである',
        '所有元を調べるため、`/proc/2479938/root` 経由でコンテナ内の `/var/lib/dpkg` を読む',
      ],
      back: [
        ['コンテナ内のパスを解決する', '../procfs-process-to-package-mapping-ja/#_5'],
      ],
    },
    4: {
      title: 'ファイル一覧から索引を作り、パスの所有元を引く',
      body: [
        'dpkg はパッケージごとのファイル一覧を `info/<パッケージ>.list` に持つ',
        ['全パッケージの `.list` から**パス → パッケージ**の索引を作り、`maps` で残したパスを引く', [
          '`libssl3:amd64.list` には `libssl.so.3` と `libcrypto.so.3` の両方があり、どちらも `libssl3` のファイルだと分かる',
        ]],
      ],
      back: [
        ['DebianとUbuntu：dpkg', '../procfs-process-to-package-mapping-ja/#debianubuntudpkg'],
      ],
    },
    5: {
      title: 'status から libssl3 のインストール済みバージョンを読む',
      body: [
        '`.list` にあるのはパスだけなので、バージョンは `/var/lib/dpkg/status` の `libssl3` の段落から読む',
        '`Package` は `libssl3`、`Architecture` は `amd64` である',
        '`Status: install ok installed` がインストール済みの状態を示す',
        '照合に使う `Version` は `3.0.16-1~deb12u1` である',
      ],
      back: [
        ['DebianとUbuntu：dpkg', '../procfs-process-to-package-mapping-ja/#debianubuntudpkg'],
      ],
    },
    6: {
      title: '収集前後の開始時刻を比べてサンプルを採用する',
      body: [
        'PIDは再利用されることがあるため、収集前後で `/proc/2479938/stat` の22番目のフィールド `starttime` を比べる',
        'コンテナの再起動を確認するため、Docker の `State.StartedAt` も比べる',
        'この例では `starttime` は前後とも `15146823` で、`State.StartedAt` も変わっていないため、このサンプルを採用する',
      ],
      back: [
        ['名前空間の識別情報とPIDの再利用', '../procfs-process-to-package-mapping-ja/#pid_1'],
      ],
    },
    7: {
      title: '観測したパッケージ名とバージョンを Trivy の結果と照合する',
      body: [
        ['観測側のパッケージ名とバージョンを、Trivy の `PkgName` と `InstalledVersion` にそれぞれ照合する', [
          'パッケージ名は `libssl3`、バージョンは `3.0.16-1~deb12u1` で、どちらも一致する',
        ]],
        ['Trivy はこのパッケージに32件の脆弱性を検出している', [
          '図では `CVE-2025-15467`（`HIGH`、`FixedVersion` は `3.0.18-1~deb12u2`）を1件抜粋している',
        ]],
      ],
      back: [
        ['全体の手順', '../procfs-process-to-package-mapping-ja/#_13'],
      ],
    },
    8: {
      title: '有効な観測結果を読み込みの確認として記録する',
      body: [
        '5分間・30秒間隔で取得した10回のサンプルは、すべて有効だった',
        '`libssl.so.3` と `libcrypto.so.3` を検出結果のパッケージ名とバージョンに紐づけられ、`libssl3` は**読み込みを確認**（`verdict: confirmed`）と記録された',
        ['確認できるのはファイルの読み込みまでで、脆弱な関数が実行されたかは分からない', [
          '方法の限界は元記事で説明している',
        ]],
      ],
      back: [
        ['全体の手順', '../procfs-process-to-package-mapping-ja/#_13'],
        ['プロセスとパッケージの紐づけの限界', '../procfs-process-to-package-mapping-ja/#_9'],
      ],
    },
  },
};
