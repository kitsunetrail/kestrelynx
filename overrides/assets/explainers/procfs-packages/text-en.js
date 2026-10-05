window.KLX_TEXT = {
  ui: {
    play: 'Play',
    pause: 'Pause',
    prev: 'Previous',
    next: 'Next',
    reset: 'Restart',
    counter: 'Step {i} of {n}',
    back: 'In the source article:',
    backSep: ' · ',
  },
  cols: {
    proc: 'Processes as seen from the host',
    maps: 'Loaded files (maps)',
    dpkg: 'dpkg records inside the container',
    match: 'Matching against Trivy findings',
  },
  legend: {
    pid: 'PID',
    path: 'Path',
    pkg: 'Package name',
    ver: 'Version',
  },
  proc: {
    master: 'Master',
    worker: 'Worker',
    followed: 'Worker followed in this diagram',
    moreWorkers: '… 14 workers in total (listing excerpt)',
    hostPid: 'The first column contains host PIDs, used to read `/proc/<pid>`. The collector inspects every PID using the same steps.',
    followedLabel: 'PID being followed:',
    starttime: '`starttime`, field 22 of `/proc/2479938/stat`',
    startedAt: 'Docker `State.StartedAt`',
    before: 'Before collection',
    after: 'After collection',
    same: 'Both values are unchanged across collection, so this sample is accepted.',
  },
  maps: {
    waiting: 'Next, the collector reads this worker’s `maps`.',
    excerpt: 'Excerpt: address ranges and offset columns omitted',
    rule: 'Keep rows whose permissions contain `x`, path starts with `/`, and inode is nonzero.',
    kept: 'Retained files (8)',
  },
  dpkg: {
    waiting: 'After extracting the file paths, the collector reads the dpkg records inside the container.',
    where: 'Where the records are read',
    rootNote: 'The collector reads the container’s `/var/lib/dpkg` through this process’s `root`. The host’s `/var/lib/dpkg` describes packages on the host.',
    listTitle: '`info/libssl3:amd64.list` (excerpt)',
    indexTitle: 'Built index (path → package)',
    indexMore: '… Excerpt of the index built from every package’s `.list`',
    statusTitle: 'The `libssl3` paragraph in `status` (excerpt)',
  },
  match: {
    waiting: 'After identifying ownership and version and accepting the sample, the collector matches them against Trivy findings.',
    trivyTitle: 'Trivy findings (1 of 32 for libssl3)',
    observed: 'Observed package name and version',
    result: 'Both the package name and version match.',
    recordTitle: 'Recorded confirmation of loading',
  },
  steps: {
    1: {
      title: 'docker top identifies the host PIDs of the master and workers',
      body: [
        ['`docker top nginx -eo pid,ppid` lists the host PIDs of the master (PID 2479853) and 14 workers in the `nginx` container.', [
          'The collector inspects every PID in the listing using the same steps.',
        ]],
        'This diagram follows worker PID 2479938 and uses that PID to read `/proc/2479938` on the host.',
      ],
      back: [
        ["Finding a container's host PIDs", '../procfs-process-to-package-mapping/#finding-a-containers-host-pids'],
      ],
    },
    2: {
      title: 'Filtering maps extracts the paths of executable file mappings',
      body: [
        '`/proc/2479938/maps` contains `r--p`, `r-xp`, and `rw-p` rows for the same `libssl.so.3` file.',
        ['The collector keeps only rows whose permissions contain `x`, path starts with `/`, and inode is nonzero.', [
          'This excludes `[heap]` and anonymous mappings, leaving eight files for this worker, including `nginx` and `libssl.so.3`.',
        ]],
      ],
      back: [
        ['Executable and mapped libraries', '../procfs-process-to-package-mapping/#executable-and-mapped-libraries'],
      ],
    },
    3: {
      title: 'The process root provides access to the container’s dpkg records',
      body: [
        'Paths in `maps` refer to files inside the container.',
        'To identify their owners, the collector reads the container’s `/var/lib/dpkg` through `/proc/2479938/root`.',
      ],
      back: [
        ['Resolving paths inside the container', '../procfs-process-to-package-mapping/#resolving-paths-inside-the-container'],
      ],
    },
    4: {
      title: 'An index built from file lists identifies the package owning each path',
      body: [
        'dpkg stores each package’s file list in `info/<package>.list`.',
        ['The collector builds a **path → package** index from all of these lists, then looks up the paths retained from `maps`.', [
          'Both `libssl.so.3` and `libcrypto.so.3` appear in `libssl3:amd64.list`, identifying `libssl3` as their owner.',
        ]],
      ],
      back: [
        ['Debian and Ubuntu: dpkg', '../procfs-process-to-package-mapping/#debian-and-ubuntu-dpkg'],
      ],
    },
    5: {
      title: 'The status record supplies the installed version of libssl3',
      body: [
        'The `.list` file contains only paths, so the collector reads the version from the `libssl3` paragraph in `/var/lib/dpkg/status`.',
        '`Package` is `libssl3`, and `Architecture` is `amd64`.',
        '`Status: install ok installed` indicates that the package is installed.',
        'The `Version` used for matching is `3.0.16-1~deb12u1`.',
      ],
      back: [
        ['Debian and Ubuntu: dpkg', '../procfs-process-to-package-mapping/#debian-and-ubuntu-dpkg'],
      ],
    },
    6: {
      title: 'Comparing start times before and after collection validates the sample',
      body: [
        'PIDs can be reused, so the collector compares `starttime`, field 22 of `/proc/2479938/stat`, before and after collection.',
        'It also compares Docker’s `State.StartedAt` to check for a container restart.',
        'In this example, `starttime` is `15146823` both times and `State.StartedAt` is unchanged, so the sample is accepted.',
      ],
      back: [
        ['Namespace identity and PID reuse', '../procfs-process-to-package-mapping/#namespace-identity-and-pid-reuse'],
      ],
    },
    7: {
      title: 'The observed package name and version are matched against Trivy findings',
      body: [
        ['The collector compares the observed package name and version with Trivy’s `PkgName` and `InstalledVersion`, respectively.', [
          'Both the package name, `libssl3`, and the version, `3.0.16-1~deb12u1`, match.',
        ]],
        ['Trivy reported 32 vulnerabilities for this package.', [
          'The diagram shows one finding, `CVE-2025-15467`, with severity `HIGH` and `FixedVersion` set to `3.0.18-1~deb12u2`.',
        ]],
      ],
      back: [
        ['Putting it together', '../procfs-process-to-package-mapping/#putting-it-together'],
      ],
    },
    8: {
      title: 'Valid observations are recorded as confirmation that package files were loaded',
      body: [
        'All 10 samples collected at 30-second intervals over five minutes were valid.',
        'The observed `libssl.so.3` and `libcrypto.so.3` files were linked to the package name and version in the findings, so `libssl3` was recorded as **confirmed loaded** (`verdict: confirmed`).',
        ['This confirms file loading but does not establish whether a vulnerable function executed.', [
          'The source article explains the method’s limits.',
        ]],
      ],
      back: [
        ['Putting it together', '../procfs-process-to-package-mapping/#putting-it-together'],
        ['Limits of process-to-package mapping', '../procfs-process-to-package-mapping/#limits-of-process-to-package-mapping'],
      ],
    },
  },
};
