// Command runtime-discovery is a measurement harness for Runtime Discovery:
// it collects procfs/Docker-API evidence about which OS packages a running
// container actually touches, then matches that evidence against a Trivy
// scan to compute how much of the reported vulnerability surface is
// confirmed in use.
//
// It has two subcommands:
//
//	runtime-discovery collect -case-variant R1 -permission root -interval 30 -window 300 -phase 0 -replicate 1 -out-dir ./out/collect
//	runtime-discovery match -observation container.json -trivy trivy.json -case case.json -gtb gtb.json -intel-snapshot intel.json -out-json result.json -out-csv-dir ./out/match-csv
//
// # collect
//
// collect samples every running container (or a chosen subset) over a fixed
// window at a fixed interval, writing one record file per container, named
// after the container and the run_key so two conditions of the same case
// never overwrite each other. Each record identifies the run by its run_key
// (case variant, permission condition, interval, window, phase offset,
// replicate — permission and replicate are always given on the command
// line, never inferred) and carries: the container's identity and
// Docker-reported configuration (NetworkMode, port bindings and their
// actual publication, attached networks); the sampling window's schedule
// and actual timing per sample; each sampled process generation's (pid +
// starttime) namespace identity; executable path, file-backed memory
// mappings, effective UID and capabilities; each observed path's ownership
// resolution against the container's own package database (dpkg, dpkg's
// distroless status.d variant, or apk — whichever is found first by
// metadata presence) and the independent maps_deleted/path_inode_changed
// flags; the full package ledger for every database generation that was
// read, so an unobserved package's file-list status can be recovered later
// even though it was never referenced by any observed path; the package
// database's own on-disk state and the dev/inode calibration that decides
// whether path_inode_changed may be trusted at all; listening sockets
// attributed to every process generation holding them; each sample's
// proc_observe/pkgdb_read outcome, which database generation each mount
// view resolved to for that sample, and the derived validity; the 3-tier
// load measurement (initial database read, the collector's own cgroup, and
// dockerd's cgroup); and every step failure. Every failure is recorded
// rather than retried or guessed at.
//
// Two integrity checks run on every sample rather than once. Each PID's
// starttime and namespace identity are read before and after that sample's
// procfs reads, and the container's StartedAt is re-checked, so a process
// that was replaced (or a container that restarted) while it was being read
// is recorded as an unusable sample instead of a mixture of two
// generations; a generation that simply replaced an earlier one between
// samples is not an error, only a different generation. And the package
// database's generation — for dpkg, the status file's content together with
// the size and mtime of every info/*.list, since a file list can change
// while status does not — is re-established each sample, so an index built
// from an earlier generation is rebuilt rather than reused, and an absent
// database is re-checked rather than remembered.
//
// # Measuring load
//
// The steady-state tier reads cpu.stat and memory.peak from a cgroup v2
// directory before and after the sampling loop. By default that is
// whichever cgroup collect itself landed in, read from /proc/self/cgroup —
// which is the collector's own cost only if the collector was started in a
// cgroup of its own. Started from an ordinary shell it shares a cgroup with
// that shell and everything else in the session, and memory.peak is in any
// case that cgroup's high-water mark over its whole lifetime, not over this
// run. Give collect a cgroup of its own:
//
//	sudo systemd-run --scope --unit=runtime-discovery-collect \
//	  -p MemoryAccounting=yes -p CPUAccounting=yes \
//	  ./runtime-discovery collect -case-variant R1 ...
//
// and pass -cgroup-path /sys/fs/cgroup/system.slice/runtime-discovery-collect.scope
// if the path collect derives for itself is not the one to measure. On a
// host without systemd, create and enter the cgroup by hand (mkdir under
// the cgroup v2 mount, write the collector's PID into cgroup.procs) and
// pass that directory. -docker-cgroup-path does the same for the daemon
// tier, whose default assumes docker.service under system.slice; the
// daemon's cgroup is measured because the ps processes docker top starts
// run inside it, so dockerd's own process statistics would miss them.
//
// A tier that cannot be measured records why, per reading: cpu.stat and
// memory.peak fail independently, and neither is ever reported as a zero
// value standing in for a file that was not read.
//
// # match
//
// match takes one such container record together with a Trivy JSON report,
// a case definition (GT-A: the pre-declared expected usage and expected
// verdict — two separate claims — plus gt_b_scope for that case), and
// optionally a ground-truth-B record (the case's own common-format usage
// log, or a limited resident-process spot check for an official image), and
// computes: per-Finding usage verdicts
// (confirmed/unresolved/unobserved/not_determined) via the fixed
// observation-state-then-verdict decision table, derived from observation
// rather than from the case definition wherever observation can determine
// it; unconditional and conditional confirmation rates, by Class and by
// triage priority; per-path ownership (collect's) and trivy_match (match's)
// results, counted in distinct paths; an Exposure verdict decided from all
// listener candidates by stage priority; the E1-E4/unclassified
// confirmation-gap breakdown, where an unrecoverable gap must be both
// declared by the case and borne out by the observation; the G4
// baseline-vs-adjusted ranking comparison, whose usage, exposure and
// privilege evidence is only ever combined within one process generation in
// one sample; and, when GT-B is available, true/false positive/negative
// counts with their FPR/FNR point estimates and upper/lower bounds. match's
// output also includes the common Evidence record list (usage/exposure/
// privilege) alongside its richer native result, each record stamped with
// the time its sample was actually taken.
//
// match reads no rootfs and makes no call depending on any live container.
// Reproducing a result also requires pinning the vulnerability
// intelligence: pass -intel-snapshot with the "intel" object of an earlier
// result (or write one with -out-intel-snapshot) and no KEV/EPSS lookup is
// performed at all, so the same saved inputs give the same classification
// however the feeds have moved since. Without it, match looks the feeds up
// through the product's own intel source and records when each was
// fetched — correct for a live run, not reproducible.
//
// # Limitations to confirm on real hardware
//
// Each of these is a known boundary of what the harness measures, to be
// checked against a real host rather than assumed away:
//
//   - A database generation is not a content hash of the whole database.
//     dpkg's info/*.list and distroless's status.d entries are
//     fingerprinted by size and mtime, so a rewrite preserving both, or an
//     update landing while the index is being built, would not be
//     detected. These runs hold the database fixed.
//   - The initial database read timing is not a cold-cache figure. A
//     generation check has already read the metadata by then, the byte and
//     file counts are logical database size rather than physical I/O, and
//     the page cache is warm. Treat it as the cost of parsing a database,
//     not of fetching one from disk.
//   - R9's dependency-library open timestamps are when the loader's trace
//     line was consumed from the FIFO, which trails the actual load by the
//     pipe's latency; and its period is the command's own runtime plus
//     five seconds, not exactly five. Record the real period alongside the
//     phase base.
//   - R8's preflight passes on finding any deleted mapping. Confirm each of
//     its three targets separately — the unlinked executable, the unlinked
//     library and the replaced library — by PID, path, inode and whether
//     the load actually succeeded, since the parent records the dlopen as
//     successful without hearing back from the child.
//
// This program is a standalone experiment: it is not part of the
// kestrelynx binary, imports no third-party dependencies, and its output
// (default ./out/) is never committed.
package main
