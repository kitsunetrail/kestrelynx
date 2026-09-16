// Command runtime-discovery is a measurement harness for Runtime Discovery:
// it collects procfs/Docker-API evidence about which OS packages a running
// container actually touches, then matches that evidence against a Trivy
// scan to compute how much of the reported vulnerability surface is
// confirmed in use.
//
// It has two subcommands:
//
//	runtime-discovery collect -case-variant 1 -permission root -interval 30 -window 300 -phase 0 -replicate 1 -out-dir ./out/collect
//	runtime-discovery collect -case-variant 17 -sync startup -expect case17 -config-id bpftrace-v2-nofilter-64p -out-dir ./out/collect
//	runtime-discovery match -observation container.json -trivy trivy.json -case case.json -gtb gtb.json -events events.jsonl -intel-snapshot intel.json -out-json result.json -out-csv-dir ./out/match-csv
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
// # Starting the observation before the workload
//
// A module loaded once when a program starts is loaded before an
// observation started afterwards can see it, and a collector that works
// perfectly would still report nothing. Enumerating running containers at
// startup cannot help: the container does not exist yet.
//
// So a target can be named before it exists. -expect registers it; collect
// then watches for it, reads its configuration and the layout its files
// will be matched against, and only then accepts it as an observation
// target. The three states — registered, being prepared, accepted — and
// the time of every transition are recorded on the result, and a
// readiness file is rewritten at each change so a case runner can tell
// from outside when to let the workload begin. A registered target that
// never appears is recorded as a failure of the run, which is a different
// thing from a target that was observed and showed nothing.
//
// The start-time enumeration is still there and is what the attach-running
// condition uses; the two coexist, and naming targets to wait for does not
// implicitly pull in every other running container. -sync records which
// condition a run belongs to and -config-id which event-collection
// configuration, both as part of the run key: two runs that differ in
// either are not the same condition, and adding them together would
// combine measurements of different things.
//
// # The mapping inputs
//
// Relating a file to a package needs information the sampling does not
// produce, and which cannot be recovered later because the container will
// be gone. collect saves it: every installed Python distribution's file
// manifest, the package database's full path index, the layout of the
// module trees and the search directories, the target of every symbolic
// link in them, the merged top-level directory links, and the process's
// mount table. Every read is bounded, and a bound that bites is recorded
// as a truncation, so a later lookup miss is never mistaken for a genuine
// absence.
//
// The package database's own path index is what reaches an operating-
// system package from an event: a scan report carries no path for one, so
// without the index an execution of a program such a package installed
// could never be related back to it.
//
// This reading has a generation of its own, computed from the files it
// describes rather than from the package database. The two change
// independently: a package manager for a language installs and removes
// packages without touching the operating system's database, and an image
// with no such database at all still has module trees to describe. Each
// reading records the stretch of the window it covered, and an observation
// is resolved against the reading that covered it — never against a
// different layout that happened to be saved too.
//
// Open file descriptors are recorded too, not only sockets. A runtime that
// holds an archive open for its whole life is visible that way without any
// event collection at all — and an open descriptor is weaker evidence than
// a mapping, which is weaker than an execution, so each observed path
// records which of the three produced it.
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
//	  ./runtime-discovery collect -case-variant 1 ...
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
// # Three evaluation series
//
// The same saved window is evaluated three ways, and the results are kept
// apart. The first applies the first stage's rules alone and reproduces
// what they produced. The second adds the read-only mapping: a compiled
// binary identified by its own path, an archive seen in an open
// descriptor, a compiled extension traced through an installed-file
// manifest, and an operating-system package reached through the saved path
// index. The third adds event evidence, passed with -events.
//
// Each layer's increment is reported separately, because "the confirmation
// rate went up" does not say which layer produced it and the two cost
// entirely different things to deploy. An increment that could not be
// computed — because the window collected no usable events — is reported
// as unavailable rather than as zero, which would claim the events were
// tried and added nothing.
//
// Every evidence source is independent, needs different inputs, and can
// succeed while the others fail. Each is asked only for what it needs: the
// first stage's sampling for both of the reads its own rule is defined
// over, the read-only sources for the process reads and the layout saved
// beside them, the event source for neither. So one source's missing input
// no longer makes the whole window undetermined — a window whose package
// database could not be read still has whatever the compiled binary's own
// path established.
//
// It works the other way too. A series is only carried past that rule by a
// source it actually admits: an event collection that worked says nothing
// about a series that does not use events. And a positive from a source
// whose inputs were not available is not adopted at all, whatever was
// recorded against it.
//
// One read is deliberately kept out of the first stage's own rule: a file
// merely held open. Recording open descriptors came later, and letting
// them into that rule would move the baseline the other two series are
// measured against.
//
// Relating an observed file to packages happens in two steps, and only the
// first can be ambiguous. Step one identifies the file a scan report
// names; step two spreads the evidence over every package that file
// carries. One file holding many packages is the ordinary case — a
// compiled binary carries every module built into it — and is not an
// ambiguity; several files answering to one observed path is, and is
// counted as a failure to resolve.
//
// Because of that, a positive records what it actually covers. Executing a
// compiled binary confirms the binary and nothing finer: every module
// built into it is reported and none of them is shown to have run. Rates
// are reported per ecosystem and per evidence granularity, with the number
// of distinct files the positives rest on, so a combined figure never
// stands alone.
//
// # Per-occurrence capture
//
// Two different questions are measured, and neither substitutes for the
// other. The first is what share of the reported vulnerabilities got any
// evidence at all. The second is what share of the individual things that
// happened were seen — which the first cannot answer, because catching one
// of sixty executions gives it a perfect score.
//
// The second needs the workload's own record of each occurrence, supplied
// with the ground truth, and a way to say that an event's process number
// and an occurrence's are the same process — a start time that agrees is
// not enough on its own: it is rounded to a clock tick, and two containers
// produce theirs independently. Two rules do this, and the stronger one is
// preferred whenever it can be used. Where the case runner recorded the
// correspondence between the process numbers the workload sees and the
// ones the host sees, per container and per generation, an event's number
// is translated through it and compared to the occurrence's; that number
// is unique across every container, so it settles the question whichever
// container an event was actually credited to. Where no such
// correspondence was recorded, an event's own namespace-scoped process and
// thread numbers — the numbers a workload inside a container reports for
// itself — are compared directly against the occurrence's, needing no
// table at all; but such a number is unique only within its own container,
// so this weaker rule can confirm a match only against the container an
// event was actually credited to, and cannot tell a genuine misattribution
// to another container from a coincidental number collision between two
// containers' own, independent numbering. A pairing that cannot be decided
// by either rule is counted as undecidable — neither a capture nor a miss,
// because nothing there could have told one process from another.
// Executions pair one to one: a successful
// execution produces exactly one event, so anything that does not pair
// that way is counted as unpairable rather than as a capture. Loads match
// against a set of events instead, since one load can read several files —
// requiring the counts to agree would give a perfect collector a rate of
// zero — and an event that could belong to more than one load is used for
// none of them. A load satisfied from memory reads nothing and is excluded
// from the denominator, which is why the workload has to record whether it
// read anything; a case that cannot tell the two apart must not be
// measured. The system-call level rate is computed only where something
// recorded the calls independently, and is otherwise reported as
// unavailable rather than replaced by the coarser rate.
//
// Attribution is reported in both directions, over the one set the
// independent log can speak about: successful events, inside the window,
// credited to a container the log covers. A collector that discarded every
// event would attribute nothing wrongly, so the share of wrong
// attributions cannot on its own show that attribution works — and
// unrelated activity is kept out of the denominator, or attribution would
// look better the more else happened to be running.
//
// Ground truth and events are separate inputs and each reader refuses the
// other's format outright. They look alike, and ground truth built from
// the observation it is meant to judge makes every capture rate and every
// false-positive count meaningless.
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
//   - Case 9's dependency-library open timestamps are when the loader's
//     trace line was consumed from the FIFO, which trails the actual load
//     by the pipe's latency; and its period is the command's own runtime
//     plus five seconds, not exactly five. Record the real period alongside
//     the phase base.
//   - Case 8's preflight passes on finding any deleted mapping. Confirm
//     each of its three targets separately — the unlinked executable, the
//     unlinked library and the replaced library — by PID, path, inode and
//     whether the load actually succeeded, since the parent records the
//     dlopen as successful without hearing back from the child.
//
// This program is a standalone experiment: it is not part of the
// kestrelynx binary, imports no third-party dependencies, and its output
// (default ./out/) is never committed.
package main
