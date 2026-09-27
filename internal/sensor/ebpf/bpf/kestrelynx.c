// Sensor CO-RE programs: the event set for observing process execution and
// executable-mapping activity from outside the container.
//
// Five attach points, each emitting a fixed-size struct kl_event into one
// ring buffer:
//
//   - tp_btf/sched_process_exec  (exec has committed: usage evidence)
//   - fentry/security_file_open  (every open; gives a path to the dev/inode
//     pairs the two success points above only carry numerically, and on its
//     own additionally reports whether the file was opened for execution)
//   - fexit/do_mmap               (mapping has committed: usage evidence)
//   - fentry/security_mmap_file  (an executable mapping is being attempted,
//     before do_mmap runs; kept separate from the mapping-success evidence
//     above, since it fires before success is known and bpf_d_path cannot
//     be called from it)
//   - tp_btf/cgroup_mkdir         (cgroup ID <-> path, for container mapping)
//
// A single self-exclusion map lets the loader hide the Sensor's own cgroup
// from every attach point before any program runs.
//
// Deduplication uses three purpose-specific LRU-backed suppression windows,
// not one shared key, matching the three things a consumer actually asks
// this event stream for:
//
//   - kl_dedup_usage, keyed (cgroup, mount namespace, dev, inode, kind, and
//     a coarse privilege class — see kl_fill_privilege_class), for the two
//     success events (exec, mmap) that are usage evidence: the same file
//     used again from the same cgroup and mount namespace, at the same
//     coarse privilege, within the window is suppressed; a later occurrence
//     at a different privilege class is not, so a one-time higher-privilege
//     use of an already-suppressed file is still reported.
//   - kl_dedup_path, keyed (mount namespace, root identity, dev, inode) only
//     — no cgroup, no kind — for the two path-resolution events (exec-open,
//     file-open): a path is a fact about (mount namespace, root identity,
//     dev, inode) alone (see the per-program comments below on why this can
//     cross processes and cgroups, and on why root identity is part of it,
//     not just mount namespace), so an exec-open and a file-open for the
//     same file, opened from the same root, share one suppression window
//     rather than two.
//   - kl_dedup_attempt, keyed (cgroup, dev, inode), for the mmap-attempt
//     event, which is neither usage evidence nor a path record — kept
//     separate so a hot mmap-attempt loop cannot consume the same budget as
//     path resolution or usage evidence.
//
// kl_dedup_usage's own key deliberately excludes tgid and the process's own
// start time, even though both are available: a process's tgid+start time
// is unique to it by construction, so including them would make every
// single exec produce its own always-distinct key, defeating this key's
// whole point of surviving a hot loop of many short-lived processes
// touching the same small set of files. The Go side's own same-sample/
// same-process exposure/privilege aggregation (sensor.
// mergeProcessObservation, capped per entity) is a separate, later
// concern — it does not affect which events reach it in the first place.
//
// Every one of these three maps exists only to keep a hot loop (e.g. a
// tight read()/write() cycle touching the same file) from flooding the ring
// buffer, not to model who is doing the reading. Once a tuple has been
// sent, any other process within the same key's scope touching the same
// file within the suppression window is suppressed too, even under a
// different PID, a different set of credentials, or a different capability
// set than the one that was actually reported. A consumer that needs every
// distinct process or privilege combination that touched a file cannot rely
// on seeing one event per occurrence from these maps alone.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// __FMODE_EXEC is the uapi-stable flag (include/uapi/linux/fs.h) the kernel
// ORs into file->f_flags when it opens a file for execution (do_open_execat
// in fs/exec.c). It is not part of any kernel BTF type, so it has to be a
// literal here rather than a vmlinux.h reference.
#define KL_FMODE_EXEC 0x20

// PROT_EXEC (include/uapi/asm-generic/mman-common.h), likewise a uapi
// constant rather than a BTF-visible type.
#define KL_PROT_EXEC 0x4

// A do_mmap return value in this range is an encoded negative errno
// (include/linux/err.h's IS_ERR_VALUE), not a mapped address.
#define KL_IS_ERR_VALUE(x) ((unsigned long)(x) >= (unsigned long)-4095)

#define KL_PATH_MAX 256

// KL_INIT_USER_NS_INUM is the initial user namespace's own nsfs inode
// number. Every "initial" namespace (user, mount, pid, net, …) is allocated
// a fixed inode number once, at boot, before any container or unshare(2)
// can run (kernel/user_namespace.c's init_user_ns, backed by nsfs); this
// specific value (4026531837) is the same one widely relied on elsewhere
// (e.g. container-detection tools comparing /proc/1/ns/* inode numbers
// against their own well-known initial values) and is stable across every
// Linux version this Sensor targets. Used only to compute a coarse "is this
// the host's own initial user namespace" bit for kl_usage_key below.
#define KL_INIT_USER_NS_INUM 4026531837U

// Event kinds. Kept as plain byte constants (rather than a BTF enum) so the
// Go side's hand-written mirror in events.go has one obviously-correct
// source to stay in sync with, checked by a round-trip test.
#define KL_EVENT_EXEC_SUCCESS 1
#define KL_EVENT_EXEC_OPEN 2
#define KL_EVENT_MMAP_SUCCESS 3
#define KL_EVENT_FILE_OPEN 4
#define KL_EVENT_CGROUP_MKDIR 5
#define KL_EVENT_MMAP_OPEN 6

// kl_event is the one wire record every attach point emits into the ring
// buffer. Not every field is meaningful for every kind (e.g. path is empty
// for the two success events, whose path comes from a separate file_open
// record instead); unused fields are left zeroed. A single fixed shape
// keeps the ring buffer layout and the generated Go decode type identical
// for all five programs instead of five separate wire formats.
struct kl_event {
	__u64 cgroup_id;
	__u64 mnt_ns_id;
	__u64 user_ns_id;
	__u64 tgid;
	__u64 start_boottime_ns;
	__u64 cap_effective;
	__u64 dev;
	__u64 ino;
	// root_dev/root_ino are the calling task's own fs->root identity (see
	// kl_current_root_identity) at the moment a success event fires — set
	// only by kl_exec_success/kl_mmap_success, zero everywhere else. A mount
	// namespace alone does not tell chroot(2) apart from init's own view of
	// the same namespace; this pair does, the same way dev/ino already tell
	// one file apart from another.
	__u64 root_dev;
	__u64 root_ino;
	__u64 ktime_ns;
	__u32 euid;
	__u32 prot;
	__u8 kind;
	__u8 path_truncated;
	__u16 path_len;
	unsigned char path[KL_PATH_MAX];
};

// Every use of struct kl_event below is through a pointer returned by
// bpf_ringbuf_reserve, so the compiler never emits BTF for the type on its
// own; this unused global forces that emission, which bpf2go's -type flag
// needs to generate the matching Go decode struct.
struct kl_event *unused_kl_event __attribute__((unused));

// kl_usage_key identifies "the same usage observation" for kl_dedup_usage:
// same cgroup, same mount namespace, same file, same kind of success event,
// and the same coarse privilege class (euid_is_root, in_init_userns,
// cap_effective — see kl_fill_privilege_class). tgid and the process's own
// start time are deliberately not part of this key: including them would
// make every single exec produce its own always-distinct key (a process's
// tgid+start time is unique to it by construction), defeating this key's
// whole point of surviving a hot loop of many short-lived processes
// touching the same small set of files. Privilege fields are included
// instead so that the one case that actually matters for a priority
// judgement — the same file later used by a differently-privileged process
// — still produces a new key and is not suppressed by an earlier, less
// privileged occurrence's own still-live suppression window.
struct kl_usage_key {
	__u64 cgroup_id;
	__u64 dev;
	__u64 ino;
	__u64 cap_effective;
	__u32 mnt_ns_id;
	__u8 kind;
	__u8 euid_is_root;
	__u8 in_init_userns;
};

// kl_path_key identifies "the same path resolution" for kl_dedup_path: a
// fact about (mount namespace, dev, inode) alone, deliberately without a
// cgroup or a kind field — see this file's header comment on why an
// exec-open and a file-open for the same file in the same mount namespace
// share one suppression window.
// root_dev/root_ino are part of this key, not just mnt_ns_id, because a path
// bpf_d_path renders is a fact about the *caller's own root* at open time,
// not just its mount namespace: two tasks in the same mount namespace can
// still see different roots via chroot(2), and each would get a different
// path string for the exact same (dev, ino) — see kl_file_open's own doc
// comment for the concrete misattribution this closes.
struct kl_path_key {
	__u32 mnt_ns_id;
	__u64 root_dev;
	__u64 root_ino;
	__u64 dev;
	__u64 ino;
};

// kl_attempt_key identifies "the same mmap attempt" for kl_dedup_attempt:
// same cgroup, same file. No mount-namespace or kind field: this map only
// ever holds KL_EVENT_MMAP_OPEN entries, and an attempt (unlike a usage
// event) has no cross-process path-sharing rationale to key on mount
// namespace instead of cgroup.
struct kl_attempt_key {
	__u64 cgroup_id;
	__u64 dev;
	__u64 ino;
};

// 10 minutes in nanoseconds: how long a (cgroup, dev, inode, kind) tuple
// stays suppressed after being sent. Long enough to keep a hot loop (e.g. a
// tight read()/write() cycle touching the same file) from flooding the ring
// buffer, short enough that a real re-occurrence is not silenced for an
// unreasonable stretch.
#define KL_DEDUP_WINDOW_NS (10ULL * 60 * 1000000000ULL)

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	// 2 MiB (512 pages): a starting size, to be revisited once real drop
	// counts are measured under load.
	__uint(max_entries, 1 << 21);
} kl_events SEC(".maps");

// Single-slot map holding the Sensor's own cgroup ID. 0 means "not set yet"
// (cgroup ID 0 is never a real leaf cgroup), so every attach point is a
// no-op until the loader writes this before attaching anything.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 1);
} kl_excluded_cgroup SEC(".maps");

// Single-slot map holding the real host's own (PID 1's) mount namespace
// inode number, written by the loader before any program attaches (see
// kl_excluded_cgroup's own doc comment for the same "0 means not set yet"
// convention — a mount namespace inode is never 0). Checked by
// kl_file_open specifically (by far this Sensor's own highest-volume hook:
// every open, not just an exec) to drop a host-side process's own file
// opens before doing any further work at all, not merely before submitting
// to the ring buffer: a real Docker container's own workload always execs
// inside a mount namespace unshared away from the host's at container
// creation (docker-compose.sensor.yml's own pid: host shares only the PID
// namespace, never the mount one), so an open reporting the host's own
// mount namespace can never be a container's own usage evidence regardless
// of which cgroup it happens to carry — see internal/sensor's own
// resolveEventGeneration, which already discards exactly this same
// condition userspace-side; this is the same rule enforced earlier, in the
// kernel, for the hook it costs the most to leave unfiltered.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 1);
} kl_host_mnt_ns SEC(".maps");

// kl_pid_ns holds the inode number of the Sensor's own PID namespace,
// written once by the loader before attaching. The Sensor reads /proc/<pid>
// for these same processes, so a tgid must be the PID that namespace
// assigns, not the one the kernel's initial PID namespace does. The two
// differ whenever the Docker host itself runs inside a PID namespace (WSL2,
// or Docker inside a nested namespace). Zero means "not configured" and
// falls back to the initial namespace's tgid.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 1);
} kl_pid_ns SEC(".maps");

// Fallback count of events dropped because bpf_ringbuf_reserve failed, for
// exactly the two cases that cannot be attributed to one cgroup's own
// counter below: the cgroup ID itself could not be determined (never
// expected on a cgroup2 host, but checked defensively), or the per-cgroup
// hash map insert itself failed (that map's own max_entries reached). Every
// other loss is counted in kl_lost_by_cgroup instead; a reader needs to sum
// both to get the Sensor-wide total.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 1);
} kl_lost_events SEC(".maps");

// Per-cgroup count of events dropped because bpf_ringbuf_reserve failed —
// what lets a reader mark only the generations that actually lost events
// "partial" instead of every generation whenever the ring buffer is briefly
// oversubscribed by one noisy container. Sized well above any realistic
// number of concurrently-observed cgroups; an insert that still does not
// fit falls back to kl_lost_events instead of being silently lost.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64); // cgroup_id
	__type(value, __u64);
	__uint(max_entries, 4096);
} kl_lost_by_cgroup SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct kl_usage_key);
	__type(value, __u64);
	__uint(max_entries, 8192);
} kl_dedup_usage SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct kl_path_key);
	__type(value, __u64);
	__uint(max_entries, 8192);
} kl_dedup_path SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct kl_attempt_key);
	__type(value, __u64);
	__uint(max_entries, 8192);
} kl_dedup_attempt SEC(".maps");

// A small hash map no attach point in this file ever reads or writes: it
// exists only so the deployment-verification tool (kestrelynx sensor
// --probe) has a map to exercise lookup/update/delete/next-key against
// once capabilities are dropped, without perturbing kl_lost_events/
// kl_lost_by_cgroup (live counters) or the three dedup maps above (whose
// contents an in-progress attach point may be relying on for suppression).
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 8);
} kl_selftest SEC(".maps");

static __always_inline bool kl_is_excluded(__u64 cgroup_id)
{
	__u32 zero = 0;
	__u64 *excluded = bpf_map_lookup_elem(&kl_excluded_cgroup, &zero);

	return excluded && *excluded != 0 && *excluded == cgroup_id;
}

// kl_is_host_mnt_ns reports whether mnt_ns_id is the real host's own mount
// namespace, per kl_host_mnt_ns's own doc comment. Returns false (never
// filters anything) if the loader has not written a nonzero value yet —
// the same fail-open convention kl_is_excluded already uses for
// kl_excluded_cgroup.
static __always_inline bool kl_is_host_mnt_ns(__u32 mnt_ns_id)
{
	__u32 zero = 0;
	__u64 *host_mnt_ns = bpf_map_lookup_elem(&kl_host_mnt_ns, &zero);

	return host_mnt_ns && *host_mnt_ns != 0 && *host_mnt_ns == (__u64)mnt_ns_id;
}

static __always_inline void kl_count_lost_fallback(void)
{
	__u32 zero = 0;
	__u64 *counter = bpf_map_lookup_elem(&kl_lost_events, &zero);

	if (counter)
		__sync_fetch_and_add(counter, 1);
}

// kl_count_lost attributes one lost event to cgroup_id's own counter,
// initializing it on first loss for that cgroup. Two CPUs both missing the
// lookup at once and both initializing to 1 (instead of one of them
// observing the other's insert and adding to it) is a possible, deliberately
// accepted race: this counter only needs to be an approximately-right
// signal for whether the ring buffer is keeping up with one cgroup's own
// load, not an exact count. cgroup_id 0 (never expected on a cgroup2 host,
// where every task has a real cgroup) and a full kl_lost_by_cgroup map both
// fall back to the Sensor-wide counter instead of being silently dropped.
static __always_inline void kl_count_lost(__u64 cgroup_id)
{
	if (!cgroup_id) {
		kl_count_lost_fallback();
		return;
	}

	__u64 *counter = bpf_map_lookup_elem(&kl_lost_by_cgroup, &cgroup_id);

	if (counter) {
		__sync_fetch_and_add(counter, 1);
		return;
	}

	// BPF_NOEXIST, not BPF_ANY: two CPUs racing this same first-loss path
	// for the same cgroup must not both blindly write a bare "1" — if the
	// second one used BPF_ANY, it would silently overwrite whatever the
	// first one already committed, losing that increment outright, rather
	// than adding to it. BPF_NOEXIST makes the loser of the race fail
	// instead, so it can fall through to the lookup+atomic-add path below
	// and add its own increment on top of the winner's "1" instead of
	// erasing it.
	__u64 one = 1;

	if (bpf_map_update_elem(&kl_lost_by_cgroup, &cgroup_id, &one, BPF_NOEXIST) == 0)
		return;

	counter = bpf_map_lookup_elem(&kl_lost_by_cgroup, &cgroup_id);
	if (counter) {
		__sync_fetch_and_add(counter, 1);
		return;
	}

	// The hash map itself is full (max_entries reached): this loss
	// cannot be attributed to any one cgroup's own counter.
	kl_count_lost_fallback();
}

// kl_usage_seen/kl_usage_mark, kl_path_seen/kl_path_mark and
// kl_attempt_seen/kl_attempt_mark each report whether their own key was
// registered within the suppression window, and register it. Each *_seen
// must be called before attempting to reserve ring buffer space; each
// *_mark must only be called after a successful bpf_ringbuf_submit, so a
// reservation failure leaves the key unregistered and the next occurrence
// tries again — never registered on the strength of an attempt alone.
static __always_inline bool kl_usage_seen(struct kl_usage_key *key, __u64 now_ns)
{
	__u64 *last = bpf_map_lookup_elem(&kl_dedup_usage, key);

	return last && now_ns - *last < KL_DEDUP_WINDOW_NS;
}

static __always_inline void kl_usage_mark(struct kl_usage_key *key, __u64 now_ns)
{
	bpf_map_update_elem(&kl_dedup_usage, key, &now_ns, BPF_ANY);
}

static __always_inline bool kl_path_seen(struct kl_path_key *key, __u64 now_ns)
{
	__u64 *last = bpf_map_lookup_elem(&kl_dedup_path, key);

	return last && now_ns - *last < KL_DEDUP_WINDOW_NS;
}

static __always_inline void kl_path_mark(struct kl_path_key *key, __u64 now_ns)
{
	bpf_map_update_elem(&kl_dedup_path, key, &now_ns, BPF_ANY);
}

static __always_inline bool kl_attempt_seen(struct kl_attempt_key *key, __u64 now_ns)
{
	__u64 *last = bpf_map_lookup_elem(&kl_dedup_attempt, key);

	return last && now_ns - *last < KL_DEDUP_WINDOW_NS;
}

static __always_inline void kl_attempt_mark(struct kl_attempt_key *key, __u64 now_ns)
{
	bpf_map_update_elem(&kl_dedup_attempt, key, &now_ns, BPF_ANY);
}

// kl_file_identity reads a file's (dev, inode) pair via its cached f_inode,
// avoiding a separate walk through f_path.dentry. Returns 0 on success.
static __always_inline int kl_file_identity(struct file *file, __u64 *dev, __u64 *ino)
{
	struct inode *inode = BPF_CORE_READ(file, f_inode);

	if (!inode)
		return -1;

	*ino = BPF_CORE_READ(inode, i_ino);
	*dev = BPF_CORE_READ(inode, i_sb, s_dev);
	return 0;
}

// kl_current_mnt_ns_id and kl_current_user_ns_id read the calling task's
// mount and user namespace inode numbers via bpf_probe_read_kernel (through
// BPF_CORE_READ) rather than direct pointer chasing, so they stay safe
// regardless of whether the intermediate fields are RCU-protected on a given
// kernel; portability here matters more than the extra instructions.
static __always_inline __u32 kl_current_mnt_ns_id(struct task_struct *task)
{
	struct mnt_namespace *mnt_ns = BPF_CORE_READ(task, nsproxy, mnt_ns);

	return mnt_ns ? BPF_CORE_READ(mnt_ns, ns.inum) : 0;
}

static __always_inline __u32 kl_current_user_ns_id(const struct cred *cred)
{
	struct user_namespace *user_ns = BPF_CORE_READ(cred, user_ns);

	return user_ns ? BPF_CORE_READ(user_ns, ns.inum) : 0;
}

// kl_current_root_identity reads the calling task's own fs->root — the
// dentry's inode number and that inode's own superblock device — into *dev
// and *ino. This is narrower than the task's mount namespace: chroot(2)
// replaces fs->root without touching the mount namespace at all, so a task
// chrooted within init's own mount namespace still passes
// kl_current_mnt_ns_id's own check while actually seeing a different root.
// Returns 0 on success, -1 if fs or its root dentry/inode could not be read
// at all (never expected for a live task, but not assumed).
static __always_inline int kl_current_root_identity(struct task_struct *task, __u64 *dev, __u64 *ino)
{
	struct inode *inode = BPF_CORE_READ(task, fs, root.dentry, d_inode);

	if (!inode)
		return -1;

	*ino = BPF_CORE_READ(inode, i_ino);
	*dev = BPF_CORE_READ(inode, i_sb, s_dev);
	return 0;
}

// kl_task_start_boottime reads task's own group leader's start_boottime,
// never the calling task's own — /proc/<tgid>/stat's own starttime column
// (fs/proc/array.c) always reports the group leader's start_boottime for
// every thread in the process, not each thread's individual one, so an
// event's own start_boottime must match that same task for a later
// /proc/<tgid>/stat-based comparison (see resolveMapsPath on the Go side) to
// ever agree with it, regardless of which thread in a multi-threaded
// process actually triggered this event. Falls back to task's own
// start_boottime if the group leader itself could not be read at all (never
// expected: every task, including the leader itself, has a group_leader).
// KL_MAX_PID_NS_DEPTH bounds how many PID namespace levels kl_current_tgid
// inspects. A container's process sits one level below the Docker host's
// namespace, and the host itself is rarely more than a level or two deep.
#define KL_MAX_PID_NS_DEPTH 8

// kl_current_tgid returns the calling task's tgid as seen from kl_pid_ns's
// PID namespace, read from the group leader's struct pid: each level of
// pid->numbers[] pairs a PID with the namespace that assigned it, from the
// initial namespace (level 0) down to the task's own. It returns 0 when no
// inspected level belongs to that namespace (the task is outside the
// Sensor's view), which userspace treats as "no process to prove anything
// against". bpf_get_ns_current_pid_tgid does not fit here: it only answers
// when the namespace is the task's own innermost one, never an ancestor.
static __always_inline __u32 kl_current_tgid(void)
{
	__u32 zero = 0;
	__u64 *want = bpf_map_lookup_elem(&kl_pid_ns, &zero);

	if (!want || !*want)
		return bpf_get_current_pid_tgid() >> 32;

	struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
	struct pid *pid = BPF_CORE_READ(task, group_leader, thread_pid);

	if (!pid)
		return 0;

	unsigned int level = BPF_CORE_READ(pid, level);

	for (int i = 0; i < KL_MAX_PID_NS_DEPTH; i++) {
		if ((unsigned int)i > level)
			break;

		struct upid up = {};

		if (bpf_core_read(&up, sizeof(up), &pid->numbers[i]))
			return 0;
		if (!up.ns)
			return 0;
		if ((__u64)BPF_CORE_READ(up.ns, ns.inum) == *want)
			return (__u32)up.nr;
	}
	return 0;
}

static __always_inline __u64 kl_task_start_boottime(struct task_struct *task)
{
	struct task_struct *leader = BPF_CORE_READ(task, group_leader);

	if (!leader)
		return BPF_CORE_READ(task, start_boottime);
	return BPF_CORE_READ(leader, start_boottime);
}

// kl_fill_privilege_class fills in kl_usage_key's three coarse privilege
// fields from a task's already-read credentials. Deliberately coarse (a
// root/non-root bit and an initial/non-initial user namespace bit, plus the
// full cap_effective value — not further reduced, since collapsing it any
// further risks two genuinely different capability sets landing on the same
// class and silently suppressing a real privilege change) rather than the
// full "cgroup, tgid, start time, user namespace, effective UID,
// cap_effective, dev, inode" identity a single specific process/file
// occurrence would have: this is what lets kl_usage_key survive a hot loop
// of many short-lived, equally-privileged processes touching the same file
// while still producing a new key the moment a differently-privileged one
// does.
static __always_inline void kl_fill_privilege_class(struct kl_usage_key *key, __u32 euid,
						      __u32 user_ns_id, __u64 cap_effective)
{
	key->euid_is_root = (euid == 0) ? 1 : 0;
	key->in_init_userns = (user_ns_id == KL_INIT_USER_NS_INUM) ? 1 : 0;
	key->cap_effective = cap_effective;
}

// tp_btf/sched_process_exec fires after begin_new_exec has committed the new
// credentials and cannot be unwound (fs/exec.c): this is the point usage
// evidence for an executed file comes from. It carries no path;
// fentry/security_file_open supplies that separately, correlated by
// (mount namespace, dev, inode).
SEC("tp_btf/sched_process_exec")
int BPF_PROG(kl_exec_success, struct task_struct *task, pid_t old_pid, struct linux_binprm *bprm)
{
	__u64 cgroup_id = bpf_get_current_cgroup_id();

	if (kl_is_excluded(cgroup_id))
		return 0;

	struct file *file = BPF_CORE_READ(bprm, file);

	if (!file)
		return 0;

	__u64 dev, ino;

	if (kl_file_identity(file, &dev, &ino))
		return 0;

	__u32 mnt_ns_id = kl_current_mnt_ns_id(task);
	const struct cred *cred = BPF_CORE_READ(task, cred);
	__u32 euid = BPF_CORE_READ(cred, euid.val);
	__u64 cap_effective = BPF_CORE_READ(cred, cap_effective.val);
	__u32 user_ns_id = kl_current_user_ns_id(cred);

	__u64 now = bpf_ktime_get_ns();
	struct kl_usage_key key = {
		.cgroup_id = cgroup_id,
		.mnt_ns_id = mnt_ns_id,
		.dev = dev,
		.ino = ino,
		.kind = KL_EVENT_EXEC_SUCCESS,
	};
	kl_fill_privilege_class(&key, euid, user_ns_id, cap_effective);

	if (kl_usage_seen(&key, now))
		return 0;

	struct kl_event *ev = bpf_ringbuf_reserve(&kl_events, sizeof(*ev), 0);

	if (!ev) {
		kl_count_lost(cgroup_id);
		return 0;
	}

	__builtin_memset(ev, 0, sizeof(*ev));
	ev->kind = KL_EVENT_EXEC_SUCCESS;
	ev->cgroup_id = cgroup_id;
	ev->dev = dev;
	ev->ino = ino;
	ev->ktime_ns = now;
	ev->tgid = kl_current_tgid();
	ev->start_boottime_ns = kl_task_start_boottime(task);
	ev->mnt_ns_id = mnt_ns_id;
	ev->euid = euid;
	ev->cap_effective = cap_effective;
	ev->user_ns_id = user_ns_id;
	kl_current_root_identity(task, &ev->root_dev, &ev->root_ino);

	bpf_ringbuf_submit(ev, 0);
	kl_usage_mark(&key, now);
	return 0;
}

// fentry/security_file_open fires for every file open, before the open can
// be said to have succeeded (it runs before the VFS finishes the open), so
// it is never itself usage evidence. It plays two roles at once: when the
// kernel is opening the file for execution (KL_FMODE_EXEC set, set only by
// do_open_execat for the file execve() is about to run), it feeds the
// richer exec-open record used to give the matching exec-success event
// a path; for every other open, it is the path source mmap-success events
// resolve their (mount namespace, dev, inode) against. Both cases resolve
// the path with the same bpf_d_path call, since security_file_open is on
// the kernel's allow-list for that helper (security_mmap_file, used below,
// is not).
//
// The path bpf_d_path renders is relative to the *calling task's own root*
// at this exact moment (fs/d_path.c walks up from the dentry only as far as
// that root), so the same physical file (dev, ino) opened from two
// different roots — e.g. once from inside a chroot, once from the
// unchrooted view that same file is also reachable from — produces two
// different, both individually correct, path strings. Recording only
// (mount namespace, dev, inode) would let a later success event confirmed
// under a *different* root than this open's own reuse this open's own path
// string anyway (bpf_d_path never validates that its caller and any later
// reader agree on which root the string is relative to); root_dev/root_ino
// (kl_current_root_identity) is what a later reader (events.go's own
// pathIndex) needs to refuse exactly that reuse.
SEC("fentry/security_file_open")
int BPF_PROG(kl_file_open, struct file *file)
{
	__u64 cgroup_id = bpf_get_current_cgroup_id();

	if (kl_is_excluded(cgroup_id))
		return 0;

	__u64 dev, ino;

	if (kl_file_identity(file, &dev, &ino))
		return 0;

	unsigned int f_flags = BPF_CORE_READ(file, f_flags);
	__u8 kind = (f_flags & KL_FMODE_EXEC) ? KL_EVENT_EXEC_OPEN : KL_EVENT_FILE_OPEN;
	struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
	__u32 mnt_ns_id = kl_current_mnt_ns_id(task);

	if (kl_is_host_mnt_ns(mnt_ns_id))
		return 0;

	__u64 root_dev = 0, root_ino = 0;

	kl_current_root_identity(task, &root_dev, &root_ino);

	__u64 now = bpf_ktime_get_ns();
	// Keyed on (mount namespace, root identity, dev, inode) — no cgroup, no
	// path — so an exec-open and a file-open for the same file, opened from
	// the same root, share the one suppression window this key gates below,
	// and a file's own rename (dev/inode unchanged) is not itself a reason
	// to lift it.
	struct kl_path_key key = {
		.mnt_ns_id = mnt_ns_id,
		.root_dev = root_dev,
		.root_ino = root_ino,
		.dev = dev,
		.ino = ino,
	};

	// KL_EVENT_EXEC_OPEN is never suppressed by kl_path_seen, unlike
	// KL_EVENT_FILE_OPEN: this key carries no path, so once anything at all
	// opens a given (dev, inode) once, kl_path_seen's own suppression window
	// would otherwise keep reporting whatever path was current at that
	// moment — including one from before a later rename(2), since a rename
	// changes no (dev, inode) at all and triggers no open of its own for
	// this hook to ever see. A file-open a moment before a real exec of the
	// exact same file (dpkg's own write-then-rename-into-place is exactly
	// this shape: the temporary name's own write-open would otherwise be
	// "seen" first) would then leave every later exec of that file attributed
	// to whatever stale path that earlier open reported, for this key's
	// whole suppression window — confirmed directly against a real container
	// (a copied binary opened once under a temporary name, renamed into
	// place, then exec'd repeatedly: the correlation table kept the
	// temporary name). An exec is inherently rate-limited by how often a
	// process can actually be created, unlike a plain file-open (mmap-driven
	// library resolution, say, can open the same file far more often) — so
	// exempting only this one kind from the check keeps its own report
	// always current without meaningfully changing this hook's overall rate
	// for its other, still-suppressed callers. kl_path_mark below still runs
	// unconditionally, so a plain file-open of the same (dev, inode) right
	// after an exec-open still benefits from suppression as before.
	if (kind == KL_EVENT_FILE_OPEN && kl_path_seen(&key, now))
		return 0;

	struct kl_event *ev = bpf_ringbuf_reserve(&kl_events, sizeof(*ev), 0);

	if (!ev) {
		kl_count_lost(cgroup_id);
		return 0;
	}

	__builtin_memset(ev, 0, sizeof(*ev));
	ev->kind = kind;
	ev->cgroup_id = cgroup_id;
	ev->dev = dev;
	ev->ino = ino;
	ev->root_dev = root_dev;
	ev->root_ino = root_ino;
	ev->ktime_ns = now;
	ev->mnt_ns_id = mnt_ns_id;

	if (kind == KL_EVENT_EXEC_OPEN) {
		ev->tgid = kl_current_tgid();
		ev->start_boottime_ns = kl_task_start_boottime(task);

		const struct cred *cred = BPF_CORE_READ(task, cred);

		ev->euid = BPF_CORE_READ(cred, euid.val);
		ev->cap_effective = BPF_CORE_READ(cred, cap_effective.val);
		ev->user_ns_id = kl_current_user_ns_id(cred);
	}

	// file is security_file_open's own trusted argument, so taking the
	// address of its embedded f_path is the one-hop pattern the kernel's
	// own bpf_d_path selftests use directly on a fentry argument.
	//
	// Like bpf_probe_read_kernel_str below, bpf_d_path's return value on
	// success counts the trailing NUL it writes into the buffer, so
	// path_len (a count of path characters, with no trailing NUL implied)
	// must be one less.
	long path_len = bpf_d_path(&file->f_path, (char *)ev->path, sizeof(ev->path));

	if (path_len <= 0) {
		ev->path_truncated = 1;
	} else if ((__u64)path_len > sizeof(ev->path)) {
		ev->path_truncated = 1;
		ev->path_len = sizeof(ev->path);
	} else {
		ev->path_len = (__u16)(path_len - 1);
	}

	bpf_ringbuf_submit(ev, 0);
	kl_path_mark(&key, now);
	return 0;
}

// fexit/do_mmap fires once the mapping has actually been created (do_mmap
// returned, and the return value is a mapped address rather than an encoded
// errno): this is the point usage evidence for a PROT_EXEC mapping comes
// from. Like the exec-success event, it carries no path;
// fentry/security_file_open's KL_EVENT_FILE_OPEN records resolve paths for
// it by (mount namespace, dev, inode).
SEC("fexit/do_mmap")
int BPF_PROG(kl_mmap_success, struct file *file, unsigned long addr, unsigned long len,
	     unsigned long prot, unsigned long flags, unsigned long vm_flags,
	     unsigned long pgoff, unsigned long *populate, struct list_head *uf,
	     unsigned long ret)
{
	if (!file || !(prot & KL_PROT_EXEC) || KL_IS_ERR_VALUE(ret))
		return 0;

	__u64 cgroup_id = bpf_get_current_cgroup_id();

	if (kl_is_excluded(cgroup_id))
		return 0;

	__u64 dev, ino;

	if (kl_file_identity(file, &dev, &ino))
		return 0;

	struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
	__u32 mnt_ns_id = kl_current_mnt_ns_id(task);
	const struct cred *cred = BPF_CORE_READ(task, cred);
	__u32 euid = BPF_CORE_READ(cred, euid.val);
	__u64 cap_effective = BPF_CORE_READ(cred, cap_effective.val);
	__u32 user_ns_id = kl_current_user_ns_id(cred);

	__u64 now = bpf_ktime_get_ns();
	struct kl_usage_key key = {
		.cgroup_id = cgroup_id,
		.mnt_ns_id = mnt_ns_id,
		.dev = dev,
		.ino = ino,
		.kind = KL_EVENT_MMAP_SUCCESS,
	};
	kl_fill_privilege_class(&key, euid, user_ns_id, cap_effective);

	if (kl_usage_seen(&key, now))
		return 0;

	struct kl_event *ev = bpf_ringbuf_reserve(&kl_events, sizeof(*ev), 0);

	if (!ev) {
		kl_count_lost(cgroup_id);
		return 0;
	}

	__builtin_memset(ev, 0, sizeof(*ev));
	ev->kind = KL_EVENT_MMAP_SUCCESS;
	ev->cgroup_id = cgroup_id;
	ev->dev = dev;
	ev->ino = ino;
	ev->ktime_ns = now;
	ev->prot = (__u32)prot;
	ev->tgid = kl_current_tgid();
	ev->start_boottime_ns = kl_task_start_boottime(task);
	ev->mnt_ns_id = mnt_ns_id;
	ev->euid = euid;
	ev->cap_effective = cap_effective;
	ev->user_ns_id = user_ns_id;
	kl_current_root_identity(task, &ev->root_dev, &ev->root_ino);

	bpf_ringbuf_submit(ev, 0);
	kl_usage_mark(&key, now);
	return 0;
}

// fentry/security_mmap_file fires before do_mmap runs (mm/util.c calls it
// ahead of do_mmap), so it cannot itself be usage evidence and is not
// consulted by the mapping success judgement above. It records the attempt
// separately: only the identifying tuple and the requested protection, with
// no path, since security_mmap_file is not on the kernel's bpf_d_path
// allow-list (checked in this kernel's BTF: only security_file_open is).
SEC("fentry/security_mmap_file")
int BPF_PROG(kl_mmap_open, struct file *file, unsigned long prot, unsigned long flags)
{
	if (!file || !(prot & KL_PROT_EXEC))
		return 0;

	__u64 cgroup_id = bpf_get_current_cgroup_id();

	if (kl_is_excluded(cgroup_id))
		return 0;

	__u64 dev, ino;

	if (kl_file_identity(file, &dev, &ino))
		return 0;

	__u64 now = bpf_ktime_get_ns();
	struct kl_attempt_key key = {
		.cgroup_id = cgroup_id,
		.dev = dev,
		.ino = ino,
	};

	if (kl_attempt_seen(&key, now))
		return 0;

	struct kl_event *ev = bpf_ringbuf_reserve(&kl_events, sizeof(*ev), 0);

	if (!ev) {
		kl_count_lost(cgroup_id);
		return 0;
	}

	__builtin_memset(ev, 0, sizeof(*ev));
	ev->kind = KL_EVENT_MMAP_OPEN;
	ev->cgroup_id = cgroup_id;
	ev->dev = dev;
	ev->ino = ino;
	ev->ktime_ns = now;
	ev->prot = (__u32)prot;

	bpf_ringbuf_submit(ev, 0);
	kl_attempt_mark(&key, now);
	return 0;
}

// tp_btf/cgroup_mkdir fires whenever a new cgroup directory is created,
// giving the loader a cgroup ID <-> path correspondence it cannot get any
// other way once a short-lived cgroup has already been removed again. Not
// deduplicated (each cgroup is created once) and not checked against the
// exclusion map by identity, since the Sensor's own cgroup is created once
// at container start and this event only matters for cgroups created after
// the Sensor is already attached.
SEC("tp_btf/cgroup_mkdir")
int BPF_PROG(kl_cgroup_mkdir, struct cgroup *cgrp, const char *path)
{
	__u64 cgroup_id = BPF_CORE_READ(cgrp, kn, id);

	if (kl_is_excluded(cgroup_id))
		return 0;

	struct kl_event *ev = bpf_ringbuf_reserve(&kl_events, sizeof(*ev), 0);

	if (!ev) {
		kl_count_lost(cgroup_id);
		return 0;
	}

	__builtin_memset(ev, 0, sizeof(*ev));
	ev->kind = KL_EVENT_CGROUP_MKDIR;
	ev->cgroup_id = cgroup_id;
	ev->ktime_ns = bpf_ktime_get_ns();

	long n = bpf_probe_read_kernel_str(ev->path, sizeof(ev->path), path);

	// bpf_probe_read_kernel_str returns a negative value only on a genuine
	// read fault, never merely for truncating a too-long source string: when
	// the source does not fit, it copies exactly size bytes (the buffer's
	// own capacity, sizeof(ev->path)) and still returns that same positive
	// count — n == sizeof(ev->path) is therefore also truncation, not a
	// path that just happens to fill the buffer exactly with its own real
	// NUL terminator (a genuine fit always returns strictly less than size,
	// since the returned count already includes that terminator).
	if (n < 0 || n == sizeof(ev->path)) {
		ev->path_truncated = 1;
	} else {
		// bpf_probe_read_kernel_str's return value includes the
		// trailing NUL; path_len should not.
		ev->path_len = (__u16)(n > 0 ? n - 1 : 0);
	}

	bpf_ringbuf_submit(ev, 0);
	return 0;
}
