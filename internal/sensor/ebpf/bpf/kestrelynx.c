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
// Deduplication here is one LRU-backed suppression window shared by every
// event kind, keyed on (cgroup, dev, inode, kind) only: it exists to keep a
// hot loop (e.g. a tight read()/write() cycle touching the same file) from
// flooding the ring buffer, not to model who is doing the reading. Its
// consequence: once a tuple has been sent, any other process in the same
// cgroup touching the same file within the suppression window is
// suppressed too, even if that later access happens under a different PID,
// a different set of credentials, or a different capability set than the
// one that was actually reported. A consumer that needs every distinct
// process or privilege combination that touched a file cannot rely on
// seeing one event per occurrence from this map alone.
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

// kl_dedup_key identifies "the same observation" for the minimal suppression
// window: same cgroup, same file, same kind of event.
struct kl_dedup_key {
	__u64 cgroup_id;
	__u64 dev;
	__u64 ino;
	__u8 kind;
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

// Global count of events dropped because bpf_ringbuf_reserve failed. A
// single counter, not broken down per cgroup or event kind: knowing
// whether the ring buffer is sized correctly for the current load needs a
// total, not an attribution.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 1);
} kl_lost_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct kl_dedup_key);
	__type(value, __u64);
	__uint(max_entries, 8192);
} kl_dedup SEC(".maps");

static __always_inline bool kl_is_excluded(__u64 cgroup_id)
{
	__u32 zero = 0;
	__u64 *excluded = bpf_map_lookup_elem(&kl_excluded_cgroup, &zero);

	return excluded && *excluded != 0 && *excluded == cgroup_id;
}

static __always_inline void kl_count_lost(void)
{
	__u32 zero = 0;
	__u64 *counter = bpf_map_lookup_elem(&kl_lost_events, &zero);

	if (counter)
		__sync_fetch_and_add(counter, 1);
}

// kl_dedup_seen reports whether this (cgroup, dev, ino, kind) tuple was
// registered within the suppression window. It must be called before
// attempting to reserve ring buffer space; kl_dedup_mark must only be called
// after a successful bpf_ringbuf_submit, so a reservation failure leaves the
// tuple unregistered and the next occurrence tries again.
static __always_inline bool kl_dedup_seen(struct kl_dedup_key *key, __u64 now_ns)
{
	__u64 *last = bpf_map_lookup_elem(&kl_dedup, key);

	return last && now_ns - *last < KL_DEDUP_WINDOW_NS;
}

static __always_inline void kl_dedup_mark(struct kl_dedup_key *key, __u64 now_ns)
{
	bpf_map_update_elem(&kl_dedup, key, &now_ns, BPF_ANY);
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

	__u64 now = bpf_ktime_get_ns();
	struct kl_dedup_key key = {
		.cgroup_id = cgroup_id,
		.dev = dev,
		.ino = ino,
		.kind = KL_EVENT_EXEC_SUCCESS,
	};

	if (kl_dedup_seen(&key, now))
		return 0;

	struct kl_event *ev = bpf_ringbuf_reserve(&kl_events, sizeof(*ev), 0);

	if (!ev) {
		kl_count_lost();
		return 0;
	}

	__builtin_memset(ev, 0, sizeof(*ev));
	ev->kind = KL_EVENT_EXEC_SUCCESS;
	ev->cgroup_id = cgroup_id;
	ev->dev = dev;
	ev->ino = ino;
	ev->ktime_ns = now;
	ev->tgid = bpf_get_current_pid_tgid() >> 32;
	ev->start_boottime_ns = BPF_CORE_READ(task, start_boottime);
	ev->mnt_ns_id = kl_current_mnt_ns_id(task);

	const struct cred *cred = BPF_CORE_READ(task, cred);

	ev->euid = BPF_CORE_READ(cred, euid.val);
	ev->cap_effective = BPF_CORE_READ(cred, cap_effective.val);
	ev->user_ns_id = kl_current_user_ns_id(cred);

	bpf_ringbuf_submit(ev, 0);
	kl_dedup_mark(&key, now);
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
	__u64 now = bpf_ktime_get_ns();
	struct kl_dedup_key key = {
		.cgroup_id = cgroup_id,
		.dev = dev,
		.ino = ino,
		.kind = kind,
	};

	if (kl_dedup_seen(&key, now))
		return 0;

	struct kl_event *ev = bpf_ringbuf_reserve(&kl_events, sizeof(*ev), 0);

	if (!ev) {
		kl_count_lost();
		return 0;
	}

	__builtin_memset(ev, 0, sizeof(*ev));
	ev->kind = kind;
	ev->cgroup_id = cgroup_id;
	ev->dev = dev;
	ev->ino = ino;
	ev->ktime_ns = now;

	struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();

	ev->mnt_ns_id = kl_current_mnt_ns_id(task);

	if (kind == KL_EVENT_EXEC_OPEN) {
		ev->tgid = bpf_get_current_pid_tgid() >> 32;
		ev->start_boottime_ns = BPF_CORE_READ(task, start_boottime);

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
	kl_dedup_mark(&key, now);
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

	__u64 now = bpf_ktime_get_ns();
	struct kl_dedup_key key = {
		.cgroup_id = cgroup_id,
		.dev = dev,
		.ino = ino,
		.kind = KL_EVENT_MMAP_SUCCESS,
	};

	if (kl_dedup_seen(&key, now))
		return 0;

	struct kl_event *ev = bpf_ringbuf_reserve(&kl_events, sizeof(*ev), 0);

	if (!ev) {
		kl_count_lost();
		return 0;
	}

	__builtin_memset(ev, 0, sizeof(*ev));
	ev->kind = KL_EVENT_MMAP_SUCCESS;
	ev->cgroup_id = cgroup_id;
	ev->dev = dev;
	ev->ino = ino;
	ev->ktime_ns = now;
	ev->prot = (__u32)prot;
	ev->tgid = bpf_get_current_pid_tgid() >> 32;

	struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();

	ev->start_boottime_ns = BPF_CORE_READ(task, start_boottime);
	ev->mnt_ns_id = kl_current_mnt_ns_id(task);

	const struct cred *cred = BPF_CORE_READ(task, cred);

	ev->euid = BPF_CORE_READ(cred, euid.val);
	ev->cap_effective = BPF_CORE_READ(cred, cap_effective.val);
	ev->user_ns_id = kl_current_user_ns_id(cred);

	bpf_ringbuf_submit(ev, 0);
	kl_dedup_mark(&key, now);
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
	struct kl_dedup_key key = {
		.cgroup_id = cgroup_id,
		.dev = dev,
		.ino = ino,
		.kind = KL_EVENT_MMAP_OPEN,
	};

	if (kl_dedup_seen(&key, now))
		return 0;

	struct kl_event *ev = bpf_ringbuf_reserve(&kl_events, sizeof(*ev), 0);

	if (!ev) {
		kl_count_lost();
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
	kl_dedup_mark(&key, now);
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
		kl_count_lost();
		return 0;
	}

	__builtin_memset(ev, 0, sizeof(*ev));
	ev->kind = KL_EVENT_CGROUP_MKDIR;
	ev->cgroup_id = cgroup_id;
	ev->ktime_ns = bpf_ktime_get_ns();

	long n = bpf_probe_read_kernel_str(ev->path, sizeof(ev->path), path);

	if (n < 0) {
		ev->path_truncated = 1;
	} else {
		// bpf_probe_read_kernel_str's return value includes the
		// trailing NUL; path_len should not.
		ev->path_len = (__u16)(n > 0 ? n - 1 : 0);
	}

	bpf_ringbuf_submit(ev, 0);
	return 0;
}
