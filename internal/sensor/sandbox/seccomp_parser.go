package sandbox

import "golang.org/x/sys/unix"

// ParserFilter builds the parser's seccomp-BPF program: an allow-list (deny
// is the default action), the opposite polarity from ObserverFilter. Only
// the syscalls a parser doing nothing but decoding bytes from fds handed to
// it over one socket needs are allowed:
//
//   - reading the fd(s) the observer handed it: read, pread64
//
//   - talking to the observer over the one socketpair end it was born with:
//     recvmsg, sendmsg
//
//   - waiting for the next request with a bounded timeout: ppoll. Not
//     setsockopt(SO_RCVTIMEO): setsockopt is excluded from the Sensor's
//     distributed container-wide seccomp profile entirely, so a parser
//     that depended on it to bound a receive would fail before ever
//     reporting its own self-check, regardless of this allow-list.
//     golang.org/x/sys/unix.Poll calls ppoll(2) on Linux on both
//     architectures this package supports, so allowing ppoll covers it.
//
//   - memory management the Go runtime and its allocator need: mmap, munmap,
//     mprotect, madvise, brk
//
//   - futex, for the runtime's own scheduling and synchronization
//
//   - time: clock_gettime
//
//   - signalling only its own thread: tgkill(selfPID, *, *), plus getpid
//     and rt_sigreturn, is what lets the runtime keep asynchronously
//     preempting tight loops after this filter is installed. All three are
//     needed together, and this was found the hard way: the Go runtime's
//     own signal-raising code (runtime.raise, used to deliver the
//     async-preemption signal to a thread that has been running the same
//     goroutine too long) calls getpid(2) as a fresh syscall every time,
//     not the cached value user code gets from os.Getpid() — it does not
//     use tgkill's own first argument for anything but the syscall itself,
//     it constructs that argument from a live getpid() call. Without
//     getpid allowed, that call itself is denied (returning -1, which the
//     runtime's raw syscall wrapper does not check), so the signal this
//     filter otherwise explicitly allows never actually gets sent — and
//     because this is the same mechanism the runtime scheduler uses to let
//     any other goroutine (including a timer's callback) run at all once
//     GOMAXPROCS(1) leaves one goroutine occupying the only P, its absence
//     silently breaks far more than tight-loop preemption: a
//     goroutine parked on a timer (time.Sleep, time.AfterFunc) simply
//     never wakes up while another goroutine keeps the sole P busy,
//     confirmed by watching Run's own per-request watchdog timer never
//     fire under exactly that condition until this was added. rt_sigreturn
//     is what lets the signal handler that runs when the signal *is*
//     delivered actually return control afterward.
//
//   - nanosleep: the Go 1.26 scheduler's own monitor thread (sysmon) calls
//     runtime.usleep in a loop for as long as the process runs at all — not
//     something any particular Handler triggers — and on both amd64 and
//     arm64 that is implemented as a direct nanosleep(2) syscall (checked
//     against the Go 1.26.4 runtime's own assembly source for both
//     architectures, not assumed). Denying it does not stop sysmon: its
//     usleep call ignores its own return value, so a denied nanosleep is
//     silently treated as an instantly-completed sleep, and sysmon simply
//     loops as fast as it can instead of actually waiting — busy-spinning
//     an entire OS thread at 100% CPU for the rest of the process's life.
//     Found the same way as getpid above: by measuring, not guessing (a
//     parser handling one request accumulated roughly a full extra CPU-core
//     worth of usage over its runtime with nanosleep denied). This is the
//     only other syscall sysmon, netpoll, the runtime's signal handling,
//     and the GC/scavenger paths need beyond what is already listed here:
//     checked directly against the Go 1.26.4 runtime source (the raw
//     syscalls reachable from sys_linux_{amd64,arm64}.s, os_linux.go,
//     netpoll_epoll.go, signal_unix.go, mgc*.go). The others that source
//     reveals — clone (thread creation, deliberately excluded, see above),
//     rt_sigaction/rt_sigprocmask/sigaltstack/sched_getaffinity/arch_prctl
//     (signal handler and TLS setup, and the initial CPU-count probe, all
//     one-time calls the runtime makes during process bootstrap, before
//     this filter is ever installed), setitimer/timer_create/timer_settime/
//     timer_delete (the OS-itimer profiling signal path, only reachable if
//     something calls runtime/pprof.StartCPUProfile, which nothing in this
//     package does), and the low-level connect/socket/access/mincore
//     primitives (used by the pure-Go DNS resolver and the crash-reporting
//     monitor respectively, neither of which a parser that never imports
//     net and never crashes into that path exercises) — are not reachable
//     during a parser's actual run, so they are not in this allow-list.
//     clock_nanosleep does not appear anywhere in that source at all, on
//     either architecture; only nanosleep is used.
//
//   - close, to release fds after handling a request
//
//   - exiting: exit, exit_group
//
//   - epoll_create1, epoll_ctl, epoll_pwait, eventfd2, and — unavoidably —
//     write: everything runtime.netpollinit() needs on Linux, independent
//     of anything this package's own code does. Confirmed empirically, not
//     assumed, by watching a real crash: a long-lived Go 1.26 process, even
//     one that never touches net/os.Pipe/os/signal, has its scheduler
//     eventually need a timer (this package's own tests use one) or run a
//     GC cycle, and either lazily initializes the epoll-based netpoller —
//     epoll_create1 for the poll fd, eventfd2 for its internal wake-up fd,
//     epoll_ctl to register that wake-up fd with the poll fd, epoll_pwait
//     to actually wait — and once initialized, runtime.netpollBreak() calls
//     the bare write(2) syscall directly on that wake-up fd whenever it
//     needs to interrupt a blocked epoll_pwait (e.g. a new timer earlier
//     than any pending one). None of this has anything to do with
//     networking — the parser is never handed a network fd.
//
//     write(2) has one other legitimate use here too: the parser inherits
//     fd 2 (standard error) from the observer at exec time, and is expected
//     to write plain diagnostic text to it on its way out when something
//     goes wrong (an unhandled panic's trace, a fatal setup error before
//     the request loop even starts) — the same as any other Unix process.
//     That is a second, deliberate reason this allow-list needs write(2),
//     not just the runtime's own internal use of it.
//
//     Either way, seccomp cannot distinguish "write to the runtime's
//     internal eventfd" or "write to fd 2" from "write to some other fd"
//     (all three are the same syscall number with a dynamically-allocated
//     fd argument), so allowing it here is a real, acknowledged weakening
//     of condition 3: this allow-list cannot itself prevent a parser from
//     calling write() on a data fd it was handed, if the code calling into
//     it via the Handler interface ever did that. That is why condition 4
//     (below) — never handing the parser a descriptor beyond its
//     socketpair fd, fd 2, and one request fd at a time, and that request
//     fd always opened read-only by the observer before being passed
//     across — carries the actual guarantee here, not this filter.
//
// Nothing here grants any way to open a new file or a new communication
// channel, execute anything, or signal another process — condition 4 is
// what keeps the write(2) allowance above from being exploitable, not this
// filter alone. clone/clone3 are deliberately absent too. This was
// confirmed empirically, and the reasoning is narrower than it might look:
// GOMAXPROCS(1) only limits how many OS threads may run Go code
// *concurrently* (the number of Ps) — it does not, by itself, stop the
// runtime from creating additional OS threads (Ms) for other reasons, and
// does not change what clone(2) itself is called with. What actually
// avoids needing a new thread here is that the real parser keeps at most
// one goroutine runnable at a time (blocked in poll or recvmsg the rest of
// the time) and never makes a syscall the runtime treats as long-blocking
// in a way that hands its P to a different M; testing confirmed that
// spawning several concurrently-runnable CPU-bound goroutines *does* still
// try to start a new M even with GOMAXPROCS(1), and crashes outright once
// clone() comes back EPERM. A Handler implementation that itself starts
// additional runnable goroutines expecting real parallelism would hit the
// same crash.
func ParserFilter(selfPID int32) ([]unix.SockFilter, error) {
	prog := []insn{
		loadArch(),
		jeq(currentAuditArch, "check_nr", "deny"),

		labeled("check_nr", loadNr()),
		jeq(uint32(unix.SYS_READ), "allow", "l1"),
		labeled("l1", jeq(uint32(unix.SYS_PREAD64), "allow", "l2")),
		labeled("l2", jeq(uint32(unix.SYS_RECVMSG), "allow", "l3")),
		labeled("l3", jeq(uint32(unix.SYS_SENDMSG), "allow", "l4")),
		labeled("l4", jeq(uint32(unix.SYS_MMAP), "allow", "l5")),
		labeled("l5", jeq(uint32(unix.SYS_MUNMAP), "allow", "l6")),
		labeled("l6", jeq(uint32(unix.SYS_MPROTECT), "allow", "l7")),
		labeled("l7", jeq(uint32(unix.SYS_MADVISE), "allow", "l8")),
		labeled("l8", jeq(uint32(unix.SYS_BRK), "allow", "l9")),
		labeled("l9", jeq(uint32(unix.SYS_FUTEX), "allow", "l10")),
		labeled("l10", jeq(uint32(unix.SYS_CLOCK_GETTIME), "allow", "l11")),
		labeled("l11", jeq(uint32(unix.SYS_RT_SIGRETURN), "allow", "l12")),
		labeled("l12", jeq(uint32(unix.SYS_CLOSE), "allow", "l13")),
		labeled("l13", jeq(uint32(unix.SYS_EXIT), "allow", "l14")),
		labeled("l14", jeq(uint32(unix.SYS_EXIT_GROUP), "allow", "l15")),
		labeled("l15", jeq(uint32(unix.SYS_EPOLL_CREATE1), "allow", "l16")),
		labeled("l16", jeq(uint32(unix.SYS_EPOLL_CTL), "allow", "l17")),
		labeled("l17", jeq(uint32(unix.SYS_EPOLL_PWAIT), "allow", "l18")),
		labeled("l18", jeq(uint32(unix.SYS_EVENTFD2), "allow", "l19")),
		labeled("l19", jeq(uint32(unix.SYS_WRITE), "allow", "l20")),
		labeled("l20", jeq(uint32(unix.SYS_PPOLL), "allow", "l21")),
		labeled("l21", jeq(uint32(unix.SYS_GETPID), "allow", "l22")),
		labeled("l22", jeq(uint32(unix.SYS_NANOSLEEP), "allow", "l23")),
		labeled("l23", jeq(uint32(unix.SYS_TGKILL), "check_tgkill", "deny")),

		labeled("check_tgkill", loadArgHigh(0)),
		jeq(0, "check_tgkill_low", "deny"),
		labeled("check_tgkill_low", loadArgLow(0)),
		jeq(uint32(selfPID), "allow", "deny"),

		labeled("allow", ret(unix.SECCOMP_RET_ALLOW)),
		labeled("deny", ret(unix.SECCOMP_RET_ERRNO|uint32(unix.EPERM))),
	}
	return assemble(prog)
}
