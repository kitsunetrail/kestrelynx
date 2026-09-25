package sandbox

// bpf(2)'s first argument selects a subcommand from enum bpf_cmd
// (linux/bpf.h). golang.org/x/sys/unix does not export this enum (it is
// cilium/ebpf's concern, not a syscall-numbering concern), so the four
// values the observer's own filter allows after it has dropped CAP_BPF are
// named here directly. The enum is append-only kernel UAPI; these first five
// values have been stable since eBPF's introduction.
const (
	bpfMapCreate     = 0
	bpfMapLookupElem = 1
	bpfMapUpdateElem = 2
	bpfMapDeleteElem = 3
	bpfMapGetNextKey = 4
	bpfProgLoad      = 5
	bpfObjGet        = 7
	bpfProgGetFdByID = 13
	bpfMapGetFdByID  = 14
	bpfLinkCreate    = 28
	bpfLinkUpdate    = 29
)
