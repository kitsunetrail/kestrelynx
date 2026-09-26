package sensor

import "github.com/kitsunetrail/kestrelynx/internal/sensor/ebpf"

// eventChCapacity bounds how many decoded eBPF events runEventReader may
// have handed to loop but not yet had applied. Sized well above one sample
// interval's worth of ordinary traffic so a momentary burst (a container
// starting many short-lived processes at once) does not itself become a
// second, unmodeled loss point on top of the kernel's own ring-buffer
// counters (kl_lost_events/kl_lost_by_cgroup) — but if loop falls far enough
// behind to fill this channel anyway, runEventReader's send blocks, which in
// turn stalls its own next h.Read(): a real, currently unmeasured risk this
// Sensor accepts for now, pending real load measurement of this specific
// channel under sustained event traffic.
const eventChCapacity = 4096

// runEventReader is the whole body of the event reader goroutine: block on
// h.Read(), decode nothing itself (h.Read already returns a decoded Event),
// and forward every event to out until h.Read fails — which happens exactly
// once per Sensor session, when h.Close() is called as part of session
// shutdown (see (*ebpf.Handle).Read's own doc comment on Close unblocking a
// pending Read with ringbuf.ErrClosed) or, in principle, some other
// unrecoverable ring buffer error. Either way this goroutine simply returns;
// it never touches Session state itself, exactly like a sample worker or
// the dbworker — loop is the only goroutine that ever applies an Event (see
// events.go's applyEvent).
func runEventReader(h *ebpf.Handle, out chan<- ebpf.Event) {
	for {
		ev, err := h.Read()
		if err != nil {
			return
		}
		out <- ev
	}
}
