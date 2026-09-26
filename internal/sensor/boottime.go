package sensor

import "golang.org/x/sys/unix"

// clockTicksPerSec is sysconf(_SC_CLK_TCK), the unit /proc/<pid>/stat's
// starttime field (and therefore InitProcess.Starttime, procfs.Handle.
// Starttime's own return value) is expressed in. Not read dynamically
// (there is no allocation-free, dependency-free way to call sysconf without
// cgo); 100 is the value on every Linux configuration this codebase
// targets (x86_64 and aarch64, both USER_HZ=100 by convention since Linux
// made this a fixed constant independent of the kernel's own internal HZ,
// specifically so that changing HZ would not require recompiling userspace
// tools that read /proc) — the same assumption internal/sensor/parser's own
// test helpers already make (see parser/parser_test.go's own
// clockTicksPerSec).
const clockTicksPerSec = 100

// nsPerClockTick is how many nanoseconds one clock tick spans at
// clockTicksPerSec.
const nsPerClockTick = 1_000_000_000 / clockTicksPerSec

// bootNsToTicks converts a boot-relative nanosecond value — as
// bpf/kestrelynx.c's kl_exec_success/kl_mmap_success report a process's own
// start time via task_struct's start_boottime — into the same boot-relative
// clock-tick unit /proc/<pid>/stat's own starttime field is expressed in,
// using the same integer-division convention (ns / (1e9/ticks)) this
// repository's own runtime-events conversion harness uses for the identical
// purpose (experiments/runtime-events/convert.go's finishEvent:
// "startNS/(1_000_000_000/ticks)"). Both start_boottime and /proc's
// starttime measure time since boot on the same modern-kernel timebase (the
// kernel derives the latter from the former), so this conversion needs no
// wall-clock reference point at all — see resolveEventGeneration's own doc
// comment for why a wall-clock projection would in fact be the wrong tool
// for the comparison this exists to support.
func bootNsToTicks(ns uint64) int64 {
	return int64(ns / nsPerClockTick)
}

// bootTicksNow reads CLOCK_BOOTTIME (time since boot, including any time
// spent suspended) and converts it to the same boot-relative clock-tick
// unit bootNsToTicks reports for an event's own start_boottime_ns — used
// exactly once, at Sensor startup right after eBPF attaches, to record the
// boot-relative instant attachment happened (Session.attachedAtBootTicks):
// comparing a container's own init.Starttime against that single captured
// value is what decides whether a freshly discovered generation could have
// been observed by eBPF from its own start (see initialEventsCoverage), and
// needs no further wall-clock conversion anywhere else — see
// resolveEventGeneration's own doc comment on why generation matching
// itself deliberately stays in this same boot-relative domain throughout.
func bootTicksNow() (int64, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		return 0, err
	}
	return bootNsToTicks(uint64(ts.Nano())), nil
}

// bootNsNow reads CLOCK_BOOTTIME and returns it as a raw boot-relative
// nanosecond value — never rounded to a clock tick. Used wherever a
// nanosecond-precision instant this session actually confirmed a process
// alive at needs to be recorded (generationState.lastAliveNs) and later
// compared, at full precision, against an eBPF event's own
// start_boottime_ns: rounding either side of that comparison down to a
// 10ms clock tick (bootTicksNow/bootNsToTicks) would let two events that
// are genuinely tens of milliseconds apart in real time — enough for a
// same-container-ID restart to have completed in between — collide into
// the same tick and become indistinguishable (see resolveEventGeneration's
// own doc comment). InitProcess.Starttime itself has no ns-precision
// equivalent — /proc/<pid>/stat only ever reports it in ticks — which is
// why that one comparison (and only that one) still has to go through
// ticksToNs's own tick-floor conversion instead.
func bootNsNow() (uint64, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		return 0, err
	}
	return uint64(ts.Nano()), nil
}

// ticksToNs converts a boot-relative clock-tick value — as
// InitProcess.Starttime/procfs.Handle.Starttime report it — to the
// nanosecond instant at the very *start* of that tick, the same
// nsPerClockTick-wide unit bootNsNow and an eBPF event's own
// start_boottime_ns are both already in. This is a floor, not an exact
// instant: the real process start this tick value came from happened
// somewhere within [ticksToNs(t), ticksToNs(t+1)), never before it — see
// resolveEventGeneration's own doc comment for the one comparison that
// still has to account for that remaining tick-wide uncertainty on this
// (and only this) side of a comparison.
func ticksToNs(ticks int64) uint64 {
	return uint64(ticks) * nsPerClockTick
}
