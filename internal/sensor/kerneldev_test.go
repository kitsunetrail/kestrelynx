package sensor

import "testing"

func TestKernelDevMajorMinor(t *testing.T) {
	cases := []struct {
		dev             uint64
		wantMaj, wantMn uint32
	}{
		{dev: (8 << 20) | 1, wantMaj: 8, wantMn: 1},     // 8:1 (e.g. /dev/sda1)
		{dev: (0 << 20) | 5, wantMaj: 0, wantMn: 5},     // /dev/console-style low device
		{dev: (259 << 20) | 3, wantMaj: 259, wantMn: 3}, // a major number needing more than 8 bits
	}
	for _, c := range cases {
		maj, mn := kernelDevMajorMinor(c.dev)
		if maj != c.wantMaj || mn != c.wantMn {
			t.Errorf("kernelDevMajorMinor(%#x) = (%d, %d), want (%d, %d)", c.dev, maj, mn, c.wantMaj, c.wantMn)
		}
	}
}

func TestFormatKernelDev(t *testing.T) {
	got := formatKernelDev((8 << 20) | 1)
	if got != "08:01" {
		t.Errorf("formatKernelDev((8<<20)|1) = %q, want %q", got, "08:01")
	}
}

// TestFormatKernelDevDiffersFromUserspaceEncoding pins the exact bug this
// file exists to fix: the kernel's own dev_t packing (major<<20|minor) and
// the userspace/glibc packing formatDevForCompare decodes are different
// encodings of the same (major, minor) pair once either number needs more
// than a handful of bits, so applying the wrong decoder to a kernel-sourced
// value produces the wrong device string entirely.
func TestFormatKernelDevDiffersFromUserspaceEncoding(t *testing.T) {
	// The kernel encoding of major=8, minor=1.
	kernelDev := uint64((8 << 20) | 1)
	if got := formatKernelDev(kernelDev); got != "08:01" {
		t.Fatalf("formatKernelDev(kernel 8:1) = %q, want \"08:01\"", got)
	}
	// Decoding that same raw value with the userspace/glibc macros
	// (formatDevForCompare) must NOT also produce "08:01" -- if it did, this
	// test would no longer be exercising a real difference between the two
	// encodings.
	if got := formatDevForCompare(kernelDev); got == "08:01" {
		t.Fatalf("formatDevForCompare(kernel-encoded 8:1) = %q, want it to differ from the kernel decoder's own answer (the two encodings are not interchangeable)", got)
	}
}
