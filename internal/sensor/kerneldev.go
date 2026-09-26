package sensor

import "fmt"

// kernelDevMinorBits and kernelDevMinorMask implement the Linux kernel's own
// internal dev_t packing (include/linux/kdev_t.h: MAJOR(dev) = dev >> 20,
// MINOR(dev) = dev & 0xfffff, MKDEV(ma, mi) = (ma << 20) | mi). This is NOT
// the same packing stat(2)'s userspace dev_t uses (glibc's makedev, which
// golang.org/x/sys/unix.Major/Minor/Mkdev implement instead): the two only
// happen to agree on very small major/minor numbers, and diverge as soon as
// either exceeds a handful of bits. bpf/kestrelynx.c reads a file's device
// straight from the kernel's own inode->i_sb->s_dev, and /proc/<pid>/maps
// formats its own "major:minor" column via this exact kernel MAJOR/MINOR
// pair too (fs/proc/task_mmu.c's show_map_vma) — so an eBPF event's own Dev
// field must be decoded with these kernel-internal macros, never with
// unix.Major/Minor, to compare correctly against a maps-derived Dev string
// or a rootfs.Reader.Stat result (both of which are the real major/minor
// numbers themselves, not a packed value, regardless of which packing
// produced them).
const (
	kernelDevMinorBits = 20
	kernelDevMinorMask = (1 << kernelDevMinorBits) - 1
)

// kernelDevMajorMinor decodes a kernel-internal dev_t (as bpf/kestrelynx.c
// reads it) into its (major, minor) numbers.
func kernelDevMajorMinor(dev uint64) (major, minor uint32) {
	return uint32(dev >> kernelDevMinorBits), uint32(dev & kernelDevMinorMask)
}

// formatKernelDev renders a raw kernel-internal dev_t (an eBPF event's own
// Dev field) in the same "MM:mm" hex form /proc/<pid>/maps and
// formatDevForCompare's own stat-based callers use, so an event's own dev
// value compares directly against a maps-derived Dev string or a
// rootfs.Reader.Stat result. Never use formatDevForCompare (which decodes
// the unrelated userspace/glibc dev_t packing) on a value that came from an
// eBPF event.
func formatKernelDev(dev uint64) string {
	major, minor := kernelDevMajorMinor(dev)
	return fmt.Sprintf("%02x:%02x", major, minor)
}
