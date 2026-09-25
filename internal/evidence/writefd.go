package evidence

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// WriteFD serializes snap and writes it to the open file descriptor fd using
// the three raw syscalls the on-disk contract is defined in terms of:
// pwrite from offset 0, ftruncate to the new length, and fsync. It writes
// the exact same bytes as WriteTo (JSON body plus trailer; see
// encodeWithTrailer) and exists for a caller that holds the evidence file as
// a bare descriptor rather than an *os.File — the Sensor's observer opens it
// with a raw syscall before installing its seccomp filter, keeps only the
// fd, and must not depend on anything in the standard library's os package
// registering that fd with the runtime poller or otherwise touching it.
//
// fd is written to directly; WriteFD never opens, closes, or reopens it.
func WriteFD(fd int, snap Snapshot) error {
	full, err := encodeWithTrailer(snap)
	if err != nil {
		return err
	}

	for off := 0; off < len(full); {
		n, err := unix.Pwrite(fd, full[off:], int64(off))
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return fmt.Errorf("pwrite evidence: %w", err)
		}
		if n == 0 {
			return fmt.Errorf("pwrite evidence: short write (0 bytes) at offset %d", off)
		}
		off += n
	}
	if err := unix.Ftruncate(fd, int64(len(full))); err != nil {
		return fmt.Errorf("ftruncate evidence: %w", err)
	}
	if err := unix.Fsync(fd); err != nil {
		return fmt.Errorf("fsync evidence: %w", err)
	}
	return nil
}
