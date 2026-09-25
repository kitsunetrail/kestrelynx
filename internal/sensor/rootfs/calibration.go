package rootfs

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"

	"github.com/kitsunetrail/kestrelynx/internal/sensor/procfs"
)

// CalibrationMode says how much a fresh stat of a candidate file agrees with
// what the same process's /proc/<pid>/maps recorded for it, once the two are
// compared. Which one holds on a given container depends on the kernel and
// the filesystem backing the container's rootfs: pre-6.8 OverlayFS reports a
// maps dev that differs from a later stat's (a kernel change around commit
// 3efdc78fdc21 is what moved this), so only the inode agrees; 6.8 and later,
// and non-overlay filesystems, agree on both.
type CalibrationMode string

const (
	// CalibrationDevInode means dev and inode both agreed: a later
	// observation is judged to be the same file only if both still match.
	CalibrationDevInode CalibrationMode = "dev_inode"
	// CalibrationInodeOnly means only the inode agreed: dev is not
	// trustworthy for this container, and a later observation is judged the
	// same file if the inode alone still matches.
	CalibrationInodeOnly CalibrationMode = "inode_only"
	// CalibrationUnknown means neither agreed (or no candidate could be
	// calibrated at all): dev/inode comparison is not usable for this
	// container's file-replacement judgement, which then relies on
	// "(deleted)" alone.
	CalibrationUnknown CalibrationMode = ""
)

// ErrNoCalibrationCandidate is returned by Calibrate when every candidate
// was either marked deleted or could not be opened through the read
// contract (gone, denied, wrong file type, disallowed filesystem — any
// reason OpenFile refuses it).
var ErrNoCalibrationCandidate = errors.New("rootfs: no usable calibration candidate")

// Calibration is the result of comparing one candidate mapping's
// maps-recorded dev/inode against a fresh stat of the same path, resolved
// through the read contract.
type Calibration struct {
	Mode      CalibrationMode
	Path      string
	MapsDev   string
	MapsInode uint64
	StatDev   string
	StatInode uint64
}

// ClassifyCalibration compares one maps-recorded (dev, inode) pair against a
// freshly-stat'd (dev, inode) pair for the same candidate path and reports
// the agreement. It has no knowledge of where either pair came from — it is
// kept pure and separate from Calibrate specifically so it can be tested
// directly against values recorded from real container runs, without
// needing a live container to reproduce the kernel/filesystem combination
// that produced them.
func ClassifyCalibration(mapsDev string, mapsInode uint64, statDev string, statInode uint64) CalibrationMode {
	switch {
	case mapsDev == statDev && mapsInode == statInode:
		return CalibrationDevInode
	case mapsInode == statInode:
		return CalibrationInodeOnly
	default:
		return CalibrationUnknown
	}
}

// formatDev renders a raw stat dev_t in the "MM:mm" hex form
// /proc/<pid>/maps uses (fs/proc/task_mmu.c's show_map_vma formats it the
// same way), so a freshly-stat'd device can be compared against a maps
// entry's Dev string directly.
func formatDev(dev uint64) string {
	return fmt.Sprintf("%02x:%02x", unix.Major(dev), unix.Minor(dev))
}

// Calibrate determines whether dev/inode comparison can be trusted for this
// container by resolving the first usable candidate mapping — in the order
// given, which the caller should arrange to start with the process's own
// executable mapping — through the read contract and comparing its
// maps-recorded dev/inode against a fresh stat. A candidate marked deleted,
// or one the read contract refuses for any reason (gone, wrong file type,
// disallowed filesystem), is skipped in favor of the next; ErrNoCalibrationCandidate
// is returned once none remain.
func Calibrate(r *Reader, candidates []procfs.MapEntry) (Calibration, error) {
	for _, c := range candidates {
		if c.Deleted {
			continue
		}
		f, err := r.OpenFile(c.Path)
		if err != nil {
			continue
		}
		var st unix.Stat_t
		ferr := unix.Fstat(int(f.Fd()), &st)
		f.Close()
		if ferr != nil {
			continue
		}
		statDev := formatDev(st.Dev)
		return Calibration{
			Mode:      ClassifyCalibration(c.Dev, c.Inode, statDev, st.Ino),
			Path:      c.Path,
			MapsDev:   c.Dev,
			MapsInode: c.Inode,
			StatDev:   statDev,
			StatInode: st.Ino,
		}, nil
	}
	return Calibration{}, ErrNoCalibrationCandidate
}
