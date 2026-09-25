package procfs

import "golang.org/x/sys/unix"

// FDNames lists the names in /proc/<pid>/fd — the process's own open file
// descriptor numbers as strings — without resolving any of them. Listing
// this directory only needs DAC search permission (generic_permission,
// crossed by CAP_DAC_READ_SEARCH); it is FDTarget, not this call, that hits
// the same ptrace_may_access check exe/root do (see fs/proc/fd.c), so a
// caller can enumerate a process's fd numbers even where resolving any one
// of them is refused.
func (h *Handle) FDNames() ([]string, error) {
	f, err := h.openRelative("fd", unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return f.Readdirnames(-1)
}

// FDTarget reads the readlink target of /proc/<pid>/fd/<name>, e.g.
// "socket:[12345]" or a resolved file path. name must be one of the values
// FDNames returned for the same Handle.
func (h *Handle) FDTarget(name string) (string, error) {
	buf := make([]byte, 4096)
	n, err := unix.Readlinkat(h.dirFD(), "fd/"+name, buf)
	if err != nil {
		return "", err
	}
	return string(buf[:n]), nil
}
