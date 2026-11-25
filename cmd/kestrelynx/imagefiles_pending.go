package main

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sync"
)

// pendingFile is the file of the pending set, in the image cache directory.
const pendingFile = "pending.json"

// maxPendingImages bounds the set; beyond it the oldest entries are dropped.
const maxPendingImages = 1000

var pendingIDRE = regexp.MustCompile(`^(docker\|(sha256:)?[0-9a-f]{64}|registry\|(sha256:)?[0-9a-f]{64}\|[A-Za-z0-9_.-]*/[A-Za-z0-9_.-]*/[A-Za-z0-9_.-]*)$`)

// pendingImages is the set of reads (see pendingKey) whose read was put off, kept in a
// file so that it survives a restart. A failure to write the file is logged
// once; the set still works in memory.
type pendingImages struct {
	path string
	log  *slog.Logger

	mu     sync.Mutex
	ids    []string // oldest first
	warned bool
}

// loadPendingImages reads the set at path; a missing or unreadable file is an
// empty set.
func loadPendingImages(path string, log *slog.Logger) *pendingImages {
	p := &pendingImages{path: path, log: log}
	b, err := os.ReadFile(path)
	if err != nil {
		return p
	}
	var ids []string
	if json.Unmarshal(b, &ids) != nil {
		return p
	}
	for _, id := range ids {
		if pendingIDRE.MatchString(id) && !slices.Contains(p.ids, id) {
			p.ids = append(p.ids, id)
		}
	}
	if len(p.ids) > maxPendingImages {
		p.ids = p.ids[len(p.ids)-maxPendingImages:]
	}
	return p
}

func (p *pendingImages) has(id string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Contains(p.ids, id)
}

// set adds id to the set or removes it, and writes the file when the set
// changed. An id that is not a digest is ignored.
func (p *pendingImages) set(id string, pending bool) {
	if !pendingIDRE.MatchString(id) {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	i := slices.Index(p.ids, id)
	switch {
	case pending && i < 0:
		p.ids = append(p.ids, id)
		if len(p.ids) > maxPendingImages {
			p.ids = p.ids[len(p.ids)-maxPendingImages:]
		}
	case !pending && i >= 0:
		p.ids = slices.Delete(p.ids, i, i+1)
	default:
		return
	}
	if err := p.write(); err != nil && !p.warned {
		p.warned = true
		p.log.Warn("the images put off to the next cycle cannot be recorded; they are remembered until the program stops", "path", p.path, "err", err)
	}
}

// write stores the set through a temporary file, so a reader never sees half
// of it.
func (p *pendingImages) write() error {
	b, err := json.Marshal(p.ids)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p.path), 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(p.path), ".tmp-pending-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, err = f.Write(b)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, p.path)
	}
	if err != nil {
		_ = os.Remove(tmp)
	}
	return err
}
