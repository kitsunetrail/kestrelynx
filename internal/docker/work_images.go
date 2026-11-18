package docker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	imageRecordSchema     = 1
	maxImageRecordEntries = 1024
	maxImageRecordBytes   = 1 << 20
	imageDeleteTimeout    = 60 * time.Second
)

// ImagePruner removes work images this installation pulled and no longer
// uses. It keeps a record of the references it pulled and removes only
// those, never by force.
//
// A reference enters the record in two steps. Before a pull it is reserved,
// which is refused when the record is full, so that no image is pulled that
// could not be tracked. After the pull succeeded it is confirmed, and only a
// confirmed reference is ever removed: a reservation whose pull did not finish
// says nothing about who put an image there later, and is dropped without the
// daemon being asked for anything.
//
// Before removing an image it inspects it and leaves
// it alone when someone else also holds it: an image that carries a tag was
// not created by this installation (which pulls by digest only), so it
// belongs to the user. The pruner sends exactly two kinds of request, an
// image inspect and an image delete.
type ImagePruner struct {
	httpClient *http.Client
	baseURL    string
	path       string
	log        *slog.Logger

	// mu guards the record file and serializes Record and Prune.
	mu sync.Mutex
}

type imageRecord struct {
	Schema int `json:"schema"`
	// Images are the references this installation pulled.
	Images []string `json:"images"`
	// Pending are the references it reserved before a pull that has not been
	// confirmed.
	Pending []string `json:"pending,omitempty"`
}

// imageState is the record in memory.
type imageState struct {
	pulled  []string
	pending []string
}

func (s imageState) len() int { return len(s.pulled) + len(s.pending) }

// NewImagePruner returns a pruner that talks to the Docker daemon at
// socketPath and keeps its record in the file recordPath. recordPath is the
// final path of the file; the caller builds it. The parent directory is
// created (0700) when the first record is written.
func NewImagePruner(socketPath, recordPath string, log *slog.Logger) (*ImagePruner, error) {
	if socketPath == "" {
		return nil, errors.New("image pruner needs the Docker socket path")
	}
	return newImagePruner("http://docker", newUnixClient(socketPath), recordPath, log)
}

// newImagePruner is used by tests to point the pruner at an httptest server.
func newImagePruner(baseURL string, hc *http.Client, recordPath string, log *slog.Logger) (*ImagePruner, error) {
	if recordPath == "" {
		return nil, errors.New("image pruner needs a record file path")
	}
	if log == nil {
		log = slog.Default()
	}
	return &ImagePruner{httpClient: hc, baseURL: baseURL, path: recordPath, log: log}, nil
}

// acceptableRef reports whether ref is a "repository@sha256:<64 hex>"
// reference that is safe to put into a request path.
func acceptableRef(ref string) bool {
	m := imageRefRE.FindStringSubmatch(ref)
	return m != nil && !strings.Contains(m[1], "//") && !strings.Contains(m[1], "..")
}

// load reads the record. A missing file is an empty record. A file that
// cannot be read or understood yields ok false, so the caller knows nothing
// may be concluded from it.
func (p *ImagePruner) load() (st imageState, ok bool) {
	f, err := os.Open(p.path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return imageState{}, true
		}
		p.log.Warn("image record is unreadable; no image is removed", "path", p.path, "err", err)
		return imageState{}, false
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxImageRecordBytes+1))
	if err != nil || len(data) > maxImageRecordBytes {
		p.log.Warn("image record is unreadable or too large; no image is removed", "path", p.path, "err", err)
		return imageState{}, false
	}
	var rec imageRecord
	if err := json.Unmarshal(data, &rec); err != nil || rec.Schema != imageRecordSchema {
		p.log.Warn("image record is malformed; no image is removed", "path", p.path, "err", err)
		return imageState{}, false
	}
	for _, r := range rec.Images {
		if acceptableRef(r) && !slices.Contains(st.pulled, r) {
			st.pulled = append(st.pulled, r)
		}
	}
	for _, r := range rec.Pending {
		if acceptableRef(r) && !slices.Contains(st.pulled, r) && !slices.Contains(st.pending, r) {
			st.pending = append(st.pending, r)
		}
	}
	return st, true
}

// save writes the record atomically: a temporary file in the same directory
// with mode 0600, then a rename.
func (p *ImagePruner) save(st imageState) error {
	pulled := append([]string{}, st.pulled...)
	sort.Strings(pulled)
	pending := append([]string(nil), st.pending...)
	sort.Strings(pending)
	data, err := json.Marshal(imageRecord{Schema: imageRecordSchema, Images: pulled, Pending: pending})
	if err != nil {
		return err
	}
	dir := filepath.Dir(p.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create image record directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".work-images-*")
	if err != nil {
		return fmt.Errorf("create image record file: %w", err)
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("create image record file: %w", err)
	}
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		tmp.Close()
		return fmt.Errorf("write image record: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("write image record: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("write image record: %w", err)
	}
	if err := os.Rename(tmp.Name(), p.path); err != nil {
		return fmt.Errorf("publish image record: %w", err)
	}
	return nil
}

// Reserve notes that this installation is about to pull ref
// ("repository@sha256:..."). It is called before the pull, and the image is
// pulled only when it returns nil: a full record, or one that cannot be
// written, would leave an image on the host that is never removed. It is safe
// for concurrent use and idempotent.
func (p *ImagePruner) Reserve(ref string) error {
	n := normalizeRef(ref)
	if !acceptableRef(ref) || !acceptableRef(n) {
		return fmt.Errorf("image reference %q is not repository@sha256:<64 hex>", ref)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	// An unreadable record is replaced: what it held cannot be trusted.
	st, ok := p.load()
	if ok && (slices.Contains(st.pulled, n) || slices.Contains(st.pending, n)) {
		return nil
	}
	if st.len() >= maxImageRecordEntries {
		return fmt.Errorf("the record of pulled work images is full (%d entries); images that are no longer used have to be removed first", maxImageRecordEntries)
	}
	st.pending = append(st.pending, n)
	if err := p.save(st); err != nil {
		return fmt.Errorf("record the work image: %w", err)
	}
	return nil
}

// Confirm notes that the pull of a reserved reference succeeded: the image is
// now one this installation put on the host, and Prune may remove it once it
// is no longer used. A reference that was not reserved is not confirmed. A
// failure to write is logged; the reference then stays reserved and its image
// is not removed.
func (p *ImagePruner) Confirm(ref string) {
	n := normalizeRef(ref)
	p.mu.Lock()
	defer p.mu.Unlock()
	st, ok := p.load()
	if !ok {
		return
	}
	i := slices.Index(st.pending, n)
	if i < 0 {
		if !slices.Contains(st.pulled, n) {
			p.log.Warn("a pulled work image was not reserved first; it is not tracked", "ref", n)
		}
		return
	}
	st.pending = slices.Delete(st.pending, i, i+1)
	st.pulled = append(st.pulled, n)
	if err := p.save(st); err != nil {
		p.log.Warn("cannot record that the work image was pulled; it will not be removed later", "ref", n, "err", err)
	}
}

// PruneResult counts what one Prune did.
type PruneResult struct {
	Removed  int // removed now, or already gone
	Kept     int // still recorded: in use, kept by the caller, or the removal failed
	Released int // no longer tracked: the image is also held under a tag
	// Unfinished are reservations whose pull was never confirmed and that are
	// no longer wanted: dropped from the record, the daemon is not asked.
	Unfinished int
}

// Prune handles every image this installation pulled whose reference is not
// in keep. Each is inspected first:
//   - already gone: dropped from the record;
//   - carries a tag: not removed, and dropped from the record so that it is
//     never removed later either (Released);
//   - also reachable through another reference that is in keep: not removed
//     and still recorded (Kept);
//   - otherwise removed, without force, and dropped from the record.
//
// An image a container still uses, or whose inspection or removal fails for
// another reason, stays recorded and is tried again by the next Prune. A
// reference that was reserved and never confirmed is not an image of this
// installation: when it is not in keep it is dropped from the record and
// nothing is removed (Unfinished).
func (p *ImagePruner) Prune(ctx context.Context, keep []string) PruneResult {
	var res PruneResult
	if ctx.Err() != nil {
		return res
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	st, ok := p.load()
	if !ok || st.len() == 0 {
		return res
	}
	keepSet := map[string]bool{}
	for _, k := range keep {
		keepSet[normalizeRef(k)] = true
	}
	var next imageState
	for _, ref := range st.pending {
		if keepSet[ref] {
			next.pending = append(next.pending, ref)
			continue
		}
		res.Unfinished++
	}
	for _, ref := range st.pulled {
		if keepSet[ref] || ctx.Err() != nil {
			next.pulled = append(next.pulled, ref)
			res.Kept++
			continue
		}
		switch p.settle(ctx, ref, keepSet) {
		case imageRemoved:
			res.Removed++
		case imageReleased:
			res.Released++
		default:
			next.pulled = append(next.pulled, ref)
			res.Kept++
		}
	}
	if next.len() != st.len() {
		if err := p.save(next); err != nil {
			p.log.Warn("cannot update the image record", "err", err)
		}
	}
	return res
}

type imageOutcome int

const (
	imageKept imageOutcome = iota
	imageRemoved
	imageReleased
)

// pruneInspect is the part of an image inspect the pruner reads.
type pruneInspect struct {
	RepoTags    []string `json:"RepoTags"`
	RepoDigests []string `json:"RepoDigests"`
}

// settle decides what happens to the recorded image ref and, when it is to be
// removed, asks the daemon to remove it.
func (p *ImagePruner) settle(ctx context.Context, ref string, keepSet map[string]bool) imageOutcome {
	rctx, cancel := context.WithTimeout(ctx, imageDeleteTimeout)
	defer cancel()
	resp, err := sendOp(rctx, p.httpClient, p.baseURL, imageInspectOp(ref, ""))
	if err != nil {
		p.log.Warn("cannot inspect the work image; it stays recorded", "ref", ref, "err", err)
		return imageKept
	}
	var img pruneInspect
	var derr error
	status := resp.StatusCode
	if status == http.StatusOK {
		derr = json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&img)
	}
	resp.Body.Close()
	switch {
	case status == http.StatusNotFound:
		p.log.Info("the work image is already gone", "ref", ref)
		return imageRemoved
	case status != http.StatusOK:
		p.log.Warn("cannot inspect the work image; it stays recorded", "ref", ref, "status", status)
		return imageKept
	case derr != nil:
		p.log.Warn("cannot read the work image inspect; it stays recorded", "ref", ref, "err", derr)
		return imageKept
	}
	// The containerd image store lists a digest reference among RepoTags too;
	// only an entry without a digest is a tag.
	var tags []string
	for _, t := range img.RepoTags {
		if !strings.Contains(t, "@") {
			tags = append(tags, t)
		}
	}
	if len(tags) > 0 {
		p.log.Info("the work image is also held under a tag; it is left alone and no longer tracked", "ref", ref, "tags", tags)
		return imageReleased
	}
	for _, d := range img.RepoDigests {
		if n := normalizeRef(d); n != ref && keepSet[n] {
			p.log.Info("the work image is also reachable through a reference still in use; it stays recorded", "ref", ref, "other", n)
			return imageKept
		}
	}
	if p.remove(rctx, ref) {
		return imageRemoved
	}
	return imageKept
}

// remove asks the daemon to remove ref and reports whether the image is gone.
func (p *ImagePruner) remove(ctx context.Context, ref string) bool {
	resp, err := sendOp(ctx, p.httpClient, p.baseURL, imageDeleteOp(ref))
	if err != nil {
		p.log.Warn("cannot remove the work image; it stays recorded", "ref", ref, "err", err)
		return false
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	switch resp.StatusCode {
	case http.StatusOK:
		p.log.Info("removed an unused work image", "ref", ref)
		return true
	case http.StatusNotFound:
		p.log.Info("the work image is already gone", "ref", ref)
		return true
	case http.StatusConflict:
		p.log.Info("the work image is still in use; it stays recorded", "ref", ref)
		return false
	default:
		p.log.Warn("cannot remove the work image; it stays recorded", "ref", ref,
			"status", resp.StatusCode, "body", strings.TrimSpace(string(b)))
		return false
	}
}
