package imagefs

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"slices"
	"strings"
)

// maxExportEntries bounds the entries of a Docker export read.
const maxExportEntries = 200000

var blobEntryRE = regexp.MustCompile(`^blobs/sha256/([0-9a-f]{64})$`)

// errExportInconsistent: the export names a blob by a digest its content
// does not have.
var errExportInconsistent = errors.New("imagefs: the export holds a blob that does not match its name")

// parseExport reads the outer tar of a Docker export to its end and returns
// the outcome for the target. Layer blobs are summarized as they stream by
// (those whose summary and digest mapping are cached are only read through),
// each JSON blob (up to the JSON limit) is judged as it is read and only the
// digests of the configs whose platform and layer list match the target are
// kept; in the end the one such config selects the layers. Entries
// are recognized by name and content, never by the order or the manifest
// files of either export layout: the OCI layout (index.json,
// blobs/sha256/<hex>) and the legacy one (manifest.json, <id>.json,
// <id>/layer.tar) both work, and a legacy layer.tar that is a symbolic link
// to another one is a duplicate of a layer already read.
func (s *runState) parseExport(r io.Reader) Outcome {
	want := map[string]bool{}
	for _, d := range s.t.DiffIDs {
		want[d] = true
	}
	pool := map[string]LayerSummary{}
	var match configMatch // the configs that fit the target
	var layerErr *Outcome // the first permanent failure of a layer blob

	tr := tar.NewReader(r)
	entries := 0
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return s.exportError(err)
		}
		if entries++; entries > maxExportEntries {
			return permanent(ReasonExportInconsistent, fmt.Errorf("the export has more than %d entries", maxExportEntries), true)
		}
		// A sparse entry has a logical size the stream does not hold: the reader
		// makes the holes out of nothing, to read or to skip, outside every
		// byte budget. No export of an image has one.
		if isSparse(hdr) {
			return permanent(ReasonExportInconsistent, fmt.Errorf("%w: %q is a sparse entry", errExportInconsistent, hdr.Name), true)
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			continue
		}
		name := NormalizePath(hdr.Name)
		base := path.Base(name)
		m := blobEntryRE.FindStringSubmatch(name)
		switch {
		case m != nil:
			digest := "sha256:" + m[1]
			br := bufio.NewReaderSize(tr, 4096)
			head, _ := br.Peek(512)
			switch blobKind(head, hdr.Size) {
			case kindLayer:
				if out, fatal := s.layerBlob(br, digest, want, pool, &layerErr); fatal {
					return out
				}
			case kindJSON:
				if hdr.Size <= s.limits.MaxJSONBytes {
					if out, fatal := s.jsonBlob(br, &match); fatal {
						return out
					}
				}
			}
		case base == "layer.tar":
			if out, fatal := s.layerBlob(tr, "", want, pool, &layerErr); fatal {
				return out
			}
		case strings.HasSuffix(name, ".json") && hdr.Size <= s.limits.MaxJSONBytes:
			if out, fatal := s.jsonBlob(tr, &match); fatal {
				return out
			}
		}
	}

	if match.first == "" || match.many {
		n := "no"
		if match.many {
			n = "more than one"
		}
		return permanent(ReasonNoMatchingConfig, fmt.Errorf("the export of %s holds %s config for %s/%s with the scanned layers", s.t.dockerID(), n, s.t.Platform.OS, s.t.Platform.Architecture), true)
	}
	refs := make([]LayerRef, len(s.t.DiffIDs))
	for i, d := range s.t.DiffIDs {
		sum, ok := pool[d]
		if !ok {
			if layerErr != nil {
				return *layerErr
			}
			return permanent(ReasonLayerMissing, fmt.Errorf("the export does not hold layer %s", d), true)
		}
		refs[i] = LayerRef{DiffID: d, Summary: sum}
	}
	return s.finish(match.first, refs)
}

// isSparse reports whether a tar entry is a GNU or PAX sparse file.
func isSparse(h *tar.Header) bool {
	if h.Typeflag == tar.TypeGNUSparse {
		return true
	}
	for k := range h.PAXRecords {
		if strings.HasPrefix(k, "GNU.sparse.") {
			return true
		}
	}
	return false
}

// errEntryTooLarge: one entry of the export is longer than a layer can be.
var errEntryTooLarge = errors.New("imagefs: an export entry is longer than a layer can be")

// entryReader passes the bytes of one entry through, failing when ctx ends or
// when more than max bytes were read.
type entryReader struct {
	ctx  context.Context
	r    io.Reader
	left int64
}

func (e *entryReader) Read(p []byte) (int, error) {
	if err := e.ctx.Err(); err != nil {
		return 0, err
	}
	if e.left <= 0 {
		// An entry of exactly the cap is fine: it is too long only when a
		// further byte exists.
		var one [1]byte
		n, err := e.r.Read(one[:])
		switch {
		case n > 0:
			return 0, errEntryTooLarge
		case err == nil:
			return 0, io.ErrNoProgress
		}
		return 0, err
	}
	if int64(len(p)) > e.left {
		p = p[:e.left]
	}
	n, err := e.r.Read(p)
	e.left -= int64(n)
	return n, err
}

// maxEntryBytes is the most one layer entry of an export may hold: the bound
// of a decompressed layer, plus what an incompressible one adds in framing.
func maxEntryBytes(l Limits) int64 { return l.MaxLayerBytes + l.MaxLayerBytes/16 + 1<<20 }

// exportError classifies a failure to read the outer stream.
func (s *runState) exportError(err error) Outcome {
	if errors.Is(err, errEntryTooLarge) {
		return permanent(ReasonExportInconsistent, err, true)
	}
	if errors.Is(err, errBudget) {
		return deferred(ReasonBudget, err)
	}
	if errors.Is(err, tar.ErrHeader) {
		return permanent(ReasonExportInconsistent, err, true)
	}
	return s.transient(err)
}

type blobType int

const (
	kindOther blobType = iota
	kindLayer
	kindJSON
)

// blobKind guesses what a blob is from its first bytes: a compressed or a
// plain tar layer, a JSON document, or something else (ignored).
func blobKind(head []byte, size int64) blobType {
	switch {
	case len(head) >= 2 && head[0] == 0x1f && head[1] == 0x8b,
		bytes.HasPrefix(head, []byte{0x28, 0xb5, 0x2f, 0xfd}),
		bytes.HasPrefix(head, []byte{0xfd, '7', 'z', 'X', 'Z', 0x00}),
		bytes.HasPrefix(head, []byte("BZh")):
		return kindLayer
	case len(head) >= 262 && string(head[257:262]) == "ustar":
		return kindLayer
	case size >= 512 && len(head) >= 512 && bytes.Count(head, []byte{0}) == 512:
		return kindLayer // a tar of nothing
	}
	if t := bytes.TrimLeft(head, " \t\r\n"); len(t) > 0 && t[0] == '{' {
		return kindJSON
	}
	return kindOther
}

// layerBlob reads one layer entry. blobDigest is "" for entries that have no
// digest in their name. fatal is true when the whole read must stop.
func (s *runState) layerBlob(r io.Reader, blobDigest string, want map[string]bool, pool map[string]LayerSummary, layerErr **Outcome) (out Outcome, fatal bool) {
	r = &entryReader{ctx: s.ctx, r: r, left: maxEntryBytes(s.limits)}
	raw := sha256.New()
	if blobDigest != "" {
		// A blob already verified to decompress to a wanted layer whose
		// summary is cached is only read through, and checked against its name.
		if diffID, ok := s.r.Cache.GetBlob(blobDigest); ok && want[diffID] {
			sum, ok, err := s.cachedSummary(diffID)
			if err != nil {
				return permanent(ReasonSummaryLimit, err, true), true
			}
			if ok {
				if _, err := io.Copy(raw, r); err != nil {
					return s.exportError(err), true
				}
				if "sha256:"+hex.EncodeToString(raw.Sum(nil)) != blobDigest {
					return permanent(ReasonExportInconsistent, fmt.Errorf("%w: %s", errExportInconsistent, blobDigest), true), true
				}
				if _, dup := pool[diffID]; !dup {
					s.stats.LayersCached++
				}
				pool[diffID] = sum
				return Outcome{}, false
			}
		}
	}
	tee := io.TeeReader(r, raw)
	sum, diffID, err := Summarize(tee, s.limits)
	if err == nil {
		// The compressed stream may continue past what the decompressor read.
		_, err = io.Copy(io.Discard, tee)
	}
	if err != nil {
		if o, ok := layerError(err); ok {
			// A blob named by its digest is read to its end first: a mismatch
			// says the transfer was bad, not the layer, and goes to the
			// export's strike rule. Only a failure of verified content is
			// kept as the layer's own.
			if blobDigest != "" {
				if _, derr := io.Copy(io.Discard, tee); derr != nil {
					return s.exportError(derr), true
				}
				if "sha256:"+hex.EncodeToString(raw.Sum(nil)) != blobDigest {
					return permanent(ReasonExportInconsistent, fmt.Errorf("%w: %s", errExportInconsistent, blobDigest), true), true
				}
			}
			// It matters only if this layer turns out to be one of the target's.
			if *layerErr == nil {
				o := o
				*layerErr = &o
			}
			// The rest of the entry is skipped by the tar reader.
			return Outcome{}, false
		}
		return s.exportError(err), true
	}
	if blobDigest != "" && "sha256:"+hex.EncodeToString(raw.Sum(nil)) != blobDigest {
		return permanent(ReasonExportInconsistent, fmt.Errorf("%w: %s", errExportInconsistent, blobDigest), true), true
	}
	if !want[diffID] {
		return Outcome{}, false
	}
	if err := s.holdSummary(diffID, sum); err != nil {
		return permanent(ReasonSummaryLimit, err, true), true
	}
	_, dup := pool[diffID]
	if !dup {
		s.stats.LayersRead++
	}
	pool[diffID] = s.sums[diffID]
	if err := s.r.Cache.PutLayer(diffID, sum); err != nil {
		s.r.log().Warn("imagefs: store a layer summary", "error", err)
	} else {
		if !dup && !s.r.Cache.off() {
			// Kept for the next cycle: a layer repeated in the export counts once.
			s.stats.LayersKept++
		}
		if blobDigest != "" {
			if err := s.r.Cache.PutBlob(blobDigest, diffID); err != nil {
				s.r.log().Warn("imagefs: store a blob mapping", "error", err)
			}
		}
	}
	return Outcome{}, false
}

// configMatch is what is known of the configs that fit the target: the first
// digest, and whether a different one was seen as well. Nothing more is
// needed to tell none, one and several apart.
type configMatch struct {
	first string
	many  bool
}

// jsonBlob reads a JSON entry; when it is an image config of the target's
// platform and layers its digest is noted in match. Any other JSON is
// dropped as soon as it is read.
func (s *runState) jsonBlob(r io.Reader, match *configMatch) (out Outcome, fatal bool) {
	b, err := io.ReadAll(io.LimitReader(r, s.limits.MaxJSONBytes+1))
	if err != nil {
		return s.exportError(err), true
	}
	if int64(len(b)) > s.limits.MaxJSONBytes {
		return Outcome{}, false
	}
	var c struct {
		OS           string `json:"os"`
		Architecture string `json:"architecture"`
		Variant      string `json:"variant"`
		RootFS       struct {
			DiffIDs []string `json:"diff_ids"`
		} `json:"rootfs"`
	}
	if json.Unmarshal(b, &c) != nil || len(c.RootFS.DiffIDs) == 0 {
		return Outcome{}, false // an index, a manifest, an attestation...
	}
	p := s.t.Platform
	if c.OS != p.OS || c.Architecture != p.Architecture || c.Variant != p.Variant || !slices.Equal(c.RootFS.DiffIDs, s.t.DiffIDs) {
		return Outcome{}, false
	}
	sum := sha256.Sum256(b)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	switch {
	case match.first == "":
		match.first = digest
	case match.first != digest:
		match.many = true
	}
	return Outcome{}, false
}
