package imagefs

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
)

// SummaryVersion is the format version of LayerSummary. A cached summary of
// another version is not used.
const SummaryVersion = 1

// Entry types in a layer summary.
const (
	TypeFile     = "f" // regular file
	TypeDir      = "d"
	TypeSymlink  = "l"
	TypeHardlink = "h"
	TypeOther    = "o" // device, FIFO and the like
	TypeWhiteout = "w" // the path named is deleted from the layers below
	TypeOpaque   = "q" // the directory named loses everything from the layers below
)

// Entry is one item of a layer, with its path normalized (no leading "./" or
// "/", no "." or ".." elements).
type Entry struct {
	Path string `json:"p"`
	Type string `json:"t"`
	// Link is the target of a symlink as written, or the normalized path of
	// the target of a hardlink.
	Link string `json:"l,omitempty"`
	// HasContent is true when Content holds the file's content: a regular
	// file named "release" of at most MaxReleaseBytes, or a hardlink to one.
	HasContent bool   `json:"hc,omitempty"`
	Content    string `json:"c,omitempty"`
	// Big marks a file named "release" larger than MaxReleaseBytes: it
	// replaces any release below it, and it is not a JDK release.
	Big bool `json:"b,omitempty"`
	// Unreadable marks a hardlink named "release" whose content cannot be
	// read from this layer.
	Unreadable bool `json:"u,omitempty"`
}

// LayerSummary is what is kept of one layer, entries in tar order.
type LayerSummary struct {
	Version int     `json:"v"`
	Entries []Entry `json:"e"`
}

// Errors of Summarize. All of them are permanent for the layer: reading it
// again gives the same answer.
var (
	// ErrUnsupportedCompression: the layer is not gzip or an uncompressed tar.
	ErrUnsupportedCompression = errors.New("imagefs: unsupported layer compression")
	// ErrCorruptLayer: the layer is not a readable tar (or gzip) stream.
	ErrCorruptLayer = errors.New("imagefs: corrupt layer")
	// ErrSummaryLimit: the summary would pass the entry or size limit.
	ErrSummaryLimit = errors.New("imagefs: layer summary over the limit")
	// ErrLayerTooLarge: the decompressed layer passes the size limit.
	ErrLayerTooLarge = errors.New("imagefs: decompressed layer over the limit")
)

const whiteoutPrefix = ".wh."
const opaqueMarker = ".wh..wh..opq"

// entryOverhead is what an entry costs in the summary size beyond its strings.
const entryOverhead = 24

// capReader fails with ErrLayerTooLarge once more than max bytes were read.
type capReader struct {
	r    io.Reader
	left int64
}

func (c *capReader) Read(p []byte) (int, error) {
	if c.left < 0 {
		return 0, ErrLayerTooLarge
	}
	if int64(len(p)) > c.left+1 {
		p = p[:c.left+1]
	}
	n, err := c.r.Read(p)
	c.left -= int64(n)
	if c.left < 0 {
		return n, ErrLayerTooLarge
	}
	return n, err
}

// classify turns the failures that say the data itself is bad into
// ErrCorruptLayer. Anything else (a read error of the source, an early end of
// the stream) is returned as it is: reading again may succeed.
func classify(err error) error {
	var corrupt flate.CorruptInputError
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrLayerTooLarge), errors.Is(err, ErrSummaryLimit), errors.Is(err, ErrUnsupportedCompression):
		return err
	case errors.Is(err, tar.ErrHeader), errors.Is(err, gzip.ErrHeader), errors.Is(err, gzip.ErrChecksum), errors.As(err, &corrupt):
		return fmt.Errorf("%w: %v", ErrCorruptLayer, err)
	}
	return err
}

// NormalizePath strips a leading "./" and "/" and resolves "." and ".."
// lexically against the root, so no path leaves it. The root itself is "".
func NormalizePath(p string) string {
	p = path.Clean("/" + p)
	return strings.TrimPrefix(p, "/")
}

// Summarize reads one layer, gzip-compressed or an uncompressed tar, to its
// end and returns its summary and the sha256 of the decompressed stream (the
// layer's diffID, "sha256:<hex>"). Zstd and every other compression is
// ErrUnsupportedCompression. A layer that decompresses to more than
// limits.MaxLayerBytes is ErrLayerTooLarge; one with more than
// limits.MaxEntries entries or a summary over limits.MaxSummaryBytes is
// ErrSummaryLimit. Errors that come from r itself are returned unchanged.
func Summarize(r io.Reader, limits Limits) (LayerSummary, string, error) {
	limits = limits.withDefaults()
	br := bufio.NewReaderSize(r, 64<<10)
	magic, err := br.Peek(6)
	if err != nil && err != io.EOF {
		return LayerSummary{}, "", err
	}
	var plain io.Reader = br
	switch {
	case len(magic) >= 2 && magic[0] == 0x1f && magic[1] == 0x8b:
		gz, err := gzip.NewReader(br)
		if err != nil {
			return LayerSummary{}, "", classify(err)
		}
		defer gz.Close()
		plain = gz
	case bytes.HasPrefix(magic, []byte{0x28, 0xb5, 0x2f, 0xfd}):
		return LayerSummary{}, "", fmt.Errorf("%w: zstd", ErrUnsupportedCompression)
	case bytes.HasPrefix(magic, []byte{0xfd, '7', 'z', 'X', 'Z', 0x00}):
		return LayerSummary{}, "", fmt.Errorf("%w: xz", ErrUnsupportedCompression)
	case bytes.HasPrefix(magic, []byte("BZh")):
		return LayerSummary{}, "", fmt.Errorf("%w: bzip2", ErrUnsupportedCompression)
	case bytes.HasPrefix(magic, []byte{0x04, 0x22, 0x4d, 0x18}):
		return LayerSummary{}, "", fmt.Errorf("%w: lz4", ErrUnsupportedCompression)
	}
	h := sha256.New()
	tee := io.TeeReader(&capReader{r: plain, left: limits.MaxLayerBytes}, h)
	sum, err := summarizeTar(tar.NewReader(tee), limits)
	if err != nil {
		return LayerSummary{}, "", classify(err)
	}
	// The tar reader stops at its end marker; the diffID covers the rest too.
	if _, err := io.Copy(io.Discard, tee); err != nil {
		return LayerSummary{}, "", classify(err)
	}
	return sum, "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

type releaseInfo struct {
	content string
	has     bool
}

func summarizeTar(tr *tar.Reader, limits Limits) (LayerSummary, error) {
	sum := LayerSummary{Version: SummaryVersion}
	releases := map[string]releaseInfo{}
	var size int64
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return sum, nil
		}
		if err != nil {
			return LayerSummary{}, err
		}
		p := NormalizePath(hdr.Name)
		if p == "" {
			continue
		}
		dir, base := path.Split(p)
		dir = strings.TrimSuffix(dir, "/")
		var e Entry
		switch {
		case hdr.Typeflag == tar.TypeXGlobalHeader:
			continue
		case base == opaqueMarker:
			e = Entry{Path: dir, Type: TypeOpaque}
		case strings.HasPrefix(base, whiteoutPrefix+".wh."):
			continue // other file-system bookkeeping of the aufs family
		case strings.HasPrefix(base, whiteoutPrefix) && len(base) > len(whiteoutPrefix):
			e = Entry{Path: path.Join(dir, base[len(whiteoutPrefix):]), Type: TypeWhiteout}
		default:
			e = Entry{Path: p}
			switch hdr.Typeflag {
			case tar.TypeReg, tar.TypeRegA:
				e.Type = TypeFile
				if base == "release" {
					if hdr.Size > limits.MaxReleaseBytes {
						e.Big = true
					} else {
						b, err := io.ReadAll(io.LimitReader(tr, limits.MaxReleaseBytes+1))
						if err != nil {
							return LayerSummary{}, err
						}
						e.HasContent, e.Content = true, string(b)
					}
					releases[detach(p)] = releaseInfo{content: e.Content, has: e.HasContent}
				}
			case tar.TypeDir:
				e.Type = TypeDir
			case tar.TypeSymlink:
				e.Type, e.Link = TypeSymlink, hdr.Linkname
			case tar.TypeLink:
				e.Type, e.Link = TypeHardlink, NormalizePath(hdr.Linkname)
				if base == "release" {
					if info, ok := releases[e.Link]; ok && info.has && path.Base(e.Link) == "release" {
						e.HasContent, e.Content = true, info.content
						releases[detach(p)] = info
					} else {
						e.Unreadable = true
					}
				}
			default:
				e.Type = TypeOther
			}
		}
		if len(sum.Entries) >= limits.MaxEntries {
			return LayerSummary{}, fmt.Errorf("%w: more than %d entries", ErrSummaryLimit, limits.MaxEntries)
		}
		size += int64(len(e.Path)+len(e.Link)+len(e.Content)) + entryOverhead
		if size > limits.MaxSummaryBytes {
			return LayerSummary{}, fmt.Errorf("%w: more than %d bytes", ErrSummaryLimit, limits.MaxSummaryBytes)
		}
		// A string cut out of a larger one keeps all of it alive; what the
		// summary keeps is its own copy, of the length that was counted.
		if beforeDetach != nil {
			beforeDetach(&e)
		}
		e.Path, e.Link = detach(e.Path), detach(e.Link)
		sum.Entries = append(sum.Entries, e)
	}
}

// beforeDetach, when set by a test, sees each entry just before its strings
// are copied.
var beforeDetach func(*Entry)

// detach returns a copy of s that shares memory with nothing else.
func detach(s string) string { return strings.Clone(s) }
