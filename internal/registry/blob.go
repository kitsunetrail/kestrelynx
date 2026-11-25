package registry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"net/http"
	"sync"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
)

// Layer is one entry of an image manifest's layers list.
type Layer struct {
	MediaType string
	Digest    string
	Size      int64
	// HasURLs is true when the manifest lists external URLs for the layer
	// (a foreign layer). The client never fetches from them.
	HasURLs bool
}

// ImageLayers is the verified platform manifest of an image: its ordered
// layers and the image config's rootfs.diff_ids.
type ImageLayers struct {
	// ManifestDigest is the image manifest of the requested platform.
	ManifestDigest string
	ConfigDigest   string
	// Layers are the manifest's layers, bottom first.
	Layers []Layer
	// DiffIDs are the verified config's rootfs.diff_ids, bottom first.
	DiffIDs []string
}

// ImageLayers resolves manifestDigest, a digest of an image manifest or of an
// index that holds one for platform, and returns the layers of the platform's
// manifest together with the diff_ids of its verified config. The manifest,
// the index entry choice and the config are checked as Resolve checks them.
func (c *Client) ImageLayers(ctx context.Context, repo, manifestDigest string, platform inventory.Platform) (ImageLayers, error) {
	if !digestRE.MatchString(manifestDigest) {
		return ImageLayers{}, fmt.Errorf("%w: digest %q", ErrInvalidInput, manifestDigest)
	}
	res, err := c.Resolve(ctx, repo, manifestDigest, platform)
	if err != nil {
		return ImageLayers{}, err
	}
	return ImageLayers{
		ManifestDigest: res.ManifestDigest,
		ConfigDigest:   res.ConfigDigest,
		Layers:         res.Layers,
		DiffIDs:        res.DiffIDs,
	}, nil
}

// sendStream sends one GET and leaves the body of a successful response
// unread. It has no timeout of its own: the body lives as long as ctx does.
// Error responses are read, truncated, and closed. The request goes through
// the client's transport, so the address policy, the redirect policy and the
// credential handling are those of every other request.
func (c *Client) sendStream(ctx context.Context, rawURL, authz string) (*response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadResponse, err)
	}
	// A blob is hashed as stored; the transport must not decode it.
	req.Header.Set("Accept-Encoding", "identity")
	if authz != "" {
		req.Header.Set("Authorization", authz)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("registry: GET %s: %w", redactURL(rawURL), redactURLError(err))
	}
	redirected := resp.Request != nil && resp.Request.URL.String() != req.URL.String()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		defer resp.Body.Close()
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
		if err != nil {
			return nil, fmt.Errorf("registry: read %s: %w", redactURL(rawURL), redactURLError(err))
		}
		return &response{status: resp.StatusCode, header: resp.Header, body: body, redirected: redirected}, nil
	}
	return &response{status: resp.StatusCode, header: resp.Header, redirected: redirected, stream: resp.Body}, nil
}

func (c *Client) onceStream(ctx context.Context, rawURL, authz string) (*response, bool, error) {
	if err := c.budget.take(); err != nil {
		return nil, false, err
	}
	r, err := c.sendStream(ctx, rawURL, authz)
	return r, true, err
}

// OpenBlob starts streaming the blob digest of repo, which the manifest says
// is size bytes long. The returned reader checks length and digest as the
// bytes pass: reading more than size bytes, or reaching the end at another
// length or another digest, fails with ErrBadResponse or ErrDigestMismatch
// instead of io.EOF. The body is never buffered whole and the only deadline
// is ctx's, so a large blob is not cut off by the per-request timeout.
// Authentication, address checks and redirects are those of the other
// requests of the client. The caller must Close the reader.
func (c *Client) OpenBlob(ctx context.Context, repo, digest string, size int64) (*BlobReader, error) {
	if !digestRE.MatchString(digest) {
		return nil, fmt.Errorf("%w: blob digest %q", ErrInvalidInput, digest)
	}
	if size < 0 {
		return nil, fmt.Errorf("%w: blob size %d", ErrInvalidInput, size)
	}
	t, err := newTarget(repo)
	if err != nil {
		return nil, err
	}
	rawURL := t.base() + "/blobs/" + digest
	r, _, err := c.getWith(ctx, t, func(authz string) (*response, bool, error) {
		return c.onceStream(ctx, rawURL, authz)
	})
	if err != nil {
		return nil, fmt.Errorf("fetch blob %s: %w", digest, err)
	}
	return &BlobReader{rc: r.stream, h: sha256.New(), digest: digest, size: size, host: t.host}, nil
}

// BlobReader streams one blob and verifies it. It is not safe for concurrent
// use.
type BlobReader struct {
	rc     io.ReadCloser
	h      hash.Hash
	digest string
	size   int64
	host   string

	n    int64
	done bool
	err  error // sticky verification result once the stream ended or failed

	closeOnce sync.Once
}

// Read implements io.Reader. The error at the end of the stream is io.EOF
// only when the whole blob had the expected length and digest.
func (b *BlobReader) Read(p []byte) (int, error) {
	if b.err != nil {
		return 0, b.err
	}
	if b.done {
		return 0, io.EOF
	}
	if len(p) == 0 {
		return 0, nil
	}
	// One byte more than size is read so an overlong body is noticed.
	if room := b.size + 1 - b.n; int64(len(p)) > room {
		p = p[:room]
	}
	n, err := b.rc.Read(p)
	b.n += int64(n)
	b.h.Write(p[:n])
	if b.n > b.size {
		b.err = fmt.Errorf("%w: %s sent more than the %d bytes announced for %s", ErrBadResponse, b.host, b.size, b.digest)
		return n, b.err
	}
	if err == io.EOF {
		switch got := "sha256:" + hex.EncodeToString(b.h.Sum(nil)); {
		case b.n != b.size:
			b.err = fmt.Errorf("%w: %s sent %d bytes for %s, announced %d", ErrBadResponse, b.host, b.n, b.digest, b.size)
		case got != b.digest:
			b.err = fmt.Errorf("%w: %s sent a blob for %s that hashes to %s", ErrDigestMismatch, b.host, b.digest, got)
		default:
			b.done = true
			return n, io.EOF
		}
		return n, b.err
	}
	return n, err
}

// Finish reads what is left of the blob and returns nil only when all of it
// arrived with the expected length and digest. A consumer that stops reading
// at the end of its own format (a gzip stream, for example) calls it before
// trusting what it read.
func (b *BlobReader) Finish() error {
	if b.err != nil {
		return b.err
	}
	_, err := io.Copy(io.Discard, b)
	return err
}

// Close releases the connection.
func (b *BlobReader) Close() error {
	var err error
	b.closeOnce.Do(func() { err = b.rc.Close() })
	return err
}
