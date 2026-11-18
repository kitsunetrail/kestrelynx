package registry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"mime"
	"strings"
)

// defaultMaxArtifactManifestBytes caps an artifact manifest when the spec
// names no cap; such a manifest is a few hundred bytes.
const defaultMaxArtifactManifestBytes = 64 << 10

// ArtifactSpec says what the manifest of an artifact must look like and how
// much may be read.
type ArtifactSpec struct {
	ArtifactType     string // required value of the manifest's artifactType
	LayerMediaType   string // required media type of the single layer
	MaxManifestBytes int64  // cap of the manifest body; 0 means 64 KiB
	MaxLayerBytes    int64  // cap of the layer; must be > 0
}

// ArtifactManifest is the checked manifest of a one-layer artifact.
type ArtifactManifest struct {
	Digest      string // sha256:... of the manifest body
	LayerDigest string // sha256:... of the layer
	LayerSize   int64
}

// ArtifactManifest fetches the manifest tagged tag in repo and checks that it
// is an OCI image manifest of the artifact type spec names with exactly one
// layer of the layer media type spec names. The config is not read. URLs a
// layer lists for fetching it elsewhere are not read either: the layer is
// fetched from the repository alone, by its digest (ArtifactLayer).
//
// The body is verified against the digest the registry reports for it. A
// manifest of another kind, artifact type or layer shape is ErrUnsupported, a
// malformed one ErrBadResponse, and a layer larger than spec.MaxLayerBytes
// ErrTooLarge.
func (c *Client) ArtifactManifest(ctx context.Context, repo, tag string, spec ArtifactSpec) (ArtifactManifest, error) {
	if !tagRE.MatchString(tag) {
		return ArtifactManifest{}, fmt.Errorf("%w: tag %q", ErrInvalidInput, tag)
	}
	if spec.ArtifactType == "" || spec.LayerMediaType == "" || spec.MaxLayerBytes <= 0 {
		return ArtifactManifest{}, fmt.Errorf("%w: artifact spec needs an artifact type, a layer media type and a positive layer cap", ErrInvalidInput)
	}
	t, err := newTarget(repo)
	if err != nil {
		return ArtifactManifest{}, err
	}
	limit := spec.MaxManifestBytes
	if limit <= 0 {
		limit = defaultMaxArtifactManifestBytes
	}
	r, err := c.get(ctx, t, t.base()+"/manifests/"+tag, mediaOCIManifest, limit)
	if err != nil {
		return ArtifactManifest{}, fmt.Errorf("fetch artifact manifest %s:%s: %w", t.key(), tag, err)
	}
	sum := sha256.Sum256(r.body)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	if h := r.header.Get("Docker-Content-Digest"); digestRE.MatchString(h) && h != digest {
		return ArtifactManifest{}, fmt.Errorf("%w: %s reported %s for content hashing to %s", ErrDigestMismatch, t.host, h, digest)
	}

	var doc struct {
		SchemaVersion int    `json:"schemaVersion"`
		MediaType     string `json:"mediaType"`
		ArtifactType  string `json:"artifactType"`
		Layers        []struct {
			MediaType string `json:"mediaType"`
			Digest    string `json:"digest"`
			Size      int64  `json:"size"`
		} `json:"layers"`
	}
	if err := json.Unmarshal(r.body, &doc); err != nil {
		return ArtifactManifest{}, fmt.Errorf("%w: artifact manifest from %s is not JSON", ErrBadResponse, t.host)
	}
	mt, _, _ := mime.ParseMediaType(r.header.Get("Content-Type"))
	switch mt {
	case "", "application/json", "text/plain", "application/octet-stream":
		mt = strings.TrimSpace(doc.MediaType)
	}
	if mt != mediaOCIManifest {
		return ArtifactManifest{}, fmt.Errorf("%w: media type %q from %s is not an OCI image manifest", ErrUnsupported, mt, t.host)
	}
	if doc.MediaType != "" && doc.MediaType != mt {
		return ArtifactManifest{}, fmt.Errorf("%w: %s declares media type %q in a %q response", ErrBadResponse, t.host, doc.MediaType, mt)
	}
	if doc.SchemaVersion != 2 {
		return ArtifactManifest{}, fmt.Errorf("%w: schemaVersion %d from %s", ErrUnsupported, doc.SchemaVersion, t.host)
	}
	if doc.ArtifactType != spec.ArtifactType {
		return ArtifactManifest{}, fmt.Errorf("%w: artifact type %q from %s", ErrUnsupported, doc.ArtifactType, t.host)
	}
	if len(doc.Layers) != 1 {
		return ArtifactManifest{}, fmt.Errorf("%w: artifact from %s has %d layers, want 1", ErrUnsupported, t.host, len(doc.Layers))
	}
	l := doc.Layers[0]
	if l.MediaType != spec.LayerMediaType {
		return ArtifactManifest{}, fmt.Errorf("%w: layer media type %q from %s", ErrUnsupported, l.MediaType, t.host)
	}
	if !digestRE.MatchString(l.Digest) {
		return ArtifactManifest{}, fmt.Errorf("%w: artifact manifest from %s holds an unusable layer digest", ErrBadResponse, t.host)
	}
	if l.Size <= 0 {
		return ArtifactManifest{}, fmt.Errorf("%w: artifact manifest from %s holds an unusable layer size %d", ErrBadResponse, t.host, l.Size)
	}
	if l.Size > spec.MaxLayerBytes {
		return ArtifactManifest{}, fmt.Errorf("%w: layer of %d bytes from %s (limit %d)", ErrTooLarge, l.Size, t.host, spec.MaxLayerBytes)
	}
	return ArtifactManifest{Digest: digest, LayerDigest: l.Digest, LayerSize: l.Size}, nil
}

// ArtifactLayer fetches the layer m names from repo. At most
// min(spec.MaxLayerBytes, m.LayerSize) bytes are read; more is ErrTooLarge. A
// body of another length than m.LayerSize is ErrBadResponse and one that does
// not hash to m.LayerDigest is ErrDigestMismatch.
func (c *Client) ArtifactLayer(ctx context.Context, repo string, m ArtifactManifest, spec ArtifactSpec) ([]byte, error) {
	if !digestRE.MatchString(m.LayerDigest) {
		return nil, fmt.Errorf("%w: layer digest %q", ErrInvalidInput, m.LayerDigest)
	}
	if spec.MaxLayerBytes <= 0 || m.LayerSize <= 0 {
		return nil, fmt.Errorf("%w: layer size %d and cap %d must be positive", ErrInvalidInput, m.LayerSize, spec.MaxLayerBytes)
	}
	t, err := newTarget(repo)
	if err != nil {
		return nil, err
	}
	limit := min(spec.MaxLayerBytes, m.LayerSize)
	r, err := c.get(ctx, t, t.base()+"/blobs/"+m.LayerDigest, "", limit)
	if err != nil {
		return nil, fmt.Errorf("fetch artifact layer %s: %w", m.LayerDigest, err)
	}
	if int64(len(r.body)) != m.LayerSize {
		return nil, fmt.Errorf("%w: %s sent %d bytes for a layer of %d", ErrBadResponse, t.host, len(r.body), m.LayerSize)
	}
	sum := sha256.Sum256(r.body)
	if got := "sha256:" + hex.EncodeToString(sum[:]); got != m.LayerDigest {
		return nil, fmt.Errorf("%w: %s sent layer for %s that hashes to %s", ErrDigestMismatch, t.host, m.LayerDigest, got)
	}
	return r.body, nil
}
