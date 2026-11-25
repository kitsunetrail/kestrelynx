package imagefs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"

	"github.com/kitsunetrail/kestrelynx/internal/docker"
	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/registry"
)

// RegistryAPI is what Reader needs of a registry client; *registry.Client
// implements it.
type RegistryAPI interface {
	ImageLayers(ctx context.Context, repo, manifestDigest string, platform inventory.Platform) (registry.ImageLayers, error)
	OpenBlob(ctx context.Context, repo, digest string, size int64) (*registry.BlobReader, error)
}

// DockerAPI is what Reader needs of a Docker client; *docker.Client
// implements it.
type DockerAPI interface {
	ExportImage(ctx context.Context, id string, platform inventory.Platform) (io.ReadCloser, error)
}

// Route is how an image is fetched.
type Route string

const (
	RouteDocker   Route = "docker"
	RouteRegistry Route = "registry"
)

// Target is one image to read, fixed to what the scan saw: a Docker image
// fetched by ID, or a registry image pinned by digest. An image known only by
// a mutable reference cannot be expressed.
type Target struct {
	Route Route
	// FetchID is the ID passed to the Docker export (RouteDocker): the image
	// config digest or a manifest list digest, "sha256:<hex>" or bare hex.
	FetchID string
	// Repository and ManifestDigest pin a registry image (RouteRegistry): the
	// digest of the platform's manifest or of an index that holds it.
	Repository     string
	ManifestDigest string
	// Platform is the platform that was scanned.
	Platform inventory.Platform
	// DiffIDs are the layer diffIDs the scan saw, bottom first. The image that
	// is read must have exactly these.
	DiffIDs []string
	// JavaHome is the JAVA_HOME of the image's environment, "" when it has
	// none. It is resolved inside the image's root once the layers are
	// stacked; the real path is in Outcome.JavaHome.
	JavaHome string
}

// DockerTarget is a Target for the Docker route.
func DockerTarget(fetchID string, platform inventory.Platform, diffIDs []string) Target {
	return Target{Route: RouteDocker, FetchID: fetchID, Platform: platform, DiffIDs: diffIDs}
}

// RegistryTarget is a Target for the registry route.
func RegistryTarget(repo, manifestDigest string, platform inventory.Platform, diffIDs []string) Target {
	return Target{Route: RouteRegistry, Repository: repo, ManifestDigest: manifestDigest, Platform: platform, DiffIDs: diffIDs}
}

func (t Target) dockerID() string {
	if digestRE.MatchString(t.FetchID) {
		return t.FetchID
	}
	return "sha256:" + t.FetchID
}

func (t Target) validate() error {
	if !t.Platform.Known() {
		return errors.New("the platform is not known")
	}
	if len(t.DiffIDs) == 0 {
		return errors.New("no layer diffIDs")
	}
	for _, d := range t.DiffIDs {
		if !digestRE.MatchString(d) {
			return fmt.Errorf("bad diffID %q", d)
		}
	}
	switch t.Route {
	case RouteDocker:
		if !digestRE.MatchString(t.dockerID()) {
			return fmt.Errorf("bad image id %q", t.FetchID)
		}
	case RouteRegistry:
		if t.Repository == "" || !digestRE.MatchString(t.ManifestDigest) {
			return errors.New("a registry target needs a repository and a pinned manifest digest")
		}
	default:
		return fmt.Errorf("unknown route %q", t.Route)
	}
	return nil
}

// key identifies the route and what it fetches, for "cannot complete"
// records and the timeout counter.
func (t Target) key() string {
	p := t.Platform
	plat := p.OS + "/" + p.Architecture + "/" + p.Variant
	if t.Route == RouteDocker {
		return "docker|" + t.dockerID() + "|" + plat
	}
	return "registry|" + t.Repository + "@" + t.ManifestDigest + "|" + plat
}

// Kind is how a read ended.
type Kind int

const (
	// Complete: the JDKs of the image are known (there may be none).
	Complete Kind = iota
	// Deferred: not finished; try again in the next cycle.
	Deferred
	// Permanent: this image cannot be read through this route under the
	// current limits and program; do not try again.
	Permanent
)

func (k Kind) String() string {
	switch k {
	case Complete:
		return "complete"
	case Deferred:
		return "deferred"
	case Permanent:
		return "permanent"
	}
	return "unknown"
}

// Reason says why a read was deferred or permanent.
type Reason string

// Reasons of a Deferred outcome.
const (
	ReasonBudget    Reason = "budget"    // the cycle's byte budget is used up
	ReasonTimeout   Reason = "timeout"   // the image's time limit passed
	ReasonTransient Reason = "transient" // a fetch failed in a way that may pass
	ReasonCancelled Reason = "cancelled" // the caller's context ended
)

// ReasonBlobMismatch is a Deferred reason as well: a registry blob did not
// arrive with the digest and size its manifest names, or did not decompress,
// so what it held cannot be trusted. The third such end in a row for one
// image is Permanent.

// Reasons of a Permanent outcome.
const (
	ReasonInvalidTarget          Reason = "invalid_target"
	ReasonUnsupportedCompression Reason = "unsupported_compression"
	ReasonUnsupportedMediaType   Reason = "unsupported_media_type"
	ReasonForeignLayer           Reason = "foreign_layer"
	ReasonCorruptLayer           Reason = "corrupt_layer"
	ReasonSummaryLimit           Reason = "summary_limit"
	ReasonLayerTooLarge          Reason = "layer_too_large"
	ReasonReleaseUnreadable      Reason = "release_unreadable"
	ReasonBlobOverBudget         Reason = "blob_over_budget"
	ReasonExportOverBudget       Reason = "export_over_budget"
	ReasonTimeoutRepeated        Reason = "timeout_repeated"
	ReasonTimeoutNoProgress      Reason = "timeout_no_progress"
	ReasonNoMatchingConfig       Reason = "no_matching_config"
	ReasonLayerMissing           Reason = "layer_missing"
	ReasonDiffIDMismatch         Reason = "diff_id_mismatch"
	ReasonBlobMismatch           Reason = "blob_mismatch" // also Deferred, see below
	ReasonDiffIDsDiffer          Reason = "diff_ids_differ"
	ReasonManifest               Reason = "manifest"
	ReasonImageNotFound          Reason = "image_not_found"
	ReasonExportInconsistent     Reason = "export_inconsistent"
	ReasonOverlayLimit           Reason = "overlay_limit"
	ReasonTooManyJDKs            Reason = "too_many_jdks"
	ReasonOverBudgetNoCache      Reason = "over_budget_without_cache"
)

// Stats says what a read cost.
type Stats struct {
	// ImageCached: the whole result came from the image cache.
	ImageCached bool
	// LayersCached counts layers whose verified summary was already cached,
	// LayersRead those read and verified in this call.
	LayersCached int
	LayersRead   int
	// LayersKept counts the layers read in this call that were stored for the
	// next cycle: none without a cache on disk.
	LayersKept int
	// RegistryBytes and DockerBytes are the bytes charged to the budgets.
	RegistryBytes int64
	DockerBytes   int64
	// ExportCalled: the Docker export was requested.
	ExportCalled bool
}

// Outcome is the result of Reader.Read.
type Outcome struct {
	Kind Kind
	// JDKs are the runtimes found; only for Complete.
	JDKs []JDK
	// ConfigDigest is the image config that was read, when known.
	ConfigDigest string
	// JavaHome is Target.JavaHome resolved inside the image: the real
	// directory, without a leading "/". "" when the image has no JAVA_HOME or
	// it does not name a directory of the image; only for Complete.
	JavaHome string
	// Reason and Detail say why a read is Deferred or Permanent.
	Reason Reason
	Detail string
	// Err is the cause behind Reason, for logs.
	Err error
	// Recorded: a "cannot complete" record exists for the route (written now
	// or found).
	Recorded bool
	Stats    Stats

	record bool // set by the read: write a record for this Permanent outcome
}

// Reader reads images. Zero Limits and a nil Budget or Cache are allowed: the
// defaults apply, there is no cycle budget, and nothing is cached.
type Reader struct {
	Registry RegistryAPI
	Docker   DockerAPI
	Cache    *Cache
	Budget   *Budget
	Limits   Limits
	// Version is the program version; a record made by another version is not
	// used.
	Version string
	Log     *slog.Logger
}

func (r *Reader) log() *slog.Logger {
	if r.Log != nil {
		return r.Log
	}
	return slog.Default()
}

func deferred(reason Reason, err error) Outcome {
	d := string(reason)
	if err != nil {
		d = err.Error()
	}
	return Outcome{Kind: Deferred, Reason: reason, Detail: d, Err: err}
}

func permanent(reason Reason, err error, record bool) Outcome {
	d := string(reason)
	if err != nil {
		d = err.Error()
	}
	return Outcome{Kind: Permanent, Reason: reason, Detail: d, Err: err, record: record}
}

// Read reads the JDKs of one image. The image gets its own deadline of
// Limits.ImageTimeout, derived from ctx; ctx ending first gives a Deferred
// outcome with ReasonCancelled.
func (r *Reader) Read(ctx context.Context, t Target) Outcome {
	limits := r.Limits.withDefaults()
	if err := t.validate(); err != nil {
		return permanent(ReasonInvalidTarget, err, false)
	}
	key := t.key()
	if rec, ok := r.Cache.GetFailure(key, limits, r.Version); ok {
		return Outcome{Kind: Permanent, Reason: rec.Reason, Detail: rec.Detail, Recorded: true}
	}
	ictx, cancel := context.WithTimeout(ctx, limits.ImageTimeout)
	defer cancel()

	st := &runState{r: r, t: t, limits: limits, ctx: ictx, parent: ctx}
	var out Outcome
	if t.Route == RouteDocker {
		out = st.readDocker()
	} else {
		out = st.readRegistry()
	}
	out.Stats = st.stats

	// A strike is an end the next try may not repeat: on the Docker route a
	// timeout or an export with no matching config, on the registry route a
	// blob that did not verify. The third one in a row is permanent. On the
	// Docker route any other end resets the count, except the ones that did
	// not try (budget, cancellation); on the registry route a Complete does.
	blobStrike := t.Route == RouteRegistry && out.Kind == Deferred && out.Reason == ReasonBlobMismatch
	strike := blobStrike || t.Route == RouteDocker &&
		(out.Kind == Deferred && out.Reason == ReasonTimeout ||
			out.Kind == Permanent && (out.Reason == ReasonNoMatchingConfig || out.Reason == ReasonExportInconsistent))
	switch {
	case strike:
		n := r.Cache.Timeouts(key) + 1
		if n >= 3 {
			switch {
			case blobStrike:
				out = permanent(ReasonBlobMismatch, fmt.Errorf("a blob of %s@%s did not verify %d times in a row: %w", t.Repository, t.ManifestDigest, n, out.Err), true)
			case out.Reason == ReasonTimeout:
				out = permanent(ReasonTimeoutRepeated, fmt.Errorf("the Docker export of %s timed out %d times in a row", t.dockerID(), n), true)
			case out.Reason == ReasonExportInconsistent:
				out = permanent(ReasonExportInconsistent, fmt.Errorf("the Docker export of %s was inconsistent %d times in a row: %w", t.dockerID(), n, out.Err), true)
			default:
				out = permanent(ReasonNoMatchingConfig, fmt.Errorf("the Docker export of %s held no matching config %d times in a row: %w", t.dockerID(), n, out.Err), true)
			}
		} else {
			if err := r.Cache.SetTimeouts(key, n); err != nil {
				r.log().Warn("imagefs: store the strike count", "error", err)
			}
			if out.Kind == Permanent {
				out = deferred(out.Reason, out.Err)
			}
		}
		out.Stats = st.stats
	default:
		if out.Kind == Deferred && out.Reason == ReasonTimeout && t.Route == RouteRegistry && st.stats.LayersKept == 0 {
			out = permanent(ReasonTimeoutNoProgress, fmt.Errorf("reading %s@%s timed out and no layer was kept for the next cycle", t.Repository, t.ManifestDigest), true)
			out.Stats = st.stats
		}
		// The strikes are consecutive: an attempt that ended any other way
		// (a Complete, another failure) starts the count again. One that
		// did not try (budget, cancellation) leaves it.
		if out.Reason != ReasonBudget && out.Reason != ReasonCancelled {
			if err := r.Cache.SetTimeouts(key, 0); err != nil {
				r.log().Warn("imagefs: reset the strike count", "error", err)
			}
		}
	}
	if out.Kind == Permanent && out.record {
		rec := FailureRecord{Key: key, Reason: out.Reason, Detail: out.Detail, Limits: limits, ProgramVersion: r.Version}
		if err := r.Cache.PutFailure(rec); err != nil {
			r.log().Warn("imagefs: store a cannot-complete record", "error", err)
		} else if r.Cache != nil {
			out.Recorded = true
		}
	}
	if err := r.Cache.pruneIfWritten(); err != nil {
		r.log().Warn("imagefs: prune the cache", "error", err)
	}
	return out
}

// runState is one Read.
type runState struct {
	r      *Reader
	t      Target
	limits Limits
	ctx    context.Context // the image's deadline
	parent context.Context
	stats  Stats

	// sums are the layer summaries this read holds, by diffID, and held their
	// size: a summary is decoded once however many layers carry it, and the
	// total is bounded.
	sums map[string]LayerSummary
	held int64

	// stacked, when set, sees the layers handed to the overlay (for tests).
	stacked func([]LayerRef)
}

// maxHeldSummaryBytes bounds the summaries one read holds at once. It is a
// variable so that a test can lower it.
var maxHeldSummaryBytes int64 = 128 << 20

func (s *runState) holdError(need int64) error {
	return fmt.Errorf("%w: the layers of the image need more than %d bytes of summaries at once (%d held, %d more)", ErrSummaryLimit, maxHeldSummaryBytes, s.held, need)
}

// cachedSummary returns the cached summary of a layer. The size of the stored
// summary is checked against the bound before it is decoded, and a diffID
// already held is not decoded again. ok is false when the cache has none.
func (s *runState) cachedSummary(diffID string) (sum LayerSummary, ok bool, err error) {
	if sum, ok := s.sums[diffID]; ok {
		return sum, true, nil
	}
	size, ok := s.r.Cache.LayerCost(diffID)
	if !ok {
		return LayerSummary{}, false, nil
	}
	if s.held+size > maxHeldSummaryBytes {
		return LayerSummary{}, false, s.holdError(size)
	}
	sum, ok = s.r.Cache.GetLayer(diffID)
	if !ok {
		return LayerSummary{}, false, nil
	}
	s.keep(diffID, sum, size)
	return sum, true, nil
}

// holdSummary records a summary made in this read, within the bound.
func (s *runState) holdSummary(diffID string, sum LayerSummary) error {
	if _, ok := s.sums[diffID]; ok {
		return nil
	}
	size := summaryCost(sum)
	if s.held+size > maxHeldSummaryBytes {
		return s.holdError(size)
	}
	s.keep(diffID, sum, size)
	return nil
}

func (s *runState) keep(diffID string, sum LayerSummary, size int64) {
	if s.sums == nil {
		s.sums = map[string]LayerSummary{}
	}
	s.sums[diffID] = sum
	s.held += size
}

// summaryCost is what holding a decoded summary costs: a base, a fixed amount
// per entry and the bytes of its strings. A cached summary stores the same
// number, so a layer weighs the same whether it was just read or restored.
func summaryCost(sum LayerSummary) int64 {
	n := int64(64)
	for _, e := range sum.Entries {
		n += 96 + int64(len(e.Path)+len(e.Link)+len(e.Content))
	}
	return n
}

// transient classifies a failure of the network or of the source that may
// pass: the caller's cancellation, the image's deadline, or anything else.
func (s *runState) transient(err error) Outcome {
	switch {
	case s.parent.Err() != nil:
		return deferred(ReasonCancelled, s.parent.Err())
	case s.ctx.Err() != nil && errors.Is(s.ctx.Err(), context.DeadlineExceeded):
		return deferred(ReasonTimeout, fmt.Errorf("the time limit of %s passed: %w", s.limits.ImageTimeout, err))
	}
	return deferred(ReasonTransient, err)
}

// layerError classifies an error of Summarize; ok is false when the error is
// not one of the layer's own (a failure of the source).
func layerError(err error) (Outcome, bool) {
	switch {
	case errors.Is(err, ErrUnsupportedCompression):
		return permanent(ReasonUnsupportedCompression, err, true), true
	case errors.Is(err, ErrCorruptLayer):
		return permanent(ReasonCorruptLayer, err, true), true
	case errors.Is(err, ErrSummaryLimit):
		return permanent(ReasonSummaryLimit, err, true), true
	case errors.Is(err, ErrLayerTooLarge):
		return permanent(ReasonLayerTooLarge, err, true), true
	}
	return Outcome{}, false
}

// finish stacks the summaries, finds the JDKs and caches the result.
func (s *runState) finish(configDigest string, refs []LayerRef) Outcome {
	if s.stacked != nil {
		s.stacked(refs)
	}
	view, err := OverlayContext(s.ctx, refs)
	if err != nil {
		return s.stackError(err)
	}
	jdks, err := view.FindJDKsContext(s.ctx)
	if err != nil {
		if errors.Is(err, ErrReleaseUnreadable) {
			return permanent(ReasonReleaseUnreadable, err, true)
		}
		return s.stackError(err)
	}
	home := view.resolveHome(s.t.JavaHome)
	if configDigest != "" {
		res := ImageResult{DiffIDs: slices.Clone(s.t.DiffIDs), JDKs: jdks, JavaHomeInput: s.t.JavaHome, JavaHome: home}
		if err := s.r.Cache.PutImage(configDigest, res); err != nil {
			s.r.log().Warn("imagefs: store an image result", "error", err)
		}
	}
	return Outcome{Kind: Complete, JDKs: jdks, ConfigDigest: configDigest, JavaHome: home}
}

// stackError classifies a failure to stack the layers or to walk the result.
func (s *runState) stackError(err error) Outcome {
	switch {
	case errors.Is(err, ErrOverlayLimit):
		return permanent(ReasonOverlayLimit, err, true)
	case errors.Is(err, ErrTooManyJDKs):
		return permanent(ReasonTooManyJDKs, err, true)
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return s.transient(err)
	}
	return permanent(ReasonCorruptLayer, err, false)
}

// cachedImage builds the Complete outcome of a cached image result.
func (s *runState) cachedImage(configDigest string) (Outcome, bool) {
	res, ok := s.r.Cache.GetImage(configDigest, s.t.DiffIDs)
	if !ok || res.JavaHomeInput != s.t.JavaHome {
		return Outcome{}, false
	}
	s.stats.ImageCached = true
	return Outcome{Kind: Complete, JDKs: res.JDKs, ConfigDigest: configDigest, JavaHome: res.JavaHome}, true
}

// cachedLayers returns the summaries of all the target's layers when the
// cache has every one.
func (s *runState) cachedLayers() ([]LayerRef, bool, error) {
	refs := make([]LayerRef, 0, len(s.t.DiffIDs))
	for _, d := range s.t.DiffIDs {
		sum, ok, err := s.cachedSummary(d)
		if err != nil || !ok {
			return nil, false, err
		}
		refs = append(refs, LayerRef{DiffID: d, Summary: sum})
	}
	return refs, true, nil
}

// ---- registry route ----

var supportedLayerTypes = map[string]bool{
	"application/vnd.oci.image.layer.v1.tar":            true,
	"application/vnd.oci.image.layer.v1.tar+gzip":       true,
	"application/vnd.docker.image.rootfs.diff.tar.gzip": true,
	"application/vnd.docker.image.rootfs.diff.tar":      true,
}

func (s *runState) readRegistry() Outcome {
	t := s.t
	if s.r.Registry == nil {
		return permanent(ReasonInvalidTarget, errors.New("no registry client"), false)
	}
	il, err := s.r.Registry.ImageLayers(s.ctx, t.Repository, t.ManifestDigest, t.Platform)
	if err != nil {
		return s.registryError(err)
	}
	if !slices.Equal(il.DiffIDs, t.DiffIDs) {
		return permanent(ReasonDiffIDsDiffer, fmt.Errorf("the image config of %s lists other layers than the scan saw", il.ConfigDigest), false)
	}
	if len(il.Layers) != len(il.DiffIDs) {
		return permanent(ReasonManifest, fmt.Errorf("the manifest lists %d layers and the config %d", len(il.Layers), len(il.DiffIDs)), true)
	}
	for _, l := range il.Layers {
		switch {
		case l.HasURLs, isForeign(l.MediaType):
			return permanent(ReasonForeignLayer, fmt.Errorf("layer %s is a foreign layer (%s)", l.Digest, l.MediaType), true)
		case !supportedLayerTypes[l.MediaType]:
			reason := ReasonUnsupportedMediaType
			if isZstd(l.MediaType) {
				reason = ReasonUnsupportedCompression
			}
			return permanent(reason, fmt.Errorf("layer %s has the media type %s", l.Digest, l.MediaType), true)
		}
		if !digestRE.MatchString(l.Digest) || l.Size < 0 {
			return permanent(ReasonManifest, fmt.Errorf("layer %q has an unusable digest or size", l.Digest), true)
		}
	}
	// Without a cache on disk no layer carries over to the next cycle, so an
	// image whose layers together pass a whole cycle's budget cannot be read
	// in pieces.
	if s.r.Cache.off() && s.r.Budget != nil {
		if total, over := layersExceed(il.Layers, s.limits.RegistryBytesPerCycle); over {
			return permanent(ReasonOverBudgetNoCache, fmt.Errorf("the layers of %s@%s total more than a cycle's registry budget of %d bytes (%d counted), and without a cache on disk they cannot be read over several cycles", t.Repository, t.ManifestDigest, s.limits.RegistryBytesPerCycle, total), false)
		}
	}
	// A cached result is for the layers of the config; this manifest may carry
	// other blobs for them. It is used only when each blob is known to
	// decompress to the diffID at its position.
	if s.blobsVerified(il) {
		if out, ok := s.cachedImage(il.ConfigDigest); ok {
			return out
		}
	}
	refs := make([]LayerRef, len(il.Layers))
	for i, l := range il.Layers {
		diffID := il.DiffIDs[i]
		sum, ok, err := s.verifiedLayer(l.Digest, diffID)
		if err != nil {
			return permanent(ReasonSummaryLimit, err, true)
		}
		if ok {
			refs[i] = LayerRef{DiffID: diffID, Summary: sum}
			s.stats.LayersCached++
			continue
		}
		sum, out, ok := s.fetchLayer(l, diffID)
		if !ok {
			return out
		}
		if err := s.holdSummary(diffID, sum); err != nil {
			return permanent(ReasonSummaryLimit, err, true)
		}
		// Blobs of other compression that hold the same layer share the one
		// summary held for it.
		refs[i] = LayerRef{DiffID: diffID, Summary: s.sums[diffID]}
		s.stats.LayersRead++
	}
	return s.finish(il.ConfigDigest, refs)
}

// blobsVerified reports whether every blob of the manifest has a verified
// mapping to the diffID of its position in the config.
func (s *runState) blobsVerified(il registry.ImageLayers) bool {
	for i, l := range il.Layers {
		if got, ok := s.r.Cache.GetBlob(l.Digest); !ok || got != il.DiffIDs[i] {
			return false
		}
	}
	return true
}

// layersExceed reports whether the layers together are larger than limit,
// without a sum that can overflow; total is what was counted when it stopped.
func layersExceed(layers []registry.Layer, limit int64) (total int64, over bool) {
	for _, l := range layers {
		if l.Size > limit-total {
			return total, true
		}
		total += l.Size
	}
	return total, false
}

func isForeign(mediaType string) bool {
	return mediaType == "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip" ||
		strings.Contains(mediaType, "nondistributable") || strings.Contains(mediaType, "foreign")
}

func isZstd(mediaType string) bool { return strings.Contains(mediaType, "zstd") }

// verifiedLayer returns the cached summary of a layer only when the blob is
// known to decompress to the diffID: a blob that merely claims a known diffID
// is read and checked.
func (s *runState) verifiedLayer(blobDigest, diffID string) (LayerSummary, bool, error) {
	if got, ok := s.r.Cache.GetBlob(blobDigest); !ok || got != diffID {
		return LayerSummary{}, false, nil
	}
	return s.cachedSummary(diffID)
}

// fetchLayer streams, summarizes and verifies one registry layer. ok is false
// when the read must stop with the returned outcome.
func (s *runState) fetchLayer(l registry.Layer, diffID string) (sum LayerSummary, out Outcome, ok bool) {
	b := s.r.Budget
	if l.Size > s.limits.RegistryBytesPerCycle {
		return sum, permanent(ReasonBlobOverBudget, fmt.Errorf("layer %s is %d bytes, more than a cycle's registry budget of %d", l.Digest, l.Size, s.limits.RegistryBytesPerCycle), true), false
	}
	if b != nil && l.Size > b.RegistryLeft() {
		return sum, deferred(ReasonBudget, fmt.Errorf("layer %s needs %d bytes and %d are left in the cycle", l.Digest, l.Size, b.RegistryLeft())), false
	}
	br, err := s.r.Registry.OpenBlob(s.ctx, s.t.Repository, l.Digest, l.Size)
	if err != nil {
		return sum, s.registryError(err), false
	}
	defer br.Close()
	counted := &budgetReader{r: br, b: b, left: registryLeft}
	// Whatever is read afterwards to verify a failure is charged to the budget
	// too, so the statistics are settled once, at the end.
	defer func() { s.stats.RegistryBytes += counted.read }()
	sum, got, err := Summarize(counted, s.limits)
	if err == nil {
		// Read the compressed stream to its end: this is where the length and
		// the digest of the blob are checked.
		_, err = io.Copy(io.Discard, counted)
	}
	if err != nil {
		return sum, s.streamError(counted, err), false
	}
	if got != diffID {
		return sum, permanent(ReasonDiffIDMismatch, fmt.Errorf("layer %s decompresses to %s, the config says %s", l.Digest, got, diffID), true), false
	}
	if err := s.r.Cache.PutLayer(diffID, sum); err != nil {
		s.r.log().Warn("imagefs: store a layer summary", "error", err)
	} else if err := s.r.Cache.PutBlob(l.Digest, diffID); err != nil {
		s.r.log().Warn("imagefs: store a blob mapping", "error", err)
	} else if !s.r.Cache.off() {
		s.stats.LayersKept++
	}
	return sum, Outcome{}, true
}

// streamError classifies an error from reading a blob stream. A blob that
// does not arrive with its digest and size, or that does not decompress before
// the end of its stream is checked, is a failure of what the source sent and
// may pass: it is Deferred with ReasonBlobMismatch. A format or limit problem
// is permanent only once the rest of the stream has arrived and matched the
// digest and size of the manifest.
func (s *runState) streamError(rest io.Reader, err error) Outcome {
	if out, ok := s.sourceError(err); ok {
		return out
	}
	if out, ok := layerError(err); ok {
		if _, derr := io.Copy(io.Discard, rest); derr != nil {
			if o, ok := s.sourceError(derr); ok {
				return o
			}
			return s.registryError(derr)
		}
		return out
	}
	return s.registryError(err)
}

// sourceError classifies the errors that say the bytes of a blob cannot be
// trusted or the budget ran out.
func (s *runState) sourceError(err error) (Outcome, bool) {
	switch {
	case errors.Is(err, errBudget):
		return deferred(ReasonBudget, err), true
	case errors.Is(err, registry.ErrDigestMismatch), errors.Is(err, registry.ErrBadResponse):
		return deferred(ReasonBlobMismatch, err), true
	}
	return Outcome{}, false
}

// registryError classifies an error of the registry client.
func (s *runState) registryError(err error) Outcome {
	switch {
	case s.parent.Err() != nil:
		return deferred(ReasonCancelled, s.parent.Err())
	case errors.Is(err, context.DeadlineExceeded) && s.ctx.Err() != nil:
		return s.transient(err)
	case errors.Is(err, registry.ErrPlatformNotFound), errors.Is(err, registry.ErrPlatformAmbiguous),
		errors.Is(err, registry.ErrPlatformMismatch), errors.Is(err, registry.ErrVariantUnsupported),
		errors.Is(err, registry.ErrUnsupported), errors.Is(err, registry.ErrTooLarge),
		errors.Is(err, registry.ErrInvalidInput):
		return permanent(ReasonManifest, err, true)
	case errors.Is(err, registry.ErrBudgetExhausted), errors.Is(err, registry.ErrBudgetReserved):
		return deferred(ReasonBudget, err)
	}
	return s.transient(err)
}

// ---- Docker route ----

func (s *runState) readDocker() Outcome {
	t := s.t
	// The ID is the config digest for an ordinary image.
	if out, ok := s.cachedImage(t.dockerID()); ok {
		return out
	}
	refs, ok, err := s.cachedLayers()
	if err != nil {
		return permanent(ReasonSummaryLimit, err, true)
	}
	if ok {
		s.stats.LayersCached = len(refs)
		return s.finish(t.dockerID(), refs)
	}
	if s.r.Docker == nil {
		return permanent(ReasonInvalidTarget, errors.New("no Docker client"), false)
	}
	b := s.r.Budget
	if b != nil && b.DockerLeft() <= 0 {
		return deferred(ReasonBudget, errors.New("the cycle's Docker budget is used up"))
	}
	s.stats.ExportCalled = true
	rc, err := s.r.Docker.ExportImage(s.ctx, t.dockerID(), t.Platform)
	if err != nil {
		var se *docker.ExportStatusError
		switch {
		case errors.As(err, &se) && se.Status == http.StatusNotFound:
			return permanent(ReasonImageNotFound, err, false)
		case errors.Is(err, docker.ErrExportInvalid):
			return permanent(ReasonInvalidTarget, err, false)
		}
		return s.transient(err)
	}
	defer rc.Close()
	counted := &budgetReader{r: rc, b: b, left: dockerLeft}
	out := s.parseExport(counted)
	s.stats.DockerBytes = counted.read
	if out.Kind == Deferred && out.Reason == ReasonBudget && counted.read >= s.limits.DockerBytesPerCycle {
		return permanent(ReasonExportOverBudget, fmt.Errorf("the export of %s is larger than a cycle's Docker budget of %d bytes", t.dockerID(), s.limits.DockerBytesPerCycle), true)
	}
	return out
}
