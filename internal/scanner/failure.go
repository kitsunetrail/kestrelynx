package scanner

import (
	"net/netip"
	"strings"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
)

// FailureCause is why a scan failed, in the terms a notification states it.
// The zero value means the scan did not fail.
type FailureCause string

const (
	// CauseLocalRegistry: the image is in a registry on the loopback address
	// of the node, which this process could not connect to.
	CauseLocalRegistry FailureCause = "local_registry"
	// CauseRegistryAuth: the registry refused the request for want of a valid
	// login.
	CauseRegistryAuth FailureCause = "registry_auth"
	// CauseImageNotFound: the registry has no such repository or manifest.
	CauseImageNotFound FailureCause = "image_not_found"
	// CauseRateLimited: the registry refused the request for too many
	// requests.
	CauseRateLimited FailureCause = "registry_rate_limited"
	// CauseRegistryUnreachable: the registry could not be connected to (no
	// such host, refused, timed out).
	CauseRegistryUnreachable FailureCause = "registry_unreachable"
	// CauseVulnDB: Trivy could not get its vulnerability database.
	CauseVulnDB FailureCause = "vulnerability_db"
	// CauseImageMismatch: the image scanned was not the one running.
	CauseImageMismatch FailureCause = "image_mismatch"
	// CauseUnknown: none of the above could be told from the error.
	CauseUnknown FailureCause = "unclassified"
)

// registryHostOf returns the registry host of the image the target fetches:
// the host of the registry reference when there is one, else of the
// reference itself, "docker.io" for a reference without a host; "" when no
// repository can be read.
func registryHostOf(target ScanTarget) string {
	ref := target.Registry.Repository
	if ref == "" {
		ref = target.Subject.Ref
	}
	key, ok := inventory.RepositoryKey(ref)
	if !ok {
		return ""
	}
	host, _, _ := strings.Cut(key, "/")
	return host
}

// isLoopbackHost reports whether a registry host (with an optional port)
// names the loopback address: "localhost", an address in 127.0.0.0/8, or
// [::1].
func isLoopbackHost(host string) bool {
	h := host
	if strings.HasPrefix(h, "[") {
		if i := strings.IndexByte(h, ']'); i > 0 {
			h = h[1:i]
		}
	} else if i := strings.LastIndexByte(h, ':'); i >= 0 {
		h = h[:i]
	}
	if strings.EqualFold(h, "localhost") {
		return true
	}
	addr, err := netip.ParseAddr(h)
	return err == nil && addr.IsLoopback()
}

// Error texts that tell the causes apart. They are matched in the order of
// classifyFailure, case-insensitively, against the whole error: Trivy's
// message, the registry's error code and Go's network error.
var (
	vulnDBTexts      = []string{"db error", "failed to download vulnerability db", "vulnerability db"}
	authTexts        = []string{"unauthorized", "authentication required", "denied: requested access", "denied: denied", "403 forbidden"}
	notFoundTexts    = []string{"manifest_unknown", "manifest unknown", "name_unknown", "404 not found"}
	rateLimitTexts   = []string{"toomanyrequests", "429 too many requests", "rate limit"}
	unreachableTexts = []string{"connection refused", "no such host", "i/o timeout", "network is unreachable", "no route to host", "connection reset", "tls handshake timeout", "client.timeout exceeded"}
)

// withheldLoginText is the note the scan adds when it held a login back. It
// says nothing of why the registry refused, so it decides the cause only when
// the error names no other.
const withheldLoginText = "the registry login was not passed on"

func containsAny(s string, subs []string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// classifyFailure tells why a scan of target failed from its error. The
// registry causes apply only to a scan that fetches from a registry; a scan
// of the local image store gets the vulnerability database cause or
// CauseUnknown.
func classifyFailure(target ScanTarget, err error) FailureCause {
	if err == nil {
		return ""
	}
	s := diagnosticText(target, err.Error())
	if containsAny(s, vulnDBTexts) {
		return CauseVulnDB
	}
	if target.Source != SourceRemote {
		return CauseUnknown
	}
	switch {
	case containsAny(s, authTexts):
		return CauseRegistryAuth
	case containsAny(s, notFoundTexts):
		return CauseImageNotFound
	case containsAny(s, rateLimitTexts):
		return CauseRateLimited
	case containsAny(s, unreachableTexts):
		if isLoopbackHost(registryHostOf(target)) {
			return CauseLocalRegistry
		}
		return CauseRegistryUnreachable
	case strings.Contains(s, withheldLoginText):
		return CauseRegistryAuth
	}
	return CauseUnknown
}

// diagnosticText is the error lower-cased with the words that name things
// taken out, so that a word of a name never reads as a cause: every word
// holding a slash (a URL, an image reference, a path; "i/o" is kept), the
// registry host as a whole word, the image reference where a reference is
// written (after "scan", or in quotes; a bare name such as "db" may also be
// a word of the error), and the host after "lookup" in a name resolution
// error.
func diagnosticText(target ScanTarget, text string) string {
	ref := strings.ToLower(target.Subject.Ref)
	host := strings.ToLower(registryHostOf(target))
	words := strings.Fields(strings.ToLower(text))
	kept := make([]string, 0, len(words))
	for i, w := range words {
		core := strings.Trim(w, `"'()[],;:`)
		switch {
		case strings.Contains(core, "/") && core != "i/o":
		case core != "" && core == host:
		case core != "" && core == ref && (strings.HasPrefix(w, `"`) || (i > 0 && words[i-1] == "scan")):
		case i > 0 && words[i-1] == "lookup":
		default:
			kept = append(kept, w)
		}
	}
	return strings.Join(kept, " ")
}
