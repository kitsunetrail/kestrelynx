package remediation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// GoModuleRegistry is what the Go part reads from the public module proxy and
// checksum database.
type GoModuleRegistry interface {
	// Info returns the canonical version and the commit time the proxy
	// records for path@version. ErrReleaseNotFound means the proxy has no
	// such version.
	Info(ctx context.Context, path, version string) (GoInfo, error)
	// GoMod returns the go.mod file the proxy serves for path@version.
	GoMod(ctx context.Context, path, version string) ([]byte, error)
	// Latest returns the version the proxy reports as the module's latest.
	Latest(ctx context.Context, path string) (GoInfo, error)
	// Sums returns the hashes the checksum database records for
	// path@version: of the module zip and of its go.mod.
	Sums(ctx context.Context, path, version string) (GoSums, error)
}

// GoInfo is the proxy's information on one version.
type GoInfo struct {
	Version string
	Time    time.Time
}

// GoSums are the checksum database's two hashes of one module version.
type GoSums struct {
	Zip string // h1: of the module zip
	Mod string // h1: of its go.mod
}

// GoClient reads proxy.golang.org and sum.golang.org.
type GoClient struct {
	HTTP *http.Client
	// ProxyURL and SumDBURL replace the public services, for tests.
	ProxyURL string
	SumDBURL string
}

var _ GoModuleRegistry = (*GoClient)(nil)

// Bounds on what one response of the proxy or the checksum database may be.
const (
	maxGoInfoBytes  = 64 << 10
	maxGoModBytes   = 2 << 20
	maxGoSumDBBytes = 64 << 10
)

// goPathRE and goVersionRE bound what is put in a URL: a module path of the
// characters Go allows, and a semantic version with its leading v.
var (
	goPathRE    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.\-_~/]*[A-Za-z0-9]$`)
	goVersionRE = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.\-]+)?(?:\+incompatible)?$`)
	goHashRE    = regexp.MustCompile(`^h1:[A-Za-z0-9+/]{43}=$`)
)

func goLookupArgsOK(path, version string) bool {
	if len(path) > 500 || !goPathRE.MatchString(path) || strings.Contains(path, "//") || strings.Contains(path, "..") {
		return false
	}
	return version == "" || (len(version) <= 200 && goVersionRE.MatchString(version))
}

// goEscape writes a module path or version as the proxy and checksum
// database expect: each upper-case letter as "!" and its lower case.
func goEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 'A' && r <= 'Z' {
			b.WriteByte('!')
			b.WriteRune(r + ('a' - 'A'))
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func (c *GoClient) proxyBase() string {
	if c.ProxyURL != "" {
		return strings.TrimRight(c.ProxyURL, "/")
	}
	return "https://proxy.golang.org"
}

func (c *GoClient) sumdbBase() string {
	if c.SumDBURL != "" {
		return strings.TrimRight(c.SumDBURL, "/")
	}
	return "https://sum.golang.org"
}

// get reads one response of at most limit bytes. 404 and 410 (the proxy's
// answer for a version it does not have) are ErrReleaseNotFound.
func (c *GoClient) get(ctx context.Context, u string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "kestrelynx")
	resp, err := boundedClient(c.HTTP).Do(req)
	if err != nil {
		return nil, fmt.Errorf("go module request: %w", err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone:
		return nil, ErrReleaseNotFound
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("%s answered %s", req.URL.Host, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", req.URL.Host, err)
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("%s sent more than %d bytes", req.URL.Host, limit)
	}
	return body, nil
}

func parseGoInfo(body []byte) (GoInfo, error) {
	var raw struct {
		Version string
		Time    time.Time
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return GoInfo{}, fmt.Errorf("proxy info is not JSON: %w", err)
	}
	if !goVersionRE.MatchString(raw.Version) {
		return GoInfo{}, fmt.Errorf("proxy info names %q, which is not a module version", raw.Version)
	}
	return GoInfo{Version: raw.Version, Time: raw.Time}, nil
}

// Info implements GoModuleRegistry with GET <proxy>/<path>/@v/<version>.info.
func (c *GoClient) Info(ctx context.Context, path, version string) (GoInfo, error) {
	if !goLookupArgsOK(path, version) || version == "" {
		return GoInfo{}, fmt.Errorf("%q %q is not a module path and version this client looks up", path, version)
	}
	body, err := c.get(ctx, c.proxyBase()+"/"+goEscape(path)+"/@v/"+goEscape(version)+".info", maxGoInfoBytes)
	if err != nil {
		return GoInfo{}, err
	}
	return parseGoInfo(body)
}

// Latest implements GoModuleRegistry with GET <proxy>/<path>/@latest.
func (c *GoClient) Latest(ctx context.Context, path string) (GoInfo, error) {
	if !goLookupArgsOK(path, "") {
		return GoInfo{}, fmt.Errorf("%q is not a module path this client looks up", path)
	}
	body, err := c.get(ctx, c.proxyBase()+"/"+goEscape(path)+"/@latest", maxGoInfoBytes)
	if err != nil {
		return GoInfo{}, err
	}
	return parseGoInfo(body)
}

// GoMod implements GoModuleRegistry with GET <proxy>/<path>/@v/<version>.mod.
func (c *GoClient) GoMod(ctx context.Context, path, version string) ([]byte, error) {
	if !goLookupArgsOK(path, version) || version == "" {
		return nil, fmt.Errorf("%q %q is not a module path and version this client looks up", path, version)
	}
	body, err := c.get(ctx, c.proxyBase()+"/"+goEscape(path)+"/@v/"+goEscape(version)+".mod", maxGoModBytes)
	if err != nil {
		return nil, err
	}
	if !utf8.Valid(body) {
		return nil, fmt.Errorf("the go.mod of %s@%s is not valid UTF-8", path, version)
	}
	return body, nil
}

// Sums implements GoModuleRegistry with GET <sumdb>/lookup/<path>@<version>.
// The answer is a record number, the two lines of the record and, after a
// blank line, the signed tree head. The record must be for exactly the path
// and version asked for; the signature and the proof that the record is in
// the tree are not checked (the answer is taken from TLS, as a registry's
// is).
func (c *GoClient) Sums(ctx context.Context, path, version string) (GoSums, error) {
	if !goLookupArgsOK(path, version) || version == "" {
		return GoSums{}, fmt.Errorf("%q %q is not a module path and version this client looks up", path, version)
	}
	body, err := c.get(ctx, c.sumdbBase()+"/lookup/"+goEscape(path)+"@"+goEscape(version), maxGoSumDBBytes)
	if err != nil {
		return GoSums{}, err
	}
	return parseSumDBLookup(body, path, version)
}

var errSumDBFormat = errors.New("checksum database answer is not in the lookup format")

// sumDBTreeHashRE is the root hash of the signed tree head: 32 bytes in
// base64.
var sumDBTreeHashRE = regexp.MustCompile(`^[A-Za-z0-9+/]{43}=$`)

func parseSumDBLookup(body []byte, path, version string) (GoSums, error) {
	lines := strings.Split(string(body), "\n")
	// The record (number, two lines, a blank line), the tree head (its name,
	// size and root hash, a blank line) and one or more signature lines,
	// each ended by a newline.
	if len(lines) < 10 || lines[len(lines)-1] != "" {
		return GoSums{}, errSumDBFormat
	}
	if _, err := strconv.ParseUint(lines[0], 10, 63); err != nil {
		return GoSums{}, errSumDBFormat
	}
	if lines[4] != "go.sum database tree" || lines[7] != "" || !sumDBTreeHashRE.MatchString(lines[6]) {
		return GoSums{}, errSumDBFormat
	}
	if _, err := strconv.ParseUint(lines[5], 10, 63); err != nil {
		return GoSums{}, errSumDBFormat
	}
	for _, sig := range lines[8 : len(lines)-1] {
		if !strings.HasPrefix(sig, "\u2014 ") || len(strings.Fields(sig)) != 3 {
			return GoSums{}, errSumDBFormat
		}
	}
	zip := strings.Fields(lines[1])
	mod := strings.Fields(lines[2])
	if len(zip) != 3 || len(mod) != 3 || lines[3] != "" {
		return GoSums{}, errSumDBFormat
	}
	if zip[0] != path || zip[1] != version || mod[0] != path || mod[1] != version+"/go.mod" {
		return GoSums{}, fmt.Errorf("checksum database answered for %s %s, not %s %s", zip[0], zip[1], path, version)
	}
	if !goHashRE.MatchString(zip[2]) || !goHashRE.MatchString(mod[2]) {
		return GoSums{}, fmt.Errorf("checksum database answered with a hash of an unknown form")
	}
	return GoSums{Zip: zip[2], Mod: mod[2]}, nil
}
