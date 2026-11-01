package remediation

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// MavenRegistry is what the remediation reads from Maven Central.
type MavenRegistry interface {
	// Versions returns the versions maven-metadata.xml lists for groupId:artifactId, in file order.
	Versions(ctx context.Context, groupID, artifactID string) ([]string, error)
	// POM returns the pom file of groupId:artifactId:version.
	POM(ctx context.Context, groupID, artifactID, version string) ([]byte, error)
}

// MavenClient reads Maven Central.
type MavenClient struct {
	BaseURL string       // default "https://repo.maven.apache.org/maven2"
	HTTP    *http.Client // default with a timeout
}

var _ MavenRegistry = (*MavenClient)(nil)

// maxMavenMetadataBytes bounds a maven-metadata.xml; a pom is bounded by
// maxMavenPOMBytes.
const maxMavenMetadataBytes = 2 << 20

const mavenCentralURL = "https://repo.maven.apache.org/maven2"

// mavenNameRE bounds a groupId or artifactId to the characters Maven
// Central's layout takes.
var mavenNameRE = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

func mavenGroupOK(g string) bool {
	if len(g) > 200 || !mavenNameRE.MatchString(g) {
		return false
	}
	for _, seg := range strings.Split(g, ".") {
		if seg == "" {
			return false // also rules out ".."
		}
	}
	return true
}

func mavenArtifactOK(a string) bool {
	return len(a) <= 200 && mavenNameRE.MatchString(a) && a != "." && a != ".."
}

// mavenPathVersionOK reports a version that is safe as one path segment.
func mavenPathVersionOK(v string) bool {
	if !mavenVersionOK(v) || v == "." || v == ".." {
		return false
	}
	return !strings.ContainsAny(v, `/\`)
}

func (c *MavenClient) base() string {
	if c.BaseURL != "" {
		return strings.TrimRight(c.BaseURL, "/")
	}
	return mavenCentralURL
}

// artifactURL is <base>/<group as a path>/<artifact>, for coordinates already
// checked.
func (c *MavenClient) artifactURL(groupID, artifactID string) string {
	return c.base() + "/" + strings.ReplaceAll(groupID, ".", "/") + "/" + url.PathEscape(artifactID)
}

// sameHostRedirect follows a redirect only within the host and the scheme of
// the first request, so an https request is never answered over plain http.
func sameHostRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 5 {
		return errors.New("too many redirects")
	}
	if req.URL.Host != via[0].URL.Host {
		return fmt.Errorf("redirect from %s to %s refused", via[0].URL.Host, req.URL.Host)
	}
	if req.URL.Scheme != via[0].URL.Scheme {
		return fmt.Errorf("redirect from %s to %s refused", via[0].URL.Scheme, req.URL.Scheme)
	}
	return nil
}

// get reads one response of at most limit bytes. 404 is ErrReleaseNotFound.
func (c *MavenClient) get(ctx context.Context, u string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	// Maven Central answers 429 to the default Go User-Agent.
	req.Header.Set("User-Agent", "kestrelynx")
	hc := *boundedClient(c.HTTP)
	hc.CheckRedirect = sameHostRedirect
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("maven request: %w", err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
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

// Versions implements MavenRegistry with GET <base>/<group path>/<artifact>/maven-metadata.xml.
// Versions that could not be fetched later (not a single safe path segment)
// are left out.
func (c *MavenClient) Versions(ctx context.Context, groupID, artifactID string) ([]string, error) {
	if !mavenGroupOK(groupID) || !mavenArtifactOK(artifactID) {
		return nil, fmt.Errorf("%q:%q is not a Maven groupId and artifactId this client looks up", groupID, artifactID)
	}
	body, err := c.get(ctx, c.artifactURL(groupID, artifactID)+"/maven-metadata.xml", maxMavenMetadataBytes)
	if err != nil {
		return nil, err
	}
	return parseMavenMetadata(body)
}

// parseMavenMetadata reads <metadata><versioning><versions><version>.
func parseMavenMetadata(body []byte) ([]string, error) {
	dec := xml.NewDecoder(bytes.NewReader(body))
	var path []string
	var out []string
	var text strings.Builder
	sawRoot := false
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("maven-metadata.xml is not well-formed XML: %w", err)
		}
		switch t := tok.(type) {
		case xml.Directive:
			return nil, errors.New("maven-metadata.xml has a DOCTYPE, which is refused")
		case xml.StartElement:
			if len(path) == 0 {
				if t.Name.Local != "metadata" {
					return nil, fmt.Errorf("maven-metadata.xml root element is %q", t.Name.Local)
				}
				sawRoot = true
			}
			path = append(path, t.Name.Local)
			text.Reset()
		case xml.CharData:
			text.Write(t)
		case xml.EndElement:
			if len(path) == 4 && path[1] == "versioning" && path[2] == "versions" && path[3] == "version" {
				if v := strings.TrimSpace(text.String()); mavenPathVersionOK(v) {
					out = append(out, v)
				}
			}
			path = path[:len(path)-1]
			text.Reset()
		}
	}
	if !sawRoot {
		return nil, errors.New("maven-metadata.xml has no root element")
	}
	return out, nil
}

// POM implements MavenRegistry with GET <base>/<group path>/<artifact>/<version>/<artifact>-<version>.pom.
func (c *MavenClient) POM(ctx context.Context, groupID, artifactID, version string) ([]byte, error) {
	if !mavenGroupOK(groupID) || !mavenArtifactOK(artifactID) || !mavenPathVersionOK(version) {
		return nil, fmt.Errorf("%q:%q:%q is not a Maven coordinate this client looks up", groupID, artifactID, version)
	}
	u := c.artifactURL(groupID, artifactID) + "/" + url.PathEscape(version) + "/" + url.PathEscape(artifactID+"-"+version) + ".pom"
	return c.get(ctx, u, maxMavenPOMBytes)
}
