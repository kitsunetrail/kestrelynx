package javacore

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/imagefs"
	"github.com/kitsunetrail/kestrelynx/internal/inventory"
)

// fakeExporter serves one prepared export tar.
type fakeExporter struct{ export []byte }

func (f fakeExporter) ExportImage(context.Context, string, inventory.Platform) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(f.export)), nil
}

type tarEntry struct {
	name, link, body string
	typ              byte
}

func tarBytes(t *testing.T, entries ...tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		h := &tar.Header{Name: e.name, Mode: 0o644, Typeflag: e.typ, Linkname: e.link}
		if e.typ == 0 {
			h.Typeflag, h.Size = tar.TypeReg, int64(len(e.body))
		}
		if e.typ == tar.TypeDir {
			h.Mode = 0o755
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if e.typ == 0 {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func sha(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

// A JAVA_HOME that is a link to the JDK reaches the advisor as the same
// directory: the reader resolves it in the image and the advisor compares the
// result with the JDK's directory.
func TestReaderToAdvisorJavaHomeThroughALink(t *testing.T) {
	rel := string(withVersion(t, "temurin21", "21.0.13.1", "21.0.13"))
	layer := tarBytes(t,
		tarEntry{name: "opt/java/openjdk/release", body: rel},
		tarEntry{name: "opt/java/openjdk/lib/modules", body: "image"},
		tarEntry{name: "opt/java/openjdk/bin/java", body: "elf"},
		tarEntry{name: "opt/java/current", typ: tar.TypeSymlink, link: "/opt/java/openjdk"},
	)
	diffID := sha(layer)
	cfg, _ := json.Marshal(map[string]any{
		"os": "linux", "architecture": "amd64",
		"rootfs": map[string]any{"type": "layers", "diff_ids": []string{diffID}},
	})
	cfgID := sha(cfg)
	export := tarBytes(t,
		tarEntry{name: "blobs/sha256/" + sha(layer)[7:], body: string(layer)},
		tarEntry{name: "blobs/sha256/" + cfgID[7:], body: string(cfg)},
	)
	platform := inventory.Platform{OS: "linux", Architecture: "amd64"}
	env := []string{"JAVA_HOME=/opt/java/current", "JAVA_VERSION=jdk-21.0.13+9"}

	r := &imagefs.Reader{Docker: fakeExporter{export}, Version: "test"}
	tg := imagefs.DockerTarget(cfgID, platform, []string{diffID})
	tg.JavaHome = "/opt/java/current"
	out := r.Read(context.Background(), tg)
	if out.Kind != imagefs.Complete || len(out.JDKs) != 1 || out.JavaHome != "opt/java/openjdk" {
		t.Fatalf("outcome %+v", out)
	}
	s := javaScan("21.0.13")
	s.ConfigEnv = env
	s.ImageFiles = &out
	aug := advisorWithFixture(t).Augment(s, allSeverities)
	if len(aug.Findings) == 0 {
		t.Fatal("no findings")
	}
	for _, f := range aug.Findings {
		if !f.RuntimeSameAsEnv {
			t.Fatalf("RuntimeSameAsEnv = false for a JAVA_HOME that links to the JDK: %+v", f)
		}
	}
}
