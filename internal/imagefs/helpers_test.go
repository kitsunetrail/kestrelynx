package imagefs

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// Release files of real runtimes.
const (
	releaseTemurin21 = `IMPLEMENTOR="Eclipse Adoptium"
IMPLEMENTOR_VERSION="Temurin-21.0.13.1+2"
JAVA_RUNTIME_VERSION="21.0.13.1+2-LTS"
JAVA_VERSION="21.0.13.1"
JAVA_VERSION_DATE="2026-11-17"
LIBC="musl"
OS_ARCH="x86_64"
OS_NAME="Linux"
SOURCE=".:git:8799347eca78"
`
	releaseZulu21 = `IMPLEMENTOR="Azul Systems, Inc."
IMPLEMENTOR_VERSION="Zulu21.54+201-CA"
JAVA_RUNTIME_VERSION="21.0.13.1+2-LTS"
JAVA_VERSION="21.0.13.1"
JAVA_VERSION_DATE="2026-11-17"
LIBC="gnu"
OS_ARCH="x86_64"
OS_NAME="Linux"
SOURCE=".:git:cd73e3ad0d88"
`
	releaseCorretto8 = `JAVA_VERSION="1.8.0_514"
OS_NAME="Linux"
OS_VERSION="2.6"
OS_ARCH="amd64"
LIBC=""
SOURCE=""
`
)

// fe is one tar entry.
type fe struct {
	name string
	typ  byte // 0 means a regular file
	link string
	body string
}

func file(name, body string) fe  { return fe{name: name, body: body} }
func dir(name string) fe         { return fe{name: name, typ: tar.TypeDir} }
func sym(name, to string) fe     { return fe{name: name, typ: tar.TypeSymlink, link: to} }
func hard(name, to string) fe    { return fe{name: name, typ: tar.TypeLink, link: to} }
func wh(dirName, name string) fe { return file(dirName+"/.wh."+name, "") }
func opaque(dirName string) fe   { return file(dirName+"/.wh..wh..opq", "") }

func tarOf(t testing.TB, entries ...fe) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		h := &tar.Header{Name: e.name, Mode: 0o644, Typeflag: e.typ, Linkname: e.link}
		switch e.typ {
		case 0:
			h.Typeflag = tar.TypeReg
			h.Size = int64(len(e.body))
		case tar.TypeDir:
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

func gzipOf(b []byte) []byte {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write(b)
	zw.Close()
	return buf.Bytes()
}

func digestOf(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

// summarize reads a layer and fails the test on error.
func summarize(t testing.TB, b []byte) LayerRef {
	t.Helper()
	sum, id, err := Summarize(bytes.NewReader(b), Limits{})
	if err != nil {
		t.Fatalf("Summarize: %v", err)
	}
	return LayerRef{DiffID: id, Summary: sum}
}

// overlayOf stacks the layers made of the entry lists, bottom first.
func overlayOf(t testing.TB, layers ...[]fe) *View {
	t.Helper()
	var refs []LayerRef
	for i, l := range layers {
		ref := summarize(t, tarOf(t, l...))
		// A synthetic diffID per position keeps equal layers apart.
		ref.DiffID = digestOf([]byte{byte(i)})
		refs = append(refs, ref)
	}
	v, err := Overlay(refs)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func exists(t testing.TB, v *View, p string) (Resolved, bool) {
	t.Helper()
	r, err := v.Lstat(p)
	if err != nil {
		t.Fatalf("Lstat(%q): %v", p, err)
	}
	return r, r.Exists
}

func cacheDirsFiles(t testing.TB, c *Cache, kind string) []string {
	t.Helper()
	es, err := os.ReadDir(filepath.Join(c.dir, kind))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range es {
		out = append(out, filepath.Join(c.dir, kind, e.Name()))
	}
	return out
}

func removeFile(t testing.TB, p string) {
	t.Helper()
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
}
