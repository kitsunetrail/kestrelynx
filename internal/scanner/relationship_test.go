package scanner

import (
	"os"
	"testing"
)

// A Go binary's package list names its main module as the root and records
// the Go version it was built with as stdlib; the other modules carry no
// relationship. The fixture is the kestrelynx binary's result of a Trivy
// 0.71.2 scan of a KestreLynx image, run with --list-all-pkgs.
func TestParseReport_GoBinaryRelationship(t *testing.T) {
	data, err := os.ReadFile("testdata/real_gobinary_root_kestrelynx.json")
	if err != nil {
		t.Fatal(err)
	}
	scan, err := ParseReport(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(scan.Packages) != 1 || scan.Packages[0].Type != "gobinary" {
		t.Fatalf("results = %+v", scan.Packages)
	}
	got := map[string]Package{}
	for _, p := range scan.Packages[0].Packages {
		got[p.Name] = p
	}
	if root := got["github.com/kitsunetrail/kestrelynx"]; root.Relationship != "root" || root.Version != "" {
		t.Errorf("root = %+v", root)
	}
	if std := got["stdlib"]; std.Relationship != "direct" || std.Version != "v1.26.10" {
		t.Errorf("stdlib = %+v", std)
	}
	if dep := got["golang.org/x/sys"]; dep.Relationship != "" || dep.Version == "" {
		t.Errorf("dependency = %+v", dep)
	}
}
