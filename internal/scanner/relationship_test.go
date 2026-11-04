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

// The dependency graph of a pom result is kept; that of any other is not.
func TestParseReport_PomDependsOn(t *testing.T) {
	doc := `{"SchemaVersion":2,"ArtifactName":"x","ArtifactType":"filesystem","Results":[
	{"Target":"pom.xml","Class":"lang-pkgs","Type":"pom","Packages":[
		{"ID":"com.example:app:1.0","Name":"com.example:app","Version":"1.0","Relationship":"root","DependsOn":["org.yaml:snakeyaml:1.30"]},
		{"ID":"org.yaml:snakeyaml:1.30","Name":"org.yaml:snakeyaml","Version":"1.30","Relationship":"direct"}]},
	{"Target":"package-lock.json","Class":"lang-pkgs","Type":"npm","Packages":[
		{"ID":"a@1.0.0","Name":"a","Version":"1.0.0","DependsOn":["b@1.0.0"]}]}]}`
	rep, err := ParseReport([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	for _, rp := range rep.Packages {
		for _, p := range rp.Packages {
			switch {
			case rp.Type == "pom" && p.Name == "com.example:app":
				if p.ID != "com.example:app:1.0" || len(p.DependsOn) != 1 || p.DependsOn[0] != "org.yaml:snakeyaml:1.30" {
					t.Errorf("pom root = %+v", p)
				}
			case rp.Type == "npm":
				if p.ID != "" || p.DependsOn != nil {
					t.Errorf("npm package kept its graph: %+v", p)
				}
			}
		}
	}
}
