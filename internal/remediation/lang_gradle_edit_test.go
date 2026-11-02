package remediation

import (
	"strings"
	"testing"
)

func TestGradleLexerOffsets(t *testing.T) {
	src := "a = 'xy' // c\nb(\"z\")"
	toks, err := lexGradle([]byte(src), false)
	if err != nil {
		t.Fatal(err)
	}
	for _, tk := range toks {
		got := src[tk.start:tk.end]
		switch tk.kind {
		case gtString:
			if got != "'"+tk.text+"'" && got != `"`+tk.text+`"` {
				t.Errorf("string %q has the span %q", tk.text, got)
			}
		default:
			if got != tk.text {
				t.Errorf("token %q has the span %q", tk.text, got)
			}
		}
	}
}

func TestReplaceGradleCoordinate(t *testing.T) {
	kts := "// c: \"g:a:1\"\ndependencies {\n\timplementation(\"g:a:1\") // keep\n}\n"
	got, err := replaceGradleCoordinate([]byte(kts), true, "g:a", "1", "2")
	if err != nil || string(got) != strings.Replace(kts, `implementation("g:a:1")`, `implementation("g:a:2")`, 1) {
		t.Fatalf("%q %v", got, err)
	}
	groovy := "\xef\xbb\xbfdependencies {\r\n    implementation 'g:a:1'\r\n}\r\n"
	got, err = replaceGradleCoordinate([]byte(groovy), false, "g:a", "1", "2")
	if err != nil || string(got) != strings.Replace(groovy, "g:a:1", "g:a:2", 1) {
		t.Fatalf("%q %v", got, err)
	}
	for name, src := range map[string]string{
		"twice": "x(\"g:a:1\")\ny(\"g:a:1\")\n", "absent": "x(\"g:a:3\")\n", "a longer name": "x(\"g:ab:1\")\n",
	} {
		if _, err := replaceGradleCoordinate([]byte(src), true, "g:a", "1", "2"); err == nil {
			t.Errorf("%s: no refusal", name)
		}
	}
}

func TestSetGradleExtra(t *testing.T) {
	for name, c := range map[string]struct {
		kotlin   bool
		src, out string
	}{
		"extra":  {true, "extra[\"p.version\"] = \"1\" // c\n", "extra[\"p.version\"] = \"2\" // c\n"},
		"ext[]":  {false, "ext['p.version'] = '1'\n", "ext['p.version'] = '2'\n"},
		"ext.":   {false, "ext.pversion = \"1\"\n", ""},
		"others": {true, "extra[\"q\"] = \"1\"\nextra[\"p.version\"] = \"1\"\n", "extra[\"q\"] = \"1\"\nextra[\"p.version\"] = \"2\"\n"},
	} {
		prop := "p.version"
		if name == "ext." {
			prop = "pversion"
		}
		got, err := setGradleExtra([]byte(c.src), c.kotlin, prop, "1", "2")
		want := c.out
		if name == "ext." {
			want = "ext.pversion = \"2\"\n"
		}
		if err != nil || string(got) != want {
			t.Errorf("%s: %q %v", name, got, err)
		}
	}
	if _, err := setGradleExtra([]byte("extra[\"p\"] = \"1\"\nextra[\"p\"] = \"1\"\n"), true, "p", "1", "2"); err == nil {
		t.Error("a property set twice was edited")
	}
	if _, err := setGradleExtra([]byte("extra[\"p\"] = \"3\"\n"), true, "p", "1", "2"); err == nil {
		t.Error("a property at another value was edited")
	}
}

func TestAppendGradleConstraintsIsReadBack(t *testing.T) {
	cs := []gradleConstraint{{"org.b:b", "2"}, {"org.a:a", "1.5"}}
	for _, c := range []struct {
		kotlin bool
		file   string
		src    string
		tail   string
	}{
		{true, "build.gradle.kts", "dependencyLocking {\n\tlockAllConfigurations()\n\tlockMode = LockMode.STRICT\n}", "\n\ndependencies {\n\tconstraints {\n\t\timplementation(\"org.a:a:1.5\")\n\t\timplementation(\"org.b:b:2\")\n\t}\n}\n"},
		{false, "build.gradle", "dependencyLocking {\r\n    lockAllConfigurations()\r\n    lockMode = LockMode.STRICT\r\n}\r\n", "\r\ndependencies {\r\n    constraints {\r\n        implementation 'org.a:a:1.5'\r\n        implementation 'org.b:b:2'\r\n    }\r\n}\r\n"},
	} {
		out := appendGradleConstraints([]byte(c.src), c.kotlin, cs)
		if !strings.HasSuffix(string(out), c.tail) || !strings.HasPrefix(string(out), c.src) {
			t.Errorf("%s:\n%q", c.file, out)
		}
		s, err := recognizeGradleScript(c.file, out, false, nil, "9.8.2")
		if err != nil {
			t.Fatalf("%s: %v", c.file, err)
		}
		n := 0
		for _, d := range s.decls {
			if d.constraint && d.conf == "implementation" {
				n++
			}
		}
		if n != 2 {
			t.Errorf("%s: %d constraints read back", c.file, n)
		}
	}
}

func TestSetPropertiesValueAndAppend(t *testing.T) {
	src := "# c\n a.version : 1\nb.version=1\r\n"
	got, err := setPropertiesValue([]byte(src), "a.version", "1", "2")
	if err != nil || string(got) != "# c\n a.version : 2\nb.version=1\r\n" {
		t.Fatalf("%q %v", got, err)
	}
	got, err = setPropertiesValue([]byte(src), "b.version", "1", "2")
	if err != nil || string(got) != "# c\n a.version : 1\nb.version=2\r\n" {
		t.Fatalf("%q %v", got, err)
	}
	if _, err := setPropertiesValue([]byte(src), "a.version", "9", "2"); err == nil {
		t.Error("a value that is not the one the plan read was edited")
	}
	if _, err := setPropertiesValue([]byte(src), "c.version", "1", "2"); err == nil {
		t.Error("a key that is not set was edited")
	}
	if got := string(appendProperty(nil, "k.version", "3")); got != "k.version=3\n" {
		t.Errorf("new file = %q", got)
	}
	if got := string(appendProperty([]byte("a=1\r\nb=2"), "k.version", "3")); got != "a=1\r\nb=2\r\nk.version=3\r\n" {
		t.Errorf("appended = %q", got)
	}
}

func TestCatalogEdits(t *testing.T) {
	const cat = "[versions]\ntext = \"1.9\" # t\n\"odd-name\" = \"2\"\n\n[libraries]\nt = { module = \"g:a\", version.ref = \"text\" }\nl = { group = \"g\", name = \"l\", version = \"3\" }\ns = \"g:s:4\"\n\n[plugins]\np = { id = \"x\", version = \"5\" }\n"
	got, err := setCatalogVersion([]byte(cat), "text", "1.9", "1.10.0")
	if err != nil || string(got) != strings.Replace(cat, `text = "1.9"`, `text = "1.10.0"`, 1) {
		t.Fatalf("%q %v", got, err)
	}
	if got, err = setCatalogVersion([]byte(cat), "odd-name", "2", "3"); err != nil || !strings.Contains(string(got), `"odd-name" = "3"`) {
		t.Fatalf("%q %v", got, err)
	}
	got, err = setCatalogLibrary([]byte(cat), "l", "g:l", "3", "4")
	if err != nil || string(got) != strings.Replace(cat, `version = "3"`, `version = "4"`, 1) {
		t.Fatalf("%q %v", got, err)
	}
	got, err = setCatalogLibrary([]byte(cat), "s", "g:s", "4", "5")
	if err != nil || string(got) != strings.Replace(cat, `"g:s:4"`, `"g:s:5"`, 1) {
		t.Fatalf("%q %v", got, err)
	}
	// The edit reads back as the catalog with that one change.
	c0, c1 := mustCatalog(t, cat), mustCatalog(t, string(got))
	if c0.libs["s"].version != "4" || c1.libs["s"].version != "5" || c1.libs["l"].version != "3" {
		t.Errorf("libs read back: %+v %+v", c0.libs, c1.libs)
	}
	for name, run := range map[string]func() error{
		"a version at another value":   func() error { _, err := setCatalogVersion([]byte(cat), "text", "1.8", "2"); return err },
		"a version of [plugins]":       func() error { _, err := setCatalogVersion([]byte(cat), "p", "5", "6"); return err },
		"a library that is not there":  func() error { _, err := setCatalogLibrary([]byte(cat), "zz", "g:zz", "1", "2"); return err },
		"a library with a version.ref": func() error { _, err := setCatalogLibrary([]byte(cat), "t", "g:a", "1.9", "2"); return err },
		"a multi-line string": func() error {
			_, err := setCatalogVersion([]byte("[versions]\na = \"\"\"1\"\"\"\n"), "a", "1", "2")
			return err
		},
		"a library at another version": func() error { _, err := setCatalogLibrary([]byte(cat), "s", "g:s", "9", "2"); return err },
		"an array of tables": func() error {
			_, err := setCatalogVersion([]byte("[[x]]\n[versions]\na = \"1\"\n"), "a", "1", "2")
			return err
		},
		"the same version set in a copy": func() error {
			_, err := setCatalogVersion([]byte(cat+"[versions]\ntext = \"1.9\"\n"), "text", "1.9", "2")
			return err
		},
	} {
		if run() == nil {
			t.Errorf("%s: no refusal", name)
		}
	}
}
