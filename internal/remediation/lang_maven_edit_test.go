package remediation

import (
	"strings"
	"testing"
)

const mavenEditBase = `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>3.2.0</version>
        <relativePath/> <!-- lookup parent from repository -->
    </parent>
    <groupId>com.example</groupId>
    <artifactId>demo</artifactId>
    <version>0.0.1-SNAPSHOT</version>

    <properties>
        <java.version>17</java.version>
        <!-- pinned for the BOM -->
        <jackson-bom.version>2.15.0</jackson-bom.version>
    </properties>

    <dependencyManagement>
        <dependencies>
            <dependency>
                <groupId>com.fasterxml.jackson</groupId>
                <artifactId>jackson-bom</artifactId>
                <version>${jackson-bom.version}</version>
                <type>pom</type>
                <scope>import</scope>
            </dependency>
        </dependencies>
    </dependencyManagement>

    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
        <!-- utilities -->
        <dependency>
            <groupId>org.apache.commons</groupId>
            <artifactId>commons-lang3</artifactId>
            <version>3.12.0</version>
        </dependency>
        <dependency>
            <groupId>com.google.guava</groupId>
            <artifactId>guava</artifactId>
            <version>31.0-jre</version>
        </dependency>
    </dependencies>

    <build>
        <plugins>
            <plugin>
                <artifactId>maven-compiler-plugin</artifactId>
                <version>3.11.0</version>
            </plugin>
        </plugins>
    </build>

    <profiles>
        <profile>
            <id>extra</id>
            <properties>
                <jackson-bom.version>1.0</jackson-bom.version>
            </properties>
            <dependencies>
                <dependency>
                    <groupId>org.apache.commons</groupId>
                    <artifactId>commons-lang3</artifactId>
                    <version>3.12.0</version>
                </dependency>
            </dependencies>
        </profile>
    </profiles>
</project>
`

const mavenEditSmall = `<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <dependencies>
    <dependency>
      <groupId>g</groupId>
      <artifactId>a</artifactId>
      <version>1.0</version>
    </dependency>
  </dependencies>
</project>
`

func mavenManagedBlock(ind, unit, g, a, v string) string {
	return ind + "<dependency>\n" +
		ind + unit + "<groupId>" + g + "</groupId>\n" +
		ind + unit + "<artifactId>" + a + "</artifactId>\n" +
		ind + unit + "<version>" + v + "</version>\n" +
		ind + "</dependency>\n"
}

func TestMavenEditExactOutputs(t *testing.T) {
	rep := func(src, old, new string) string {
		if strings.Count(src, old) != 1 {
			t.Fatalf("test setup: %q occurs %d times", old, strings.Count(src, old))
		}
		return strings.Replace(src, old, new, 1)
	}
	cr := func(s string) string { return strings.ReplaceAll(s, "\n", "\r\n") }
	tabs := func(s string) string { return strings.ReplaceAll(s, "  ", "\t") }

	tests := []struct {
		name  string
		in    string
		edits []mavenEdit
		want  string
	}{
		{
			name:  "dependency version",
			in:    mavenEditBase,
			edits: []mavenEdit{{Kind: mavenEditDependencyVersion, Index: 1, Value: "3.14.0"}},
			want:  rep(mavenEditBase, "<version>3.12.0</version>\n        </dependency>\n        <dependency>", "<version>3.14.0</version>\n        </dependency>\n        <dependency>"),
		},
		{
			name:  "dependency version of the last entry leaves the profile alone",
			in:    mavenEditBase,
			edits: []mavenEdit{{Kind: mavenEditDependencyVersion, Index: 2, Value: "33.0.0-jre"}},
			want:  rep(mavenEditBase, "31.0-jre", "33.0.0-jre"),
		},
		{
			name:  "managed version replaces a property reference",
			in:    mavenEditBase,
			edits: []mavenEdit{{Kind: mavenEditManagedVersion, Index: 0, Value: "2.17.1"}},
			want:  rep(mavenEditBase, "<version>${jackson-bom.version}</version>", "<version>2.17.1</version>"),
		},
		{
			name:  "existing property keeps comment and profile",
			in:    mavenEditBase,
			edits: []mavenEdit{{Kind: mavenSetProperty, Name: "jackson-bom.version", Value: "2.17.1"}},
			want:  rep(mavenEditBase, "<jackson-bom.version>2.15.0<", "<jackson-bom.version>2.17.1<"),
		},
		{
			name:  "new property goes last in properties",
			in:    mavenEditBase,
			edits: []mavenEdit{{Kind: mavenSetProperty, Name: "tomcat.version", Value: "10.1.20"}},
			want:  rep(mavenEditBase, "2.15.0</jackson-bom.version>\n", "2.15.0</jackson-bom.version>\n        <tomcat.version>10.1.20</tomcat.version>\n"),
		},
		{
			name:  "managed entry goes first after the import",
			in:    mavenEditBase,
			edits: []mavenEdit{{Kind: mavenAddManaged, GroupID: "org.apache.tomcat.embed", ArtifactID: "tomcat-embed-core", Value: "10.1.20"}},
			want: rep(mavenEditBase, "    <dependencyManagement>\n        <dependencies>\n",
				"    <dependencyManagement>\n        <dependencies>\n"+mavenManagedBlock("            ", "    ", "org.apache.tomcat.embed", "tomcat-embed-core", "10.1.20")),
		},
		{
			name: "no properties: block before the dependencies",
			in:   mavenEditSmall,
			edits: []mavenEdit{
				{Kind: mavenSetProperty, Name: "tomcat.version", Value: "10.1.20"},
			},
			want: rep(mavenEditSmall, "  <dependencies>\n", "  <properties>\n    <tomcat.version>10.1.20</tomcat.version>\n  </properties>\n  <dependencies>\n"),
		},
		{
			name:  "no properties, CRLF",
			in:    cr(mavenEditSmall),
			edits: []mavenEdit{{Kind: mavenSetProperty, Name: "tomcat.version", Value: "10.1.20"}},
			want:  cr(rep(mavenEditSmall, "  <dependencies>\n", "  <properties>\n    <tomcat.version>10.1.20</tomcat.version>\n  </properties>\n  <dependencies>\n")),
		},
		{
			name:  "no properties, tabs",
			in:    tabs(mavenEditSmall),
			edits: []mavenEdit{{Kind: mavenSetProperty, Name: "tomcat.version", Value: "10.1.20"}},
			want:  tabs(rep(mavenEditSmall, "  <dependencies>\n", "  <properties>\n    <tomcat.version>10.1.20</tomcat.version>\n  </properties>\n  <dependencies>\n")),
		},
		{
			name:  "no properties, four spaces",
			in:    strings.ReplaceAll(mavenEditSmall, "  ", "    "),
			edits: []mavenEdit{{Kind: mavenSetProperty, Name: "p", Value: "1"}},
			want:  strings.ReplaceAll(rep(mavenEditSmall, "  <dependencies>\n", "  <properties>\n    <p>1</p>\n  </properties>\n  <dependencies>\n"), "  ", "    "),
		},
		{
			name:  "self-closing properties",
			in:    rep(mavenEditSmall, "  <dependencies>\n", "  <properties/>\n  <dependencies>\n"),
			edits: []mavenEdit{{Kind: mavenSetProperty, Name: "p", Value: "1"}},
			want:  rep(mavenEditSmall, "  <dependencies>\n", "  <properties>\n    <p>1</p>\n  </properties>\n  <dependencies>\n"),
		},
		{
			name:  "empty properties with whitespace",
			in:    rep(mavenEditSmall, "  <dependencies>\n", "  <properties>\n  </properties>\n  <dependencies>\n"),
			edits: []mavenEdit{{Kind: mavenSetProperty, Name: "p", Value: "1"}},
			want:  rep(mavenEditSmall, "  <dependencies>\n", "  <properties>\n    <p>1</p>\n  </properties>\n  <dependencies>\n"),
		},
		{
			name:  "properties before dependencyManagement when that comes first",
			in:    rep(mavenEditSmall, "  <dependencies>\n", "  <dependencyManagement/>\n  <dependencies>\n"),
			edits: []mavenEdit{{Kind: mavenSetProperty, Name: "p", Value: "1"}},
			want:  rep(mavenEditSmall, "  <dependencies>\n", "  <properties>\n    <p>1</p>\n  </properties>\n  <dependencyManagement/>\n  <dependencies>\n"),
		},
		{
			name:  "properties and managed block without any sibling go before the end tag",
			in:    "<project>\n  <modelVersion>4.0.0</modelVersion>\n</project>\n",
			edits: []mavenEdit{{Kind: mavenSetProperty, Name: "p", Value: "1"}, {Kind: mavenAddManaged, GroupID: "g", ArtifactID: "a", Value: "2"}},
			want: "<project>\n  <modelVersion>4.0.0</modelVersion>\n  <properties>\n    <p>1</p>\n  </properties>\n" +
				"  <dependencyManagement>\n    <dependencies>\n" + mavenManagedBlock("      ", "  ", "g", "a", "2") + "    </dependencies>\n  </dependencyManagement>\n</project>\n",
		},
		{
			name:  "missing dependencyManagement goes before dependencies",
			in:    mavenEditSmall,
			edits: []mavenEdit{{Kind: mavenAddManaged, GroupID: "g2", ArtifactID: "a2", Value: "2.0"}},
			want: rep(mavenEditSmall, "  <dependencies>\n", "  <dependencyManagement>\n    <dependencies>\n"+
				mavenManagedBlock("      ", "  ", "g2", "a2", "2.0")+"    </dependencies>\n  </dependencyManagement>\n  <dependencies>\n"),
		},
		{
			name: "missing dependencyManagement goes before build when there are no dependencies",
			in:   "<project>\n  <build/>\n</project>\n",
			edits: []mavenEdit{
				{Kind: mavenAddManaged, GroupID: "g", ArtifactID: "a", Value: "1"},
			},
			want: "<project>\n  <dependencyManagement>\n    <dependencies>\n" + mavenManagedBlock("      ", "  ", "g", "a", "1") +
				"    </dependencies>\n  </dependencyManagement>\n  <build/>\n</project>\n",
		},
		{
			name: "dependencyManagement without dependencies gets them",
			in:   "<project>\n  <dependencyManagement>\n  </dependencyManagement>\n</project>\n",
			edits: []mavenEdit{
				{Kind: mavenAddManaged, GroupID: "g", ArtifactID: "a", Value: "1"},
			},
			want: "<project>\n  <dependencyManagement>\n    <dependencies>\n" + mavenManagedBlock("      ", "  ", "g", "a", "1") +
				"    </dependencies>\n  </dependencyManagement>\n</project>\n",
		},
		{
			name: "two managed entries keep the order given, before the existing one",
			in:   mavenEditBase,
			edits: []mavenEdit{
				{Kind: mavenAddManaged, GroupID: "g1", ArtifactID: "a1", Value: "1"},
				{Kind: mavenAddManaged, GroupID: "g2", ArtifactID: "a2", Value: "2"},
			},
			want: rep(mavenEditBase, "    <dependencyManagement>\n        <dependencies>\n",
				"    <dependencyManagement>\n        <dependencies>\n"+
					mavenManagedBlock("            ", "    ", "g1", "a1", "1")+mavenManagedBlock("            ", "    ", "g2", "a2", "2")),
		},
		{
			name: "several edits at once use the original positions",
			in:   mavenEditBase,
			edits: []mavenEdit{
				{Kind: mavenEditDependencyVersion, Index: 2, Value: "33.0.0-jre"},
				{Kind: mavenSetProperty, Name: "jackson-bom.version", Value: "2.17.1"},
				{Kind: mavenSetProperty, Name: "tomcat.version", Value: "10.1.20"},
				{Kind: mavenEditDependencyVersion, Index: 1, Value: "3.14.0"},
				{Kind: mavenEditManagedVersion, Index: 0, Value: "2.17.1"},
			},
			want: rep(rep(rep(rep(mavenEditBase,
				"31.0-jre", "33.0.0-jre"),
				"<jackson-bom.version>2.15.0</jackson-bom.version>\n", "<jackson-bom.version>2.17.1</jackson-bom.version>\n        <tomcat.version>10.1.20</tomcat.version>\n"),
				"<version>3.12.0</version>\n        </dependency>\n        <dependency>", "<version>3.14.0</version>\n        </dependency>\n        <dependency>"),
				"<version>${jackson-bom.version}</version>", "<version>2.17.1</version>"),
		},
		{
			name: "properties block and managed block share one anchor",
			in:   mavenEditSmall,
			edits: []mavenEdit{
				{Kind: mavenAddManaged, GroupID: "g2", ArtifactID: "a2", Value: "2.0"},
				{Kind: mavenSetProperty, Name: "p", Value: "1"},
			},
			want: rep(mavenEditSmall, "  <dependencies>\n", "  <properties>\n    <p>1</p>\n  </properties>\n  <dependencyManagement>\n    <dependencies>\n"+
				mavenManagedBlock("      ", "  ", "g2", "a2", "2.0")+"    </dependencies>\n  </dependencyManagement>\n  <dependencies>\n"),
		},
		{
			name:  "profile properties are not the project's",
			in:    "<project>\n  <modelVersion>4.0.0</modelVersion>\n  <profiles>\n    <profile>\n      <properties>\n        <p>old</p>\n      </properties>\n    </profile>\n  </profiles>\n</project>\n",
			edits: []mavenEdit{{Kind: mavenSetProperty, Name: "p", Value: "1"}},
			want:  "<project>\n  <modelVersion>4.0.0</modelVersion>\n  <profiles>\n    <profile>\n      <properties>\n        <p>old</p>\n      </properties>\n    </profile>\n  </profiles>\n  <properties>\n    <p>1</p>\n  </properties>\n</project>\n",
		},
		{
			name:  "self-closing version is filled",
			in:    rep(mavenEditSmall, "<version>1.0</version>", "<version />"),
			edits: []mavenEdit{{Kind: mavenEditDependencyVersion, Index: 0, Value: "2.0"}},
			want:  rep(mavenEditSmall, "<version>1.0</version>", "<version>2.0</version>"),
		},
		{
			name:  "whitespace around the version text is replaced with it",
			in:    rep(mavenEditSmall, "<version>1.0</version>", "<version>\n 1.0\n</version>"),
			edits: []mavenEdit{{Kind: mavenEditDependencyVersion, Index: 0, Value: "2.0"}},
			want:  rep(mavenEditSmall, "<version>1.0</version>", "<version>2.0</version>"),
		},
		{
			name:  "no namespace",
			in:    strings.Replace(mavenEditSmall, ` xmlns="http://maven.apache.org/POM/4.0.0"`, "", 1),
			edits: []mavenEdit{{Kind: mavenEditDependencyVersion, Index: 0, Value: "2.0"}},
			want:  strings.Replace(strings.Replace(mavenEditSmall, ` xmlns="http://maven.apache.org/POM/4.0.0"`, "", 1), "1.0", "2.0", 1),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := applyMavenEdits([]byte(tc.in), tc.edits)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tc.want {
				t.Fatalf("output differs\n--- got ---\n%s\n--- want ---\n%s", got, tc.want)
			}
		})
	}
}

func TestMavenEditErrors(t *testing.T) {
	prefixedVersion := strings.Replace(strings.Replace(mavenEditSmall, "<version>1.0</version>", "<x:version>1.0</x:version>", 1), `<project `, `<project xmlns:x="urn:x" `, 1)
	prefixedProps := strings.Replace(mavenEditSmall, "  <dependencies>", `  <m:properties xmlns:m="http://maven.apache.org/POM/4.0.0"><m:p>1</m:p></m:properties>
  <dependencies>`, 1)
	noVersion := strings.Replace(mavenEditSmall, "      <version>1.0</version>\n", "", 1)
	twoVersions := strings.Replace(mavenEditSmall, "<version>1.0</version>", "<version>1.0</version><version>1.1</version>", 1)
	commentVersion := strings.Replace(mavenEditSmall, "<version>1.0</version>", "<version>1<!-- x -->.0</version>", 1)
	cdataVersion := strings.Replace(mavenEditSmall, "<version>1.0</version>", "<version><![CDATA[1.0]]></version>", 1)
	dupProp := strings.Replace(mavenEditSmall, "  <dependencies>", "  <properties><p>1</p><p>2</p></properties>\n  <dependencies>", 1)
	prefixedRoot := `<m:project xmlns:m="urn:m"><m:modelVersion>4</m:modelVersion></m:project>`
	dupProps := strings.Replace(mavenEditSmall, "  <dependencies>", "  <properties/>\n  <properties/>\n  <dependencies>", 1)
	latin1 := "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\n<!-- caf\xe9 -->\n" + mavenEditSmall

	ver := func(i int, v string) []mavenEdit {
		return []mavenEdit{{Kind: mavenEditDependencyVersion, Index: i, Value: v}}
	}
	tests := []struct {
		name  string
		in    string
		edits []mavenEdit
	}{
		{"index out of range", mavenEditSmall, ver(1, "2.0")},
		{"negative index", mavenEditSmall, ver(-1, "2.0")},
		{"managed index out of range", mavenEditBase, []mavenEdit{{Kind: mavenEditManagedVersion, Index: 1, Value: "1"}}},
		{"managed without dependencyManagement", mavenEditSmall, []mavenEdit{{Kind: mavenEditManagedVersion, Index: 0, Value: "1"}}},
		{"profile dependencies are not indexed", mavenEditBase, ver(3, "1.0")},
		{"missing version", noVersion, ver(0, "2.0")},
		{"two version elements", twoVersions, ver(0, "2.0")},
		{"comment inside version", commentVersion, ver(0, "2.0")},
		{"CDATA inside version", cdataVersion, ver(0, "2.0")},
		{"prefixed version", prefixedVersion, ver(0, "2.0")},
		{"prefixed properties", prefixedProps, []mavenEdit{{Kind: mavenSetProperty, Name: "p", Value: "2"}}},
		{"prefixed root", prefixedRoot, []mavenEdit{{Kind: mavenSetProperty, Name: "p", Value: "2"}}},
		{"duplicate property", dupProp, []mavenEdit{{Kind: mavenSetProperty, Name: "p", Value: "3"}}},
		{"two properties elements", dupProps, []mavenEdit{{Kind: mavenSetProperty, Name: "p", Value: "3"}}},
		{"same property twice", mavenEditSmall, []mavenEdit{{Kind: mavenSetProperty, Name: "p", Value: "1"}, {Kind: mavenSetProperty, Name: "p", Value: "2"}}},
		{"same version element twice", mavenEditSmall, append(ver(0, "2.0"), ver(0, "3.0")...)},
		{"same managed version twice", mavenEditBase, []mavenEdit{{Kind: mavenEditManagedVersion, Index: 0, Value: "1"}, {Kind: mavenEditManagedVersion, Index: 0, Value: "2"}}},
		{"empty value", mavenEditSmall, ver(0, "")},
		{"value with space", mavenEditSmall, ver(0, "1 0")},
		{"value with angle bracket", mavenEditSmall, ver(0, "1<0")},
		{"value with ampersand", mavenEditSmall, ver(0, "1&0")},
		{"value with quote", mavenEditSmall, ver(0, `1"0`)},
		{"value with apostrophe", mavenEditSmall, ver(0, "1'0")},
		{"value with newline", mavenEditSmall, ver(0, "1\n0")},
		{"value with control character", mavenEditSmall, ver(0, "1\x000")},
		{"value too long", mavenEditSmall, ver(0, strings.Repeat("1", 257))},
		{"bad property name", mavenEditSmall, []mavenEdit{{Kind: mavenSetProperty, Name: "a b", Value: "1"}}},
		{"property name with colon", mavenEditSmall, []mavenEdit{{Kind: mavenSetProperty, Name: "x:y", Value: "1"}}},
		{"property name starting with a digit", mavenEditSmall, []mavenEdit{{Kind: mavenSetProperty, Name: "1a", Value: "1"}}},
		{"bad groupId", mavenEditSmall, []mavenEdit{{Kind: mavenAddManaged, GroupID: "g<", ArtifactID: "a", Value: "1"}}},
		{"empty artifactId", mavenEditSmall, []mavenEdit{{Kind: mavenAddManaged, GroupID: "g", ArtifactID: "", Value: "1"}}},
		{"unknown kind", mavenEditSmall, []mavenEdit{{Kind: 99, Value: "1"}}},
		{"not XML", "<project>", ver(0, "1")},
		{"DOCTYPE", "<!DOCTYPE project>\n" + mavenEditSmall, ver(0, "2.0")},
		{"wrong root", "<settings></settings>", []mavenEdit{{Kind: mavenSetProperty, Name: "p", Value: "1"}}},
		{"non-ASCII bytes in a recoded file", latin1, ver(0, "2.0")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := applyMavenEdits([]byte(tc.in), tc.edits)
			if err == nil {
				t.Fatalf("expected an error, got output:\n%s", got)
			}
		})
	}
}

func TestMavenEditKeepsInputAndAllowsNoEdits(t *testing.T) {
	in := []byte(mavenEditBase)
	cp := string(in)
	got, err := applyMavenEdits(in, nil)
	if err != nil || string(got) != cp {
		t.Fatalf("no edits: err=%v changed=%v", err, string(got) != cp)
	}
	if _, err := applyMavenEdits(in, []mavenEdit{{Kind: mavenEditDependencyVersion, Index: 1, Value: "9"}}); err != nil {
		t.Fatal(err)
	}
	if string(in) != cp {
		t.Fatal("input was modified")
	}
}

func TestMavenEditResultParses(t *testing.T) {
	got, err := applyMavenEdits([]byte(mavenEditBase), []mavenEdit{
		{Kind: mavenSetProperty, Name: "tomcat.version", Value: "10.1.20"},
		{Kind: mavenAddManaged, GroupID: "org.apache.tomcat.embed", ArtifactID: "tomcat-embed-core", Value: "10.1.20"},
		{Kind: mavenEditDependencyVersion, Index: 1, Value: "3.14.0"},
	})
	if err != nil {
		t.Fatal(err)
	}
	p, err := parseMavenPOM(got)
	if err != nil {
		t.Fatal(err)
	}
	if p.Properties["tomcat.version"] != "10.1.20" || p.Dependencies[1].Version != "3.14.0" {
		t.Fatalf("unexpected model: %+v", p)
	}
	if len(p.DependencyManagement) != 2 || p.DependencyManagement[0].ArtifactID != "tomcat-embed-core" || !p.DependencyManagement[1].IsImport() {
		t.Fatalf("managed dependencies: %+v", p.DependencyManagement)
	}
	if len(p.Profiles) != 1 || p.Profiles[0].ID != "extra" {
		t.Fatalf("profiles: %+v", p.Profiles)
	}
}

func TestMavenEditVerifyRejectsExtraChanges(t *testing.T) {
	edits := []mavenEdit{{Kind: mavenSetProperty, Name: "jackson-bom.version", Value: "2.17.1"}}
	good := strings.Replace(mavenEditBase, "<jackson-bom.version>2.15.0<", "<jackson-bom.version>2.17.1<", 1)
	if err := verifyMavenEdits([]byte(mavenEditBase), []byte(good), edits); err != nil {
		t.Fatal(err)
	}
	mutate := func(old, new string) string { return strings.Replace(good, old, new, 1) }
	tests := []struct {
		name  string
		after string
		edits []mavenEdit
	}{
		{"second property changed by hand", mutate("<java.version>17<", "<java.version>21<"), edits},
		{"property added by hand", mutate("</properties>", "<extra>1</extra></properties>"), edits},
		{"property removed by hand", mutate("<java.version>17</java.version>", ""), edits},
		{"requested value not applied", mutate("2.17.1", "2.17.2"), edits},
		{"dependency version changed by hand", mutate("<version>3.12.0</version>\n        </dependency>\n        <dependency>", "<version>3.13.0</version>\n        </dependency>\n        <dependency>"), edits},
		{"dependency added by hand", mutate("</dependencies>\n\n    <build>", "<dependency><groupId>x</groupId><artifactId>y</artifactId></dependency></dependencies>\n\n    <build>"), edits},
		{"parent version changed", mutate("<version>3.2.0</version>", "<version>3.3.0</version>"), edits},
		{"module added", mutate("</project>", "<modules><module>m</module></modules></project>"), edits},
		{"requested edit missing", mavenEditBase, edits},
		{"managed entry added at the end", strings.Replace(good, "</dependencies>\n    </dependencyManagement>", mavenManagedBlock("", "  ", "g", "a", "1")+"</dependencies>\n    </dependencyManagement>", 1),
			append(append([]mavenEdit{}, edits...), mavenEdit{Kind: mavenAddManaged, GroupID: "g", ArtifactID: "a", Value: "1"})},
		{"index out of range", good, []mavenEdit{{Kind: mavenEditDependencyVersion, Index: 9, Value: "1"}}},
		{"not XML", "<project>", edits},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := verifyMavenEdits([]byte(mavenEditBase), []byte(tc.after), tc.edits); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}
