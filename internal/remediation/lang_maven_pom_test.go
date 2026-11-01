package remediation

import (
	"reflect"
	"strings"
	"testing"
)

const bootPOM = `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <modelVersion>4.0.0</modelVersion>
  <parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>3.2.1</version>
    <relativePath/>
  </parent>
  <artifactId>demo-app</artifactId>
  <packaging>jar</packaging>
  <modules>
    <module>mod-a</module>
    <module> mod-b </module>
  </modules>
  <properties>
    <java.version>21</java.version>
    <jackson.ver>2.15.0</jackson.ver>
    <java.version>17</java.version>
    <tomcat.version>
      10.1.16
    </tomcat.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>${jackson.ver}</version>
    </dependency>
    <dependency>
      <groupId>org.example</groupId>
      <artifactId>opt</artifactId>
      <version>1.0</version>
      <optional>true</optional>
      <exclusions>
        <exclusion><groupId>x</groupId><artifactId>y</artifactId></exclusion>
      </exclusions>
    </dependency>
    <dependency>
      <groupId>org.example</groupId>
      <artifactId>noex</artifactId>
      <exclusions/>
    </dependency>
  </dependencies>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>com.fasterxml.jackson</groupId>
        <artifactId>jackson-bom</artifactId>
        <version>${jackson-bom.version}</version>
        <type>pom</type>
        <scope>import</scope>
      </dependency>
      <dependency>
        <groupId>io.netty</groupId>
        <artifactId>netty-transport-native-epoll</artifactId>
        <version>4.1.100.Final</version>
        <classifier>linux-x86_64</classifier>
      </dependency>
    </dependencies>
  </dependencyManagement>
  <profiles>
    <profile>
      <id>extra</id>
      <dependencies>
        <dependency><groupId>a</groupId><artifactId>b</artifactId><version>1</version></dependency>
      </dependencies>
    </profile>
    <profile>
      <id>props</id>
      <properties><foo>bar</foo></properties>
    </profile>
    <profile>
      <id>idle</id>
      <activation><activeByDefault>true</activeByDefault></activation>
    </profile>
  </profiles>
  <repositories>
    <repository><id>r</id><url>https://example.com/repo</url></repository>
  </repositories>
  <pluginRepositories>
    <pluginRepository><id>pr</id><url>https://example.com/plugins</url></pluginRepository>
  </pluginRepositories>
  <distributionManagement>
    <relocation><groupId>new.group</groupId></relocation>
  </distributionManagement>
  <build>
    <dependencies><dependency><groupId>no</groupId><artifactId>no</artifactId></dependency></dependencies>
    <plugins>
      <plugin>
        <artifactId>maven-compiler-plugin</artifactId>
        <version>${compiler.version}</version>
        <configuration>
          <release>${java.version}</release>
          <args>${a} and ${b} and ${a}</args>
        </configuration>
      </plugin>
    </plugins>
  </build>
</project>`

func TestParseMavenPOMBootStyle(t *testing.T) {
	p, err := parseMavenPOM([]byte(bootPOM))
	if err != nil {
		t.Fatal(err)
	}
	wantParent := &mavenParent{GroupID: "org.springframework.boot", ArtifactID: "spring-boot-starter-parent", Version: "3.2.1", RelativePathSet: true}
	if !reflect.DeepEqual(p.Parent, wantParent) {
		t.Errorf("parent = %+v", p.Parent)
	}
	if p.GroupID != "" || p.ArtifactID != "demo-app" || p.Version != "" || p.Packaging != "jar" {
		t.Errorf("coordinates = %q %q %q %q", p.GroupID, p.ArtifactID, p.Version, p.Packaging)
	}
	if p.EffectiveGroupID() != "org.springframework.boot" || p.EffectiveVersion() != "3.2.1" {
		t.Errorf("effective = %q %q", p.EffectiveGroupID(), p.EffectiveVersion())
	}
	if !reflect.DeepEqual(p.Modules, []string{"mod-a", "mod-b"}) {
		t.Errorf("modules = %q", p.Modules)
	}
	if !reflect.DeepEqual(p.PropertyOrder, []string{"java.version", "jackson.ver", "tomcat.version"}) {
		t.Errorf("property order = %q", p.PropertyOrder)
	}
	if p.Properties["java.version"] != "17" || p.Properties["tomcat.version"] != "10.1.16" || p.Properties["jackson.ver"] != "2.15.0" {
		t.Errorf("properties = %v", p.Properties)
	}
	if len(p.Dependencies) != 3 {
		t.Fatalf("dependencies = %+v", p.Dependencies)
	}
	if d := p.Dependencies[0]; d.GroupID != "com.fasterxml.jackson.core" || d.ArtifactID != "jackson-databind" || d.Version != "${jackson.ver}" {
		t.Errorf("dep 0 = %+v", d)
	}
	if d := p.Dependencies[1]; d.Optional != "true" || !d.HasExclusions {
		t.Errorf("dep 1 = %+v", d)
	}
	if d := p.Dependencies[2]; d.HasExclusions || d.Optional != "" || d.Version != "" {
		t.Errorf("dep 2 = %+v", d)
	}
	if len(p.DependencyManagement) != 2 {
		t.Fatalf("dependencyManagement = %+v", p.DependencyManagement)
	}
	if bom := p.DependencyManagement[0]; !bom.IsImport() || bom.Version != "${jackson-bom.version}" {
		t.Errorf("bom = %+v", bom)
	}
	if c := p.DependencyManagement[1]; c.IsImport() || c.Classifier != "linux-x86_64" {
		t.Errorf("classifier entry = %+v", c)
	}
	if len(p.Profiles) != 3 {
		t.Fatalf("profiles = %+v", p.Profiles)
	}
	if e := p.Profiles[0]; e.ID != "extra" || !e.Dependencies || !e.RuntimeDependencies || e.Activation || e.Properties {
		t.Errorf("extra = %+v", e)
	}
	if e := p.Profiles[1]; e.ID != "props" || !e.Properties || !reflect.DeepEqual(e.PropertyNames, []string{"foo"}) || e.Dependencies {
		t.Errorf("props = %+v", e)
	}
	if e := p.Profiles[2]; e.ID != "idle" || !e.Activation || e.Dependencies || e.Properties {
		t.Errorf("idle = %+v", e)
	}
	if !reflect.DeepEqual(p.Repositories, []string{"https://example.com/repo"}) ||
		!reflect.DeepEqual(p.PluginRepositories, []string{"https://example.com/plugins"}) {
		t.Errorf("repositories = %q %q", p.Repositories, p.PluginRepositories)
	}
	if !p.Relocation {
		t.Error("relocation not seen")
	}
	// The build's own <dependencies> is not the project's.
	for _, d := range p.Dependencies {
		if d.GroupID == "no" {
			t.Error("a dependency inside <build> was taken as a project dependency")
		}
	}
	want := []string{"compiler.version", "java.version", "a", "b"}
	if !reflect.DeepEqual(p.PluginVersionRefs, want) {
		t.Errorf("PluginVersionRefs = %q, want %q", p.PluginVersionRefs, want)
	}
}

func TestParseMavenPOMNamespaceAndEmptyRelativePath(t *testing.T) {
	plain := `<project><groupId>g</groupId><artifactId>a</artifactId><version>1</version>
<parent><groupId>pg</groupId><artifactId>pa</artifactId><version>2</version><relativePath>../x/pom.xml</relativePath></parent></project>`
	ns := strings.Replace(plain, "<project>", `<project xmlns="http://maven.apache.org/POM/4.0.0">`, 1)
	for name, doc := range map[string]string{"plain": plain, "namespaced": ns} {
		p, err := parseMavenPOM([]byte(doc))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if p.EffectiveGroupID() != "g" || p.EffectiveVersion() != "1" {
			t.Errorf("%s: effective = %q %q", name, p.EffectiveGroupID(), p.EffectiveVersion())
		}
		if !p.Parent.RelativePathSet || p.Parent.RelativePath != "../x/pom.xml" {
			t.Errorf("%s: parent = %+v", name, p.Parent)
		}
	}
	p, err := parseMavenPOM([]byte(`<project><artifactId>a</artifactId></project>`))
	if err != nil {
		t.Fatal(err)
	}
	if p.Parent != nil || p.EffectiveGroupID() != "" || p.EffectiveVersion() != "" {
		t.Errorf("pom without parent = %+v", p)
	}
}

func TestParseMavenPOMLatin1(t *testing.T) {
	doc := "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><project><name>caf\xe9</name><artifactId>a</artifactId></project>"
	if _, err := parseMavenPOM([]byte(doc)); err != nil {
		t.Fatal(err)
	}
	doc = "<?xml version=\"1.0\" encoding=\"EBCDIC\"?><project/>"
	if _, err := parseMavenPOM([]byte(doc)); err == nil {
		t.Error("an unknown encoding must be refused")
	}
}

func TestParseMavenPOMRefused(t *testing.T) {
	deep := strings.Repeat("<a>", maxMavenPOMDepth+1) + strings.Repeat("</a>", maxMavenPOMDepth+1)
	for name, doc := range map[string]string{
		"doctype":        `<?xml version="1.0"?><!DOCTYPE project [<!ENTITY x "y">]><project><artifactId>&x;</artifactId></project>`,
		"doctype-plain":  `<!DOCTYPE project><project/>`,
		"oversize":       "<project><description>" + strings.Repeat("x", maxMavenPOMBytes) + "</description></project>",
		"malformed":      `<project><artifactId>a</project>`,
		"truncated":      `<project><artifactId>a</artifactId>`,
		"empty":          ``,
		"not xml":        `hello`,
		"wrong root":     `<settings/>`,
		"two roots":      `<project/><project/>`,
		"deep":           "<project>" + deep + "</project>",
		"unknown entity": `<project><name>&nope;</name></project>`,
	} {
		if _, err := parseMavenPOM([]byte(doc)); err == nil {
			t.Errorf("%s: parsed, want an error", name)
		}
	}
}

func TestMavenPropertyRefs(t *testing.T) {
	for s, want := range map[string]string{"${a.b}": "a.b", "  ${x}\n": "x"} {
		if got, ok := mavenPropertyRef(s); !ok || got != want {
			t.Errorf("mavenPropertyRef(%q) = %q, %v", s, got, ok)
		}
	}
	for _, s := range []string{"", "1.0", "${a}${b}", "x${a}", "${}", "${a", "$${a}"} {
		if got, ok := mavenPropertyRef(s); ok {
			t.Errorf("mavenPropertyRef(%q) = %q, want not ok", s, got)
		}
	}
	if got := mavenPropertyRefs("${a}-${b.c}/${a}"); !reflect.DeepEqual(got, []string{"a", "b.c", "a"}) {
		t.Errorf("mavenPropertyRefs = %q", got)
	}
	if got := mavenPropertyRefs("plain"); len(got) != 0 {
		t.Errorf("mavenPropertyRefs(plain) = %q", got)
	}
}

func TestIsMavenVersionRange(t *testing.T) {
	for s, want := range map[string]bool{
		"[1.0,2.0)": true, "(,1.0]": true, "[1.0]": true, " [1.0,) ": true, "(,1.0],[1.2,)": true,
		"1.0": false, "": false, "[": false, "${v}": false, "1.0-SNAPSHOT": false,
	} {
		if got := isMavenVersionRange(s); got != want {
			t.Errorf("isMavenVersionRange(%q) = %v, want %v", s, got, want)
		}
	}
}
