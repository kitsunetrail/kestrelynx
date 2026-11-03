package remediation

import (
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/github"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

func TestGlobalNodeModule(t *testing.T) {
	for path, want := range map[string]string{
		"usr/local/lib/node_modules/npm/node_modules/brace-expansion/package.json":                                 "npm",
		"usr/local/lib/node_modules/npm/node_modules/@npmcli/metavuln-calculator/node_modules/pacote/package.json": "npm",
		"usr/local/lib/node_modules/npm/package.json":                                                              "npm",
		"/usr/lib/node_modules/corepack/package.json":                                                              "corepack",
		"root/.nvm/versions/node/v22.1.0/lib/node_modules/@scope/tool/node_modules/x/package.json":                 "@scope/tool",
		"app/node_modules/.pnpm/brace-expansion@1.1.14/node_modules/brace-expansion/package.json":                  "",
		"app/node_modules/lib/node_modules/x/package.json":                                                         "",
		"node_modules/x/package.json":                                                                              "",
		"usr/local/lib/node_modules":                                                                               "",
		"":                                                                                                         "",
	} {
		owner, ok := GlobalNodeModule(path)
		if ok != (want != "") || owner != want {
			t.Errorf("%q = %q %v, want %q", path, owner, ok, want)
		}
	}
}

func globalFinding(vuln, pkg, ver, fixed, path string) scanner.Finding {
	f := nodeFinding(vuln, pkg, ver, fixed)
	f.PkgPath = path
	return f
}

const npmGlobal = "usr/local/lib/node_modules/npm/node_modules/"

// The packages of npm in a node image are not matched against the project's
// lockfile, even when it lists the same name or the same version; the
// project's own copy of a package is.
func TestLanguagePlan_GlobalNodeModulesAreListedApart(t *testing.T) {
	gh := newFakeGitHub()
	npmRepo(gh, "ex/app", "web")
	deps := []DependencyMapping{depMapping("compose/shop/web", "ex/app", "web")}
	plan := langPlan(t, gh, deps, nil, langInput("shop", "web",
		globalFinding("CVE-1", "lodash", "4.17.20", "4.17.21", "app/node_modules/lodash/package.json"),
		globalFinding("CVE-1", "lodash", "4.17.20", "4.17.21", npmGlobal+"lodash/package.json"),
		globalFinding("CVE-2", "qs", "6.10.0", "6.11.3", npmGlobal+"qs/package.json"),
		globalFinding("CVE-3", "sigstore", "3.1.0", "4.1.1", npmGlobal+"sigstore/package.json")))
	if len(plan.LanguageItems) != 1 {
		t.Fatalf("items = %d", len(plan.LanguageItems))
	}
	it := plan.LanguageItems[0]
	if it.Category != CategoryDependencyUpdateCandidate || it.Manager != ManagerNpm || it.Key != "deps:ex/app@main:web#npm" {
		t.Errorf("item = %s %s %q (%s)", it.Category, it.Manager, it.Key, it.Detail)
	}
	var update, global []string
	for _, p := range it.Packages {
		switch {
		case p.Action == ActionUpdate:
			update = append(update, p.Name)
			if len(p.Origins) != 1 || !strings.HasPrefix(p.Origins[0].PkgPath, "app/") {
				t.Errorf("the update carries %+v", p.Origins)
			}
		case p.Reason == ReasonGlobalNodeModules && p.Action == ActionManual:
			global = append(global, p.Name)
			if len(p.Occurrences) != 0 || !strings.Contains(p.Detail, npmGlobal+p.Name+"/package.json") {
				t.Errorf("%s: occurrences %+v, detail %q", p.Name, p.Occurrences, p.Detail)
			}
		default:
			t.Errorf("unexpected package %+v", p)
		}
	}
	if strings.Join(update, ",") != "lodash" || strings.Join(global, ",") != "lodash,qs,sigstore" {
		t.Errorf("update %v, global %v", update, global)
	}
}

// A unit whose findings are all in a global node_modules is one manual item
// named after the lockfile; its files are not read.
func TestLanguagePlan_OnlyGlobalNodeModules(t *testing.T) {
	gh := newFakeGitHub()
	npmRepo(gh, "ex/app", "web")
	deps := []DependencyMapping{depMapping("compose/shop/web", "ex/app", "web")}
	plan := langPlan(t, gh, deps, nil, langInput("shop", "web",
		globalFinding("CVE-1", "brace-expansion", "2.0.2", "2.0.3", npmGlobal+"brace-expansion/package.json"),
		globalFinding("CVE-2", "pacote", "20.0.1", "21.5.1", npmGlobal+"@npmcli/metavuln-calculator/node_modules/pacote/package.json")))
	if len(plan.LanguageItems) != 1 {
		t.Fatalf("items = %d", len(plan.LanguageItems))
	}
	it := plan.LanguageItems[0]
	if it.Category != CategoryManual || it.Reason != ReasonGlobalNodeModules || it.Manager != ManagerNpm || it.Key != "deps:ex/app@main:web#npm" {
		t.Errorf("item = %s %s %s %q", it.Category, it.Reason, it.Manager, it.Key)
	}
	if len(it.Packages) != 2 || it.Count(ActionManual) != 2 {
		t.Errorf("packages = %+v", it.Packages)
	}
	if gh.count("read:") != 0 {
		t.Errorf("files were read: %v", gh.calls)
	}

	// Without a lockfile the item says so, keeps the key of the ecosystem, and
	// its packages keep their own reason.
	empty := newFakeGitHub()
	empty.put("ex/app", "web", "README.md", "x")
	plan = langPlan(t, empty, deps, nil, langInput("shop", "web",
		globalFinding("CVE-1", "brace-expansion", "2.0.2", "2.0.3", npmGlobal+"brace-expansion/package.json")))
	if it := plan.LanguageItems[0]; it.Category != CategoryManual || it.Reason != ReasonDependencyFilesNotFound || it.Manager != "" ||
		it.Key != "deps:ex/app@main:web#node-pkg" || it.Packages[0].Reason != ReasonGlobalNodeModules {
		t.Errorf("item = %s %s %s %q %+v", it.Category, it.Reason, it.Manager, it.Key, it.Packages)
	}
}

// When the branch cannot be read the item has that outcome, and the packages
// of a global node_modules keep their own reason, with or without packages of
// the project.
func TestLanguagePlan_GlobalNodeModulesWhenTheSourceCannotBeRead(t *testing.T) {
	deps := []DependencyMapping{depMapping("compose/shop/web", "ex/app", "web")}
	g := globalFinding("CVE-2", "qs", "6.10.0", "6.11.3", npmGlobal+"qs/package.json")
	for name, fs := range map[string][]scanner.Finding{
		"mixed":       {nodeFinding("CVE-1", "lodash", "4.17.20", "4.17.21"), g},
		"global only": {g},
	} {
		gh := newFakeGitHub()
		gh.branchErr["ex/app"] = github.ErrNotFound
		it := langPlan(t, gh, deps, nil, langInput("shop", "web", fs...)).LanguageItems[0]
		if it.Category != CategoryFailed || it.Reason != ReasonSourceNotFound || len(it.Packages) != len(fs) {
			t.Fatalf("%s: item = %s %s %+v", name, it.Category, it.Reason, it.Packages)
		}
		last := it.Packages[len(it.Packages)-1]
		if last.Name != "qs" || last.Action != ActionManual || last.Reason != ReasonGlobalNodeModules {
			t.Errorf("%s: global package = %+v", name, last)
		}
		if len(fs) == 2 && (it.Packages[0].Reason != "" || it.Packages[0].Action != "") {
			t.Errorf("%s: project package = %+v", name, it.Packages[0])
		}
	}
}

// An item whose files cannot be used keeps their outcome, and still lists the
// packages of a global node_modules with their own reason.
func TestLanguagePlan_GlobalNodeModulesWithUnusableFiles(t *testing.T) {
	gh := newFakeGitHub()
	gh.put("ex/app", "web", "package.json", npmManifest)
	gh.put("ex/app", "web", "package-lock.json", "{not json")
	deps := []DependencyMapping{depMapping("compose/shop/web", "ex/app", "web")}
	plan := langPlan(t, gh, deps, nil, langInput("shop", "web",
		nodeFinding("CVE-1", "lodash", "4.17.20", "4.17.21"),
		globalFinding("CVE-2", "qs", "6.10.0", "6.11.3", npmGlobal+"qs/package.json")))
	it := plan.LanguageItems[0]
	if it.Category != CategoryManual || it.Reason != ReasonUnparsableSource || len(it.Packages) != 2 {
		t.Fatalf("item = %s %s %+v", it.Category, it.Reason, it.Packages)
	}
	if p := it.Packages[0]; p.Name != "lodash" || p.Reason != ReasonUnparsableSource {
		t.Errorf("project package = %+v", p)
	}
	if p := it.Packages[1]; p.Name != "qs" || p.Reason != ReasonGlobalNodeModules {
		t.Errorf("global package = %+v", p)
	}
}
