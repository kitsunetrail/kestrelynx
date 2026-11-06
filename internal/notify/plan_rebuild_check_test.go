package notify

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/remediation"
)

func rebuildCheckItem(c *remediation.RebuildCheck) remediation.DockerfileItem {
	it := runtimeRebuildItem(remediation.DockerfileFromMapping)
	it.BaseRef = "node:24-alpine"
	it.RebuildRuntimes = nil
	it.RebuildCheck = c
	return it
}

func rbPkg(name, version, owner string) remediation.RebuildPackage {
	return remediation.RebuildPackage{Name: name, Version: version, Owner: owner, VulnIDs: []string{"CVE-1"}}
}

// As the regfis-backend image reads: rebuilding on the current base shows no
// finding going away, so a rebuild is not proposed.
func rebuildNothingGone() *remediation.RebuildCheck {
	return &remediation.RebuildCheck{
		Status:    remediation.RebuildChecked,
		Remaining: []remediation.RebuildPackage{rbPkg("brace-expansion", "5.0.9", "npm"), rbPkg("undici", "6.28.0", "npm")},
		NotInBase: []remediation.RebuildPackage{rbPkg("brace-expansion", "2.1.1", "pnpm"), rbPkg("ip-address", "10.2.0", "pnpm"), rbPkg("pnpm", "10.34.4", "pnpm"), rbPkg("tar", "7.5.16", "pnpm")},
	}
}

func TestPlanMessage_RebuildCheckStates(t *testing.T) {
	const layers = "稼働中のイメージの先頭のレイヤーが現在の node:24-alpine と一致しない。"
	const guide = layers + "ベースを取り直して再ビルドし(`docker build --pull` など)、デプロイし直す"
	gone := remediation.RebuildPackage{Name: "openssl", Version: "3.5.1", BaseVersion: "3.5.4", VulnIDs: []string{"CVE-2"}}

	t.Run("something is expected to disappear", func(t *testing.T) {
		got := rebuildPlanText(t, rebuildCheckItem(&remediation.RebuildCheck{
			Status: remediation.RebuildChecked, Gone: []remediation.RebuildPackage{gone}, Remaining: []remediation.RebuildPackage{rbPkg("undici", "6.28.0", "npm")},
			OnlyInBase: []remediation.RebuildPackage{rbPkg("glob", "13.0.6", "npm")},
		}), LanguageJA)
		for _, want := range []string{
			"再ビルド 1件",
			"再ビルド: " + guide + "\n",
			"  • 現在のベースの版を引き継げば消える見込み: openssl 3.5.1 → 3.5.4\n",
			"  • 現在のベースにも残る: undici 6.28.0\n",
			"  • 現在のベースで新しく出る: glob 13.0.6",
		} {
			if !strings.Contains(got, want) {
				t.Errorf("missing %q in\n%s", want, got)
			}
		}
	})
	t.Run("nothing is confirmed to disappear", func(t *testing.T) {
		got := rebuildPlanText(t, rebuildCheckItem(rebuildNothingGone()), LanguageJA)
		for _, want := range []string{
			"ベースの確認: 現在の node:24-alpine で消えると確認できた所見はない\n",
			"  • 現在のベースにも残る: brace-expansion 5.0.9、undici 6.28.0\n",
			"  • 現在のベースにない: pnpm 10.34.4(同梱を含め4パッケージ)",
		} {
			if !strings.Contains(got, want) {
				t.Errorf("missing %q in\n%s", want, got)
			}
		}
		for _, not := range []string{"再ビルド", "docker build"} {
			if strings.Contains(got, not) {
				t.Errorf("has %q:\n%s", not, got)
			}
		}
	})
	t.Run("nothing to say", func(t *testing.T) {
		got := rebuildPlanText(t, rebuildCheckItem(&remediation.RebuildCheck{Status: remediation.RebuildChecked, OtherNotInBase: 3}), LanguageJA)
		for _, not := range []string{"再ビルド", "ベースの確認", "node:24-alpine", "Dockerfile"} {
			if strings.Contains(got, not) {
				t.Errorf("has %q:\n%s", not, got)
			}
		}
	})
	t.Run("some findings could not be matched", func(t *testing.T) {
		got := rebuildPlanText(t, rebuildCheckItem(&remediation.RebuildCheck{
			Status: remediation.RebuildPartial, Undetermined: 1, Remaining: []remediation.RebuildPackage{rbPkg("undici", "6.28.0", "npm")},
		}), LanguageJA)
		for _, want := range []string{"再ビルド 1件", "再ビルド: " + guide + "(一部の所見は確認できなかった)\n", "  • 現在のベースにも残る: undici 6.28.0"} {
			if !strings.Contains(got, want) {
				t.Errorf("missing %q in\n%s", want, got)
			}
		}
	})
	t.Run("partial with nothing listed keeps the line", func(t *testing.T) {
		got := rebuildPlanText(t, rebuildCheckItem(&remediation.RebuildCheck{Status: remediation.RebuildPartial, Undetermined: 1}), LanguageJA)
		if !strings.Contains(got, "再ビルド: "+guide+"(一部の所見は確認できなかった)") {
			t.Errorf("%s", got)
		}
	})
	t.Run("not compared", func(t *testing.T) {
		for _, c := range []*remediation.RebuildCheck{nil, {Status: remediation.RebuildNotChecked, Reason: remediation.ReasonScanFailed}} {
			got := rebuildPlanText(t, rebuildCheckItem(c), LanguageJA)
			if !strings.Contains(got, "再ビルド: "+guide+"(消える所見は確認できなかった)") || !strings.Contains(got, "再ビルド 1件") {
				t.Errorf("%+v:\n%s", c, got)
			}
		}
	})
}

// The runtime estimate decides like the packages: findings that only remain do
// not make a rebuild worth proposing, but they are still shown.
func TestPlanMessage_RebuildCheckRuntime(t *testing.T) {
	rr := func(disappearing, remaining []string) []remediation.RuntimeRebuild {
		return []remediation.RuntimeRebuild{{Package: "Node.js", Installed: "24.1.0", BaseVersion: "24.22.2", Disappearing: disappearing, Remaining: remaining}}
	}
	it := rebuildCheckItem(&remediation.RebuildCheck{Status: remediation.RebuildChecked})
	it.RebuildRuntimes = rr(nil, []string{"CVE-1"})
	got := rebuildPlanText(t, it, LanguageJA)
	if !strings.Contains(got, "ベースの確認: ") || strings.Contains(got, "再ビルド 1件") || !strings.Contains(got, "1 件のうち 0 件") {
		t.Errorf("only remaining:\n%s", got)
	}
	it.RebuildRuntimes = rr([]string{"CVE-1"}, nil)
	got = rebuildPlanText(t, it, LanguageJA)
	if !strings.Contains(got, "再ビルド 1件") || strings.Contains(got, "ベースの確認") || !strings.Contains(got, "1 件のうち 1 件") {
		t.Errorf("disappearing:\n%s", got)
	}
}

func TestPlanMessage_RebuildCheckEnglish(t *testing.T) {
	got := rebuildPlanText(t, rebuildCheckItem(rebuildNothingGone()), LanguageEN)
	for _, want := range []string{
		"Base check: no finding is confirmed to disappear with the current node:24-alpine\n",
		"  • also in the current base: brace-expansion 5.0.9, undici 6.28.0\n",
		"  • not in the current base: pnpm 10.34.4 (4 packages with what it bundles)",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
	got = rebuildPlanText(t, rebuildCheckItem(&remediation.RebuildCheck{Status: remediation.RebuildNotChecked}), LanguageEN)
	if !strings.Contains(got, "the first layers of the running image do not match the current node:24-alpine; pull the base again") ||
		!strings.Contains(got, "(which findings disappear could not be confirmed)") {
		t.Errorf("%s", got)
	}
}

func TestPlanMessage_RebuildCheckNotInBase(t *testing.T) {
	got := rebuildPlanText(t, rebuildCheckItem(&remediation.RebuildCheck{
		Status: remediation.RebuildChecked,
		NotInBase: []remediation.RebuildPackage{
			rbPkg("curl", "8.0", ""),
			rbPkg("undici", "6.28.0", "npm"), rbPkg("tar", "7.0", "npm"),
			rbPkg("yarn", "1.22", "yarn"),
		},
	}), LanguageJA)
	if !strings.Contains(got, "現在のベースにない: curl 8.0、npm に同梱の2パッケージ、yarn 1.22") {
		t.Errorf("%s", got)
	}

	got = rebuildPlanText(t, rebuildCheckItem(&remediation.RebuildCheck{
		Status: remediation.RebuildChecked,
		NotInBase: []remediation.RebuildPackage{
			rbPkg("pnpm", "10.34.4", "pnpm"), rbPkg("pnpm", "10.34.5", "pnpm"), rbPkg("tar", "7.0", "pnpm"),
		},
	}), LanguageJA)
	if !strings.Contains(got, "現在のベースにない: pnpm 10.34.4、pnpm 10.34.5、pnpm に同梱の1パッケージ") {
		t.Errorf("two versions of the package:\n%s", got)
	}

	var many []remediation.RebuildPackage
	for i := range 12 {
		many = append(many, rbPkg(fmt.Sprintf("p%02d", i), "1", "npm"))
	}
	got = rebuildPlanText(t, rebuildCheckItem(&remediation.RebuildCheck{Status: remediation.RebuildChecked, Remaining: many}), LanguageJA)
	if !strings.Contains(got, "p09 1") || strings.Contains(got, "p10 1") || !strings.Contains(got, "2") {
		t.Errorf("a long list:\n%s", got)
	}
}

// A package moving to another outcome changes the Slack message; another
// finding of a package in the same outcome does not.
func TestSlackFingerprint_RebuildCheck(t *testing.T) {
	fp := func(c *remediation.RebuildCheck) string {
		p := dockerfileFixture()
		p.DockerfileItems = []remediation.DockerfileItem{rebuildCheckItem(c)}
		return (&PlanInfo{Plan: &p}).SlackFingerprint()
	}
	base := fp(&remediation.RebuildCheck{Status: remediation.RebuildChecked, Remaining: []remediation.RebuildPackage{{Name: "undici", Version: "6.28.0", VulnIDs: []string{"CVE-1"}}}})
	if got := fp(&remediation.RebuildCheck{Status: remediation.RebuildChecked, Remaining: []remediation.RebuildPackage{{Name: "undici", Version: "6.28.0", VulnIDs: []string{"CVE-1", "CVE-2"}}}}); got != base {
		t.Errorf("a new finding of the same package changes the fingerprint")
	}
	if got := fp(&remediation.RebuildCheck{Status: remediation.RebuildChecked, Remaining: []remediation.RebuildPackage{{Name: "undici", Version: "6.29.1", VulnIDs: []string{"CVE-1"}}}}); got == base {
		t.Errorf("a new version does not change the fingerprint")
	}
}

func TestWebhook_DockerfileRebuildCheck(t *testing.T) {
	p := dockerfileFixture()
	p.Scans = []remediation.ScanExecution{
		{ID: "s1", Role: remediation.RoleBaseline, Ref: "myapp:1"},
		{ID: "s2", Role: remediation.RoleBaseline, Ref: "node:24-alpine"},
	}
	check := rebuildNothingGone()
	check.OtherNotInBase = 7
	entity := *check
	entity.RunningScan, entity.BaseScan = "s1", "s2"
	it := rebuildCheckItem(check)
	it.Entities = []remediation.DockerfileEntity{{Category: it.Category, Reason: it.Reason, RebuildCheck: &entity}}
	scans := map[string]remediation.ScanExecution{}
	for _, s := range p.Scans {
		scans[s.ID] = s
	}
	raw, err := json.Marshal(dockerfileItemPayloadOf(it, scans, nil))
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		RebuildCheck struct {
			Status         string `json:"status"`
			OtherNotInBase int    `json:"other_not_in_base"`
			Remaining      []struct {
				Name    string   `json:"name"`
				VulnIDs []string `json:"vuln_ids"`
			} `json:"remaining"`
			RunningScan *struct {
				Ref string `json:"ref"`
			} `json:"running_scan"`
		} `json:"rebuild_check"`
		Entities []struct {
			RebuildCheck struct {
				RunningScan struct {
					Ref string `json:"ref"`
				} `json:"running_scan"`
				BaseScan struct {
					Ref string `json:"ref"`
				} `json:"base_scan"`
			} `json:"rebuild_check"`
		} `json:"entities"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	rc := got.RebuildCheck
	if rc.Status != "checked" || rc.OtherNotInBase != 7 || len(rc.Remaining) != 2 || rc.Remaining[0].VulnIDs[0] != "CVE-1" || rc.RunningScan != nil {
		t.Errorf("item: %s", raw)
	}
	ec := got.Entities[0].RebuildCheck
	if ec.RunningScan.Ref != "myapp:1" || ec.BaseScan.Ref != "node:24-alpine" {
		t.Errorf("entity scans: %s", raw)
	}
}
