package notify

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/analyze"
	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// TestScanFailures_GroupedByCauseWithWorkloads: the failed images are listed
// under their cause, every one with the workloads that run it, and the error
// texts are not shown.
func TestScanFailures_GroupedByCauseWithWorkloads(t *testing.T) {
	failed := func(ref string, cause scanner.FailureCause, host string) scanner.ImageScan {
		return scanner.ImageScan{Image: ref, Source: scanner.SourceRemote, Err: errString("trivy scan " + ref + ": exit status 1: FATAL connection refused"), Cause: cause, RegistryHost: host}
	}
	scans := []scanner.ImageScan{
		failed("127.0.0.1:5000/gradleboot:1", scanner.CauseLocalRegistry, "127.0.0.1:5000"),
		failed("127.0.0.1:5000/gradleapp:1", scanner.CauseLocalRegistry, "127.0.0.1:5000"),
		failed("127.0.0.1:5000/kestrelynx@sha256:9672", scanner.CauseLocalRegistry, "127.0.0.1:5000"),
		failed("ghcr.io/team/private:2", scanner.CauseRegistryAuth, "ghcr.io"),
		failed("orphan:1", "", ""),
	}
	container := func(ref string, kind inventory.WorkloadKind, group, name string) inventory.Container {
		return inventory.Container{Name: name + "-abc/app", Workload: inventory.Workload{Kind: kind, Group: group, Name: name}, Image: inventory.RunningImage{Ref: ref}}
	}
	containers := []inventory.Container{
		container("127.0.0.1:5000/gradleapp:1", inventory.WorkloadDeployment, "gradle-verify", "gradleapp"),
		container("127.0.0.1:5000/gradleboot:1", inventory.WorkloadDeployment, "gradle-verify", "gradleboot"),
		container("127.0.0.1:5000/kestrelynx@sha256:9672", inventory.WorkloadDeployment, "gradle-verify", "kestrelynx"),
		container("ghcr.io/team/private:2", inventory.WorkloadStatefulSet, "prod", "db"),
		container("ghcr.io/team/private:2", inventory.WorkloadCronJob, "prod", "backup"),
	}
	r := analyze.Build(scans, containers, analyze.Triage{}, genTime)
	out := renderFull(r, LanguageJA)

	want := strings.Join([]string{
		"*⚠️ スキャンできなかったイメージ 5件（脆弱性は確認できていない）*",
		"• ローカルレジストリ（127.0.0.1:5000）のイメージは KestreLynx から取得できない",
		"  • Deployment gradle-verify/gradleapp — 127.0.0.1:5000/gradleapp:1",
		"  • Deployment gradle-verify/gradleboot — 127.0.0.1:5000/gradleboot:1",
		"  • Deployment gradle-verify/kestrelynx — 127.0.0.1:5000/kestrelynx@sha256:9672",
		"• レジストリ（ghcr.io）のログイン情報が無い、または違うため、イメージを取得できない",
		"  • CronJob prod/backup — ghcr.io/team/private:2",
		"  • StatefulSet prod/db — ghcr.io/team/private:2",
		"• 原因を分類できなかった（詳細はログ）",
		"  • orphan:1",
	}, "\n")
	if !strings.Contains(out, want) {
		t.Errorf("scan failures not rendered as expected:\nwant:\n%s\n---\ngot:\n%s", want, out)
	}
	for _, bad := range []string{"connection refused", "exit status", "実体未確認: 参照によるスキャン — trivy"} {
		if strings.Contains(out, bad) {
			t.Errorf("scan failures carry %q:\n%s", bad, out)
		}
	}
}

// TestScanFailures_WorkloadLabels: each kind of owner is named as its owner
// knows it, and an image with no known workload comes after the rest.
func TestScanFailures_WorkloadLabels(t *testing.T) {
	cases := []struct {
		c    inventory.Container
		want string
	}{
		{inventory.Container{Name: "shop-web-1", Workload: inventory.Workload{Kind: inventory.WorkloadCompose, Group: "shop", Name: "web"}}, "Compose shop/web"},
		{inventory.Container{Name: "standalone"}, "コンテナ standalone"},
		{inventory.Container{Name: "p/c", Workload: inventory.Workload{Kind: inventory.WorkloadDaemonSet, Group: "kube-system", Name: "agent"}}, "DaemonSet kube-system/agent"},
		{inventory.Container{Name: "p/c", Workload: inventory.Workload{Kind: inventory.WorkloadPod, Group: "default", Name: "debug"}}, "Pod default/debug"},
		{inventory.Container{Name: "p/c", Workload: inventory.Workload{Kind: inventory.WorkloadJob, Group: "", Name: "x"}}, ""},
		{inventory.Container{}, ""},
	}
	for _, tc := range cases {
		if got := workloadLabel(tc.c, jaMessages); got != tc.want {
			t.Errorf("workloadLabel(%+v) = %q, want %q", tc.c, got, tc.want)
		}
	}

	scans := []scanner.ImageScan{
		{Image: "a-no-owner:1", Err: errString("x")},
		{Image: "z-owned:1", Err: errString("x")},
	}
	containers := []inventory.Container{{Name: "zz", Image: inventory.RunningImage{Ref: "z-owned:1"}}}
	out := renderFull(analyze.Build(scans, containers, analyze.Triage{}, genTime), LanguageJA)
	if !strings.Contains(out, "  • コンテナ zz — z-owned:1\n  • a-no-owner:1") {
		t.Errorf("an image with no known workload must come last:\n%s", out)
	}
}

// TestScanFailures_RegistryCauseWithoutHost: a registry cause with no host to
// name falls back to the unclassified line, and the same image failing twice
// is counted and listed once.
func TestScanFailures_RegistryCauseWithoutHost(t *testing.T) {
	scans := []scanner.ImageScan{
		{Image: "app:1", Err: errString("x"), Cause: scanner.CauseRegistryUnreachable},
		{Image: "app:1", Err: errString("y"), Cause: scanner.CauseRegistryUnreachable},
	}
	r := analyze.Build(scans, nil, analyze.Triage{}, genTime)
	out := renderFull(r)
	want := "*⚠️ 1 image(s) could not be scanned (vulnerabilities not checked)*\n• The cause could not be determined (see the log)\n  • app:1"
	if !strings.Contains(out, want) {
		t.Errorf("want:\n%s\n---\ngot:\n%s", want, out)
	}
	if strings.Count(out, "  • app:1") != 1 {
		t.Errorf("app:1 listed more than once:\n%s", out)
	}
}

// TestScanFailures_WebhookKeepsErrorAndCause: the webhook carries the error
// text with the cause and the registry host.
func TestScanFailures_WebhookKeepsErrorAndCause(t *testing.T) {
	r := analyze.Build([]scanner.ImageScan{{Image: "127.0.0.1:5000/app:1", Err: errString("dial tcp 127.0.0.1:5000: connect: connection refused"), Cause: scanner.CauseLocalRegistry, RegistryHost: "127.0.0.1:5000"}}, nil, analyze.Triage{}, genTime)
	data, err := json.Marshal(BuildWebhookPayload(r, nil))
	if err != nil {
		t.Fatal(err)
	}
	want := `"scan_errors":[{"image":"127.0.0.1:5000/app:1","error":"dial tcp 127.0.0.1:5000: connect: connection refused","cause":"local_registry","registry":"127.0.0.1:5000"}]`
	if !strings.Contains(string(data), want) {
		t.Errorf("payload lacks %s:\n%s", want, data)
	}
}

// TestScanFailures_OnlyWorkloadsOfTheFailedImage: when one reference runs as
// two images and only one fails, only the workloads of the failed one are
// listed.
func TestScanFailures_OnlyWorkloadsOfTheFailedImage(t *testing.T) {
	const ref = "ghcr.io/team/app:1"
	keyOf := func(hex string) (inventory.RunningImage, inventory.ImageSubject) {
		img := inventory.RunningImage{Ref: ref, Registry: inventory.RegistryRef{Repository: "ghcr.io/team/app", Digest: inventory.Digest{Kind: inventory.DigestRegistry, Algorithm: "sha256", Hex: hex}}, Platform: inventory.Platform{OS: "linux", Architecture: "amd64"}}
		key, ok := inventory.EntityKeyOf(img)
		if !ok {
			t.Fatalf("no entity key for %s", hex)
		}
		return img, inventory.ImageSubject{Ref: ref, Key: key, Resolved: true}
	}
	okImg, okSubject := keyOf(strings.Repeat("a", 64))
	badImg, badSubject := keyOf(strings.Repeat("b", 64))
	scans := []scanner.ImageScan{
		{Image: ref, Subject: okSubject, ScannedKey: okSubject.Key, Pinned: true, Source: scanner.SourceRemote},
		{Image: ref, Subject: badSubject, Source: scanner.SourceRemote, Err: errString("x"), Cause: scanner.CauseImageNotFound, RegistryHost: "ghcr.io"},
	}
	containers := []inventory.Container{
		{Name: "a-1/app", Workload: inventory.Workload{Kind: inventory.WorkloadDeployment, Group: "prod", Name: "ok"}, Image: okImg},
		{Name: "b-1/app", Workload: inventory.Workload{Kind: inventory.WorkloadDeployment, Group: "prod", Name: "failed"}, Image: badImg},
	}
	out := renderFull(analyze.Build(scans, containers, analyze.Triage{}, genTime))
	if !strings.Contains(out, "  • Deployment prod/failed — ghcr.io/team/app:1") {
		t.Errorf("the workload of the failed image is not listed:\n%s", out)
	}
	if strings.Contains(out, "Deployment prod/ok") {
		t.Errorf("the workload of the scanned image is listed as failed:\n%s", out)
	}
}
