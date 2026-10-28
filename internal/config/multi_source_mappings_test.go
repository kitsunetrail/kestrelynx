package config

import (
	"strings"
	"testing"
)

func TestParse_MappingWithSeveralSources(t *testing.T) {
	c, err := Parse(remediationWith(
		mapping("compose/p/web", "ex/app", "main", composeRoute+dockerfileRoute+depsRoute),
		mapping("container/api", "ex/api", "dev", dockerfileRoute+depsRoute),
	))
	if err != nil {
		t.Fatal(err)
	}
	ms := c.Remediation.Mappings
	if len(ms) != 2 {
		t.Fatalf("mappings = %d, want 2", len(ms))
	}
	web := ms[0]
	if web.Compose == nil || web.Compose.Path != "compose.yml" || web.Dockerfile == nil || web.Dockerfile.Target != "runtime" ||
		web.Dependencies == nil || web.Dependencies.Directory != "app" {
		t.Errorf("compose/p/web = %+v, want its compose, dockerfile and dependencies sources", web)
	}
	if api := ms[1]; api.Dockerfile == nil || api.Dependencies == nil || api.BaseBranch != "dev" {
		t.Errorf("container/api = %+v, want its dockerfile and dependencies sources on dev", api)
	}
}

func TestParse_SourcesOfAWorkloadSplitByRepository(t *testing.T) {
	_, err := Parse(remediationWith(
		mapping("compose/p/web", "ex/deploy", "main", composeRoute+dockerfileRoute),
		mapping("compose/p/web", "ex/lib", "dev", depsRoute),
	))
	if err != nil {
		t.Errorf("sources of one workload in two repositories: %v", err)
	}
}

func TestParse_KubernetesMappingWithSeveralSources(t *testing.T) {
	for name, source := range map[string]string{
		"manifest":    manifestSource,
		"kustomize":   kustSource(kustPath, "api"),
		"helm_values": helmSource(helmPath, "image"),
	} {
		_, err := Parse([]byte(minimal + k8sHeader + k8sMapping("deployment/shop/web/app", source+dockerfileRoute+depSource)))
		if err != nil {
			t.Errorf("%s with dockerfile and dependencies: %v", name, err)
		}
	}
}

func TestParse_MappingWithSeveralSourcesRejected(t *testing.T) {
	cases := map[string]struct {
		mappings []string
		want     string
	}{
		"no source": {
			[]string{mapping("compose/p/web", "ex/app", "main", "")},
			"at least one",
		},
		"source repeated by another mapping": {
			[]string{
				mapping("compose/p/web", "ex/app", "main", dockerfileRoute+depsRoute),
				mapping("compose/p/web", "ex/app", "main", depsRoute),
			},
			"remediation.mappings[1] repeats the dependencies mapping",
		},
		"invalid source among valid ones": {
			[]string{mapping("compose/p/web", "ex/app", "main", depsRoute+"      dockerfile:\n        path: ../Dockerfile\n")},
			"remediation.mappings[0].dockerfile.path",
		},
		"compose for a container": {
			[]string{mapping("container/web", "ex/app", "main", composeRoute+dockerfileRoute)},
			"sets a compose mapping for workload",
		},
		"Dockerfile on another branch in the same repository": {
			[]string{
				mapping("compose/p/web", "ex/app", "main", dockerfileRoute+depsRoute),
				mapping("compose/p/api", "ex/app", "dev", dockerfileRoute),
			},
			"base_branch",
		},
	}
	for name, tc := range cases {
		_, err := Parse(remediationWith(tc.mappings...))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want it to contain %q", name, err, tc.want)
		}
	}
}

func TestParse_KubernetesMappingWithTwoTagSourcesRejected(t *testing.T) {
	for name, sources := range map[string]string{
		"manifest and kustomize":                      manifestSource + kustSource(kustPath, "api"),
		"manifest and helm_values":                    manifestSource + helmSource(helmPath, "image"),
		"kustomize and helm_values with dependencies": kustSource(kustPath, "api") + helmSource(helmPath, "image") + depSource,
	} {
		_, err := Parse([]byte(minimal + k8sHeader + k8sMapping("deployment/shop/web/app", sources)))
		if err == nil || !strings.Contains(err.Error(), "more than one") {
			t.Errorf("%s: err = %v, want it to refuse two sources that decide the image tag", name, err)
		}
	}
}

func TestParse_KubernetesMappingWithSeveralSourcesKeepsSharedChecks(t *testing.T) {
	other := "    - workload: deployment/shop/api/app\n      repository: example/app\n      base_branch: dev\n" + kustSource(kustPath, "api")
	_, err := Parse([]byte(minimal + k8sHeader + k8sMapping("deployment/shop/web/app", kustSource(kustPath, "api")+depSource) + other))
	if err == nil || !strings.Contains(err.Error(), "base_branch") {
		t.Errorf("kustomization file on two branches: err = %v, want a base_branch error", err)
	}
}
