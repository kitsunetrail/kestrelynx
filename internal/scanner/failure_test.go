package scanner

import (
	"errors"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
)

func TestClassifyFailure(t *testing.T) {
	remote := func(repo string) ScanTarget {
		return ScanTarget{Subject: inventory.ImageSubject{Ref: repo + ":1"}, Registry: inventory.RegistryRef{Repository: repo}, Source: SourceRemote}
	}
	local := ScanTarget{Subject: inventory.ImageSubject{Ref: "app:1"}, Source: SourceLocal}
	cases := []struct {
		name   string
		target ScanTarget
		err    string
		want   FailureCause
	}{
		{"loopback registry refused", remote("127.0.0.1:5000/gradleapp"),
			`trivy scan 127.0.0.1:5000/gradleapp@sha256:2565: exit status 1: 2026-11-03T00:02:02Z FATAL Fatal error run error: image scan error: scan error: unable to initialize a scan service: unable to initialize artifact: unable to initialize container image: unable to find the specified image "127.0.0.1:5000/gradleapp@sha256:2565" in ["remote"]: 1 error occurred: * remote error: Get "https://127.0.0.1:5000/v2/": dial tcp 127.0.0.1:5000: connect: connection refused; Get "http://127.0.0.1:5000/v2/": dial tcp 127.0.0.1:5000: connect: connection refused`,
			CauseLocalRegistry},
		{"localhost registry timed out", remote("localhost:5000/app"), "dial tcp: i/o timeout", CauseLocalRegistry},
		{"ipv6 loopback registry", remote("[::1]:5000/app"), "connect: connection refused", CauseLocalRegistry},
		{"remote registry refused", remote("registry.example.com/app"), "dial tcp 10.0.0.1:443: connect: connection refused", CauseRegistryUnreachable},
		{"no such host", remote("registry.example.com/app"), "dial tcp: lookup registry.example.com: no such host", CauseRegistryUnreachable},
		{"unauthorized", remote("ghcr.io/team/app"), "GET https://ghcr.io/v2/team/app/manifests/sha256:1: UNAUTHORIZED: authentication required", CauseRegistryAuth},
		{"denied", remote("docker.io/team/app"), "DENIED: requested access to the resource is denied", CauseRegistryAuth},
		{"login withheld", remote("ghcr.io/team/app"), "exit status 1: FATAL (the registry login was not passed on: the registry gave no authentication challenge to check)", CauseRegistryAuth},
		{"manifest unknown", remote("ghcr.io/team/app"), "MANIFEST_UNKNOWN: manifest unknown", CauseImageNotFound},
		{"rate limited", remote("docker.io/library/redis"), "TOOMANYREQUESTS: You have reached your pull rate limit", CauseRateLimited},
		{"vulnerability db", remote("ghcr.io/team/app"), "init error: DB error: failed to download vulnerability DB: TOOMANYREQUESTS", CauseVulnDB},
		{"vulnerability db, local store", local, "DB error: failed to download vulnerability DB", CauseVulnDB},
		{"local store refused is not a registry", local, "Cannot connect to the Docker daemon: connection refused", CauseUnknown},
		{"anything else", remote("ghcr.io/team/app"), "exit status 2: something odd", CauseUnknown},
		{"local permission denied is not a login", remote("ghcr.io/team/app"), "mkdir /tmp/x: permission denied: exit status 1", CauseUnknown},
		{"own deadline is not the registry", remote("ghcr.io/team/app"), "signal: killed: context deadline exceeded", CauseUnknown},
		{"cause word in the image name", remote("127.0.0.1:5000/unauthorized-app"), `trivy scan 127.0.0.1:5000/unauthorized-app@sha256:1: unable to find the specified image "127.0.0.1:5000/unauthorized-app@sha256:1": Get "https://127.0.0.1:5000/v2/": dial tcp 127.0.0.1:5000: connect: connection refused`, CauseLocalRegistry},
		{"cause word in the repository path of a URL", remote("ghcr.io/team/manifest_unknown-db"), `GET https://ghcr.io/v2/team/manifest_unknown-db/manifests/sha256:1: dial tcp: lookup ghcr.io: no such host`, CauseRegistryUnreachable},
		{"withheld login with a refused connection", remote("127.0.0.1:5000/app"), "dial tcp 127.0.0.1:5000: connect: connection refused (the registry login was not passed on: the registry's authentication challenge could not be read: connection refused)", CauseLocalRegistry},
		{"repository named like a word of the error", remote("127.0.0.1:5000/io"), `trivy scan 127.0.0.1:5000/io@sha256:1: unable to find the specified image "127.0.0.1:5000/io@sha256:1": dial tcp 127.0.0.1:5000: connect: connection refused`, CauseLocalRegistry},
		{"repository named db", remote("127.0.0.1:5000/db"), "trivy scan 127.0.0.1:5000/db@sha256:1: init error: DB error: failed to download vulnerability DB: TOOMANYREQUESTS", CauseVulnDB},
		{"cause word in the host name", remote("unauthorized.example.com/app"), `trivy scan unauthorized.example.com/app@sha256:1: Get "https://unauthorized.example.com/v2/": dial tcp: lookup unauthorized.example.com: no such host`, CauseRegistryUnreachable},
		{"short reference named like a cause", ScanTarget{Subject: inventory.ImageSubject{Ref: "unauthorized:1"}, Source: SourceRemote}, "trivy scan unauthorized:1: dial tcp 10.0.0.1:443: i/o timeout", CauseRegistryUnreachable},
		{"bare reference named db", ScanTarget{Subject: inventory.ImageSubject{Ref: "db"}, Source: SourceRemote}, `trivy scan db: init error: DB error: failed to download vulnerability DB: TOOMANYREQUESTS`, CauseVulnDB},
		{"bare reference in quotes", ScanTarget{Subject: inventory.ImageSubject{Ref: "unauthorized"}, Source: SourceRemote}, `unable to find the specified image "unauthorized" in ["remote"]: dial tcp 10.0.0.1:443: connect: connection refused`, CauseRegistryUnreachable},
		{"ghcr denied", remote("ghcr.io/team/app"), "GET https://ghcr.io/v2/team/app/manifests/1: DENIED: denied", CauseRegistryAuth},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyFailure(tc.target, errors.New(tc.err)); got != tc.want {
				t.Errorf("classifyFailure = %q, want %q", got, tc.want)
			}
		})
	}
	if got := classifyFailure(remote("ghcr.io/team/app"), nil); got != "" {
		t.Errorf("no error: %q", got)
	}
}

func TestRegistryHostOf(t *testing.T) {
	cases := []struct {
		target ScanTarget
		want   string
	}{
		{ScanTarget{Registry: inventory.RegistryRef{Repository: "127.0.0.1:5000/gradleapp"}}, "127.0.0.1:5000"},
		{ScanTarget{Subject: inventory.ImageSubject{Ref: "redis:7"}}, "docker.io"},
		{ScanTarget{Subject: inventory.ImageSubject{Ref: "ghcr.io/team/app:1"}}, "ghcr.io"},
		{ScanTarget{Subject: inventory.ImageSubject{Ref: "sha256:abc"}}, ""},
	}
	for _, tc := range cases {
		if got := registryHostOf(tc.target); got != tc.want {
			t.Errorf("registryHostOf(%+v) = %q, want %q", tc.target, got, tc.want)
		}
	}
}

func TestIsLoopbackHost(t *testing.T) {
	for host, want := range map[string]bool{
		"127.0.0.1:5000": true, "127.1.2.3": true, "localhost": true, "LOCALHOST:80": true, "[::1]:5000": true,
		"10.0.0.1:5000": false, "registry.local:5000": false, "ghcr.io": false, "": false,
	} {
		if got := isLoopbackHost(host); got != want {
			t.Errorf("isLoopbackHost(%q) = %v, want %v", host, got, want)
		}
	}
}
