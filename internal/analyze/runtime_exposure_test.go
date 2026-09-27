package analyze

import (
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/docker"
)

// TestExposureOfListeners_HostPublishedAll covers a listener whose Docker
// port mapping is published to every host interface (0.0.0.0 or ::):
// host_published_all, the strongest stage.
func TestExposureOfListeners_HostPublishedAll(t *testing.T) {
	insp := docker.InspectResult{Ports: map[string][]docker.PortBinding{
		"443/tcp": {{HostIP: "0.0.0.0", HostPort: "443"}},
	}}
	if got := exposureOfListeners([]string{"tcp:0.0.0.0:443"}, insp); got != ExposureHostPublishedAll {
		t.Errorf("exposureOfListeners = %q, want host_published_all", got)
	}
	// An empty HostIP means "every interface" the same way 0.0.0.0 does.
	insp2 := docker.InspectResult{Ports: map[string][]docker.PortBinding{
		"443/tcp": {{HostIP: "", HostPort: "443"}},
	}}
	if got := exposureOfListeners([]string{"tcp:0.0.0.0:443"}, insp2); got != ExposureHostPublishedAll {
		t.Errorf("exposureOfListeners (empty HostIP) = %q, want host_published_all", got)
	}
}

// TestExposureOfListeners_HostPublishedLoopback covers a port published only
// to a loopback host address.
func TestExposureOfListeners_HostPublishedLoopback(t *testing.T) {
	insp := docker.InspectResult{Ports: map[string][]docker.PortBinding{
		"5432/tcp": {{HostIP: "127.0.0.1", HostPort: "5432"}},
	}}
	if got := exposureOfListeners([]string{"tcp:127.0.0.1:5432"}, insp); got != ExposureHostPublishedLoopback {
		t.Errorf("exposureOfListeners = %q, want host_published_loopback", got)
	}
}

// TestExposureOfListeners_ContainerListening covers a port declared in
// NetworkSettings.Ports but not actually published to the host (a null
// binding list) — reachable only from inside the container's own network.
func TestExposureOfListeners_ContainerListening(t *testing.T) {
	insp := docker.InspectResult{Ports: map[string][]docker.PortBinding{
		"8080/tcp": nil,
	}}
	if got := exposureOfListeners([]string{"tcp:0.0.0.0:8080"}, insp); got != ExposureContainerListening {
		t.Errorf("exposureOfListeners = %q, want container_listening", got)
	}
}

// TestExposureOfListeners_UnknownUndeclaredPort covers a listener whose port
// has no corresponding NetworkSettings.Ports key at all: this Sensor
// observed a socket Docker never declared (a port the container didn't
// EXPOSE), so the stage cannot be determined either way.
func TestExposureOfListeners_UnknownUndeclaredPort(t *testing.T) {
	insp := docker.InspectResult{Ports: map[string][]docker.PortBinding{}}
	if got := exposureOfListeners([]string{"tcp:0.0.0.0:9999"}, insp); got != ExposureUnknown {
		t.Errorf("exposureOfListeners = %q, want unknown (no Ports key for this port)", got)
	}
}

// TestExposureOfListeners_UnknownMixedHostAddress covers a port published to
// a host address that is neither all-interfaces nor loopback (e.g. a single
// LAN-facing IP): the reachability of that specific address isn't something
// this codebase claims to judge, so it stays unknown rather than guessing.
func TestExposureOfListeners_UnknownMixedHostAddress(t *testing.T) {
	insp := docker.InspectResult{Ports: map[string][]docker.PortBinding{
		"443/tcp": {{HostIP: "203.0.113.5", HostPort: "443"}},
	}}
	if got := exposureOfListeners([]string{"tcp:0.0.0.0:443"}, insp); got != ExposureUnknown {
		t.Errorf("exposureOfListeners = %q, want unknown (published to neither all-interfaces nor loopback)", got)
	}
}

// TestExposureOfListeners_HostNetworkModeIsUnknown pins the documented
// reason network_mode: host is always unknown: Docker port publishing is
// not meaningful in that mode, and a listener in the host network namespace
// cannot be distinguished from an unrelated host service, so even a
// listener that would otherwise look host_published_all is not claimed.
func TestExposureOfListeners_HostNetworkModeIsUnknown(t *testing.T) {
	insp := docker.InspectResult{
		NetworkMode: "host",
		Ports:       map[string][]docker.PortBinding{"443/tcp": {{HostIP: "0.0.0.0", HostPort: "443"}}},
	}
	if got := exposureOfListeners([]string{"tcp:0.0.0.0:443"}, insp); got != ExposureUnknown {
		t.Errorf("exposureOfListeners(network_mode=host) = %q, want unknown", got)
	}
}

// TestExposureOfListeners_NoneNetworkMode covers network_mode: none, where
// no publishing is possible at all regardless of NetworkSettings.Ports: a
// listener is container_listening, and no listener at all is unknown (there
// is nothing to judge).
func TestExposureOfListeners_NoneNetworkMode(t *testing.T) {
	insp := docker.InspectResult{NetworkMode: "none"}
	if got := exposureOfListeners([]string{"tcp:0.0.0.0:443"}, insp); got != ExposureContainerListening {
		t.Errorf("exposureOfListeners(network_mode=none, with a listener) = %q, want container_listening", got)
	}
	if got := exposureOfListeners(nil, insp); got != ExposureUnknown {
		t.Errorf("exposureOfListeners(network_mode=none, no listener) = %q, want unknown", got)
	}
}

// TestExposureOfListeners_StrongestWins covers a process listening on both a
// loopback-published and an all-interfaces-published port: the strongest
// stage must win regardless of which listener the Sensor happened to list
// first (mirrors the research harness's own guard against this).
func TestExposureOfListeners_StrongestWins(t *testing.T) {
	insp := docker.InspectResult{Ports: map[string][]docker.PortBinding{
		"5432/tcp": {{HostIP: "127.0.0.1", HostPort: "5432"}},
		"443/tcp":  {{HostIP: "0.0.0.0", HostPort: "443"}},
	}}
	forward := exposureOfListeners([]string{"tcp:127.0.0.1:5432", "tcp:0.0.0.0:443"}, insp)
	backward := exposureOfListeners([]string{"tcp:0.0.0.0:443", "tcp:127.0.0.1:5432"}, insp)
	if forward != ExposureHostPublishedAll || backward != ExposureHostPublishedAll {
		t.Errorf("exposureOfListeners = %q / %q (order-dependent), want host_published_all both ways", forward, backward)
	}
}
