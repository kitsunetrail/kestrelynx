package analyze

import (
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/kitsunetrail/kestrelynx/internal/docker"
	"github.com/kitsunetrail/kestrelynx/internal/evidence"
)

// Exposure is how far the strongest evidence-observed listener behind an
// in-use package's process is reachable from outside its own container,
// strongest first. It is only meaningful on an in-use verdict — a
// not-observed or unavailable package has no process to judge exposure from.
type Exposure string

const (
	// ExposureUnknown covers host networking (a listener there cannot be
	// told apart from an unrelated host service), a listener Docker's own
	// port metadata doesn't recognize, and "no listener observed at all" —
	// including every language-package verdict, since a runtime process's
	// own listening sockets are not what makes its packages in-use.
	ExposureUnknown Exposure = "unknown"
	// ExposureContainerListening is a listener that is not published to the
	// host at all: reachable only from inside the container's own network,
	// or (network_mode: none) not reachable from outside the host at all.
	ExposureContainerListening Exposure = "container_listening"
	// ExposureHostPublishedLoopback is published only to a loopback host
	// address.
	ExposureHostPublishedLoopback Exposure = "host_published_loopback"
	// ExposureHostPublishedAll is published to every host interface
	// (0.0.0.0 or ::).
	ExposureHostPublishedAll Exposure = "host_published_all"
)

// exposureRank orders Exposure strongest-first, for both display and the
// same-sample/same-process strongest-combination rule below: the same total
// order the priority-view sort (triage.go) uses to place a more exposed
// package ahead of a less exposed one within the same priority bucket.
var exposureRank = map[Exposure]int{
	ExposureUnknown:               0,
	ExposureContainerListening:    1,
	ExposureHostPublishedLoopback: 2,
	ExposureHostPublishedAll:      3,
}

// dangerousCapBits are the fixed 8 capabilities this codebase treats as
// "dangerous": CAP_SYS_ADMIN, CAP_SYS_PTRACE, CAP_SYS_MODULE, CAP_NET_ADMIN,
// CAP_DAC_READ_SEARCH, CAP_DAC_OVERRIDE, CAP_SETUID, CAP_SETGID (Linux
// capability bit numbers, man 7 capabilities) — ported from the research
// harness (experiments/runtime-discovery/g4.go).
var dangerousCapBits = []uint{21, 19, 16, 12, 2, 1, 7, 6}

// hasDangerousCapability reports whether capEffHex (a ProcessObservation.
// CapEff hex string) sets any of dangerousCapBits. An unparseable value
// (empty, or not a hex bitmask) is never guessed at as dangerous.
func hasDangerousCapability(capEffHex string) bool {
	v, err := strconv.ParseUint(capEffHex, 16, 64)
	if err != nil {
		return false
	}
	for _, bit := range dangerousCapBits {
		if v&(1<<bit) != 0 {
			return true
		}
	}
	return false
}

// dangerousCapNamesTable pairs each dangerousCapBits entry with its
// conventional name (man 7 capabilities), for the webhook's
// process.dangerous_caps list.
var dangerousCapNamesTable = []struct {
	bit  uint
	name string
}{
	{21, "CAP_SYS_ADMIN"},
	{19, "CAP_SYS_PTRACE"},
	{16, "CAP_SYS_MODULE"},
	{12, "CAP_NET_ADMIN"},
	{2, "CAP_DAC_READ_SEARCH"},
	{1, "CAP_DAC_OVERRIDE"},
	{7, "CAP_SETUID"},
	{6, "CAP_SETGID"},
}

// dangerousCapNames returns the sorted names of every dangerous capability
// set in capEffHex, or nil for an unparseable value or none set.
func dangerousCapNames(capEffHex string) []string {
	v, err := strconv.ParseUint(capEffHex, 16, 64)
	if err != nil {
		return nil
	}
	var names []string
	for _, e := range dangerousCapNamesTable {
		if v&(1<<e.bit) != 0 {
			names = append(names, e.name)
		}
	}
	sort.Strings(names)
	return names
}

// highPrivilege reports whether a process counts as high-privilege: it is
// UID 0 outside any user namespace, holds a dangerous capability, or its
// container runs privileged.
func highPrivilege(obs evidence.ProcessObservation, privileged bool) bool {
	if privileged {
		return true
	}
	if hasDangerousCapability(obs.CapEff) {
		return true
	}
	return obs.EffectiveUID == 0 && !obs.Userns
}

// parseListener splits a Sensor-recorded "tcp:<addr>:<port>" listener string
// (internal/sensor/sampleworker.go's ownedListeners) into its transport kind
// ("tcp" or "tcp6"), address and port. The address is split off from the
// right, not the left, because it may itself contain colons (an IPv6
// address).
func parseListener(s string) (kind, addr string, port int, ok bool) {
	i := strings.IndexByte(s, ':')
	if i < 0 {
		return "", "", 0, false
	}
	kind = s[:i]
	rest := s[i+1:]
	j := strings.LastIndexByte(rest, ':')
	if j < 0 {
		return "", "", 0, false
	}
	addr = rest[:j]
	p, err := strconv.Atoi(rest[j+1:])
	if err != nil {
		return "", "", 0, false
	}
	return kind, addr, p, true
}

// formatPort renders a Sensor-recorded "tcp:<addr>:<port>" listener string
// in the webhook's own display form, "<addr>:<port>/<proto>" (e.g.
// "0.0.0.0:443/tcp") — the same convention Docker's own NetworkSettings.
// Ports keys use for the protocol part. Returns the input unchanged if it
// doesn't parse (never hides a malformed value).
func formatPort(l string) string {
	kind, addr, port, ok := parseListener(l)
	if !ok {
		return l
	}
	return addr + ":" + strconv.Itoa(port) + "/" + dockerProto(kind)
}

// formatPorts maps formatPort over a whole listener list.
func formatPorts(listeners []string) []string {
	if len(listeners) == 0 {
		return nil
	}
	out := make([]string, len(listeners))
	for i, l := range listeners {
		out[i] = formatPort(l)
	}
	return out
}

// dockerProto normalizes a Sensor listener kind ("tcp"/"tcp6") to Docker's
// own protocol vocabulary, which does not distinguish IPv4 from IPv6.
func dockerProto(kind string) string {
	if kind == "tcp6" || kind == "" {
		return "tcp"
	}
	return kind
}

// dockerPortKey is the NetworkSettings.Ports key a listener corresponds to.
// Docker keys a port mapping by transport protocol only ("80/tcp" whether
// the socket is IPv4 or IPv6), so "tcp6" is folded into "tcp" — mirrors the
// research harness's dockerPortKey (match_metrics.go).
func dockerPortKey(kind string, port int) string {
	proto := kind
	if proto == "tcp6" || proto == "" {
		proto = "tcp"
	}
	return strconv.Itoa(port) + "/" + proto
}

// anyAllInterfaces reports whether any binding publishes to every host
// interface (an empty HostIP, 0.0.0.0, or ::).
func anyAllInterfaces(bindings []docker.PortBinding) bool {
	for _, b := range bindings {
		if b.HostIP == "" || b.HostIP == "0.0.0.0" || b.HostIP == "::" {
			return true
		}
	}
	return false
}

// allLoopback reports whether every binding publishes only to a loopback
// host address. An unparseable HostIP is never assumed loopback.
func allLoopback(bindings []docker.PortBinding) bool {
	if len(bindings) == 0 {
		return false
	}
	for _, b := range bindings {
		ip := net.ParseIP(b.HostIP)
		if ip == nil || !ip.IsLoopback() {
			return false
		}
	}
	return true
}

// exposureOfListeners decides one process observation's exposure stage from
// its own listeners and the container's current Docker configuration,
// ported from the research harness's exposureFromListeners
// (experiments/runtime-discovery/match_metrics.go). Every listener is
// evaluated and the strongest stage wins, so a process listening on both a
// loopback-published and an all-interfaces-published port is never
// under-reported depending on which listener the Sensor happened to list
// first.
func exposureOfListeners(listeners []string, insp docker.InspectResult) Exposure {
	switch insp.NetworkMode {
	case "host":
		// Docker port publishing is not meaningful in this mode, and a
		// listener in the host network namespace cannot be distinguished
		// from an unrelated host service.
		return ExposureUnknown
	case "none":
		if len(listeners) > 0 {
			return ExposureContainerListening
		}
		return ExposureUnknown
	}

	best := ExposureUnknown
	for _, l := range listeners {
		kind, _, port, ok := parseListener(l)
		if !ok {
			continue
		}
		key := dockerPortKey(kind, port)
		bindings, declared := insp.Ports[key]
		var stage Exposure
		switch {
		case !declared:
			stage = ExposureUnknown
		case len(bindings) == 0:
			stage = ExposureContainerListening
		case anyAllInterfaces(bindings):
			stage = ExposureHostPublishedAll
		case allLoopback(bindings):
			stage = ExposureHostPublishedLoopback
		default:
			stage = ExposureUnknown
		}
		if exposureRank[stage] > exposureRank[best] {
			best = stage
		}
	}
	return best
}

// combo is one same-sample/same-process observation, evaluated for its
// exposure and privilege strength.
type combo struct {
	obs      evidence.ProcessObservation
	exposure Exposure
	highPriv bool
}

// strongerCombo reports whether a is at least as strong as b: exposure stage
// first, then privilege. Ties (equal exposure, equal privilege) keep
// whichever the caller already holds — this is used to fold a list
// left-to-right, so ">=" rather than ">" keeps the fold deterministic
// without needing a separate stable-sort step.
func strongerCombo(a, b combo) bool {
	if exposureRank[a.exposure] != exposureRank[b.exposure] {
		return exposureRank[a.exposure] > exposureRank[b.exposure]
	}
	if a.highPriv != b.highPriv {
		return a.highPriv
	}
	return false
}

// comboScore turns an (exposure, privilege) pair into a single strictly
// ordered integer, for sorting containerRTs in groupRuntime: exposureRank
// dominates (multiplied up so no privilege difference can outweigh it), then
// high privilege breaks a tie within the same exposure stage. Unlike
// strongerCombo (a "fold" comparison that treats a tie as "keep what I have"
// and is therefore not a strict order), this is a genuine total order
// suitable for sort.Slice's Less function.
func comboScore(exposure Exposure, highPriv bool) int {
	score := exposureRank[exposure] * 2
	if highPriv {
		score++
	}
	return score
}

// strongestCombo picks the strongest same-sample/same-process combination
// from a package or executable's accumulated Observations, evaluating each
// against insp (nil insp — no matching container inspect — yields
// ExposureUnknown for every observation, so privilege still comes through).
// ok is false only when observations is empty.
func strongestCombo(observations []evidence.ProcessObservation, insp docker.InspectResult) (combo, bool) {
	if len(observations) == 0 {
		return combo{}, false
	}
	best := combo{
		obs:      observations[0],
		exposure: exposureOfListeners(observations[0].Listeners, insp),
		highPriv: highPrivilege(observations[0], insp.Privileged),
	}
	for _, o := range observations[1:] {
		c := combo{
			obs:      o,
			exposure: exposureOfListeners(o.Listeners, insp),
			highPriv: highPrivilege(o, insp.Privileged),
		}
		if strongerCombo(c, best) {
			best = c
		}
	}
	return best, true
}

// strongestSource is strongestCombo extended across a pool of evidenceSource
// values: it picks the strongest same-sample/same-process combination among
// every observation in every source, and returns the whole winning source
// (never a different source's kinds or observations) so a display line's
// kind and executable always come from the one record that actually
// produced both. ok is false only when every source has zero observations
// (an in-use verdict with kinds but no ProcessObservation at all, e.g. an
// exec_event the Sensor recorded without a same-sample identity snapshot);
// the caller shows no kind/executable pairing in that case rather than
// guessing one.
func strongestSource(sources []evidenceSource, insp docker.InspectResult) (best combo, src evidenceSource, ok bool) {
	for _, s := range sources {
		c, srcOK := strongestCombo(s.observations, insp)
		if !srcOK {
			continue
		}
		if !ok || strongerCombo(c, best) {
			best, src, ok = c, s, true
		}
	}
	return best, src, ok
}
