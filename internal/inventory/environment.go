// Package inventory defines the runtime-agnostic vocabulary of observed
// environments, workloads, and containers. Every Runtime Adapter (Docker
// today; Kubernetes is the reason this package exists as its own thing)
// translates its own runtime-specific data into these types; consumers
// (runner, analyze, notify, state) work only in this vocabulary and never
// depend on an adapter package directly.
package inventory

import (
	"fmt"
	"regexp"
)

// Environment identifies the runtime instance a scan cycle observed. Name is
// entirely configuration-driven ("" is the unnamed default environment, not
// a name that failed validation); Kind is set by the composition root to
// match whichever adapter it wired up, never by configuration — a config key
// for it could only ever record a value that might drift from the adapter
// actually running.
type Environment struct {
	Name string
	Kind EnvironmentKind
}

// EnvironmentKind identifies which Runtime Adapter produced an Environment.
type EnvironmentKind string

// KindDocker is a single Docker Engine host reached over docker.sock.
const KindDocker EnvironmentKind = "docker" // future: KindKubernetes

// environmentNamePattern is a DNS-1123 label: lowercase alphanumerics and
// hyphens, 1-63 bytes, starting and ending with an alphanumeric. This is
// deliberately narrower than "whatever Slack can render" because the name
// may later appear in URL path segments, Kubernetes label values, and
// idempotent send keys, all of which are stricter than free text.
var environmentNamePattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// ValidateEnvironmentName rejects any environment.name that isn't a valid
// DNS-1123 label. An empty name is valid: it means the unnamed default
// environment, which is a distinct concept from "invalid". Uppercase, dots,
// underscores, whitespace, and control characters are all rejected outright
// rather than normalized — silently lowercasing "Prod" to "prod" would mean
// the tool decides on its own whether two configured names share history;
// that decision is left to whoever can fix the config value.
func ValidateEnvironmentName(name string) error {
	if name == "" {
		return nil
	}
	if !environmentNamePattern.MatchString(name) {
		return fmt.Errorf("invalid environment name %q: must be 1-63 bytes of lowercase alphanumerics and hyphens, starting and ending with an alphanumeric", name)
	}
	return nil
}
