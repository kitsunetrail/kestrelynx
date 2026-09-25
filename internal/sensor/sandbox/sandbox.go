// Package sandbox provides the isolation primitives the Sensor's two
// processes (observer and parser) apply to themselves at startup: raising
// and dropping Linux capabilities, setting NO_NEW_PRIVS and non-dumpable on
// every OS thread, installing classic-BPF seccomp filters, restricting a
// process's filesystem access with Landlock, and self-checking that all of
// the above actually took effect.
//
// Nothing here talks to procfs package databases, eBPF, or the evidence
// file format; it only changes and inspects the calling process's own
// security state. The two filters this package builds (ObserverFilter and
// ParserFilter) and the Landlock restriction (RestrictAllFiles) are the only
// things that make the Sensor's containment claims true, so
// every exported function here is deliberately narrow and independently
// testable without root or any capability.
package sandbox
