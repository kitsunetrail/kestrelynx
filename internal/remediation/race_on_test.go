//go:build race

package remediation

// raceSlowdown widens the time limits of tests that check an operation stays
// fast: the race detector makes such a test several times slower, and more on
// a busy machine. Without the detector the limits stay tight.
const raceSlowdown = 10
