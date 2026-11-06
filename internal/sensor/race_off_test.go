//go:build !race

package sensor

// raceSlowdown widens the time limits of tests that check an operation stays
// fast when they run under the race detector, which this build is not.
const raceSlowdown = 1
