package evidence

import "time"

// Limits the reader enforces on an evidence file's size, counts, format,
// timestamps and interval before trusting any of its content. Every value
// here is a rejection threshold for a file coming from a
// separately-privileged, potentially-compromised Sensor: generous enough for
// any real deployment, tight enough that a corrupt or hostile file cannot
// make the main body allocate unbounded memory.
const (
	// maxFileBytes is the whole evidence file's size limit.
	maxFileBytes = 64 << 20 // 64 MiB

	// maxGenerations is how many container generations one snapshot may
	// describe.
	maxGenerations = 5000

	// maxEntitiesPerGeneration bounds one generation's combined OS package,
	// unavailable-package and executable record count.
	maxEntitiesPerGeneration = 50000

	// maxObservationsPerEntity bounds how many same-sample/same-process
	// combinations one package or executable record may carry — the same
	// cap the Sensor itself applies when accumulating them.
	maxObservationsPerEntity = 8

	// maxStringBytes bounds a path or version string. Longer than this is
	// treated as malformed input, not a legitimately long path.
	maxStringBytes = 512

	// minIntervalSeconds and maxIntervalSeconds bound SensorInfo.IntervalSeconds.
	minIntervalSeconds = 10
	maxIntervalSeconds = 300

	// maxFutureSkew is how far into the future a timestamp may claim to be
	// before it is rejected as malformed (clock skew between the Sensor and
	// the main body is tolerated up to this much). ParseFailure.RetryAfter is
	// exempt: it is a scheduled retry time, legitimately up to 24h ahead.
	maxFutureSkew = 5 * time.Minute

	// maxRetryAfterSkew bounds ParseFailure.RetryAfter specifically, matching
	// the backoff schedule's own 24-hour cap.
	maxRetryAfterSkew = 24 * time.Hour
)
