package kubework

import (
	"context"
	"strings"
	"testing"
)

// A runtime that is not listed in Images gets its image from ImageFor, and the
// Pod is made and checked with that image like any other.
func TestRunJobTakesTheImageOfAnUnlistedRuntimeFromImageFor(t *testing.T) {
	gradleImg := "docker.io/library/gradle@sha256:" + strings.Repeat("7", 64)
	f := newFake()
	f.workImageID = gradleImg
	r := testRunner(t, f)
	var asked []string
	r.cfg.ImageFor = func(key string) (string, bool) {
		asked = append(asked, key)
		if key == "gradle9.8.2-jdk21" {
			return gradleImg, true
		}
		return "", false
	}
	verified(t, r)

	spec := testSpec("job-1")
	spec.Runtime = "gradle9.8.2-jdk21"
	if _, err := r.RunJob(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	// The listed runtime does not ask.
	f2 := newFake()
	r2 := testRunner(t, f2)
	r2.cfg.ImageFor = func(key string) (string, bool) { asked = append(asked, "unexpected "+key); return "", false }
	verified(t, r2)
	if _, err := r2.RunJob(context.Background(), testSpec("job-2")); err != nil {
		t.Fatal(err)
	}
	if len(asked) != 1 || asked[0] != "gradle9.8.2-jdk21" {
		t.Errorf("asked %v", asked)
	}

	// A runtime nobody knows has no image, and no Pod is made for it.
	spec.Runtime, spec.JobID = "gradle1.0-jdk8", "job-3"
	before := f.creates
	if _, err := r.RunJob(context.Background(), spec); err == nil || !strings.Contains(err.Error(), "no work image") {
		t.Errorf("err = %v", err)
	}
	if f.creates != before {
		t.Error("a Pod was made without an image")
	}
	// Without ImageFor an unlisted runtime has none either.
	r.cfg.ImageFor = nil
	spec.Runtime = "gradle9.8.2-jdk21"
	if _, err := r.RunJob(context.Background(), spec); err == nil {
		t.Error("an unlisted runtime ran without ImageFor")
	}
}
