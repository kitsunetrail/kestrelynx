package intel

import (
	"context"
	"testing"
	"time"
)

func TestNoteURL(t *testing.T) {
	cases := []struct{ notes, want string }{
		// Real KEV shapes (verified 2026-07-06).
		{"https://www.jenkins.io/security/advisory/2024-01-24/#SECURITY-3314; https://nvd.nist.gov/vuln/detail/CVE-2024-23897", "https://www.jenkins.io/security/advisory/2024-01-24/#SECURITY-3314"},
		{"https://security.paloaltonetworks.com/CVE-2024-3400 ;   https://nvd.nist.gov/vuln/detail/CVE-2024-3400", "https://security.paloaltonetworks.com/CVE-2024-3400"},
		{"For more information, please see: CISA: https://www.cisa.gov/news-events/alerts/2023/10/10/x ; https://nvd.nist.gov/vuln/detail/CVE-2023-44487", "https://www.cisa.gov/news-events/alerts/2023/10/10/x"},
		{"https://nvd.nist.gov/vuln/detail/CVE-2020-0001", ""}, // NVD only: nothing worth adding
		{"", ""},
	}
	for _, c := range cases {
		if got := noteURL(c.notes); got != c.want {
			t.Errorf("noteURL(%q) = %q, want %q", c.notes, got, c.want)
		}
	}
}

func TestLookupCarriesKEVNoteURL(t *testing.T) {
	feeds := newTestFeeds(t)
	now := time.Date(2026, 7, 6, 9, 0, 0, 0, time.UTC)
	s := newSource(t, feeds, &now)

	got, _, err := s.Lookup(context.Background(), []string{"CVE-2026-1111"})
	if err != nil {
		t.Fatal(err)
	}
	if got["CVE-2026-1111"].KEVNoteURL != "https://vendor.test/advisory" {
		t.Errorf("KEVNoteURL = %q, want the vendor advisory from the notes", got["CVE-2026-1111"].KEVNoteURL)
	}
}
