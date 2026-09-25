package evidence

import "testing"

func TestValidString_LengthBoundary(t *testing.T) {
	atLimit := make([]byte, maxStringBytes)
	for i := range atLimit {
		atLimit[i] = 'a'
	}
	if !validString(string(atLimit)) {
		t.Error("a string exactly at maxStringBytes should be valid")
	}

	overLimit := append(atLimit, 'a')
	if validString(string(overLimit)) {
		t.Error("a string one byte over maxStringBytes should be invalid")
	}
}

func TestValidString_RejectsControlCharacters(t *testing.T) {
	cases := []string{
		"contains\x00null",
		"contains\x1fus",
		"contains\x7fdel",
		"contains\u0085nel", // Unicode NEL, outside the ASCII control range
		"contains\u009cst",  // Unicode C1 "STRING TERMINATOR"
	}
	for _, s := range cases {
		if validString(s) {
			t.Errorf("validString(%q) = true, want false (control character)", s)
		}
	}
}

func TestValidString_AcceptsOrdinaryUnicode(t *testing.T) {
	cases := []string{
		"usr/local/bin/日本語",
		"3.0.15-1~deb12u1",
		"",
	}
	for _, s := range cases {
		if !validString(s) {
			t.Errorf("validString(%q) = false, want true", s)
		}
	}
}

func TestValidString_RejectsInvalidUTF8(t *testing.T) {
	// A lone continuation byte: not valid UTF-8 on its own. validString
	// itself catches this directly (defense in depth); Read additionally
	// checks the raw file body before this function ever runs, since
	// json.Unmarshal would otherwise sanitize the byte away first — see
	// TestRead_InvalidUTF8InRawBodyRejected.
	bad := string([]byte{'a', 0x80, 'b'})
	if validString(bad) {
		t.Error("validString should reject invalid UTF-8")
	}
}

func TestValidContainerID(t *testing.T) {
	sixtyFourZeros := ""
	for i := 0; i < 64; i++ {
		sixtyFourZeros += "0"
	}
	cases := []struct {
		id   string
		want bool
	}{
		{sixtyFourZeros, true},
		{sixtyFourZeros[:63], false},  // one short
		{sixtyFourZeros + "0", false}, // one long
		{"", false},
		{sixtyFourZeros[:63] + "G", false}, // non-hex character
		{sixtyFourZeros[:63] + "A", false}, // uppercase hex is rejected
	}
	for _, c := range cases {
		if got := validContainerID(c.id); got != c.want {
			t.Errorf("validContainerID(%q) = %v, want %v", c.id, got, c.want)
		}
	}
}
