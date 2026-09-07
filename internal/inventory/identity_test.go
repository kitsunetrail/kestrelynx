package inventory

import (
	"strings"
	"testing"
)

// validHex is a well-formed 64-character lowercase sha256 hex digest, used
// wherever a test needs some valid hex without caring about its specific
// value.
var validHex = strings.Repeat("0123456789abcdef", 4)

// --- ParseDigest ---

func TestParseDigest_ValidSHA256Accepted(t *testing.T) {
	for _, kind := range []DigestKind{DigestConfig, DigestRegistry} {
		d, ok := ParseDigest(kind, "sha256:"+validHex)
		if !ok {
			t.Fatalf("ParseDigest(%q, ...) ok = false, want true", kind)
		}
		if d.Kind != kind || d.Algorithm != "sha256" || d.Hex != validHex {
			t.Errorf("ParseDigest(%q, ...) = %+v, want {Kind:%q Algorithm:sha256 Hex:%s}", kind, d, kind, validHex)
		}
		if !d.Valid() {
			t.Errorf("ParseDigest(%q, ...) returned a Digest that fails Valid(): %+v", kind, d)
		}
	}
}

func TestParseDigest_UppercaseHexRejected(t *testing.T) {
	s := "sha256:" + strings.ToUpper(validHex)
	if d, ok := ParseDigest(DigestConfig, s); ok {
		t.Errorf("ParseDigest(%q) = %+v, ok=true, want zero value and false", s, d)
	}
}

func TestParseDigest_WrongAlgorithmRejected(t *testing.T) {
	// sha512 hex is 128 characters; use a 128-char run so only the algorithm
	// name (not the length) is under test.
	s := "sha512:" + strings.Repeat("a", 128)
	if d, ok := ParseDigest(DigestConfig, s); ok {
		t.Errorf("ParseDigest(%q) = %+v, ok=true, want zero value and false", s, d)
	}
}

func TestParseDigest_BareHexRejected(t *testing.T) {
	// No "sha256:" prefix at all.
	if d, ok := ParseDigest(DigestConfig, validHex); ok {
		t.Errorf("ParseDigest(%q) = %+v, ok=true, want zero value and false (missing algorithm prefix)", validHex, d)
	}
}

func TestParseDigest_FailureReturnsZeroValue(t *testing.T) {
	d, ok := ParseDigest(DigestConfig, "not-a-digest")
	if ok {
		t.Fatal("ok = true, want false")
	}
	if d != (Digest{}) {
		t.Errorf("d = %+v, want the zero Digest on failure", d)
	}
}

// TestParseDigest_UnknownKindRejected fixes that a well-formed wire string
// still fails to construct a Digest when the requested kind is not one of
// the enumerated kinds — ParseDigest never produces a value Valid() would
// reject.
func TestParseDigest_UnknownKindRejected(t *testing.T) {
	for _, kind := range []DigestKind{DigestUnknown, DigestKind("invalid")} {
		if d, ok := ParseDigest(kind, "sha256:"+validHex); ok || d != (Digest{}) {
			t.Errorf("ParseDigest(%q, valid wire string) = %+v, ok=%v, want zero value and false", kind, d, ok)
		}
	}
}

// --- Digest.Valid ---

// TestDigest_InvalidKindRejected fixes the requirement that Valid() checks
// Kind against the enumerated allow-list, not merely "!= DigestUnknown": an
// undefined DigestKind value must never read as valid, since it isn't
// DigestUnknown either.
func TestDigest_InvalidKindRejected(t *testing.T) {
	d := Digest{Kind: DigestKind("invalid"), Algorithm: "sha256", Hex: validHex}
	if d.Valid() {
		t.Errorf("Digest{Kind: %q}.Valid() = true, want false", d.Kind)
	}
}

func TestDigest_ZeroValueInvalid(t *testing.T) {
	if (Digest{}).Valid() {
		t.Error("zero-value Digest.Valid() = true, want false")
	}
}

func TestDigest_String(t *testing.T) {
	valid, ok := ParseDigest(DigestConfig, "sha256:"+validHex)
	if !ok {
		t.Fatal("test fixture: ParseDigest failed")
	}
	if got, want := valid.String(), "sha256:"+validHex; got != want {
		t.Errorf("valid Digest.String() = %q, want %q", got, want)
	}

	invalid := Digest{Kind: DigestKind("invalid"), Algorithm: "sha256", Hex: validHex}
	if got := invalid.String(); got != "" {
		t.Errorf("invalid Digest.String() = %q, want empty", got)
	}
}

// --- EntityKeyOf ---

func TestEntityKeyOf_ValidConfigDigest(t *testing.T) {
	cfg, ok := ParseDigest(DigestConfig, "sha256:"+validHex)
	if !ok {
		t.Fatal("test fixture: ParseDigest failed")
	}
	// Platform is populated but must not leak into the key: a config digest
	// already hashes one specific platform's config.
	img := RunningImage{Ref: "app:1", Config: cfg, Platform: Platform{OS: "linux", Architecture: "amd64"}}

	key, ok := EntityKeyOf(img)
	if !ok {
		t.Fatal("ok = false, want true (valid config digest)")
	}
	want := EntityKey{Digest: cfg}
	if key != want {
		t.Errorf("key = %+v, want %+v (Platform must not contribute to a config-kind key)", key, want)
	}
}

func TestEntityKeyOf_RegistryDigestWithKnownPlatform(t *testing.T) {
	reg, ok := ParseDigest(DigestRegistry, "sha256:"+validHex)
	if !ok {
		t.Fatal("test fixture: ParseDigest failed")
	}
	plat := Platform{OS: "linux", Architecture: "arm64"}
	img := RunningImage{Ref: "app:1", Registry: RegistryRef{Repository: "app", Digest: reg}, Platform: plat}

	key, ok := EntityKeyOf(img)
	if !ok {
		t.Fatal("ok = false, want true (valid registry digest + known platform)")
	}
	want := EntityKey{Digest: reg, Platform: plat}
	if key != want {
		t.Errorf("key = %+v, want %+v", key, want)
	}
}

// TestEntityKeyOf_RegistryDigestWithUnknownPlatform guards the platform
// guard: an index digest does not pin a platform, so without a known
// Platform no key can be derived — not even within a single Environment (a
// mixed-architecture cluster can observe the same index digest under two
// different platforms).
func TestEntityKeyOf_RegistryDigestWithUnknownPlatform(t *testing.T) {
	reg, ok := ParseDigest(DigestRegistry, "sha256:"+validHex)
	if !ok {
		t.Fatal("test fixture: ParseDigest failed")
	}
	img := RunningImage{Ref: "app:1", Registry: RegistryRef{Digest: reg}} // Platform left zero (unknown)

	if key, ok := EntityKeyOf(img); ok {
		t.Errorf("EntityKeyOf(%+v) = %+v, ok=true, want ok=false (Platform unknown)", img, key)
	}
}

func TestEntityKeyOf_NeitherDigestValid(t *testing.T) {
	img := RunningImage{Ref: "app:1"}
	if key, ok := EntityKeyOf(img); ok {
		t.Errorf("EntityKeyOf(%+v) = %+v, ok=true, want ok=false", img, key)
	}
}

// TestEntityKeyOf_MisassignedKindNotConfused fixes the requirement that each
// branch checks the specific Kind it expects rather than trusting Valid()
// alone: a Digest carrying DigestRegistry stored in the Config field
// must not be treated as a config digest just because it passes Valid().
func TestEntityKeyOf_MisassignedKindNotConfused(t *testing.T) {
	reg, ok := ParseDigest(DigestRegistry, "sha256:"+validHex)
	if !ok {
		t.Fatal("test fixture: ParseDigest failed")
	}
	img := RunningImage{Ref: "app:1", Config: reg} // wrong field for this Kind
	if key, ok := EntityKeyOf(img); ok {
		t.Errorf("EntityKeyOf(%+v) = %+v, ok=true, want ok=false (registry-kind digest in Config must not be accepted as a config digest)", img, key)
	}
}

// TestEntityKeyOf_MisassignedConfigKindInRegistryField covers the reverse
// misassignment: a config-kind digest stored in Registry.Digest must not be
// accepted as a registry digest, even when the platform is known.
func TestEntityKeyOf_MisassignedConfigKindInRegistryField(t *testing.T) {
	cfg, ok := ParseDigest(DigestConfig, "sha256:"+validHex)
	if !ok {
		t.Fatal("test fixture: ParseDigest failed")
	}
	img := RunningImage{
		Ref:      "app:1",
		Registry: RegistryRef{Repository: "app", Digest: cfg}, // wrong field for this Kind
		Platform: Platform{OS: "linux", Architecture: "amd64"},
	}
	if key, ok := EntityKeyOf(img); ok {
		t.Errorf("EntityKeyOf(%+v) = %+v, ok=true, want ok=false (config-kind digest in Registry must not be accepted as a registry digest)", img, key)
	}
}

// --- ImageSubject ---

// TestImageSubject_UnresolvedSubjectsShareZeroKey documents why ImageSubject
// carries Ref alongside Key: an EntityKey cannot be derived from a
// reference, so two unresolved observations (Resolved == false) always carry
// the same zero-value Key. Distinguishing them — never colliding two
// different references' unresolved entities — has to come from Ref instead.
func TestImageSubject_UnresolvedSubjectsShareZeroKey(t *testing.T) {
	a := ImageSubject{Ref: "app:1"}
	b := ImageSubject{Ref: "app:2"}
	if a.Resolved || b.Resolved {
		t.Fatal("zero-value ImageSubject must be unresolved")
	}
	if a.Key != b.Key {
		t.Fatalf("unresolved subjects should carry the same zero EntityKey, got %+v and %+v", a.Key, b.Key)
	}
	if a.Ref == b.Ref {
		t.Fatal("test fixture invalid: want distinct Ref")
	}
}
