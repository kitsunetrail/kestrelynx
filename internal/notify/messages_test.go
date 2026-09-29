package notify

import (
	"strings"
	"testing"
)

// TestMessagesFor_SelectsDictionary confirms messagesFor picks the right
// dictionary by identity (comparing one field is enough since Language only
// ever selects between the two package-level vars) and falls back to English
// for the zero value, which is what every pre-existing caller that never
// mentions a language relies on.
func TestMessagesFor_SelectsDictionary(t *testing.T) {
	if got := messagesFor(LanguageEN); got.RoleEverythingOpen != enMessages.RoleEverythingOpen {
		t.Errorf("messagesFor(LanguageEN) did not select enMessages")
	}
	if got := messagesFor(LanguageJA); got.RoleEverythingOpen != jaMessages.RoleEverythingOpen {
		t.Errorf("messagesFor(LanguageJA) did not select jaMessages")
	}
	if got := messagesFor(""); got.RoleEverythingOpen != enMessages.RoleEverythingOpen {
		t.Errorf("messagesFor(\"\") (zero value) did not default to enMessages")
	}
}

// TestResolveLanguage_DefaultsToEnglish confirms the variadic trailing
// language argument FormatSlackText/FormatSlackDiffText/BuildThreadMessages
// take defaults to English when omitted — the property every pre-existing
// call site (including every golden test) depends on for byte-identical
// output.
func TestResolveLanguage_DefaultsToEnglish(t *testing.T) {
	if got := resolveLanguage(nil); got != LanguageEN {
		t.Errorf("resolveLanguage(nil) = %q, want %q", got, LanguageEN)
	}
	if got := resolveLanguage([]Language{LanguageJA}); got != LanguageJA {
		t.Errorf("resolveLanguage([]Language{LanguageJA}) = %q, want %q", got, LanguageJA)
	}
}

// testMessages returns enMessages with exactly one field swapped for a
// marker string, so a test can prove the dictionary actually reaches the
// rendered output rather than being silently ignored, independent of
// whatever jaMessages currently says.
func testMessages(marker string) messages {
	m := enMessages
	m.RoleEverythingOpen = marker
	return m
}

// TestLanguageSwitch_CustomDictionaryTakesEffect confirms the messages
// struct actually reaches FormatSlackText's output: swapping one field in a
// test-local dictionary changes exactly the text that field controls, and
// nothing else in the message.
func TestLanguageSwitch_CustomDictionaryTakesEffect(t *testing.T) {
	const marker = "TEST-MARKER-EVERYTHING-OPEN"
	r := sampleReport()

	got := formatSlackText(r, testMessages(marker))
	if !strings.Contains(got, marker) {
		t.Errorf("formatSlackText with a swapped RoleEverythingOpen did not contain the marker:\n%s", got)
	}
	if strings.Contains(got, enMessages.RoleEverythingOpen) {
		t.Errorf("formatSlackText with a swapped RoleEverythingOpen still contained the English text:\n%s", got)
	}

	// The rest of the message must be byte-identical to the English
	// rendering with the marker line removed — swapping one dictionary
	// entry must never perturb any other line.
	want := formatSlackText(r, enMessages)
	gotOther := strings.Replace(got, marker, enMessages.RoleEverythingOpen, 1)
	if gotOther != want {
		t.Errorf("swapping one messages field changed more than that field's own text:\ngot  = %q\nwant = %q", gotOther, want)
	}
}

// TestLanguageSwitch_DiffTextTakesCustomDictionary extends the same proof to
// formatSlackDiffText, so the diff-mode entry point is covered too, not just
// FormatSlackText.
func TestLanguageSwitch_DiffTextTakesCustomDictionary(t *testing.T) {
	const marker = "TEST-MARKER-CHANGES-SINCE-LAST-SCAN"
	r, changed, _, _ := goldenCycle(goldenModes()[0], false)

	got := formatSlackDiffText(r, changed, false, false, func() messages {
		m := enMessages
		m.RoleChangesSinceLastScan = marker
		return m
	}())
	if !strings.Contains(got, marker) {
		t.Errorf("formatSlackDiffText with a swapped RoleChangesSinceLastScan did not contain the marker:\n%s", got)
	}
}

// TestLanguageSwitch_ThreadTakesCustomDictionary extends the same proof to
// buildThreadMessages, so the thread-report entry point is covered too.
func TestLanguageSwitch_ThreadTakesCustomDictionary(t *testing.T) {
	const marker = "TEST-MARKER-THREAD-TITLE"
	r, _, _, next := goldenCycle(goldenModes()[0], false)

	m := enMessages
	m.ThreadTitle = marker
	msgs := buildThreadMessages(r, Ages{Finding: next.FirstSeen, EOL: next.EOLFirstSeen}, 0, m)
	if len(msgs) == 0 || !strings.Contains(msgs[0], marker) {
		t.Errorf("buildThreadMessages with a swapped ThreadTitle did not contain the marker:\n%v", msgs)
	}
}

// TestFormatSlackText_LanguageArgumentReachesTheImplementation confirms the
// exported, variadic-language FormatSlackText forwards to formatSlackText
// with the requested dictionary rather than always defaulting to English —
// the thin-wrapper contract every other entry point (FormatSlackDiffText,
// BuildThreadMessages) shares.
func TestFormatSlackText_LanguageArgumentReachesTheImplementation(t *testing.T) {
	r := sampleReport()
	if got, want := FormatSlackText(r), FormatSlackText(r, LanguageEN); got != want {
		t.Errorf("FormatSlackText(r) != FormatSlackText(r, LanguageEN):\n%q\n%q", got, want)
	}
	// jaMessages is now a real translation, so LanguageJA must actually
	// change the rendered text relative to English — proof the argument
	// reaches formatSlackText rather than being ignored.
	if got, en := FormatSlackText(r, LanguageJA), FormatSlackText(r, LanguageEN); got == en {
		t.Errorf("FormatSlackText(r, LanguageJA) is byte-identical to English; expected jaMessages's translation to change the output")
	}
}
