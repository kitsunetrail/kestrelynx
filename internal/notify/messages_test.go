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
// struct actually reaches the channel message's output: swapping one field in a
// test-local dictionary changes exactly the text that field controls, and
// nothing else in the message.
func TestLanguageSwitch_CustomDictionaryTakesEffect(t *testing.T) {
	const marker = "TEST-MARKER-EVERYTHING-OPEN"
	r := sampleReport()

	got := allBlocksText(buildChannelMessages(Message{Report: r}, ChannelFooter{}, testMessages(marker), defaultRenderLimits))
	if !strings.Contains(got, marker) {
		t.Errorf("the channel message with a swapped RoleEverythingOpen did not contain the marker:\n%s", got)
	}
	if strings.Contains(got, enMessages.RoleEverythingOpen) {
		t.Errorf("the channel message with a swapped RoleEverythingOpen still contained the English text:\n%s", got)
	}

	// The rest of the message must be byte-identical to the English
	// rendering with the marker line removed — swapping one dictionary
	// entry must never perturb any other line.
	want := allBlocksText(buildChannelMessages(Message{Report: r}, ChannelFooter{}, enMessages, defaultRenderLimits))
	gotOther := strings.Replace(got, marker, enMessages.RoleEverythingOpen, 1)
	if gotOther != want {
		t.Errorf("swapping one messages field changed more than that field's own text:\ngot  = %q\nwant = %q", gotOther, want)
	}
}

// TestLanguageSwitch_DiffTextTakesCustomDictionary extends the same proof to
// the diff-mode entry point is covered too, not just
// the full view.
func TestLanguageSwitch_DiffTextTakesCustomDictionary(t *testing.T) {
	const marker = "TEST-MARKER-CHANGES-SINCE-LAST-SCAN"
	r, changed, _, _ := goldenCycle(goldenModes()[0], false)

	m := enMessages
	m.RoleChangesSinceLastScan = marker
	got := allBlocksText(buildChannelMessages(Message{Report: r, Diff: &changed}, ChannelFooter{}, m, defaultRenderLimits))
	if !strings.Contains(got, marker) {
		t.Errorf("the diff message with a swapped RoleChangesSinceLastScan did not contain the marker:\n%s", got)
	}
}

// TestLanguageSwitch_ThreadTakesCustomDictionary extends the same proof to
// the thread report, so the thread-report entry point is covered too.
func TestLanguageSwitch_ThreadTakesCustomDictionary(t *testing.T) {
	const marker = "TEST-MARKER-THREAD-TITLE"
	r, _, _, next := goldenCycle(goldenModes()[0], false)

	m := enMessages
	m.ThreadTitle = marker
	msgs := buildThreadBlockMessages(r, Ages{Finding: next.FirstSeen, EOL: next.EOLFirstSeen}, m, defaultRenderLimits)
	if len(msgs) == 0 || !strings.Contains(allBlocksText(msgs[:1]), marker) {
		t.Errorf("the thread with a swapped ThreadTitle did not contain the marker:\n%v", msgs)
	}
}

// TestChannel_LanguageArgumentReachesTheImplementation confirms the exported
// builders use the requested dictionary rather than always defaulting to
// English.
func TestChannel_LanguageArgumentReachesTheImplementation(t *testing.T) {
	r := sampleReport()
	if got, want := renderFull(r), renderFull(r, LanguageEN); got != want {
		t.Errorf("renderFull(r) != renderFull(r, LanguageEN):\n%q\n%q", got, want)
	}
	// jaMessages is now a real translation, so LanguageJA must actually
	// change the rendered text relative to English — proof the argument
	// reaches the renderer rather than being ignored.
	if got, en := renderFull(r, LanguageJA), renderFull(r, LanguageEN); got == en {
		t.Errorf("renderFull(r, LanguageJA) is byte-identical to English; expected jaMessages's translation to change the output")
	}
}
