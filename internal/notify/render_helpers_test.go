package notify

import (
	"github.com/kitsunetrail/kestrelynx/internal/analyze"
	"github.com/kitsunetrail/kestrelynx/internal/state"
)

func pickLang(lang []Language) Language {
	if len(lang) > 0 {
		return lang[0]
	}
	return LanguageEN
}

// renderFull is the text of every block of the full-view channel message,
// newline-joined: what a reader of the channel sees, without the layout.
func renderFull(r analyze.Report, lang ...Language) string {
	return allBlocksText(BuildChannelMessages(Message{Report: r}, ChannelFooter{}, pickLang(lang)))
}

// renderDiff is renderFull for the diff-mode channel message.
func renderDiff(r analyze.Report, d state.Diff, fullReport, holding bool, lang ...Language) string {
	m := Message{Report: r, Diff: &d, FullReport: fullReport, Holding: holding}
	return allBlocksText(BuildChannelMessages(m, ChannelFooter{}, pickLang(lang)))
}

// renderThread is the text of every block of every thread reply, in order.
func renderThread(r analyze.Report, ages Ages, lang ...Language) string {
	return allBlocksText(BuildThreadBlockMessages(r, ages, pickLang(lang)))
}

// inUsePhrase is the evidence phrase of an in-use runtime verdict (the
// kind(s), with the executable they are paired with, or the unattributed
// list), as the in-use evidence line shows it.
func inUsePhrase(rt analyze.Runtime) string {
	f, ok := runtimeInUseFacts(rt, enMessages)
	if !ok {
		return enMessages.InUseFallbackArrow
	}
	return f.Evidence
}

// runtimeLinesOf renders a package group's runtime lines in the given mode.
func runtimeLinesOf(mode runtimeMode, rt analyze.Runtime) []string {
	rd := renderer{msg: enMessages, lim: defaultRenderLimits}
	c := pkgCard{RuntimeMode: mode, Runtime: cardRuntimeOf(rt, enMessages)}
	return rd.runtimeLines(c)
}
