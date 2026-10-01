// Block Kit message model: the structure a Slack chat message is assembled
// into before it is sent. A message is a short fallback text (the
// notification preview and screen-reader text) plus the visible body, a list
// of section / divider / context blocks. Only those three block kinds are
// used, and sections carry a single mrkdwn text (no fields, no header block,
// no expand), so a message stays within what an Incoming Webhook and a bot
// token both accept.
package notify

import (
	"encoding/json"
	"strings"
	"unicode/utf8"
)

// BlockKind is the Block Kit block type of one Block.
type BlockKind int

const (
	// BlockSection is a section block with one mrkdwn text.
	BlockSection BlockKind = iota
	// BlockDivider is a divider block; it carries no text.
	BlockDivider
	// BlockContext is a context block with one mrkdwn element.
	BlockContext
)

// String names the kind the way the structure dump and the Slack payload do.
func (k BlockKind) String() string {
	switch k {
	case BlockDivider:
		return "divider"
	case BlockContext:
		return "context"
	default:
		return "section"
	}
}

// Block is one visible block of a message. Text is mrkdwn and empty for a
// divider.
type Block struct {
	Kind BlockKind
	Text string
}

// SlackMessage is one chat message: Text is the notification preview /
// screen-reader text, Blocks the visible body.
type SlackMessage struct {
	Text   string
	Blocks []Block
}

type mrkdwnText struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type blockJSON struct {
	Type     string       `json:"type"`
	Text     *mrkdwnText  `json:"text,omitempty"`
	Elements []mrkdwnText `json:"elements,omitempty"`
}

// MarshalJSON renders the block in Slack's wire format: a section as
// {"type":"section","text":{"type":"mrkdwn","text":...}}, a context as
// {"type":"context","elements":[{"type":"mrkdwn","text":...}]}, a divider as
// {"type":"divider"}.
func (b Block) MarshalJSON() ([]byte, error) {
	out := blockJSON{Type: b.Kind.String()}
	switch b.Kind {
	case BlockSection:
		out.Text = &mrkdwnText{Type: "mrkdwn", Text: b.Text}
	case BlockContext:
		out.Elements = []mrkdwnText{{Type: "mrkdwn", Text: b.Text}}
	}
	return json.Marshal(out)
}

// MarshalJSON renders the message as a chat.postMessage / Incoming Webhook
// body: {"text": ..., "blocks": [...]}.
func (m SlackMessage) MarshalJSON() ([]byte, error) {
	blocks := m.Blocks
	if blocks == nil {
		blocks = []Block{}
	}
	return json.Marshal(struct {
		Text   string  `json:"text"`
		Blocks []Block `json:"blocks"`
	}{m.Text, blocks})
}

// RenderLimits are the size limits one rendered message is packed against.
// They are internal constants of the renderer, not configuration. Text sizes
// are counted in UTF-16 code units, deliberately conservative: Slack does not
// document which Unicode unit its character limits count.
type RenderLimits struct {
	// MaxBlocks is the most blocks one message may carry.
	MaxBlocks int
	// MaxTextUnits is the most UTF-16 code units one section or context text
	// may hold.
	MaxTextUnits int
	// MaxMessageUnits is a soft cap on the total block text of one message,
	// kept well below what Slack would accept so a message stays readable.
	MaxMessageUnits int
	// MaxFallbackUnits caps the fallback text.
	MaxFallbackUnits int
}

// normalized returns lim with the values the packer needs to make progress:
// a section must fit twice in a message and a message must have room for a
// heading, a divider, a section and a context.
func (lim RenderLimits) normalized() RenderLimits {
	if lim.MaxBlocks < 6 {
		lim.MaxBlocks = 6
	}
	if half := lim.MaxMessageUnits / 2; lim.MaxTextUnits > half {
		lim.MaxTextUnits = half
	}
	return lim
}

// defaultRenderLimits are the limits every public builder uses.
var defaultRenderLimits = RenderLimits{
	MaxBlocks:        50,
	MaxTextUnits:     3000,
	MaxMessageUnits:  12000,
	MaxFallbackUnits: 4000,
}

// utf16Len counts s in UTF-16 code units: a rune outside the Basic
// Multilingual Plane (most emoji) counts twice.
func utf16Len(s string) int {
	n := 0
	for _, r := range s {
		if r >= 0x10000 {
			n += 2
		} else {
			n++
		}
	}
	return n
}

// blocksUnits is the total text size of blocks in UTF-16 code units.
func blocksUnits(blocks []Block) int {
	n := 0
	for _, b := range blocks {
		n += utf16Len(b.Text)
	}
	return n
}

// truncateUnits cuts s to at most max UTF-16 code units, at a rune boundary,
// marking the cut with an ellipsis.
func truncateUnits(s string, max int) string {
	if utf16Len(s) <= max {
		return s
	}
	var b strings.Builder
	n := 0
	for _, r := range s {
		w := 1
		if r >= 0x10000 {
			w = 2
		}
		if n+w > max-1 {
			break
		}
		b.WriteRune(r)
		n += w
	}
	b.WriteString("…")
	return b.String()
}

// atom is a piece of mrkdwn text a long line is cut between, never inside.
type atom struct {
	text string
	n    int  // UTF-16 units
	hard bool // a cut must follow this atom (a closed code fragment)
}

// escapedEntity reports the length of the &amp; / &lt; / &gt; entity s
// starts with, or 0.
func escapedEntity(s string) int {
	for _, e := range []string{"&amp;", "&lt;", "&gt;"} {
		if strings.HasPrefix(s, e) {
			return len(e)
		}
	}
	return 0
}

// runeAtoms cuts plain mrkdwn text into entities and single runes.
func runeAtoms(s string) []atom {
	var out []atom
	for i := 0; i < len(s); {
		w := escapedEntity(s[i:])
		if w == 0 {
			_, w = utf8.DecodeRuneInString(s[i:])
		}
		out = append(out, atom{text: s[i : i+w], n: utf16Len(s[i : i+w])})
		i += w
	}
	return out
}

// textAtoms cuts s into atoms: a Slack link <...>, an inline code span
// `...`, an escaped entity, or a single rune. A link or code span larger
// than max cannot stay whole: a code span becomes several closed fragments
// (the backticks are closed and reopened per fragment), and a link becomes
// plain text — the label and URL as text — cut like any other text.
func textAtoms(s string, max int) []atom {
	var atoms []atom
	for i := 0; i < len(s); {
		switch s[i] {
		case '<':
			if j := strings.IndexByte(s[i:], '>'); j > 0 {
				tok := s[i : i+j+1]
				i += j + 1
				if n := utf16Len(tok); n <= max {
					atoms = append(atoms, atom{text: tok, n: n})
					continue
				}
				atoms = append(atoms, runeAtoms(linkAsText(tok))...)
				continue
			}
		case '`':
			if j := strings.IndexByte(s[i+1:], '`'); j >= 0 {
				tok := s[i : i+j+2]
				i += j + 2
				if n := utf16Len(tok); n <= max {
					atoms = append(atoms, atom{text: tok, n: n})
					continue
				}
				atoms = append(atoms, codeFragments(tok[1:len(tok)-1], max)...)
				continue
			}
		}
		w := escapedEntity(s[i:])
		if w == 0 {
			_, w = utf8.DecodeRuneInString(s[i:])
		}
		atoms = append(atoms, atom{text: s[i : i+w], n: utf16Len(s[i : i+w])})
		i += w
	}
	return atoms
}

// linkAsText renders a <url|label> token as plain text: the label with the
// URL in parentheses, or the URL alone.
func linkAsText(tok string) string {
	inner := tok[1 : len(tok)-1]
	url, label, ok := strings.Cut(inner, "|")
	if !ok || label == "" || label == url {
		return url
	}
	return label + " (" + url + ")"
}

// codeFragments cuts the inside of an over-long code span into closed
// fragments of at most max units, each wrapped in its own backticks.
func codeFragments(inner string, max int) []atom {
	var out []atom
	var cur strings.Builder
	curN := 0
	flush := func() {
		if curN > 0 {
			out = append(out, atom{text: "`" + cur.String() + "`", n: curN + 2, hard: true})
			cur.Reset()
			curN = 0
		}
	}
	for _, a := range runeAtoms(inner) {
		if curN+a.n > max-2 {
			flush()
		}
		cur.WriteString(a.text)
		curN += a.n
	}
	flush()
	return out
}

// flattenTokenNewlines turns a newline inside a link or an inline code span
// into a space, so the newlines left are the ones outside them, where a line
// may be cut.
func flattenTokenNewlines(s string) string {
	if !strings.Contains(s, "\n") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		var end int
		switch s[i] {
		case '<':
			if j := strings.IndexByte(s[i:], '>'); j > 0 {
				end = i + j + 1
			}
		case '`':
			if j := strings.IndexByte(s[i+1:], '`'); j >= 0 {
				end = i + j + 2
			}
		}
		if end > 0 {
			b.WriteString(strings.ReplaceAll(s[i:end], "\n", " "))
			i = end
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// splitLongLine breaks one line of more than max UTF-16 units into pieces of
// at most max, preferring to cut after a space or newline. It never cuts
// inside a link, an inline code span or an escaped entity; a token too large
// to stay whole is reshaped by textAtoms.
func splitLongLine(line string, max int) []string {
	if utf16Len(line) <= max {
		return []string{line}
	}
	var pieces []string
	var cur []atom
	curN := 0
	emit := func(k int) {
		var b strings.Builder
		n := 0
		for _, a := range cur[:k] {
			b.WriteString(a.text)
			n += a.n
		}
		if b.Len() > 0 {
			pieces = append(pieces, b.String())
		}
		cur = append([]atom(nil), cur[k:]...)
		curN -= n
	}
	for _, a := range textAtoms(line, max) {
		for curN+a.n > max && len(cur) > 0 {
			cut := len(cur)
			for i := len(cur) - 1; i > 0; i-- {
				if cur[i].text == " " || cur[i].text == "\n" {
					cut = i + 1
					break
				}
			}
			emit(cut)
		}
		cur = append(cur, a)
		curN += a.n
		if a.hard {
			emit(len(cur))
		}
	}
	emit(len(cur))
	return pieces
}

// packLines joins lines with newlines into texts of at most max UTF-16 units,
// breaking only between lines; a line longer than max is split by
// splitLongLine. A nil/empty input yields no texts, so a section is never
// built from nothing.
func packLines(lines []string, max int) []string {
	var out []string
	var cur []string
	curN := 0
	flush := func() {
		if len(cur) > 0 {
			out = append(out, strings.Join(cur, "\n"))
			cur, curN = nil, 0
		}
	}
	for _, line := range lines {
		if line == "" {
			continue
		}
		// Existing newlines are the first place to cut; only a single line
		// that is itself over the limit is cut inside.
		for _, sub := range strings.Split(flattenTokenNewlines(line), "\n") {
			if sub == "" {
				continue
			}
			for _, piece := range splitLongLine(sub, max) {
				n := utf16Len(piece)
				add := n
				if len(cur) > 0 {
					add++
				}
				if curN+add > max {
					flush()
					add = n
				}
				cur = append(cur, piece)
				curN += add
			}
		}
	}
	flush()
	return out
}

// sectionBlocks packs lines into one or more section blocks.
func sectionBlocks(lines []string, max int) []Block {
	texts := packLines(lines, max)
	out := make([]Block, len(texts))
	for i, t := range texts {
		out[i] = Block{Kind: BlockSection, Text: t}
	}
	return out
}

func sectionBlock(text string) Block { return Block{Kind: BlockSection, Text: text} }
func contextBlock(text string) Block { return Block{Kind: BlockContext, Text: text} }

var dividerBlock = Block{Kind: BlockDivider}
