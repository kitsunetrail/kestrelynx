// Layout of a view into units: the order of headings, cards and dividers
// the channel body and the thread report share. A layout only arranges what
// the renderers hand it; splitting into messages is split.go's job.
package notify

import "strings"

// cardView is one package card ready to place: either a multi-section card
// (detail) or a few lines for a single section (compact).
type cardView struct {
	detail    bool
	blocks    []Block  // detail: the card's blocks, without a divider
	lines     []string // compact: the card's lines
	pkgs      int
	contTitle string
}

// imageView is one image's heading and its cards.
type imageView struct {
	heading string   // the bold image line
	cont    string   // the image line as repeated on a continuation message
	extra   []string // further lines of the image heading (counts)
	name    string   // the bare image name
	cards   []cardView
}

// contHeading is the image line a continuation message repeats.
func (im imageView) contHeading() string {
	if im.cont != "" {
		return im.cont
	}
	return im.heading
}

// layout accumulates units and tracks the category and image in effect.
type layout struct {
	units      []unit
	cat        string
	catShort   string
	image      string
	imageName  string
	groupStart bool
}

// group makes the next unit open with a divider: it starts a new group of
// the view. The very first unit never gets one.
func (l *layout) group() { l.groupStart = true }

// emit appends u, stamping it with the current category and image context.
// div asks for a divider in front of it.
func (l *layout) emit(u unit, div bool) {
	if (div || l.groupStart) && len(l.units) > 0 {
		u.blocks = append([]Block{dividerBlock}, u.blocks...)
	}
	l.groupStart = false
	u.cat, u.catShort, u.image, u.imageName = l.cat, l.catShort, l.image, l.imageName
	l.units = append(l.units, u)
}

func (l *layout) openCat(cat, short string) {
	l.cat, l.catShort, l.image, l.imageName = cat, short, "", ""
}

func (l *layout) openImage(heading, name string) { l.image, l.imageName = heading, name }

func (l *layout) closeCat() { l.openCat("", "") }

// section emits a plain section unit (summary lines, warnings).
func (l *layout) section(lim RenderLimits, lines []string, tail bool) {
	blocks := sectionBlocks(lines, lim.MaxTextUnits)
	if len(blocks) == 0 {
		return
	}
	l.emit(unit{blocks: blocks, tail: tail}, false)
}

// heading emits a standalone heading section, kept with the unit after it.
func (l *layout) heading(lim RenderLimits, lines []string) {
	blocks := sectionBlocks(lines, lim.MaxTextUnits)
	if len(blocks) == 0 {
		return
	}
	l.emit(unit{blocks: blocks, sticky: true}, false)
}

// note emits supplementary text as context blocks of at most the text limit
// each, every one attached to the unit before it.
// head says what the note is about; a message that starts partway through a
// long note opens with it.
func (l *layout) note(lim RenderLimits, head, text string, tail bool) {
	for _, t := range packLines([]string{text}, lim.MaxTextUnits) {
		l.emit(unit{blocks: []Block{contextBlock(t)}, attach: true, tail: tail, noteHead: head}, false)
	}
}

func (cv cardView) unit(lim RenderLimits, headLines []string) unit {
	var blocks []Block
	if cv.detail {
		blocks = cv.blocks
	} else {
		blocks = sectionBlocks(append(append([]string(nil), headLines...), cv.lines...), lim.MaxTextUnits)
	}
	return unit{blocks: blocks, pkgs: cv.pkgs, contTitle: cv.contTitle}
}

const (
	prevNone = iota
	prevCompact
	prevDetail
)

// channelCategory lays out a category of the channel body: its heading and,
// per image, the cards. Detail cards are several sections each and are
// separated by dividers; compact cards are one section each and sit
// together. The category heading shares a section with the first image's
// heading when a detail card follows; ahead of compact cards it stands
// alone and each image's heading joins that image's first card.
func (l *layout) channelCategory(lim RenderLimits, cat, short string, imgs []imageView) {
	if len(imgs) == 0 {
		return
	}
	l.group()
	l.openCat(cat, short)
	prev := prevNone
	for idx, im := range imgs {
		if len(im.cards) == 0 {
			continue
		}
		headLines := append([]string{im.heading}, im.extra...)
		first := im.cards[0]
		if first.detail {
			l.openImage(im.contHeading(), im.name)
			if idx == 0 {
				l.emit(unit{blocks: sectionBlocks(append([]string{cat}, headLines...), lim.MaxTextUnits), sticky: true, startsCat: true, startsImage: true}, false)
			} else {
				l.emit(unit{blocks: sectionBlocks(headLines, lim.MaxTextUnits), sticky: true, startsImage: true}, prev != prevNone)
			}
			l.emit(first.unit(lim, nil), false)
			prev = prevDetail
		} else {
			if idx == 0 {
				l.emit(unit{blocks: []Block{sectionBlock(cat)}, sticky: true, startsCat: true}, false)
			}
			l.openImage(im.contHeading(), im.name)
			u := first.unit(lim, headLines)
			u.startsImage = true
			l.emit(u, prev == prevDetail)
			prev = prevCompact
		}
		for _, c := range im.cards[1:] {
			div := prev == prevDetail || c.detail
			l.emit(c.unit(lim, nil), div)
			prev = prevCompact
			if c.detail {
				prev = prevDetail
			}
		}
	}
	// What follows is outside the category: a message split here must not
	// head it with a continuation of the category or image.
	l.closeCat()
}

// threadCategory lays out a category of the thread: the category heading
// shares a section with the first image's heading, a later image's heading
// has a divider in front, and every card has one too.
func (l *layout) threadCategory(lim RenderLimits, cat, short string, imgs []imageView) {
	if len(imgs) == 0 {
		return
	}
	l.group()
	l.openCat(cat, short)
	for idx, im := range imgs {
		headLines := append([]string{im.heading}, im.extra...)
		l.openImage(im.contHeading(), im.name)
		// An image with no cards ends with its heading section.
		sticky := len(im.cards) > 0
		if idx == 0 {
			l.emit(unit{blocks: sectionBlocks(append([]string{cat}, headLines...), lim.MaxTextUnits), sticky: sticky, startsCat: true, startsImage: true}, false)
		} else {
			l.emit(unit{blocks: sectionBlocks(headLines, lim.MaxTextUnits), sticky: sticky, startsImage: true}, true)
		}
		for _, c := range im.cards {
			l.emit(c.unit(lim, nil), true)
		}
	}
	l.closeCat()
}

// trimNL strips the newlines the dictionary's line formats carry.
func trimNL(s string) string { return strings.Trim(s, "\n") }

// emphasizeLabel makes the leading "label:" of a summary line bold, after
// any leading emoji: "📌 Open now: x" becomes "📌 *Open now:* x". A line
// without a ": " is returned unchanged.
func emphasizeLabel(s string) string {
	i := strings.Index(s, ": ")
	if i < 0 {
		return s
	}
	label, prefix := s[:i+1], ""
	if j := strings.IndexByte(label, ' '); j >= 0 {
		prefix, label = label[:j+1], label[j+1:]
	}
	return prefix + "*" + label + "*" + s[i+1:]
}
