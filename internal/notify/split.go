// Message splitting shared by the channel body and the thread report. A view
// lays its content out as a sequence of units — a package card with the
// divider in front of it, an image heading, a category heading, a summary
// section — and splitUnits packs that sequence into messages that respect
// RenderLimits. A message boundary never falls inside a unit, and a heading
// is kept with the unit that follows it, so no message ends in a divider, a
// heading or a lone context. A message that continues a category (or an
// image) opens with a continuation heading naming it again.
package notify

// unit is the smallest piece of a view that stays in one message.
type unit struct {
	blocks []Block
	// sticky marks a heading-only unit: it is packed together with the unit
	// that follows it.
	sticky bool
	// attach marks a supplementary unit (a context note): it is packed
	// together with the unit before it, so a note never stands alone.
	attach bool
	// startsCat and startsImage mark a unit whose first block opens a new
	// category or image, so a message starting here needs no continuation
	// heading for it.
	startsCat   bool
	startsImage bool
	// cat, catShort, image and imageName are the category and image in effect
	// after this unit: the bold heading text (continuation headings repeat it)
	// and the bare names (fallback text uses them). All empty outside a
	// category.
	cat       string
	catShort  string
	image     string
	imageName string
	// pkgs counts package cards, for the fallback text.
	pkgs int
	// tail marks a unit of the closing open-now group, which the footer
	// notice joins without a divider of its own.
	tail bool
	// contTitle is the heading a card repeats on a later message when the
	// card alone is larger than a message and has to be cut between its
	// sections.
	contTitle string
	// noteHead names what a note unit is about, for the heading of a message
	// that starts inside a long note.
	noteHead string
}

// msgInfo describes one packed message to the fallback-text builder.
type msgInfo struct {
	n, total   int
	contCat    bool // opens in the middle of a category
	catShort   string
	firstImage string
	images     int
	pkgs       int
}

// splitSpec parameterizes the packer for a view.
type splitSpec struct {
	lim RenderLimits
	// lead is the first line of a continuation message's heading (the
	// channel's product header with its continuation number); nil for none.
	lead func(n, total int) string
	// cont is appended to a repeated category or image heading.
	cont string
	// fallback builds a message's fallback text.
	fallback func(info msgInfo) string
	// footer, when non-empty, is closed onto the first message: a divider
	// (unless footerJoinsTail and the message ends in the tail group) and
	// then the footer context.
	footer          string
	footerJoinsTail bool
}

// heading holds what a continuation heading is made of, until the message
// count is known and the numbering can be filled in.
type heading struct {
	present            bool
	showCat, showImage bool
	cat, image         string
	contTitle          string
}

// pendingMsg is a message being filled.
type pendingMsg struct {
	head      heading
	headBlock int // blocks and text units reserved for the heading, at its widest numbering
	headUnits int
	body      []Block
	bodyUnits int
	lastTail  bool
	info      msgInfo
	images    []string
}

func (spec splitSpec) renderHeading(h heading, n, total int) []Block {
	if !h.present {
		return nil
	}
	var lines []string
	if spec.lead != nil {
		lines = append(lines, spec.lead(n, total))
	}
	if h.showCat {
		lines = append(lines, h.cat+spec.cont)
	}
	if h.showImage {
		lines = append(lines, h.image+spec.cont)
	}
	if h.contTitle != "" {
		lines = append(lines, h.contTitle)
	}
	return sectionBlocks(lines, spec.lim.MaxTextUnits)
}

// digitsMax is the widest continuation number a split into at most n
// messages can need, as the largest number of that many digits.
func digitsMax(n int) int {
	w := 9
	for n >= 10 {
		n /= 10
		w = w*10 + 9
	}
	return w
}

// piece is a part of a chunk that may start a message when the chunk alone
// is larger than one: headings and dividers are glued to the block after
// them, a context to the block before it.
type piece struct {
	blocks      []Block
	u           unit // the unit the piece's main block belongs to
	first       bool // the first piece of its unit
	startsCat   bool
	startsImage bool
}

// startsWithContext reports whether the first block that is not a divider
// is a context.
func startsWithContext(blocks []Block) bool {
	for _, b := range blocks {
		if b.Kind != BlockDivider {
			return b.Kind == BlockContext
		}
	}
	return false
}

func hasContext(blocks []Block) bool {
	for _, b := range blocks {
		if b.Kind == BlockContext {
			return true
		}
	}
	return false
}

// cutPieces splits a chunk into pieces.
func cutPieces(ch []unit) []piece {
	var pieces []piece
	var head []Block
	headCat, headImg := false, false
	for _, u := range ch {
		if u.sticky {
			head = append(head, u.blocks...)
			headCat = headCat || u.startsCat
			headImg = headImg || u.startsImage
			continue
		}
		first := true
		for _, b := range u.blocks {
			if b.Kind == BlockDivider {
				head = append(head, b)
				continue
			}
			// A context joins the section before it, but only one: a long
			// note is several contexts, which may fall in different messages.
			if b.Kind == BlockContext && len(head) == 0 && len(pieces) > 0 && !hasContext(pieces[len(pieces)-1].blocks) {
				last := &pieces[len(pieces)-1]
				last.blocks = append(last.blocks, b)
				continue
			}
			pieces = append(pieces, piece{
				blocks:      append(append([]Block(nil), head...), b),
				u:           u,
				first:       first,
				startsCat:   (first && u.startsCat) || headCat,
				startsImage: (first && u.startsImage) || headImg,
			})
			head, headCat, headImg = nil, false, false
			first = false
		}
	}
	if len(head) > 0 {
		if len(pieces) > 0 {
			last := &pieces[len(pieces)-1]
			last.blocks = append(last.blocks, head...)
		} else {
			pieces = append(pieces, piece{blocks: head, u: ch[len(ch)-1], first: true, startsCat: headCat, startsImage: headImg})
		}
	}
	return pieces
}

// splitUnits packs units into messages. It returns nil for no units.
func splitUnits(units []unit, spec splitSpec) []SlackMessage {
	if len(units) == 0 {
		return nil
	}
	// Chunks: a run of sticky units plus the unit that closes it; a note
	// unit joins the chunk before it.
	var chunks [][]unit
	var run []unit
	totalBlocks := 0
	for _, u := range units {
		totalBlocks += len(u.blocks)
		if u.attach && len(run) == 0 && len(chunks) > 0 {
			chunks[len(chunks)-1] = append(chunks[len(chunks)-1], u)
			continue
		}
		run = append(run, u)
		if !u.sticky {
			chunks = append(chunks, run)
			run = nil
		}
	}
	if len(run) > 0 {
		chunks = append(chunks, run)
	}

	// Every message holds at least one block, so the block count bounds the
	// message count; the continuation numbering is reserved at the widest
	// number that bound allows.
	wide := digitsMax(totalBlocks + 1)

	var footerTexts []string
	footerBlocks, footerUnits := 0, 0
	if spec.footer != "" {
		footerTexts = packLines([]string{spec.footer}, spec.lim.MaxTextUnits)
		footerBlocks = 1 + len(footerTexts)
		for _, t := range footerTexts {
			footerUnits += utf16Len(t)
		}
		// A footer that would take over the first message is dropped: the
		// body and its heading come first.
		if footerBlocks > spec.lim.MaxBlocks/2 || footerUnits > spec.lim.MaxMessageUnits/2 {
			footerTexts, footerBlocks, footerUnits = nil, 0, 0
		}
	}

	var msgs []*pendingMsg
	var ctx unit // context in effect after everything packed so far

	// newMsg starts a message whose first content is first, with before the
	// category and image in effect ahead of it.
	newMsg := func(first, before unit, contTitle string) *pendingMsg {
		m := &pendingMsg{}
		if len(msgs) == 0 {
			return m
		}
		// The message continues the category (and image) in effect only if
		// its first unit belongs to it: a unit outside any category, or one
		// that opens a new category or image, needs no repeated heading.
		inCat := before.cat != "" && first.cat != "" && !first.startsCat
		m.head = heading{
			present:   true,
			showCat:   inCat,
			showImage: inCat && !first.startsImage && before.image != "" && first.image != "",
			cat:       before.cat,
			image:     before.image,
			contTitle: contTitle,
		}
		m.info.contCat = m.head.showCat
		if m.head.showCat {
			m.info.catShort = before.catShort
		}
		if !m.head.showCat && !m.head.showImage && spec.lead == nil && contTitle == "" {
			m.head.present = false
		}
		// The heading must leave room for content: drop its parts, least
		// essential first, until it takes at most half a message.
		hb := spec.renderHeading(m.head, wide, wide)
		for (blocksUnits(hb) > spec.lim.MaxMessageUnits/2 || len(hb) > spec.lim.MaxBlocks/2) &&
			(m.head.contTitle != "" || m.head.showImage || m.head.showCat) {
			switch {
			case m.head.contTitle != "":
				m.head.contTitle = ""
			case m.head.showImage:
				m.head.showImage = false
			default:
				m.head.showCat = false
			}
			hb = spec.renderHeading(m.head, wide, wide)
		}
		m.headBlock, m.headUnits = len(hb), blocksUnits(hb)
		return m
	}
	fits := func(m *pendingMsg, idx, nb, nu int) bool {
		maxB, maxU := spec.lim.MaxBlocks, spec.lim.MaxMessageUnits
		if idx == 0 {
			maxB, maxU = maxB-footerBlocks, maxU-footerUnits
		}
		return m.headBlock+len(m.body)+nb <= maxB && m.headUnits+m.bodyUnits+nu <= maxU
	}
	// note records what a message holds, for its fallback text: the first
	// category named, and every package and image it carries.
	note := func(m *pendingMsg, us []unit) {
		for _, u := range us {
			if m.info.catShort == "" {
				m.info.catShort = u.catShort
			}
			m.info.pkgs += u.pkgs
			// Images and packages are counted over the whole message; a
			// package is a package card rendered in it.
			if u.imageName != "" {
				seen := false
				for _, im := range m.images {
					seen = seen || im == u.imageName
				}
				if !seen {
					m.images = append(m.images, u.imageName)
				}
			}
		}
		if len(m.images) > 0 {
			m.info.firstImage = m.images[0]
			m.info.images = len(m.images)
		}
	}
	place := func(m *pendingMsg, blocks []Block) {
		// With no heading ahead of it, a message does not open on a divider.
		if len(m.body) == 0 && !m.head.present && len(blocks) > 0 && blocks[0].Kind == BlockDivider {
			blocks = blocks[1:]
		}
		m.body = append(m.body, blocks...)
		m.bodyUnits += blocksUnits(blocks)
	}

	cur := newMsg(chunks[0][0], unit{}, "")
	for _, ch := range chunks {
		var blocks []Block
		for _, u := range ch {
			blocks = append(blocks, u.blocks...)
		}
		nb, nu := len(blocks), blocksUnits(blocks)
		last := ch[len(ch)-1]
		if len(cur.body) > 0 && !fits(cur, len(msgs), nb, nu) {
			msgs = append(msgs, cur)
			cur = newMsg(ch[0], ctx, "")
		}
		if fits(cur, len(msgs), nb, nu) {
			place(cur, blocks)
			note(cur, ch)
			cur.lastTail = last.tail
			ctx = last
			continue
		}
		// The chunk alone is larger than a message: cut it between its
		// blocks and head each continuation with the card's name. The
		// fallback details are recorded per fragment.
		var pieces []piece
		for _, p := range cutPieces(ch) {
			// A piece that cannot fit a message of its own is cut into single
			// blocks, giving up the gluing, so no message exceeds a limit.
			if len(p.blocks) > spec.lim.MaxBlocks/2 || blocksUnits(p.blocks) > spec.lim.MaxMessageUnits/2 {
				for i, b := range p.blocks {
					if b.Kind == BlockDivider {
						continue
					}
					q := p
					q.blocks = []Block{b}
					q.first = p.first && i == 0
					pieces = append(pieces, q)
				}
				continue
			}
			pieces = append(pieces, p)
		}
		for _, p := range pieces {
			if len(cur.body) > 0 && !fits(cur, len(msgs), len(p.blocks), blocksUnits(p.blocks)) {
				msgs = append(msgs, cur)
				title := ""
				switch {
				case startsWithContext(p.blocks) && p.u.noteHead != "":
					// Partway through a long note: say what the list is.
					title = p.u.noteHead + spec.cont
				case !p.first:
					title = p.u.contTitle
				}
				first := unit{cat: p.u.cat, image: p.u.image, startsCat: p.startsCat, startsImage: p.startsImage}
				cur = newMsg(first, p.u, title)
			}
			place(cur, p.blocks)
			pu := p.u
			if !p.first {
				pu.pkgs = 0
			}
			note(cur, []unit{pu})
			cur.lastTail = p.u.tail
		}
		ctx = last
	}
	msgs = append(msgs, cur)

	out := make([]SlackMessage, len(msgs))
	total := len(msgs)
	for i, m := range msgs {
		blocks := append(spec.renderHeading(m.head, i+1, total), m.body...)
		if i == 0 && len(footerTexts) > 0 {
			if !(spec.footerJoinsTail && m.lastTail) {
				blocks = append(blocks, dividerBlock)
			}
			for _, t := range footerTexts {
				blocks = append(blocks, contextBlock(t))
			}
		}
		info := m.info
		info.n, info.total = i+1, total
		text := spec.fallback(info)
		out[i] = SlackMessage{Text: truncateUnits(text, spec.lim.MaxFallbackUnits), Blocks: blocks}
	}
	return out
}
