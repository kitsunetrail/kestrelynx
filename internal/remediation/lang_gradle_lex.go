package remediation

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// The scripts of a Gradle build (build.gradle, build.gradle.kts and the
// settings files) are code. They are not run or evaluated here: this file
// cuts them into tokens and top-level statements so that the recognizer in
// lang_gradle_script.go can compare each statement with the forms it accepts.
// Anything the lexer does not understand is an error, not a guess.

type gradleTokKind int

const (
	gtIdent gradleTokKind = iota
	gtString
	gtNumber
	gtPunct
)

// gradleTok is one token of a script. text is the name of an identifier, the
// content of a string (without quotes), the digits of a number or the one
// character of a punctuation mark.
type gradleTok struct {
	kind gradleTokKind
	text string
	line int
	// nl: a line break lies between the previous token and this one.
	nl bool
	// quoted: an identifier written in backticks.
	quoted bool
	// start and end are the byte offsets of the token in the script without
	// its byte order mark; a string includes its quotes.
	start, end int
}

func (t gradleTok) isPunct(p string) bool { return t.kind == gtPunct && t.text == p }

// plainIdent reports an identifier that is not written in backticks.
func (t gradleTok) plainIdent(name string) bool {
	return t.kind == gtIdent && !t.quoted && t.text == name
}

// gradleSyntaxError is a script the lexer or the statement reader cannot read.
type gradleSyntaxError struct {
	line int
	msg  string
}

func (e *gradleSyntaxError) Error() string { return fmt.Sprintf("line %d: %s", e.line, e.msg) }

// maxGradleTokens bounds the work done for one script.
const maxGradleTokens = 200000

// lexGradle cuts a script into tokens. Comments are dropped. A string must be
// on one line, hold no "$" (a template or interpolation in either language)
// and no backslash, and be quoted as the language quotes a string: either
// quote in Groovy, double quotes in Kotlin. Triple-quoted strings are refused.
func lexGradle(src []byte, kotlin bool) ([]gradleTok, error) {
	if !utf8.Valid(src) {
		return nil, &gradleSyntaxError{1, "not valid UTF-8"}
	}
	s := strings.TrimPrefix(string(src), "\xef\xbb\xbf")
	if loneCR(s) {
		return nil, &gradleSyntaxError{1, "a carriage return that does not end a CRLF line break"}
	}
	var toks []gradleTok
	line, nl := 1, false
	i := 0
	add := func(t gradleTok) error {
		if len(toks) >= maxGradleTokens {
			return &gradleSyntaxError{line, "too many tokens"}
		}
		t.nl = nl
		t.start = i
		toks = append(toks, t)
		nl = false
		return nil
	}
	// closed is how many tokens have their end set: a token ends where the
	// pass that read it left off.
	closed := 0
	for i < len(s) {
		if closed < len(toks) {
			toks[len(toks)-1].end = i
			closed = len(toks)
		}
		c := s[i]
		switch {
		case c == '\n':
			line++
			nl = true
			i++
		case c == ' ' || c == '\t' || c == '\r' || c == '\f':
			i++
		case c == '/' && i+1 < len(s) && s[i+1] == '/':
			for i < len(s) && s[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < len(s) && s[i+1] == '*':
			// Kotlin block comments nest; Groovy's do not.
			j, depth := i+2, 1
			for j < len(s) && depth > 0 {
				switch {
				case strings.HasPrefix(s[j:], "*/"):
					depth--
					j += 2
				case kotlin && strings.HasPrefix(s[j:], "/*"):
					depth++
					j += 2
				default:
					j++
				}
			}
			if depth > 0 {
				return nil, &gradleSyntaxError{line, "a comment is not closed"}
			}
			if n := strings.Count(s[i:j], "\n"); n > 0 {
				line += n
				nl = true
			}
			i = j
		case c == '"' || c == '\'':
			if c == '\'' && kotlin {
				return nil, &gradleSyntaxError{line, "a single-quoted literal in a Kotlin script"}
			}
			if strings.HasPrefix(s[i:], string([]byte{c, c, c})) {
				return nil, &gradleSyntaxError{line, "a triple-quoted string"}
			}
			j := i + 1
			for j < len(s) && s[j] != c {
				switch s[j] {
				case '\n', '\r':
					return nil, &gradleSyntaxError{line, "a string runs over the end of the line"}
				case '$':
					return nil, &gradleSyntaxError{line, "a string with $, which interpolates"}
				case '\\':
					return nil, &gradleSyntaxError{line, "a string with an escape"}
				}
				j++
			}
			if j >= len(s) {
				return nil, &gradleSyntaxError{line, "a string is not closed"}
			}
			if err := add(gradleTok{kind: gtString, text: s[i+1 : j], line: line}); err != nil {
				return nil, err
			}
			i = j + 1
		case c == '`':
			j := strings.IndexByte(s[i+1:], '`')
			if j < 0 || strings.ContainsAny(s[i+1:i+1+j], "\n$\\") || j == 0 {
				return nil, &gradleSyntaxError{line, "a backtick name is not valid"}
			}
			if err := add(gradleTok{kind: gtIdent, text: s[i+1 : i+1+j], line: line, quoted: true}); err != nil {
				return nil, err
			}
			i += j + 2
		case isIdentStart(c):
			j := i + 1
			for j < len(s) && (isIdentStart(s[j]) || s[j] >= '0' && s[j] <= '9') {
				j++
			}
			if err := add(gradleTok{kind: gtIdent, text: s[i:j], line: line}); err != nil {
				return nil, err
			}
			i = j
		case c >= '0' && c <= '9':
			j := i + 1
			for j < len(s) && (s[j] >= '0' && s[j] <= '9' || s[j] == '_') {
				j++
			}
			if err := add(gradleTok{kind: gtNumber, text: s[i:j], line: line}); err != nil {
				return nil, err
			}
			i = j
		case strings.IndexByte("(){}[];,=.<>:+-*/!?@&|~^%#", c) >= 0:
			if err := add(gradleTok{kind: gtPunct, text: string(c), line: line}); err != nil {
				return nil, err
			}
			i++
		default:
			return nil, &gradleSyntaxError{line, fmt.Sprintf("the character %q is not handled", rune(c))}
		}
	}
	if closed < len(toks) {
		toks[len(toks)-1].end = i
	}
	return toks, nil
}

// loneCR reports a carriage return not followed by a line feed. Some readers
// end a line comment at one and others do not, so a script holding one is
// not read.
func loneCR(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '\r' && (i+1 >= len(s) || s[i+1] != '\n') {
			return true
		}
	}
	return false
}

func isIdentStart(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// gradleStmt is one statement of a script: the tokens before its block, and
// the statements inside the block when it has one.
type gradleStmt struct {
	head     []gradleTok
	block    []gradleStmt
	hasBlock bool
	line     int
}

// maxGradleDepth bounds how deep blocks may nest.
const maxGradleDepth = 8

// readGradleStmts reads tokens into statements. A statement ends at a line
// break outside parentheses and brackets, at ";", at "}" of its block, or
// after its own "{...}" block.
func readGradleStmts(toks []gradleTok) ([]gradleStmt, error) {
	stmts, i, err := readGradleBlock(toks, 0, 0)
	if err != nil {
		return nil, err
	}
	if i < len(toks) {
		return nil, &gradleSyntaxError{toks[i].line, "a closing brace has no opening brace"}
	}
	return stmts, nil
}

// readGradleBlock reads the statements from toks[i:] up to a "}" at its own
// level (not consumed) or the end, and returns where it stopped.
func readGradleBlock(toks []gradleTok, i, depth int) ([]gradleStmt, int, error) {
	if depth > maxGradleDepth {
		return nil, i, &gradleSyntaxError{toks[i-1].line, "blocks nest too deep"}
	}
	var out []gradleStmt
	for i < len(toks) {
		t := toks[i]
		if t.isPunct(";") {
			i++
			continue
		}
		if t.isPunct("}") {
			return out, i, nil
		}
		st := gradleStmt{line: t.line}
		var open []string // the parentheses, brackets and braces still open in the head
	head:
		for i < len(toks) {
			t = toks[i]
			if len(open) == 0 {
				switch {
				case len(st.head) > 0 && t.nl, t.isPunct(";"), t.isPunct("}"):
					break head
				case t.isPunct("{"):
					block, j, err := readGradleBlock(toks, i+1, depth+1)
					if err != nil {
						return nil, j, err
					}
					if j >= len(toks) {
						return nil, j, &gradleSyntaxError{t.line, "a block is not closed"}
					}
					st.block, st.hasBlock = block, true
					i = j + 1
					break head
				}
			}
			switch {
			case t.kind != gtPunct:
			case t.text == "(" || t.text == "[" || t.text == "{":
				open = append(open, t.text)
			case t.text == ")" || t.text == "]" || t.text == "}":
				want := map[string]string{")": "(", "]": "[", "}": "{"}[t.text]
				if len(open) == 0 || open[len(open)-1] != want {
					return nil, i, &gradleSyntaxError{t.line, fmt.Sprintf("%q does not match what is open", t.text)}
				}
				open = open[:len(open)-1]
			}
			st.head = append(st.head, t)
			i++
		}
		if len(open) > 0 {
			return nil, i, &gradleSyntaxError{st.line, "a parenthesis or bracket is not closed"}
		}
		if len(st.head) == 0 {
			return nil, i, &gradleSyntaxError{st.line, "a block with no statement before it"}
		}
		out = append(out, st)
	}
	return out, i, nil
}

// text is the statement as source, shortened, for a message.
func (s gradleStmt) text() string {
	var b strings.Builder
	for i, t := range s.head {
		if i > 0 && t.kind != gtPunct && s.head[i-1].kind != gtPunct {
			b.WriteByte(' ')
		}
		switch {
		case t.kind == gtString:
			b.WriteString(`"` + t.text + `"`)
		case t.quoted:
			b.WriteString("`" + t.text + "`")
		case t.kind == gtPunct && t.text == "=":
			b.WriteString(" = ")
		default:
			b.WriteString(t.text)
		}
	}
	if s.hasBlock {
		b.WriteString(" { ... }")
	}
	out := b.String()
	if len(out) > 120 {
		out = out[:120] + "..."
	}
	return out
}
