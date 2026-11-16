package guides

import (
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// codeLanguages are the languages a fenced block may name. The page shows the
// text as is; the language only labels it.
var codeLanguages = map[string]bool{"bash": true, "powershell": true, "yaml": true, "json": true, "ini": true, "text": true}

var (
	orderedMarker = regexp.MustCompile(`^\d{1,3}\. `)
	headingID     = regexp.MustCompile(`^[a-z0-9-]{1,60}$`)
	sitePath      = regexp.MustCompile(`^/[a-z0-9/_-]*$`)
	sourcePath    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]*$`)
	separatorCell = regexp.MustCompile(`^:?-{3,}:?$`)
	entityLike    = regexp.MustCompile(`^&(#\d+|#x[0-9a-fA-F]+|[A-Za-z][A-Za-z0-9]*);`)
	linkChars     = regexp.MustCompile(`^[A-Za-z0-9._~/:#?=&-]+$`)
	uiPath        = regexp.MustCompile(`^/[A-Za-z0-9._~/-]*(\?[A-Za-z0-9._~=&-]*)?(#[a-z0-9-]+)?$`)
)

// isZeroWidth reports the invisible characters that would hide text inside a
// command a reader copies: zero-width space, non-joiner, joiner and word
// joiner (the byte order mark U+FEFF is refused with the controls).
func isZeroWidth(r rune) bool {
	return r == 0x200B || r == 0x200C || r == 0x200D || r == 0x2060
}

// parser carries the state of one file.
type parser struct {
	slug    string
	lines   []string // the body
	offset  int      // lines before the body, for error positions
	ids     map[string]bool
	anchors []anchorRef
	blocks  []Block
}

type anchorRef struct {
	id   string
	line int
}

func (p *parser) errf(i int, msg string) error {
	return &ParseError{Slug: p.slug, Line: p.offset + i + 1, Msg: msg}
}

// Parse reads one guide file. slug names it; src is the whole file.
func Parse(slug string, src []byte) (*Guide, error) {
	fail := func(msg string) (*Guide, error) { return nil, &ParseError{Slug: slug, Msg: msg} }
	if !ValidSlug(slug) {
		return fail("the slug may use only a-z, 0-9 and - (at most 40 characters)")
	}
	if len(src) > MaxFileBytes {
		return fail("the file is larger than " + strconv.Itoa(MaxFileBytes>>10) + " KiB")
	}
	if !utf8.Valid(src) {
		return fail("the file is not valid UTF-8")
	}
	text := strings.ReplaceAll(string(src), "\r\n", "\n")
	for i, r := range text {
		if r == '\r' || r == 0xFEFF || (r < 0x20 && r != '\n' && r != '\t') || r == 0x7f || unicode.Is(unicode.Bidi_Control, r) || isZeroWidth(r) {
			return nil, &ParseError{Slug: slug, Line: 1 + strings.Count(text[:i], "\n"), Msg: "a control, byte order mark, zero-width or bidirectional character is not allowed"}
		}
	}
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	g := &Guide{Slug: slug, Order: 100}
	end, err := parseFrontMatter(g, lines)
	if err != nil {
		return nil, err
	}
	p := &parser{slug: slug, lines: lines[end:], offset: end, ids: map[string]bool{}}
	if err := p.parseBody(); err != nil {
		return nil, err
	}
	if len(p.blocks) == 0 {
		return fail("the guide has no body")
	}
	if len(p.blocks) > MaxBlocks {
		return fail("more than " + strconv.Itoa(MaxBlocks) + " blocks")
	}
	for _, a := range p.anchors {
		if !p.ids[a.id] {
			return nil, p.errf(a.line, "the link #"+a.id+" does not name a heading of this guide")
		}
	}
	g.Blocks = p.blocks
	return g, nil
}

// parseFrontMatter fills g from the lines between the first two "---" lines
// and returns the index of the first body line.
func parseFrontMatter(g *Guide, lines []string) (int, error) {
	fm := func(i int, msg string) error { return &ParseError{Slug: g.Slug, Line: i + 1, Msg: msg} }
	if len(lines) == 0 || lines[0] != "---" {
		return 0, &ParseError{Slug: g.Slug, Line: 1, Msg: "the file starts with a front matter between two lines of three dashes"}
	}
	seen := map[string]bool{}
	inSources := false
	for i := 1; i < len(lines); i++ {
		line := lines[i]
		switch {
		case line == "---":
			if g.Title == "" || g.Summary == "" || g.Audience == "" {
				return 0, fm(i, "title, summary and audience are required")
			}
			return i + 1, nil
		case strings.HasPrefix(line, "  - ") && inSources:
			v := strings.TrimSpace(line[4:])
			if !sourcePath.MatchString(v) || strings.Contains(v, "..") || strings.Contains(v, "//") {
				return 0, fm(i, "a source is a repository path such as internal/web/app.go")
			}
			g.Sources = append(g.Sources, v)
		case strings.TrimSpace(line) == "":
			return 0, fm(i, "no blank line inside the front matter")
		default:
			inSources = false
			key, value, ok := strings.Cut(line, ":")
			if !ok || key != strings.TrimSpace(key) || strings.HasPrefix(line, " ") {
				return 0, fm(i, "a front matter line is key: value")
			}
			if seen[key] {
				return 0, fm(i, "the key "+key+" appears twice")
			}
			seen[key] = true
			value = strings.TrimSpace(value)
			if len(value) >= 2 && strings.HasPrefix(value, `"`) && strings.HasSuffix(value, `"`) {
				value = value[1 : len(value)-1]
			}
			if err := setFrontMatter(g, key, value, &inSources); err != nil {
				return 0, fm(i, err.Error())
			}
		}
	}
	return 0, &ParseError{Slug: g.Slug, Msg: "the front matter is not closed by a line of three dashes"}
}

type frontMatterError string

func (e frontMatterError) Error() string { return string(e) }

func setFrontMatter(g *Guide, key, value string, inSources *bool) error {
	short := func(limit int) error {
		if value == "" || utf8.RuneCountInString(value) > limit || strings.ContainsAny(value, "\t<>`") {
			return frontMatterError(key + " is one line of 1 to " + strconv.Itoa(limit) + " characters without < > or backticks")
		}
		return nil
	}
	switch key {
	case "title":
		g.Title = value
		return short(80)
	case "summary":
		g.Summary = value
		return short(240)
	case "audience":
		g.Audience = value
		return short(80)
	case "order":
		n, err := strconv.Atoi(value)
		if err != nil || n < 0 || n > 1000 {
			return frontMatterError("order is a number from 0 to 1000")
		}
		g.Order = n
	case "site":
		if !sitePath.MatchString(value) || !strings.HasSuffix(value, "/") || strings.Contains(value, "//") {
			return frontMatterError("site is the permalink of the longer page, such as /guides/certbot/")
		}
		g.Site = value
	case "sources":
		if value != "" {
			return frontMatterError("sources is a list: one \"  - path\" line per file")
		}
		*inSources = true
	default:
		return frontMatterError("unknown front matter key " + key)
	}
	return nil
}

func (p *parser) add(b Block) { p.blocks = append(p.blocks, b) }

// parseBody reads the blocks.
func (p *parser) parseBody() error {
	for i := 0; i < len(p.lines); {
		line := p.lines[i]
		var next int
		var err error
		switch {
		case strings.TrimSpace(line) == "":
			i++
			continue
		case strings.HasPrefix(line, "```"):
			next, err = p.parseCode(i)
		case strings.HasPrefix(line, "## "), strings.HasPrefix(line, "### "):
			next, err = i+1, p.parseHeading(i)
		case strings.HasPrefix(line, "#"):
			return p.errf(i, "headings are ## and ###; the page title is the h1")
		case strings.HasPrefix(line, ">"):
			next, err = p.parseNote(i)
		case strings.HasPrefix(line, "- "):
			next, err = p.parseList(i, false)
		case orderedMarker.MatchString(line):
			next, err = p.parseList(i, true)
		case strings.HasPrefix(line, "|"):
			next, err = p.parseTable(i)
		case strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t"):
			return p.errf(i, "a line does not start with a space (no indented blocks, no nested lists)")
		case strings.HasPrefix(line, "* ") || strings.HasPrefix(line, "+ "):
			return p.errf(i, "a list item starts with \"- \"")
		default:
			next, err = p.parseParagraph(i)
		}
		if err != nil {
			return err
		}
		i = next
	}
	return nil
}

func (p *parser) inlines(i int, s string) ([]Inline, error) {
	out, err := parseInlines(s, p.slug, p.offset+i+1)
	if err != nil {
		return nil, err
	}
	for _, in := range out {
		if in.Kind == InlineLink && in.Target == LinkAnchor {
			p.anchors = append(p.anchors, anchorRef{id: in.Href, line: i})
		}
	}
	return out, nil
}

// startsBlock reports whether a line would begin a block of its own. Such a
// line directly under a paragraph or a note is refused: a block starts after a
// blank line, so no reader has to guess what the author meant.
func startsBlock(line string) bool {
	for _, prefix := range []string{"```", "#", ">", "- ", "|", "* ", "+ "} {
		if strings.HasPrefix(line, prefix) {
			return true
		}
	}
	return orderedMarker.MatchString(line)
}

func (p *parser) parseParagraph(i int) (int, error) {
	var parts []string
	j := i
	for ; j < len(p.lines) && strings.TrimSpace(p.lines[j]) != ""; j++ {
		line := p.lines[j]
		if j > i && startsBlock(line) {
			return 0, p.errf(j, "a list, table, code block or heading starts after a blank line")
		}
		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			return 0, p.errf(j, "a line does not start with a space")
		}
		if strings.HasSuffix(line, " ") || strings.HasSuffix(line, "\t") {
			return 0, p.errf(j, "no trailing space (a line break inside a paragraph is not supported)")
		}
		parts = append(parts, line)
	}
	text, err := p.inlines(i, strings.Join(parts, " "))
	if err != nil {
		return 0, err
	}
	p.add(Block{Kind: KindParagraph, Text: text})
	return j, nil
}

func (p *parser) parseHeading(i int) error {
	line := p.lines[i]
	level := 2
	text := strings.TrimPrefix(line, "## ")
	if strings.HasPrefix(line, "### ") {
		level, text = 3, strings.TrimPrefix(line, "### ")
	}
	text = strings.TrimSpace(text)
	if text == "" || utf8.RuneCountInString(text) > 100 || strings.ContainsAny(text, "`*[]<>{}\\") {
		return p.errf(i, "a heading is 1 to 100 characters of plain text")
	}
	if level == 3 {
		seenTwo := false
		for _, b := range p.blocks {
			if b.Kind == KindHeading && b.Level == 2 {
				seenTwo = true
			}
		}
		if !seenTwo {
			return p.errf(i, "a ### heading needs a ## heading before it")
		}
	}
	id := slugify(text)
	if id == "" {
		return p.errf(i, "a heading needs letters or digits")
	}
	for n := 2; p.ids[id]; n++ {
		id = slugify(text) + "-" + strconv.Itoa(n)
	}
	if !headingID.MatchString(id) {
		return p.errf(i, "the heading is too long to make an anchor")
	}
	p.ids[id] = true
	p.add(Block{Kind: KindHeading, Level: level, ID: id, Text: []Inline{{Kind: InlineText, Text: text}}})
	return nil
}

// slugify makes a heading anchor: lower case letters and digits, runs of
// anything else become one dash.
func slugify(s string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			if dash && b.Len() > 0 {
				b.WriteByte('-')
			}
			dash = false
			b.WriteRune(r)
		} else {
			dash = true
		}
	}
	return b.String()
}

func (p *parser) parseCode(i int) (int, error) {
	lang := strings.TrimPrefix(p.lines[i], "```")
	if !codeLanguages[lang] {
		return 0, p.errf(i, "a code block names its language right after the three backticks: bash, powershell, yaml, json, ini or text")
	}
	var body []string
	for j := i + 1; j < len(p.lines); j++ {
		if p.lines[j] == "```" {
			if len(body) == 0 {
				return 0, p.errf(i, "the code block is empty")
			}
			code := strings.Join(body, "\n")
			if err := checkPlaceholders(code, p.slug, p.offset+i+1, true); err != nil {
				return 0, err
			}
			p.add(Block{Kind: KindCode, Lang: lang, Code: code})
			return j + 1, nil
		}
		body = append(body, p.lines[j])
	}
	return 0, p.errf(i, "the code block is not closed by a line of three backticks")
}

func (p *parser) parseNote(i int) (int, error) {
	const noteMarker, warningMarker = "> **Note:** ", "> **Warning:** "
	first := p.lines[i]
	warning := false
	var rest string
	switch {
	case strings.HasPrefix(first, noteMarker):
		rest = first[len(noteMarker):]
	case strings.HasPrefix(first, warningMarker):
		warning, rest = true, first[len(warningMarker):]
	default:
		return 0, p.errf(i, "a quote is a note: it starts with \"> **Note:** \" or \"> **Warning:** \"")
	}
	parts := []string{rest}
	j := i + 1
	for ; j < len(p.lines) && strings.HasPrefix(p.lines[j], ">"); j++ {
		cont, ok := strings.CutPrefix(p.lines[j], "> ")
		if !ok || strings.TrimSpace(cont) == "" {
			return 0, p.errf(j, "a note is one paragraph: continue it with \"> \" and text")
		}
		if strings.HasPrefix(cont, "**Note:**") || strings.HasPrefix(cont, "**Warning:**") {
			return 0, p.errf(j, "a new note starts after a blank line")
		}
		parts = append(parts, cont)
	}
	if strings.TrimSpace(rest) == "" {
		return 0, p.errf(i, "the note has no text")
	}
	text, err := p.inlines(i, strings.Join(parts, " "))
	if err != nil {
		return 0, err
	}
	p.add(Block{Kind: KindNote, Warning: warning, Text: text})
	return j, nil
}

func (p *parser) parseList(i int, ordered bool) (int, error) {
	isMarker := func(line string) bool {
		if ordered {
			return orderedMarker.MatchString(line)
		}
		return strings.HasPrefix(line, "- ")
	}
	var items []string
	j := i
	for ; j < len(p.lines) && strings.TrimSpace(p.lines[j]) != ""; j++ {
		line := p.lines[j]
		switch {
		case isMarker(line):
			if ordered {
				line = line[strings.Index(line, ". ")+2:]
			} else {
				line = line[2:]
			}
			if strings.TrimSpace(line) == "" {
				return 0, p.errf(j, "an empty list item")
			}
			items = append(items, strings.TrimSpace(line))
		case strings.HasPrefix(line, "  "):
			rest := strings.TrimSpace(line)
			if strings.HasPrefix(rest, "- ") || strings.HasPrefix(rest, "* ") || orderedMarker.MatchString(rest) {
				return 0, p.errf(j, "nested lists are not supported")
			}
			items[len(items)-1] += " " + rest
		default:
			return 0, p.errf(j, "a list item starts with its marker; a continuation line is indented by two spaces; anything else starts after a blank line")
		}
	}
	parsed := make([][]Inline, len(items))
	for n, item := range items {
		text, err := p.inlines(i, item)
		if err != nil {
			return 0, err
		}
		parsed[n] = text
	}
	p.add(Block{Kind: KindList, Ordered: ordered, Items: parsed})
	return j, nil
}

// splitRow splits "| a | b |" at the pipes that are not inside a code span.
func splitRow(line string) ([]string, bool) {
	line = strings.TrimSpace(line)
	if len(line) < 2 || line[0] != '|' || line[len(line)-1] != '|' {
		return nil, false
	}
	var cells []string
	var cur strings.Builder
	inCode := false
	for k := 1; k < len(line)-1; k++ {
		switch c := line[k]; {
		case c == '`':
			inCode = !inCode
			cur.WriteByte(c)
		case c == '|' && !inCode:
			cells = append(cells, strings.TrimSpace(cur.String()))
			cur.Reset()
		default:
			cur.WriteByte(c)
		}
	}
	return append(cells, strings.TrimSpace(cur.String())), !inCode
}

func (p *parser) parseTable(i int) (int, error) {
	j := i
	for ; j < len(p.lines) && strings.HasPrefix(p.lines[j], "|"); j++ {
	}
	if j-i < 2 {
		return 0, p.errf(i, "a table is a header row, a separator row of dashes and the rows")
	}
	head, ok := splitRow(p.lines[i])
	if !ok {
		return 0, p.errf(i, "a table row starts and ends with | and keeps a code span inside one cell")
	}
	sep, ok := splitRow(p.lines[i+1])
	if !ok || len(sep) != len(head) {
		return 0, p.errf(i+1, "the separator row has as many cells as the header")
	}
	for _, c := range sep {
		if !separatorCell.MatchString(c) {
			return 0, p.errf(i+1, "the separator row has cells of three or more dashes")
		}
	}
	b := Block{Kind: KindTable}
	for _, c := range head {
		if c == "" {
			return 0, p.errf(i, "a header cell is not empty")
		}
		cell, err := p.inlines(i, c)
		if err != nil {
			return 0, err
		}
		b.Header = append(b.Header, cell)
	}
	for k := i + 2; k < j; k++ {
		cells, ok := splitRow(p.lines[k])
		if !ok {
			return 0, p.errf(k, "a table row starts and ends with | and closes every code span")
		}
		if len(cells) != len(head) {
			return 0, p.errf(k, "a table row has as many cells as the header")
		}
		row := make([][]Inline, len(cells))
		for n, c := range cells {
			cell, err := p.inlines(k, c)
			if err != nil {
				return 0, err
			}
			row[n] = cell
		}
		b.Rows = append(b.Rows, row)
	}
	p.add(b)
	return j, nil
}
