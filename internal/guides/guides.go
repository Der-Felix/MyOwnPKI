// Package guides is the content of the Help guides in the web UI (docs/PHASE3.md
// section 17, decisions 8, 9, 12 and 13): short texts that are written in a
// small, closed subset of Markdown, embedded in the binary and parsed into
// typed blocks. Text is never HTML. Raw HTML, an image, a script link or any
// construct outside the subset is a parse error, so what can ever reach a page
// is decided by this package and not by a sanitizer. The package uses the
// standard library only and runs no code from a guide.
//
// A guide is a file content/<slug>.md: a front matter between two lines of
// three dashes, then the body.
//
//	---
//	title: Connect certbot
//	summary: One sentence for the list of guides.
//	audience: Admins who run certbot on a host
//	order: 30
//	site: /guides/certbot/
//	sources:
//	  - internal/web/app_acme.go
//	---
//
// The body knows headings (## and ###), paragraphs, lists (- and 1.), fenced
// code blocks with a language, tables, notes (> **Note:** and > **Warning:**)
// and the inline forms **bold**, *italic*, `code` and [text](link). Links lead
// to a page of the UI (a path), to another guide (/guides/<slug>), to a heading
// of the same guide (#id) or to the documentation site and the repository of
// the project (the constants SiteBase and RepoBase). Code blocks and code
// spans may contain the placeholders {acme_directory} and {ca_name}; they are
// replaced after parsing by [Guide.Resolve], from configuration and engine
// data only.
package guides

import (
	"fmt"
	"regexp"
	"slices"
	"sort"
)

// Limits (docs/PHASE3.md step 71).
const (
	MaxFileBytes = 32 << 10 // one guide file
	MaxBlocks    = 200      // blocks of one guide
	MaxGuides    = 8        // guides in one registry
)

// The only external addresses a guide may link to (decision 13). No trailing
// slash; a link is the constant itself or the constant followed by a slash and
// a path.
const (
	SiteBase = "https://der-felix.github.io/MyOwnPKI"
	RepoBase = "https://github.com/Der-Felix/MyOwnPKI"
)

// Kind is the type of a [Block].
type Kind int

// The kinds of block.
const (
	KindHeading Kind = iota + 1
	KindParagraph
	KindList
	KindCode
	KindTable
	KindNote
)

// Block is one block of a guide. Which fields are set depends on Kind:
//
//	KindHeading    Level (2 or 3), ID, Text (one plain text inline)
//	KindParagraph  Text
//	KindList       Ordered, Items
//	KindCode       Lang, Code
//	KindTable      Header, Rows
//	KindNote       Warning, Text
//
// Every string is text: a page must escape it, never insert it as HTML.
type Block struct {
	Kind    Kind
	Level   int
	ID      string
	Text    []Inline
	Ordered bool
	Items   [][]Inline
	Lang    string
	Code    string
	Header  [][]Inline
	Rows    [][][]Inline
	Warning bool
}

// InlineKind is the type of an [Inline].
type InlineKind int

// The kinds of inline text.
const (
	InlineText InlineKind = iota + 1
	InlineBold
	InlineItalic
	InlineCode
	InlineLink
)

// LinkTarget says where a link leads.
type LinkTarget int

// The kinds of link target.
const (
	LinkAnchor LinkTarget = iota + 1 // a heading of the same guide; Href is the heading ID
	LinkUI                           // a path of the admin UI, with an optional query and fragment
	LinkGuide                        // another guide: /guides/<slug>, with an optional fragment
	LinkSite                         // the documentation site or the repository (SiteBase, RepoBase)
)

// Inline is a piece of text inside a block. Link has the link text in Text and
// the checked destination in Href.
type Inline struct {
	Kind   InlineKind
	Text   string
	Href   string
	Target LinkTarget
}

// Guide is one parsed guide. It is read-only once built.
type Guide struct {
	Slug     string
	Title    string
	Summary  string
	Audience string // who it is for, one short phrase
	Order    int    // the position in the list, small first
	Site     string // the permalink of the longer page on the documentation site, "" = none
	Sources  []string
	Blocks   []Block
}

// SiteURL is the address of the longer page, or "".
func (g *Guide) SiteURL() string {
	if g.Site == "" {
		return ""
	}
	return SiteBase + g.Site
}

// Link is one link of a guide as [Guide.Links] lists it.
type Link struct {
	Target LinkTarget
	Href   string
	Text   string
}

// Links lists every link in the body, in reading order.
func (g *Guide) Links() []Link {
	var out []Link
	add := func(in []Inline) {
		for _, i := range in {
			if i.Kind == InlineLink {
				out = append(out, Link{Target: i.Target, Href: i.Href, Text: i.Text})
			}
		}
	}
	for _, b := range g.Blocks {
		add(b.Text)
		for _, item := range b.Items {
			add(item)
		}
		for _, cell := range b.Header {
			add(cell)
		}
		for _, row := range b.Rows {
			for _, cell := range row {
				add(cell)
			}
		}
	}
	return out
}

// Headings returns the level 2 headings, for a table of contents.
func (g *Guide) Headings() []Block {
	var out []Block
	for _, b := range g.Blocks {
		if b.Kind == KindHeading && b.Level == 2 {
			out = append(out, b)
		}
	}
	return out
}

// Placeholders are the only names a code block or code span may use, with the
// example that stays visible while the instance has no value. The examples are
// documentation names, never real addresses.
var placeholderExamples = map[string]string{
	"acme_directory": "https://pki.homelab.lan/acme/directory",
	"ca_name":        "homelab-issuing",
}

// PlaceholderNames lists the closed set of placeholders.
func PlaceholderNames() []string {
	names := make([]string, 0, len(placeholderExamples))
	for n := range placeholderExamples {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

var (
	slugPattern        = regexp.MustCompile(`^[a-z0-9-]{1,40}$`)
	placeholderPattern = regexp.MustCompile(`\{[a-z][a-z0-9_]*\}`)
)

// ValidSlug reports whether s can name a guide.
func ValidSlug(s string) bool { return slugPattern.MatchString(s) }

// Values are what the placeholders turn into. They come from configuration and
// engine data, never from the request; an empty or unusual value leaves the
// visible example in place, because the text ends up in a command a person
// pastes into a shell.
type Values struct {
	ACMEDirectory string // the ACME directory URL clients use
	CAName        string // the name of a CA of this instance
}

// Resolve returns a copy of g with the placeholders replaced. A value that is
// empty or contains anything beyond letters, digits and . _ - : / (a name or a
// plain URL) is replaced by its example.
func (g *Guide) Resolve(v Values) *Guide {
	repl := map[string]string{
		"{acme_directory}": safeValue(v.ACMEDirectory, true, "acme_directory"),
		"{ca_name}":        safeValue(v.CAName, false, "ca_name"),
	}
	out := *g
	out.Blocks = make([]Block, len(g.Blocks))
	for i, b := range g.Blocks {
		switch b.Kind {
		case KindCode:
			b.Code = replacePlaceholders(b.Code, repl)
		case KindParagraph, KindNote:
			b.Text = replaceInlines(b.Text, repl)
		case KindList:
			items := make([][]Inline, len(b.Items))
			for j, item := range b.Items {
				items[j] = replaceInlines(item, repl)
			}
			b.Items = items
		case KindTable:
			b.Header = replaceCells(b.Header, repl)
			rows := make([][][]Inline, len(b.Rows))
			for j, row := range b.Rows {
				rows[j] = replaceCells(row, repl)
			}
			b.Rows = rows
		case KindHeading:
		}
		out.Blocks[i] = b
	}
	return &out
}

func replaceCells(cells [][]Inline, repl map[string]string) [][]Inline {
	out := make([][]Inline, len(cells))
	for i, c := range cells {
		out[i] = replaceInlines(c, repl)
	}
	return out
}

func replaceInlines(in []Inline, repl map[string]string) []Inline {
	out := slices.Clone(in)
	for i := range out {
		if out[i].Kind == InlineCode {
			out[i].Text = replacePlaceholders(out[i].Text, repl)
		}
	}
	return out
}

func replacePlaceholders(s string, repl map[string]string) string {
	return placeholderPattern.ReplaceAllStringFunc(s, func(m string) string {
		if r, ok := repl[m]; ok {
			return r
		}
		return m
	})
}

var (
	nameValue = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)
	urlValue  = regexp.MustCompile(`^https?://[A-Za-z0-9][A-Za-z0-9._:/-]{0,190}$`)
)

func safeValue(value string, isURL bool, name string) string {
	re := nameValue
	if isURL {
		re = urlValue
	}
	if re.MatchString(value) {
		return value
	}
	return placeholderExamples[name]
}

// ParseError says where a guide is wrong.
type ParseError struct {
	Slug string
	Line int // 1-based; 0 = the file as a whole
	Msg  string
}

func (e *ParseError) Error() string {
	if e.Line == 0 {
		return fmt.Sprintf("guide %s: %s", e.Slug, e.Msg)
	}
	return fmt.Sprintf("guide %s: line %d: %s", e.Slug, e.Line, e.Msg)
}
