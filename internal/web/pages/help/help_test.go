package help_test

import (
	"bytes"
	"context"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Der-Felix/MyOwnPKI/internal/guides"
	"github.com/Der-Felix/MyOwnPKI/internal/web/pages/help"
	"github.com/Der-Felix/MyOwnPKI/internal/web/view"
)

const payload = `<script>alert(1)</script><img src=x onerror=alert(2)>"'&`

func render(t *testing.T, c interface {
	Render(ctx context.Context, w io.Writer) error
}) string {
	t.Helper()
	var buf bytes.Buffer
	if err := c.Render(t.Context(), &buf); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

// hostileGuide has markup, quotes and a script in every field a block can
// hold. The parser would refuse most of it; a page must be safe regardless.
func hostileGuide() *guides.Guide {
	text := []guides.Inline{
		{Kind: guides.InlineText, Text: payload}, {Kind: guides.InlineBold, Text: payload}, {Kind: guides.InlineItalic, Text: payload},
		{Kind: guides.InlineCode, Text: payload},
		{Kind: guides.InlineLink, Text: payload, Href: "javascript:alert(1)", Target: guides.LinkUI},
		{Kind: guides.InlineLink, Text: payload, Href: `/x" onmouseover="alert(1)`, Target: guides.LinkUI},
		{Kind: guides.InlineLink, Text: payload, Href: "https://der-felix.github.io/MyOwnPKI/x", Target: guides.LinkSite},
	}
	return &guides.Guide{
		Slug: "x", Title: payload, Summary: payload, Audience: payload, Site: "/guides/x/",
		Blocks: []guides.Block{
			{Kind: guides.KindHeading, Level: 2, ID: "one", Text: []guides.Inline{{Kind: guides.InlineText, Text: payload}}},
			{Kind: guides.KindHeading, Level: 3, ID: "sub", Text: []guides.Inline{{Kind: guides.InlineText, Text: payload}}},
			{Kind: guides.KindParagraph, Text: text},
			{Kind: guides.KindList, Items: [][]guides.Inline{text}},
			{Kind: guides.KindList, Ordered: true, Items: [][]guides.Inline{text}},
			{Kind: guides.KindCode, Lang: "bash", Code: payload + "\n" + payload},
			{Kind: guides.KindTable, Header: [][]guides.Inline{text}, Rows: [][][]guides.Inline{{text}}},
			{Kind: guides.KindNote, Text: text},
			{Kind: guides.KindNote, Warning: true, Text: text},
			{Kind: guides.KindHeading, Level: 2, ID: "two", Text: []guides.Inline{{Kind: guides.InlineText, Text: "Two"}}},
		},
	}
}

// TestGuideEscapes: every string of a guide is text. Markup, quotes and script
// come out escaped, a link with a script or a broken-out attribute is made
// harmless by templ.SafeURL, and nothing is inline.
func TestGuideEscapes(t *testing.T) {
	t.Parallel()
	page := render(t, help.Guide(view.Page{Title: payload}, help.GuideData{Guide: hostileGuide()}))
	for _, bad := range []string{"<script", "<img src=x", "onerror=alert(2)>", "alert(1)</script>", `"'&`, `href="javascript:`, `onmouseover="alert(1)`, " style=", "<style"} {
		if strings.Contains(strings.ToLower(page), strings.ToLower(bad)) {
			t.Errorf("the page contains %q unescaped", bad)
		}
	}
	if !strings.Contains(page, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Error("the payload is missing: it should appear as escaped text")
	}
	if got := strings.Count(page, `rel="noopener noreferrer"`); got < 8 {
		t.Errorf("external links carry rel=noopener noreferrer %d times", got)
	}
}

// TestGuideStructure: headings, landmarks and focus order.
func TestGuideStructure(t *testing.T) {
	t.Parallel()
	page := render(t, help.Guide(view.Page{Title: "T"}, help.GuideData{Guide: hostileGuide()}))
	for _, want := range []string{
		`<nav class="section" aria-label="On this page">`, `href="#g-one"`, `href="#g-two"`,
		`<section class="section" aria-labelledby="g-one"><div class="section-head"><h2 id="g-one">`,
		`<h3 id="g-sub">`, `<ul>`, `<ol>`,
		`<pre class="pem" tabindex="0" role="region" aria-label="Shell commands"><code>`,
		`<th scope="col">`, `<span class="msg-label">Note:</span>`, `<span class="msg-label">Warning:</span>`, `role="note"`,
		`<section class="section" aria-labelledby="g-longer">`, `https://der-felix.github.io/MyOwnPKI/guides/x/`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the page lacks %q", want)
		}
	}
	// A single level 2 heading needs no contents list; a guide without a site
	// page has no "Longer version".
	g := hostileGuide()
	g.Site = ""
	g.Blocks = g.Blocks[:3]
	page = render(t, help.Guide(view.Page{Title: "T"}, help.GuideData{Guide: g}))
	if strings.Contains(page, "On this page") || strings.Contains(page, "Longer version") {
		t.Error("a contents list for one section or a longer version without a site page")
	}
}

// TestAnchorLinksUseTheHeadingPrefix: an anchor link of a guide reaches the id
// the heading gets, and the page shell's own ids stay apart.
func TestAnchorLinksUseTheHeadingPrefix(t *testing.T) {
	t.Parallel()
	g := &guides.Guide{Slug: "x", Title: "T", Summary: "S", Audience: "A", Blocks: []guides.Block{
		{Kind: guides.KindHeading, Level: 2, ID: "main", Text: []guides.Inline{{Kind: guides.InlineText, Text: "Main"}}},
		{Kind: guides.KindParagraph, Text: []guides.Inline{{Kind: guides.InlineLink, Text: "up", Href: "main", Target: guides.LinkAnchor}}},
	}}
	page := render(t, help.Guide(view.Page{Title: "T"}, help.GuideData{Guide: g}))
	if !strings.Contains(page, `<h2 id="g-main">`) || !strings.Contains(page, `<a href="#g-main">up</a>`) || strings.Contains(page, `id="main"><h2`) {
		t.Errorf("anchors: %s", page)
	}
}

// TestTemplatesNeverWriteRawHTML: templ.Raw and friends appear nowhere in the
// Help templates (docs/PHASE3.md section 17.4).
func TestTemplatesNeverWriteRawHTML(t *testing.T) {
	t.Parallel()
	files, err := filepath.Glob("*.templ")
	if err != nil || len(files) == 0 {
		t.Fatal(files, err)
	}
	for _, f := range files {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, bad := range []string{"templ.Raw", "templ.SafeHTML", "templ.SafeScript", "templ.SafeCSS", "@templ.", "<script", "style="} {
			if strings.Contains(string(src), bad) {
				t.Errorf("%s contains %s", f, bad)
			}
		}
	}
	fset := token.NewFileSet()
	goFiles, _ := filepath.Glob("*.go")
	for _, f := range goFiles {
		if strings.HasSuffix(f, "_test.go") || strings.HasSuffix(f, "_templ.go") {
			continue
		}
		if _, err := parser.ParseFile(fset, f, nil, parser.ImportsOnly); err != nil {
			t.Fatal(err)
		}
	}
}
