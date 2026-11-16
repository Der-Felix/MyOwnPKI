package guides

import (
	"flag"
	"fmt"
	goparser "go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"
)

var update = flag.Bool("update", false, "rewrite the golden files")

// dump writes a guide as stable text: one line per block, the inline forms
// marked, so a change of the parser shows in a diff.
func dump(g *Guide) string {
	var b strings.Builder
	fmt.Fprintf(&b, "slug=%s title=%q summary=%q audience=%q order=%d site=%q sources=%q\n", g.Slug, g.Title, g.Summary, g.Audience, g.Order, g.Site, g.Sources)
	for _, bl := range g.Blocks {
		switch bl.Kind {
		case KindHeading:
			fmt.Fprintf(&b, "heading level=%d id=%s %s\n", bl.Level, bl.ID, dumpInlines(bl.Text))
		case KindParagraph:
			fmt.Fprintf(&b, "paragraph %s\n", dumpInlines(bl.Text))
		case KindNote:
			fmt.Fprintf(&b, "note warning=%v %s\n", bl.Warning, dumpInlines(bl.Text))
		case KindList:
			fmt.Fprintf(&b, "list ordered=%v\n", bl.Ordered)
			for _, item := range bl.Items {
				fmt.Fprintf(&b, "  item %s\n", dumpInlines(item))
			}
		case KindCode:
			fmt.Fprintf(&b, "code lang=%s %q\n", bl.Lang, bl.Code)
		case KindTable:
			fmt.Fprintf(&b, "table\n")
			for _, c := range bl.Header {
				fmt.Fprintf(&b, "  head %s\n", dumpInlines(c))
			}
			for _, row := range bl.Rows {
				fmt.Fprintf(&b, "  row")
				for _, c := range row {
					fmt.Fprintf(&b, " | %s", dumpInlines(c))
				}
				b.WriteString("\n")
			}
		}
	}
	return b.String()
}

func dumpInlines(in []Inline) string {
	var parts []string
	for _, i := range in {
		switch i.Kind {
		case InlineText:
			parts = append(parts, strconv.Quote(i.Text))
		case InlineBold:
			parts = append(parts, "bold("+strconv.Quote(i.Text)+")")
		case InlineItalic:
			parts = append(parts, "italic("+strconv.Quote(i.Text)+")")
		case InlineCode:
			parts = append(parts, "code("+strconv.Quote(i.Text)+")")
		case InlineLink:
			parts = append(parts, fmt.Sprintf("link(%q -> %d %s)", i.Text, i.Target, i.Href))
		}
	}
	return strings.Join(parts, " ")
}

func mustRead(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseGolden(t *testing.T) {
	t.Parallel()
	g, err := Parse("fixture", mustRead(t, "fixture.md"))
	if err != nil {
		t.Fatal(err)
	}
	got := dump(g)
	golden := filepath.Join("testdata", "fixture.golden")
	if *update {
		if werr := os.WriteFile(golden, []byte(got), 0o600); werr != nil {
			t.Fatal(werr)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if got != strings.ReplaceAll(string(want), "\r\n", "\n") {
		t.Errorf("the parse of testdata/fixture.md changed; run go test ./internal/guides -run Golden -update and read the diff\n%s", got)
	}
}

// TestCRLFIsTheSame: a checkout with Windows line ends parses to the same guide.
func TestCRLFIsTheSame(t *testing.T) {
	t.Parallel()
	src := mustRead(t, "fixture.md")
	a, err := Parse("fixture", src)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Parse("fixture", []byte(strings.ReplaceAll(string(src), "\n", "\r\n")))
	if err != nil {
		t.Fatal(err)
	}
	if dump(a) != dump(b) {
		t.Error("CRLF line ends change the parse")
	}
}

const header = "---\ntitle: T\nsummary: S\naudience: A\n---\n\n"

// TestRefusals: every construct outside the subset is an error, with the line.
func TestRefusals(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("a", MaxFileBytes)
	tests := []struct {
		name, src, want string
	}{
		{"raw html tag", header + "A <b>bold</b> word.\n", "raw HTML"},
		{"raw html comment", header + "Text <!-- x --> text.\n", "raw HTML"},
		{"script tag", header + "<script>alert(1)</script>\n", "raw HTML"},
		{"html block", header + "<div>\ntext\n</div>\n", "raw HTML"},
		{"autolink", header + "See <https://example.org>.\n", "raw HTML"},
		{"entity", header + "Fish &amp; chips.\n", "entity"},
		{"image", header + "![logo](/static/brand/logo.svg)\n", "images"},
		{"javascript link", header + "[x](javascript:alert(1))\n", "link address"},
		{"javascript upper case", header + "[x](JavaScript:alert(1))\n", "link address"},
		{"data link", header + "[x](data:text/html;base64,AAAA)\n", "link address"},
		{"http link", header + "[x](http://der-felix.github.io/MyOwnPKI/)\n", "documentation site or the repository"},
		{"other site", header + "[x](https://example.org/)\n", "documentation site or the repository"},
		{"look-alike site", header + "[x](https://der-felix.github.io/MyOwnPKI.evil.example/)\n", "documentation site or the repository"},
		{"mailto", header + "[x](mailto:a@b.example)\n", "link address"},
		{"relative file", header + "[x](other.md)\n", "link goes to"},
		{"protocol relative", header + "[x](//evil.example/x)\n", "plain path"},
		{"dot segments", header + "[x](/a/../b)\n", "no . or .. segment"},
		{"backslash path", header + "[x](/a\\b)\n", "link address"},
		{"percent", header + "[x](/a%2F%2Fb)\n", "link address"},
		{"link title", header + "[x](/a \"title\")\n", "link address"},
		{"reference link", header + "[x][1]\n", "reference links"},
		{"stray bracket", header + "a ] b\n", "without a"},
		{"unclosed link", header + "[x](/a\n", "not closed"},
		{"empty link text", header + "[](/a)\n", "not empty"},
		{"guide link bad slug", header + "[x](/guides/A_B)\n", "guide link"},
		{"unknown anchor", header + "## One\n\n[x](#two)\n", "does not name a heading"},
		{"unknown placeholder in code", header + "```bash\necho {password}\n```\n", "unknown placeholder"},
		{"unknown placeholder in span", header + "Use `{token}` here.\n", "unknown placeholder"},
		{"known placeholder in text", header + "The {ca_name} CA.\n", "inside code only"},
		{"unclosed fence", header + "```bash\nls\n", "not closed"},
		{"fence without language", header + "```\nls\n```\n", "language"},
		{"fence unknown language", header + "```html\n<b>x</b>\n```\n", "language"},
		{"empty fence", header + "```bash\n```\n", "empty"},
		{"h1", header + "# Title\n", "h1"},
		{"h4", header + "## A\n\n#### Deep\n", "h1"},
		{"h3 first", header + "### Deep\n", "needs a ## heading"},
		{"heading markup", header + "## A `b`\n", "plain text"},
		{"setext-like rule", header + "* * *\n", "starts with"},
		{"star list", header + "* item\n", "starts with"},
		{"nested list", header + "- a\n  - b\n", "nested"},
		{"mixed list", header + "- a\n1. b\n", "marker"},
		{"indented block", header + "    code\n", "start with a space"},
		{"list in paragraph", header + "Text\n- item\n", "after a blank line"},
		{"code in paragraph", header + "Text\n```bash\nls\n```\n", "after a blank line"},
		{"plain quote", header + "> just a quote\n", "note"},
		{"note without text", header + "> **Note:** \n", "no text"},
		{"note with a list", header + "> **Note:** a\n> - b\n> \n", "one paragraph"},
		{"table without separator", header + "| a | b |\n", "separator"},
		{"table bad separator", header + "| a | b |\n| - | - |\n", "separator"},
		{"table row width", header + "| a | b |\n|---|---|\n| 1 |\n", "as many cells"},
		{"table open span", header + "| a | b |\n|---|---|\n| `1 | 2 |\n", "starts and ends"},
		{"backslash", header + "A \\* star.\n", "backslash"},
		{"unclosed bold", header + "A **bold word.\n", "closing mark"},
		{"bold with code", header + "A **b `c`** d.\n", "not allowed inside"},
		{"unclosed code span", header + "A `code.\n", "not closed"},
		{"too large", header + long + "\n", "larger than"},
		{"no body", header, "no body"},
		{"no front matter", "## A\n", "front matter"},
		{"front matter not closed", "---\ntitle: T\n", "not closed"},
		{"front matter unknown key", "---\ntitle: T\nsummary: S\naudience: A\nlayout: x\n---\n\ntext\n", "unknown front matter key"},
		{"front matter duplicate", "---\ntitle: T\ntitle: U\n---\n\ntext\n", "twice"},
		{"front matter missing", "---\ntitle: T\n---\n\ntext\n", "required"},
		{"front matter html", "---\ntitle: <b>\nsummary: S\naudience: A\n---\n\ntext\n", "without < >"},
		{"front matter site", "---\ntitle: T\nsummary: S\naudience: A\nsite: https://example.org/\n---\n\ntext\n", "permalink"},
		{"front matter order", "---\ntitle: T\nsummary: S\naudience: A\norder: x\n---\n\ntext\n", "order"},
		{"front matter source", "---\ntitle: T\nsummary: S\naudience: A\nsources:\n  - ../secret\n---\n\ntext\n", "source"},
		{"nul byte", header + "a\x00b\n", "control"},
		{"bidi character", header + "a" + string(rune(0x202e)) + "b", "control"},
		{"byte order mark", header + "a" + string(rune(0xfeff)) + "b", "control"},
		{"invalid utf-8", header + "a\xffb\n", "UTF-8"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			g, err := Parse("x", []byte(tt.src))
			if err == nil {
				t.Fatalf("parsed without an error: %+v", g)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error %q lacks %q", err, tt.want)
			}
		})
	}
}

func TestBlockLimit(t *testing.T) {
	t.Parallel()
	body := strings.Repeat("A paragraph.\n\n", MaxBlocks)
	if g, err := Parse("x", []byte(header+body)); err != nil || len(g.Blocks) != MaxBlocks {
		t.Fatalf("%d blocks must pass: %v", MaxBlocks, err)
	}
	if _, err := Parse("x", []byte(header+body+"One more.\n")); err == nil || !strings.Contains(err.Error(), "more than 200 blocks") {
		t.Errorf("201 blocks: %v", err)
	}
	if _, err := Parse("x", []byte(header+"text\n"+strings.Repeat(" ", MaxFileBytes))); err == nil {
		t.Error("a file over the limit passed")
	}
}

func TestSlug(t *testing.T) {
	t.Parallel()
	for _, s := range []string{"", "A", "a_b", "a b", "../x", "a/b", "ä", strings.Repeat("a", 41)} {
		if ValidSlug(s) {
			t.Errorf("%q is a valid slug", s)
		}
		if _, err := Parse(s, []byte(header+"text\n")); err == nil {
			t.Errorf("Parse accepted the slug %q", s)
		}
	}
	for _, s := range []string{"a", "build-a-ca", "x1", strings.Repeat("a", 40)} {
		if !ValidSlug(s) {
			t.Errorf("%q is not a valid slug", s)
		}
	}
}

func TestHeadingIDsAreUnique(t *testing.T) {
	t.Parallel()
	g, err := Parse("x", []byte(header+"## Same name\n\ntext\n\n## Same name!\n\ntext\n\n### Same name\n"))
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, b := range g.Blocks {
		if b.Kind == KindHeading {
			ids = append(ids, b.ID)
		}
	}
	if strings.Join(ids, ",") != "same-name,same-name-2,same-name-3" {
		t.Errorf("ids = %v", ids)
	}
}

func TestResolve(t *testing.T) {
	t.Parallel()
	g, err := Parse("fixture", mustRead(t, "fixture.md"))
	if err != nil {
		t.Fatal(err)
	}
	code := func(g *Guide) string {
		for _, b := range g.Blocks {
			if b.Kind == KindCode {
				return b.Code
			}
		}
		return ""
	}
	span := func(g *Guide) string { return g.Blocks[1].Text[5].Text }
	tests := []struct {
		name        string
		v           Values
		wantURL, ca string
	}{
		{"values", Values{ACMEDirectory: "https://pki.example.test:8443/acme/directory", CAName: "issuing-2"}, "https://pki.example.test:8443/acme/directory", "issuing-2"},
		{"empty", Values{}, "https://pki.homelab.lan/acme/directory", "homelab-issuing"},
		{"hostile", Values{ACMEDirectory: "https://x.example/$(id)", CAName: "a b;rm -rf /"}, "https://pki.homelab.lan/acme/directory", "homelab-issuing"},
		{"quote", Values{ACMEDirectory: `https://x.example/"; id #`, CAName: "a'b"}, "https://pki.homelab.lan/acme/directory", "homelab-issuing"},
		{"markup", Values{ACMEDirectory: "https://x.example/<script>", CAName: "<b>"}, "https://pki.homelab.lan/acme/directory", "homelab-issuing"},
		{"not a url", Values{ACMEDirectory: "javascript:alert(1)", CAName: ""}, "https://pki.homelab.lan/acme/directory", "homelab-issuing"},
		{"newline", Values{ACMEDirectory: "https://x.example/a\nb", CAName: "a\nb"}, "https://pki.homelab.lan/acme/directory", "homelab-issuing"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := g.Resolve(tt.v)
			if got := code(r); !strings.HasPrefix(got, "curl --silent "+tt.wantURL+"\n") || strings.ContainsAny(got, "{}") {
				t.Errorf("code = %q", got)
			}
			if got := span(r); got != "code with "+tt.ca {
				t.Errorf("span = %q", got)
			}
		})
	}
	// The original is untouched.
	if !strings.Contains(code(g), "{acme_directory}") || g.Blocks[1].Text[5].Text != "code with {ca_name}" {
		t.Error("Resolve changed the parsed guide")
	}
}

// TestEmbeddedGuides parses what ships in the binary and checks it against the
// rest of the repository.
func TestEmbeddedGuides(t *testing.T) {
	t.Parallel()
	r, err := Embedded()
	if err != nil {
		t.Fatal(err)
	}
	list := r.List()
	if len(list) == 0 || len(list) > MaxGuides {
		t.Fatalf("%d guides", len(list))
	}
	permalinks := sitePermalinks(t)
	secrets := []struct {
		name string
		re   *regexp.Regexp
	}{
		{"an IPv4 address", regexp.MustCompile(`\b[0-9]{1,3}(\.[0-9]{1,3}){3}\b`)},
		{"a fingerprint or hash", regexp.MustCompile(`(?i)\b[0-9a-f]{2}(:[0-9a-f]{2}){15,}\b|\b[0-9a-f]{40,}\b`)},
		{"PEM material", regexp.MustCompile(`-----BEGIN`)},
		{"a token", regexp.MustCompile(`\b(mjt|mop|mpa|mea)_[A-Za-z0-9]+`)},
		{"a credential", regexp.MustCompile(`(?i)\b(password|passphrase|secret|token|key)s?\s*[:=]\s*[^\s<{]`)},
	}
	for _, g := range list {
		if g.Site == "" || !permalinks[g.Site] {
			t.Errorf("%s: the site permalink %q does not exist in site/", g.Slug, g.Site)
		}
		if len(g.Sources) == 0 {
			t.Errorf("%s: no sources", g.Slug)
		}
		for _, s := range g.Sources {
			if _, err := os.Stat(filepath.Join("..", "..", filepath.FromSlash(s))); err != nil {
				t.Errorf("%s: the source %s does not exist", g.Slug, s)
			}
		}
		text := dump(g)
		for _, s := range secrets {
			if m := s.re.FindString(text); m != "" {
				t.Errorf("%s: the text contains %s: %q", g.Slug, s.name, m)
			}
		}
		// Placeholders resolve cleanly with the examples.
		for _, b := range g.Resolve(Values{}).Blocks {
			if b.Kind == KindCode && placeholderPattern.MatchString(b.Code) {
				t.Errorf("%s: a placeholder is left in %q", g.Slug, b.Code)
			}
		}
		if g.SiteURL() != SiteBase+g.Site {
			t.Errorf("%s: SiteURL %q", g.Slug, g.SiteURL())
		}
	}
}

// sitePermalinks reads the permalinks of the documentation site pages.
func sitePermalinks(t *testing.T) map[string]bool {
	t.Helper()
	root := filepath.Join("..", "..", "site")
	out := map[string]bool{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".md") {
			return err
		}
		src, err := os.ReadFile(path) //nolint:gosec // the site sources of this repository
		if err != nil {
			return err
		}
		for _, line := range strings.Split(strings.ReplaceAll(string(src), "\r\n", "\n"), "\n")[1:] {
			if line == "---" {
				break
			}
			if v, ok := strings.CutPrefix(line, "permalink:"); ok {
				out[strings.TrimSpace(v)] = true
			}
		}
		return nil
	})
	if err != nil || len(out) < 20 {
		t.Fatalf("read the site permalinks: %d found, %v", len(out), err)
	}
	return out
}

func TestRegistry(t *testing.T) {
	t.Parallel()
	file := func(title string, order int, body string) *fstest.MapFile {
		return &fstest.MapFile{Data: []byte(fmt.Sprintf("---\ntitle: %s\nsummary: S\naudience: A\norder: %d\n---\n\n%s\n", title, order, body))}
	}
	fsys := fstest.MapFS{
		"c/b-second.md": file("Second", 20, "See [the first](/guides/a-first#x-section).\n\n## X section"),
		"c/a-first.md":  file("First", 20, "text"),
		"c/z-early.md":  file("Early", 10, "text"),
	}
	r, err := NewRegistry(fsys, "c")
	if err != nil {
		t.Fatal(err)
	}
	var order []string
	for _, g := range r.List() {
		order = append(order, g.Slug)
	}
	if strings.Join(order, ",") != "z-early,a-first,b-second" {
		t.Errorf("order = %v", order)
	}
	if _, ok := r.Get("a-first"); !ok {
		t.Error("a-first not found")
	}
	for _, s := range []string{"", "nope", "A-First", "../a-first", "a-first/", "a_first"} {
		if g, ok := r.Get(s); ok {
			t.Errorf("Get(%q) = %v", s, g)
		}
	}
	if len(Empty().List()) != 0 {
		t.Error("Empty has guides")
	}

	bad := map[string]fstest.MapFS{
		"a file that is not a guide":  {"c/readme.txt": file("x", 1, "t")},
		"a directory":                 {"c/sub/a.md": file("x", 1, "t")},
		"a link to a missing guide":   {"c/a.md": file("x", 1, "[x](/guides/missing)")},
		"a guide that does not parse": {"c/a.md": {Data: []byte("nothing")}},
		"an upper case name":          {"c/A.md": file("x", 1, "t")},
	}
	many := fstest.MapFS{}
	for i := range MaxGuides + 1 {
		many[fmt.Sprintf("c/g%d.md", i)] = file("x", i, "t")
	}
	bad["too many guides"] = many
	for name, fsys := range bad {
		if _, err := NewRegistry(fsys, "c"); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

// TestPackageUsesTheStandardLibraryOnly: the engine has no dependency (decision 9).
func TestPackageUsesTheStandardLibraryOnly(t *testing.T) {
	t.Parallel()
	files, err := filepath.Glob("*.go")
	if err != nil || len(files) == 0 {
		t.Fatal(files, err)
	}
	fset := token.NewFileSet()
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		parsed, err := goparser.ParseFile(fset, f, nil, goparser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range parsed.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			if first, _, _ := strings.Cut(path, "/"); strings.Contains(first, ".") {
				t.Errorf("%s imports %s: the guide engine uses the standard library only", f, path)
			}
		}
	}
}

func FuzzParse(f *testing.F) {
	for _, name := range []string{"fixture.md", "other.md"} {
		b, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Add([]byte(header + "[a](/b) **c** *d* `e`\n"))
	f.Add([]byte(header + "| a |\n|---|\n| `x |\n"))
	f.Add([]byte(header + "```bash\n{ca_name}\n```\n"))
	f.Add([]byte("---\n---\n"))
	f.Fuzz(func(t *testing.T, src []byte) {
		g, err := Parse("fuzz", src)
		if err != nil {
			return
		}
		if len(g.Blocks) == 0 || len(g.Blocks) > MaxBlocks {
			t.Fatalf("%d blocks", len(g.Blocks))
		}
		resolved := g.Resolve(Values{ACMEDirectory: "https://x.example/d", CAName: "ca"})
		for _, l := range resolved.Links() {
			if l.Target == LinkSite && !strings.HasPrefix(l.Href, SiteBase) && !strings.HasPrefix(l.Href, RepoBase) {
				t.Fatalf("link %q", l.Href)
			}
			if strings.HasPrefix(strings.ToLower(l.Href), "javascript:") || strings.ContainsAny(l.Href, "<>\"' \\") {
				t.Fatalf("link %q", l.Href)
			}
		}
		for _, b := range resolved.Blocks {
			if b.Kind == KindCode && placeholderPattern.MatchString(b.Code) {
				t.Fatalf("placeholder left in %q", b.Code)
			}
		}
	})
}
