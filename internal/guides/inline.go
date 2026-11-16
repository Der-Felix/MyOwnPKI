package guides

import (
	"strings"
)

// inlineParser reads the inline forms of one block of text. line is the
// 1-based file line used in errors.
type inlineParser struct {
	slug string
	line int
}

func (ip inlineParser) errf(msg string) error {
	return &ParseError{Slug: ip.slug, Line: ip.line, Msg: msg}
}

// parseInlines reads **bold**, *italic*, `code` and [text](link); everything
// else is text. Nesting is not part of the subset: the content of bold, italic
// and a link text is plain.
func parseInlines(s, slug string, line int) ([]Inline, error) {
	return inlineParser{slug: slug, line: line}.run(s, false)
}

func (ip inlineParser) run(s string, plainOnly bool) ([]Inline, error) {
	var out []Inline
	var text strings.Builder
	flush := func() {
		if text.Len() > 0 {
			out = append(out, Inline{Kind: InlineText, Text: text.String()})
			text.Reset()
		}
	}
	markup := func(what string) error {
		return ip.errf(what + " is not allowed inside bold, italic or a link text")
	}
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == '`':
			if plainOnly {
				return nil, markup("code")
			}
			j := strings.IndexByte(s[i+1:], '`')
			if j < 0 {
				return nil, ip.errf("a code span is not closed")
			}
			code := s[i+1 : i+1+j]
			if strings.TrimSpace(code) == "" {
				return nil, ip.errf("a code span is not empty and uses single backticks")
			}
			if err := checkPlaceholders(code, ip.slug, ip.line, true); err != nil {
				return nil, err
			}
			flush()
			out = append(out, Inline{Kind: InlineCode, Text: code})
			i += j + 2
		case c == '*':
			if plainOnly {
				return nil, markup("an asterisk")
			}
			kind, open := InlineItalic, "*"
			if strings.HasPrefix(s[i:], "**") {
				kind, open = InlineBold, "**"
			}
			j := strings.Index(s[i+len(open):], open)
			if j <= 0 {
				return nil, ip.errf("bold (**) and italic (*) need a closing mark and some text")
			}
			inner, err := ip.plainText(s[i+len(open) : i+len(open)+j])
			if err != nil {
				return nil, err
			}
			flush()
			out = append(out, Inline{Kind: kind, Text: inner})
			i += j + 2*len(open)
		case c == '[':
			if plainOnly {
				return nil, markup("a link")
			}
			in, n, err := ip.link(s[i:])
			if err != nil {
				return nil, err
			}
			flush()
			out = append(out, in)
			i += n
		case c == ']':
			return nil, ip.errf("a ] without a [: links are [text](address)")
		case c == '!' && strings.HasPrefix(s[i:], "!["):
			return nil, ip.errf("images are not allowed")
		case c == '<':
			if i+1 < len(s) && (s[i+1] == '/' || s[i+1] == '!' || s[i+1] == '?' || isASCIILetter(s[i+1])) {
				return nil, ip.errf("raw HTML is not allowed: put it in a code span")
			}
			text.WriteByte(c)
			i++
		case c == '&':
			if entityLike.MatchString(s[i:]) {
				return nil, ip.errf("an HTML entity is not allowed: write the character itself")
			}
			text.WriteByte(c)
			i++
		case c == '\\':
			return nil, ip.errf("a backslash is not allowed outside a code span or a code block")
		case c == '{':
			if n := placeholderLen(s[i:]); n > 0 {
				return nil, ip.errf("the placeholder " + s[i:i+n] + " works inside code only")
			}
			text.WriteByte(c)
			i++
		default:
			text.WriteByte(c)
			i++
		}
	}
	flush()
	return out, nil
}

func isASCIILetter(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

// placeholderLen returns the length of a placeholder ({name}, the form of
// placeholderPattern) at the very start of s, or 0. It looks at the current
// position only: searching the rest of s for every brace made a line of many
// braces quadratic.
func placeholderLen(s string) int {
	if len(s) < 3 || s[0] != '{' || s[1] < 'a' || s[1] > 'z' {
		return 0
	}
	for j := 2; j < len(s); j++ {
		switch c := s[j]; {
		case c == '}':
			return j + 1
		case (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_':
		default:
			return 0
		}
	}
	return 0
}

// plainText checks s as the content of bold, italic or a link text and returns
// it as one string.
func (ip inlineParser) plainText(s string) (string, error) {
	in, err := ip.run(s, true)
	if err != nil {
		return "", err
	}
	if len(in) != 1 || in[0].Kind != InlineText || strings.TrimSpace(in[0].Text) == "" {
		return "", ip.errf("the text of bold, italic or a link is not empty")
	}
	return in[0].Text, nil
}

// link reads "[text](address)" at the start of s and returns the inline and
// the number of bytes it covers.
func (ip inlineParser) link(s string) (Inline, int, error) {
	closeText := strings.IndexByte(s, ']')
	if closeText < 0 {
		return Inline{}, 0, ip.errf("a link is [text](address)")
	}
	label, err := ip.plainText(s[1:closeText])
	if err != nil {
		return Inline{}, 0, err
	}
	rest := s[closeText+1:]
	if !strings.HasPrefix(rest, "(") {
		return Inline{}, 0, ip.errf("a link is [text](address); reference links are not supported")
	}
	closeDest := strings.IndexByte(rest, ')')
	if closeDest < 0 {
		return Inline{}, 0, ip.errf("a link address is not closed by )")
	}
	target, href, err := ip.classify(rest[1:closeDest])
	if err != nil {
		return Inline{}, 0, err
	}
	return Inline{Kind: InlineLink, Text: label, Href: href, Target: target}, closeText + 1 + closeDest + 1, nil
}

// classify checks a link address and says where it leads. Allowed: a heading
// of the same guide (#id), a path of the UI, another guide (/guides/<slug>)
// and the project's documentation site and repository. Anything else
// (javascript:, data:, http:, mailto:, a relative file name, another site) is
// an error.
func (ip inlineParser) classify(dest string) (LinkTarget, string, error) {
	if dest == "" || len(dest) > 200 || !linkChars.MatchString(dest) {
		return 0, "", ip.errf("a link address is 1 to 200 characters of letters, digits and . _ ~ / : # ? = & -")
	}
	switch {
	case strings.HasPrefix(dest, "#"):
		id := dest[1:]
		if !headingID.MatchString(id) {
			return 0, "", ip.errf("an anchor link names a heading id: lower case letters, digits and -")
		}
		return LinkAnchor, id, nil
	case strings.HasPrefix(dest, "/"):
		if strings.HasPrefix(dest, "//") || !uiPath.MatchString(dest) {
			return 0, "", ip.errf("a path link is a plain path of the UI, such as /domains/new")
		}
		path := dest
		if k := strings.IndexAny(path, "?#"); k >= 0 {
			path = path[:k]
		}
		for seg := range strings.SplitSeq(path, "/") {
			if seg == "." || seg == ".." {
				return 0, "", ip.errf("a path link has no . or .. segment")
			}
		}
		if slug, ok := strings.CutPrefix(path, "/guides/"); ok {
			if !ValidSlug(slug) {
				return 0, "", ip.errf("a guide link is /guides/<slug>")
			}
			return LinkGuide, dest, nil
		}
		return LinkUI, dest, nil
	case strings.HasPrefix(dest, "https://"):
		for _, base := range []string{SiteBase, RepoBase} {
			if rest, ok := strings.CutPrefix(dest, base); ok && (rest == "" || strings.HasPrefix(rest, "/")) {
				if !plainSitePath(rest) {
					return 0, "", ip.errf("a link to the documentation site or the repository has no . or .. segment and no //")
				}
				return LinkSite, dest, nil
			}
		}
		return 0, "", ip.errf("an external link goes to the documentation site or the repository of the project only")
	}
	return 0, "", ip.errf("a link goes to a #heading, a /path of the UI, /guides/<slug> or, by https, the documentation site or the repository of the project")
}

// plainSitePath reports whether the part of an https link behind the base
// ("" or "/..." with an optional query or fragment) stays below the base when
// a browser normalizes it: no "." or ".." segment and no empty segment (//),
// which a server may fold into one slash. A trailing slash is fine. Percent
// escapes and backslashes never get here: linkChars refuses them.
func plainSitePath(rest string) bool {
	if k := strings.IndexAny(rest, "?#"); k >= 0 {
		rest = rest[:k]
	}
	if rest == "" || rest == "/" {
		return true
	}
	segs := strings.Split(rest[1:], "/")
	for i, seg := range segs {
		if seg == "." || seg == ".." || (seg == "" && i != len(segs)-1) {
			return false
		}
	}
	return true
}

// checkPlaceholders refuses a {name} that is not in the closed list. Text
// outside code never reaches here with a placeholder (the inline parser refuses
// it first).
func checkPlaceholders(s, slug string, line int, inCode bool) error {
	if !inCode {
		return nil
	}
	for _, m := range placeholderPattern.FindAllString(s, -1) {
		name := m[1 : len(m)-1]
		if _, ok := placeholderExamples[name]; !ok {
			return &ParseError{Slug: slug, Line: line, Msg: "unknown placeholder " + m + "; the closed list is {acme_directory} and {ca_name}"}
		}
	}
	return nil
}
