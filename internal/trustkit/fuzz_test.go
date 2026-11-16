package trustkit

import (
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The targets of docs/PHASE3.md section 18.1 step 87: the two places where
// the public trust page turns text from outside into something: the
// User-Agent header (anybody on the public listener sends it) and the CA name
// and base URL that end up inside commands a visitor pastes into a shell.

// FuzzDetect: Detect reads at most 512 bytes, picks a platform from a fixed
// table and keeps nothing of the input. The oracle below is a second reading
// of the table in the comment of detectRules, written with a different
// method (a byte loop over the capped string).
func FuzzDetect(f *testing.F) {
	for _, ua := range []string{
		"", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/17.4 Safari/605.1.15",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15",
		"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/126.0 Mobile Safari/537.36",
		"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
		"Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/126.0 Safari/537.36",
		"Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36",
		"Mozilla/5.0 (iPad; CPU OS 17_4 like Mac OS X) Firefox/126.0",
		"WINDOWS", "LiNuX", "FIREFOX/1", "Kindows", "İphone", "wind\x00ows", "\xff\xfe windows",
		strings.Repeat("a", 505) + "windows",   // a needle across the cut at 512
		strings.Repeat("a", 512) + "windows",   // a needle behind the cut
		strings.Repeat("a", 506) + "firefox/1", // the cut is inside the needle
		strings.Repeat("windows", 5000),        // far above the limit
		strings.Repeat("\xff", 100_000),        // not UTF-8
		strings.Repeat("a", 511) + "élinux",    // a multi-byte character across the cut
	} {
		f.Add(ua)
	}
	known := map[Platform]bool{"": true, IOS: true, Android: true, Windows: true, MacOS: true, Debian: true, Fedora: true, Linux: true}

	f.Fuzz(func(t *testing.T, ua string) {
		start := time.Now()
		got := Detect(ua)
		if d := time.Since(start); d > 2*time.Second {
			t.Fatalf("Detect took %v for %d bytes", d, len(ua))
		}
		if !known[got.Platform] {
			t.Fatalf("Detect(%.60q) gave the platform %q, which is no row of the table", ua, got.Platform)
		}
		if got.Platform != "" && got.Platform.Label() == "" {
			t.Fatalf("platform %q has no label", got.Platform)
		}
		if want := detectOracle(ua); got != want {
			t.Fatalf("Detect(%.80q) = %+v, the table says %+v", ua, got, want)
		}
		// Only the first 512 bytes count.
		if len(ua) > 512 && Detect(ua[:512]) != got {
			t.Fatalf("bytes after the 512th changed the result of %.60q", ua)
		}
		if got.Found() != (got.Platform != "" || got.Firefox) {
			t.Fatal("Found disagrees with the fields")
		}
	})
}

func detectOracle(ua string) Detection {
	if len(ua) > 512 {
		ua = ua[:512]
	}
	b := []byte(ua)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 32
		}
	}
	s := string(b)
	has := func(words ...string) bool {
		for _, w := range words {
			if strings.Contains(s, w) {
				return true
			}
		}
		return false
	}
	var d Detection
	switch {
	case has("iphone", "ipad", "ipod", "like mac os x"):
		d.Platform = IOS
	case has("android"):
		d.Platform = Android
	case has("windows"):
		d.Platform = Windows
	case has("macintosh", "mac os x"):
		d.Platform = MacOS
	case has("cros"):
		d.Platform = ""
	case has("ubuntu", "debian"):
		d.Platform = Debian
	case has("fedora", "red hat", "centos"):
		d.Platform = Fedora
	case has("linux", "x11"):
		d.Platform = Linux
	}
	d.Firefox = d.Platform != IOS && has("firefox/")
	return d
}

// FuzzGuide builds the guide of every platform for a root with a fuzzed name,
// base URL, generation and certificate and checks what the commands may hold.
//
// The check is made from the outside: a small tokenizer reads every line of
// every block the way a POSIX shell and PowerShell read quotes, and says for
// each byte whether it is unquoted, in single quotes or in double quotes.
// Then: every line ends outside a quote; the download URL stands only inside
// single quotes and is plain text there; the file name is plain letters,
// digits, dot, underscore and hyphen. And a twin root with harmless values
// shows that nothing else of the output depends on the fuzzed text: the
// output of the fuzzed root is the output of the twin with two strings
// swapped.
func FuzzGuide(f *testing.F) {
	der := []byte("not a certificate, only hashed")
	type seed struct {
		name, base string
		gen        int64
		current    bool
	}
	for _, s := range []seed{
		{"root-ca", "https://pki.homelab.lan", 1, true},
		{"root-ca", "http://pki.homelab.lan:8080/pki/", 3, false},
		{"my.root_ca-2", "https://pki.homelab.lan/~ca/a_b.c-d", 1, true},
		{"x", "https://1.2.3.4", 2, false},
		{"root'; touch pwned; '", "https://pki.homelab.lan", 1, true},
		{"root", "https://pki.homelab.lan/x'; touch pwned; '", 1, true},
		{"root", "https://pki.homelab.lan/$(id)", 1, true},
		{"root", "https://pki.homelab.lan/`id`", 1, true},
		{"root", "https://pki.homelab.lan/a b", 1, true},
		{"root", "https://pki.homelab.lan/a\nb", 1, true},
		{"root", "https://pki.homelab.lan/a;b", 1, true},
		{"root", "https://pki.homelab.lan/a&b|c>d<e", 1, true},
		{"root", "https://pki.homelab.lan/a\\b", 1, true},
		{"root", "https://pki.homelab.lan/a\"b", 1, true},
		{"root", "https://pki.homelab.lan/a%27b", 1, true},
		{"root", "https://pki.homelab.lan/../x", 1, true},
		{"root", "https://pki.homelab.lan/?q=1", 1, true},
		{"root", "https://pki.homelab.lan/#f", 1, true},
		{"root", "https://user:pw@pki.homelab.lan", 1, true},
		{"root", "https://pki.homelab.lan:0", 1, true},
		{"root", "https://pki.homelab.lan:+80", 1, true},
		{"root", "https://pki.homelab.lan:65536", 1, true},
		{"root", "https://[::1]/", 1, true},
		{"root", "https://päki.homelab.lan", 1, true},
		{"root", "ftp://pki.homelab.lan", 1, true},
		{"root", "HTTPS://pki.homelab.lan", 1, true},
		{"root", "https://", 1, true},
		{"root", "", 1, true},
		{"root", "https://pki.homelab.lan/" + strings.Repeat("a", 300), 1, true},
		{"", "https://pki.homelab.lan", 1, true},
		{"-root", "https://pki.homelab.lan", 1, true},
		{".root", "https://pki.homelab.lan", 1, true},
		{"Root", "https://pki.homelab.lan", 1, true},
		{"ro ot", "https://pki.homelab.lan", 1, true},
		{"root\n", "https://pki.homelab.lan", 1, true},
		{strings.Repeat("a", 64), "https://pki.homelab.lan", 1, true},
		{"root", "https://pki.homelab.lan", 0, true},
		{"0..", "http://0", 1, true},
		{"a..b", "http://0/a.b", 1, false},
		{"root", "https://pki.homelab.lan", -1, false},
		{"root", "https://pki.homelab.lan", 1 << 62, false},
	} {
		for p := range uint8(10) {
			f.Add(s.name, s.base, s.gen, s.current, der, p)
		}
	}
	// Every single metacharacter alone, in the path and in the name, so a
	// check that is loosened for one of them fails on a seed.
	for _, c := range "'\"`$;&|<>()[]{}*?!#%^=,+@\\ \t\n~:" {
		for p := range uint8(10) {
			f.Add("a"+string(c)+"b", "https://pki.homelab.lan", int64(1), true, der, p)
			f.Add("root", "https://pki.homelab.lan/a"+string(c)+"b", int64(1), true, der, p)
			f.Add("root", "https://pki.homelab.lan"+string(c), int64(2), false, der, p)
		}
	}

	platforms := append(Platforms(), Linux, Platform("bogus"))
	f.Fuzz(func(t *testing.T, name, base string, gen int64, current bool, der []byte, which uint8) {
		p := platforms[int(which)%len(platforms)]
		r := Root{Name: name, BaseURL: base, Generation: gen, Current: current, DER: der}
		start := time.Now()
		blocks := Guide(p, r)
		if d := time.Since(start); d > 2*time.Second {
			t.Fatalf("Guide took %v", d)
		}
		u, ok := r.CertURL()

		// CertURL says yes only to what an independent reading accepts.
		if ok != (nameOK(name) && gen >= 1 && baseOK(base)) {
			t.Fatalf("CertURL(%q, %q, %d) = %v, the rules say %v", name, base, gen, ok, !ok)
		}
		if !ok {
			// No command is produced, and the text depends on the root only
			// through the file name it shows (a refused name shows none).
			for _, b := range blocks {
				if len(b.Lines) != 0 {
					t.Fatalf("a command for a root that CertURL refuses (%q, %q, %d): %q", name, base, gen, b.Lines)
				}
			}
			refused := Root{Name: "", Generation: gen, Current: current, DER: der}
			swap := strings.NewReplacer()
			if nameOK(name) && gen >= 1 {
				refused.Name = "twinname"
				swap = strings.NewReplacer(refused.File(), r.File())
			}
			want := Guide(p, refused)
			if len(blocks) != len(want) {
				t.Fatalf("%d blocks for a refused root, its twin has %d", len(blocks), len(want))
			}
			for i := range blocks {
				if !sameBlock(blocks[i], want[i], swap) {
					t.Fatalf("block %d of a refused root (%q, %q, %d) differs from its twin:\n%+v\n%+v", i, name, base, gen, blocks[i], want[i])
				}
			}
			return
		}

		// The URL: plain characters, and a URL a parser reads as it was
		// built, with no user name, query or fragment.
		if !onlyOf(u, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_~/:") {
			t.Fatalf("download URL %q holds a character outside the plain set", u)
		}
		pu, err := url.Parse(u)
		if err != nil || pu.User != nil || pu.RawQuery != "" || pu.Fragment != "" || (pu.Scheme != "http" && pu.Scheme != "https") ||
			!strings.HasSuffix(pu.Path, "/ca/"+name+"/"+strconv.FormatInt(gen, 10)+".crt") || parentSegment(pu.Path) {
			t.Fatalf("download URL %q is not what it was built from: %v", u, err)
		}
		file := r.File()
		if !onlyOf(file, "abcdefghijklmnopqrstuvwxyz0123456789._-") || strings.HasPrefix(file, "-") {
			t.Fatalf("file name %q holds a character outside the plain set", file)
		}

		// Quoting, byte by byte.
		for _, b := range blocks {
			for _, line := range b.Lines {
				ctx, closed := quoteContexts(line)
				if !closed {
					t.Fatalf("a line ends inside a quote: %q", line)
				}
				for _, occ := range indexAll(line, u) {
					for i := occ; i < occ+len(u); i++ {
						if ctx[i] != inSingle {
							t.Fatalf("the URL is not inside single quotes at byte %d of %q", i-occ, line)
						}
					}
				}
				for _, occ := range indexAll(line, file) {
					for i := occ; i < occ+len(file); i++ {
						if ctx[i] == inDouble {
							t.Fatalf("the file name is inside double quotes: %q", line)
						}
					}
				}
			}
		}

		// Nothing else depends on the fuzzed text: the twin.
		twin := Root{Name: "twinname", BaseURL: "https://twin.invalid", Generation: gen, Current: current, DER: der}
		twinURL, twinOK := twin.CertURL()
		if !twinOK {
			t.Fatal("the twin is refused")
		}
		same := strings.NewReplacer(twinURL, u, twin.File(), file)
		want := Guide(p, twin)
		if len(blocks) != len(want) {
			t.Fatalf("%d blocks, the twin has %d", len(blocks), len(want))
		}
		for i := range blocks {
			if !sameBlock(blocks[i], want[i], same) {
				t.Fatalf("block %d differs from the twin beyond the URL and the file name:\n%+v\n%+v", i, blocks[i], want[i])
			}
		}
	})
}

// sameBlock compares a block with the twin's after the two swaps.
func sameBlock(got, twin Block, swap *strings.Replacer) bool {
	if got.Title != swap.Replace(twin.Title) || got.Note != swap.Replace(twin.Note) ||
		len(got.Steps) != len(twin.Steps) || len(got.Lines) != len(twin.Lines) {
		return false
	}
	for i := range got.Steps {
		if got.Steps[i] != swap.Replace(twin.Steps[i]) {
			return false
		}
	}
	for i := range got.Lines {
		if got.Lines[i] != swap.Replace(twin.Lines[i]) {
			return false
		}
	}
	return true
}

type quoteContext uint8

const (
	unquoted quoteContext = iota
	inSingle
	inDouble
)

// quoteContexts says for every byte of line how a shell reads it. The quote
// characters themselves count as the context they open or close with. A
// backslash outside single quotes escapes the next byte (the generator ends a
// line with " \" to continue a chain).
func quoteContexts(line string) (ctx []quoteContext, closed bool) {
	ctx = make([]quoteContext, len(line))
	state := unquoted
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch state {
		case unquoted:
			switch c {
			case '\'':
				state = inSingle
				ctx[i] = inSingle
			case '"':
				state = inDouble
				ctx[i] = inDouble
			case '\\':
				if i+1 < len(line) {
					i++
				}
			}
		case inSingle:
			ctx[i] = inSingle
			if c == '\'' {
				state = unquoted
			}
		case inDouble:
			ctx[i] = inDouble
			switch c {
			case '\\':
				if i+1 < len(line) {
					i++
					ctx[i] = inDouble
				}
			case '"':
				state = unquoted
			}
		}
	}
	return ctx, state == unquoted
}

func indexAll(s, sub string) []int {
	var out []int
	for from := 0; from+len(sub) <= len(s); {
		i := strings.Index(s[from:], sub)
		if i < 0 {
			break
		}
		out = append(out, from+i)
		from += i + 1
	}
	return out
}

func onlyOf(s, set string) bool {
	for i := range len(s) {
		if !strings.ContainsRune(set, rune(s[i])) {
			return false
		}
	}
	return true
}

// nameOK: 1 to 63 bytes of a-z, 0-9, '.', '_' and '-', the first a letter or
// a digit.
func nameOK(s string) bool {
	if s == "" || len(s) > 63 {
		return false
	}
	for i := range len(s) {
		c := s[i]
		letterOrDigit := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
		if !letterOrDigit && (i == 0 || (c != '.' && c != '_' && c != '-')) {
			return false
		}
	}
	return true
}

// baseOK states the pattern of a public base URL in other words than
// ValidBaseURL: the scheme in lower case, a host of letters, digits, dots and
// hyphens that starts with a letter or digit and has no "..", an optional
// port of 1 to 65535, an optional path of letters, digits and "._~/-" with no
// "..", at most 253 bytes once trailing slashes are gone.
func baseOK(s string) bool {
	s = strings.TrimRight(s, "/")
	var rest string
	switch {
	case strings.HasPrefix(s, "https://"):
		rest = s[len("https://"):]
	case strings.HasPrefix(s, "http://"):
		rest = s[len("http://"):]
	default:
		return false
	}
	if len(s) > 253 || rest == "" {
		return false
	}
	authority, path := rest, ""
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		authority, path = rest[:i], rest[i:]
	}
	host := authority
	if i := strings.IndexByte(authority, ':'); i >= 0 {
		host = authority[:i]
		port := authority[i+1:]
		if port == "" || len(port) > 5 || !onlyOf(port, "0123456789") {
			return false
		}
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			return false
		}
	}
	if host == "" || !onlyOf(host, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-") ||
		host[0] == '.' || host[0] == '-' || strings.Contains(host, "..") {
		return false
	}
	return onlyOf(path, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._~/-") && !strings.Contains(path, "..")
}

// parentSegment reports whether a path has a segment "..", which a server or
// a client would resolve to the directory above instead of requesting it. A
// name such as "0.." is no such segment, and a segment "." only names the
// same directory (the base URL rule leaves it alone, it has no effect).
func parentSegment(p string) bool {
	return slices.Contains(strings.Split(p, "/"), "..")
}
