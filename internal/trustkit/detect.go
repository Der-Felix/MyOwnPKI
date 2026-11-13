package trustkit

import "strings"

// maxUserAgent is how much of the User-Agent header Detect looks at.
const maxUserAgent = 512

// Detection is what the User-Agent says about the visitor's system. It is a
// guess, shown as a guess: the page lets the visitor choose another platform.
type Detection struct {
	// Platform is the detected platform, [Linux] when the string only says
	// Linux or X11 (both families are shown), or "" when nothing matched.
	Platform Platform
	// Firefox is set when the browser is Firefox, which keeps its own store of
	// certificate authorities on most systems.
	Firefox bool
}

// Found reports whether the string told anything the page can use.
func (d Detection) Found() bool { return d.Platform != "" || d.Firefox }

// rule is one row of the detection table.
type rule struct {
	platform Platform
	needles  []string
}

// detectRules is checked in order, the first row with a match wins. The
// needles are lower case. Order matters: iOS and Android strings also say
// "Mac OS X" and "Linux"; ChromeOS says "X11" and must not look like Linux.
var detectRules = []rule{
	{IOS, []string{"iphone", "ipad", "ipod", "like mac os x"}},
	{Android, []string{"android"}},
	{Windows, []string{"windows"}},
	{MacOS, []string{"macintosh", "mac os x"}},
	{"", []string{"cros"}}, // ChromeOS: no row of this page fits
	{Debian, []string{"ubuntu", "debian"}},
	{Fedora, []string{"fedora", "red hat", "centos"}},
	{Linux, []string{"linux", "x11"}},
}

// Detect reads a User-Agent header value. Only the first 512 bytes count, case
// is folded for ASCII only, and the result comes from a fixed table: the
// string selects a row and nothing else, and no part of it is kept. The work
// is linear in the (capped) length: strings.Contains on fixed needles, no
// regular expression, so there is no backtracking.
func Detect(ua string) Detection {
	if len(ua) > maxUserAgent {
		ua = ua[:maxUserAgent]
	}
	s := foldASCII(ua)
	var d Detection
	for _, r := range detectRules {
		if containsAny(s, r.needles) {
			d.Platform = r.platform
			break
		}
	}
	d.Firefox = d.Platform != IOS && strings.Contains(s, "firefox/")
	return d
}

// foldASCII lower-cases A-Z and leaves every other byte alone.
func foldASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

func containsAny(s string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}
