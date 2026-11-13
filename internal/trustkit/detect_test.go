package trustkit

import (
	"strings"
	"testing"
)

func TestDetect(t *testing.T) {
	t.Parallel()
	const (
		chrome  = " AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
		safari  = " AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15"
		gecko   = " Gecko/20100101 Firefox/121.0"
		padding = "a"
	)
	for _, tc := range []struct {
		name, ua string
		want     Platform
		firefox  bool
	}{
		{"Chrome on Windows", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" + chrome, Windows, false},
		{"Edge on Windows", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" + chrome + " Edg/120.0.0.0", Windows, false},
		{"Chrome on macOS", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)" + chrome, MacOS, false},
		{"Edge on macOS", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)" + chrome + " Edg/120.0.0.0", MacOS, false},
		{"Safari on macOS", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)" + safari, MacOS, false},
		{"Safari on an iPad that claims to be a Mac", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)" + safari, MacOS, false},
		{"Chrome on Linux", "Mozilla/5.0 (X11; Linux x86_64)" + chrome, Linux, false},
		{"Chrome on Android", "Mozilla/5.0 (Linux; Android 14; Pixel 8)" + chrome + " Mobile", Android, false},
		{"Android tablet", "Mozilla/5.0 (Linux; Android 13; SM-X700) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36", Android, false},
		{"old Android browser (Linux inside the Android string)", "Mozilla/5.0 (Linux; U; Android 4.0.3; en-us; Nexus S Build/IML74K) AppleWebKit/534.30", Android, false},
		{"Safari on an iPhone", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)" + safari + " Mobile/15E148", IOS, false},
		{"Safari on an iPad", "Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X)" + safari + " Mobile/15E148", IOS, false},
		{"an iPod", "Mozilla/5.0 (iPod touch; CPU iPhone OS 15_0 like Mac OS X)" + safari, IOS, false},
		{"only like Mac OS X", "CPU OS 17_0 like Mac OS X", IOS, false},
		{"Firefox on iOS", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/121.0 Mobile/15E148 Safari/605.1.15", IOS, false},
		{"Firefox on Windows", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0)" + gecko, Windows, true},
		{"Firefox on macOS", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0)" + gecko, MacOS, true},
		{"Firefox on Ubuntu", "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0)" + gecko, Debian, true},
		{"Firefox on Fedora", "Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:121.0)" + gecko, Fedora, true},
		{"Firefox on Linux without a distribution", "Mozilla/5.0 (X11; Linux x86_64; rv:121.0)" + gecko, Linux, true},
		{"Firefox on Android", "Mozilla/5.0 (Android 14; Mobile; rv:121.0) Gecko/121.0 Firefox/121.0", Android, true},
		{"Chromium on Debian", "Mozilla/5.0 (X11; Debian; Linux x86_64)" + chrome, Debian, false},
		{"CentOS", "Mozilla/5.0 (X11; CentOS; Linux x86_64)" + chrome, Fedora, false},
		{"Red Hat", "Mozilla/5.0 (X11; Red Hat Enterprise Linux; Linux x86_64)" + chrome, Fedora, false},
		{"ChromeOS is no Linux row", "Mozilla/5.0 (X11; CrOS x86_64 14541.0.0)" + chrome, "", false},
		{"curl", "curl/8.4.0", "", false},
		{"empty", "", "", false},
		{"upper case", "MOZILLA/5.0 (WINDOWS NT 10.0) FIREFOX/121.0", Windows, true},
		{"Firefox without a version slash", "Firefox", "", false},
		{"NUL bytes only", "\x00\x00\x00", "", false},
		{"NUL bytes inside", "Mozilla\x00(Windows\x00NT)", Windows, false},
		{"header injection attempt", "Mozilla/5.0 (iPhone)\r\nSet-Cookie: x=1\r\nLocation: http://evil.test/", IOS, false},
		{"CRLF inside the word", "Win\r\ndows", "", false},
		{"bidi controls around a match", "\u202eMozilla (Windows\u2066 NT\u2069)\u202e", Windows, false},
		{"script", "<script>alert(1)</script>", "", false},
		{"script with a platform", "<script>alert('Android')</script>", Android, false},
		{"10 KB of A", strings.Repeat("A", 10*1024), "", false},
		{"Windows 5000 times", strings.Repeat("Windows", 5000), Windows, false},
		{"Cyrillic", "\u041c\u043e\u0437\u0438\u043b\u043b\u0430/5.0 (\u0412\u0438\u043d\u0434\u043e\u0443\u0441)", "", false},
		{"Cyrillic look-alike of Windows", "Mozilla/5.0 (W\u0456ndows)", "", false},
		{"match at the 512 byte limit", strings.Repeat(padding, 505) + "windows", Windows, false},
		{"match beyond the limit", strings.Repeat(padding, 506) + "windows", "", false},
		{"Firefox at the limit", strings.Repeat(padding, 504) + "Firefox/121.0", "", true},
		{"Firefox beyond the limit", strings.Repeat(padding, 505) + "Firefox/121.0", "", false},
		{"X11 without a distribution", "Mozilla/5.0 (X11; FreeBSD amd64)", Linux, false},
	} {
		got := Detect(tc.ua)
		if got.Platform != tc.want || got.Firefox != tc.firefox {
			t.Errorf("%s: got %q firefox=%v, want %q firefox=%v", tc.name, got.Platform, got.Firefox, tc.want, tc.firefox)
		}
		if got.Found() != (tc.want != "" || tc.firefox) {
			t.Errorf("%s: Found() is %v", tc.name, got.Found())
		}
	}
}

// TestDetectNeverEchoes: the result is a member of a fixed set whatever the
// input (it is looked up, never copied), and the cap is honored.
func TestDetectNeverEchoes(t *testing.T) {
	t.Parallel()
	fixed := map[Platform]bool{"": true, Linux: true}
	for _, p := range Platforms() {
		fixed[p] = true
	}
	rng := &prng{state: 7}
	words := []string{"windows", "Android", "iPhone", "Mac OS X", "Linux", "X11", "Ubuntu", "Fedora", "CrOS", "Firefox/1", "\x00", "\r\n", "\u202e", "<>'\"`$", "a", " "}
	for range 5000 {
		var b strings.Builder
		for range rng.Intn(40) + 1 {
			b.WriteString(words[rng.Intn(len(words))])
		}
		d := Detect(b.String())
		if !fixed[d.Platform] {
			t.Fatalf("%q gave %q", b.String(), d.Platform)
		}
	}
	// A cap on the work: a huge string costs the same as 512 bytes.
	huge := strings.Repeat("a", 50<<20)
	if got := Detect(huge); got.Found() {
		t.Error("a huge string of a's matched")
	}
}

func BenchmarkDetect(b *testing.B) {
	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	for range b.N {
		_ = Detect(ua)
	}
}

func BenchmarkDetectHostile(b *testing.B) {
	ua := strings.Repeat("Windows", 5000)
	for range b.N {
		_ = Detect(ua)
	}
}
