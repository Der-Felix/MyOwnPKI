package publish

import (
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Der-Felix/MyOwnPKI/internal/trustkit"
)

// sectionIDs lists the platform guides on a page.
func sectionIDs(page string) []string {
	var ids []string
	for _, p := range trustkit.Platforms() {
		if strings.Contains(page, `<h2 id="h-`+string(p)+`">`) {
			ids = append(ids, string(p))
		}
	}
	return ids
}

// TestPortalDetection: the user agent selects the guide, the choice in the
// query overrides it, and the cache headers follow what the page depends on.
func TestPortalDetection(t *testing.T) {
	t.Parallel()
	_, h, _ := trustSetup(t)
	const (
		iphone  = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"
		macUA   = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15"
		winUA   = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
		android = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"
		linux   = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
		ffUbu   = "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0"
		ffWin   = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0"
		curl    = "curl/8.4.0"
	)
	for _, tc := range []struct {
		name, path, ua string
		want           []string
		cache          string
		hint           bool
	}{
		{"iPhone", "/", iphone, []string{"ios"}, "private", false},
		{"Mac", "/", macUA, []string{"macos"}, "private", false},
		{"Windows", "/", winUA, []string{"windows"}, "private", false},
		{"Android", "/", android, []string{"android"}, "private", false},
		{"Linux without a distribution shows both families", "/", linux, []string{"debian", "fedora"}, "private", false},
		{"Firefox on Ubuntu", "/", ffUbu, []string{"debian"}, "private", true},
		{"Firefox on Windows", "/", ffWin, []string{"windows"}, "private", true},
		{"curl: nothing found, the list only", "/", curl, nil, "public", false},
		{"no agent", "/", "", nil, "public", false},
		{"explicit choice beats the iPhone", "/?os=windows", iphone, []string{"windows"}, "public", false},
		{"explicit Firefox shows its steps and no hint", "/?os=firefox", ffWin, []string{"firefox"}, "public", false},
		{"explicit list entry", "/?os=java", "", []string{"java"}, "public", false},
		{"all platforms", "/?os=all", iphone, []string{"windows", "macos", "ios", "android", "debian", "fedora", "firefox", "java"}, "public", false},
	} {
		a := fetch(t, h, tc.path, "User-Agent", tc.ua)
		checkPage(t, h, a)
		page := string(a.body)
		if got := sectionIDs(page); strings.Join(got, ",") != strings.Join(tc.want, ",") {
			t.Errorf("%s: sections %v, want %v", tc.name, got, tc.want)
		}
		if cc := a.h.Get("Cache-Control"); cc != tc.cache+", max-age=300" {
			t.Errorf("%s: Cache-Control %q", tc.name, cc)
		}
		if got := strings.Contains(page, "Your browser is Firefox"); got != tc.hint {
			t.Errorf("%s: Firefox hint %v, want %v", tc.name, got, tc.hint)
		}
		if tc.want != nil && !strings.Contains(page, "shown below") {
			t.Errorf("%s: the chosen system is not marked in words", tc.name)
		}
		if tc.ua != "" && !strings.Contains(tc.path, "os=") && len(tc.want) > 0 && !strings.Contains(page, "Your browser says:") {
			t.Errorf("%s: the guess is not named", tc.name)
		}
		if strings.Contains(tc.path, "os=") && strings.Contains(page, "Your browser says:") {
			t.Errorf("%s: an explicit choice shows a guess", tc.name)
		}
	}
	// The same page for the same agent: the answer depends on nothing else.
	a, b := fetch(t, h, "/", "User-Agent", iphone), fetch(t, h, "/", "User-Agent", iphone)
	if !bytes.Equal(a.body, b.body) || a.h.Get("ETag") != b.h.Get("ETag") {
		t.Error("the page is not stable")
	}
	if fetch(t, h, "/", "User-Agent", winUA).h.Get("ETag") == a.h.Get("ETag") {
		t.Error("two platforms share an ETag")
	}
	// The detected platform is explained in words, from a fixed table.
	if page := string(a.body); !strings.Contains(page, "<strong>iPhone and iPad</strong>") {
		t.Error("the detected platform is not named")
	}
	// A conditional request works on a private answer, and HEAD has no body.
	if r := fetch(t, h, "/", "User-Agent", iphone, "If-None-Match", a.h.Get("ETag")); r.code != http.StatusNotModified {
		t.Errorf("If-None-Match: %d", r.code)
	}
	if r := fetchMethod(t, h, http.MethodHead, "/", "User-Agent", iphone); r.code != http.StatusOK || len(r.body) != 0 || r.h.Get("Cache-Control") != "private, max-age=300" {
		t.Errorf("HEAD: %d %d bytes %v", r.code, len(r.body), r.h)
	}
	// Other methods are not served.
	if r := fetchMethod(t, h, http.MethodPost, "/"); r.code != http.StatusMethodNotAllowed {
		t.Errorf("POST: %d", r.code)
	}
}

// TestPortalNoReflection: no byte of the user agent or of the query reaches
// the page, a header or a file name; a bad ?os= value counts as not given.
func TestPortalNoReflection(t *testing.T) {
	t.Parallel()
	_, h, _ := trustSetup(t)
	const uaCanary, qCanary = "CANARYUA7f3a91", "CANARYQ5b2c08"
	plain := fetch(t, h, "/", "User-Agent", "curl/8.4.0")

	// A page for a Windows agent, with a canary and markup inside the agent string.
	hostileUA := "Mozilla/5.0 (Windows NT 10.0; " + uaCanary + ") <script>alert(1)</script>\"'`$(id);|&\x00\r\nX-Injected: 1\r\nLocation: http://evil.example/"
	a := fetch(t, h, "/", "User-Agent", hostileUA)
	if sectionIDs(string(a.body))[0] != "windows" {
		t.Fatal("the hostile agent was not detected as Windows")
	}
	assertNoCanary(t, "user agent", a, uaCanary, "<script>alert", "X-Injected", "evil.example")

	// A value of ?os= never comes back, whether or not it is accepted.
	for _, q := range []string{
		"os=" + qCanary,
		"os=<script>alert('" + qCanary + "')</script>",
		"os=" + url.QueryEscape("\"><img src=x onerror=alert(1)>"+qCanary),
		"os=windows&os=macos&x=" + qCanary,
		"os=" + strings.Repeat("a", 2048) + qCanary,
		"os=" + strings.Repeat("windows", 300),
		"os=",
		"os=Windows",
		"os=WINDOWS",
		"os=windows%00",
		"os=windows%20",
		"os=%77indows%0d%0aSet-Cookie:%20x=" + qCanary,
		"os=linux",
		"os=all%20",
		"OS=windows",
		"os[]=windows",
		"x=" + qCanary,
		"%00=" + qCanary,
		"os=windows;os=macos",
	} {
		r := fetch(t, h, "/?"+q, "User-Agent", "curl/8.4.0")
		if r.code != http.StatusOK {
			t.Errorf("?%.40s: %d", q, r.code)
			continue
		}
		assertNoCanary(t, "query "+q[:min(len(q), 40)], r, qCanary, "<script>alert", "onerror", "Set-Cookie")
		// An invalid value is the same as no value: the page for curl, byte for byte.
		if !bytes.Equal(r.body, plain.body) {
			t.Errorf("?%.40s: the page differs from the page without os", q)
		}
	}
	// Accepted values name their platform and nothing else.
	for _, os := range []string{"windows", "macos", "ios", "android", "debian", "fedora", "firefox", "java"} {
		got := sectionIDs(string(fetch(t, h, "/?os="+os).body))
		if len(got) != 1 || got[0] != os {
			t.Errorf("?os=%s: %v", os, got)
		}
	}
	// A path is not a place for either value: nothing else is routed.
	for _, p := range []string{"/" + qCanary, "/index.html", "/trust/" + qCanary, "/trust/root/1/" + qCanary + ".cmd", "/?os=windows/../x"} {
		r := fetch(t, h, p, "User-Agent", uaCanary)
		if r.code != http.StatusNotFound && p != "/?os=windows/../x" {
			t.Errorf("%s: %d", p, r.code)
		}
		assertNoCanary(t, p, r, uaCanary)
	}
}

// assertNoCanary fails when a marker appears in the body, a header name or a
// header value of the answer.
func assertNoCanary(t *testing.T, what string, a answer, canaries ...string) {
	t.Helper()
	var all strings.Builder
	all.Write(a.body)
	for k, vs := range a.h {
		all.WriteString("\n" + k + ": " + strings.Join(vs, ","))
	}
	for _, c := range canaries {
		if strings.Contains(all.String(), c) {
			t.Errorf("%s: %q is reflected", what, c)
		}
	}
	if a.h.Get("Location") != "" || a.h.Get("Set-Cookie") != "" {
		t.Errorf("%s: Location %q, Set-Cookie %q", what, a.h.Get("Location"), a.h.Get("Set-Cookie"))
	}
}

// TestPortalProfile: the profile route for a root: types, file name, cache,
// the exact certificate in a well-formed plist, HEAD and conditional requests.
func TestPortalProfile(t *testing.T) {
	t.Parallel()
	_, h, _ := trustSetup(t)
	der := fetch(t, h, "/ca/root/1.crt").body
	a := fetch(t, h, "/trust/root/1/profile.mobileconfig")
	if a.code != http.StatusOK {
		t.Fatalf("profile: %d", a.code)
	}
	if a.h.Get("Content-Type") != "application/x-apple-aspen-config" {
		t.Errorf("Content-Type %q", a.h.Get("Content-Type"))
	}
	if a.h.Get("Content-Disposition") != `attachment; filename="`+wantFile("root", 1, true, der)+`.mobileconfig"` {
		t.Errorf("Content-Disposition %q", a.h.Get("Content-Disposition"))
	}
	if a.h.Get("Cache-Control") != "public, max-age=900" || a.h.Get("ETag") == "" || a.h.Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("headers %v", a.h)
	}
	// Well-formed XML that carries the exact DER and nothing of the request.
	dec := xml.NewDecoder(bytes.NewReader(a.body))
	var datas []string
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("the profile is not well-formed: %v", err)
		}
		if start, ok := tok.(xml.StartElement); ok && start.Name.Local == "data" {
			var s string
			if err := dec.DecodeElement(&s, &start); err != nil {
				t.Fatal(err)
			}
			datas = append(datas, strings.Join(strings.Fields(s), ""))
		}
	}
	if len(datas) != 1 || datas[0] != base64.StdEncoding.EncodeToString(der) {
		t.Errorf("the profile does not carry exactly the root certificate (%d data elements)", len(datas))
	}
	if !strings.Contains(string(a.body), "<key>PayloadRemovalDisallowed</key>\n\t<false/>") || !strings.Contains(string(a.body), "local.myownpki.root."+trustkit.SHA256Hex(der)[:32]) {
		t.Error("removal flag or identifier")
	}
	// The same bytes every time, whoever asks, and the user agent changes nothing.
	b := fetch(t, h, "/trust/root/1/profile.mobileconfig", "User-Agent", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)")
	c := fetch(t, h, "/trust/root/1/profile.mobileconfig?os=windows&x=CANARY")
	if !bytes.Equal(a.body, b.body) || !bytes.Equal(a.body, c.body) || a.h.Get("ETag") != b.h.Get("ETag") {
		t.Error("the profile depends on the request")
	}
	if strings.Contains(string(c.body), "CANARY") {
		t.Error("the query is reflected")
	}
	if r := fetch(t, h, "/trust/root/1/profile.mobileconfig", "If-None-Match", a.h.Get("ETag")); r.code != http.StatusNotModified {
		t.Errorf("If-None-Match: %d", r.code)
	}
	if r := fetchMethod(t, h, http.MethodHead, "/trust/root/1/profile.mobileconfig"); r.code != http.StatusOK || len(r.body) != 0 ||
		r.h.Get("Content-Type") != "application/x-apple-aspen-config" || r.h.Get("Content-Disposition") != a.h.Get("Content-Disposition") {
		t.Errorf("HEAD: %d %v", r.code, r.h)
	}
	// The page links to it for the Apple platforms, only for a root.
	page := string(fetch(t, h, "/?os=macos").body)
	if !strings.Contains(page, `href="/trust/root/1/profile.mobileconfig"`) || strings.Contains(page, "/trust/issuing/") {
		t.Error("profile link on the macOS page")
	}
}

// TestPortalHostileBaseURL: a CA whose public base URL fails the pattern gets
// no command anywhere, only the compare-by-hand text; the profile and the
// page still work.
func TestPortalHostileBaseURL(t *testing.T) {
	t.Parallel()
	v, h, _ := trustSetup(t)
	// The engine refuses most of these and its trigger forbids changing the URL:
	// the test damages a throwaway database to show what the page does with data
	// it should never meet.
	if _, err := v.PKIDB.Write.ExecContext(t.Context(), `DROP TRIGGER cas_base_url_immutable`); err != nil {
		t.Fatal(err)
	}
	for _, base := range []string{
		"http://pki.homelab.lan/'; touch /tmp/x #", "http://pki.homelab.lan/$(id)", "http://pki.homelab.lan/`id`", "http://user:pw@pki.homelab.lan",
		"http://pki.homelab.lan/a b", "http://pki.homelab.lan/%0a", "http://pki.homelab.lan/\n", "http://pki.homelab.lan/\"", "http://päki.homelab.lan",
	} {
		if _, err := v.PKIDB.Write.ExecContext(t.Context(), `UPDATE cas SET public_base_url = ? WHERE name = 'root'`, base); err != nil {
			t.Fatal(err)
		}
		a := fetch(t, h, "/?os=all")
		checkPage(t, h, a)
		text := string(a.body)
		for _, bad := range []string{"curl -fsS", "Invoke-WebRequest", "sha256sum", "shasum", "keytool -importcert", "Import-Certificate"} {
			if strings.Contains(text, bad) {
				t.Errorf("base URL %q: the page contains %q", base, bad)
			}
		}
		if !strings.Contains(text, "compare its SHA-256 by hand") {
			t.Errorf("base URL %q: no compare-by-hand text", base)
		}
		if strings.Contains(text, "touch") || strings.Contains(text, "päki") {
			t.Errorf("base URL %q is reflected", base)
		}
		if r := fetch(t, h, "/trust/root/1/profile.mobileconfig"); r.code != http.StatusOK {
			t.Errorf("profile with base URL %q: %d", base, r.code)
		}
	}
}

// TestPortalCost reports what one request costs: the CA list, the steps and
// the render. It is a measurement, not a limit; run with -v to see it. (The
// test instance needs a *testing.T, so the benchmark runs inside a test.)
func TestPortalCost(t *testing.T) {
	if testing.Short() {
		t.Skip("measurement only")
	}
	_, h, _ := trustSetup(t)
	for name, tc := range map[string]struct{ path, ua string }{
		"detected platform": {"/", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)"},
		"all platforms":     {"/?os=all", ""},
		"profile":           {"/trust/root/1/profile.mobileconfig", ""},
	} {
		res := testing.Benchmark(func(b *testing.B) {
			b.Helper()
			b.ReportAllocs()
			for range b.N {
				req := httptest.NewRequestWithContext(b.Context(), http.MethodGet, tc.path, nil)
				req.Header.Set("User-Agent", tc.ua)
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, req)
				if rec.Code != http.StatusOK {
					b.Fatalf("%d", rec.Code)
				}
			}
		})
		t.Logf("%-18s %8d ns/op %8d B/op %6d allocs/op", name, res.NsPerOp(), res.AllocedBytesPerOp(), res.AllocsPerOp())
	}
}
