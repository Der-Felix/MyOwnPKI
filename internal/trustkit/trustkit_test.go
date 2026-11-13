package trustkit

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"unicode"
)

// guideText renders blocks the way the golden files pin them.
func guideText(blocks []Block) []byte {
	var b strings.Builder
	for i, bl := range blocks {
		if i > 0 {
			b.WriteString("\n")
		}
		b.WriteString("## " + bl.Title + "\n")
		for j, s := range bl.Steps {
			b.WriteString(string(rune('1'+j)) + ". " + s + "\n")
		}
		if len(bl.Lines) > 0 {
			b.WriteString("```\n" + strings.Join(bl.Lines, "\n") + "\n```\n")
		}
		if bl.Note != "" {
			b.WriteString("Note: " + bl.Note + "\n")
		}
	}
	return []byte(b.String())
}

// TestGolden pins the profile and every guide for the fixture root, so any
// change of a command or a sentence shows in review.
func TestGolden(t *testing.T) {
	t.Parallel()
	r := fixtureRoot(t)
	prof, err := MobileConfig(r)
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "profile.mobileconfig.golden", prof)
	for _, p := range Platforms() {
		golden(t, "guide-"+string(p)+".golden", guideText(Guide(p, r)))
	}
	old := r
	old.Current, old.Generation = false, 2
	golden(t, "guide-debian-older-generation.golden", guideText(Guide(Debian, old)))
	bad := r
	bad.BaseURL = "http://x.test/'; id #"
	golden(t, "guide-debian-refused.golden", guideText(Guide(Debian, bad)))
}

// plist is a minimal property list: a dict of strings, integers, booleans,
// data and nested arrays and dicts, read with encoding/xml only.
type plist map[string]any

func parsePlist(t *testing.T, data []byte) plist {
	t.Helper()
	dec := xml.NewDecoder(bytes.NewReader(data))
	var sawDoctype bool
	var root any
	var read func(start xml.StartElement) any
	text := func() string {
		var sb strings.Builder
		for {
			tok, err := dec.Token()
			if err != nil {
				t.Fatal(err)
			}
			switch v := tok.(type) {
			case xml.CharData:
				sb.Write(v)
			case xml.EndElement:
				return sb.String()
			default:
				t.Fatalf("unexpected %T inside a text element", tok)
			}
		}
	}
	read = func(start xml.StartElement) any {
		switch start.Name.Local {
		case "string", "data":
			s := text()
			if start.Name.Local == "data" {
				return "data:" + strings.Join(strings.Fields(s), "")
			}
			return s
		case "integer":
			return "int:" + text()
		case "true", "false":
			if _, err := dec.Token(); err != nil { // the end tag
				t.Fatal(err)
			}
			return start.Name.Local
		case "array":
			var out []any
			for {
				tok, err := dec.Token()
				if err != nil {
					t.Fatal(err)
				}
				switch v := tok.(type) {
				case xml.StartElement:
					out = append(out, read(v))
				case xml.EndElement:
					return out
				}
			}
		case "dict":
			out := plist{}
			var key string
			for {
				tok, err := dec.Token()
				if err != nil {
					t.Fatal(err)
				}
				switch v := tok.(type) {
				case xml.StartElement:
					if v.Name.Local == "key" {
						key = text()
						continue
					}
					if _, dup := out[key]; dup || key == "" {
						t.Fatalf("value without key or duplicate key %q", key)
					}
					out[key] = read(v)
					key = ""
				case xml.EndElement:
					return out
				}
			}
		}
		t.Fatalf("unknown plist element %s", start.Name.Local)
		return nil
	}
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		switch v := tok.(type) {
		case xml.Directive:
			if !strings.HasPrefix(string(v), "DOCTYPE plist PUBLIC") {
				t.Errorf("directive %q", v)
			}
			sawDoctype = true
		case xml.StartElement:
			if v.Name.Local == "plist" {
				continue
			}
			root = read(v)
		}
	}
	if !sawDoctype {
		t.Error("no DOCTYPE")
	}
	d, ok := root.(plist)
	if !ok {
		t.Fatalf("the top level is %T, want a dict", root)
	}
	return d
}

var reUUID = regexp.MustCompile(`^[0-9A-F]{8}-[0-9A-F]{4}-8[0-9A-F]{3}-[89AB][0-9A-F]{3}-[0-9A-F]{12}$`)

// TestMobileConfig: the profile parses, carries the exact DER and nothing
// else, and is a pure function of the root.
func TestMobileConfig(t *testing.T) {
	t.Parallel()
	r := fixtureRoot(t)
	out, err := MobileConfig(r)
	if err != nil {
		t.Fatal(err)
	}
	d := parsePlist(t, out)
	sum := sha256.Sum256(r.DER)
	fp32 := hex.EncodeToString(sum[:])[:32]

	if d["PayloadType"] != "Configuration" || d["PayloadVersion"] != "int:1" || d["PayloadRemovalDisallowed"] != "false" {
		t.Errorf("top level: %v", d)
	}
	if d["PayloadIdentifier"] != "local.myownpki.root."+fp32 {
		t.Errorf("identifier %v", d["PayloadIdentifier"])
	}
	if d["PayloadDisplayName"] != "Fixture Root CA (never real)" {
		t.Errorf("display name %v", d["PayloadDisplayName"])
	}
	content, ok := d["PayloadContent"].([]any)
	if !ok || len(content) != 1 {
		t.Fatalf("PayloadContent: %v", d["PayloadContent"])
	}
	inner := payloadOf(t, d)
	if inner["PayloadType"] != "com.apple.security.root" || inner["PayloadVersion"] != "int:1" ||
		inner["PayloadIdentifier"] != "local.myownpki.root."+fp32+".cert" || inner["PayloadCertificateFileName"] != "fixture-root.crt" {
		t.Errorf("payload: %v", inner)
	}
	if der := carriedDER(t, d); !bytes.Equal(der, r.DER) {
		t.Error("the profile does not carry the exact DER")
	}
	for _, u := range []any{d["PayloadUUID"], inner["PayloadUUID"]} {
		if s, _ := u.(string); !reUUID.MatchString(s) {
			t.Errorf("UUID %v is not version 8 / variant 1, upper case", u)
		}
	}
	if d["PayloadUUID"] == inner["PayloadUUID"] {
		t.Error("both payloads share a UUID")
	}
	// Only the known keys: no scope, URL, webhook or other payload.
	for k := range d {
		switch k {
		case "PayloadContent", "PayloadDescription", "PayloadDisplayName", "PayloadIdentifier",
			"PayloadRemovalDisallowed", "PayloadType", "PayloadUUID", "PayloadVersion":
		default:
			t.Errorf("unexpected top-level key %s", k)
		}
	}
	for k := range inner {
		switch k {
		case "PayloadCertificateFileName", "PayloadContent", "PayloadDescription", "PayloadDisplayName",
			"PayloadIdentifier", "PayloadType", "PayloadUUID", "PayloadVersion":
		default:
			t.Errorf("unexpected payload key %s", k)
		}
	}
	// No date, host name, serial or private data.
	text := string(out)
	for _, bad := range []string{"<date>", "PRIVATE", "PayloadScope", r.BaseURL, "pki.example.test", "<true/>"} {
		if strings.Contains(text, bad) {
			t.Errorf("the profile contains %q", bad)
		}
	}

	// Deterministic, and another root gives other identifiers.
	again, _ := MobileConfig(r)
	if !bytes.Equal(out, again) {
		t.Error("the same root gave different bytes")
	}
	other := fixtureRoot(t)
	other.DER = append([]byte(nil), r.DER...)
	other.DER[len(other.DER)-1] ^= 0xff // another signature: parses, other hash
	o2, err := MobileConfig(other)
	if err != nil {
		t.Fatal(err)
	}
	od := parsePlist(t, o2)
	if od["PayloadIdentifier"] == d["PayloadIdentifier"] || od["PayloadUUID"] == d["PayloadUUID"] ||
		payloadOf(t, od)["PayloadUUID"] == inner["PayloadUUID"] {
		t.Error("another certificate gave the same identifier or UUID")
	}
}

// TestMobileConfigOpenSSL cross-checks the fingerprint of the carried DER.
func TestMobileConfigOpenSSL(t *testing.T) {
	t.Parallel()
	ossl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl is not on the PATH")
	}
	r := fixtureRoot(t)
	out, err := MobileConfig(r)
	if err != nil {
		t.Fatal(err)
	}
	d := parsePlist(t, out)
	der := carriedDER(t, d)
	f := filepath.Join(t.TempDir(), "root.der")
	if werr := os.WriteFile(f, der, 0o600); werr != nil {
		t.Fatal(werr)
	}
	got, err := exec.CommandContext(t.Context(), ossl, "x509", "-inform", "DER", "-in", f, "-noout", "-fingerprint", "-sha256").Output()
	if err != nil {
		t.Fatal(err)
	}
	line := strings.TrimSpace(string(got))
	_, fp, _ := strings.Cut(line, "=")
	if strings.ToLower(strings.ReplaceAll(fp, ":", "")) != r.SHA256() {
		t.Errorf("openssl says %s, SHA256Hex says %s", fp, r.SHA256())
	}
	if ColonHex(r.SHA256()) != fp {
		t.Errorf("ColonHex %s, openssl %s", ColonHex(r.SHA256()), fp)
	}
}

// TestMobileConfigRefusals: a profile only for a valid root.
func TestMobileConfigRefusals(t *testing.T) {
	t.Parallel()
	r := fixtureRoot(t)
	for name, mut := range map[string]func(*Root){
		"empty der":     func(r *Root) { r.DER = nil },
		"garbage der":   func(r *Root) { r.DER = []byte("not a certificate") },
		"hostile name":  func(r *Root) { r.Name = "a\"><x" },
		"zero gen":      func(r *Root) { r.Generation = 0 },
		"uppercase":     func(r *Root) { r.Name = "Root" },
		"long name":     func(r *Root) { r.Name = strings.Repeat("a", 64) },
		"leading dot":   func(r *Root) { r.Name = ".root" },
		"newline name":  func(r *Root) { r.Name = "root\n" },
		"unicode name":  func(r *Root) { r.Name = "wurzel\u00fc" },
		"slash in name": func(r *Root) { r.Name = "a/b" },
	} {
		x := r
		mut(&x)
		if out, err := MobileConfig(x); err == nil {
			t.Errorf("%s: accepted:\n%s", name, out)
		}
	}
}

// TestMobileConfigHostileCommonName: the display name is cleaned and escaped,
// and the document stays well-formed.
func TestMobileConfigHostileCommonName(t *testing.T) {
	t.Parallel()
	r := fixtureRoot(t)
	for _, cn := range []string{
		"'; rm -rf / #", "<", "</string><key>PayloadRemovalDisallowed</key><true/>", `"quote"`, "line\nbreak", "tab\there",
		"bidi \u202e\u2066\u2069 text", "nul\x00byte", "\ufffd\xff\xfe", strings.Repeat("A", 10000), strings.Repeat("\u202e", 500), "&amp;",
	} {
		r.CommonName = cn
		out, err := MobileConfig(r)
		if err != nil {
			t.Fatalf("%q: %v", cn, err)
		}
		d := parsePlist(t, out)
		name, _ := d["PayloadDisplayName"].(string)
		if len([]rune(name)) > 64 || name == "" {
			t.Errorf("%q: display name %q", cn, name)
		}
		for _, c := range name {
			if unicode.IsControl(c) || unicode.Is(unicode.Cf, c) || c == 0xfffd {
				t.Errorf("%q: display name keeps U+%04X", cn, c)
			}
		}
		if d["PayloadRemovalDisallowed"] != "false" {
			t.Errorf("%q: the profile was altered", cn)
		}
		if strings.Contains(string(out), "<key>PayloadRemovalDisallowed</key>\n\t<true/>") || strings.Count(string(out), "<key>PayloadRemovalDisallowed</key>") != 1 {
			t.Errorf("%q: injected markup", cn)
		}
	}
	r.CommonName = "\u202e\u2066"
	out, _ := MobileConfig(r)
	if d := parsePlist(t, out); d["PayloadDisplayName"] != "fixture-root" {
		t.Errorf("empty display name falls back to the CA name, got %v", d["PayloadDisplayName"])
	}
}

// TestUUID: version 8, variant 1, stable, different per label and root.
func TestUUID(t *testing.T) {
	t.Parallel()
	var a, b [32]byte
	b[0] = 1
	if uuid(a, "profile") == uuid(a, "certificate") || uuid(a, "profile") == uuid(b, "profile") {
		t.Error("uuid is not a function of label and fingerprint")
	}
	for i := range 200 {
		var fp [32]byte
		fp[i%32] = byte(i)
		if u := uuid(fp, "profile"); !reUUID.MatchString(u) {
			t.Fatalf("%s", u)
		}
	}
}

func TestFormatting(t *testing.T) {
	t.Parallel()
	if got := ColonHex("00ab1fFF"); got != "00:AB:1F:FF" {
		t.Error(got)
	}
	if got := ColonHex(""); got != "" {
		t.Error(got)
	}
	if got := ColonHex("abc"); got != "AB:C" {
		t.Error(got)
	}
	sum := sha256.Sum256([]byte("x"))
	if SHA256Hex([]byte("x")) != hex.EncodeToString(sum[:]) || len(SHA256Hex(nil)) != 64 {
		t.Error("SHA256Hex")
	}
	r := Root{Name: "root", Generation: 2, Current: false}
	if r.File() != "root-2" || (Root{Name: "root", Generation: 2, Current: true}).File() != "root" {
		t.Error("File")
	}
}

func TestParsePlatform(t *testing.T) {
	t.Parallel()
	for _, p := range Platforms() {
		if got, ok := ParsePlatform(string(p)); !ok || got != p || p.Label() == "" {
			t.Errorf("%s: %v %v", p, got, ok)
		}
	}
	for _, bad := range []string{"", "all", "linux", "Windows", "windows ", "<script>", "windowswindowswindows", "windows\x00", "ios\n"} {
		if p, ok := ParsePlatform(bad); ok || p != "" {
			t.Errorf("%q accepted", bad)
		}
	}
}

// TestValidBaseURL: the conservative pattern.
func TestValidBaseURL(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"http://pki.example.test":          "http://pki.example.test",
		"http://pki.example.test/":         "http://pki.example.test",
		"https://pki.example.test:8443":    "https://pki.example.test:8443",
		"http://10.0.0.5:8080/pki/v1":      "http://10.0.0.5:8080/pki/v1",
		"http://a-b.c.example.test/x_y.z~": "http://a-b.c.example.test/x_y.z~",
		"HTTP://x.test":                    "",
	} {
		got, ok := ValidBaseURL(in)
		if (want == "") == ok || got != want {
			t.Errorf("%q: %q %v, want %q", in, got, ok, want)
		}
	}
	for _, bad := range hostileBaseURLs() {
		if got, ok := ValidBaseURL(bad); ok {
			t.Errorf("%q accepted as %q", bad, got)
		}
	}
}

func hostileBaseURLs() []string {
	return []string{
		"", "/", "http://", "https://", "ftp://x.test", "x.test", "//x.test", "javascript:alert(1)",
		"http://x.test'", "http://x.test/'; rm -rf / #", "http://x.test/`id`", "http://x.test/$(id)", "http://x.test/${IFS}",
		"http://x.test/a\nb", "http://x.test/a\rb", "http://x.test/a b", " http://x.test", "http://x.test ", "http://x.test\t",
		"http://x.test/%0a", "http://x.test/%27", "http://x.test/a%2fb", "http://x.t\u00e9st/", "http://x.test/\u00fc", "http://\u202e.test",
		"http://user:pw@x.test", "http://user@x.test", "http://x.test?a=b", "http://x.test/#frag", "http://x.test/;id", "http://x.test/|id",
		"http://x.test/&id", "http://x.test/<x>", "http://x.test/\"x\"", "http://x.test/a\\b", "http://x.test/a*b", "http://x.test/a?b",
		"http://x.test:", "http://x.test:0", "http://x.test:99999", "http://x.test:+80", "http://x.test:8 0", "http://x.test:abc", "http://x.test::80",
		"http://[::1]/", "http://-x.test", "http://.x.test", "http://x..test", "http://x.test/../x", "http://x.test/..", "http://x\x00.test",
		"http://" + strings.Repeat("a", 300), "http://x.test/" + strings.Repeat("a", 300),
	}
}

// hostileNames are CA names the engine would never accept.
func hostileNames() []string {
	return []string{
		"", "Root", "-root", ".root", "_root", "ro ot", "ro'ot", "ro`ot", "ro$(id)ot", "ro;ot", "ro|ot", "ro&ot", "ro\not", "ro\rot",
		"ro/ot", "ro\\ot", "ro%0aot", "r\u00f6ot", "ro\u202eot", "ro\x00ot", strings.Repeat("a", 64), "ro\"ot", "ro<ot", "ro>ot", "../root",
	}
}

// commandText joins every line of every block with a newline.
func commandText(blocks []Block) string {
	var all []string
	for _, b := range blocks {
		all = append(all, b.Lines...)
	}
	return strings.Join(all, "\n")
}

var commandPlatforms = []Platform{Windows, MacOS, Debian, Fedora, Java}

// TestGuideCommands: every command that checks a download carries the root's
// 64 hex digits and the download URL, and nothing else variable; the chain
// stops at a failed check.
func TestGuideCommands(t *testing.T) {
	t.Parallel()
	r := fixtureRoot(t)
	url := fixtureBase + "/ca/fixture-root/1.crt"
	hexSum := r.SHA256()
	for _, p := range commandPlatforms {
		blocks := Guide(p, r)
		cmds := commandText(blocks)
		if cmds == "" {
			t.Fatalf("%s: no command", p)
		}
		if !strings.Contains(strings.ToLower(cmds), hexSum) || !strings.Contains(cmds, url) {
			t.Errorf("%s: the commands lack the fingerprint or the URL:\n%s", p, cmds)
		}
		if p == Windows && !strings.Contains(cmds, strings.ToUpper(hexSum)) {
			t.Errorf("windows: the hash must be upper case for Get-FileHash")
		}
		if p != Windows {
			// Every command is joined to the previous one, so a failed check stops the install.
			for block := range blocks {
				lines := blocks[block].Lines
				for i, l := range lines {
					if i < len(lines)-1 && !strings.HasSuffix(l, " \\") {
						t.Errorf("%s: line %d does not continue: %q", p, i, l)
					}
					if i > 0 && !strings.HasPrefix(l, "  && ") {
						t.Errorf("%s: line %d is not joined with &&: %q", p, i, l)
					}
				}
			}
			ci, ki := strings.Index(cmds, "sha256sum -c"), strings.Index(cmds, "update-ca")
			if p == MacOS {
				ci, ki = strings.Index(cmds, "shasum -a 256 -c"), strings.Index(cmds, "add-trusted-cert")
			}
			if p == Java {
				ki = strings.Index(cmds, "keytool")
			}
			if ci < 0 || ki < 0 || ci > ki {
				t.Errorf("%s: the check must come before the install:\n%s", p, cmds)
			}
		}
		for _, b := range blocks {
			if len(b.Lines) > 0 && !strings.Contains(b.Note, "only checks the download against this page") {
				t.Errorf("%s: block %q lacks the limit of the embedded value", p, b.Title)
			}
		}
	}
	if strings.Contains(commandText(Guide(Java, r)), "-noprompt") {
		t.Error("keytool must not use -noprompt")
	}
	if !strings.Contains(commandText(Guide(Windows, r)), `Cert:\CurrentUser\Root`) || !strings.Contains(commandText(Guide(Windows, r)), `Cert:\LocalMachine\Root`) {
		t.Error("both Windows stores are expected")
	}
	// An older generation: other URL and file names.
	old := r
	old.Current, old.Generation = false, 3
	c := commandText(Guide(Debian, old))
	if !strings.Contains(c, fixtureBase+"/ca/fixture-root/3.crt") || !strings.Contains(c, "myownpki-fixture-root-3.crt") {
		t.Errorf("older generation:\n%s", c)
	}
	// Platforms without commands have none, and an unknown platform has no blocks.
	for _, p := range []Platform{IOS, Android, Firefox} {
		if b := Guide(p, r); len(b) == 0 || commandText(b) != "" {
			t.Errorf("%s: %v", p, b)
		}
	}
	if Guide("nope", r) != nil || Guide(Linux, r) != nil {
		t.Error("an unknown platform has blocks")
	}
}

// TestGuideIndependentOfCommonName: commands and steps never contain the
// common name, hostile or not.
func TestGuideIndependentOfCommonName(t *testing.T) {
	t.Parallel()
	r := fixtureRoot(t)
	canary := "CANARY-CN-0xdead"
	for _, cn := range []string{canary, "'; rm -rf / #", "<", "\"", "line\nbreak", "\u202e bidi", strings.Repeat("A", 10000), "`id`"} {
		a := r
		a.CommonName = cn
		for _, p := range Platforms() {
			x, y := guideText(Guide(p, r)), guideText(Guide(p, a))
			if !bytes.Equal(x, y) {
				t.Errorf("%s: the guide depends on the common name %q", p, cn)
			}
		}
	}
}

// TestGuideHostileInput: a hostile base URL or CA name gives no command, and
// the text carries none of the hostile characters.
func TestGuideHostileInput(t *testing.T) {
	t.Parallel()
	r := fixtureRoot(t)
	for _, base := range hostileBaseURLs() {
		x := r
		x.BaseURL = base
		for _, p := range Platforms() {
			text := string(guideText(Guide(p, x)))
			if cmds := commandText(Guide(p, x)); cmds != "" {
				t.Errorf("%s: base URL %q gave commands:\n%s", p, base, cmds)
			}
			if strings.TrimSpace(base) != "" && len(base) > 8 && len(base) < 50 && strings.Contains(text, base) {
				t.Errorf("%s: base URL %q appears in the text", p, base)
			}
			for _, c := range []string{"'; rm", "$(id)", "`id`", "\u202e", "\x00"} {
				if strings.Contains(text, c) && strings.Contains(base, c) {
					t.Errorf("%s: %q leaked", p, c)
				}
			}
		}
		if p := Guide(Debian, x); !strings.Contains(p[0].Note, "compare its SHA-256 by hand") {
			t.Errorf("a refused base URL says nothing: %v", p)
		}
	}
	for _, name := range hostileNames() {
		x := r
		x.Name = name
		for _, p := range Platforms() {
			if cmds := commandText(Guide(p, x)); cmds != "" {
				t.Errorf("%s: name %q gave commands:\n%s", p, name, cmds)
			}
			if text := string(guideText(Guide(p, x))); strings.ContainsAny(text, "\x00\u202e`$;|") && strings.ContainsAny(name, "\x00\u202e`$;|") {
				// The fixed texts carry "$JAVA_HOME" only inside a command, which is absent here.
				t.Errorf("%s: name %q leaked into the text", p, name)
			}
		}
	}
	x := r
	x.Generation = 0
	if commandText(Guide(Debian, x)) != "" {
		t.Error("generation 0 gave commands")
	}
}

// TestGuideProperty: random base URLs and names from a hostile alphabet give
// either no command or commands whose variable parts are the checked ones.
func TestGuideProperty(t *testing.T) {
	t.Parallel()
	rng := &prng{state: 1}
	const alphabet = "abcAZ09.-_/:~'\"`$();|&<>\\ \n\r\t%@#?*{}[]!\u00e9\u202e\x00"
	pick := func(n int) string {
		var b strings.Builder
		for range rng.Intn(n) + 1 {
			b.WriteByte(alphabet[rng.Intn(len(alphabet))])
		}
		return b.String()
	}
	r := fixtureRoot(t)
	accepted := 0
	runes := []rune(alphabet)
	mutate := func(s string) string {
		b := []rune(s)
		i, c := rng.Intn(len(b)+1), runes[rng.Intn(len(runes))]
		if rng.Intn(2) == 0 && i < len(b) {
			b[i] = c
			return string(b)
		}
		return string(b[:i]) + string(c) + string(b[i:])
	}
	for n := range 20000 {
		x := r
		if n%2 == 0 {
			x.BaseURL = "http://" + pick(12)
			x.Name = pick(6)
		} else {
			x.BaseURL = mutate("http://pki.example.test:8080/pki")
			x.Name = mutate("root-ca.1")
		}
		cmds := commandText(Guide(Debian, x))
		if cmds == "" {
			continue
		}
		accepted++
		url, ok := x.CertURL()
		if !ok || !ValidName(x.Name) || len(url) > 400 {
			t.Fatalf("commands for an invalid input %q %q", x.BaseURL, x.Name)
		}
		// Only the safe character set appears outside the fixed command words.
		for _, c := range url + x.Name {
			if !safeChar(c) {
				t.Fatalf("unsafe character %q in an accepted input %q %q", c, x.BaseURL, x.Name)
			}
		}
		if !strings.Contains(cmds, "'"+url+"'") {
			t.Fatalf("the URL is not quoted as a whole:\n%s", cmds)
		}
	}
	if accepted == 0 {
		t.Error("the generator never produced an acceptable input")
	}
}

// TestGuideShell: the Linux and macOS blocks are valid shell for shellcheck;
// the Windows blocks parse in PowerShell. Both skip without the tools.
func TestGuideShell(t *testing.T) {
	t.Parallel()
	r := fixtureRoot(t)
	t.Run("shellcheck", func(t *testing.T) {
		t.Parallel()
		sc, err := exec.LookPath("shellcheck")
		if err != nil {
			t.Skip("shellcheck is not on the PATH")
		}
		for _, p := range []Platform{Debian, Fedora, MacOS, Java} {
			script := "#!/bin/bash\n" + commandText(Guide(p, r)) + "\n"
			f := filepath.Join(t.TempDir(), string(p)+".sh")
			if err := os.WriteFile(f, []byte(script), 0o600); err != nil {
				t.Fatal(err)
			}
			if out, err := exec.CommandContext(t.Context(), sc, "--shell=bash", f).CombinedOutput(); err != nil {
				t.Errorf("%s: shellcheck: %v\n%s\n%s", p, err, out, script)
			}
		}
	})
	t.Run("powershell", func(t *testing.T) {
		t.Parallel()
		ps, err := exec.LookPath("pwsh")
		if err != nil {
			if ps, err = exec.LookPath("powershell"); err != nil {
				t.Skip("PowerShell is not on the PATH")
			}
		}
		for i, b := range Guide(Windows, r) {
			if len(b.Lines) == 0 {
				continue
			}
			f := filepath.Join(t.TempDir(), "block"+string(rune('0'+i))+".ps1")
			if err := os.WriteFile(f, []byte(strings.Join(b.Lines, "\r\n")+"\r\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			const parse = `$e=$null;$t=$null;[void][System.Management.Automation.Language.Parser]::ParseFile($env:TRUSTKIT_PS1,[ref]$t,[ref]$e);if($e -and $e.Count){$e|ForEach-Object{[Console]::Error.WriteLine($_.Message)};exit 1}`
			cmd := exec.CommandContext(t.Context(), ps, "-NoProfile", "-NonInteractive", "-Command", parse)
			cmd.Env = append(os.Environ(), "TRUSTKIT_PS1="+f)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Errorf("block %q does not parse: %v\n%s", b.Title, err, out)
			}
		}
	})
}

// payloadOf returns the single certificate payload of a parsed profile.
func payloadOf(t *testing.T, d plist) plist {
	t.Helper()
	content, ok := d["PayloadContent"].([]any)
	if !ok || len(content) != 1 {
		t.Fatalf("PayloadContent: %v", d["PayloadContent"])
	}
	inner, ok := content[0].(plist)
	if !ok {
		t.Fatalf("payload is %T", content[0])
	}
	return inner
}

// carriedDER decodes the certificate inside a parsed profile.
func carriedDER(t *testing.T, d plist) []byte {
	t.Helper()
	text, ok := payloadOf(t, d)["PayloadContent"].(string)
	if !ok {
		t.Fatal("the payload carries no data")
	}
	der, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(text, "data:"))
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// prng is a tiny deterministic generator (xorshift64): the tests want the same
// "random" inputs on every run, and nothing here is security relevant.
type prng struct{ state uint64 }

func (p *prng) Intn(n int) int {
	p.state ^= p.state << 13
	p.state ^= p.state >> 7
	p.state ^= p.state << 17
	return int(p.state%(1<<31)) % n
}

// safeChar reports whether c may appear in an accepted URL or name.
func safeChar(c rune) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("./:_~-", c)
}
