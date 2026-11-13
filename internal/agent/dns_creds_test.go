package agent

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// sentinel stands for a real token; none of the tests may find it, or any
// spelling of it, in an output.
const sentinel = "SENTINEL-s3cr3t-t0k3n-0123456789"

var sentinelB64 = base64.StdEncoding.EncodeToString([]byte("SENTINEL-tsig-key-bytes"))

// credsDir is a directory the credentials checks accept (mode 0700).
func credsDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "dns")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

// credsFile writes a credentials file of mode 0600.
func credsFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(credsDir(t), "homelab.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func credsErr(t *testing.T, err error, state string) *credentialsError {
	t.Helper()
	var ce *credentialsError
	if !errors.As(err, &ce) {
		t.Fatalf("want a credentialsError %q, got %v", state, err)
	}
	if ce.State != state {
		t.Fatalf("state %q (%s), want %q", ce.State, ce.Detail, state)
	}
	return ce
}

// wantCredsState checks the state of a credentials error.
func wantCredsState(t *testing.T, err error, state string) {
	t.Helper()
	_ = credsErr(t, err, state)
}

func TestLoadDNSCredentialsCloudflare(t *testing.T) {
	t.Parallel()
	c, err := loadDNSCredentials(credsFile(t, "api_token: "+sentinel+"\n"), DNSTypeCloudflare)
	if err != nil {
		t.Fatal(err)
	}
	if string(c.APIToken.reveal()) != sentinel || c.ZoneToken.isSet() || c.Type != DNSTypeCloudflare {
		t.Fatalf("parsed %+v", c)
	}
	c, err = loadDNSCredentials(credsFile(t, "# split token\napi_token: \""+sentinel+"\"\nzone_token: 'zone-"+sentinel+"'\n"), DNSTypeCloudflare)
	if err != nil {
		t.Fatal(err)
	}
	if string(c.APIToken.reveal()) != sentinel || string(c.ZoneToken.reveal()) != "zone-"+sentinel {
		t.Fatalf("parsed %+v", c)
	}
	c.wipe()
	if c.APIToken.isSet() || c.ZoneToken.isSet() {
		t.Fatal("wipe left a value")
	}
}

func TestLoadDNSCredentialsRFC2136(t *testing.T) {
	t.Parallel()
	for name, tt := range map[string]struct{ alg, want string }{
		"default":    {"", "hmac-sha256"},
		"sha256":     {"tsig_algorithm: hmac-sha256\n", "hmac-sha256"},
		"sha384":     {"tsig_algorithm: hmac-sha384\n", "hmac-sha384"},
		"sha512":     {"tsig_algorithm: HMAC-SHA512\n", "hmac-sha512"},
		"quoted":     {"tsig_algorithm: \"hmac-sha256\"\n", "hmac-sha256"},
		"with space": {"tsig_algorithm:   hmac-sha384   \n", "hmac-sha384"},
	} {
		c, err := loadDNSCredentials(credsFile(t, "tsig_key_name: acme-agent\ntsig_secret: "+sentinelB64+"\n"+tt.alg), DNSTypeRFC2136)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if c.TSIGKeyName != "acme-agent" || c.TSIGAlgorithm != tt.want || string(c.TSIGSecret.reveal()) != sentinelB64 || c.APIToken.isSet() {
			t.Errorf("%s: parsed %+v", name, c)
		}
	}
}

func TestLoadDNSCredentialsRefusals(t *testing.T) {
	t.Parallel()
	long := "api_token: " + strings.Repeat("x", 4096-len("api_token: ")-1) + "\n"
	tests := []struct {
		name, typ, content, want string // want: a substring of the detail
	}{
		{"empty file", DNSTypeCloudflare, "", "the file is empty"},
		{"comment only", DNSTypeCloudflare, "# nothing\n", "the file is empty"},
		{"a bare value", DNSTypeCloudflare, sentinel + "\n", "must be a mapping"},
		{"a list", DNSTypeCloudflare, "- " + sentinel + "\n", "must be a mapping"},
		{"two documents", DNSTypeCloudflare, "api_token: a\n---\napi_token: b\n", "one YAML document"},
		{"broken YAML", DNSTypeCloudflare, "api_token: [" + sentinel + "\n", "not valid YAML"},
		{"unknown key", DNSTypeCloudflare, "api_token: " + sentinel + "\nbase_url: https://example.test\n", `unknown key "base_url"`},
		{"misspelled key", DNSTypeCloudflare, "api_tokne: " + sentinel + "\n", `unknown key "api_tokne"`},
		{"key of the other type", DNSTypeCloudflare, "tsig_key_name: k\ntsig_secret: " + sentinelB64 + "\n", `unknown key "tsig_key_name"`},
		{"key of the other type, rfc2136", DNSTypeRFC2136, "api_token: " + sentinel + "\n", `unknown key "api_token"`},
		{"a secret as a key", DNSTypeCloudflare, "\"" + sentinel + "\": x\n", "an unknown key"},
		{"duplicate key", DNSTypeCloudflare, "api_token: a\napi_token: b\n", ""},
		{"missing token", DNSTypeCloudflare, "zone_token: " + sentinel + "\n", "api_token: required"},
		{"missing key name", DNSTypeRFC2136, "tsig_secret: " + sentinelB64 + "\n", "tsig_key_name: required"},
		{"missing secret", DNSTypeRFC2136, "tsig_key_name: k\n", "tsig_secret: required"},
		{"empty token", DNSTypeCloudflare, "api_token: \"\"\n", "api_token: the value is empty"},
		{"null token", DNSTypeCloudflare, "api_token:\n", "api_token: the value is empty"},
		{"explicit null", DNSTypeCloudflare, "api_token: null\n", "the value is empty"},
		{"blank token", DNSTypeCloudflare, "api_token: \"   \"\n", "the value is empty"},
		{"empty optional token", DNSTypeCloudflare, "api_token: " + sentinel + "\nzone_token: \"\"\n", "zone_token: the value is empty"},
		{"token with a space", DNSTypeCloudflare, "api_token: \"" + sentinel + " " + sentinel + "\"\n", "white space"},
		{"token with a newline", DNSTypeCloudflare, "api_token: \"" + sentinel + "\\n" + sentinel + "\"\n", "white space"},
		{"a map as value", DNSTypeCloudflare, "api_token:\n  inner: " + sentinel + "\n", "the value must be text"},
		{"a list as value", DNSTypeCloudflare, "api_token: [" + sentinel + "]\n", "the value must be text"},
		{"an alias", DNSTypeCloudflare, "zone_token: &a " + sentinel + "\napi_token: *a\n", "anchors, aliases"},
		{"an anchor", DNSTypeCloudflare, "api_token: &a " + sentinel + "\n", "anchors, aliases"},
		{"a merge key", DNSTypeCloudflare, "<<: {api_token: " + sentinel + "}\n", "unknown key"},
		{"secret not base64", DNSTypeRFC2136, "tsig_key_name: k\ntsig_secret: " + sentinel + "\n", "not valid base64"},
		{"secret decodes to nothing", DNSTypeRFC2136, "tsig_key_name: k\ntsig_secret: \"====\"\n", "not valid base64"},
		{"md5", DNSTypeRFC2136, "tsig_key_name: k\ntsig_secret: " + sentinelB64 + "\ntsig_algorithm: hmac-md5\n", "hmac-md5 and hmac-sha1 are refused"},
		{"sha1", DNSTypeRFC2136, "tsig_key_name: k\ntsig_secret: " + sentinelB64 + "\ntsig_algorithm: hmac-sha1\n", "hmac-md5 and hmac-sha1 are refused"},
		{"algorithm holds a secret", DNSTypeRFC2136, "tsig_key_name: k\ntsig_secret: " + sentinelB64 + "\ntsig_algorithm: " + sentinel + "\n", "tsig_algorithm"},
		{"key name with a slash", DNSTypeRFC2136, "tsig_key_name: a/b\ntsig_secret: " + sentinelB64 + "\n", "tsig_key_name"},
		{"too large", DNSTypeCloudflare, long + "# " + strings.Repeat("y", 10) + "\n", "more than 4096 bytes"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := loadDNSCredentials(credsFile(t, tt.content), tt.typ)
			if err == nil {
				t.Fatal("accepted")
			}
			state := credInvalid
			if tt.name == "too large" {
				state = credTooLarge
			}
			ce := credsErr(t, err, state)
			if !strings.Contains(ce.Detail, tt.want) {
				t.Fatalf("detail %q lacks %q", ce.Detail, tt.want)
			}
			for _, leak := range []string{sentinel, sentinelB64, "SENTINEL"} {
				if strings.Contains(err.Error(), leak) {
					t.Fatalf("the error contains the content: %v", err)
				}
			}
		})
	}
}

func TestLoadDNSCredentialsSizeLimit(t *testing.T) {
	t.Parallel()
	fill := "api_token: " + strings.Repeat("x", 4096-len("api_token: ")-1) + "\n"
	if len(fill) != maxCredentialsSize {
		t.Fatalf("fixture is %d bytes", len(fill))
	}
	if _, err := loadDNSCredentials(credsFile(t, fill), DNSTypeCloudflare); err != nil {
		t.Fatalf("exactly 4 KiB: %v", err)
	}
	_, err := loadDNSCredentials(credsFile(t, fill+"#"), DNSTypeCloudflare)
	wantCredsState(t, err, credTooLarge)
}

func TestLoadDNSCredentialsFileStates(t *testing.T) {
	t.Parallel()
	dir := credsDir(t)
	_, err := loadDNSCredentials(filepath.Join(dir, "nope.yaml"), DNSTypeCloudflare)
	wantCredsState(t, err, credMissing)
	_, err = loadDNSCredentials(dir, DNSTypeCloudflare)
	wantCredsState(t, err, credNotRegular)
	_, err = loadDNSCredentials(filepath.Join(dir, "x.yaml"), "route53")
	wantCredsState(t, err, credInvalid)
	_, err = loadDNSCredentials(filepath.Join(t.TempDir(), "missing-dir", "x.yaml"), DNSTypeCloudflare)
	wantCredsState(t, err, credMissing)
}

// Every way Go prints a value shows [redacted] and never a byte of it.
func TestSecretNeverPrints(t *testing.T) {
	t.Parallel()
	c, err := loadDNSCredentials(credsFile(t, "api_token: "+sentinel+"\nzone_token: "+sentinel+"-zone\n"), DNSTypeCloudflare)
	if err != nil {
		t.Fatal(err)
	}
	r, err := loadDNSCredentials(credsFile(t, "tsig_key_name: acme-agent\ntsig_secret: "+sentinelB64+"\n"), DNSTypeRFC2136)
	if err != nil {
		t.Fatal(err)
	}
	type holder struct { // an unexported field: fmt cannot call methods on it
		creds  dnsCredentials
		token  secret
		inner  *dnsCredentials
		parent map[string]secret
	}
	type exported struct {
		Creds dnsCredentials
		Token secret
		Plain []secret
	}
	h := holder{*c, c.APIToken, c, map[string]secret{"k": c.APIToken}}
	e := exported{*c, c.APIToken, []secret{c.APIToken, c.ZoneToken}}
	values := map[string]any{
		"secret": c.APIToken, "secret pointer": &c.APIToken, "zone": c.ZoneToken, "tsig": r.TSIGSecret,
		"credentials": *c, "credentials pointer": c, "rfc2136": r, "holder": h, "holder pointer": &h, "exported": e,
		"slice": []secret{c.APIToken}, "map": map[string]secret{"k": c.APIToken}, "array": [1]secret{c.APIToken},
		"any in any": []any{c.APIToken, c},
	}
	leaks := []string{sentinel, "SENTINEL", sentinelB64, hex.EncodeToString([]byte(sentinel)), hex.EncodeToString([]byte("SENTINEL")), "83 69 78 84 73 78 69 76", "U0VOVElORUw"}
	for name, v := range values {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%T%v", "%10.3v", "%-20s"} {
			out := fmt.Sprintf(verb, v)
			for _, leak := range leaks {
				if strings.Contains(out, leak) {
					t.Errorf("%s with %s contains %q: %s", name, verb, leak, out)
				}
			}
		}
		out := fmt.Sprint(v) + fmt.Sprintln(v)
		if strings.Contains(out, "SENTINEL") {
			t.Errorf("%s: Sprint leaks: %s", name, out)
		}
	}
	for _, s := range []secret{c.APIToken, c.ZoneToken, r.TSIGSecret, {}} {
		if s.String() != redacted || fmt.Sprintf("%v|%+v|%#v|%s|%q", s, s, s, s, s) != strings.Join([]string{redacted, redacted, redacted, redacted, redacted}, "|") {
			t.Errorf("a secret prints %q", fmt.Sprintf("%v|%+v|%#v|%s|%q", s, s, s, s, s))
		}
	}
	if got := fmt.Sprintf("%v %+v %#v", *c, *c, c); !strings.Contains(got, "secrets redacted") {
		t.Errorf("credentials print %q", got)
	}
}

func TestSecretNeverReachesJSONYAMLOrSlog(t *testing.T) {
	t.Parallel()
	c, err := loadDNSCredentials(credsFile(t, "api_token: "+sentinel+"\nzone_token: "+sentinel+"-zone\n"), DNSTypeCloudflare)
	if err != nil {
		t.Fatal(err)
	}
	type report struct {
		Provider string `json:"provider"`
		Token    secret `json:"token"`
		Creds    *dnsCredentials
		Tokens   map[string]secret
	}
	rep := report{"homelab-dns", c.APIToken, c, map[string]secret{"zone": c.ZoneToken}}

	out, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(out, []byte("SENTINEL")) || !bytes.Contains(out, []byte(redacted)) {
		t.Fatalf("JSON: %s", out)
	}
	if out, err = json.MarshalIndent(c, "", " "); err != nil || bytes.Contains(out, []byte("SENTINEL")) {
		t.Fatalf("JSON of credentials: %s %v", out, err)
	}
	if out, err = yaml.Marshal(map[string]any{"token": c.APIToken, "c": c, "r": rep}); err != nil || bytes.Contains(out, []byte("SENTINEL")) {
		t.Fatalf("YAML: %s %v", out, err)
	}
	if text, merr := c.APIToken.MarshalText(); merr != nil || bytes.Contains(text, []byte("SENTINEL")) {
		t.Fatalf("text: %s %v", text, merr)
	}

	for name, newHandler := range map[string]func(*bytes.Buffer) slog.Handler{
		"text": func(b *bytes.Buffer) slog.Handler {
			return slog.NewTextHandler(b, &slog.HandlerOptions{Level: slog.LevelDebug})
		},
		"json": func(b *bytes.Buffer) slog.Handler {
			return slog.NewJSONHandler(b, &slog.HandlerOptions{Level: slog.LevelDebug})
		},
	} {
		var buf bytes.Buffer
		log := slog.New(newHandler(&buf)).With(slog.Any("token", c.APIToken))
		log.Info("loaded", slog.Any("creds", c), slog.Any("value", *c), slog.Any("zone", c.ZoneToken),
			slog.Group("g", slog.Any("t", c.APIToken)), slog.Any("report", rep), slog.Any("map", map[string]secret{"k": c.APIToken}),
			slog.String("printed", fmt.Sprintf("%v", c)))
		log.Error("failed", slog.Any("error", c.redact(fmt.Errorf("401 for Bearer %s", sentinel))))
		if strings.Contains(buf.String(), "SENTINEL") || !strings.Contains(buf.String(), redacted) {
			t.Errorf("%s log: %s", name, buf.String())
		}
	}
}

func TestRedact(t *testing.T) {
	t.Parallel()
	c, err := loadDNSCredentials(credsFile(t, "api_token: "+sentinel+"\nzone_token: zone-"+sentinel+"\n"), DNSTypeCloudflare)
	if err != nil {
		t.Fatal(err)
	}
	if redact(nil, c.APIToken) != nil {
		t.Fatal("nil became an error")
	}
	cause := errors.New("cloudflare: 403 for Bearer " + sentinel + ", zone token zone-" + sentinel + ", again " + sentinel)
	for name, err := range map[string]error{
		"plain":     cause,
		"wrapped":   fmt.Errorf("deployment %q: %w", "wild", cause),
		"joined":    errors.Join(errors.New("first"), cause),
		"formatted": errors.New(cause.Error()),
	} {
		got := c.redact(err)
		for _, verb := range []string{"%v", "%+v", "%s", "%q"} {
			if text := fmt.Sprintf(verb, got); strings.Contains(text, "SENTINEL") {
				t.Errorf("%s %s: %s", name, verb, text)
			}
		}
		if !strings.Contains(got.Error(), "Bearer "+redacted) || !strings.Contains(got.Error(), "zone token "+redacted) {
			t.Errorf("%s: %q", name, got)
		}
		if errors.Unwrap(got) != nil {
			t.Errorf("%s: the redacted error offers its unredacted cause", name)
		}
	}
	// The redacted error still matches what it was.
	marker := errors.New("marker")
	var target *credentialsError
	got := c.redact(fmt.Errorf("%w: %s", marker, sentinel))
	if !errors.Is(got, marker) || errors.Is(got, errors.New("marker")) {
		t.Fatalf("errors.Is: %v", got)
	}
	got = c.redact(fmt.Errorf("x: %w", &credentialsError{State: credInvalid, Path: "p", Detail: sentinel}))
	if !errors.As(got, &target) || target.State != credInvalid || strings.Contains(got.Error(), "SENTINEL") {
		t.Fatalf("errors.As: %v", got)
	}
	// An unset secret and an unrelated text change nothing.
	if text := redactText("plain text", secret{}, newSecret(nil)); text != "plain text" {
		t.Fatalf("redactText: %q", text)
	}
	c.wipe()
	if text := redactText("token "+sentinel, c.APIToken); text != "token "+sentinel {
		t.Fatalf("a wiped secret holds nothing, so it redacts nothing: %q", text)
	}
}

func TestSecretWipeReachesEveryCopy(t *testing.T) {
	t.Parallel()
	buf := []byte("never-printed")
	s := newSecret(buf)
	copyOfS := s
	buf[0] = 'X' // newSecret copied: the caller's buffer is independent
	if string(s.reveal()) != "never-printed" {
		t.Fatal("newSecret kept the caller's slice")
	}
	raw := s.reveal()
	s.wipe()
	if copyOfS.isSet() || !bytes.Equal(raw, make([]byte, len(raw))) {
		t.Fatalf("wipe left %q", raw)
	}
	var zero secret
	zero.wipe() // must not panic
	if zero.isSet() || zero.reveal() != nil {
		t.Fatal("the zero secret holds a value")
	}
}

func TestDNSProviderStatuses(t *testing.T) {
	t.Parallel()
	dir := credsDir(t)
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	c := &Config{
		DNSProviders: map[string]DNSProvider{
			"good":    {Type: DNSTypeCloudflare, CredentialsFile: write("good.yaml", "api_token: "+sentinel+"\n")},
			"missing": {Type: DNSTypeRFC2136, CredentialsFile: filepath.Join(dir, "missing.yaml")},
			"broken":  {Type: DNSTypeCloudflare, CredentialsFile: write("broken.yaml", "api_tokne: "+sentinel+"\n")},
			"spare":   {Type: DNSTypeCloudflare, CredentialsFile: write("spare.yaml", "api_token: "+sentinel+"\n")},
		},
		Deployments: []Deployment{
			{Name: "a", Challenge: ChallengeDNS01, DNSProvider: "good"},
			{Name: "b", Challenge: ChallengeDNS01, DNSProvider: "good"},
			{Name: "c", Challenge: ChallengeDNS01, DNSProvider: "missing"},
			{Name: "d", Challenge: ChallengeDNS01, DNSProvider: "broken"},
			{Name: "e", Challenge: ChallengeStandalone},
		},
	}
	got := c.DNSProviderStatuses()
	want := []struct {
		name, state string
		users       []string
	}{
		{"broken", credInvalid, []string{"d"}}, {"good", credOK, []string{"a", "b"}}, {"missing", credMissing, []string{"c"}}, {"spare", credOK, nil},
	}
	if len(got) != len(want) {
		t.Fatalf("statuses %+v", got)
	}
	for i, w := range want {
		s := got[i]
		if s.Name != w.name || s.State != w.state || strings.Join(s.Users, ",") != strings.Join(w.users, ",") || s.OK() != (w.state == credOK) {
			t.Errorf("status %d: %+v, want %+v", i, s, w)
		}
		if strings.Contains(fmt.Sprintf("%+v", s), "SENTINEL") {
			t.Errorf("status %d leaks: %+v", i, s)
		}
	}
	if got[0].Type != DNSTypeCloudflare || got[2].Path != filepath.Join(dir, "missing.yaml") {
		t.Errorf("type or path missing: %+v", got)
	}
}
