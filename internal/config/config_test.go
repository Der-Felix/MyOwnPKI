package config

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// absDir returns an absolute directory valid on the test's OS.
func absDir(t *testing.T) string {
	t.Helper()
	return t.TempDir()
}

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestExampleFileIsValid(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile(filepath.Join("..", "..", "deploy", "config.example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := Parse("config.example.yaml", data)
	if err != nil {
		t.Fatal(err)
	}
	// The example documents the defaults; only data_dir has none.
	want := Default()
	want.DataDir = "/var/lib/myownpki"
	if cfg != want {
		t.Errorf("example differs from the defaults:\n got %+v\nwant %+v", cfg, want)
	}
	cfg.DataDir = absDir(t) // /var/lib/... is not absolute on Windows
	if err := cfg.Validate(); err != nil {
		t.Error(err)
	}
}

func TestParseIsStrict(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, yaml, wantErr string
	}{
		{"unknown key", "data_dir: /x\nlisten: :9443\n", "field listen not found"},
		{"unknown nested key", "admin:\n  port: 9443\n", "field port not found"},
		{"typo in key", "log:\n  lvel: debug\n", "field lvel not found"},
		{"dev mode", "dev: true\n", "dev mode is a command-line flag"},
		{"dev mode, other case", "DEV: true\n", "dev mode is a command-line flag"},
		{"two documents", "log:\n  level: info\n---\nlog:\n  level: debug\n", "only one YAML document"},
		{"empty file", "", "file is empty"},
		{"wrong type", "admin: 9443\n", "cannot unmarshal"},
		{"too large", "# " + strings.Repeat("x", MaxFileSize) + "\n", "larger than"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := Parse("test.yaml", []byte(tt.yaml))
			if err == nil || !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("err = %v, want ErrInvalid containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestParseKeepsDefaults(t *testing.T) {
	t.Parallel()
	cfg, err := Parse("test.yaml", []byte("data_dir: /srv/pki\nlog:\n  level: debug\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Log.Level != "debug" || cfg.Log.Format != "json" || cfg.Admin.Listen != "127.0.0.1:9443" {
		t.Errorf("defaults not kept: %+v", cfg)
	}
}

func TestValidate(t *testing.T) {
	t.Parallel()
	dir := absDir(t)
	cert, key := filepath.Join(dir, "admin.crt"), filepath.Join(dir, "admin.key")
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr string // "" = valid
	}{
		{"defaults with data_dir", func(*Config) {}, ""},
		{"all interfaces IPv6", func(c *Config) { c.Admin.Listen = "[::]:9443" }, ""},
		{"operator certificate", func(c *Config) { c.Admin.TLSCertFile, c.Admin.TLSKeyFile = cert, key }, ""},
		{"public listener off", func(c *Config) { c.Public.Listen = "" }, ""},
		{"same port, different IPs", func(c *Config) { c.Admin.Listen, c.Public.Listen = "127.0.0.1:8080", "192.0.2.1:8080" }, ""},
		{"missing data_dir", func(c *Config) { c.DataDir = "" }, "data_dir: required"},
		{"relative data_dir", func(c *Config) { c.DataDir = "data" }, "data_dir: must be an absolute path"},
		{"log level", func(c *Config) { c.Log.Level = "verbose" }, "log.level"},
		{"log format", func(c *Config) { c.Log.Format = "xml" }, "log.format"},
		{"host name", func(c *Config) { c.Admin.Listen = "localhost:9443" }, "host must be an IP address"},
		{"no port", func(c *Config) { c.Admin.Listen = "127.0.0.1" }, "want IP:port"},
		{"port 0", func(c *Config) { c.Admin.Listen = "127.0.0.1:0" }, "port must be 1-65535"},
		{"port too high", func(c *Config) { c.Public.Listen = ":70000" }, "port must be 1-65535"},
		{"zone", func(c *Config) { c.Admin.Listen = "[fe80::1%eth0]:9443" }, "host must be an IP address"},
		{"cert without key", func(c *Config) { c.Admin.TLSCertFile = cert }, "set both or neither"},
		{"relative cert", func(c *Config) { c.Admin.TLSCertFile, c.Admin.TLSKeyFile = "admin.crt", key }, "tls_cert_file: must be an absolute path"},
		{"same address", func(c *Config) { c.Public.Listen = "127.0.0.1:9443" }, "collides with admin.listen"},
		{"all interfaces vs loopback", func(c *Config) { c.Public.Listen = ":9443" }, "collides with admin.listen"},
		{"IPv4-mapped IPv6", func(c *Config) { c.Public.Listen = "[::ffff:127.0.0.1]:9443" }, "collides with admin.listen"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := Default()
			cfg.DataDir = dir
			tt.mutate(&cfg)
			err := cfg.Validate()
			switch {
			case tt.wantErr == "" && err != nil:
				t.Errorf("unexpected error: %v", err)
			case tt.wantErr != "" && (err == nil || !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), tt.wantErr)):
				t.Errorf("err = %v, want ErrInvalid containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestValidateReportsAllProblems(t *testing.T) {
	t.Parallel()
	cfg := Config{Log: Log{Level: "loud", Format: "xml"}, Admin: Admin{Listen: "x"}}
	err := cfg.Validate()
	for _, want := range []string{"data_dir", "log.level", "log.format", "admin.listen"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %s: %v", want, err)
		}
	}
}

func TestApplyEnv(t *testing.T) {
	t.Parallel()
	cfg := Default()
	applied, err := cfg.ApplyEnv([]string{
		"PATH=/usr/bin",
		"MYOWNPKI_ADMIN_LISTEN=0.0.0.0:9443",
		"MYOWNPKI_PUBLIC_LISTEN=", // empty value disables the listener
		"MYOWNPKI_CONFIG=/etc/myownpki/config.yaml",
		"MYOWNPKI_BROWSER=/usr/bin/chromium",
		"MYOWNPKI_LOG_LEVEL=debug=x", // value may contain "="
	})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"MYOWNPKI_ADMIN_LISTEN", "MYOWNPKI_LOG_LEVEL", "MYOWNPKI_PUBLIC_LISTEN"}; !slices.Equal(applied, want) {
		t.Errorf("applied = %v, want %v", applied, want)
	}
	if cfg.Admin.Listen != "0.0.0.0:9443" || cfg.Public.Listen != "" || cfg.Log.Level != "debug=x" {
		t.Errorf("overrides not applied: %+v", cfg)
	}
}

func TestApplyEnvRejectsUnknown(t *testing.T) {
	t.Parallel()
	cfg := Default()
	_, err := cfg.ApplyEnv([]string{"MYOWNPKI_ADMIN_LISTN=0.0.0.0:9443", "MYOWNPKI_DEV=1"})
	if err == nil || !errors.Is(err, ErrInvalid) ||
		!strings.Contains(err.Error(), "MYOWNPKI_ADMIN_LISTN, MYOWNPKI_DEV") ||
		!strings.Contains(err.Error(), "MYOWNPKI_ADMIN_LISTEN") {
		t.Errorf("err = %v", err)
	}
}

func TestEveryFieldHasAnEnvVariable(t *testing.T) {
	t.Parallel()
	// Setting every variable to a marker must reach every string field.
	var env []string
	for _, name := range EnvNames() {
		env = append(env, name+"=marker")
	}
	var cfg Config
	if _, err := cfg.ApplyEnv(env); err != nil {
		t.Fatal(err)
	}
	all := Config{DataDir: "marker", Log: Log{"marker", "marker"}, Admin: Admin{"marker", "marker", "marker", "marker", "marker"}, Public: Public{"marker"},
		Auth: Auth{"marker", "marker", "marker"}, ACME: ACME{"marker", "marker", "marker", "marker"}}
	if cfg != all {
		t.Errorf("not every field is reachable from the environment: %+v", cfg)
	}
}

func TestLoad(t *testing.T) {
	t.Parallel()
	dir := absDir(t)
	// Double-quoted YAML: backslashes of Windows paths must be escaped.
	path := writeConfig(t, "data_dir: \""+strings.ReplaceAll(dir, `\`, `\\`)+"\"\n")

	cfg, src, err := Load(path, []string{"MYOWNPKI_LOG_FORMAT=text"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DataDir != dir || cfg.Log.Format != "text" || src.File != path || !slices.Equal(src.Env, []string{"MYOWNPKI_LOG_FORMAT"}) {
		t.Errorf("cfg = %+v, src = %+v", cfg, src)
	}

	if _, _, err := Load(path, []string{"MYOWNPKI_LOG_FORMAT=xml"}); err == nil || !strings.Contains(err.Error(), "log.format") {
		t.Errorf("invalid override accepted: %v", err)
	}
	if _, _, err := Load(filepath.Join(dir, "missing.yaml"), nil); err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("missing file: %v", err)
	}
}

func TestAuthSettings(t *testing.T) {
	t.Parallel()
	cfg := Default()
	cfg.DataDir = absDir(t)
	if got := cfg.AuthKeyFile(); got != filepath.Join(cfg.DataDir, "auth.key") {
		t.Errorf("default key file: %s", got)
	}
	got, err := ParseNetworks(" 10.0.0.5, 192.168.1.0/24,fd00::/8 ,::ffff:10.0.0.7")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"10.0.0.5/32", "192.168.1.0/24", "fd00::/8", "10.0.0.7/32"}
	for i, p := range got {
		if i >= len(want) || p.String() != want[i] {
			t.Errorf("proxies: %v, want %v", got, want)
			break
		}
	}
	for in, msg := range map[string]string{
		"10.0.0.1/8":          "did you mean 10.0.0.0/8",
		"proxy.lan":           "is not an IP or CIDR",
		"fe80::1%eth0":        "is not an IP or CIDR",
		"::ffff:10.0.0.0/104": "write IPv4 networks as IPv4",
	} {
		if _, err := ParseNetworks(in); err == nil || !strings.Contains(err.Error(), msg) {
			t.Errorf("%q: %v, want %q", in, err, msg)
		}
	}
	cfg.Auth = Auth{KeyFile: "auth.key", TrustedProxies: "10.0.0.1/8"}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "auth.key_file: must be an absolute path") ||
		!strings.Contains(err.Error(), "auth.trusted_proxies") {
		t.Errorf("validate: %v", err)
	}
}

func TestAdminTLSNamesAndAllowlist(t *testing.T) {
	t.Parallel()
	names, ips, err := ParseTLSNames(" pki.homelab.lan, 192.0.2.5 ,::ffff:10.0.0.1, ca01")
	if err != nil || strings.Join(names, ",") != "pki.homelab.lan,ca01" || len(ips) != 2 || ips[1].String() != "10.0.0.1" {
		t.Errorf("tls names: %v %v %v", names, ips, err)
	}
	for _, bad := range []string{"*.homelab.lan", "PKI.lan", "-x.lan", "a..b", "fe80::1%eth0", "host_name"} {
		if _, _, err := ParseTLSNames(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	cfg := Default()
	cfg.DataDir = absDir(t)
	cfg.Admin.AllowedNetworks, cfg.Admin.TLSNames = "10.0.0.1/8", "*.lan"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "admin.allowed_networks") || !strings.Contains(err.Error(), "admin.tls_names") {
		t.Errorf("validate: %v", err)
	}
}

func TestPasskeyRPID(t *testing.T) {
	t.Parallel()
	for origin, want := range map[string]string{
		"": "", "https://PKI.homelab.lan:9443": "pki.homelab.lan", "https://pki.homelab.lan": "pki.homelab.lan",
		"http://localhost:9443": "localhost",
	} {
		if got, err := PasskeyRPID(origin); err != nil || got != want {
			t.Errorf("%q: %q %v", origin, got, err)
		}
	}
	for _, bad := range []string{"http://pki.homelab.lan", "https://192.0.2.10:9443", "https://pki.homelab.lan/ui", "pki.homelab.lan", "https://user@pki.lan", "https://pki.lan?x=1"} {
		if _, err := PasskeyRPID(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// TestExampleFileHasEveryKey: every setting is in the example – a new key
// must not be left undocumented (auth.passkey_origin was, until step 20).
func TestExampleFileHasEveryKey(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile(filepath.Join("..", "..", "deploy", "config.example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{}
	for k, v := range doc {
		sub, ok := v.(map[string]any)
		if !ok {
			have[EnvPrefix+strings.ToUpper(k)] = true
			continue
		}
		for kk := range sub {
			have[EnvPrefix+strings.ToUpper(k+"_"+kk)] = true
		}
	}
	for _, name := range EnvNames() {
		if !have[name] {
			t.Errorf("deploy/config.example.yaml lacks the key of %s", name)
		}
	}
}

// TestDockerFiles: the container config is valid, and the Dockerfile matches
// it (ports, data directory) and pins one base image for both stages.
func TestDockerFiles(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile(filepath.Join("..", "..", "deploy", "docker", "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := Parse("config.yaml", data)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DataDir != "/var/lib/myownpki" || cfg.Admin.Listen != "0.0.0.0:9443" || cfg.Public.Listen != "0.0.0.0:8080" {
		t.Errorf("container config: %+v", cfg)
	}
	cfg.DataDir = absDir(t)
	if verr := cfg.Validate(); verr != nil {
		t.Error(verr)
	}
	df, err := os.ReadFile(filepath.Join("..", "..", "deploy", "docker", "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	text := strings.ReplaceAll(string(df), "\r\n", "\n")
	for _, want := range []string{"EXPOSE 9443 8080", `VOLUME ["/var/lib/myownpki"]`, " /var/lib/myownpki\n", `CMD ["/usr/local/bin/myownpki", "healthcheck"]`} {
		if !strings.Contains(text, want) {
			t.Errorf("Dockerfile lacks %q", want)
		}
	}
	const base = "gcr.io/distroless/static-debian12:nonroot@sha256:"
	if n := strings.Count(text, base); n != 2 || strings.Count(text, "gcr.io/") != 2 {
		t.Errorf("the Dockerfile must name the pinned base image twice (FROM and COPY --from), found %d", n)
	}
}

// TestACMEConfig (PHASE2, owner Q1): off without a base URL, https only,
// its own port, a valid resolver and trusted proxies.
func TestACMEConfig(t *testing.T) {
	t.Parallel()
	base := Default()
	base.DataDir = absDir(t)
	if err := base.Validate(); err != nil || base.ACME.BaseURL != "" || base.ACME.Listen != "127.0.0.1:8081" {
		t.Fatalf("defaults: %v %+v", err, base.ACME)
	}
	for name, tc := range map[string]struct {
		mod  func(*Config)
		want string
	}{
		"http base URL":   {func(c *Config) { c.ACME.BaseURL = "http://pki.homelab.lan/acme" }, "must be https://"},
		"query":           {func(c *Config) { c.ACME.BaseURL = "https://pki.homelab.lan/acme?x=1" }, "want https://host"},
		"no host":         {func(c *Config) { c.ACME.BaseURL = "https:///acme" }, "want https://host"},
		"public port":     {func(c *Config) { c.ACME.Listen = "0.0.0.0:8080" }, "public CRL port"},
		"admin port":      {func(c *Config) { c.ACME.Listen = "127.0.0.1:9443" }, "collides with admin.listen"},
		"host name":       {func(c *Config) { c.ACME.Listen = "localhost:8081" }, "acme.listen"},
		"bad proxy":       {func(c *Config) { c.ACME.TrustedProxies = "10.0.0.1/8" }, "acme.trusted_proxies"},
		"bad resolver":    {func(c *Config) { c.ACME.Resolver = "dns.homelab.lan" }, "acme.resolver"},
		"resolver port 0": {func(c *Config) { c.ACME.Resolver = "10.0.0.53:0" }, "acme.resolver"},
	} {
		c := base
		tc.mod(&c)
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
	good := base
	good.ACME.BaseURL, good.ACME.Resolver = "https://pki.homelab.lan/acme/", "192.0.2.53"
	if err := good.Validate(); err != nil {
		t.Error(err)
	}
	if u, _ := ACMEBaseURL(good.ACME.BaseURL); u != "https://pki.homelab.lan/acme" {
		t.Errorf("base URL %q", u)
	}
	if r, _ := ACMEResolver(good.ACME.Resolver); r != "192.0.2.53:53" {
		t.Errorf("resolver %q", r)
	}
}
