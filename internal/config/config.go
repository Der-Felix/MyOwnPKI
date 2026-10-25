// Package config loads the server configuration: one YAML file, decoded
// strictly, plus MYOWNPKI_* environment overrides (go-conventions.md
// "Configuration", PLAN §14).
//
// Rules:
//   - Unknown keys, a second YAML document and files over MaxFileSize are errors.
//   - Unknown MYOWNPKI_* variables are errors too: a typo must not be ignored.
//   - Dev mode is a command-line flag (serve --dev), never a config key.
//   - No secrets: the unseal passphrase is never read from a file or variable.
//
// Load returns a validated Config or an error that names every problem.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

// MaxFileSize limits the config file; a real one is a few hundred bytes.
const MaxFileSize = 64 << 10

// ErrInvalid is wrapped by every error about a malformed or inconsistent configuration.
var ErrInvalid = errors.New("invalid configuration")

// Config is the server configuration. Field order is the order of the example file.
type Config struct {
	// DataDir holds system.db and the tenant directories. Absolute path.
	DataDir string `yaml:"data_dir"`
	Log     Log    `yaml:"log"`
	Admin   Admin  `yaml:"admin"`
	Public  Public `yaml:"public"`
	Auth    Auth   `yaml:"auth"`
	ACME    ACME   `yaml:"acme"`
	Agent   Agent  `yaml:"agent"`
}

// Log configures the process log (not the audit log).
type Log struct {
	Level  string `yaml:"level"`  // debug, info, warn, error
	Format string `yaml:"format"` // json (production) or text
}

// Admin is the admin listener: web UI and REST API (ADR-08).
type Admin struct {
	// Listen is IP:port; an empty IP means all interfaces.
	Listen string `yaml:"listen"`
	// TLSCertFile and TLSKeyFile name an operator-provided certificate. Both
	// empty: a self-signed bootstrap certificate is created (PLAN §5).
	TLSCertFile string `yaml:"tls_cert_file"`
	TLSKeyFile  string `yaml:"tls_key_file"`
	// TLSNames are further DNS names or IPs (comma-separated) for the
	// bootstrap certificate, besides the host name, the listen IP and
	// loopback – the names admins type into the browser. With TLSIssuer they
	// are exactly the names of the issued certificate.
	TLSNames string `yaml:"tls_names"`
	// TLSIssuer names a CA of this instance (v0.2.2): the server issues the
	// listener's certificate from it itself, while unsealed, and renews it.
	// Empty: the operator certificate or the bootstrap certificate.
	TLSIssuer string `yaml:"tls_issuer"`
	// AllowedNetworks limits who may connect (IPs or CIDRs, comma-separated);
	// empty: everybody. Checked against the direct peer before TLS (ADR-08).
	AllowedNetworks string `yaml:"allowed_networks"`
}

// Public is the public listener: CRL now, OCSP, AIA and ACME later (ADR-08).
type Public struct {
	// Listen is IP:port; empty disables the listener.
	Listen string `yaml:"listen"`
}

// Auth configures sign-in (PHASE1 step 10).
type Auth struct {
	// KeyFile holds the key that encrypts the TOTP secrets and keys the
	// recovery code hashes. Empty: <data_dir>/auth.key. It may live outside
	// the data directory (Docker secret, systemd credential): then a copy of
	// the databases alone holds no usable TOTP secret.
	KeyFile string `yaml:"key_file"`
	// TrustedProxies lists reverse proxies (IPs or CIDRs, comma-separated)
	// whose X-Forwarded-For header is believed. Empty: the direct peer is
	// the client – the safe default.
	TrustedProxies string `yaml:"trusted_proxies"`
	// PasskeyOrigin is the address users open the admin UI with, e.g.
	// https://pki.homelab.lan:9443 (PHASE1 step 17). Passkeys are bound to its
	// host name (the WebAuthn RP ID). Empty: no passkeys, TOTP only.
	PasskeyOrigin string `yaml:"passkey_origin"`
}

// ACME is the ACME server (PHASE2): by default plain HTTP on its own listener,
// only behind a reverse proxy that terminates TLS (owner Q1 2026-10-22); with
// TLSIssuer it speaks TLS itself (v0.2.2, owner 2026-10-24).
type ACME struct {
	// Listen is IP:port of the ACME listener – never the public CRL port, so
	// nobody talks ACME in clear text. Without TLSIssuer it is for the reverse
	// proxy only; with it, for the clients (e.g. :443).
	Listen string `yaml:"listen"`
	// BaseURL is what clients use (the proxy's https URL, e.g.
	// https://pki.homelab.lan/acme); every URL the server hands out is built
	// from it. Empty: ACME is off.
	BaseURL string `yaml:"base_url"`
	// TrustedProxies may connect to Listen (others get 403), and only their
	// X-Forwarded-For is believed (IPs or CIDRs, comma-separated). Ignored
	// with TLSIssuer: then every client connects directly and the peer is
	// the client address.
	TrustedProxies string `yaml:"trusted_proxies"`
	// Resolver is the DNS server (IP or IP:port) for dns-01 and for resolving
	// http-01 names. Empty: the system resolver.
	Resolver string `yaml:"resolver"`
	// TLSIssuer names a CA of this instance: ACME runs with TLS on Listen,
	// with a certificate for the host of BaseURL that the server issues from
	// this CA itself. Empty: plain HTTP behind a reverse proxy.
	TLSIssuer string `yaml:"tls_issuer"`
}

// DirectTLS reports whether the ACME listener speaks TLS itself.
func (a ACME) DirectTLS() bool { return a.TLSIssuer != "" }

// Agent is the agent listener (ADR-08, docs/PHASE3.md §1.4): Connect-RPC
// over mTLS for myownpki-agent. Off while BaseURL is empty.
type Agent struct {
	// BaseURL is what agents connect to, e.g. https://pki.homelab.lan:8444;
	// its host is the name in the listener certificate. Empty: no agents.
	BaseURL string `yaml:"base_url"`
	// Listen is IP:port of the agent listener – its own port, never the
	// admin, ACME or public one.
	Listen string `yaml:"listen"`
	// TLSIssuer names the CA that issues the listener certificate, as for
	// admin.tls_issuer: an intermediate, issued while unsealed.
	TLSIssuer string `yaml:"tls_issuer"`
	// CA names the agent CA: an intermediate with the EKU limit clientAuth
	// only. It signs the agents' 7-day certificates, and only certificates
	// from it pass the listener's client authentication.
	CA string `yaml:"ca"`
}

// Enabled reports whether the agent listener runs.
func (a Agent) Enabled() bool { return a.BaseURL != "" }

// Allowed values.
var (
	LogLevels  = []string{"debug", "info", "warn", "error"}
	LogFormats = []string{"json", "text"}
)

// Default returns the configuration used for every key the file leaves out.
// The admin listener binds to loopback only: remote administration is a
// deliberate decision of the operator.
func Default() Config {
	return Config{
		Log:    Log{Level: "info", Format: "json"},
		Admin:  Admin{Listen: "127.0.0.1:9443"},
		Public: Public{Listen: ":8080"},
		ACME:   ACME{Listen: "127.0.0.1:8081", TrustedProxies: "127.0.0.1, ::1"},
		Agent:  Agent{Listen: ":8444"},
	}
}

// Parse decodes a config file over the defaults. name is used in messages only.
func Parse(name string, data []byte) (Config, error) {
	cfg := Default()
	if len(data) > MaxFileSize {
		return cfg, fmt.Errorf("%s: %w: file is larger than %d bytes", name, ErrInvalid, MaxFileSize)
	}
	if err := rejectDevKey(data); err != nil {
		return cfg, fmt.Errorf("%s: %w: %w", name, ErrInvalid, err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		if errors.Is(err, io.EOF) {
			return cfg, fmt.Errorf("%s: %w: file is empty", name, ErrInvalid)
		}
		return cfg, fmt.Errorf("%s: %w: %w", name, ErrInvalid, err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return cfg, fmt.Errorf("%s: %w: only one YAML document per file is allowed", name, ErrInvalid)
	}
	return cfg, nil
}

// rejectDevKey gives "dev" at the top level a clearer message than
// "field dev not found": dev mode must never be switchable from a file.
func rejectDevKey(data []byte) error {
	// A syntax error leaves top empty; the strict decoder reports it.
	var top map[string]yaml.Node
	_ = yaml.Unmarshal(data, &top)
	for key := range top {
		if strings.EqualFold(key, "dev") || strings.EqualFold(key, "dev_mode") {
			return fmt.Errorf("key %q: dev mode is a command-line flag (myownpki serve --dev), never a config key", key)
		}
	}
	return nil
}

// Validate checks every value and returns all problems at once.
func (c Config) Validate() error {
	var errs []error
	add := func(format string, args ...any) {
		errs = append(errs, fmt.Errorf(format, args...))
	}

	switch {
	case c.DataDir == "":
		add("data_dir: required (for example /var/lib/myownpki)")
	case !filepath.IsAbs(c.DataDir):
		add("data_dir: must be an absolute path, got %q", c.DataDir)
	}
	if !slices.Contains(LogLevels, c.Log.Level) {
		add("log.level: must be one of %s, got %q", strings.Join(LogLevels, ", "), c.Log.Level)
	}
	if !slices.Contains(LogFormats, c.Log.Format) {
		add("log.format: must be one of %s, got %q", strings.Join(LogFormats, ", "), c.Log.Format)
	}

	admin, err := parseListen(c.Admin.Listen)
	if err != nil {
		add("admin.listen: %w", err)
	}
	if (c.Admin.TLSCertFile == "") != (c.Admin.TLSKeyFile == "") {
		add("admin.tls_cert_file and admin.tls_key_file: set both or neither")
	}
	if c.Admin.TLSIssuer != "" {
		if err := checkCAName(c.Admin.TLSIssuer); err != nil {
			add("admin.tls_issuer: %w", err)
		}
		if c.Admin.TLSCertFile != "" {
			add("admin.tls_issuer and admin.tls_cert_file: set one of them – a certificate the server issues itself, or your own file")
		}
		if names, ips, err := ParseTLSNames(c.Admin.TLSNames); err == nil && len(names)+len(ips) == 0 {
			add("admin.tls_issuer needs admin.tls_names: the names of the issued certificate (the names admins type into the browser)")
		}
	}
	for key, file := range map[string]string{"admin.tls_cert_file": c.Admin.TLSCertFile, "admin.tls_key_file": c.Admin.TLSKeyFile} {
		if file != "" && !filepath.IsAbs(file) {
			add("%s: must be an absolute path, got %q", key, file)
		}
	}

	if c.Public.Listen != "" {
		public, err := parseListen(c.Public.Listen)
		switch {
		case err != nil:
			add("public.listen: %w", err)
		case admin.valid && overlaps(admin, public):
			add("public.listen: %q collides with admin.listen %q", c.Public.Listen, c.Admin.Listen)
		}
	}

	if c.Auth.KeyFile != "" && !filepath.IsAbs(c.Auth.KeyFile) {
		add("auth.key_file: must be an absolute path, got %q", c.Auth.KeyFile)
	}
	if _, err := ParseNetworks(c.Admin.AllowedNetworks); err != nil {
		add("admin.allowed_networks: %w", err)
	}
	if _, _, err := ParseTLSNames(c.Admin.TLSNames); err != nil {
		add("admin.tls_names: %w", err)
	}
	if _, err := ParseNetworks(c.Auth.TrustedProxies); err != nil {
		add("auth.trusted_proxies: %w", err)
	}
	if _, err := PasskeyRPID(c.Auth.PasskeyOrigin); err != nil {
		add("auth.passkey_origin: %w", err)
	}
	c.validateACME(admin, add)
	c.validateAgent(add)

	if len(errs) > 0 {
		return fmt.Errorf("%w:\n  %w", ErrInvalid, joinIndented(errs))
	}
	return nil
}

// AuthKeyFile returns the path of the auth key: auth.key_file or
// <data_dir>/auth.key.
func (c Config) AuthKeyFile() string {
	if c.Auth.KeyFile != "" {
		return c.Auth.KeyFile
	}
	return filepath.Join(c.DataDir, "auth.key")
}

// ParseNetworks parses a comma-separated list of IPs and CIDRs (trusted
// proxies, the admin allowlist). A single IP
// becomes a /32 or /128. Zones and host bits in a CIDR are refused – a typo
// like 10.0.0.1/8 must not silently trust a whole network.
func ParseNetworks(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for item := range strings.SplitSeq(s, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if strings.Contains(item, "/") {
			p, err := netip.ParsePrefix(item)
			if err != nil {
				return nil, fmt.Errorf("%q is not an IP or CIDR", item)
			}
			if p != p.Masked() {
				return nil, fmt.Errorf("%q has host bits set – did you mean %s?", item, p.Masked())
			}
			if p.Addr().Is4In6() {
				return nil, fmt.Errorf("%q: write IPv4 networks as IPv4 (for example 10.0.0.0/8)", item)
			}
			out = append(out, p)
			continue
		}
		ip, err := netip.ParseAddr(item)
		if err != nil || ip.Zone() != "" {
			return nil, fmt.Errorf("%q is not an IP or CIDR", item)
		}
		ip = ip.Unmap()
		out = append(out, netip.PrefixFrom(ip, ip.BitLen()))
	}
	return out, nil
}

func joinIndented(errs []error) error {
	lines := make([]string, len(errs))
	for i, e := range errs {
		lines[i] = e.Error()
	}
	return errors.New(strings.Join(lines, "\n  "))
}

type listenAddr struct {
	ip    netip.Addr // invalid = all interfaces
	port  uint16
	valid bool
}

// parseListen accepts IP:port or :port. Host names are rejected: what a name
// resolves to can change, the interface a listener binds to must not.
func parseListen(s string) (listenAddr, error) {
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return listenAddr{}, fmt.Errorf("want IP:port or :port, got %q", s)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil || port == 0 {
		return listenAddr{}, fmt.Errorf("port must be 1-65535, got %q", portStr)
	}
	l := listenAddr{port: uint16(port), valid: true}
	if host != "" {
		ip, err := netip.ParseAddr(host)
		if err != nil || ip.Zone() != "" {
			return listenAddr{}, fmt.Errorf("host must be an IP address or empty (all interfaces), got %q", host)
		}
		if !ip.IsUnspecified() {
			l.ip = ip.Unmap()
		}
	}
	return l, nil
}

// overlaps reports whether two listeners would fight over the same socket.
func overlaps(a, b listenAddr) bool {
	if a.port != b.port {
		return false
	}
	return !a.ip.IsValid() || !b.ip.IsValid() || a.ip == b.ip
}

// Source describes where the configuration came from, for `config check`.
type Source struct {
	File string   // the config file that was read
	Env  []string // MYOWNPKI_* variables that overrode a value, sorted
}

// Load reads the file at path, applies the environment and validates the result.
func Load(path string, environ []string) (Config, Source, error) {
	src := Source{File: path}
	data, err := readLimited(path)
	if err != nil {
		return Config{}, src, err
	}
	cfg, err := Parse(path, data)
	if err != nil {
		return cfg, src, err
	}
	src.Env, err = cfg.ApplyEnv(environ)
	if err != nil {
		return cfg, src, err
	}
	if err := cfg.Validate(); err != nil {
		return cfg, src, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, src, nil
}

func readLimited(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("config file %s does not exist (choose one with --config or MYOWNPKI_CONFIG)", path)
		}
		return nil, fmt.Errorf("read config: %w", err)
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, MaxFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	return data, nil
}

// ParseTLSNames splits admin.tls_names into DNS names and IPs. DNS names are
// LDH labels in lower case (a wildcard is not allowed: the bootstrap
// certificate names exactly the hosts admins use).
func ParseTLSNames(s string) ([]string, []netip.Addr, error) {
	var names []string
	var ips []netip.Addr
	for item := range strings.SplitSeq(s, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if ip, err := netip.ParseAddr(item); err == nil {
			if ip.Zone() != "" {
				return nil, nil, fmt.Errorf("%q: an IP with a zone can't be in a certificate", item)
			}
			ips = append(ips, ip.Unmap())
			continue
		}
		if !validDNSName(item) {
			return nil, nil, fmt.Errorf("%q is neither an IP nor a DNS name (lower case letters, digits, hyphens, dots)", item)
		}
		names = append(names, item)
	}
	return names, ips, nil
}

func validDNSName(s string) bool {
	if len(s) > 253 {
		return false
	}
	for label := range strings.SplitSeq(s, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	return true
}

// PasskeyRPID checks auth.passkey_origin and returns its host name, the
// WebAuthn RP ID ("" when passkeys are off). Browsers allow WebAuthn only
// in a secure context: https, or http on localhost.
func PasskeyRPID(origin string) (string, error) {
	if origin == "" {
		return "", nil
	}
	u, err := url.Parse(origin)
	switch {
	case err != nil:
		return "", fmt.Errorf("%q is not a URL", origin)
	case u.Host == "" || u.Hostname() == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "":
		return "", fmt.Errorf("%q: want only scheme, host and port, e.g. https://pki.homelab.lan:9443", origin)
	case u.Scheme == "https":
	case u.Scheme == "http" && u.Hostname() == "localhost":
	default:
		return "", fmt.Errorf("%q: passkeys need https (browsers allow plain http only for localhost)", origin)
	}
	if net.ParseIP(u.Hostname()) != nil {
		return "", fmt.Errorf("%q: passkeys need a host name, not an IP address (WebAuthn RP ID)", origin)
	}
	return strings.ToLower(u.Hostname()), nil
}

// validateACME checks the acme section. An empty base URL switches ACME off;
// then the other keys are still checked, so a typo shows before it matters.
func (c Config) validateACME(admin listenAddr, add func(string, ...any)) {
	if c.ACME.BaseURL != "" {
		if _, err := ACMEBaseURL(c.ACME.BaseURL); err != nil {
			add("acme.base_url: %w", err)
		}
	}
	if c.ACME.TLSIssuer != "" {
		if err := checkCAName(c.ACME.TLSIssuer); err != nil {
			add("acme.tls_issuer: %w", err)
		}
		if c.ACME.BaseURL == "" {
			add("acme.tls_issuer needs acme.base_url: its host is the name in the certificate")
		}
	}
	acme, err := parseListen(c.ACME.Listen)
	switch {
	case err != nil:
		add("acme.listen: %w", err)
	case admin.valid && overlaps(admin, acme):
		add("acme.listen: %q collides with admin.listen %q", c.ACME.Listen, c.Admin.Listen)
	default:
		if public, perr := parseListen(c.Public.Listen); c.Public.Listen != "" && perr == nil && overlaps(public, acme) {
			add("acme.listen: %q collides with public.listen %q – ACME must not share the public CRL port", c.ACME.Listen, c.Public.Listen)
		}
	}
	if _, err := ParseNetworks(c.ACME.TrustedProxies); err != nil {
		add("acme.trusted_proxies: %w", err)
	}
	if _, err := ACMEResolver(c.ACME.Resolver); err != nil {
		add("acme.resolver: %w", err)
	}
}

// validateAgent checks the agent section: with base_url, tls_issuer and ca
// are required and the listener needs a port of its own.
func (c Config) validateAgent(add func(string, ...any)) {
	a := c.Agent
	if !a.Enabled() {
		for _, kv := range [][2]string{{"agent.tls_issuer", a.TLSIssuer}, {"agent.ca", a.CA}} {
			if kv[1] != "" {
				add("%s needs agent.base_url: without it the agent listener is off", kv[0])
			}
		}
		return
	}
	if _, err := AgentBaseURL(a.BaseURL); err != nil {
		add("agent.base_url: %w", err)
	}
	for _, kv := range [][2]string{{"agent.tls_issuer", a.TLSIssuer}, {"agent.ca", a.CA}} {
		if kv[1] == "" {
			add("%s: required with agent.base_url", kv[0])
		} else if err := checkCAName(kv[1]); err != nil {
			add("%s: %w", kv[0], err)
		}
	}
	if a.CA != "" && a.CA == a.TLSIssuer {
		add("agent.ca and agent.tls_issuer: the agent CA signs only agents' client certificates – name another CA as tls_issuer")
	}
	l, err := parseListen(a.Listen)
	if err != nil {
		add("agent.listen: %w", err)
		return
	}
	for _, kv := range [][2]string{{"admin.listen", c.Admin.Listen}, {"public.listen", c.Public.Listen}, {"acme.listen", c.ACME.Listen}} {
		if kv[0] == "acme.listen" && c.ACME.BaseURL == "" {
			continue
		}
		if o, perr := parseListen(kv[1]); kv[1] != "" && perr == nil && overlaps(l, o) {
			add("agent.listen: %q collides with %s %q – the agent listener needs a port of its own", a.Listen, kv[0], kv[1])
		}
	}
}

// AgentBaseURL checks agent.base_url: https://host[:port], no path.
func AgentBaseURL(s string) (string, error) {
	u, err := url.Parse(s)
	switch {
	case err != nil:
		return "", fmt.Errorf("%q is not a URL", s)
	case u.Scheme != "https":
		return "", fmt.Errorf("%q: must be https:// – agents talk to the server only over mTLS", s)
	case u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || strings.Trim(u.Path, "/") != "":
		return "", fmt.Errorf("%q: want https://host[:port] without a path, e.g. https://pki.homelab.lan:8444", s)
	}
	return strings.TrimRight(s, "/"), nil
}

// AgentHost is the host of agent.base_url in lower case: the name (or IP)
// in the agent listener's certificate.
func AgentHost(base string) string { return ACMEHost(base) }

// ACMEBaseURL checks acme.base_url and returns it without a trailing slash:
// https only (the proxy terminates TLS; RFC 8555 §6.1), a host, no user,
// query or fragment.
func ACMEBaseURL(s string) (string, error) {
	u, err := url.Parse(s)
	switch {
	case err != nil:
		return "", fmt.Errorf("%q is not a URL", s)
	case u.Scheme != "https":
		return "", fmt.Errorf("%q: must be https:// – clients talk ACME only over TLS (RFC 8555 §6.1): through the reverse proxy, or directly with acme.tls_issuer", s)
	case u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "":
		return "", fmt.Errorf("%q: want https://host[:port][/path], e.g. https://pki.homelab.lan/acme", s)
	}
	return strings.TrimRight(s, "/"), nil
}

// caNamePattern is the rule for CA names (internal/ca, profile.go): the
// name a CA was created with, not its common name.
var caNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

func checkCAName(s string) error {
	if !caNamePattern.MatchString(s) {
		return fmt.Errorf("%q is not a CA name (the name the CA was created with: lower case letters, digits, '.', '_', '-')", s)
	}
	return nil
}

// ACMEHost is the host of acme.base_url in lower case: the name (or IP) in
// the certificate of the ACME listener with acme.tls_issuer.
func ACMEHost(base string) string {
	u, err := url.Parse(base)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// ACMEResolver checks acme.resolver: empty, an IP (port 53) or IP:port.
func ACMEResolver(s string) (string, error) {
	if s == "" {
		return "", nil
	}
	if ip, err := netip.ParseAddr(s); err == nil && ip.Zone() == "" {
		return netip.AddrPortFrom(ip, 53).String(), nil
	}
	ap, err := netip.ParseAddrPort(s)
	if err != nil || ap.Port() == 0 || ap.Addr().Zone() != "" {
		return "", fmt.Errorf("want an IP or IP:port of a DNS server, got %q", s)
	}
	return ap.String(), nil
}
