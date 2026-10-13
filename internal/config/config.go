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
	"os"
	"path/filepath"
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
}

// Public is the public listener: CRL now, OCSP, AIA and ACME later (ADR-08).
type Public struct {
	// Listen is IP:port; empty disables the listener.
	Listen string `yaml:"listen"`
}

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

	if len(errs) > 0 {
		return fmt.Errorf("%w:\n  %w", ErrInvalid, joinIndented(errs))
	}
	return nil
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
