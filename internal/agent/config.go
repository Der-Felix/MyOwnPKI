// Package agent is myownpki-agent on a host (docs/PHASE3.md): it enrolls
// with proof of control (ADR-18), keeps its 7-day agent certificate, and –
// from block C on – gets certificates by ACME and deploys them.
//
// The agent's only source for what it deploys, where it writes and what it
// runs is its local agent.yaml: the server never sends a path, a command or
// a hook name.
package agent

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

// DefaultConfigPath and DefaultStateDir are the Linux defaults.
const (
	DefaultConfigPath = "/etc/myownpki-agent/agent.yaml"
	DefaultStateDir   = "/var/lib/myownpki-agent"
	maxConfigSize     = 1 << 20
)

// Challenge modes for http-01 (owner 2026-10-24).
const (
	ChallengeStandalone = "standalone"
	ChallengeWebroot    = "webroot"
)

// Profiles (docs/PHASE3.md step 5).
const (
	ProfileNginx = "nginx"
	ProfileFile  = "file"
)

// ErrInvalid wraps every problem of agent.yaml.
var ErrInvalid = errors.New("invalid agent configuration")

// Config is agent.yaml.
type Config struct {
	// Server is agent.base_url of the server, e.g. https://pki.homelab.lan:8444.
	Server string `yaml:"server"`
	// CABundle is the trust anchor (PEM) for the agent listener and ACME.
	CABundle string `yaml:"ca_bundle"`
	// Hostname is the FQDN the agent proves at enrollment; "" = the host's name.
	Hostname string `yaml:"hostname"`
	// ACMEDirectory is the directory URL of any ACME CA.
	ACMEDirectory string `yaml:"acme_directory"`
	// Proxy is an http(s) proxy for both connections; environment variables
	// (HTTPS_PROXY, HTTP_PROXY, NO_PROXY) are never used (owner 2026-10-24).
	Proxy string `yaml:"proxy"`
	// StateDir holds the agent's key, certificate and enrollment.
	StateDir string `yaml:"state_dir"`
	// LogLevel: debug, info, warn, error.
	LogLevel string `yaml:"log_level"`

	Enrollment  Enrollment          `yaml:"enrollment"`
	Hooks       map[string][]string `yaml:"hooks"`
	Paths       []string            `yaml:"paths"`
	Deployments []Deployment        `yaml:"deployments"`
}

// Enrollment says how the enrollment check is answered.
type Enrollment struct {
	Challenge string `yaml:"challenge"`
	Webroot   string `yaml:"webroot"`
}

// Deployment is one certificate the agent keeps in place (block C).
type Deployment struct {
	Name       string   `yaml:"name"`
	Profile    string   `yaml:"profile"`
	Names      []string `yaml:"names"`
	Challenge  string   `yaml:"challenge"`
	Webroot    string   `yaml:"webroot"`
	Dir        string   `yaml:"dir"`
	Files      Files    `yaml:"files"`
	Owner      string   `yaml:"owner"`
	Group      string   `yaml:"group"`
	KeyMode    string   `yaml:"key_mode"`
	TestHook   string   `yaml:"test_hook"`
	ReloadHook string   `yaml:"reload_hook"`
	Check      string   `yaml:"check"`
}

// Files are the targets of the file profile.
type Files struct {
	Certificate string `yaml:"certificate"`
	Chain       string `yaml:"chain"`
	Fullchain   string `yaml:"fullchain"`
	Key         string `yaml:"key"`
}

// LoadConfig reads and validates agent.yaml.
func LoadConfig(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxConfigSize+1))
	if err != nil {
		return nil, err
	}
	return ParseConfig(path, data)
}

// ParseConfig decodes and validates; name is for messages.
func ParseConfig(name string, data []byte) (*Config, error) {
	if len(data) > maxConfigSize {
		return nil, fmt.Errorf("%s: %w: larger than 1 MiB", name, ErrInvalid)
	}
	c := Config{StateDir: DefaultStateDir, LogLevel: "info", Enrollment: Enrollment{Challenge: ChallengeStandalone}}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("%s: %w: the file is empty", name, ErrInvalid)
		}
		return nil, fmt.Errorf("%s: %w: %w", name, ErrInvalid, err)
	}
	if c.Hostname == "" {
		c.Hostname, _ = os.Hostname()
	}
	c.Hostname = strings.TrimSuffix(strings.ToLower(c.Hostname), ".")
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return &c, nil
}

var (
	nameRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$`)
	hookRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
)

// Validate checks every rule of docs/PHASE3.md §1.3 and returns all
// problems at once.
func (c *Config) Validate() error {
	var errs []string
	add := func(format string, args ...any) { errs = append(errs, fmt.Sprintf(format, args...)) }

	if u, err := url.Parse(c.Server); err != nil || u.Scheme != "https" || u.Hostname() == "" || strings.Trim(u.Path, "/") != "" || u.User != nil {
		add("server: want https://host[:port] of the agent listener, e.g. https://pki.homelab.lan:8444")
	}
	if !filepath.IsAbs(c.CABundle) {
		add("ca_bundle: an absolute path to the root certificate (PEM), e.g. /etc/myownpki-agent/root.pem")
	}
	if !filepath.IsAbs(c.StateDir) {
		add("state_dir: an absolute path")
	}
	if !slices.Contains([]string{"debug", "info", "warn", "error"}, c.LogLevel) {
		add("log_level: debug, info, warn or error")
	}
	if err := checkHost(c.Hostname); err != nil {
		add("hostname: %v – set the host's fully qualified name, e.g. proxy1.homelab.lan", err)
	}
	if c.Proxy != "" {
		if u, err := url.Parse(c.Proxy); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
			add("proxy: want http://host:port or https://host:port")
		}
	}
	paths := make([]string, 0, len(c.Paths))
	for _, p := range c.Paths {
		if !filepath.IsAbs(p) || strings.Contains(filepath.ToSlash(p), "/../") || strings.HasSuffix(filepath.ToSlash(p), "/..") {
			add("paths: %q: an absolute path without ..", p)
			continue
		}
		cp := filepath.Clean(p)
		if cp == string(filepath.Separator) || cp == filepath.VolumeName(cp)+string(filepath.Separator) {
			add("paths: %q: not the whole file system", p)
			continue
		}
		paths = append(paths, cp)
	}
	c.Paths = paths
	under := func(field, p string) {
		switch {
		case !filepath.IsAbs(p):
			add("%s: %q: an absolute path", field, p)
		case slices.Contains(strings.Split(filepath.ToSlash(p), "/"), ".."):
			add("%s: %q: no .. path segments", field, p)
		case !Under(c.Paths, p):
			add("%s: %q: not under one of paths – the agent writes only there", field, p)
		default:
			if _, rerr := resolveUnder(c.Paths, p); rerr != nil {
				add("%s: %v", field, rerr)
			}
		}
	}
	for name, cmd := range c.Hooks {
		switch {
		case !hookRE.MatchString(name):
			add("hooks: %q: a name of letters, digits, '.', '_', '-'", name)
		case len(cmd) == 0 || !filepath.IsAbs(cmd[0]):
			add("hooks: %s: a command line whose first element is an absolute path, e.g. [\"/usr/sbin/nginx\", \"-t\"]", name)
		}
	}
	switch c.Enrollment.Challenge {
	case ChallengeStandalone:
	case ChallengeWebroot:
		under("enrollment.webroot", c.Enrollment.Webroot)
	default:
		add("enrollment.challenge: standalone or webroot")
	}
	if len(c.Deployments) > 0 {
		if u, err := url.Parse(c.ACMEDirectory); err != nil || u.Scheme != "https" || u.Hostname() == "" {
			add("acme_directory: the https URL of the ACME directory, e.g. https://pki.homelab.lan/acme/directory")
		}
	}
	seen := map[string]bool{}
	if len(c.Deployments) > 100 {
		add("deployments: at most 100")
	}
	seenFiles := map[string]string{}
	for i, d := range c.Deployments {
		where := fmt.Sprintf("deployments[%d]", i)
		if !nameRE.MatchString(d.Name) {
			add("%s.name: lower case letters, digits and '-', e.g. proxy", where)
		} else if seen[d.Name] {
			add("%s.name: %q twice", where, d.Name)
		}
		seen[d.Name] = true
		where = "deployment " + d.Name
		if len(d.Names) == 0 || len(d.Names) > 100 {
			add("%s: names: 1 to 100 DNS names", where)
		}
		for _, n := range d.Names {
			if err := checkHost(n); err != nil {
				add("%s: names: %q: %v", where, n, err)
			}
		}
		switch d.Challenge {
		case ChallengeStandalone:
		case ChallengeWebroot:
			under(where+": webroot", d.Webroot)
		default:
			add("%s: challenge: standalone or webroot", where)
		}
		switch d.Profile {
		case ProfileNginx:
			under(where+": dir", d.Dir)
		case ProfileFile:
			if d.Files.Key == "" || d.Files.Certificate == "" && d.Files.Fullchain == "" {
				add("%s: files: key and certificate or fullchain at least", where)
			}
			for field, p := range map[string]string{"certificate": d.Files.Certificate, "chain": d.Files.Chain, "fullchain": d.Files.Fullchain, "key": d.Files.Key} {
				if p != "" {
					under(where+": files."+field, p)
				}
			}
		default:
			add("%s: profile: nginx or file", where)
		}
		for field, h := range map[string]string{"test_hook": d.TestHook, "reload_hook": d.ReloadHook} {
			if _, ok := c.Hooks[h]; h != "" && !ok {
				add("%s: %s: %q is not under hooks", where, field, h)
			}
		}
		if d.Check != "" {
			host, port, err := net.SplitHostPort(d.Check)
			n, numErr := strconv.ParseUint(port, 10, 16)
			if err != nil || numErr != nil || n == 0 || host == "" {
				add("%s: check: host:port of the service, e.g. 127.0.0.1:443", where)
			}
		}
		f := deploymentPaths(d)
		for _, target := range []string{f.Certificate, f.Chain, f.Fullchain, f.Key} {
			if target == "" {
				continue
			}
			key := filepath.Clean(target)
			if Under([]string{c.StateDir}, key) || key == filepath.Clean(c.CABundle) {
				add("%s: target overlaps state_dir or ca_bundle", where)
			}
			if runtime.GOOS == "windows" {
				key = strings.ToLower(key)
			}
			if old, exists := seenFiles[key]; exists {
				add("%s: target file is also used by %s", where, old)
			}
			seenFiles[key] = d.Name
		}
		if d.KeyMode != "" {
			if m, err := strconv.ParseUint(d.KeyMode, 8, 32); err != nil || m&0o007 != 0 || m > 0o777 {
				add("%s: key_mode: an octal mode without rights for others, e.g. \"0600\" or \"0640\"", where)
			}
		}
	}
	if len(errs) > 0 {
		slices.Sort(errs)
		return fmt.Errorf("%w:\n  %s", ErrInvalid, strings.Join(errs, "\n  "))
	}
	return nil
}

// Under reports whether p lies in one of dirs (lexically, after Clean). At
// write time the agent also resolves symlinks (see resolveUnder).
func Under(dirs []string, p string) bool {
	p = filepath.Clean(p)
	for _, d := range dirs {
		d = filepath.Clean(d)
		if p == d || strings.HasPrefix(p, d+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// checkHost: a fully qualified DNS name, lower case.
func checkHost(h string) error {
	if net.ParseIP(h) != nil {
		return errors.New("IP identifiers are not supported by this agent release")
	}
	if len(h) == 0 || len(h) > 253 {
		return errors.New("1 to 253 characters")
	}
	labels := strings.Split(h, ".")
	if len(labels) < 2 {
		return errors.New("not fully qualified")
	}
	for _, l := range labels {
		if !nameRE.MatchString(l) {
			return fmt.Errorf("label %q: letters, digits and '-'", l)
		}
	}
	return nil
}
