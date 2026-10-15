package config

import (
	"fmt"
	"slices"
	"strings"
)

// EnvPrefix starts every environment variable this package reads.
const EnvPrefix = "MYOWNPKI_"

// EnvConfigFile names the config file when --config is not given.
const EnvConfigFile = EnvPrefix + "CONFIG"

// envFields maps each override variable to the field it sets. The names are
// the YAML path in upper case with "_" for ".".
func envFields(c *Config) map[string]*string {
	return map[string]*string{
		EnvPrefix + "DATA_DIR":               &c.DataDir,
		EnvPrefix + "LOG_LEVEL":              &c.Log.Level,
		EnvPrefix + "LOG_FORMAT":             &c.Log.Format,
		EnvPrefix + "ADMIN_LISTEN":           &c.Admin.Listen,
		EnvPrefix + "ADMIN_TLS_CERT_FILE":    &c.Admin.TLSCertFile,
		EnvPrefix + "ADMIN_TLS_KEY_FILE":     &c.Admin.TLSKeyFile,
		EnvPrefix + "ADMIN_TLS_NAMES":        &c.Admin.TLSNames,
		EnvPrefix + "ADMIN_ALLOWED_NETWORKS": &c.Admin.AllowedNetworks,
		EnvPrefix + "PUBLIC_LISTEN":          &c.Public.Listen,
		EnvPrefix + "AUTH_KEY_FILE":          &c.Auth.KeyFile,
		EnvPrefix + "AUTH_TRUSTED_PROXIES":   &c.Auth.TrustedProxies,
	}
}

// otherEnv lists MYOWNPKI_* variables that are valid but are not config
// overrides, so they are not reported as typos.
var otherEnv = []string{
	EnvConfigFile,
	EnvPrefix + "BROWSER", // task screenshots (dev tool)
}

// ApplyEnv applies MYOWNPKI_* overrides from environ (os.Environ format) and
// returns the names it applied, sorted. An unknown MYOWNPKI_* variable is an
// error: a typo would otherwise be ignored silently. An empty value is applied
// as well, so MYOWNPKI_PUBLIC_LISTEN= disables the public listener.
func (c *Config) ApplyEnv(environ []string) ([]string, error) {
	fields := envFields(c)
	var applied, unknown []string
	for _, kv := range environ {
		name, value, _ := strings.Cut(kv, "=")
		if !strings.HasPrefix(name, EnvPrefix) || slices.Contains(otherEnv, name) {
			continue
		}
		field, ok := fields[name]
		if !ok {
			unknown = append(unknown, name)
			continue
		}
		*field = value
		applied = append(applied, name)
	}
	slices.Sort(applied)
	if len(unknown) > 0 {
		slices.Sort(unknown)
		return applied, fmt.Errorf("%w: unknown environment variable %s (known: %s)",
			ErrInvalid, strings.Join(unknown, ", "), strings.Join(EnvNames(), ", "))
	}
	return applied, nil
}

// DefaultPath is the config file used when neither --config nor
// MYOWNPKI_CONFIG is given: %ProgramData%\MyOwnPKI\config.yaml on Windows,
// /etc/myownpki/config.yaml elsewhere. getenv is os.Getenv in production.
func DefaultPath(goos string, getenv func(string) string) string {
	if goos == "windows" {
		base := getenv("ProgramData")
		if base == "" {
			base = `C:\ProgramData`
		}
		return base + `\MyOwnPKI\config.yaml`
	}
	return "/etc/myownpki/config.yaml"
}

// EnvNames returns the override variables, sorted.
func EnvNames() []string {
	var c Config
	names := make([]string, 0, 8)
	for name := range envFields(&c) {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}
