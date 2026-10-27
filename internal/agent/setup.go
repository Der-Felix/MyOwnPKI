package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/Der-Felix/MyOwnPKI/deploy"
	agentv1 "github.com/Der-Felix/MyOwnPKI/internal/gen/myownpki/agent/v1"
)

const (
	DefaultSetupExampleDir = "/usr/share/myownpki-agent/examples"
	maxSetupRootSize       = 1 << 20
	maxSetupTokenSize      = 16 << 10
)

// SetupOptions are the local inputs of myownpki-agent setup.
type SetupOptions struct {
	Server        string
	CABundle      string
	RootSHA256    string
	TokenFile     string
	Webroot       string
	LowPorts      bool
	Hostname      string
	ConfigPath    string
	StateDir      string
	UnitPath      string
	DropinDir     string
	ExampleDir    string
	Version       string
	PackageFormat string
	Stdout        io.Writer
	Stderr        io.Writer
}

type setupAgent interface {
	Enroll(context.Context, string) (*Result, error)
	Poll(context.Context) (*Result, error)
	Status() Status
}

type setupRunner interface {
	Run(context.Context, ...string) error
}

type setupExecRunner struct{}

func (setupExecRunner) Run(ctx context.Context, args ...string) error {
	cmd := exec.CommandContext(ctx, "systemctl", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

var (
	setupPlatformCheck             = platformSetupPreflight
	setupSystemd       setupRunner = setupExecRunner{}
	setupNewAgent                  = func(cfg *Config, stderr io.Writer, version string) (setupAgent, error) {
		return New(cfg, slog.New(slog.NewTextHandler(stderr, nil)), version)
	}
	setupHostname = func() (string, error) {
		if out, err := exec.Command("hostname", "-f").Output(); err == nil { // #nosec G204 -- fixed executable and arguments
			if hostname := strings.TrimSpace(string(out)); hostname != "" && hostname != "localhost" {
				return hostname, nil
			}
		}
		return os.Hostname()
	}
)

type setupPlan struct {
	cfg         *Config
	configData  []byte
	rootData    []byte
	token       string
	newConfig   bool
	unitData    []byte
	lowPortData []byte
	needLowPort bool
}

// Setup installs local configuration and units, enrolls, and only then enables
// or starts the service. It never changes host state before preflight succeeds.
func Setup(ctx context.Context, opts SetupOptions) error {
	if opts.Stdout == nil {
		opts.Stdout = io.Discard
	}
	if opts.Stderr == nil {
		opts.Stderr = io.Discard
	}
	if opts.PackageFormat == "" {
		opts.PackageFormat = "tarball"
	}
	if opts.PackageFormat != "deb" && opts.PackageFormat != "rpm" && opts.PackageFormat != "tarball" {
		return errors.New("--package-format must be deb, rpm or tarball")
	}
	plan, err := prepareSetup(opts)
	if err != nil {
		return err
	}
	if err = setupPlatformCheck(); err != nil {
		return err
	}

	configPath := opts.ConfigPath
	if configPath == "" {
		configPath = DefaultConfigPath
	}
	stateDir := plan.cfg.StateDir
	// #nosec G301 G703 -- root chooses the standard system configuration path.
	if err = os.MkdirAll(filepath.Dir(configPath), 0o755); err != nil {
		return fmt.Errorf("create configuration directory: %w", err)
	}
	// #nosec G703 -- state_dir was validated as an absolute local path.
	if err = os.MkdirAll(stateDir, 0o700); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}
	// #nosec G302 G703 -- the validated private state directory is intentionally owner-only.
	if err = os.Chmod(stateDir, 0o700); err != nil {
		return fmt.Errorf("set state directory mode: %w", err)
	}
	if err = atomicSetupFile(filepath.Join(stateDir, packageFormatFile), []byte(opts.PackageFormat+"\n"), 0o600); err != nil {
		return err
	}
	if err = atomicSetupFile(plan.cfg.CABundle, plan.rootData, 0o600); err != nil {
		return err
	}
	if plan.configData != nil {
		if err = atomicSetupFile(configPath, plan.configData, 0o644); err != nil {
			return err
		}
	}
	unitPath := opts.UnitPath
	if unitPath == "" {
		unitPath = "/etc/systemd/system/myownpki-agent.service"
	}
	dropinDir := opts.DropinDir
	if dropinDir == "" {
		dropinDir = unitPath + ".d"
	}
	if err = atomicSetupFile(unitPath, plan.unitData, 0o644); err != nil {
		return err
	}
	// #nosec G301 G703 -- root chooses the standard systemd drop-in directory.
	if err = os.MkdirAll(dropinDir, 0o755); err != nil {
		return fmt.Errorf("create unit drop-in directory: %w", err)
	}
	paths := "[Service]\nReadWritePaths=" + strings.Join(append([]string{stateDir}, plan.cfg.Paths...), " ") + "\n"
	if err = atomicSetupFile(filepath.Join(dropinDir, "10-paths.conf"), []byte(paths), 0o644); err != nil {
		return err
	}
	lowPorts := filepath.Join(dropinDir, "20-low-ports.conf")
	if plan.needLowPort {
		if err = atomicSetupFile(lowPorts, plan.lowPortData, 0o644); err != nil {
			return err
		}
	} else if removeErr := os.Remove(lowPorts); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
		return fmt.Errorf("remove unused low-ports drop-in: %w", removeErr)
	}
	if err = setupSystemd.Run(ctx, "daemon-reload"); err != nil {
		return err
	}

	enrollCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	a, err := setupNewAgent(plan.cfg, opts.Stderr, opts.Version)
	if err != nil {
		return err
	}
	status := a.Status()
	newlyAdmitted := false
	var res *Result
	switch {
	case status.Enrolled:
		res = &Result{State: agentv1.EnrollState_ENROLL_STATE_ADMITTED, AgentID: status.AgentID}
	case status.Enrollment != "":
		res, err = a.Poll(enrollCtx)
	default:
		res, err = a.Enroll(enrollCtx, plan.token)
		newlyAdmitted = err == nil && res != nil && res.Admitted()
	}
	if err != nil {
		return err
	}
	if res == nil {
		return errors.New("enrollment state disappeared; run setup again")
	}
	switch {
	case res.Admitted():
		if newlyAdmitted && opts.TokenFile != "" {
			if err := os.Remove(opts.TokenFile); err != nil {
				return fmt.Errorf("delete consumed token file: %w", err)
			}
		}
		if err := setupSystemd.Run(ctx, "enable", "myownpki-agent.service"); err != nil {
			return err
		}
		if err := setupSystemd.Run(ctx, "restart", "myownpki-agent.service"); err != nil {
			return err
		}
		_, _ = fmt.Fprintf(opts.Stdout, "Agent %s is enrolled; myownpki-agent is enabled and running.\n", res.AgentID)
		return nil
	case res.State == agentv1.EnrollState_ENROLL_STATE_DENIED, res.State == agentv1.EnrollState_ENROLL_STATE_EXPIRED:
		return fmt.Errorf("enrollment ended: %s", res.Message)
	default:
		if err := setupSystemd.Run(ctx, "disable", "myownpki-agent.service"); err != nil {
			return err
		}
		_, _ = fmt.Fprintf(opts.Stdout, "Enrollment is pending: %s\nThe service remains disabled. After approval run: systemctl enable --now myownpki-agent\n", res.Message)
		return nil
	}
}

func prepareSetup(opts SetupOptions) (*setupPlan, error) {
	if opts.Server == "" {
		return nil, errors.New("--server is required")
	}
	u, err := url.Parse(opts.Server)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || strings.Trim(u.Path, "/") != "" || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("--server must be https://host[:port] without a path")
	}
	expected, err := normalizeRootSHA256(opts.RootSHA256)
	if err != nil {
		return nil, err
	}
	if opts.CABundle == "" {
		return nil, errors.New("--ca-bundle is required")
	}
	rootData, err := readSetupRegular(opts.CABundle, maxSetupRootSize, false)
	if err != nil {
		return nil, fmt.Errorf("read root certificate: %w", err)
	}
	rootData, err = verifiedRoot(rootData, expected)
	if err != nil {
		return nil, err
	}
	token := ""
	if opts.TokenFile != "" {
		data, readErr := readSetupRegular(opts.TokenFile, maxSetupTokenSize, true)
		if readErr != nil {
			return nil, fmt.Errorf("read token file: %w", readErr)
		}
		token = strings.TrimSpace(string(data))
		if token == "" {
			return nil, errors.New("token file is empty")
		}
	}
	if opts.Webroot != "" {
		if !filepath.IsAbs(opts.Webroot) || filepath.Clean(opts.Webroot) == string(filepath.Separator) {
			return nil, errors.New("--webroot must be an absolute directory other than /")
		}
		st, statErr := os.Stat(opts.Webroot)
		if statErr != nil || !st.IsDir() {
			return nil, errors.New("--webroot must name an existing directory")
		}
	}
	unitData, err := setupAsset(opts.ExampleDir, "unit", "myownpki-agent.service")
	if err != nil {
		return nil, err
	}
	lowPortData, err := setupAsset(opts.ExampleDir, "low-ports", "agent-low-ports.conf")
	if err != nil {
		return nil, err
	}
	example, err := setupAsset(opts.ExampleDir, "agent.yaml", "agent.yaml")
	if err != nil {
		return nil, err
	}
	configPath := opts.ConfigPath
	if configPath == "" {
		configPath = DefaultConfigPath
	}
	stateDir := opts.StateDir
	if stateDir == "" {
		stateDir = DefaultStateDir
	}
	plan := &setupPlan{token: token, rootData: rootData, unitData: unitData, lowPortData: lowPortData}
	current, err := os.ReadFile(configPath)
	switch {
	case err == nil:
		if bytes.Equal(current, example) {
			plan.newConfig = true
		} else {
			plan.cfg, err = ParseConfig(configPath, current)
			if err != nil {
				return nil, err
			}
		}
	case errors.Is(err, os.ErrNotExist):
		plan.newConfig = true
	default:
		return nil, fmt.Errorf("read existing configuration: %w", err)
	}
	if plan.newConfig {
		hostname := opts.Hostname
		if hostname == "" {
			hostname, err = setupHostname()
			if err != nil {
				return nil, fmt.Errorf("determine host name: %w", err)
			}
		}
		hostname = strings.TrimSuffix(strings.ToLower(hostname), ".")
		challenge, webroot := ChallengeStandalone, ""
		var paths []string
		if opts.Webroot != "" {
			challenge, webroot = ChallengeWebroot, opts.Webroot
			paths = []string{opts.Webroot}
		}
		cfg := &Config{Server: opts.Server, CABundle: filepath.Join(filepath.Dir(configPath), "root.pem"), Hostname: hostname,
			StateDir: stateDir, LogLevel: "info", Enrollment: Enrollment{Challenge: challenge, Webroot: webroot}, Paths: paths}
		if err := cfg.Validate(); err != nil {
			return nil, fmt.Errorf("generated configuration: %w", err)
		}
		plan.cfg = cfg
		plan.configData = renderSetupConfig(cfg)
	} else {
		plan.cfg.CABundle = filepath.Clean(plan.cfg.CABundle)
		installedRoot, err := readSetupRegular(plan.cfg.CABundle, maxSetupRootSize, false)
		if err != nil {
			return nil, fmt.Errorf("read configured root certificate: %w", err)
		}
		installedRoot, err = verifiedRoot(installedRoot, expected)
		if err != nil {
			return nil, fmt.Errorf("configured root certificate: %w", err)
		}
		plan.rootData = installedRoot
		if opts.Webroot != "" || opts.LowPorts || opts.Server != plan.cfg.Server {
			_, _ = fmt.Fprintln(opts.Stderr, "Existing agent.yaml is preserved; edit it by hand to change server or enrollment settings.")
		}
	}
	plan.needLowPort = opts.LowPorts || plan.cfg.Enrollment.Challenge == ChallengeStandalone
	return plan, nil
}

func renderSetupConfig(cfg *Config) []byte {
	var b strings.Builder
	b.WriteString("# Written by myownpki-agent setup; this file is preserved on later runs.\n")
	fmt.Fprintf(&b, "server: %q\nca_bundle: %q\nhostname: %q\nstate_dir: %q\nlog_level: \"info\"\n", cfg.Server, cfg.CABundle, cfg.Hostname, cfg.StateDir)
	fmt.Fprintf(&b, "enrollment:\n  challenge: %q\n", cfg.Enrollment.Challenge)
	if cfg.Enrollment.Webroot != "" {
		fmt.Fprintf(&b, "  webroot: %q\n", cfg.Enrollment.Webroot)
	}
	fmt.Fprintf(&b, "paths: [")
	for i, path := range cfg.Paths {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "%q", path)
	}
	b.WriteString("]\ndeployments: []\n")
	return []byte(b.String())
}

func normalizeRootSHA256(value string) ([]byte, error) {
	normalized := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(value), ":", ""))
	if len(normalized) != sha256.Size*2 {
		return nil, errors.New("--root-sha256 must contain exactly 32 bytes of hexadecimal SHA-256")
	}
	decoded, err := hex.DecodeString(normalized)
	if err != nil {
		return nil, errors.New("--root-sha256 must contain only hexadecimal digits and optional colons")
	}
	return decoded, nil
}

func verifiedRoot(data []byte, expected []byte) ([]byte, error) {
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("root file must contain exactly one PEM CERTIFICATE and no trailing data")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse root certificate: %w", err)
	}
	if !cert.BasicConstraintsValid || !cert.IsCA {
		return nil, errors.New("root certificate is not a CA")
	}
	if err := cert.CheckSignatureFrom(cert); err != nil {
		return nil, errors.New("root certificate is not self-signed")
	}
	actual := sha256.Sum256(cert.Raw)
	if !bytes.Equal(actual[:], expected) {
		return nil, fmt.Errorf("root certificate SHA-256 mismatch: got %X", actual)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), nil
}

func readSetupRegular(path string, limit int64, secret bool) ([]byte, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	if secret && runtime.GOOS != "windows" && st.Mode().Perm() != 0o600 {
		return nil, errors.New("permissions must be exactly 0600")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("file exceeds %d bytes", limit)
	}
	return data, nil
}

func setupAsset(dir, key, name string) ([]byte, error) {
	if dir != "" {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, fmt.Errorf("read packaged setup asset %s: %w", name, err)
		}
		return data, nil
	}
	packaged := filepath.Join(DefaultSetupExampleDir, name)
	if data, err := os.ReadFile(packaged); err == nil {
		return data, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read packaged setup asset %s: %w", name, err)
	}
	return deploy.AgentExample(key)
}

func atomicSetupFile(path string, data []byte, mode os.FileMode) error {
	// #nosec G703 -- callers pass validated local configuration or fixed systemd paths.
	if current, readErr := os.ReadFile(path); readErr == nil && bytes.Equal(current, data) {
		return os.Chmod(path, mode)
	}
	// #nosec G301 G703 -- system configuration directories are intentionally 0755.
	if mkdirErr := os.MkdirAll(filepath.Dir(path), 0o755); mkdirErr != nil {
		return fmt.Errorf("create parent of %s: %w", path, mkdirErr)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".setup-*")
	if err != nil {
		return fmt.Errorf("create temporary file for %s: %w", path, err)
	}
	tmpName := tmp.Name()
	// #nosec G703 -- tmpName comes from CreateTemp in the validated destination directory.
	defer func() { _ = os.Remove(tmpName) }()
	if chmodErr := tmp.Chmod(mode); chmodErr != nil {
		_ = tmp.Close()
		return fmt.Errorf("set temporary file mode for %s: %w", path, chmodErr)
	}
	if _, writeErr := tmp.Write(data); writeErr != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temporary file for %s: %w", path, writeErr)
	}
	if syncErr := tmp.Sync(); syncErr != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temporary file for %s: %w", path, syncErr)
	}
	if closeErr := tmp.Close(); closeErr != nil {
		return fmt.Errorf("close temporary file for %s: %w", path, closeErr)
	}
	// #nosec G703 -- atomically replace the validated local destination.
	if renameErr := os.Rename(tmpName, path); renameErr != nil {
		return fmt.Errorf("replace %s: %w", path, renameErr)
	}
	return nil
}
