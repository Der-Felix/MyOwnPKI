package agent

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// "myownpki-agent trust install|remove|status" and the "system trust" block of
// "config check" (docs/PHASE3.md §15, decision 4). The core is in trust_store.go.

// TrustOptions are the inputs of the three trust commands.
type TrustOptions struct {
	ConfigPath string
	// RootSHA256 is the pin given on the command line: required for install,
	// optional for remove and status (agent.yaml has the pin of an installed host).
	RootSHA256 string
	// NoRecord (install): do not write system_trust into agent.yaml, for a file
	// that another tool owns and renders (the Salt formula with config_source).
	NoRecord bool
	// Quiet (status): print nothing, the exit code answers.
	Quiet  bool
	Stdout io.Writer
	Stderr io.Writer
}

func (o TrustOptions) out() io.Writer {
	if o.Stdout == nil {
		return io.Discard
	}
	return o.Stdout
}

func (o TrustOptions) configPath() string {
	if o.ConfigPath == "" {
		return DefaultConfigPath
	}
	return o.ConfigPath
}

// TrustInstall puts the root of ca_bundle into the system trust store of this
// host and records the pin in agent.yaml. Root only; a second run changes nothing.
func TrustInstall(ctx context.Context, opts TrustOptions) error {
	return installTrust(ctx, trustHost(), opts)
}

// TrustRemove deletes the file again, and the key of agent.yaml.
func TrustRemove(ctx context.Context, opts TrustOptions) error {
	return removeTrust(ctx, trustHost(), opts)
}

// TrustStatus reports whether the file in the store is the pinned root. It
// writes nothing and does not need root.
func TrustStatus(opts TrustOptions) (bool, error) {
	return trustStatus(trustHost(), opts)
}

// SystemTrustCheck is the block "system trust" of "config check": the text to
// print, and false when agent.yaml and ca_bundle disagree about the root.
func SystemTrustCheck(cfg *Config) (string, bool) {
	return systemTrustCheck(trustHost(), cfg)
}

func installTrust(ctx context.Context, env trustEnv, opts TrustOptions) error {
	out := opts.out()
	if env.EUID() != 0 {
		return rootRequiredError("trust install")
	}
	fam, err := env.detect()
	if err != nil {
		return fmt.Errorf("%w; nothing was changed", err)
	}
	pin, err := normalizeRootSHA256(opts.RootSHA256)
	if err != nil {
		return err
	}
	pinHex := hex.EncodeToString(pin)
	configPath := opts.configPath()
	cfg, err := LoadConfig(configPath)
	if err != nil {
		return err
	}
	// The root is the one setup verified: read once, checked against the pin,
	// and the bytes written below are the checked ones.
	caBundle := filepath.Clean(cfg.CABundle)
	data, err := readSetupRegular(caBundle, maxSetupRootSize, false)
	if err != nil {
		return fmt.Errorf("read ca_bundle %s: %w; nothing was changed", caBundle, err)
	}
	pem, err := verifiedRoot(data, pin)
	if err != nil {
		return fmt.Errorf("ca_bundle %s: %w; nothing was changed", caBundle, err)
	}
	t, err := env.target(fam, true)
	if err != nil {
		return err
	}
	changed, err := env.installTrustFile(ctx, fam, t, pem)
	if err != nil {
		return err
	}
	if changed {
		_, _ = fmt.Fprintf(out, "Installed the root certificate (SHA-256 %s) as %s.\nRan %s.\n", pinHex, t.File, joinArgv(fam.Install))
	} else {
		_, _ = fmt.Fprintf(out, "The root certificate is already installed as %s; the file is unchanged.\nRan %s.\n", t.File, joinArgv(fam.Install))
	}
	if opts.NoRecord {
		return nil
	}
	wrote, err := editConfigFile(configPath, func(e *yamlEditor) error { return e.setSystemTrust(pinHex) })
	if err != nil {
		return fmt.Errorf("the root is installed, but agent.yaml could not record system_trust: %w; run the command again after fixing it", err)
	}
	if wrote {
		_, _ = fmt.Fprintf(out, "Recorded system_trust in %s (previous file: %s.bak).\n", configPath, filepath.Base(configPath))
	}
	return nil
}

func removeTrust(ctx context.Context, env trustEnv, opts TrustOptions) error {
	out := opts.out()
	if env.EUID() != 0 {
		return rootRequiredError("trust remove")
	}
	fam, err := env.detect()
	if err != nil {
		return fmt.Errorf("%w; nothing was changed", err)
	}
	configPath := opts.configPath()
	cfg, err := LoadConfig(configPath)
	if err != nil {
		return err
	}
	pin, pinHex, err := resolvePin(cfg, opts.RootSHA256)
	if err != nil {
		return err
	}
	if pin == nil {
		return errors.New("no pin: system_trust is not set in agent.yaml; name the root with --root-sha256 (nothing was changed)")
	}
	t, err := env.target(fam, false)
	if err != nil {
		return err
	}
	if t.Have {
		// Only the pinned root: the file name is ours, but its content might not be.
		if _, err = verifiedRoot(t.Current, pin); err != nil {
			return fmt.Errorf("%s does not hold the root with SHA-256 %s (%w); not removing it", t.File, pinHex, err)
		}
	}
	// Without the file the hook still runs, so a bundle that is stale (the file
	// was deleted by hand) is built again; the command ends with 0 then.
	if err = env.removeTrustFile(ctx, fam, t); err != nil {
		return err
	}
	switch {
	case t.NoDir:
		_, _ = fmt.Fprintf(out, "%s does not exist (the CA certificates package is not installed); nothing to remove.\n", t.Dir)
	case t.Have:
		_, _ = fmt.Fprintf(out, "Removed %s.\nRan %s.\n", t.File, joinArgv(fam.Remove))
	default:
		_, _ = fmt.Fprintf(out, "%s does not exist; nothing to remove.\nRan %s, so a stale bundle is built again.\n", t.File, joinArgv(fam.Remove))
	}
	wrote, err := editConfigFile(configPath, func(e *yamlEditor) error { e.removeSystemTrust(); return nil })
	if err != nil {
		return fmt.Errorf("the root is removed, but agent.yaml could not drop system_trust: %w; delete the key by hand", err)
	}
	if wrote {
		_, _ = fmt.Fprintf(out, "Removed system_trust from %s (previous file: %s.bak).\n", configPath, filepath.Base(configPath))
	}
	return nil
}

// resolvePin returns the pin of remove and status: the argument, or the key of
// agent.yaml. Both given and different is an error; none is a nil pin.
func resolvePin(cfg *Config, arg string) ([]byte, string, error) {
	var argPin []byte
	if arg != "" {
		var err error
		if argPin, err = normalizeRootSHA256(arg); err != nil {
			return nil, "", err
		}
	}
	var cfgPin []byte
	if cfg.SystemTrust != nil {
		cfgPin, _ = hex.DecodeString(cfg.SystemTrust.RootSHA256) // validated by ParseConfig
	}
	switch {
	case argPin != nil && cfgPin != nil && !bytes.Equal(argPin, cfgPin):
		return nil, "", fmt.Errorf("system_trust in agent.yaml names the root %s, --root-sha256 another one (%s)", hex.EncodeToString(cfgPin), hex.EncodeToString(argPin))
	case argPin != nil:
		return argPin, hex.EncodeToString(argPin), nil
	case cfgPin != nil:
		return cfgPin, hex.EncodeToString(cfgPin), nil
	}
	return nil, "", nil
}

func joinArgv(argv []string) string { return strings.Join(argv, " ") }

// trustReport is what is in the store for a pin.
type trustReport struct {
	Installed bool
	// Text is one line without the label.
	Text string
}

// inspect compares the fixed file with the pinned root. It reads, never writes.
func (e trustEnv) inspect(fam *trustFamily, pin []byte, pinHex string) (trustReport, error) {
	t, err := e.target(fam, false)
	if err != nil {
		return trustReport{}, err
	}
	install := "myownpki-agent trust install --root-sha256 " + pinHex
	switch {
	case !t.Have:
		return trustReport{Text: fmt.Sprintf("not installed (%s); as root run: %s", t.File, install)}, nil
	default:
		if _, err = verifiedRoot(t.Current, pin); err != nil {
			return trustReport{Text: fmt.Sprintf("differs: %s does not hold the pinned root (%v); as root run: %s", t.File, err, install)}, nil
		}
	}
	return trustReport{Installed: true, Text: fmt.Sprintf("installed: %s holds the root with SHA-256 %s", t.File, pinHex)}, nil
}

func trustStatus(env trustEnv, opts TrustOptions) (bool, error) {
	cfg, err := LoadConfig(opts.configPath())
	if err != nil {
		return false, err
	}
	say := func(format string, args ...any) {
		if !opts.Quiet {
			_, _ = fmt.Fprintf(opts.out(), format+"\n", args...)
		}
	}
	pin, pinHex, err := resolvePin(cfg, opts.RootSHA256)
	if err != nil {
		say("system trust: pin differs: %v", err)
		return false, nil
	}
	if pin == nil {
		say("system trust: not configured (system_trust is not set in agent.yaml)")
		return false, nil
	}
	fam, err := env.detect()
	if err != nil {
		say("system trust: %v", err)
		return false, nil
	}
	r, err := env.inspect(fam, pin, pinHex)
	if err != nil {
		say("system trust: %v", err)
		return false, nil
	}
	say("system trust: %s", r.Text)
	return r.Installed, nil
}

func systemTrustCheck(env trustEnv, cfg *Config) (string, bool) {
	const label = "  system trust  "
	if cfg.SystemTrust == nil {
		return label + "off\n", true
	}
	pin, pinHex, err := resolvePin(cfg, "")
	if err != nil || pin == nil {
		return label + "system_trust cannot be read\n", false
	}
	// Does the root that setup verified still carry the pin? A different
	// certificate means the pin is stale or ca_bundle was replaced: exit 1.
	if data, readErr := readSetupRegular(filepath.Clean(cfg.CABundle), maxSetupRootSize, false); readErr == nil {
		if _, verr := verifiedRoot(data, pin); verr != nil {
			return fmt.Sprintf("%spin differs from ca_bundle %s: %v\n", label, cfg.CABundle, verr), false
		}
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return fmt.Sprintf("%sca_bundle cannot be checked against the pin: %v\n", label, readErr), true
	}
	fam, err := env.detect()
	if err != nil {
		return fmt.Sprintf("%sconfigured (%s), but %v\n", label, pinHex, err), true
	}
	r, err := env.inspect(fam, pin, pinHex)
	if err != nil {
		return fmt.Sprintf("%s%v\n", label, err), true
	}
	return label + r.Text + "\n", true
}
