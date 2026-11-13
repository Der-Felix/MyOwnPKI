package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	good := filepath.Join(dir, "good.yaml")
	bad := filepath.Join(dir, "bad.yaml")
	state := filepath.Join(dir, "state")
	writeFile(t, good, "server: https://pki.homelab.lan:8444\nca_bundle: "+yamlPath(filepath.Join(dir, "root.pem"))+
		"\nhostname: proxy1.homelab.lan\nstate_dir: "+yamlPath(state)+"\n")
	writeFile(t, bad, "server: http://pki.homelab.lan:8444\nhostname: proxy1\nbogus: 1\n")
	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout string // prefix
		wantStderr string // substring
	}{
		{name: "version", args: []string{"--version"}, wantCode: 0, wantStdout: binary + " "},
		{name: "help", args: []string{"--help"}, wantCode: 0},
		{name: "no arguments", args: nil, wantCode: 2},
		{name: "unknown flag", args: []string{"--bogus"}, wantCode: 2},
		{name: "unknown command", args: []string{"deploy"}, wantCode: 2},
		{name: "config check", args: []string{"config", "check", "--config", good}, wantCode: 0, wantStdout: "Config file: "},
		{name: "config check of a bad file", args: []string{"config", "check", "--config", bad}, wantCode: 1, wantStderr: "field bogus not found"},
		{name: "missing file", args: []string{"status", "--config", filepath.Join(dir, "nope.yaml")}, wantCode: 1},
		{name: "enroll with extra arguments", args: []string{"enroll", "--config", good, "extra"}, wantCode: 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			if code := run(t.Context(), tt.args, &stdout, &stderr); code != tt.wantCode {
				t.Errorf("exit code = %d, want %d (stderr: %s)", code, tt.wantCode, stderr.String())
			}
			if !strings.HasPrefix(stdout.String(), tt.wantStdout) {
				t.Errorf("stdout = %q, want prefix %q", stdout.String(), tt.wantStdout)
			}
			if !strings.Contains(stderr.String(), tt.wantStderr) {
				t.Errorf("stderr = %q, want %q", stderr.String(), tt.wantStderr)
			}
		})
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// yamlPath quotes a path for YAML (Windows paths have backslashes).
func yamlPath(p string) string { return `"` + strings.ReplaceAll(p, `\`, `\\`) + `"` }

func TestConfigCheckShowsTheSandbox(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "agent.yaml")
	writeFile(t, cfg, "server: https://pki.homelab.lan:8444\nca_bundle: "+yamlPath(filepath.Join(dir, "root.pem"))+
		"\nhostname: proxy1.homelab.lan\nstate_dir: "+yamlPath(filepath.Join(dir, "state"))+"\nsandbox:\n  low_ports: false\n"+
		"enrollment:\n  challenge: standalone\n")
	var stdout, stderr bytes.Buffer
	if code := run(t.Context(), []string{"config", "check", "--config", cfg}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit code %d: %s", code, stderr.String())
	}
	for _, want := range []string{"sandbox       ReadWritePaths " + filepath.Join(dir, "state"), "20-low-ports.conf removed", "warning", "Configuration is valid."} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("config check output lacks %q:\n%s", want, stdout.String())
		}
	}
}

func TestDeploymentAndSandboxCommands(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "agent.yaml")
	original := "server: https://pki.homelab.lan:8444\nca_bundle: " + yamlPath(filepath.Join(dir, "root.pem")) +
		"\nhostname: proxy1.homelab.lan\nstate_dir: " + yamlPath(filepath.Join(dir, "state")) + "\n"
	writeFile(t, cfg, original)
	// Not root (or not Linux): the command says so and changes nothing. On a
	// Linux machine where the test runs as root the commands would really run.
	wantRefusal := "supported only on Linux"
	if runtime.GOOS == "linux" {
		if os.Geteuid() == 0 {
			t.Skip("running as root: the refusal cannot be tested")
		}
		wantRefusal = "must run as root; nothing was changed"
	}
	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout string
		wantStderr string
	}{
		{name: "list", args: []string{"deployment", "list", "--config", cfg}, wantCode: 0, wantStdout: "No deployments."},
		{name: "list needs a valid file", args: []string{"deployment", "list", "--config", filepath.Join(dir, "nope.yaml")}, wantCode: 1},
		{name: "add without a name", args: []string{"deployment", "add", "--config", cfg}, wantCode: 2},
		{name: "add with two names", args: []string{"deployment", "add", "a", "b", "--config", cfg}, wantCode: 2},
		{name: "add with an unknown flag", args: []string{"deployment", "add", "a", "--bogus"}, wantCode: 2},
		{name: "add with a bad hook", args: []string{"deployment", "add", "a", "--hook", "nginx-test=nginx -t", "--config", cfg}, wantCode: 1, wantStderr: `hook "nginx-test": the first element must be an absolute path`},
		{name: "add, flags before and after the name", args: []string{"deployment", "add", "--dir", "/etc/ssl/myownpki/a", "a", "--name", "a.homelab.lan", "--dry-run", "--config", cfg}, wantCode: 1, wantStderr: wantRefusal},
		{name: "unknown recipe", args: []string{"deployment", "add", "a", "--recipe", "apache", "--config", cfg}, wantCode: 1, wantStderr: `unknown recipe "apache" – known: dovecot, nginx, postfix, proxmox`},
		{name: "known recipe reaches the root check", args: []string{"deployment", "add", "a", "--recipe", "postfix", "--dry-run", "--config", cfg}, wantCode: 1, wantStderr: wantRefusal},
		{name: "remove without a name", args: []string{"deployment", "remove", "--config", cfg}, wantCode: 2},
		{name: "remove", args: []string{"deployment", "remove", "a", "--config", cfg}, wantCode: 1, wantStderr: wantRefusal},
		{name: "unknown deployment subcommand", args: []string{"deployment", "frobnicate"}, wantCode: 2},
		{name: "sandbox sync", args: []string{"sandbox", "sync", "--dry-run", "--config", cfg}, wantCode: 1, wantStderr: wantRefusal},
		{name: "adopt and prune", args: []string{"sandbox", "sync", "--adopt", "--prune", "--config", cfg}, wantCode: 1, wantStderr: "exclude each other"},
		{name: "sandbox without sync", args: []string{"sandbox"}, wantCode: 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			if code := run(t.Context(), tt.args, &stdout, &stderr); code != tt.wantCode {
				t.Errorf("exit code = %d, want %d (stderr: %s)", code, tt.wantCode, stderr.String())
			}
			if !strings.Contains(stdout.String(), tt.wantStdout) || !strings.Contains(stderr.String(), tt.wantStderr) {
				t.Errorf("stdout %q stderr %q; want %q and %q", stdout.String(), stderr.String(), tt.wantStdout, tt.wantStderr)
			}
		})
	}
	if data, err := os.ReadFile(cfg); err != nil || string(data) != original {
		t.Errorf("agent.yaml changed: %v\n%s", err, data)
	}
}

const dnsSentinel = "SENTINEL-cf-token-0123456789"

// dnsAgentYAML is an agent.yaml with one Cloudflare provider; withDeployment
// adds a wildcard deployment that uses it.
func dnsAgentYAML(dir, credentials string, withDeployment bool) string {
	out := "server: https://pki.homelab.lan:8444\nca_bundle: " + yamlPath(filepath.Join(dir, "root.pem")) +
		"\nhostname: proxy1.homelab.lan\nstate_dir: " + yamlPath(filepath.Join(dir, "state")) +
		"\nacme_directory: https://pki.homelab.lan/acme/directory\npaths: [" + yamlPath(filepath.Join(dir, "ssl")) + "]\n" +
		"dns_providers:\n  homelab-dns:\n    type: cloudflare\n    credentials_file: " + yamlPath(credentials) + "\n"
	if withDeployment {
		out += "deployments:\n  - name: wild\n    profile: file\n    names: ['*.homelab.lan', homelab.lan]\n    challenge: dns-01\n    dns_provider: homelab-dns\n" +
			"    files: {fullchain: " + yamlPath(filepath.Join(dir, "ssl", "fullchain.pem")) + ", key: " + yamlPath(filepath.Join(dir, "ssl", "key.pem")) + "}\n"
	}
	return out
}

// dnsCredentialsFile writes a credentials file that passes the checks of this
// platform (directory 0700, file 0600) and returns its path.
func dnsCredentialsFile(t *testing.T, dir, content string) string {
	t.Helper()
	cdir := filepath.Join(dir, "dns")
	if err := os.Mkdir(cdir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(cdir, "homelab.yaml")
	writeFile(t, path, content)
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestConfigCheckShowsDNSProviders(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	creds := dnsCredentialsFile(t, dir, "api_token: "+dnsSentinel+"\n")
	cfg := filepath.Join(dir, "agent.yaml")
	writeFile(t, cfg, dnsAgentYAML(dir, creds, true))
	var stdout, stderr bytes.Buffer
	if code := run(t.Context(), []string{"config", "check", "--config", cfg}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit code %d: %s\n%s", code, stderr.String(), stdout.String())
	}
	for _, want := range []string{"  dns providers\n", "    homelab-dns  cloudflare  " + creds + ": ok\n", "Configuration is valid."} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, stdout.String())
		}
	}
	if strings.Contains(stdout.String()+stderr.String(), "SENTINEL") {
		t.Fatalf("config check printed the content of the credentials file:\n%s%s", stdout.String(), stderr.String())
	}
}

func TestConfigCheckFailsForAnUnusableCredentialsFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "agent.yaml")
	missing := filepath.Join(dir, "dns", "absent.yaml")
	writeFile(t, cfg, dnsAgentYAML(dir, missing, true))
	var stdout, stderr bytes.Buffer
	code := run(t.Context(), []string{"config", "check", "--config", cfg}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stdout.String(), missing+": missing: no such file") ||
		!strings.Contains(stderr.String(), "1 DNS credentials file(s) used by a deployment cannot be used") || strings.Contains(stdout.String(), "Configuration is valid.") {
		t.Fatalf("exit code %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}

	// An invalid file is reported without its content.
	bad := dnsCredentialsFile(t, t.TempDir(), "api_tokne: "+dnsSentinel+"\n")
	writeFile(t, cfg, dnsAgentYAML(dir, bad, true))
	stdout.Reset()
	stderr.Reset()
	code = run(t.Context(), []string{"config", "check", "--config", cfg}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stdout.String(), bad+": invalid: unknown key \"api_tokne\"") || strings.Contains(stdout.String()+stderr.String(), "SENTINEL") {
		t.Fatalf("exit code %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
}

func TestConfigCheckAnUnusedProviderIsOnlyAWarning(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "agent.yaml")
	missing := filepath.Join(dir, "dns", "absent.yaml")
	writeFile(t, cfg, dnsAgentYAML(dir, missing, false))
	var stdout, stderr bytes.Buffer
	if code := run(t.Context(), []string{"config", "check", "--config", cfg}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit code %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	for _, want := range []string{missing + ": missing: no such file (no deployment uses it)", "warning       dns_providers.homelab-dns: no deployment uses it", "Configuration is valid."} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, stdout.String())
		}
	}
}

func TestConfigCheckRefusesUnknownDNSKeys(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "agent.yaml")
	creds := dnsCredentialsFile(t, dir, "api_token: x\n")
	writeFile(t, cfg, dnsAgentYAML(dir, creds, true)+"    api_token: "+dnsSentinel+"\n")
	var stdout, stderr bytes.Buffer
	_ = run(t.Context(), []string{"config", "check", "--config", cfg}, &stdout, &stderr)
	// The wildcard deployment above is last in the file, so the stray key is
	// read as a key of the deployment: refused by name.
	if !strings.Contains(stderr.String(), "field api_token not found") {
		t.Fatalf("stderr: %s", stderr.String())
	}
}

func TestTrustCommandLine(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "agent.yaml")
	pin := strings.Repeat("ab", 32)
	writeFile(t, cfg, "server: https://pki.homelab.lan:8444\nca_bundle: "+yamlPath(filepath.Join(dir, "root.pem"))+
		"\nhostname: proxy1.homelab.lan\nstate_dir: "+yamlPath(filepath.Join(dir, "state"))+"\n")
	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStderr string
		wantStdout string
	}{
		{name: "no subcommand", args: []string{"trust"}, wantCode: 2, wantStderr: "trust install"},
		{name: "unknown subcommand", args: []string{"trust", "add"}, wantCode: 2, wantStderr: "trust remove"},
		{name: "install needs the pin", args: []string{"trust", "install", "--config", cfg}, wantCode: 2, wantStderr: "--root-sha256 is required"},
		{name: "install with a stray argument", args: []string{"trust", "install", "--root-sha256", pin, "--config", cfg, "extra"}, wantCode: 2},
		{name: "unknown flag", args: []string{"trust", "install", "--force"}, wantCode: 2},
		{name: "status has no --no-record", args: []string{"trust", "status", "--no-record"}, wantCode: 2},
		{name: "remove has no --quiet", args: []string{"trust", "remove", "--quiet"}, wantCode: 2},
		{name: "status without a pin", args: []string{"trust", "status", "--config", cfg}, wantCode: 1, wantStdout: "not configured"},
		{name: "status quiet without a pin", args: []string{"trust", "status", "--quiet", "--config", cfg}, wantCode: 1},
		{name: "status of a missing file", args: []string{"trust", "status", "--config", filepath.Join(dir, "nope.yaml")}, wantCode: 1, wantStderr: "nope.yaml"},
		// install and remove need root and a Linux host: on this machine (a test
		// run is not root) they refuse before anything is read or written.
		{name: "install refuses a non-root caller", args: []string{"trust", "install", "--root-sha256", pin, "--config", cfg}, wantCode: 1, wantStderr: "must run as root"},
		{name: "remove refuses a non-root caller", args: []string{"trust", "remove", "--config", cfg}, wantCode: 1, wantStderr: "must run as root"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if os.Geteuid() == 0 && strings.Contains(tt.name, "non-root") {
				t.Skip("the test run is root; the refusal is for everybody else")
			}
			var stdout, stderr bytes.Buffer
			if code := run(t.Context(), tt.args, &stdout, &stderr); code != tt.wantCode {
				t.Errorf("exit code = %d, want %d (stderr: %s)", code, tt.wantCode, stderr.String())
			}
			if !strings.Contains(stderr.String(), tt.wantStderr) || !strings.Contains(stdout.String(), tt.wantStdout) {
				t.Errorf("stdout %q, stderr %q: want %q and %q", stdout.String(), stderr.String(), tt.wantStdout, tt.wantStderr)
			}
		})
	}
	if _, err := os.Stat(cfg + ".bak"); err == nil {
		t.Error("a refused command wrote agent.yaml.bak")
	}
}

func TestSetupHasTheSystemTrustFlag(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	// No --server: setup refuses at once, but the flag must parse (usage error 2 would mean it does not).
	if code := run(t.Context(), []string{"setup", "--system-trust"}, &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "--server is required") {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
}

func TestConfigCheckShowsTheSystemTrustBlock(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	write := func(extra string) string {
		path := filepath.Join(dir, "agent.yaml")
		writeFile(t, path, "server: https://pki.homelab.lan:8444\nca_bundle: "+yamlPath(filepath.Join(dir, "root.pem"))+
			"\nhostname: proxy1.homelab.lan\nstate_dir: "+yamlPath(filepath.Join(dir, "state"))+"\n"+extra)
		return path
	}
	check := func(path string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := run(t.Context(), []string{"config", "check", "--config", path}, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
	if code, out, errOut := check(write("")); code != 0 || !strings.Contains(out, "  system trust  off\n") {
		t.Fatalf("off: %d\n%s%s", code, out, errOut)
	}
	pin := strings.Repeat("cd", 32)
	// The root is not there yet (a laptop, a host before setup): information, exit 0.
	if code, out, errOut := check(write("system_trust:\n  root_sha256: \"" + pin + "\"\n")); code != 0 || !strings.Contains(out, "  system trust  ") || strings.Contains(out, "system trust  off") {
		t.Fatalf("configured: %d\n%s%s", code, out, errOut)
	}
	// ca_bundle holds another root than the pin: exit 1.
	root, _ := testRootPEM(t)
	writeFile(t, filepath.Join(dir, "root.pem"), string(root))
	code, out, errOut := check(write("system_trust:\n  root_sha256: \"" + pin + "\"\n"))
	if code != 1 || !strings.Contains(out, "pin differs from ca_bundle") || !strings.Contains(errOut, "system_trust") {
		t.Fatalf("pin mismatch: %d\n%s%s", code, out, errOut)
	}
	// A bad pin is a configuration error like any other.
	if code, _, errOut := check(write("system_trust:\n  root_sha256: nothex\n")); code != 1 || !strings.Contains(errOut, "system_trust.root_sha256") {
		t.Fatalf("bad pin: %d %s", code, errOut)
	}
	if code, _, errOut := check(write("system_trust:\n  root_sha256: \"" + pin + "\"\n  extra: 1\n")); code != 1 || !strings.Contains(errOut, "extra") {
		t.Fatalf("unknown key: %d %s", code, errOut)
	}
}
