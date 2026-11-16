// Package demo holds the static test of the demo files (docs/PHASE3.md §17,
// step 75): what can be checked without Docker. The demo itself runs in CI
// (scripts/ci/demo-check.sh) and on a Docker host.
package demo

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/Der-Felix/MyOwnPKI/internal/config"
	"github.com/Der-Felix/MyOwnPKI/internal/testinstance"
)

type composeFile struct {
	Name     string                    `yaml:"name"`
	Services map[string]composeService `yaml:"services"`
	Networks map[string]struct {
		Name string `yaml:"name"`
	} `yaml:"networks"`
	Volumes map[string]any `yaml:"volumes"`
}

type composeService struct {
	Image       string   `yaml:"image"`
	Build       any      `yaml:"build"`
	Profiles    []string `yaml:"profiles"`
	Ports       []string `yaml:"ports"`
	Volumes     []string `yaml:"volumes"`
	ReadOnly    bool     `yaml:"read_only"`
	CapDrop     []string `yaml:"cap_drop"`
	SecurityOpt []string `yaml:"security_opt"`
	Privileged  bool     `yaml:"privileged"`
	NetworkMode string   `yaml:"network_mode"`
	Pid         string   `yaml:"pid"`
	IPC         string   `yaml:"ipc"`
	Environment any      `yaml:"environment"`
	Entrypoint  []string `yaml:"entrypoint"`
}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.FromSlash(path))
	if err != nil {
		t.Fatal(err)
	}
	return strings.ReplaceAll(string(b), "\r\n", "\n")
}

func load(t *testing.T, path string) (composeFile, string) {
	t.Helper()
	text := read(t, path)
	var c composeFile
	if err := yaml.Unmarshal([]byte(text), &c); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return c, text
}

var (
	pinned   = regexp.MustCompile(`^[a-z0-9][a-z0-9./_-]*:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}$`)
	variable = regexp.MustCompile(`^\$\{MYOWNPKI_IMAGE:-ghcr\.io/der-felix/myownpki:[0-9]+\.[0-9]+\.[0-9]+\}$`)
	envRef   = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)([^}]*)\}`)
	digest   = regexp.MustCompile(`@(sha256:[0-9a-f]{64})`)
)

// TestComposeIsPinnedAndHardened checks the compose file the way the plan
// asks: every third-party image by digest, the hardening of the server, nothing
// published but the UI on loopback, no secret in the file.
func TestComposeIsPinnedAndHardened(t *testing.T) {
	c, text := load(t, "docker-compose.yml")
	prod, _ := load(t, "../docker-compose.yml")

	if c.Name != "myownpki-demo" || c.Name == prod.Name {
		t.Errorf("project name %q: want myownpki-demo, different from the production example's", c.Name)
	}
	if n := c.Networks["demo"].Name; n != "myownpki-demo" {
		t.Errorf("network name %q", n)
	}
	for name := range c.Volumes {
		if _, shared := prod.Volumes[name]; shared {
			t.Errorf("volume %q is also a volume of deploy/docker-compose.yml", name)
		}
	}

	for name, s := range c.Services {
		switch {
		case s.Build != nil:
			if s.Image != "myownpki-demo-web:local" {
				t.Errorf("%s: a build must be tagged myownpki-demo-web:local, got %q", name, s.Image)
			}
		case variable.MatchString(s.Image):
		case pinned.MatchString(s.Image):
		default:
			t.Errorf("%s: image %q is neither name:tag@sha256:<digest> nor ${MYOWNPKI_IMAGE:-ghcr.io/der-felix/myownpki:X.Y.Z}", name, s.Image)
		}
		if strings.Contains(s.Image, ":latest") || strings.HasSuffix(s.Image, "/latest") {
			t.Errorf("%s: no latest tag", name)
		}
		if s.Privileged || s.NetworkMode != "" || s.Pid != "" || s.IPC != "" {
			t.Errorf("%s: privileged, network_mode, pid and ipc are not allowed", name)
		}
		if !slices.Contains(s.CapDrop, "ALL") {
			t.Errorf("%s: cap_drop: [ALL] is missing", name)
		}
		if !slices.Contains(s.SecurityOpt, "no-new-privileges:true") {
			t.Errorf("%s: no-new-privileges is missing", name)
		}
		if !s.ReadOnly {
			t.Errorf("%s: read_only is missing", name)
		}
		for _, p := range s.Ports {
			if name != "myownpki" || !strings.HasPrefix(p, "127.0.0.1:") {
				t.Errorf("%s: port %q: only the admin UI of the server, on 127.0.0.1", name, p)
			}
		}
		for _, v := range s.Volumes {
			src, _, _ := strings.Cut(v, ":")
			switch {
			case strings.Contains(v, "docker.sock"):
				t.Errorf("%s: the Docker socket is mounted", name)
			case strings.HasPrefix(src, "./"):
				if !strings.HasSuffix(v, ":ro") {
					t.Errorf("%s: bind mount %q must be read-only", name, v)
				}
				if _, err := os.Stat(filepath.FromSlash(src)); err != nil {
					t.Errorf("%s: %q does not exist", name, src)
				}
			case strings.HasPrefix(src, "/") || strings.HasPrefix(src, "."):
				t.Errorf("%s: host path %q: use a named volume", name, src)
			default:
				if _, ok := c.Volumes[src]; !ok {
					t.Errorf("%s: volume %q is not declared", name, src)
				}
			}
		}
		if env, ok := s.Environment.(map[string]any); ok {
			for k, v := range env {
				value, _ := v.(string)
				if secretName.MatchString(k) && value != "" && !strings.HasPrefix(value, "${") {
					t.Errorf("%s: environment %s carries a literal value", name, k)
				}
			}
		}
	}
	if len(c.Services["myownpki"].Ports) != 1 {
		t.Errorf("the server publishes %v, want exactly the admin UI", c.Services["myownpki"].Ports)
	}

	// Every ${VAR} has a default, and only these variables exist.
	for _, m := range envRef.FindAllStringSubmatch(text, -1) {
		if !strings.HasPrefix(m[2], ":-") {
			t.Errorf("%s has no default", m[0])
		}
		if !slices.Contains([]string{"MYOWNPKI_IMAGE", "DEMO_AGENT_BASE_URL", "DEMO_AGENT_TLS_ISSUER", "DEMO_AGENT_CA"}, m[1]) {
			t.Errorf("unexpected variable %s", m[1])
		}
	}
	if regexp.MustCompile(`(?i)passphrase|password|totp`).MatchString(text) {
		t.Error("the compose file names a secret")
	}
}

var secretName = regexp.MustCompile(`(?i)pass|secret|token|key`)

// TestPinsAreListed: every digest in the demo files is in THIRD_PARTY.md, and
// the images are the ones the plan names.
func TestPinsAreListed(t *testing.T) {
	third := read(t, "../../THIRD_PARTY.md")
	_, compose := load(t, "docker-compose.yml")
	dockerfile := read(t, "web/Dockerfile")
	found := 0
	for _, file := range []string{compose, dockerfile} {
		for _, m := range digest.FindAllStringSubmatch(file, -1) {
			found++
			if !strings.Contains(third, m[1]) {
				t.Errorf("%s is not listed in THIRD_PARTY.md", m[1])
			}
		}
	}
	if found != 2 {
		t.Errorf("want two pinned third-party images (certbot, nginx), found %d digests", found)
	}
	for line := range strings.SplitSeq(dockerfile, "\n") {
		if rest, ok := strings.CutPrefix(line, "FROM "); ok {
			if !strings.HasPrefix(rest, "${MYOWNPKI_IMAGE} ") && !pinned.MatchString(strings.Fields(rest)[0]) {
				t.Errorf("web/Dockerfile: FROM %q is not pinned", rest)
			}
		}
	}
}

// TestFilesExist: everything the files name is in the directory.
func TestFilesExist(t *testing.T) {
	_, text := load(t, "docker-compose.yml")
	for _, f := range []string{"config.yaml", "certbot/run.sh", "web/Dockerfile", "web/entrypoint.sh", "demo.sh", "README.md", ".env.example"} {
		if _, err := os.Stat(filepath.FromSlash(f)); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
	dockerfile := read(t, "web/Dockerfile")
	if !strings.Contains(dockerfile, "COPY --chmod=0755 entrypoint.sh") || !strings.Contains(text, "context: ./web") {
		t.Error("web/Dockerfile and the compose file do not agree on entrypoint.sh")
	}
}

// TestScripts: strict mode, no tracing that could print a secret.
func TestScripts(t *testing.T) {
	for file, strict := range map[string]string{
		"demo.sh":           "set -euo pipefail",
		"certbot/run.sh":    "set -eu",
		"web/entrypoint.sh": "set -eu",
	} {
		text := read(t, file)
		if !strings.Contains(text, "\n"+strict+"\n") {
			t.Errorf("%s: want %q", file, strict)
		}
		if regexp.MustCompile(`(?m)^\s*set -[a-z]*x|bash -x|set -o xtrace`).MatchString(text) {
			t.Errorf("%s: tracing is on", file)
		}
	}
	// demo.sh never prints a secret variable: no echo, note or say of it, and
	// none inside the text of an error message.
	printing := regexp.MustCompile(`^\s*(echo|note|say)\b.*\$\{?(pass|admin_password|totp_secret)\b|\bdie\s+"[^"]*\$\{?(pass|admin_password|totp_secret)\b`)
	for i, line := range strings.Split(read(t, "demo.sh"), "\n") {
		if printing.MatchString(line) {
			t.Errorf("demo.sh:%d prints a secret: %s", i+1, line)
		}
	}
}

// TestDemoConfig: the server configuration is valid with and without the
// agent listener of the second act, and ACME speaks TLS itself.
func TestDemoConfig(t *testing.T) {
	dir := t.TempDir()
	base := []string{"MYOWNPKI_DATA_DIR=" + dir}
	cfg, _, err := config.Load("config.yaml", base)
	if err != nil {
		t.Fatalf("config.yaml: %v", err)
	}
	if cfg.ACME.TLSIssuer != "issuing" || !strings.HasPrefix(cfg.ACME.BaseURL, "https://acme.demo.test:") {
		t.Errorf("acme: %+v", cfg.ACME)
	}
	if cfg.Agent.Enabled() {
		t.Error("the agent listener must be off until the second act")
	}
	agentEnv := append(slices.Clone(base),
		"MYOWNPKI_AGENT_BASE_URL=https://agent.demo.test:8444", "MYOWNPKI_AGENT_TLS_ISSUER=issuing", "MYOWNPKI_AGENT_CA=agent-ca")
	cfg, _, err = config.Load("config.yaml", agentEnv)
	if err != nil || !cfg.Agent.Enabled() {
		t.Fatalf("with the agent listener: %v", err)
	}
	empty := append(slices.Clone(base), "MYOWNPKI_AGENT_BASE_URL=", "MYOWNPKI_AGENT_TLS_ISSUER=", "MYOWNPKI_AGENT_CA=")
	if cfg, _, err = config.Load("config.yaml", empty); err != nil || cfg.Agent.Enabled() {
		t.Fatalf("the empty variables of the compose file must leave the listener off: %v", err)
	}
	if strings.Contains(read(t, "config.yaml"), "passphrase") {
		t.Error("config.yaml names a passphrase")
	}
}

// TestScriptReadsTheSecretsFileOfInit runs read_secrets and totp of demo.sh on
// the file a real `init --demo` wrote: the TOTP secret is printed there in
// groups of four, and the script must make the same code of it as the server
// does. A damaged secret must stop the script without printing it.
func TestScriptReadsTheSecretsFileOfInit(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is not installed")
	}
	if _, err = exec.LookPath("openssl"); err != nil {
		t.Skip("openssl is not installed")
	}
	if runtime.GOOS == "windows" && os.Getenv("MYOWNPKI_TEST_DEMO_SCRIPT") != "1" {
		t.Skip("on Windows only with Git Bash first in the PATH: set MYOWNPKI_TEST_DEMO_SCRIPT=1")
	}
	inst := testinstance.New(t, testinstance.Options{})
	file := filepath.Join(inst.Config.DataDir, "init-demo-secrets.txt")
	text := strings.ReplaceAll(read(t, filepath.ToSlash(file)), "\r\n", "\n")
	var shown string
	for line := range strings.SplitSeq(text, "\n") {
		if v, ok := strings.CutPrefix(line, "secret:"); ok {
			shown = strings.TrimSpace(v)
		}
	}
	if !strings.Contains(shown, " ") {
		t.Fatalf("the test expects the secret in groups, as init writes it (%d characters)", len(shown))
	}
	script, err := filepath.Abs("demo.sh")
	if err != nil {
		t.Fatal(err)
	}
	at := time.Unix(1_700_000_010, 0)
	want := testinstance.TOTP(shown, at)
	normal := strings.ReplaceAll(shown, " ", "")

	run := func(t *testing.T, secretsFile string) (string, string, error) {
		t.Helper()
		const program = `source "$1"; read_secrets "$2"; printf '%s %s\n' "$totp_secret" "$(totp "$totp_secret" "$3")"`
		cmd := exec.CommandContext(t.Context(), bash, "-c", program, "bash", filepath.ToSlash(script), filepath.ToSlash(secretsFile), "56666667") // #nosec G204 -- fixed program, test files
		cmd.Env = append(os.Environ(), "GITHUB_ACTIONS=false")                                                                                    // no ::add-mask:: lines in the output
		var stdout, stderr strings.Builder
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		err := cmd.Run()
		return stdout.String(), stderr.String(), err
	}
	// 1700000010 / 30 = 56666667.
	good := map[string]string{
		"as init wrote it": text,
		"lower case":       strings.Replace(text, "secret:       "+shown, "secret: "+strings.ToLower(normal), 1),
		"padded":           strings.Replace(text, "secret:       "+shown, "secret: "+normal+"====", 1),
		"crlf":             strings.ReplaceAll(text, "\n", "\r\n"),
		"link only":        strings.Replace(text, "secret:       "+shown, "", 1),
	}
	for name, content := range good {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "secrets.txt")
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			stdout, stderr, err := run(t, path)
			if err != nil {
				t.Fatalf("%v\nstdout: %s\nstderr: %s", err, stdout, stderr)
			}
			if got := strings.TrimSpace(stdout); got != normal+" "+want {
				t.Errorf("the script read a different secret or computed a different code (code want %s, output has %d characters)", want, len(got))
			}
		})
	}
	for name, bad := range map[string]string{
		"not base32": "NOT-A-BASE32-SECRET-1",
		"too short":  "GEZD GNBV",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "secrets.txt")
			damaged := strings.Replace(text, "secret:       "+shown, "secret:       "+bad, 1)
			if err := os.WriteFile(path, []byte(damaged), 0o600); err != nil {
				t.Fatal(err)
			}
			stdout, stderr, err := run(t, path)
			if err == nil || !strings.Contains(stderr, "is not base32") {
				t.Fatalf("want the script to stop with 'is not base32': %v\nstderr: %s", err, stderr)
			}
			if strings.Contains(stdout+stderr, bad) || strings.Contains(stdout+stderr, normal) {
				t.Error("the script printed a secret")
			}
		})
	}
}

// TestImageTagIsTheCurrentRelease: the demo names the release it was made for
// (docs/PHASE3.md §19, step 119). A static compose file cannot read the
// version at build time, so the tag is bumped by hand at every release
// (docs/RELEASING.md "Before the tag"); this test fails when it is not.
func TestImageTagIsTheCurrentRelease(t *testing.T) {
	m := regexp.MustCompile(`(?m)^DEFAULT_VERSION=(\S+)$`).FindStringSubmatch(read(t, "../install.sh"))
	if m == nil {
		t.Fatal("deploy/install.sh: DEFAULT_VERSION not found")
	}
	want := m[1]

	tag := regexp.MustCompile(`ghcr\.io/der-felix/myownpki:([0-9A-Za-z._-]+)`)
	found := 0
	for _, file := range []string{"docker-compose.yml", "web/Dockerfile", ".env.example", "README.md"} {
		for _, hit := range tag.FindAllStringSubmatch(read(t, file), -1) {
			found++
			if hit[1] != want {
				t.Errorf("%s: image tag %q, but deploy/install.sh has DEFAULT_VERSION=%s; bump the demo files (docs/RELEASING.md)", file, hit[1], want)
			}
		}
	}
	if found == 0 {
		t.Error("no image tag found in the demo files")
	}
}
