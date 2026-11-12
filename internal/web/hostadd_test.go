package web

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Der-Felix/MyOwnPKI/internal/agent"
	"github.com/Der-Felix/MyOwnPKI/internal/agentdist"
	"github.com/Der-Felix/MyOwnPKI/internal/agents"
	"github.com/Der-Felix/MyOwnPKI/internal/recipe"
	"github.com/Der-Felix/MyOwnPKI/internal/tenant"
)

const testACMEDirectory = "https://pki.homelab.lan/acme/directory"

// hostileValues are what a form could carry to a command line: quotes,
// substitutions, control characters, option look-alikes, unicode, NUL, length.
var hostileValues = []string{
	"", "plain", "it's", `"double"`, "$(touch pwned)", "`touch pwned`", "${IFS}x", "a;touch pwned", "a&&touch pwned", "a|b", "a>b", "a<b",
	"a\nb", "a\rb", "a\\\nb", "a\tb", "a b", "-rf", "--recipe", "%s%n", "%h", "*", "?", "~", "!!", "#c", "{a,b}", "é€😀", "a\x00b",
	"'; touch pwned; '", "'\"'\"'", "''", "\\", "\\'", strings.Repeat("a", 5000),
}

// shellWords splits one shell command line the way a POSIX shell does for the
// subset the assistant may produce: words separated by white space, single
// quotes, backslash-newline continuation outside quotes. Everything else that
// a shell would act on outside quotes is an error, so a value that escaped its
// quotes cannot hide.
func shellWords(line string) ([]string, error) {
	var words []string
	var cur strings.Builder
	inWord, inQuote := false, false
	flush := func() {
		if inWord {
			words = append(words, cur.String())
			cur.Reset()
			inWord = false
		}
	}
	for i := 0; i < len(line); i++ {
		ch := line[i]
		switch {
		case inQuote:
			if ch == '\'' {
				inQuote = false
			} else {
				cur.WriteByte(ch)
			}
		case ch == '\'':
			inQuote, inWord = true, true
		case strings.HasPrefix(line[i:], `"'"`): // shellQuote writes an embedded quote as "'"
			cur.WriteByte('\'')
			inWord = true
			i += 2
		case ch == '\\' && i+1 < len(line) && line[i+1] == '\n':
			i++
		case ch == ' ' || ch == '\t' || ch == '\n':
			flush()
		case strings.IndexByte("\\\"`$;&|<>*?~!#{}[]%\r\x00", ch) >= 0 || ch > 0x7e:
			return nil, fmt.Errorf("unquoted %q at %d in %q", ch, i, line)
		default:
			cur.WriteByte(ch)
			inWord = true
		}
	}
	if inQuote {
		return nil, fmt.Errorf("unterminated quote in %q", line)
	}
	flush()
	return words, nil
}

func TestShellQuoteKeepsEveryValueOneWord(t *testing.T) {
	t.Parallel()
	for _, v := range hostileValues {
		words, err := shellWords("printf " + shellQuote(v))
		if err != nil || len(words) != 2 || words[1] != v {
			t.Errorf("shellQuote(%q) = %s, parsed %q (%v)", v, shellQuote(v), words, err)
		}
	}
	// And bash agrees (it cannot hold a NUL, so those are left to the parser above).
	if _, err := exec.LookPath("bash"); err != nil {
		t.Log("no bash: shell cross-check skipped")
		return
	}
	for _, v := range hostileValues {
		if strings.ContainsAny(v, "\x00\r") { // bash cannot hold a NUL; Git Bash on Windows drops a CR from script text
			continue
		}
		script := "set -- " + shellQuote(v) + "; test $# -eq 1 && printf %s \"$1\""
		out, err := exec.CommandContext(t.Context(), "bash", "-c", script).Output() // #nosec G204 -- a quoted test value
		if err != nil || string(out) != v {
			t.Errorf("bash read %q as %q (%v)", v, out, err)
		}
	}
}

// goodForm is a valid step 1 that tests change one field of.
func goodForm(extra map[string]string) func(string) string {
	form := map[string]string{"hostname": "proxy1.homelab.lan", "service": "nginx", "challenge": "webroot", "webroot": "/var/www/acme",
		"format": "deb", "arch": "amd64", "admission": admitToken}
	for k, v := range extra {
		form[k] = v
	}
	return func(k string) string { return form[k] }
}

func TestParseHostPlan(t *testing.T) {
	t.Parallel()
	p, err := parseHostPlan(goodForm(nil), true)
	if err != nil {
		t.Fatal(err)
	}
	if p.Host != "proxy1.homelab.lan" || !slices.Equal(p.Names, []string{"proxy1.homelab.lan"}) || p.Service.ID != "nginx" || p.Webroot != "/var/www/acme" || p.Admission != admitToken {
		t.Errorf("plan: %+v", p)
	}
	// Case and the trailing dot of the host name are normalized; extras are deduplicated.
	p, err = parseHostPlan(goodForm(map[string]string{"hostname": " Proxy1.HomeLab.lan. ", "names": "www.homelab.lan\nPROXY1.homelab.lan, www.homelab.lan"}), true)
	if err != nil || !slices.Equal(p.Names, []string{"proxy1.homelab.lan", "www.homelab.lan"}) {
		t.Errorf("normalized: %+v %v", p, err)
	}
	// No admission in the field = none; "already installed" has no architecture.
	p, err = parseHostPlan(goodForm(map[string]string{"admission": "", "format": "none", "arch": "sparc"}), false)
	if err != nil || p.Admission != admitNone || p.Arch != "" {
		t.Errorf("defaults: %+v %v", p, err)
	}
	for name, form := range map[string]map[string]string{
		"wildcard host":      {"hostname": "*.homelab.lan"},
		"ip":                 {"hostname": "192.0.2.1"},
		"single label":       {"hostname": "proxy1"},
		"space":              {"hostname": "proxy1.homelab.lan -x"},
		"injection":          {"hostname": "proxy1.homelab.lan';id;'"},
		"unicode":            {"hostname": "bücher.homelab.lan"},
		"dash":               {"hostname": "-x.homelab.lan"},
		"wildcard name":      {"names": "*.homelab.lan"},
		"bad name":           {"names": "ok.homelab.lan\n$(reboot).homelab.lan"},
		"five extra names":   {"names": "a.homelab.lan b.homelab.lan c.homelab.lan d.homelab.lan e.homelab.lan"},
		"unknown service":    {"service": "apache"},
		"service injection":  {"service": "nginx --hook x='/bin/sh'"},
		"unknown challenge":  {"challenge": "dns-01"},
		"webroot standalone": {"challenge": "standalone"},
		"no webroot":         {"webroot": ""},
		"unknown format":     {"format": "msi"},
		"unknown arch":       {"arch": "sparc"},
		"unknown admission":  {"admission": "pass-through"},
	} {
		if _, err := parseHostPlan(goodForm(form), true); err == nil {
			t.Errorf("%s: accepted", name)
		} else if !strings.Contains(err.Error(), "invalid") && !strings.Contains(err.Error(), "must") && !strings.Contains(err.Error(), "choose") {
			t.Logf("%s: %v", name, err)
		}
	}
	if _, err := parseHostPlan(goodForm(map[string]string{"format": "deb"}), false); err == nil {
		t.Error("a package format without packages was accepted")
	}
}

func TestCheckHostPath(t *testing.T) {
	t.Parallel()
	for p, want := range map[string]bool{
		"/var/www/acme": true, "/srv/www/acme": true, "/var/www/html/.well-known": true, "/opt/web/acme-root": true, "/var/www/-rf": true,
		"": false, "relative/dir": false, "/": false, "/etc": false, "/etc/": false, "/usr": false, "/var": false, "/root": false, "/home": false,
		"/tmp": false, "/proc/1": false, "/sys/x": false, "/dev/shm": false, "/lib64": false, "/var/www/": false, "//var/www": false,
		"/var/www/../../etc": false, "/var/./www": false, "/var/www/a b": false, "/var/www/a'b": false, `/var/www/a"b`: false,
		"/var/www/a\nb": false, "/var/www/a\x00b": false, "/var/www/%h": false, "/var/www/$HOME": false, "/var/www/a;b": false,
		"/var/www/a`b": false, `/var/www/a\b`: false, "/var/www/é": false, "/var/www/" + strings.Repeat("a", 300): false,
	} {
		if err := checkHostPath(p); (err == nil) != want {
			t.Errorf("checkHostPath(%q) = %v, want accepted=%v", p, err, want)
		}
	}
}

func TestClipTextKeepsOneShortLine(t *testing.T) {
	t.Parallel()
	got := clipText("line one\nline two\x00\x1b[31m"+strings.Repeat("x", 500), 40)
	if strings.ContainsAny(got, "\n\x00\x1b") || len([]rune(got)) != 41 || !strings.HasSuffix(got, "…") {
		t.Errorf("clipText = %q", got)
	}
	if got := clipText("short", 40); got != "short" {
		t.Errorf("clipText(short) = %q", got)
	}
}

func TestAdmissionOutcome(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		mode, admission string
		approval        bool
		contains        string
	}{
		{tenant.EnrollVerified, admitToken, false, "without an approval"},
		{tenant.EnrollVerified, admitPass, false, "without an approval"},
		{tenant.EnrollVerified, admitNone, true, "waits in the queue"},
		{tenant.EnrollAuto, admitToken, false, "admitted as soon as"},
		{tenant.EnrollAuto, admitNone, false, "auto mode"},
		{tenant.EnrollManual, admitToken, true, "manual mode"},
		{tenant.EnrollManual, admitNone, true, "manual mode"},
		{"unknown", admitToken, false, "without an approval"},
	} {
		approval, text := admissionOutcome(tc.mode, tc.admission)
		if approval != tc.approval || !strings.Contains(text, tc.contains) {
			t.Errorf("%s/%s: %v %q", tc.mode, tc.admission, approval, text)
		}
	}
}

// ---------------------------------------------------------------- the generated line and the real parser

// hostPlanFor makes a valid plan for a service and challenge.
func hostPlanFor(t *testing.T, service, challenge string, extras ...string) hostPlan {
	t.Helper()
	form := map[string]string{"service": service, "challenge": challenge, "names": strings.Join(extras, "\n")}
	if challenge == "standalone" {
		form["webroot"] = ""
	}
	p, err := parseHostPlan(goodForm(form), true)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// runBlock runs the rendered block under bash with mock agent and install
// programs (the way a person would paste it) and returns what each received.
func runBlock(t *testing.T, block string) (agentCalls, installCalls [][]string) {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("no bash on this machine")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o750); err != nil {
		t.Fatal(err)
	}
	record := func(name, file string) string {
		script := "#!/usr/bin/env bash\nprintf '%s\\0' \"$@\" >> \"$MOCK_DIR/" + file + "\"\nprintf '\\001' >> \"$MOCK_DIR/" + file + "\"\n"
		p := filepath.Join(bin, name)
		if err := os.WriteFile(p, []byte(script), 0o700); err != nil { // #nosec G306 -- a mock in t.TempDir must be executable
			t.Fatal(err)
		}
		return p
	}
	agentMock := record("myownpki-agent", "agent.calls")
	record("install", "install.calls")
	script := strings.ReplaceAll(block, agentdist.BinaryPath, filepath.ToSlash(agentMock))
	cmd := exec.CommandContext(t.Context(), "bash", "-c", script) // #nosec G204 -- the rendered block with mock executables
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "PATH="+filepath.ToSlash(bin)+":/usr/bin:/bin", "MOCK_DIR="+filepath.ToSlash(dir))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("block failed: %v\n%s\n%s", err, clipText(string(out), 300), clipForLog(block))
	}
	if _, err := os.Stat(filepath.Join(dir, "pwned")); err == nil {
		t.Fatalf("a value was executed:\n%s", clipForLog(block))
	}
	read := func(file string) [][]string {
		data, err := os.ReadFile(filepath.Join(dir, file))
		if err != nil {
			return nil
		}
		var calls [][]string
		for _, rec := range strings.Split(string(data), "\x01") {
			if rec == "" {
				continue
			}
			calls = append(calls, strings.Split(strings.TrimSuffix(rec, "\x00"), "\x00"))
		}
		return calls
	}
	return read("agent.calls"), read("install.calls")
}

// newDryRunHost is a host as setup leaves it for plan: agent.yaml with the
// enrollment challenge of the plan, below a temporary root.
func newDryRunHost(t *testing.T, p hostPlan) agent.DryRunHost {
	t.Helper()
	root := t.TempDir()
	slash := filepath.ToSlash(root)
	for _, dir := range []string{"etc/myownpki-agent", "var/lib/myownpki-agent", "etc/systemd/system"} {
		if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(dir)), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	yaml := fmt.Sprintf("server: %q\nca_bundle: %q\nhostname: %q\nstate_dir: %q\nlog_level: \"info\"\nenrollment:\n  challenge: %q\n",
		"https://pki.homelab.lan:8444", slash+"/etc/myownpki-agent/root.pem", p.Host, slash+"/var/lib/myownpki-agent", p.Challenge)
	paths := "[]"
	if p.Webroot != "" {
		yaml += fmt.Sprintf("  webroot: %q\n", slash+p.Webroot)
		paths = fmt.Sprintf("[%q]", slash+p.Webroot)
	}
	yaml += "paths: " + paths + "\ndeployments: []\n"
	config := filepath.Join(root, "etc", "myownpki-agent", "agent.yaml")
	unit := filepath.Join(root, "etc", "systemd", "system", "myownpki-agent.service")
	for file, body := range map[string]string{config: yaml, unit: "[Unit]\n"} {
		if err := os.WriteFile(file, []byte(body), 0o600); err != nil { // #nosec G306 -- a test file
			t.Fatal(err)
		}
	}
	return agent.DryRunHost{Root: root, ConfigPath: config, UnitPath: unit}
}

// assertAgentAccepts is the central check: the line the page prints, run by
// bash, is read by the agent's own flag parser into exactly what the plan
// says, and the agent's own validation accepts it in a dry run on a host set
// up for the plan.
func assertAgentAccepts(t *testing.T, p hostPlan, block string) {
	t.Helper()
	calls, installs := runBlock(t, block)
	if len(calls) != 1 || len(calls[0]) < 2 || calls[0][0] != "deployment" || calls[0][1] != "add" {
		t.Fatalf("want exactly one deployment add call, got %q in\n%s", calls, block)
	}
	host := newDryRunHost(t, p)
	fs := flag.NewFlagSet("deployment add", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	config := fs.String("config", host.ConfigPath, "")
	cmd, err := agent.ParseDeploymentAdd(fs, config, calls[0][2:])
	if err != nil {
		t.Fatalf("the agent cannot parse %q: %v\n%s", calls[0], err, block)
	}
	s := cmd.Spec
	if s.Name != p.Service.ID || !slices.Equal(s.Names, p.Names) || s.Challenge != p.Challenge || s.Webroot != p.Webroot ||
		s.ACMEDirectory != testACMEDirectory || s.Recipe != p.Service.Recipe || !cmd.Restart || cmd.DryRun || cmd.CreateDirs {
		t.Errorf("the agent reads %+v, the page shows %+v\n%s", cmd, p, block)
	}
	if p.Service.Recipe == "" && (s.Dir != certDirRoot+"/"+p.Host || s.KeyMode != "0600" || len(s.Hooks) != 0 || s.TestHook != "" || s.ReloadHook != "") {
		t.Errorf("files only: %+v", s)
	}
	if p.Service.Recipe != "" {
		// Hooks, sandbox and check come from the recipe, never from the line.
		r, _ := recipe.Get(p.Service.Recipe)
		for _, h := range s.Hooks {
			if !slices.ContainsFunc(r.Hooks, func(rh recipe.Hook) bool { return rh.Name == h.Name && slices.Equal(rh.Command, h.Command) }) {
				t.Errorf("hook %v is not the recipe's", h)
			}
		}
		if s.Check != r.Check || s.LowPorts != r.LowPorts || !slices.Equal(s.SandboxWrite, r.SandboxWrite) {
			t.Errorf("recipe values changed: %+v", s)
		}
	}
	// install -d makes exactly the parents of the certificate directory.
	var made []string
	for _, call := range installs {
		if len(call) != 4 || call[0] != "-d" || call[1] != "-m" || call[2] != "0755" {
			t.Errorf("install call %q", call)
			continue
		}
		made = append(made, call[3])
	}
	if !slices.Equal(made, certParents(p)) {
		t.Errorf("install -d made %q, want %q", made, certParents(p))
	}
	// The directories exist on a real host: the parents the block made, the
	// webroot and the service's log directory.
	for _, dir := range append(append(made, p.Webroot), s.SandboxWrite...) {
		if dir == "" {
			continue
		}
		if err = os.MkdirAll(filepath.Join(host.Root, filepath.FromSlash(dir)), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	before := snapshotDir(t, host.Root)
	var stderr bytes.Buffer
	host.Stderr = &stderr
	out, err := agent.DryRunDeploymentAdd(context.Background(), cmd, host)
	if err != nil {
		t.Fatalf("the agent refuses the line it was shown: %v\n%s\n%s", err, out, block)
	}
	if !strings.Contains(out, "Dry run: nothing was written.") || !strings.Contains(out, p.Service.ID) {
		t.Errorf("dry run output:\n%s", out)
	}
	if after := snapshotDir(t, host.Root); !maps_equal(before, after) {
		t.Error("the dry run changed the host")
	}
}

func maps_equal(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func snapshotDir(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		if d.IsDir() {
			out[rel] = "dir"
			return nil
		}
		data, readErr := os.ReadFile(p) // #nosec G122 -- a private temporary directory
		out[rel] = string(data)
		return readErr
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// Every service and both challenges, with and without more names: the line is
// the one in the docs, and the agent parses and accepts it.
func TestGeneratedDeploymentLineIsWhatTheAgentReads(t *testing.T) {
	for _, svc := range hostServices {
		for _, challenge := range []string{"webroot", "standalone"} {
			for _, extras := range [][]string{nil, {"www.homelab.lan", "mail.homelab.lan"}} {
				t.Run(svc.ID+"/"+challenge+"/"+fmt.Sprint(len(extras)), func(t *testing.T) {
					p := hostPlanFor(t, svc.ID, challenge, extras...)
					assertAgentAccepts(t, p, deploymentAddCommand(p, testACMEDirectory))
				})
			}
		}
	}
}

// The exact lines, one per recipe: these are what the docs show.
func TestGeneratedDeploymentLines(t *testing.T) {
	t.Parallel()
	want := map[string]string{
		"nginx": "( set -euo pipefail\n" +
			"install -d -m 0755 '/etc/ssl/myownpki'\n" +
			"/usr/local/bin/myownpki-agent deployment add 'nginx' \\\n  --recipe nginx \\\n  --name 'proxy1.homelab.lan' \\\n  --challenge webroot --webroot '/var/www/acme' \\\n" +
			"  --acme-directory 'https://pki.homelab.lan/acme/directory' \\\n  --restart\n )\n",
		"postfix": "( set -euo pipefail\n" +
			"install -d -m 0755 '/etc/ssl/myownpki/postfix'\n" +
			"/usr/local/bin/myownpki-agent deployment add 'postfix' \\\n  --recipe postfix \\\n  --name 'proxy1.homelab.lan' \\\n  --challenge webroot --webroot '/var/www/acme' \\\n" +
			"  --acme-directory 'https://pki.homelab.lan/acme/directory' \\\n  --restart\n )\n",
		"files": "( set -euo pipefail\n" +
			"install -d -m 0755 '/etc/ssl/myownpki'\n" +
			"/usr/local/bin/myownpki-agent deployment add 'files' \\\n  --dir '/etc/ssl/myownpki/proxy1.homelab.lan' \\\n  --key-mode 0600 \\\n  --name 'proxy1.homelab.lan' \\\n  --challenge webroot --webroot '/var/www/acme' \\\n" +
			"  --acme-directory 'https://pki.homelab.lan/acme/directory' \\\n  --restart\n )\n",
	}
	for id, block := range want {
		if got := deploymentAddCommand(hostPlanFor(t, id, "webroot"), testACMEDirectory); got != block {
			t.Errorf("%s:\n%s\nwant:\n%s", id, got, block)
		}
	}
	// Standalone has no webroot, extra names repeat --name.
	got := deploymentAddCommand(hostPlanFor(t, "dovecot", "standalone", "imap.homelab.lan"), testACMEDirectory)
	for _, line := range []string{"--recipe dovecot", "--name 'proxy1.homelab.lan'", "--name 'imap.homelab.lan'", "--challenge standalone \\\n"} {
		if !strings.Contains(got, line) {
			t.Errorf("dovecot lacks %q:\n%s", line, got)
		}
	}
	if strings.Contains(got, "--webroot") {
		t.Errorf("standalone with a webroot:\n%s", got)
	}
}

// Hostile input: either the plan is refused, or the line it makes is read by
// the agent as exactly what the plan says. Nothing in between.
func TestHostileFormValuesNeverReachTheAgentAsSomethingElse(t *testing.T) {
	for _, field := range []string{"hostname", "names", "webroot", "service", "challenge", "format", "arch", "admission"} {
		for _, v := range hostileValues {
			t.Run(fmt.Sprintf("%s=%.20q", field, v), func(t *testing.T) {
				p, err := parseHostPlan(goodForm(map[string]string{field: v}), true)
				if err != nil {
					return // refused early: the page says why and shows the form again
				}
				if field == "service" || field == "challenge" || field == "format" || field == "arch" || field == "admission" {
					if v != "" && v != "none" {
						t.Fatalf("%s=%q accepted", field, v)
					}
				}
				assertAgentAccepts(t, p, deploymentAddCommand(p, testACMEDirectory))
			})
		}
	}
	// Combinations the single-field loop cannot reach.
	for _, form := range []map[string]string{
		{"hostname": "PROXY1.HOMELAB.LAN.", "names": "a.homelab.lan"},
		{"webroot": "/var/www/-rf", "hostname": "a-b.c-d.homelab.lan"},
		{"names": "--recipe.homelab.lan"},
	} {
		if p, err := parseHostPlan(goodForm(form), true); err == nil {
			assertAgentAccepts(t, p, deploymentAddCommand(p, testACMEDirectory))
		}
	}
}

// The builder alone, with values no validation has seen: every one of them is a
// single word in the line, nothing is executed. This is the layer that quoting
// protects when a check upstream is wrong or forgotten.
func TestDeploymentAddCommandQuotesWhateverItIsGiven(t *testing.T) {
	t.Parallel()
	for _, v := range hostileValues {
		for _, svc := range []string{"nginx", "files"} {
			plan := hostPlan{Host: v, Names: []string{v, v + "2"}, Service: hostService{ID: svc, Recipe: map[string]string{"nginx": "nginx"}[svc]}, Challenge: "webroot", Webroot: v}
			block := deploymentAddCommand(plan, v)
			var line string
			for _, l := range strings.SplitAfter(block, "\n") {
				_ = l
			}
			line = strings.TrimSuffix(strings.TrimPrefix(block, "( set -euo pipefail\n"), "\n )\n")
			// Drop the install -d lines (their own quoting is covered by the loop below).
			if i := strings.Index(line, agentdist.BinaryPath); i >= 0 {
				line = line[i:]
			}
			words, err := shellWords(line)
			if err != nil {
				t.Errorf("service %s value %q: %v\n%s", svc, v, err, block)
				continue
			}
			for _, want := range []string{v, v + "2"} {
				if !slices.Contains(words, want) {
					t.Errorf("service %s: %.40q is not a word of the line", svc, want)
				}
			}
			if v != "" && !slices.Contains(words, "--webroot") {
				t.Errorf("service %s: no --webroot word in %q", svc, words)
			}
			i := slices.Index(words, "--acme-directory")
			if i < 0 || i+1 >= len(words) || words[i+1] != v {
				t.Errorf("service %s: the ACME directory %q is not one word after --acme-directory: %q", svc, v, words)
			}
			if words[0] != agentdist.BinaryPath || words[1] != "deployment" || words[2] != "add" || words[3] != svc {
				t.Errorf("service %s: leading words %q", svc, words[:4])
			}
			if strings.Count(line, agentdist.BinaryPath) != 1 {
				t.Errorf("service %s value %q: a second command in the line", svc, v)
			}
			if !strings.ContainsAny(v, "\x00\r") && len(v) < 1000 { // bash cannot hold a NUL; Git Bash on Windows drops a CR and limits a command line to 32 KiB
				calls, _ := runBlock(t, strings.ReplaceAll(block, "install -d", ":"))
				if len(calls) != 1 || !slices.Contains(calls[0], v) {
					t.Errorf("service %s: bash did not pass %q as one word: %q", svc, v, calls)
				}
			}
		}
	}
}

func TestCertParentsAreTheRecipeDirectories(t *testing.T) {
	t.Parallel()
	for id, want := range map[string][]string{
		"nginx": {"/etc/ssl/myownpki"}, "postfix": {"/etc/ssl/myownpki/postfix"}, "dovecot": {"/etc/ssl/myownpki/dovecot"},
		"proxmox": {"/etc/ssl/myownpki/pve"}, "files": {"/etc/ssl/myownpki"},
	} {
		svc, _ := hostServiceByID(id)
		if got := certParents(hostPlan{Service: svc}); !slices.Equal(got, want) {
			t.Errorf("%s: %q, want %q", id, got, want)
		}
	}
	for _, s := range hostServices {
		if s.Recipe == "" {
			continue
		}
		if _, ok := recipe.Get(s.Recipe); !ok {
			t.Errorf("service %s names the unknown recipe %q", s.ID, s.Recipe)
		}
		if path.Base(s.ID) != s.ID || strings.ContainsAny(s.ID, " ./") {
			t.Errorf("service id %q is not a plain deployment name", s.ID)
		}
	}
}

func TestACMEDirectoryForTheAgent(t *testing.T) {
	t.Parallel()
	if got, err := acmeDirectoryFor(testACMEDirectory); err != nil || got != testACMEDirectory {
		t.Errorf("https directory: %q %v", got, err)
	}
	for _, bad := range []string{"", "http://pki.homelab.lan/acme/directory", "pki.homelab.lan", "https://"} {
		if _, err := acmeDirectoryFor(bad); err == nil || !strings.Contains(err.Error(), agents.ErrInvalid.Error()) {
			t.Errorf("acmeDirectoryFor(%q) = %v", bad, err)
		}
	}
}

// clipForLog keeps a failure message readable when a test value is 5000 bytes long.
func clipForLog(s string) string {
	if len(s) > 600 {
		return s[:600] + "…"
	}
	return s
}
