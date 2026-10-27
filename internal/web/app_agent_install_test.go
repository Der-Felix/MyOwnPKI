package web

import (
	"crypto/sha1" // #nosec G505 -- verifies the display-only Windows dialog value
	"crypto/sha256"
	"encoding/hex"
	stdhtml "html"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/agentdist"
	"github.com/Der-Felix/MyOwnPKI/internal/agents"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
	"github.com/Der-Felix/MyOwnPKI/internal/testinstance"
)

func guidedForm(csrf, host string) url.Values {
	return url.Values{"csrf_token": {csrf}, "hostname": {host}, "arch": {"amd64"}, "format": {"deb"}, "mode": {"standalone"}, "webroot": {""}, "token": {"yes"}}
}

func TestGuidedAgentInstallTrustStepUpAndOneTimeToken(t *testing.T) {
	t.Parallel()
	v, svc := newAgentsUIEnv(t)
	// A different root sorts first; the trust decision must still follow the
	// configured agent TLS issuer, never an arbitrary CA.
	if _, err := v.Engine.CreateRoot(t.Context(), ca.RootRequest{CASettings: ca.CASettings{Name: "aaa-root", BaseURL: "http://other.homelab.lan"},
		Subject: ca.Subject{CommonName: "Unrelated root"}, Who: testinstance.Console}); err != nil {
		t.Fatal(err)
	}
	b := v.browser("192.0.2.1")
	b.signIn(t, "demo", v.DemoPassword)
	csrf := b.csrf(t)
	if page := b.get(t, "/agents/install"); page.Code != http.StatusOK || !strings.Contains(page.html(), "Exact host FQDN") {
		t.Fatalf("install page: %d", page.Code)
	}
	if page := b.post(t, "/agents/install", guidedForm("wrong", "proxy1.homelab.lan")); page.Code != http.StatusForbidden {
		t.Fatalf("CSRF: %d", page.Code)
	}
	v.Clock.Advance(authz.StepUpWindow + time.Second)
	r := b.post(t, "/agents/install", guidedForm(csrf, "proxy1.homelab.lan"))
	if r.Code != http.StatusSeeOther || r.location() != "/step-up" {
		t.Fatalf("protected action: %d %q", r.Code, r.location())
	}
	challenge := b.get(t, "/step-up").html()
	if !strings.Contains(challenge, "Prepare guided agent installation for exact host proxy1.homelab.lan") {
		t.Errorf("action summary: %s", challenge)
	}
	r = confirmPending(t, b, csrf, "demo")
	if r.Code != http.StatusOK || r.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("continued install: %d", r.Code)
	}
	html := r.html()
	secret := reSecret.FindString(html)
	if secret == "" {
		t.Fatal("join token was not shown once")
	}
	chain, err := v.Engine.CAChain(t.Context(), testinstance.Console, v.CAIDs["issuing"])
	if err != nil {
		t.Fatal(err)
	}
	rootSum := sha256.Sum256(chain[len(chain)-1])
	rootHex := hex.EncodeToString(rootSum[:])
	rootSHA1 := sha1.Sum(chain[len(chain)-1]) // #nosec G401 -- expected display-only value
	rootSHA1Hex := strings.ToUpper(hex.EncodeToString(rootSHA1[:]))
	packageName := "myownpki-agent_0.3.1_linux_amd64.deb"
	packageSum := sha256.Sum256([]byte(packageName))
	for _, want := range []string{
		rootHex, rootSHA1Hex, hex.EncodeToString(packageSum[:]), "http://pki.homelab.lan/ca/root/1.pem",
		"https://pki.homelab.lan:8444/agent-packages/" + packageName,
		"Root SHA-256 (DER, authoritative)", "Root SHA-1 (Windows dialog comparison only)", "Only SHA-256 authorizes installation",
		"--root-sha256", "--token-file /root/myownpki-join-token", "--hostname", "proxy1.homelab.lan",
		"--package-format deb", "--cacert /root/myownpki-root.pem", "openssl x509", "sha256sum --check",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("guided output lacks %q", want)
		}
	}
	command := "test \"$(" + `openssl x509 -in /root/myownpki-root.pem -outform DER | sha256sum | awk '{print $1}'` + ")\" = '" + rootHex + "'"
	if strings.Count(html, rootSHA1Hex) != 1 || !strings.Contains(html, stdhtml.EscapeString(command)) {
		t.Error("SHA-1 entered a command or the independent root SHA-256 literal changed")
	}
	if strings.Contains(html, "other.homelab.lan") || strings.Contains(r.location(), secret) || strings.Contains(v.logs.String(), secret) {
		t.Error("wrong trust chain or token leaked to URL/log")
	}
	if strings.Contains(html, "--token ") || strings.Contains(html, "token=") {
		t.Error("token appeared in an argument or URL")
	}
	for _, target := range []string{"/agents", "/agents/tokens", "/agents/install"} {
		if strings.Contains(b.get(t, target).html(), secret) {
			t.Errorf("token shown again on %s", target)
		}
	}
	tokens, err := svc.ListJoinTokens(t.Context(), testinstance.Console)
	if err != nil || len(tokens) != 1 {
		t.Fatalf("tokens: %v %d", err, len(tokens))
	}
	if len(tokens[0].Patterns) != 1 || tokens[0].Patterns[0] != "proxy1.homelab.lan" || tokens[0].ExpiresAt.Sub(tokens[0].CreatedAt) != 15*time.Minute {
		t.Errorf("guided token scope/TTL: %+v", tokens[0])
	}
	if !strings.Contains(b.get(t, "/agents/install").html(), "Install agent") {
		t.Error("install form missing")
	}
}

func TestGuidedAgentInstallRolesInjectionAndMode(t *testing.T) {
	t.Parallel()
	v, svc := newAgentsUIEnv(t)
	for _, role := range []authz.Role{authz.Viewer, authz.Operator} {
		name := string(role)
		v.User(t, name, false, authz.Binding{Role: role})
		b := v.browser("192.0.2." + strconv.Itoa(len(name)+1))
		b.signIn(t, name, testinstance.Password)
		if r := b.get(t, "/agents/install"); r.Code != http.StatusForbidden {
			t.Errorf("%s GET: %d", role, r.Code)
		}
		if r := b.post(t, "/agents/install", guidedForm(b.csrf(t), "proxy1.homelab.lan")); r.Code != http.StatusForbidden {
			t.Errorf("%s POST: %d", role, r.Code)
		}
	}
	b := v.browser("192.0.2.1")
	b.signIn(t, "demo", v.DemoPassword)
	csrf := b.csrf(t)
	bad := guidedForm(csrf, "proxy1.homelab.lan';id;'")
	bad.Del("token")
	if r := b.post(t, "/agents/install", bad); r.Code != http.StatusSeeOther || !strings.Contains(flashOf(t, b, "/agents/install"), "exact host") {
		t.Errorf("hostname injection: %d", r.Code)
	}
	injected := guidedForm(csrf, "proxy1.homelab.lan")
	injected.Set("action", "anything")
	if r := b.post(t, "/agents/install", injected); r.Code != http.StatusBadRequest {
		t.Errorf("injected action field: %d", r.Code)
	}
	webroot := guidedForm(csrf, "proxy1.homelab.lan")
	webroot.Del("token")
	webroot.Set("mode", "webroot")
	webroot.Set("webroot", "/var/www/acme")
	r := b.post(t, "/agents/install", webroot)
	if r.Code != http.StatusOK || !strings.Contains(r.html(), "--webroot") || strings.Contains(r.html(), "--token-file") {
		t.Errorf("webroot/no token: %d %s", r.Code, r.html())
	}
	v.Clock.Advance(authz.StepUpWindow + time.Second)
	if r := b.post(t, "/agents/install", webroot); r.Code != http.StatusSeeOther || r.location() != "/step-up" {
		t.Errorf("tokenless guided installation without fresh step-up: %d %q", r.Code, r.location())
	}
	tokens, _ := svc.ListJoinTokens(t.Context(), testinstance.Console)
	if len(tokens) != 0 {
		t.Errorf("invalid or tokenless requests created tokens: %d", len(tokens))
	}
}

func TestAgentUpdateOnlyOlderWithInstalledFormat(t *testing.T) {
	t.Parallel()
	v, svc := newAgentsUIEnvVersion(t, "v0.3.1-alpha.1")
	secret, _, err := svc.CreateJoinToken(t.Context(), testinstance.Console, "update", []string{"proxy1.homelab.lan"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	enroll(t, svc, "proxy1.homelab.lan", secret, "0.3.0")
	listAgents, err := svc.ListAgents(t.Context(), testinstance.Console)
	if err != nil || len(listAgents) != 1 {
		t.Fatalf("admitted agents: %v %d", err, len(listAgents))
	}
	id := listAgents[0].ID
	caller := &agents.Caller{Agent: pkidb.Agent{ID: id}, Who: testinstance.Console}
	if err := svc.Report(t.Context(), caller, agents.ReportInput{Version: "0.3.0", OS: "linux", Arch: "amd64", PackageFormat: "deb"}); err != nil {
		t.Fatal(err)
	}
	b := v.browser("192.0.2.1")
	b.signIn(t, "demo", v.DemoPassword)
	list := b.get(t, "/agents").html()
	if !strings.Contains(list, "update available") || !strings.Contains(list, "/agents/"+id+"/update") {
		t.Errorf("older agent list: %s", list)
	}
	update := b.get(t, "/agents/"+id+"/update")
	if update.Code != http.StatusOK || !strings.Contains(update.html(), "--package-format deb") || strings.Contains(update.html(), "--token-file") {
		t.Errorf("update command: %d %s", update.Code, update.html())
	}
	for _, version := range []string{"0.3.1", "0.3.2", "dev", "0.3.1-alpha.1"} {
		if err := svc.Report(t.Context(), caller, agents.ReportInput{Version: version, OS: "linux", Arch: "amd64", PackageFormat: "deb"}); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(b.get(t, "/agents").html(), "update available") {
			t.Errorf("update offered for %s", version)
		}
		if r := b.get(t, "/agents/"+id+"/update"); r.Code != http.StatusNotFound {
			t.Errorf("direct update for %s: %d", version, r.Code)
		}
	}
}

func TestAgentOlderUsesSemverWithoutDowngrades(t *testing.T) {
	t.Parallel()
	a := app{d: AppDeps{AgentDist: agentdist.New("", "v0.3.1")}}
	for _, tt := range []struct {
		version string
		older   bool
	}{
		{"0.3.0", true},
		{"0.3.1-alpha.1", true},
		{"0.3.1-alpha.1+build.2", true},
		{"0.3.1", false},
		{"0.3.1+build.2", false},
		{"0.3.2-alpha.1", false},
		{"0.3.2", false},
		{"dev", false},
	} {
		if got := a.agentOlder(agents.Agent{Version: tt.version}); got != tt.older {
			t.Errorf("agentOlder(%q) = %v, want %v", tt.version, got, tt.older)
		}
	}
}

func TestGuidedCommandFailClosed(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("executes the rendered POSIX shell command")
	}
	v, _ := newAgentsUIEnv(t)
	b := v.browser("192.0.2.1")
	b.signIn(t, "demo", v.DemoPassword)
	form := guidedForm(b.csrf(t), "proxy1.homelab.lan")
	form.Del("token")
	response := b.post(t, "/agents/install", form)
	if response.Code != http.StatusOK {
		t.Fatalf("render guided command: %d", response.Code)
	}
	chain, err := v.Engine.CAChain(t.Context(), testinstance.Console, v.CAIDs["issuing"])
	if err != nil {
		t.Fatal(err)
	}
	rootSum := sha256.Sum256(chain[len(chain)-1])
	rootHash := hex.EncodeToString(rootSum[:])
	var command string
	for _, part := range strings.Split(response.html(), "<pre") {
		if !strings.Contains(part, "myownpki-agent setup") {
			continue
		}
		_, body, _ := strings.Cut(part, ">")
		text, _, _ := strings.Cut(body, "</pre>")
		command = stdhtml.UnescapeString(text)
	}
	if !strings.HasPrefix(command, "( set -euo pipefail\n") || !strings.Contains(command, "apt-get install -y") {
		t.Fatalf("command is not a noninteractive fail-closed subshell:\n%s", command)
	}

	for _, tt := range []struct {
		name, rootHash, sumStatus, wantMessage string
		wantCurls                              int
		wantInstall, wantSetup                 bool
	}{
		{name: "wrong root", rootHash: strings.Repeat("0", 64), sumStatus: "0", wantMessage: "root fingerprint does not match", wantCurls: 1},
		{name: "wrong package", rootHash: rootHash, sumStatus: "1", wantMessage: "package checksum does not match", wantCurls: 3},
		{name: "success", rootHash: rootHash, sumStatus: "0", wantCurls: 3, wantInstall: true, wantSetup: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			bin := filepath.Join(dir, "bin")
			if err := os.Mkdir(bin, 0o700); err != nil {
				t.Fatal(err)
			}
			logPath := filepath.Join(dir, "calls.log")
			writeMock := func(name, body string) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			writeMock("curl", "#!/usr/bin/env bash\nprintf 'curl %s\\n' \"$*\" >> \"$MOCK_LOG\"\n")
			writeMock("openssl", "#!/usr/bin/env bash\nprintf '%s\\n' \"$MOCK_ROOT_HASH\"\n")
			writeMock("sha256sum", "#!/usr/bin/env bash\nexit \"$MOCK_SUM_STATUS\"\n")
			writeMock("apt-get", "#!/usr/bin/env bash\nprintf 'apt-get %s\\n' \"$*\" >> \"$MOCK_LOG\"\n")
			writeMock("myownpki-agent", "#!/usr/bin/env bash\nprintf 'myownpki-agent %s\\n' \"$*\" >> \"$MOCK_LOG\"\n")
			cmd := exec.CommandContext(t.Context(), "bash", "-c", command) // #nosec G204 -- actual rendered command with only mocked executables
			cmd.Env = append(os.Environ(), "PATH="+bin+":/usr/bin:/bin", "MOCK_LOG="+logPath, "MOCK_ROOT_HASH="+tt.rootHash, "MOCK_SUM_STATUS="+tt.sumStatus)
			output, err := cmd.CombinedOutput()
			if tt.name == "success" {
				if err != nil {
					t.Fatalf("rendered command failed: %v\n%s\n%s", err, output, command)
				}
			} else {
				if err == nil || !strings.Contains(string(output), tt.wantMessage) {
					t.Fatalf("failure did not stop with a clear message: %v\n%s", err, output)
				}
			}
			log, readErr := os.ReadFile(logPath)
			if readErr != nil {
				t.Fatal(readErr)
			}
			calls := string(log)
			if got := strings.Count(calls, "curl "); got != tt.wantCurls {
				t.Errorf("curl calls = %d, want %d\n%s", got, tt.wantCurls, calls)
			}
			if got := strings.Contains(calls, "apt-get install -y"); got != tt.wantInstall {
				t.Errorf("install reached = %v, want %v\n%s", got, tt.wantInstall, calls)
			}
			if got := strings.Contains(calls, "myownpki-agent setup"); got != tt.wantSetup {
				t.Errorf("setup reached = %v, want %v\n%s", got, tt.wantSetup, calls)
			}
		})
	}
}
