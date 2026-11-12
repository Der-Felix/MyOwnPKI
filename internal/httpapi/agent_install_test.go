package httpapi

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/Der-Felix/MyOwnPKI/internal/agentdist"
	"github.com/Der-Felix/MyOwnPKI/internal/agents"
)

// TestAgentInstallFacts: a viewer token reads the values the guided
// installation shows; the hashes are those of the files, the root is the one
// of the agent TLS issuer, and without packages there is a plain 404.
func TestAgentInstallFacts(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	v.unseal(t)
	admin := v.client("192.0.2.1")
	admin.signIn(t, "demo", v.demoPass)
	header := tokenFor(t, admin, "viewer")
	bot := v.client("192.0.2.77")

	if r := bot.do(t, http.MethodGet, "/agent-install", nil, header...); r.Code != http.StatusNotFound {
		t.Fatalf("no distribution configured: %d %s", r.Code, r.Body.String())
	}

	dir := t.TempDir()
	dist := agentdist.New(dir, "0.3.5")
	want := map[string]string{}
	for _, f := range agentdist.Formats {
		for _, a := range agentdist.Arches {
			name, _ := dist.Name(f, a)
			content := []byte("package " + name)
			if err := os.WriteFile(filepath.Join(dir, name), content, 0o600); err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(content)
			want[name] = hex.EncodeToString(sum[:])
		}
	}
	v.agents.Install = &agents.InstallSource{Dist: dist, BaseURL: "https://pki.homelab.lan:8444/", TLSIssuer: "issuing", Clock: v.clk}
	if r := bot.do(t, http.MethodGet, "/agent-install", nil, header...); r.Code != http.StatusNotFound {
		t.Fatalf("checksums.txt missing: %d %s", r.Code, r.Body.String())
	}
	if err := os.WriteFile(filepath.Join(dir, agentdist.Checksums), []byte("sums"), 0o600); err != nil {
		t.Fatal(err)
	}
	v.clk.Advance(2 * agents.PackagesTTL)
	r := bot.do(t, http.MethodGet, "/agent-install", nil, header...)
	if r.Code != http.StatusOK {
		t.Fatalf("install facts: %d %s", r.Code, r.Body.String())
	}
	if r.body["server_url"] != "https://pki.homelab.lan:8444" || r.body["acme_directory"] != nil || r.body["agent_version"] != "0.3.5" {
		t.Errorf("facts: %v", r.body)
	}
	root, _ := r.body["root"].(map[string]any)
	sha, _ := root["sha256"].(string)
	if len(sha) != 64 || root["url"] == "" {
		t.Errorf("root: %v", root)
	}
	pkgs, _ := r.body["packages"].([]any)
	if len(pkgs) != 7 {
		t.Fatalf("%d packages", len(pkgs))
	}
	for _, p := range pkgs {
		m, _ := p.(map[string]any)
		name, _ := m["name"].(string)
		if w, ok := want[name]; ok && m["sha256"] != w {
			t.Errorf("%s: sha256 %v, want %s", name, m["sha256"], w)
		}
		if m["url"] != "https://pki.homelab.lan:8444/agent-packages/"+name {
			t.Errorf("%s: url %v", name, m["url"])
		}
	}
	// A pass or a join token is not needed and not offered here.
	if r := v.client("192.0.2.9").do(t, http.MethodGet, "/agent-install", nil); r.Code != http.StatusUnauthorized {
		t.Errorf("anonymous: %d", r.Code)
	}
}
