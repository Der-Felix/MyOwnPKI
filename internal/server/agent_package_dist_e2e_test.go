package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/agentdist"
	"github.com/Der-Felix/MyOwnPKI/internal/agents"
)

// TestAgentPackageDistributionE2E is driven by agent-package-systemd.sh on a
// disposable Linux runner. It keeps the real server up while the script uses
// the actual package manager and systemd.
func TestAgentPackageDistributionE2E(t *testing.T) {
	distDir := os.Getenv("MYOWNPKI_PACKAGE_E2E_DIST")
	control := os.Getenv("MYOWNPKI_PACKAGE_E2E_CONTROL")
	version := os.Getenv("MYOWNPKI_PACKAGE_E2E_VERSION")
	if distDir == "" || control == "" || version == "" {
		t.Skip("only the disposable served-package systemd check supplies a release")
	}
	e := newAgentEnv(t, func(opt *Options) {
		opt.Version = "v" + version
		opt.Config.Agent.PackageDir = distDir
		opt.Config.Agent.Listen = "127.0.0.1:8444"
		opt.Config.ACME.Listen = "127.0.0.1:443"
	})
	e.webroot = filepath.Join(control, "www")
	token, _, err := e.srv.Agents().CreateJoinToken(t.Context(), console, "served package", []string{"proxy1.homelab.lan"}, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := agentdist.New(distDir, version).Artifact("deb", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	rootSum := sha256.Sum256(e.rootDER)
	write := func(name, value string) {
		t.Helper()
		// #nosec G703 -- the disposable CI script supplies its private control directory.
		if writeErr := os.WriteFile(filepath.Join(control, name), []byte(value), 0o600); writeErr != nil {
			t.Fatal(writeErr)
		}
	}
	write("root-url", e.srv.PublicAddr()+"/ca/root/1.pem")
	write("root-sha256", hex.EncodeToString(rootSum[:]))
	write("package-name", artifact.Name)
	write("package-sha256", artifact.SHA256)
	write("join-token", token)
	write("ready", "ready")

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	done := filepath.Join(control, "done")
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		// #nosec G703 -- done is a fixed name in the disposable CI control directory.
		if _, statErr := os.Stat(done); statErr == nil {
			break
		} else if !os.IsNotExist(statErr) {
			t.Fatal(statErr)
		}
		select {
		case <-ctx.Done():
			t.Fatal("served-package installation did not finish")
		case <-ticker.C:
		}
	}

	for {
		list, listErr := e.srv.Agents().ListAgents(ctx, console)
		if listErr != nil {
			t.Fatal(listErr)
		}
		if len(list) == 1 && list[0].Version == "v"+version && list[0].PackageFormat == "deb" && !list[0].LastSeenAt.IsZero() {
			ag := list[0]
			if ag.Status != agents.StatusActive || ag.OS != "linux" || ag.Arch != "amd64" {
				t.Fatalf("updated agent: %+v", ag)
			}
			break
		}
		select {
		case <-ctx.Done():
			t.Fatalf("updated agent was not reported: %+v", list)
		case <-ticker.C:
		}
	}
	tokens, err := e.srv.Agents().ListJoinTokens(t.Context(), console)
	if err != nil || len(tokens) != 1 || tokens[0].UsedAt.IsZero() || tokens[0].ExpiresAt.Sub(tokens[0].CreatedAt) != 15*time.Minute {
		t.Fatalf("guided token was not consumed once with its 15-minute scope: %+v, %v", tokens, err)
	}
}
