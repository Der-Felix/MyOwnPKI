package agent

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestBlockCConfigBoundaries(t *testing.T) {
	t.Parallel()
	for _, scenario := range []string{"ip", "wildcard", "dotdot", "duplicate", "state", "trust", "port", "symlink"} {
		t.Run(scenario, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			cfg := &Config{Server: "https://pki.homelab.lan:8444", CABundle: filepath.Join(dir, "root.pem"), Hostname: "proxy1.homelab.lan", StateDir: filepath.Join(dir, "state"),
				LogLevel: "info", ACMEDirectory: "https://pki.homelab.lan/acme/directory", Enrollment: Enrollment{Challenge: ChallengeStandalone}, Paths: []string{dir}}
			d := Deployment{Name: "proxy", Profile: ProfileFile, Names: []string{"proxy1.homelab.lan"}, Challenge: ChallengeStandalone,
				Files: Files{Fullchain: filepath.Join(dir, "ssl", "fullchain.pem"), Key: filepath.Join(dir, "ssl", "key.pem")}}
			switch scenario {
			case "ip":
				d.Names = []string{"192.0.2.10"}
			case "wildcard":
				d.Names = []string{"*.homelab.lan"}
			case "dotdot":
				d.Files.Key = filepath.Join(dir, "ssl") + string(filepath.Separator) + ".." + string(filepath.Separator) + "key.pem"
			case "duplicate":
				d.Files.Key = d.Files.Fullchain
			case "state":
				d.Files.Key = filepath.Join(cfg.StateDir, "agent.key")
			case "trust":
				d.Files.Fullchain = cfg.CABundle
			case "port":
				d.Check = "127.0.0.1:0"
			case "symlink":
				if err := os.Symlink(t.TempDir(), filepath.Join(dir, "ssl")); err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
			}
			cfg.Deployments = []Deployment{d}
			if err := cfg.Validate(); !errors.Is(err, ErrInvalid) {
				t.Fatalf("%s boundary accepted: %v", scenario, err)
			}
		})
	}
}
