//go:build e2etest

package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
)

func TestNginxStagedFaultRollsBack(t *testing.T) {
	bin, err := exec.LookPath("nginx")
	if err != nil {
		t.Fatal("nginx is required in the agent end-to-end CI image")
	}
	for _, profile := range []string{ProfileNginx, ProfileFile} {
		t.Run(profile, func(t *testing.T) {
			r := newDeployRig(t, profile)
			r.installOld(t)
			d := r.a.cfg.Deployments[0]
			addr := freeNginxAddress(t)
			d.Check = addr
			r.a.cfg.Deployments[0] = d
			prefix := t.TempDir()
			files := deploymentPaths(d)
			certificate := files.Fullchain
			if certificate == "" {
				certificate = files.Certificate
			}
			configuration := fmt.Sprintf("pid %s;\nerror_log %s;\nevents {}\nhttp { access_log off; server { listen %s ssl; server_name %s; ssl_certificate %s; ssl_certificate_key %s; return 200; } }\n",
				strconv.Quote(filepath.Join(prefix, "nginx.pid")), strconv.Quote(filepath.Join(prefix, "error.log")), addr, d.Names[0], strconv.Quote(certificate), strconv.Quote(files.Key))
			configPath := filepath.Join(prefix, "nginx.conf")
			if err := os.WriteFile(configPath, []byte(configuration), 0o600); err != nil {
				t.Fatal(err)
			}
			r.a.cfg.Hooks["test"] = []string{bin, "-p", prefix, "-c", configPath, "-t", "-q"}
			r.a.cfg.Hooks["reload"] = []string{bin, "-p", prefix, "-c", configPath, "-s", "reload"}
			r.a.runHookForTest = nil
			r.a.Sleep = sleep
			cmd := exec.CommandContext(t.Context(), bin, "-p", prefix, "-c", configPath, "-g", "daemon off;") // #nosec G204 G702 -- test-only nginx executable and private config
			cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGQUIT) }
			cmd.WaitDelay = 5 * time.Second
			cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			t.Cleanup(func() {
				_ = cmd.Process.Signal(syscall.SIGQUIT)
				timer := time.NewTimer(5 * time.Second)
				defer timer.Stop()
				select {
				case <-done:
				case <-timer.C:
					_ = cmd.Process.Kill()
					<-done
				}
			})
			if _, err := r.a.RunPass(t.Context(), nil); err != nil {
				t.Fatal(err)
			}
			r.a.obtainForTest = func(context.Context, Deployment) (*Material, error) {
				return testMaterial(t, d.Names[0], 900), nil
			}
			if err := os.WriteFile(r.a.st.path(stagedFaultMarker), []byte("next pass\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			results, passErr := r.a.RunPass(t.Context(), nil)
			if passErr == nil || len(results) != 1 || results[0].State != "rolled_back" {
				t.Fatalf("staged fault did not roll back: %+v, %v", results, passErr)
			}
			if _, err := r.a.checkServed(t.Context(), d, fingerprint(r.next[d.Name].Leaf.Raw)); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(r.a.st.path(stagedFaultMarker)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("one-shot staged fault marker remains")
			}
			r.assertFiles(t, r.next)
		})
	}
}

func TestNginxPort443InSystemdSandbox(t *testing.T) {
	if os.Getenv("MYOWNPKI_SYSTEMD_E2E") != "1" {
		t.Skip("runs only as the ExecStart of the real unit in the agent CI job")
	}
	bin, err := exec.LookPath("nginx")
	if err != nil {
		t.Fatal("nginx is required in the systemd sandbox")
	}
	prefix := "/var/lib/myownpki-agent/nginx-e2e"
	if err := os.MkdirAll(prefix, 0o700); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(prefix, "nginx.conf")
	configuration := fmt.Sprintf("pid %s;\nerror_log /var/log/nginx/myownpki-agent-e2e-error.log;\nevents {}\nhttp { access_log off; server { listen 0.0.0.0:443; server_name _; return 200; } }\n",
		strconv.Quote(filepath.Join(prefix, "nginx.pid")))
	if err := os.WriteFile(configPath, []byte(configuration), 0o600); err != nil {
		t.Fatal(err)
	}
	a := &Agent{cfg: &Config{Hooks: map[string][]string{"test": {bin, "-p", prefix, "-c", configPath, "-t", "-q"}}}}
	group := reloadGroup{deployments: []Deployment{{Name: "proxy", TestHook: "test"}}}
	if err := a.runTests(t.Context(), group); err != nil {
		t.Fatalf("nginx -t on port 443 failed inside the real unit: %v", err)
	}
}
