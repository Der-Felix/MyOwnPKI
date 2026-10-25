package agent

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
)

// Run in the pinned nginx container of the Linux agent CI job (step 9).
// The server process, config, PID, ports and certificate files belong only
// to this test; an installed system nginx is never signaled or reloaded.
func TestNginxDeployProfiles(t *testing.T) {
	bin, err := exec.LookPath("nginx")
	if err != nil {
		if os.Getenv("MYOWNPKI_REQUIRE_NGINX") == "1" {
			t.Fatal("nginx is required by the agent end-to-end CI job")
		}
		t.Skip("nginx is not installed; the Linux agent CI container runs this test")
	}
	for _, profile := range []string{ProfileNginx, ProfileFile} {
		t.Run(profile, func(t *testing.T) {
			r := newDeployRig(t, profile)
			r.installOld(t)
			d := r.a.cfg.Deployments[0]
			// Use a separate free port for nginx; the rig's TLS endpoint
			// remains isolated from this real subprocess.
			addr := freeNginxAddress(t)
			d.Check = addr
			r.a.cfg.Deployments[0] = d
			prefix := t.TempDir()
			files := deploymentPaths(d)
			cert := files.Fullchain
			if cert == "" {
				cert = files.Certificate
			}
			configuration := fmt.Sprintf("pid %s;\nerror_log %s;\nevents {}\nhttp { access_log off; server { listen %s ssl; server_name %s; ssl_certificate %s; ssl_certificate_key %s; return 200; } }\n",
				strconv.Quote(filepath.Join(prefix, "nginx.pid")), strconv.Quote(filepath.Join(prefix, "error.log")), addr, d.Names[0], strconv.Quote(cert), strconv.Quote(files.Key))
			configPath := filepath.Join(prefix, "nginx.conf")
			if err := os.WriteFile(configPath, []byte(configuration), 0o600); err != nil {
				t.Fatal(err)
			}
			r.a.cfg.Hooks["test"] = []string{bin, "-p", prefix, "-c", configPath, "-t", "-q"}
			r.a.cfg.Hooks["reload"] = []string{bin, "-p", prefix, "-c", configPath, "-s", "reload"}
			r.a.runHookForTest = nil
			r.a.Sleep = sleep                                                                                 // readiness of a real subprocess uses the production bounded TLS retries
			cmd := exec.CommandContext(t.Context(), bin, "-p", prefix, "-c", configPath, "-g", "daemon off;") // #nosec G204 G702 -- test-only nginx executable and private config
			// T.Context is canceled before cleanup. Quit the owned master
			// gracefully so it also stops its workers before Wait returns.
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
			if _, err := r.a.checkServed(t.Context(), d, fingerprint(r.old[d.Name].Leaf.Raw)); err != nil {
				t.Fatal(err)
			}
			if _, err := r.a.RunPass(t.Context(), nil); err != nil {
				t.Fatal(err)
			}
			if _, err := r.a.checkServed(t.Context(), d, fingerprint(r.next[d.Name].Leaf.Raw)); err != nil {
				t.Fatal(err)
			}
			// Simulate corruption after the validated ACME material was staged:
			// nginx -t must reject a certificate/key mismatch, without a reload.
			newer := map[string]*Material{d.Name: testMaterial(t, d.Names[0], 900)}
			group := groups(r.a.cfg.Deployments)[0]
			journal, err := r.a.stageGroup(group, newer)
			if err != nil {
				t.Fatal(err)
			}
			if err := r.a.atomicTarget(targetFile{files.Key, r.old[d.Name].Key, 0o600, -1, -1}); err != nil {
				t.Fatal(err)
			}
			failure := r.a.runTests(t.Context(), group)
			if failure == nil {
				t.Fatal("nginx -t accepted a mismatched key")
			}
			results, rollbackErr := r.a.rollback(t.Context(), group, journal, false, failure)
			if !errors.Is(rollbackErr, failure) || len(results) != 1 || results[0].State != "rolled_back" {
				t.Fatal("nginx test failure did not roll back")
			}
			if _, err := r.a.checkServed(t.Context(), d, fingerprint(r.next[d.Name].Leaf.Raw)); err != nil {
				t.Fatal(err)
			}
			r.assertFiles(t, r.next)
		})
	}
}

func freeNginxAddress(t *testing.T) string {
	t.Helper()
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}
