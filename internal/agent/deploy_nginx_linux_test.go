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
	"strings"
	"syscall"
	"testing"
	"time"
)

// Run in the pinned nginx container of the Linux agent CI job (step 9).
// The server process, config, PID, ports and certificate files belong only
// to this test; an installed system nginx is never signaled or reloaded.
func TestNginxDeployProfiles(t *testing.T) {
	if _, err := exec.LookPath("nginx"); err != nil {
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
			files := startNginx(t, r, d)
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

func startNginx(t *testing.T, r *deployRig, d Deployment) Files {
	t.Helper()
	bin, err := exec.LookPath("nginx")
	if err != nil {
		t.Fatal("nginx is required")
	}
	prefix := t.TempDir()
	files := deploymentPaths(d)
	certificate := files.Fullchain
	if certificate == "" {
		certificate = files.Certificate
	}
	configuration := fmt.Sprintf("pid %s;\nerror_log %s;\nevents {}\nhttp { access_log off; server { listen %s ssl; server_name %s; ssl_certificate %s; ssl_certificate_key %s; return 200; } }\n",
		strconv.Quote(filepath.Join(prefix, "nginx.pid")), strconv.Quote(filepath.Join(prefix, "error.log")), d.Check, d.Names[0], strconv.Quote(certificate), strconv.Quote(files.Key))
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
	go func() {
		done <- cmd.Wait()
		close(done)
	}()
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
	waitForNginxPID(t, filepath.Join(prefix, "nginx.pid"), done)
	if _, err := r.a.checkServed(t.Context(), d, fingerprint(r.old[d.Name].Leaf.Raw)); err != nil {
		t.Fatalf("nginx did not serve the old certificate after writing its PID: %v", err)
	}
	return files
}

func waitForNginxPID(t *testing.T, path string, done <-chan error) {
	t.Helper()
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case err := <-done:
			t.Fatalf("nginx exited before writing a valid PID: %v", err)
		case <-deadline.C:
			t.Fatalf("nginx did not write a valid PID within 10s: %s", path)
		case <-ticker.C:
			data, err := os.ReadFile(path) // #nosec G304 -- test-owned PID file
			if err != nil {
				continue
			}
			pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
			if err == nil && pid > 0 {
				return
			}
		}
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
