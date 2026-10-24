package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type deployRig struct {
	a                      *Agent
	old, next              map[string]*Material
	served                 map[string]*atomic.Pointer[tls.Certificate]
	testCalls, reloadCalls int
}

func newDeployRig(t *testing.T, profiles ...string) *deployRig {
	t.Helper()
	dir := t.TempDir()
	root := filepath.Join(dir, "ssl")
	if err := os.Mkdir(root, 0o750); err != nil {
		t.Fatal(err)
	}
	a := &Agent{cfg: &Config{Paths: []string{root}, Hooks: map[string][]string{
		"test": {filepath.Join(dir, "test")}, "reload": {filepath.Join(dir, "reload")},
	}}, st: state{filepath.Join(dir, "state")}, log: slog.New(slog.DiscardHandler),
		Now:   func() time.Time { return time.Date(2026, 10, 24, 0, 0, 0, 0, time.UTC) },
		Sleep: func(ctx context.Context, _ time.Duration) error { return ctx.Err() },
	}
	if err := a.st.ensure(); err != nil {
		t.Fatal(err)
	}
	r := &deployRig{a: a, old: map[string]*Material{}, next: map[string]*Material{}, served: map[string]*atomic.Pointer[tls.Certificate]{}}
	for i, profile := range profiles {
		name := fmt.Sprintf("service%d", i)
		d := Deployment{Name: name, Profile: profile, Names: []string{name + ".homelab.lan"}, TestHook: "test", ReloadHook: "reload"}
		if profile == ProfileNginx {
			d.Dir = filepath.Join(root, name)
		} else {
			d.Files = Files{Certificate: filepath.Join(root, name+".crt"), Chain: filepath.Join(root, name+".chain"), Fullchain: filepath.Join(root, name+".fullchain"), Key: filepath.Join(root, name+".key")}
		}
		r.old[name], r.next[name] = testMaterial(t, d.Names[0], int64(i+1)), testMaterial(t, d.Names[0], int64(i+100))
		pair, err := tls.X509KeyPair(r.old[name].Certificate, r.old[name].Key)
		if err != nil {
			t.Fatal(err)
		}
		pointer := &atomic.Pointer[tls.Certificate]{}
		pointer.Store(&pair)
		r.served[name] = pointer
		server := httptest.NewUnstartedServer(http.NotFoundHandler())
		server.Config.ErrorLog = slog.NewLogLogger(slog.DiscardHandler, slog.LevelError)
		server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if hello.ServerName != d.Names[0] {
				return nil, errors.New("unexpected SNI")
			}
			return pointer.Load(), nil
		}}
		server.StartTLS()
		t.Cleanup(server.Close)
		d.Check = server.Listener.Addr().String()
		a.cfg.Deployments = append(a.cfg.Deployments, d)
	}
	a.obtainForTest = func(_ context.Context, d Deployment) (*Material, error) { return cloneMaterial(r.next[d.Name]), nil }
	a.runHookForTest = func(_ context.Context, name string) error {
		if name == "test" {
			r.testCalls++
			return nil
		}
		r.reloadCalls++
		return r.loadFiles()
	}
	return r
}

func (r *deployRig) loadFiles() error {
	for _, d := range r.a.cfg.Deployments {
		files := deploymentPaths(d)
		cert := files.Fullchain
		if cert == "" {
			cert = files.Certificate
		}
		pair, err := tls.LoadX509KeyPair(cert, files.Key)
		if err != nil {
			return errors.New("test service could not load the files")
		}
		r.served[d.Name].Store(&pair)
	}
	return nil
}

func (r *deployRig) installOld(t *testing.T) {
	t.Helper()
	for _, d := range r.a.cfg.Deployments {
		files, err := targets(d, r.old[d.Name])
		if err != nil {
			t.Fatal(err)
		}
		for _, file := range files {
			if err := r.a.atomicTarget(file); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func (r *deployRig) assertFiles(t *testing.T, materials map[string]*Material) {
	t.Helper()
	for _, d := range r.a.cfg.Deployments {
		if materials[d.Name] == nil {
			continue
		}
		files, err := targets(d, materials[d.Name])
		if err != nil {
			t.Fatal(err)
		}
		for _, file := range files {
			data, info, err := r.a.readTarget(file.path)
			if err != nil || !bytes.Equal(data, file.data) {
				t.Fatalf("%s: target differs from the expected complete file (%v)", d.Name, err)
			}
			if runtime.GOOS != "windows" && info.Mode().Perm() != file.mode {
				t.Errorf("%s: mode %o, want %o", d.Name, info.Mode().Perm(), file.mode)
			}
		}
	}
}

func TestDeployProfilesAndSharedReload(t *testing.T) {
	t.Parallel()
	r := newDeployRig(t, ProfileNginx, ProfileFile)
	r.installOld(t)
	results, err := r.a.RunPass(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.testCalls != 1 || r.reloadCalls != 1 || len(results) != 2 {
		t.Fatalf("test/reload/results: %d/%d/%d", r.testCalls, r.reloadCalls, len(results))
	}
	for _, result := range results {
		if result.State != "deployed" || result.Fingerprint != fingerprint(r.next[result.Name].Leaf.Raw) {
			t.Fatalf("wrong deployment result: %+v", result)
		}
	}
	r.assertFiles(t, r.next)
	if _, err := os.Stat(r.a.st.path(journalFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("journal remains after success")
	}
	if results := r.a.Status().Deployments; len(results) != 2 {
		t.Fatal("results were not saved for Report")
	}
}

func TestDeployGroupRollback(t *testing.T) {
	t.Parallel()
	for _, failure := range []string{"test", "reload", "check", "rollback"} {
		t.Run(failure, func(t *testing.T) {
			t.Parallel()
			r := newDeployRig(t, ProfileNginx, ProfileFile)
			r.installOld(t)
			r.a.runHookForTest = func(_ context.Context, name string) error {
				if name == "test" {
					r.testCalls++
					if failure == "test" && r.testCalls == 1 {
						return errors.New("configuration test rejected the new files")
					}
					return nil
				}
				r.reloadCalls++
				if failure == "rollback" {
					if r.reloadCalls == 1 {
						return errors.New("primary reload error")
					}
					return errors.New("rollback reload error")
				}
				if r.reloadCalls == 1 {
					if failure == "reload" {
						return errors.New("primary reload error")
					}
					if failure == "check" {
						return nil
					} // the service keeps the old certificate
				}
				return r.loadFiles()
			}
			results, err := r.a.RunPass(t.Context(), nil)
			if err == nil {
				t.Fatal("the failure was hidden")
			}
			wantState, wantReloads := "rolled_back", 2
			if failure == "test" {
				wantReloads = 0
			}
			if failure == "rollback" {
				wantState = "failed"
			}
			if r.reloadCalls != wantReloads {
				t.Fatalf("%d reload attempts, want %d", r.reloadCalls, wantReloads)
			}
			for _, result := range results {
				if result.State != wantState || result.LastError == "" {
					t.Fatalf("wrong rollback result: %+v", result)
				}
				if failure == "rollback" && (!strings.Contains(result.LastError, "primary reload error") || !strings.Contains(result.LastError, "rollback reload error")) {
					t.Fatal("both failures must be reported")
				}
			}
			r.assertFiles(t, r.old)
			if _, err := os.Stat(r.a.st.path(journalFile)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("a completed rollback left a journal and could retry automatically")
			}
		})
	}
}

func TestDeployFirstInstallFailure(t *testing.T) {
	t.Parallel()
	for _, failure := range []string{"test", "reload", "check"} {
		t.Run(failure, func(t *testing.T) {
			t.Parallel()
			r := newDeployRig(t, ProfileNginx, ProfileFile)
			r.a.runHookForTest = func(_ context.Context, name string) error {
				if name == "test" {
					r.testCalls++
					if failure == "test" || r.testCalls > 1 {
						return errors.New("configuration references files absent before the first installation")
					}
					return nil
				}
				r.reloadCalls++
				if failure == "reload" {
					return errors.New("initial reload failed")
				}
				return nil
			}
			results, err := r.a.RunPass(t.Context(), nil)
			if err == nil {
				t.Fatal("initial failure was hidden")
			}
			wantReloads := 1
			if failure == "test" {
				wantReloads = 0
			}
			if r.reloadCalls != wantReloads {
				t.Fatal("a first install attempted a rollback reload")
			}
			if r.testCalls != 2 {
				t.Fatal("the restored configuration was not tested")
			}
			for _, result := range results {
				if result.State != "failed" {
					t.Fatal("a first install cannot claim rolled_back")
				}
			}
			for _, d := range r.a.cfg.Deployments {
				f := deploymentPaths(d)
				for _, path := range []string{f.Certificate, f.Chain, f.Fullchain, f.Key} {
					if path == "" {
						continue
					}
					if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
						t.Fatal("a new file remained after initial failure")
					}
				}
			}
		})
	}
}

func TestDeployMixedGroupRollback(t *testing.T) {
	t.Parallel()
	for _, failure := range []string{"before_reload", "tls_check", "restored_test"} {
		t.Run(failure, func(t *testing.T) {
			t.Parallel()
			r := newDeployRig(t, ProfileNginx, ProfileFile)
			r.installOld(t)
			existing, initial := r.a.cfg.Deployments[0], r.a.cfg.Deployments[1]
			newFiles, targetErr := targets(initial, r.old[initial.Name])
			if targetErr != nil {
				t.Fatal(targetErr)
			}
			for _, file := range newFiles {
				if err := os.Remove(file.path); err != nil {
					t.Fatal(err)
				}
			}
			r.a.runHookForTest = func(_ context.Context, hook string) error {
				if hook == "test" {
					r.testCalls++
					if (failure == "before_reload" && r.testCalls == 1) || (failure == "restored_test" && r.testCalls == 2) {
						return errors.New("configuration test failed")
					}
					return nil
				}
				r.reloadCalls++
				if r.reloadCalls == 1 {
					if err := r.loadFiles(); err != nil {
						return err
					}
					// The existing deployment really serves the new leaf. Only
					// the first installation's TLS check fails after this reload.
					old, err := tls.X509KeyPair(r.old[initial.Name].Fullchain, r.old[initial.Name].Key)
					if err != nil {
						return err
					}
					r.served[initial.Name].Store(&old)
					return nil
				}
				f := deploymentPaths(existing)
				old, err := tls.LoadX509KeyPair(f.Fullchain, f.Key)
				if err == nil {
					r.served[existing.Name].Store(&old)
				}
				return err
			}
			results, err := r.a.RunPass(t.Context(), nil)
			if err == nil || len(results) != 2 || r.testCalls != 2 {
				t.Fatalf("mixed rollback: results=%d, tests=%d, error=%v", len(results), r.testCalls, err)
			}
			wantReloads := 2
			switch failure {
			case "before_reload":
				wantReloads = 0
			case "restored_test":
				wantReloads = 1
			}
			if r.reloadCalls != wantReloads {
				t.Fatalf("reload attempts=%d, want %d", r.reloadCalls, wantReloads)
			}
			for _, result := range results {
				want := "rolled_back"
				if result.Name == initial.Name || failure == "restored_test" {
					want = "failed"
				}
				if result.State != want {
					t.Fatalf("mixed rollback result: %+v", result)
				}
				if failure == "restored_test" && !strings.Contains(result.LastError, "service still has the state from before the rollback") {
					t.Fatalf("missing service-state explanation: %+v", result)
				}
				if failure == "tls_check" && result.Name == existing.Name && result.Fingerprint != fingerprint(r.old[existing.Name].Leaf.Raw) {
					t.Fatal("rollback did not verify the existing deployment's old leaf")
				}
			}
			r.assertFiles(t, map[string]*Material{existing.Name: r.old[existing.Name]})
			for _, file := range newFiles {
				if _, err := os.Stat(file.path); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("the first installation's new files remain")
				}
			}
			wantLeaf := r.old[existing.Name].Leaf
			if failure == "restored_test" {
				wantLeaf = r.next[existing.Name].Leaf
			}
			if _, err := r.a.checkServed(t.Context(), existing, fingerprint(wantLeaf.Raw)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestAgentRunStopsOnACMEAccountRegistrationRefusal(t *testing.T) {
	t.Parallel()
	r := newDeployRig(t, ProfileNginx, ProfileFile)
	r.a.cfg.Deployments[1].ReloadHook = "" // a second group must not retry the same account
	id := testMaterial(t, "agent.homelab.lan", 999)
	for name, data := range map[string][]byte{certFile: id.Certificate, keyFile: id.Key} {
		if err := os.WriteFile(r.a.st.path(name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	calls, sleeps := 0, 0
	r.a.obtainForTest = func(context.Context, Deployment) (*Material, error) {
		calls++
		return nil, ErrACMEAccountRegistration
	}
	r.a.Sleep = func(context.Context, time.Duration) error {
		sleeps++
		return errors.New("unexpected retry")
	}
	if err := r.a.Run(t.Context()); !errors.Is(err, ErrACMEAccountRegistration) {
		t.Fatalf("terminal account refusal: %v", err)
	}
	if calls != 1 || sleeps != 0 {
		t.Fatalf("account refusal retried: obtains=%d, sleeps=%d", calls, sleeps)
	}
}

func TestRecoverInterruptedDeployment(t *testing.T) {
	t.Parallel()
	r := newDeployRig(t, ProfileNginx, ProfileFile)
	r.installOld(t)
	group := groups(r.a.cfg.Deployments)[0]
	// Stop at the exact durable boundary between replacement and reload.
	j, err := r.a.stageGroup(group, r.next)
	if err != nil || j.Phase != "replaced" {
		t.Fatalf("stage: %v", err)
	}
	r.assertFiles(t, r.next)
	if r.reloadCalls != 0 {
		t.Fatal("the interrupted pass already reloaded")
	}
	// A fresh Agent has no in-memory deployment or journal state.
	restarted := &Agent{cfg: r.a.cfg, st: r.a.st, log: r.a.log, Now: r.a.Now, Sleep: r.a.Sleep, runHookForTest: r.a.runHookForTest}
	results, err := restarted.Recover(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if r.reloadCalls != 1 || r.testCalls != 1 {
		t.Fatal("recovery did not test and reload exactly once")
	}
	for _, result := range results {
		if result.State != "rolled_back" || result.Fingerprint != fingerprint(r.old[result.Name].Leaf.Raw) {
			t.Fatalf("recovery result: %+v", result)
		}
	}
	r.assertFiles(t, r.old)
	if again, err := restarted.Recover(t.Context()); err != nil || len(again) != 0 {
		t.Fatal("recovery was not completed durably")
	}
}

func TestDeploymentPathsAndJournalStayLocal(t *testing.T) {
	t.Parallel()
	r := newDeployRig(t, ProfileNginx)
	outside := filepath.Join(t.TempDir(), "keep.pem")
	if err := os.WriteFile(outside, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	original := r.a.cfg.Deployments[0].Dir
	r.a.cfg.Deployments[0].Dir = filepath.Dir(outside)
	if _, err := r.a.RunPass(t.Context(), nil); err == nil {
		t.Fatal("path outside paths was accepted")
	}
	r.a.cfg.Deployments[0].Dir = original
	r.installOld(t)
	j, err := r.a.stageGroup(groups(r.a.cfg.Deployments)[0], r.next)
	if err != nil {
		t.Fatal(err)
	}
	j.Files[0].Path = outside
	if jerr := r.a.saveJournal(j, "replaced"); jerr != nil {
		t.Fatal(jerr)
	}
	if _, rerr := r.a.Recover(t.Context()); rerr == nil {
		t.Fatal("the journal expanded the write allowlist")
	}
	data, err := os.ReadFile(outside)
	if err != nil || string(data) != "keep" {
		t.Fatal("recovery touched an unrelated file")
	}
}

func TestDeploymentRejectsSymlinkEscape(t *testing.T) {
	t.Parallel()
	r := newDeployRig(t, ProfileNginx)
	d := r.a.cfg.Deployments[0]
	outside := t.TempDir()
	if err := os.Symlink(outside, d.Dir); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := r.a.RunPass(t.Context(), nil); err == nil {
		t.Fatal("deployment followed a symlink outside paths")
	}
	entries, err := os.ReadDir(outside)
	if err != nil || len(entries) != 0 {
		t.Fatal("deployment wrote outside paths")
	}
}

func TestRecoverSelectedMemberOfReloadGroup(t *testing.T) {
	t.Parallel()
	r := newDeployRig(t, ProfileNginx, ProfileFile)
	r.installOld(t)
	selected := groups(r.a.cfg.Deployments[1:])[0]
	if _, err := r.a.stageGroup(selected, r.next); err != nil {
		t.Fatal(err)
	}
	results, err := r.a.Recover(t.Context())
	if err != nil || len(results) != 1 || results[0].Name != r.a.cfg.Deployments[1].Name || results[0].State != "rolled_back" {
		t.Fatalf("partial group recovery: %v", err)
	}
	r.assertFiles(t, r.old)
}
