package agent

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
)

func TestWritablePreflightSkipsACMEAndMarksOnlyAffectedDeployment(t *testing.T) {
	t.Parallel()
	r := newDeployRig(t, ProfileNginx, ProfileFile)
	r.installOld(t)
	www := filepath.Join(r.a.cfg.Paths[0], "www")
	if err := os.Mkdir(www, 0o750); err != nil {
		t.Fatal(err)
	}
	r.a.cfg.Enrollment = Enrollment{Challenge: ChallengeWebroot, Webroot: www}
	for i := range r.a.cfg.Deployments {
		r.a.cfg.Deployments[i].Challenge = ChallengeWebroot
		r.a.cfg.Deployments[i].Webroot = www
	}
	badDirectory := r.a.cfg.Deployments[0].Dir
	var mu sync.Mutex
	var checked []string
	r.a.openRootForTest = func(path string) (*os.Root, error) {
		mu.Lock()
		checked = append(checked, path)
		mu.Unlock()
		if path == badDirectory {
			return nil, &os.PathError{Op: "create", Path: path, Err: syscall.EROFS}
		}
		return os.OpenRoot(path)
	}
	if err := r.a.preflightStart(); err != nil {
		t.Fatal(err)
	}
	stored, err := r.a.deploymentResults()
	if err != nil || len(stored) != 1 || stored[0].Name != "service0" || stored[0].State != "failed" {
		t.Fatalf("startup write failure not stored: %+v, %v", stored, err)
	}
	hint := "add " + badDirectory + " to /etc/systemd/system/myownpki-agent.service.d/10-paths.conf (ReadWritePaths), then systemctl daemon-reload and restart"
	if !strings.Contains(stored[0].LastError, hint) {
		t.Fatalf("missing systemd hint: %q", stored[0].LastError)
	}

	var orders []string
	r.a.obtainForTest = func(_ context.Context, d Deployment) (*Material, error) {
		orders = append(orders, d.Name)
		return cloneMaterial(r.next[d.Name]), nil
	}
	results, passErr := r.a.RunPass(t.Context(), nil)
	if passErr == nil || len(results) != 2 {
		t.Fatalf("preflight pass: %+v, %v", results, passErr)
	}
	if results[0].State != "failed" || results[1].State != "deployed" {
		t.Fatalf("wrong states after write failure: %+v", results)
	}
	if len(orders) != 1 || orders[0] != "service1" {
		t.Fatalf("ACME orders after write failure: %v", orders)
	}
	for _, path := range []string{r.a.st.dir, www, badDirectory, r.a.cfg.Paths[0]} {
		found := false
		for _, got := range checked {
			found = found || got == path
		}
		if !found {
			t.Errorf("path was not write-checked: %s", path)
		}
	}
	left, err := filepath.Glob(filepath.Join(www, ".myownpki-agent-write-check-*"))
	if err != nil || len(left) != 0 {
		t.Fatalf("write-check files remain: %v, %v", left, err)
	}
}

func TestWritablePreflightStateErrorHasSystemdHint(t *testing.T) {
	t.Parallel()
	r := newDeployRig(t, ProfileFile)
	// Use EROFS explicitly: the test does not depend on chmod or root privileges.
	r.a.openRootForTest = func(path string) (*os.Root, error) {
		if path == r.a.st.dir {
			return nil, &os.PathError{Op: "create", Path: path, Err: syscall.EROFS}
		}
		return os.OpenRoot(path)
	}
	err := r.a.preflightStart()
	if err == nil || !strings.Contains(err.Error(), "add "+r.a.st.dir+" to /etc/systemd/system/myownpki-agent.service.d/10-paths.conf") {
		t.Fatalf("state error lacks path and systemd hint: %v", err)
	}
}
