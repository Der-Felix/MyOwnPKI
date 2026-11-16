package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"
)

// Real HAProxy (the distribution package haproxy) with the recipe "haproxy"
// (docs/PHASE3.md section 17, step 69). Switch: MYOWNPKI_E2E_HAPROXY=1.
//
// HAProxy runs as the user of the test in master-worker mode (-W), in the
// foreground, with its own configuration and a free loopback port. The test
// hook is the recipe's own command, with the configuration of the test in
// place of /etc/haproxy/haproxy.cfg. The reload is SIGUSR2 to the master,
// which is what systemctl reload haproxy does; the recipe's systemctl would
// touch the installed service.
const (
	haproxyBinary      = "/usr/sbin/haproxy"
	haproxySystemCfg   = "/etc/haproxy/haproxy.cfg"
	haproxyMismatchSer = 900
)

// What the notes of the haproxy recipe may say about the three observations.
const (
	haproxyNoteRefuses     = "haproxy -c refuses a certificate and key that do not match"
	haproxyNoteAccepts     = "haproxy -c accepts a certificate and key that do not match"
	haproxyNoteSkipsTemp   = "the directory form of crt skips the agent's temporary .myownpki-* file"
	haproxyNoteLoadsTemp   = "the directory form of crt does not skip the agent's temporary .myownpki-* file"
	haproxyNoteOrderMatter = "the key must come after the certificate in the file"
	haproxyNoteOrderFree   = "the order of the certificate and the key in the file does not matter"
)

// haproxyConfig is a minimal configuration: one TLS frontend on addr with
// crt (a file or a directory) that answers every request with 200.
func haproxyConfig(addr, crt string) string {
	return fmt.Sprintf(`global
	maxconn 64
defaults
	mode http
	timeout connect 5s
	timeout client 15s
	timeout server 15s
frontend tls
	bind %s ssl crt %s
	http-request return status 200 content-type text/plain string ok
`, addr, crt)
}

func writeHAProxyConfig(t *testing.T, path, addr, crt string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(haproxyConfig(addr, crt)), 0o600); err != nil {
		t.Fatal(err)
	}
}

// haproxyCheck runs haproxy -c on a configuration and returns its verdict.
func haproxyCheck(t *testing.T, conf string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, haproxyBinary, "-c", "-f", conf).CombinedOutput() // #nosec G204 -- fixed argv, test-owned configuration
	return oneLine(string(out)), err
}

// startHAProxy starts a master-worker HAProxy on addr with crt and waits until
// it listens.
func startHAProxy(t *testing.T, dir, name, addr, crt string) *realService {
	t.Helper()
	conf := filepath.Join(dir, name+".cfg")
	writeHAProxyConfig(t, conf, addr, crt)
	svc := startRealService(t, name, dir, []string{haproxyBinary, "-W", "-f", conf})
	svc.waitListening(t, addr)
	return svc
}

func newHAProxyHarness(t *testing.T) *serviceHarness {
	t.Helper()
	rec := requireRealService(t, "haproxy", envE2EHAProxy, "haproxy", haproxyBinary)
	r := newServiceRig(t, rec)
	r.installOld(t)
	d := r.a.cfg.Deployments[0]
	d.Check = freeLoopbackAddress(t)
	r.a.cfg.Deployments[0] = d
	files := deploymentPaths(d)
	if files.Combined == "" {
		t.Fatalf("recipe haproxy no longer deploys one combined file: %+v", files)
	}

	prefix := t.TempDir()
	conf := filepath.Join(prefix, "haproxy.cfg")
	writeHAProxyConfig(t, conf, d.Check, files.Combined)

	// The recipe's own test command, pointed at the configuration of the test.
	testHook := recipeHook(t, rec, rec.TestHook)
	i := slices.Index(testHook, haproxySystemCfg)
	if i < 0 {
		t.Fatalf("the test hook of recipe haproxy no longer names %s: %v – adjust this test", haproxySystemCfg, testHook)
	}
	testHook[i] = conf
	r.a.cfg.Hooks["test"] = testHook
	r.a.runHookForTest = nil
	r.a.Sleep = sleep
	group := groups(r.a.cfg.Deployments)[0]
	if err := r.a.runTests(t.Context(), group); err != nil {
		t.Fatalf("the test hook of recipe haproxy rejects the good configuration of the test: %v", err)
	}

	svc := startRealService(t, "haproxy", prefix, []string{haproxyBinary, "-W", "-f", conf})
	svc.waitListening(t, d.Check)
	marker := filepath.Join(prefix, "reloads.log")
	// systemctl reload haproxy sends SIGUSR2 to the master process.
	r.a.cfg.Hooks["reload"] = reloadWrapper(marker, "/bin/sh", "-c", `kill -USR2 "$1"`, "sh", strconv.Itoa(svc.cmd.Process.Pid))
	if _, err := r.a.checkServed(t.Context(), d, fingerprint(r.old[d.Name].Leaf.Raw)); err != nil {
		t.Fatalf("HAProxy does not serve the old certificate after it started: %v", err)
	}
	return &serviceHarness{r: r, d: d, files: files, svc: svc, rec: rec, marker: marker}
}

// TestHAProxyDeployProfile: the agent writes the combined file (chain, then
// key), haproxy -c (the recipe's command) accepts it, the master reloads on
// SIGUSR2 and the served certificate is the deployed one.
func TestHAProxyDeployProfile(t *testing.T) {
	h := newHAProxyHarness(t)
	results, err := h.r.a.RunPass(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].State != "deployed" {
		t.Fatalf("pass result: %+v", results)
	}
	if n := reloadCount(t, h.marker); n != 1 {
		t.Fatalf("the agent issued %d reloads, want 1", n)
	}
	next := h.r.next[h.d.Name].Leaf
	assertServes(t, h.d.Check, h.d.Names[0], next)
	if results[0].Fingerprint != fingerprint(next.Raw) {
		t.Fatalf("the result names %s, the service serves %s", results[0].Fingerprint, fingerprint(next.Raw))
	}
	h.r.assertFiles(t, h.r.next)
}

// TestHAProxyCheckOnKeyMismatch records what haproxy -c (the recipe's test
// hook) does with a combined file whose key belongs to another certificate
// (lane A open point, expected: refused) and compares it with the notes.
func TestHAProxyCheckOnKeyMismatch(t *testing.T) {
	h := newHAProxyHarness(t)
	d := h.d
	newer := map[string]*Material{d.Name: testMaterial(t, d.Names[0], haproxyMismatchSer)}
	group := groups(h.r.a.cfg.Deployments)[0]
	journal, err := h.r.a.stageGroup(group, newer)
	if err != nil {
		t.Fatal(err)
	}
	corruptStaged(t, h.r, d, newer[d.Name], h.r.old[d.Name].Key)
	failure := h.r.a.runTests(t.Context(), group)

	result := "haproxy -c passed although the key does not belong to the certificate"
	if failure != nil {
		result = "haproxy -c failed on the mismatch: " + oneLine(failure.Error())
	}
	cause := errors.New("observation recorded")
	results, rollbackErr := h.r.a.rollback(t.Context(), group, journal, false, cause)
	if !errors.Is(rollbackErr, cause) || len(results) != 1 || results[0].State != "rolled_back" {
		t.Fatalf("restoring the files failed: %+v, %v", results, rollbackErr)
	}
	h.r.assertFiles(t, h.r.old)
	if n := reloadCount(t, h.marker); n != 0 {
		t.Fatalf("the observation reloaded HAProxy %d times", n)
	}
	noteClaim{
		recipe: "haproxy", topic: "haproxy -c with a certificate/key mismatch", result: result,
		seen: failure != nil, ifSeen: haproxyNoteRefuses, ifNot: haproxyNoteAccepts,
	}.check(t)
}

// writeCombined writes a combined file: the parts in the given order.
func writeCombined(t *testing.T, path string, parts ...[]byte) {
	t.Helper()
	if err := os.WriteFile(path, bytes.Join(parts, nil), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestHAProxyDirectoryAndTemporaryFile records whether the directory form of
// crt skips the agent's .myownpki-* temporary file (lane A open point): the
// agent writes every file next to its target under that name and renames it,
// so a directory that HAProxy reads at a reload can hold one.
//
// Two observations must agree. A truncated temporary file, as a write in
// progress leaves it, either makes haproxy -c fail (not skipped) or not. A
// complete temporary file with another name, as the last moment before the
// rename, is either served for its name (loaded) or not.
func TestHAProxyDirectoryAndTemporaryFile(t *testing.T) {
	requireRealService(t, "haproxy", envE2EHAProxy, "haproxy", haproxyBinary)
	dir := t.TempDir()
	certs := filepath.Join(dir, "certs")
	if err := os.Mkdir(certs, 0o750); err != nil {
		t.Fatal(err)
	}
	primary := testMaterial(t, "primary.homelab.lan", 1)
	other := testMaterial(t, "temp.homelab.lan", 2)
	writeCombined(t, filepath.Join(certs, "primary.pem"), combinedPEM(primary))
	conf := filepath.Join(dir, "check.cfg")
	writeHAProxyConfig(t, conf, freeLoopbackAddress(t), certs+"/")

	// Control: the directory alone is valid.
	if out, err := haproxyCheck(t, conf); err != nil {
		t.Fatalf("haproxy -c rejects a directory with one good file: %v: %s", err, out)
	}

	// 1. A truncated temporary file: the chain and half of the key.
	temp := filepath.Join(certs, ".myownpki-e2etest0123456789")
	full := combinedPEM(other)
	writeCombined(t, temp, full[:len(other.Fullchain)+len(other.Key)/2])
	out, checkErr := haproxyCheck(t, conf)
	truncatedSkipped := checkErr == nil
	t.Logf("haproxy -c with a truncated .myownpki-* file in the crt directory: err=%v output=%s", checkErr, out)

	// 2. A complete temporary file for another name: is it served?
	writeCombined(t, temp, full)
	addr := freeLoopbackAddress(t)
	startHAProxy(t, dir, "haproxy-dir", addr, certs+"/")
	leaf, err := servedLeaf(t.Context(), addr, "temp.homelab.lan")
	if err != nil {
		t.Fatalf("read the certificate for the name of the temporary file: %v", err)
	}
	loaded := fingerprint(leaf.Raw) == fingerprint(other.Leaf.Raw)
	t.Logf("a complete .myownpki-* file in the crt directory is served for its name: %t", loaded)

	if truncatedSkipped == loaded {
		t.Errorf("the two observations disagree: the truncated file was skipped by haproxy -c: %t, the complete file was loaded: %t; read the logs above before the notes are changed", truncatedSkipped, loaded)
		return
	}
	result := "HAProxy ignored the .myownpki-* file (haproxy -c passed with a truncated one, the complete one was not served)"
	if !truncatedSkipped {
		result = "HAProxy read the .myownpki-* file (haproxy -c failed with a truncated one, the complete one was served for its name), so a reload during a write can fail; a single file in crt, not the directory form, avoids it"
	}
	noteClaim{
		recipe: "haproxy", topic: "the crt directory and the agent's temporary file", result: result,
		seen: truncatedSkipped, ifSeen: haproxyNoteSkipsTemp, ifNot: haproxyNoteLoadsTemp,
	}.check(t)
}

// TestHAProxyCombinedOrder records whether the order of certificate and key
// inside the combined PEM matters to HAProxy (lane A open point). The agent
// writes the certificate chain first; the test also tries the key first.
func TestHAProxyCombinedOrder(t *testing.T) {
	requireRealService(t, "haproxy", envE2EHAProxy, "haproxy", haproxyBinary)
	dir := t.TempDir()
	m := testMaterial(t, "order.homelab.lan", 3)
	agentOrder := filepath.Join(dir, "chain-then-key.pem")
	keyFirst := filepath.Join(dir, "key-then-chain.pem")
	writeCombined(t, agentOrder, m.Fullchain, m.Key)
	writeCombined(t, keyFirst, m.Key, m.Fullchain)

	check := func(name, crt string) (string, error) {
		conf := filepath.Join(dir, name+"-check.cfg")
		writeHAProxyConfig(t, conf, freeLoopbackAddress(t), crt)
		return haproxyCheck(t, conf)
	}
	if out, err := check("agent", agentOrder); err != nil {
		t.Fatalf("haproxy -c rejects the file in the order the agent writes: %v: %s", err, out)
	}
	out, err := check("keyfirst", keyFirst)
	t.Logf("haproxy -c with the key before the certificate: err=%v output=%s", err, out)
	orderMatters := err != nil
	if err == nil {
		addr := freeLoopbackAddress(t)
		startHAProxy(t, dir, "haproxy-keyfirst", addr, keyFirst)
		leaf, serveErr := servedLeaf(t.Context(), addr, "order.homelab.lan")
		if serveErr != nil || fingerprint(leaf.Raw) != fingerprint(m.Leaf.Raw) {
			orderMatters = true
			t.Logf("haproxy -c passed with the key first, but the service does not serve the certificate: %v", serveErr)
		}
	}
	result := "HAProxy accepts and serves the file with the key before the certificate"
	if orderMatters {
		result = "HAProxy does not load the file with the key before the certificate (the agent writes the certificate first, so deployments are not affected)"
	}
	noteClaim{
		recipe: "haproxy", topic: "the order of certificate and key in the combined file", result: result,
		seen: orderMatters, ifSeen: haproxyNoteOrderMatter, ifNot: haproxyNoteOrderFree,
	}.check(t)
}
