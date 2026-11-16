package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// materialWithChain is testMaterial with one intermediate after the leaf, so a
// full chain is more than the leaf.
func materialWithChain(t *testing.T, name string, serial int64) *Material {
	t.Helper()
	m := testMaterial(t, name, serial)
	other := testMaterial(t, "intermediate.homelab.lan", serial+1000)
	m.Chain = other.Certificate
	m.Fullchain = append(bytes.Clone(m.Certificate), m.Chain...)
	return m
}

func combinedDeployment(t *testing.T, mode string) (*Agent, Deployment) {
	t.Helper()
	root := realTempDir(t)
	a := &Agent{cfg: &Config{Paths: []string{root}}}
	return a, Deployment{Name: "ha", Profile: ProfileFile, KeyMode: mode, Files: Files{Combined: filepath.Join(root, "haproxy", "www.pem")}}
}

// The one file is the full chain followed by the key, byte for byte; it is
// read by crypto/tls as certificate and as key, and its blocks parse.
func TestCombinedFileIsFullchainPlusKey(t *testing.T) {
	t.Parallel()
	a, d := combinedDeployment(t, "")
	m := materialWithChain(t, "www.homelab.lan", 7)
	files, err := targets(d, m)
	if err != nil || len(files) != 1 {
		t.Fatalf("targets = %d files, %v", len(files), err)
	}
	want := append(bytes.Clone(m.Fullchain), m.Key...)
	if !bytes.Equal(files[0].data, want) || files[0].path != d.Files.Combined {
		t.Fatalf("the combined file is not fullchain plus key:\n%s", files[0].data)
	}
	if files[0].mode != 0o600 {
		t.Errorf("mode = %o, want the key mode 0600 (never the 0644 of a certificate)", files[0].mode)
	}
	if err = a.atomicTarget(files[0]); err != nil {
		t.Fatal(err)
	}
	data, info, err := a.readTarget(d.Files.Combined)
	if err != nil || !bytes.Equal(data, want) {
		t.Fatalf("read back: %v", err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Errorf("file mode = %o", info.Mode().Perm())
	}
	pair, err := tls.X509KeyPair(data, data)
	if err != nil || len(pair.Certificate) != 2 {
		t.Fatalf("tls.X509KeyPair(file, file): %d certificates, %v", len(pair.Certificate), err)
	}
	var types []string
	for rest := data; ; {
		var block *pem.Block
		if block, rest = pem.Decode(rest); block == nil {
			break
		}
		types = append(types, block.Type)
		switch block.Type {
		case "CERTIFICATE":
			_, err = x509.ParseCertificate(block.Bytes)
		case "PRIVATE KEY":
			_, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		}
		if err != nil {
			t.Errorf("block %s: %v", block.Type, err)
		}
	}
	if !slices.Equal(types, []string{"CERTIFICATE", "CERTIFICATE", "PRIVATE KEY"}) {
		t.Errorf("blocks = %v, want the chain first and the key last", types)
	}
	// The key mode of the deployment applies to the one file.
	_, d = combinedDeployment(t, "0640")
	if files, err = targets(d, m); err != nil || files[0].mode != 0o640 {
		t.Errorf("key_mode 0640: %v %v", files, err)
	}
	// The buffer is a copy: clearing it leaves the Material alone.
	fullchain, key := bytes.Clone(m.Fullchain), bytes.Clone(m.Key)
	clear(files[0].data)
	if !bytes.Equal(m.Fullchain, fullchain) || !bytes.Equal(m.Key, key) {
		t.Error("clearing the combined buffer cleared the material")
	}
}

// A rights-for-others key mode is refused for the one file, too.
func TestCombinedRefusesAnUnsafeKeyMode(t *testing.T) {
	t.Parallel()
	_, d := combinedDeployment(t, "0644")
	if _, err := targets(d, testMaterial(t, "www.homelab.lan", 1)); err == nil {
		t.Fatal("key_mode 0644 was accepted for a file with a private key")
	}
}

// The write is the atomic one: a temporary file next to the target, no half
// file when the rename fails, and the old file stays.
func TestCombinedWriteIsAtomic(t *testing.T) {
	t.Parallel()
	a, d := combinedDeployment(t, "")
	files, err := targets(d, testMaterial(t, "www.homelab.lan", 1))
	if err != nil {
		t.Fatal(err)
	}
	// A directory (not empty) where the file should go: the rename must fail.
	if err = os.MkdirAll(filepath.Join(d.Files.Combined, "keep"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err = a.atomicTarget(files[0]); err == nil {
		t.Fatal("the write replaced a directory")
	}
	entries, err := os.ReadDir(filepath.Dir(d.Files.Combined))
	if err != nil || len(entries) != 1 || entries[0].Name() != "www.pem" {
		t.Errorf("a temporary or half file remained: %v %v", entries, err)
	}
	if _, err = os.Stat(filepath.Join(d.Files.Combined, "keep")); err != nil {
		t.Errorf("the directory was damaged: %v", err)
	}
}

// writtenLeafFingerprint and currentLeaf read the first block of the one file.
func TestCombinedLeafIsFoundInTheOneFile(t *testing.T) {
	t.Parallel()
	a, d := combinedDeployment(t, "")
	d.Names = []string{"www.homelab.lan"}
	m := materialWithChain(t, "www.homelab.lan", 9)
	files, err := targets(d, m)
	if err != nil {
		t.Fatal(err)
	}
	if err = a.atomicTarget(files[0]); err != nil {
		t.Fatal(err)
	}
	want := fingerprint(m.Leaf.Raw)
	if got, werr := a.writtenLeafFingerprint(d, want); werr != nil || got != want {
		t.Errorf("writtenLeafFingerprint = %q, %v", got, werr)
	}
	leaf, err := a.currentLeaf(d)
	if err != nil || fingerprint(leaf.Raw) != want {
		t.Errorf("currentLeaf: %v", err)
	}
}

// Both profiles of a reload group, one of them the one-file form.
func TestCombinedDeployAndSharedReload(t *testing.T) {
	t.Parallel()
	r := newDeployRig(t, ProfileNginx, rigCombined)
	r.installOld(t)
	r.assertFiles(t, r.old)
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
	if _, err = os.Stat(r.a.st.path(journalFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("journal remains after success")
	}
}

// A failed test hook, reload or TLS check restores the previous combined file
// exactly; the key never stays in a half state.
func TestCombinedGroupRollback(t *testing.T) {
	t.Parallel()
	for _, failure := range []string{"test", "reload", "check"} {
		t.Run(failure, func(t *testing.T) {
			t.Parallel()
			r := newDeployRig(t, rigCombined, ProfileNginx)
			r.installOld(t)
			combined := r.a.cfg.Deployments[0].Files.Combined
			before, err := os.ReadFile(combined)
			if err != nil {
				t.Fatal(err)
			}
			r.a.runHookForTest = func(_ context.Context, name string) error {
				if name == "test" {
					r.testCalls++
					if failure == "test" && r.testCalls == 1 {
						return errors.New("configuration test rejected the new files")
					}
					return nil
				}
				r.reloadCalls++
				if r.reloadCalls == 1 {
					if failure == "reload" {
						return errors.New("primary reload error")
					}
					if failure == "check" {
						return nil // the service keeps the old certificate
					}
				}
				return r.loadFiles()
			}
			results, err := r.a.RunPass(t.Context(), nil)
			if err == nil {
				t.Fatal("the failure was hidden")
			}
			for _, result := range results {
				if result.State != "rolled_back" {
					t.Fatalf("result: %+v", result)
				}
			}
			after, err := os.ReadFile(combined)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatalf("the previous combined file was not restored exactly: %v", err)
			}
			r.assertFiles(t, r.old)
			if _, err = os.Stat(r.a.st.path(journalFile)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("a completed rollback left a journal")
			}
		})
	}
}

// A first installation that fails leaves no combined file behind.
func TestCombinedFirstInstallFailureRemovesTheFile(t *testing.T) {
	t.Parallel()
	for _, failure := range []string{"test", "reload"} {
		t.Run(failure, func(t *testing.T) {
			t.Parallel()
			r := newDeployRig(t, rigCombined)
			r.a.runHookForTest = func(_ context.Context, name string) error {
				if name == "test" {
					r.testCalls++
					if failure == "test" || r.testCalls > 1 {
						return errors.New("configuration references files absent before the first installation")
					}
					return nil
				}
				return errors.New("initial reload failed")
			}
			results, err := r.a.RunPass(t.Context(), nil)
			if err == nil || len(results) != 1 || results[0].State != "failed" {
				t.Fatalf("results %+v, error %v", results, err)
			}
			if _, err = os.Stat(r.a.cfg.Deployments[0].Files.Combined); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("the combined file remained after the failed first installation")
			}
		})
	}
}

// The journal backup of the old combined file holds a key, so it is a 0600
// state file, and an interrupted pass is recovered to the old file.
func TestCombinedJournalBackupAndRecovery(t *testing.T) {
	t.Parallel()
	r := newDeployRig(t, rigCombined, ProfileNginx)
	r.installOld(t)
	oldKey, nextKey := bytes.Clone(r.old["service0"].Key), bytes.Clone(r.next["service0"].Key)
	j, err := r.a.stageGroup(groups(r.a.cfg.Deployments)[0], r.next)
	if err != nil || j.Phase != "replaced" {
		t.Fatalf("stage: %v", err)
	}
	r.assertFiles(t, r.next)
	if !bytes.Equal(r.next["service0"].Key, nextKey) {
		t.Error("staging cleared the key of the material, not only its own copy")
	}
	combined, err := resolveUnder(r.a.cfg.Paths, r.a.cfg.Deployments[0].Files.Combined)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for i, entry := range j.Files {
		if entry.Path != combined {
			continue
		}
		found = true
		backup := r.a.st.path(j.backup(i))
		info, serr := os.Stat(backup)
		if serr != nil {
			t.Fatal(serr)
		}
		if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
			t.Errorf("backup mode = %o", info.Mode().Perm())
		}
		if data, _ := os.ReadFile(backup); !bytes.Contains(data, oldKey) {
			t.Error("the backup is not the old combined file")
		}
	}
	if !found {
		t.Fatal("the journal does not list the combined file")
	}
	// The journal itself carries paths and modes, never key material.
	raw, err := os.ReadFile(r.a.st.path(journalFile))
	if err != nil || bytes.Contains(raw, []byte("PRIVATE KEY")) {
		t.Errorf("the journal holds key material: %v", err)
	}
	restarted := &Agent{cfg: r.a.cfg, st: r.a.st, log: r.a.log, Now: r.a.Now, Sleep: r.a.Sleep, runHookForTest: r.a.runHookForTest}
	if _, err = restarted.Recover(t.Context()); err != nil {
		t.Fatal(err)
	}
	r.assertFiles(t, r.old)
	for _, p := range []string{r.a.st.path(j.backup(0)), r.a.st.path(j.backup(1))} {
		if _, err = os.Stat(p); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("backup %s remained after the recovery", filepath.Base(p))
		}
	}
}

// A Material never prints its key, and a status after a pass holds none.
func TestCombinedKeyDoesNotReachResultsOrLogText(t *testing.T) {
	t.Parallel()
	r := newDeployRig(t, rigCombined)
	r.installOld(t)
	results, err := r.a.RunPass(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	key := string(bytes.TrimSpace(r.next["service0"].Key))
	body := key[strings.Index(key, "\n")+1 : strings.LastIndex(key, "\n")]
	if text := strings.Join([]string{r.next["service0"].String(), r.next["service0"].LogValue().String(), resultsText(results)}, "\n"); strings.Contains(text, body) || strings.Contains(text, "PRIVATE KEY") {
		t.Error("key material in a printed result")
	}
}

func resultsText(results []DeploymentResult) string {
	var b strings.Builder
	for _, r := range results {
		b.WriteString(r.Name + " " + r.State + " " + r.Fingerprint + " " + r.LastError + "\n")
	}
	return b.String()
}

// A pass over the combined deployment writes the one file and no other.
func TestCombinedDeploymentWritesNothingElse(t *testing.T) {
	t.Parallel()
	r := newDeployRig(t, rigCombined)
	if _, err := r.a.RunPass(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(r.a.cfg.Paths[0])
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if !slices.Equal(names, []string{"service0.pem"}) {
		t.Errorf("files = %v", names)
	}
}
