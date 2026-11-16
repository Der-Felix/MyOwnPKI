package backup

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Der-Felix/MyOwnPKI/internal/backup/backupkey"
	"github.com/Der-Felix/MyOwnPKI/internal/testinstance"
)

// signedBackup makes a backup of a fresh instance with one certificate.
func signedBackup(t *testing.T) (*testinstance.Instance, Options, string, *Created) {
	t.Helper()
	v, o := newInstance(t)
	issue(t, v, "nas.homelab.lan")
	dir := filepath.Join(t.TempDir(), "backup")
	c, err := Create(t.Context(), dir, o)
	if err != nil {
		t.Fatal(err)
	}
	return v, o, dir, c
}

// makeFormat1 turns a backup into what versions before 0.9.0 wrote: format 1
// in the manifest and no signature.
func makeFormat1(t *testing.T, dir string) {
	t.Helper()
	m, err := readManifest(dir)
	if err != nil {
		t.Fatal(err)
	}
	m.Format = FormatUnsigned
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ManifestFile), append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, SignatureFile)); err != nil {
		t.Fatal(err)
	}
}

// rewriteHashes fixes the file hashes in manifest.json after a database was
// changed – and leaves manifest.sig alone, as somebody without the key must.
func rewriteHashes(t *testing.T, dir string, rels ...string) {
	t.Helper()
	m, err := readManifest(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, rel := range rels {
		for i, f := range m.Files {
			if f.Path == rel {
				if m.Files[i].SHA256, m.Files[i].Size, err = hashFile(filepath.Join(dir, filepath.FromSlash(rel))); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ManifestFile), append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

// signedDir is signedBackup for the tests that need only the backup.
func signedDir(t *testing.T) (string, *Created) {
	t.Helper()
	_, _, dir, c := signedBackup(t)
	return dir, c
}

func problemsOf(err error, rep *Report) string {
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	if rep != nil {
		msg += " | " + strings.Join(rep.Problems, " | ")
	}
	return msg
}

func notesOf(rep *Report) string { return strings.Join(rep.Notes, " | ") }

func TestCreateSignsTheManifest(t *testing.T) {
	t.Parallel()
	v, o, dir, c := signedBackup(t)
	keyPath := backupkey.Path(o.Layout.DataDir)
	// The key is the one init made (setup step "backup-key"), not a new one.
	initKey, _, kerr := backupkey.Load(keyPath)
	if kerr != nil {
		t.Fatal(kerr)
	}
	if c.NewKey || c.SigningKey != initKey.Fingerprint() || !strings.HasPrefix(c.SigningKey, backupkey.Prefix) {
		t.Errorf("first backup: new key %v, fingerprint %q, init made %q", c.NewKey, c.SigningKey, initKey.Fingerprint())
	}
	if runtime.GOOS != "windows" {
		if fi, err := os.Stat(keyPath); err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("key file: %v %v", fi, err)
		}
		if fi, err := os.Stat(filepath.Join(dir, SignatureFile)); err != nil || fi.Mode().Perm()&0o077 != 0 {
			t.Errorf("manifest.sig: %v %v", fi, err)
		}
	}
	m, raw, err := loadManifest(dir)
	if err != nil || m.Format != Format {
		t.Fatalf("manifest: %v %+v", err, m)
	}
	sig, err := os.ReadFile(filepath.Join(dir, SignatureFile))
	if err != nil {
		t.Fatal(err)
	}
	pub, err := verifySignature(sig, raw)
	if err != nil || backupkey.Fingerprint(pub) != c.SigningKey {
		t.Fatalf("signature: %v", err)
	}
	// The signature is over the exact bytes: one more blank breaks it.
	if _, verr := verifySignature(sig, append(append([]byte(nil), raw...), '\n')); !errors.Is(verr, ErrBadSignature) {
		t.Errorf("signature of changed bytes: %v", verr)
	}
	// A second backup of the same instance uses the same key.
	c2, err := Create(t.Context(), filepath.Join(t.TempDir(), "second"), o)
	if err != nil || c2.NewKey || c2.SigningKey != c.SigningKey {
		t.Fatalf("second backup: %+v %v", c2, err)
	}
	// The key never comes along: no file of the backup is the key file, and
	// neither the key text nor its seed is in any of them.
	key, err := os.ReadFile(keyPath) // #nosec G304 -- the test's own key file
	if err != nil {
		t.Fatal(err)
	}
	b64 := strings.Fields(string(key))[1]
	seed, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatal(err)
	}
	err = filepath.WalkDir(dir, func(p string, d fs.DirEntry, werr error) error {
		if werr != nil || d.IsDir() {
			return werr
		}
		if d.Name() == backupkey.FileName {
			t.Errorf("the key file is in the backup: %s", p)
		}
		data, rerr := os.ReadFile(p) // #nosec G304 G122 -- a file of the test's own backup
		if rerr != nil {
			return rerr
		}
		if bytes.Contains(data, []byte(b64)) || bytes.Contains(data, seed) {
			t.Errorf("%s contains the backup key", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range m.Files {
		if strings.Contains(f.Path, "backup-signing") {
			t.Errorf("manifest lists %s", f.Path)
		}
	}
	// The audit log of the instance names the key, so a changed key shows.
	data, err := os.ReadFile(filepath.Join(dir, "audit.db")) // #nosec G304 -- a file of the test's own backup
	if err != nil || !bytes.Contains(data, []byte(c.SigningKey)) {
		t.Errorf("the system.backup audit entry does not carry the key fingerprint: %v", err)
	}
	_ = v
}

func TestVerifyAuthenticity(t *testing.T) {
	t.Parallel()
	_, _, dir, c := signedBackup(t)
	digits := strings.TrimPrefix(c.SigningKey, backupkey.Prefix)

	t.Run("no pin: signed, and it says by whom", func(t *testing.T) {
		t.Parallel()
		rep, err := Verify(t.Context(), dir, Check{})
		if err != nil || rep.Authenticity != Signed || rep.SigningKey != c.SigningKey {
			t.Fatalf("%v %+v", err, rep)
		}
		if n := notesOf(rep); !strings.Contains(n, "signed by key "+c.SigningKey) || !strings.Contains(n, "--backup-key") {
			t.Errorf("notes %q", n)
		}
	})
	for name, pin := range map[string]string{
		"as printed": c.SigningKey, "without prefix": digits, "upper case": strings.ToUpper(digits), "16 digits": digits[:16],
	} {
		t.Run("pinned, "+name, func(t *testing.T) {
			t.Parallel()
			rep, err := Verify(t.Context(), dir, Check{BackupKey: pin})
			if err != nil || rep.Authenticity != Pinned || rep.SigningKey != c.SigningKey {
				t.Fatalf("%v %+v", err, rep)
			}
			if strings.Contains(notesOf(rep), "unauthenticated") || strings.Contains(notesOf(rep), "signed by key") {
				t.Errorf("a pinned backup carries a warning: %q", notesOf(rep))
			}
		})
	}
	t.Run("another key", func(t *testing.T) {
		t.Parallel()
		other := forgerKey(t).Fingerprint()
		rep, err := Verify(t.Context(), dir, Check{BackupKey: other})
		if !errors.Is(err, ErrRefused) || !strings.Contains(problemsOf(err, rep), "signed by key "+c.SigningKey+", not by the expected key") {
			t.Fatalf("%v", problemsOf(err, rep))
		}
		// --allow-unsigned is for backups that have no signature, not for a
		// signature by a key you did not expect.
		_, err = Verify(t.Context(), dir, Check{BackupKey: other, AllowUnsigned: true})
		if !errors.Is(err, ErrRefused) {
			t.Errorf("allow-unsigned accepted a signature by another key: %v", err)
		}
	})
	t.Run("a pin that is no fingerprint", func(t *testing.T) {
		t.Parallel()
		for _, pin := range []string{"abc", "SHA256:zzzzzzzzzzzzzzzzzzzzzzzz", strings.Repeat("a", 65)} {
			if _, err := Verify(t.Context(), dir, Check{BackupKey: pin}); err == nil || !strings.Contains(err.Error(), "backup key") || errors.Is(err, ErrRefused) {
				t.Errorf("pin %q: %v", pin, err)
			}
		}
	})
}

// TestForgedBackup: somebody who can write the backup directory changes
// pki.db and rewrites the hashes. Without the key the signature stops him;
// with a key of his own the backup is valid but says who signed it, and the
// pin stops it.
func TestForgedBackup(t *testing.T) {
	t.Parallel()
	v, o, good, c := signedBackup(t)
	forge := func(t *testing.T) string {
		t.Helper()
		dir := backupCopy(t, good)
		// A change that every other check lets pass: one more table.
		execOn(t, filepath.Join(dir, filepath.FromSlash(pkiRel)), `CREATE TABLE planted (x TEXT)`)
		rewriteHashes(t, dir, pkiRel)
		return dir
	}

	t.Run("hashes rewritten, signature kept", func(t *testing.T) {
		t.Parallel()
		dir := forge(t)
		before := tree(t, dir)
		rep, err := Verify(t.Context(), dir, Check{})
		if !errors.Is(err, ErrRefused) || !strings.Contains(problemsOf(err, rep), SignatureFile+": the signature does not match the manifest") {
			t.Fatalf("verify: %s", problemsOf(err, rep))
		}
		target := targetOptions(t, v)
		rep, err = Restore(t.Context(), dir, Check{BackupKey: c.SigningKey}, target)
		if !errors.Is(err, ErrRefused) || !strings.Contains(problemsOf(err, rep), "signature does not match") {
			t.Fatalf("restore: %s", problemsOf(err, rep))
		}
		if _, serr := os.Stat(target.Layout.DataDir); !errors.Is(serr, fs.ErrNotExist) {
			t.Errorf("a refused restore created the data directory: %v", serr)
		}
		sameTree(t, before, tree(t, dir))
	})

	t.Run("signed again with the forger's key", func(t *testing.T) {
		t.Parallel()
		dir := forge(t)
		editManifestOf(t, dir, func(*Manifest) {}) // signs with a key of the forger
		// Unpinned the backup verifies – and says that it is signed by a key
		// nobody vouched for.
		rep, err := Verify(t.Context(), dir, Check{})
		if err != nil || rep.Authenticity != Signed || rep.SigningKey == c.SigningKey {
			t.Fatalf("unpinned: %v %+v", err, rep)
		}
		if !strings.Contains(notesOf(rep), "signed by key "+rep.SigningKey) {
			t.Errorf("notes %q", notesOf(rep))
		}
		// Pinned to the key of the instance it is refused.
		rep, err = Verify(t.Context(), dir, Check{BackupKey: c.SigningKey})
		if !errors.Is(err, ErrRefused) || !strings.Contains(problemsOf(err, rep), "not by the expected key") {
			t.Fatalf("pinned: %s", problemsOf(err, rep))
		}
		target := targetOptions(t, v)
		if _, err = Restore(t.Context(), dir, Check{BackupKey: c.SigningKey, AllowUnsigned: true}, target); !errors.Is(err, ErrRefused) {
			t.Errorf("restore with the pin: %v", err)
		}
		if _, serr := os.Stat(target.Layout.DataDir); !errors.Is(serr, fs.ErrNotExist) {
			t.Errorf("a refused restore created the data directory: %v", serr)
		}
	})

	t.Run("manifest changed, nothing else", func(t *testing.T) {
		t.Parallel()
		dir := backupCopy(t, good)
		path := filepath.Join(dir, ManifestFile)
		data, err := os.ReadFile(path) // #nosec G304 -- the test's own backup copy
		if err != nil {
			t.Fatal(err)
		}
		if werr := os.WriteFile(path, bytes.Replace(data, []byte(`"tenants": [`), []byte(`"tenants":  [`), 1), 0o600); werr != nil { // #nosec G703 -- the test's own backup copy
			t.Fatal(werr)
		}
		rep, err := Verify(t.Context(), dir, Check{})
		if !errors.Is(err, ErrRefused) || !strings.Contains(problemsOf(err, rep), "does not match the manifest") {
			t.Fatalf("%s", problemsOf(err, rep))
		}
	})

	t.Run("signature of another backup", func(t *testing.T) {
		t.Parallel()
		other := filepath.Join(t.TempDir(), "other")
		if _, err := Create(t.Context(), other, o); err != nil {
			t.Fatal(err)
		}
		dir := backupCopy(t, good)
		data, err := os.ReadFile(filepath.Join(other, SignatureFile)) // #nosec G304 -- the test's own backup
		if err != nil {
			t.Fatal(err)
		}
		if werr := os.WriteFile(filepath.Join(dir, SignatureFile), data, 0o600); werr != nil { // #nosec G703 -- the test's own backup copy
			t.Fatal(werr)
		}
		rep, err := Verify(t.Context(), dir, Check{})
		if !errors.Is(err, ErrRefused) || !strings.Contains(problemsOf(err, rep), "does not match the manifest") {
			t.Fatalf("%s", problemsOf(err, rep))
		}
	})
}

// TestDamagedSignature: a signature file that is cut off, empty, too large or
// made of the wrong parts is a refusal, never a pass.
func TestDamagedSignature(t *testing.T) {
	t.Parallel()
	good, _ := signedDir(t)
	sig, err := os.ReadFile(filepath.Join(good, SignatureFile)) // #nosec G304 -- the test's own backup
	if err != nil {
		t.Fatal(err)
	}
	var parts Signature
	if err := json.Unmarshal(sig, &parts); err != nil {
		t.Fatal(err)
	}
	with := func(edit func(*Signature)) []byte {
		p := parts
		edit(&p)
		data, merr := json.Marshal(p)
		if merr != nil {
			t.Fatal(merr)
		}
		return data
	}
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{"cut in half", sig[:len(sig)/2], "can't be read"},
		{"cut after the key", sig[:max(0, bytes.Index(sig, []byte(`"signature"`)))], "can't be read"},
		{"empty", nil, "can't be read"},
		{"not JSON", []byte("-----BEGIN SIGNATURE-----\n"), "can't be read"},
		{"larger than the limit", bytes.Repeat([]byte(" "), maxSignature+1), "is larger than"},
		{"something after the JSON", append(append([]byte(nil), sig...), []byte(`{}`)...), "can't be read"},
		{"an unknown member", bytes.Replace(sig, []byte(`"format"`), []byte(`"extra": 1, "format"`), 1), "can't be read"},
		{"another algorithm", with(func(p *Signature) { p.Algorithm = "rsa" }), "algorithm"},
		{"another format", with(func(p *Signature) { p.Format = "myownpki-backup-signature/2" }), "format"},
		{"a signature that is too short", with(func(p *Signature) { p.Signature = p.Signature[:len(p.Signature)-2] }), "signature is not"},
		{"a signature that is not hex", with(func(p *Signature) { p.Signature = strings.Repeat("zz", 64) }), "signature is not"},
		{"a public key that is too short", with(func(p *Signature) { p.PublicKey = p.PublicKey[:60] }), "public key is not"},
		{"a flipped bit in the signature", with(func(p *Signature) {
			b := []byte(p.Signature)
			if b[0] == '0' {
				b[0] = '1'
			} else {
				b[0] = '0'
			}
			p.Signature = string(b)
		}), "does not match"},
		{"the key of another signer", with(func(p *Signature) { p.PublicKey = hex.EncodeToString(forgerKey(t).Public()) }), "does not match"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := backupCopy(t, good)
			if err := os.WriteFile(filepath.Join(dir, SignatureFile), tc.data, 0o600); err != nil { // #nosec G703 -- the test's own backup copy
				t.Fatal(err)
			}
			rep, err := Verify(t.Context(), dir, Check{})
			if !errors.Is(err, ErrRefused) || !strings.Contains(problemsOf(err, rep), tc.want) {
				t.Fatalf("want a refusal with %q, got %s", tc.want, problemsOf(err, rep))
			}
			if rep.Authenticity != "" {
				t.Errorf("a refused backup is %q", rep.Authenticity)
			}
		})
	}
	t.Run("a directory instead of the file", func(t *testing.T) {
		t.Parallel()
		dir := backupCopy(t, good)
		if err := os.Remove(filepath.Join(dir, SignatureFile)); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(filepath.Join(dir, SignatureFile), 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := Verify(t.Context(), dir, Check{}); !errors.Is(err, ErrRefused) {
			t.Errorf("%v", err)
		}
	})
}

// TestDowngrade: a backup of format 2 is always signed. Taking the signature
// away is refused; rewriting it as a backup of format 1 is a backup like the
// ones of older versions, which the pin refuses.
func TestDowngrade(t *testing.T) {
	t.Parallel()
	v, _, good, c := signedBackup(t)

	t.Run("signature deleted", func(t *testing.T) {
		t.Parallel()
		dir := backupCopy(t, good)
		if err := os.Remove(filepath.Join(dir, SignatureFile)); err != nil {
			t.Fatal(err)
		}
		for _, check := range []Check{{}, {BackupKey: c.SigningKey}, {BackupKey: c.SigningKey, AllowUnsigned: true}} {
			rep, err := Verify(t.Context(), dir, check)
			if !errors.Is(err, ErrRefused) || !strings.Contains(problemsOf(err, rep), SignatureFile+" is missing") {
				t.Errorf("%+v: %s", check, problemsOf(err, rep))
			}
		}
		target := targetOptions(t, v)
		if _, err := Restore(t.Context(), dir, Check{AllowUnsigned: true}, target); !errors.Is(err, ErrRefused) {
			t.Errorf("restore: %v", err)
		}
	})

	t.Run("rewritten as format 1", func(t *testing.T) {
		t.Parallel()
		dir := backupCopy(t, good)
		makeFormat1(t, dir)
		// Without a pin nobody can tell it from a backup of an older version.
		rep, err := Verify(t.Context(), dir, Check{})
		if err != nil || rep.Authenticity != Unauthenticated {
			t.Fatalf("unpinned: %v %+v", err, rep)
		}
		// With the pin it is refused ...
		rep, err = Verify(t.Context(), dir, Check{BackupKey: c.SigningKey})
		if !errors.Is(err, ErrRefused) || !strings.Contains(problemsOf(err, rep), "has no signature") {
			t.Fatalf("pinned: %s", problemsOf(err, rep))
		}
		target := targetOptions(t, v)
		if _, err = Restore(t.Context(), dir, Check{BackupKey: c.SigningKey}, target); !errors.Is(err, ErrRefused) {
			t.Fatalf("restore with the pin: %v", err)
		}
		if _, serr := os.Stat(target.Layout.DataDir); !errors.Is(serr, fs.ErrNotExist) {
			t.Errorf("a refused restore created the data directory: %v", serr)
		}
		// ... unless the operator says that he knows.
		rep, err = Verify(t.Context(), dir, Check{BackupKey: c.SigningKey, AllowUnsigned: true})
		if err != nil || rep.Authenticity != Unauthenticated || !strings.Contains(notesOf(rep), "unauthenticated") {
			t.Fatalf("allow-unsigned: %v %+v", err, rep)
		}
	})

	t.Run("a format 1 backup with a signature file", func(t *testing.T) {
		t.Parallel()
		dir := backupCopy(t, good)
		sig, err := os.ReadFile(filepath.Join(dir, SignatureFile)) // #nosec G304 -- the test's own backup copy
		if err != nil {
			t.Fatal(err)
		}
		makeFormat1(t, dir)
		if werr := os.WriteFile(filepath.Join(dir, SignatureFile), sig, 0o600); werr != nil { // #nosec G703 -- the test's own backup copy
			t.Fatal(werr)
		}
		rep, err := Verify(t.Context(), dir, Check{})
		if !errors.Is(err, ErrRefused) || !strings.Contains(problemsOf(err, rep), SignatureFile+" is not in the manifest") {
			t.Fatalf("%s", problemsOf(err, rep))
		}
	})
}

// TestFormat1BackupsStillRestore: what versions before 0.9.0 wrote verifies
// and restores, with the note that nobody can tell whether it was changed.
func TestFormat1BackupsStillRestore(t *testing.T) {
	t.Parallel()
	v, _, good, _ := signedBackup(t)
	dir := backupCopy(t, good)
	makeFormat1(t, dir)

	rep, err := Verify(t.Context(), dir, Check{})
	if err != nil || rep.Authenticity != Unauthenticated || rep.SigningKey != "" {
		t.Fatalf("verify: %v %+v", err, rep)
	}
	if n := notesOf(rep); !strings.Contains(n, "unauthenticated") || !strings.Contains(n, "no signature (made before 0.9.0)") {
		t.Errorf("notes %q", n)
	}
	target := targetOptions(t, v)
	rep, err = Restore(t.Context(), dir, Check{}, target)
	if err != nil || rep.Authenticity != Unauthenticated {
		t.Fatalf("restore: %v %+v", err, rep)
	}
	if _, serr := os.Stat(target.Layout.SystemDB()); serr != nil {
		t.Error(serr)
	}
	if _, serr := os.Stat(backupkey.Path(target.Layout.DataDir)); !errors.Is(serr, fs.ErrNotExist) {
		t.Errorf("a restore invented a backup key: %v", serr)
	}
	if !strings.Contains(notesOf(rep), "first backup made here creates a new one") {
		t.Errorf("notes %q", notesOf(rep))
	}
	// Prune treats it as the complete backup it is.
	parent := t.TempDir()
	if err := os.CopyFS(filepath.Join(parent, "20200101T000000Z"), os.DirFS(dir)); err != nil {
		t.Fatal(err)
	}
	if res, perr := Prune(parent, 1, true); perr != nil || len(res.Skipped) != 0 || len(res.Kept) != 1 {
		t.Errorf("prune: %+v %v", res, perr)
	}
}

// TestRestoreOnANewHost: the key stays on the old host. The restore works with
// the fingerprint the backup shows, says that the new instance has no key yet,
// and the next backup there makes a new one – old backups stay verifiable
// with the old fingerprint and not with the new one.
func TestRestoreOnANewHost(t *testing.T) {
	t.Parallel()
	v, _, good, c := signedBackup(t)

	// What the operator sees on the new host: the fingerprint of the backup.
	rep, err := Verify(t.Context(), good, Check{})
	if err != nil || rep.SigningKey != c.SigningKey {
		t.Fatalf("verify: %v %+v", err, rep)
	}
	target := targetOptions(t, v)
	rep, err = Restore(t.Context(), good, Check{BackupKey: rep.SigningKey}, target)
	if err != nil || rep.Authenticity != Pinned {
		t.Fatalf("restore: %v %+v", err, rep)
	}
	if n := notesOf(rep); !strings.Contains(n, backupkey.FileName+") is never part of a backup") || !strings.Contains(n, "--backup-key "+c.SigningKey) {
		t.Errorf("notes %q", n)
	}
	keyPath := backupkey.Path(target.Layout.DataDir)
	if _, serr := os.Stat(keyPath); !errors.Is(serr, fs.ErrNotExist) {
		t.Fatalf("the key file came along: %v", serr)
	}

	// The first backup on the new host makes a new key and says so.
	next := filepath.Join(t.TempDir(), "next")
	c2, err := Create(t.Context(), next, target)
	if err != nil || !c2.NewKey || c2.SigningKey == c.SigningKey {
		t.Fatalf("first backup after the restore: %+v %v", c2, err)
	}
	if _, verr := Verify(t.Context(), next, Check{BackupKey: c2.SigningKey}); verr != nil {
		t.Error(verr)
	}
	// The old backup is still good with the old fingerprint, and refused with
	// the new one: that is the case the message has to explain.
	if _, verr := Verify(t.Context(), good, Check{BackupKey: c.SigningKey}); verr != nil {
		t.Error(verr)
	}
	rep, err = Verify(t.Context(), good, Check{BackupKey: c2.SigningKey})
	if !errors.Is(err, ErrRefused) || !strings.Contains(problemsOf(err, rep), "signed by key "+c.SigningKey) {
		t.Errorf("old backup, new key: %s", problemsOf(err, rep))
	}
}

// TestLostKeyFile: a deleted key file is made again by the next backup; the
// backups made before verify with the old fingerprint.
func TestLostKeyFile(t *testing.T) {
	t.Parallel()
	_, o, good, c := signedBackup(t)
	if err := os.Remove(backupkey.Path(o.Layout.DataDir)); err != nil {
		t.Fatal(err)
	}
	next := filepath.Join(t.TempDir(), "next")
	c2, err := Create(t.Context(), next, o)
	if err != nil || !c2.NewKey || c2.SigningKey == c.SigningKey {
		t.Fatalf("backup after the loss: %+v %v", c2, err)
	}
	if _, verr := Verify(t.Context(), good, Check{BackupKey: c.SigningKey}); verr != nil {
		t.Errorf("the old backup with the noted fingerprint: %v", verr)
	}
}

func TestCreateWithAnUnusableKeyFile(t *testing.T) {
	t.Parallel()
	v, o := newInstance(t)
	issue(t, v, "nas.homelab.lan")
	keyPath := backupkey.Path(o.Layout.DataDir)
	for name, content := range map[string]string{"empty": "", "garbage": "not a key\n"} {
		if err := os.WriteFile(keyPath, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		dir := filepath.Join(t.TempDir(), name)
		c, err := Create(t.Context(), dir, o)
		if err == nil || c != nil || !strings.Contains(err.Error(), "backup signing key") {
			t.Errorf("%s: %+v %v", name, c, err)
		}
		if _, serr := os.Stat(dir); !errors.Is(serr, fs.ErrNotExist) {
			t.Errorf("%s: the refused backup left a directory: %v", name, serr)
		}
		if data, _ := os.ReadFile(keyPath); string(data) != content { // #nosec G304 G703 -- the test's own key file
			t.Errorf("%s: the key file was changed", name)
		}
	}
}

// TestPruneKeepsFormat2Complete: a backup of format 2 without its signature is
// not complete, so Prune leaves it alone; with it, it is.
func TestPruneKeepsFormat2Complete(t *testing.T) {
	t.Parallel()
	good, _ := signedDir(t)
	parent := t.TempDir()
	for _, n := range []string{"20200101T000000Z", "20200102T000000Z"} {
		if err := os.CopyFS(filepath.Join(parent, n), os.DirFS(good)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Remove(filepath.Join(parent, "20200101T000000Z", SignatureFile)); err != nil {
		t.Fatal(err)
	}
	res, err := Prune(parent, 1, true)
	if err != nil || len(res.Kept) != 1 || res.Kept[0] != "20200102T000000Z" || len(res.Skipped) != 1 || !strings.Contains(res.Skipped[0].Reason, SignatureFile) {
		t.Errorf("%+v %v", res, err)
	}
}

// TestFirstBackupMakesTheKey: an instance from before 0.9.0 has no key file;
// its first backup makes one (0600) and says so, and the next one keeps it.
func TestFirstBackupMakesTheKey(t *testing.T) {
	t.Parallel()
	v, o := newInstance(t)
	issue(t, v, "nas.homelab.lan")
	keyPath := backupkey.Path(o.Layout.DataDir)
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "first")
	c, err := Create(t.Context(), dir, o)
	if err != nil || !c.NewKey {
		t.Fatalf("first backup: %+v %v", c, err)
	}
	if runtime.GOOS != "windows" {
		if fi, serr := os.Stat(keyPath); serr != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("key file: %v %v", fi, serr)
		}
	}
	if rep, verr := Verify(t.Context(), dir, Check{BackupKey: c.SigningKey}); verr != nil || rep.Authenticity != Pinned {
		t.Errorf("verify: %v %+v", verr, rep)
	}
	c2, err := Create(t.Context(), filepath.Join(t.TempDir(), "second"), o)
	if err != nil || c2.NewKey || c2.SigningKey != c.SigningKey {
		t.Errorf("second backup: %+v %v", c2, err)
	}
}

// TestHostKeyIsOnlyAHint: Check.HostKey (the key file of the host that
// verifies) never refuses a backup. Signed by it: pinned. Signed by another
// key: passes with a note. No signature (format 1): passes, unauthenticated.
// Only an explicit BackupKey refuses, and then HostKey is ignored.
func TestHostKeyIsOnlyAHint(t *testing.T) {
	t.Parallel()
	_, _, good, c := signedBackup(t)
	other := forgerKey(t).Fingerprint()

	rep, err := Verify(t.Context(), good, Check{HostKey: c.SigningKey})
	if err != nil || rep.Authenticity != Pinned || rep.SigningKey != c.SigningKey {
		t.Fatalf("signed by the host key: %v %+v", err, rep)
	}
	rep, err = Verify(t.Context(), good, Check{HostKey: other})
	if err != nil || rep.Authenticity != Signed || !strings.Contains(notesOf(rep), "signed by key "+c.SigningKey+", not this host's key "+other) {
		t.Fatalf("signed by another key: %v %s", err, notesOf(rep))
	}
	if _, err = Verify(t.Context(), good, Check{BackupKey: other, HostKey: c.SigningKey}); !errors.Is(err, ErrRefused) {
		t.Errorf("an explicit pin on another key must refuse, whatever the host key: %v", err)
	}
	if _, err = Verify(t.Context(), good, Check{BackupKey: c.SigningKey, HostKey: other}); err != nil {
		t.Errorf("an explicit pin on the signer passes, whatever the host key: %v", err)
	}

	old := backupCopy(t, good)
	makeFormat1(t, old)
	rep, err = Verify(t.Context(), old, Check{HostKey: c.SigningKey})
	if err != nil || rep.Authenticity != Unauthenticated || !strings.Contains(notesOf(rep), "unauthenticated") {
		t.Fatalf("format 1 with a host key: %v %+v", err, rep)
	}
	if _, err = Verify(t.Context(), old, Check{BackupKey: c.SigningKey, HostKey: c.SigningKey}); !errors.Is(err, ErrRefused) {
		t.Errorf("format 1 with an explicit pin: %v", err)
	}
	if rep, err = Verify(t.Context(), old, Check{BackupKey: c.SigningKey, AllowUnsigned: true}); err != nil || rep.Authenticity != Unauthenticated {
		t.Errorf("format 1 with a pin and allow-unsigned: %v", err)
	}
	// A deleted signature of a format 2 backup is refused with a host key too.
	broken := backupCopy(t, good)
	if err = os.Remove(filepath.Join(broken, SignatureFile)); err != nil {
		t.Fatal(err)
	}
	if _, err = Verify(t.Context(), broken, Check{HostKey: c.SigningKey}); !errors.Is(err, ErrRefused) {
		t.Errorf("format 2 without a signature: %v", err)
	}
	if _, err = Verify(t.Context(), good, Check{HostKey: "abc"}); err == nil || errors.Is(err, ErrRefused) {
		t.Errorf("a host key that is no fingerprint: %v", err)
	}
}
