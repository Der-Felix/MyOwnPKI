package backupkey

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCreateLoadRoundTrip(t *testing.T) {
	t.Parallel()
	path := Path(t.TempDir())
	k, err := Create(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if fi, serr := os.Stat(path); serr != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("mode of the key file: %v %v", fi, serr)
		}
	}
	loaded, warnings, err := Load(path)
	if err != nil || len(warnings) != 0 {
		t.Fatalf("load: %v %v", err, warnings)
	}
	if !bytes.Equal(loaded.Public(), k.Public()) || loaded.Fingerprint() != k.Fingerprint() {
		t.Error("the loaded key is another key")
	}
	msg := []byte("message")
	if !ed25519.Verify(k.Public(), msg, loaded.Sign(msg)) {
		t.Error("a signature of the loaded key does not verify with the public key")
	}
	if fp := k.Fingerprint(); !strings.HasPrefix(fp, Prefix) || len(fp) != len(Prefix)+2*fingerprintBytes {
		t.Errorf("fingerprint %q", fp)
	}
}

func TestCreateNeverOverwrites(t *testing.T) {
	t.Parallel()
	path := Path(t.TempDir())
	first, err := Create(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, cerr := Create(path, nil); !errors.Is(cerr, ErrExists) {
		t.Errorf("second create: %v", cerr)
	}
	again, _, err := Load(path)
	if err != nil || again.Fingerprint() != first.Fingerprint() {
		t.Errorf("the key changed: %v", err)
	}
}

func TestCreateFailsOnShortRandomSource(t *testing.T) {
	t.Parallel()
	path := Path(t.TempDir())
	if _, err := Create(path, strings.NewReader("too short")); err == nil {
		t.Fatal("a key from 9 random bytes")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a failed create left a file: %v", err)
	}
}

func TestLoadOrCreate(t *testing.T) {
	t.Parallel()
	path := Path(t.TempDir())
	k1, created, _, err := LoadOrCreate(path, nil)
	if err != nil || !created {
		t.Fatalf("first: %v %v", created, err)
	}
	k2, created, _, err := LoadOrCreate(path, nil)
	if err != nil || created || k2.Fingerprint() != k1.Fingerprint() {
		t.Fatalf("second: %v %v", created, err)
	}
}

func TestLoadRefusals(t *testing.T) {
	t.Parallel()
	for name, content := range map[string]string{
		"empty":         "",
		"wrong header":  "myownpki-auth-key-v1 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n",
		"not base64":    header + " ***\n",
		"short key":     header + " AAAA\n",
		"extra field":   header + " AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= more\n",
		"large garbage": strings.Repeat("x", maxFile+1),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			path := Path(t.TempDir())
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			_, _, err := Load(path)
			if err == nil || strings.Contains(err.Error(), "AAAA") {
				t.Fatalf("load: %v", err)
			}
			// A damaged file is no reason to make another key behind the
			// operator's back: LoadOrCreate says so.
			if _, _, _, err := LoadOrCreate(path, nil); err == nil {
				t.Error("LoadOrCreate replaced a damaged key file")
			}
			if data, _ := os.ReadFile(path); string(data) != content { // #nosec G304 G703 -- the test's own file
				t.Error("the damaged file was changed")
			}
		})
	}
	if _, _, err := Load(filepath.Join(t.TempDir(), "missing")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing file: %v", err)
	}
}

func TestLoadPermissions(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("file modes mean nothing on Windows")
	}
	path := Path(t.TempDir())
	if _, err := Create(path, nil); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o640); err != nil { // #nosec G302 -- the test makes a readable key on purpose
		t.Fatal(err)
	}
	if _, warnings, err := Load(path); err != nil || len(warnings) != 1 || !strings.Contains(warnings[0], "readable by group or others") {
		t.Errorf("group readable: %v %v", warnings, err)
	}
	if err := os.Chmod(path, 0o660); err != nil { // #nosec G302 -- the test makes a writable key on purpose
		t.Fatal(err)
	}
	if _, _, err := Load(path); err == nil || !strings.Contains(err.Error(), "writable by group or others") {
		t.Errorf("group writable: %v", err)
	}
}

func TestNormalizePinAndMatches(t *testing.T) {
	t.Parallel()
	k, err := Generate(nil)
	if err != nil {
		t.Fatal(err)
	}
	fp := k.Fingerprint()
	digits := strings.TrimPrefix(fp, Prefix)
	for name, in := range map[string]string{
		"as printed":     fp,
		"without prefix": digits,
		"upper case":     strings.ToUpper(digits),
		"lower prefix":   "sha256:" + digits,
		"16 digits":      digits[:MinPinDigits],
		"with blanks":    "  " + fp + "\n",
		"the full hash":  digits + strings.Repeat("0", 32), // longer than shown: no match, but well formed
	} {
		pin, err := NormalizePin(in)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if want := name != "the full hash"; Matches(fp, pin) != want {
			t.Errorf("%s: matches = %v", name, !want)
		}
	}
	for name, in := range map[string]string{
		"empty":     "",
		"too short": digits[:MinPinDigits-1],
		"not hex":   "SHA256:" + strings.Repeat("z", 32),
		"too long":  strings.Repeat("a", 65),
		"prefix":    "SHA256:",
	} {
		if _, err := NormalizePin(in); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if Matches(fp, strings.Repeat("0", 32)) {
		t.Error("another fingerprint matched")
	}
}
