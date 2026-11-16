package backup

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/backup/backupkey"
	"github.com/Der-Felix/MyOwnPKI/internal/testutil/racemode"
)

// FuzzManifest feeds the same bytes to the two parsers of a backup directory:
// manifest.json (parseManifest) and manifest.sig (ParseSignature,
// verifySignature). Both read files that whoever can write the backup
// directory controls (PHASE3 section 18.2, 19.3). The target calls them
// unchanged and re-checks what they accepted with the standard library only.

// fuzzMaxTime is the wall time one input may take (section 18.2, rule 2).
var fuzzMaxTime = racemode.Scale(2 * time.Second)

// fuzzMaxError bounds the text of a refusal (rule 5).
const fuzzMaxError = 400

// fuzzKey is made once per process, not per input.
var fuzzKey = sync.OnceValue(func() *backupkey.Key {
	k, err := backupkey.Generate(nil)
	if err != nil {
		panic(err)
	}
	return k
})

func FuzzManifest(f *testing.F) {
	manifest := func(format string) []byte {
		data, err := json.MarshalIndent(&Manifest{
			Format: format, CreatedAt: "2026-11-16T10:00:00.000Z", Version: "v0.9.0", Tenants: []string{"default"},
			Files: []File{{Path: "system.db", Kind: "system", SHA256: hex.EncodeToString(make([]byte, 32)), Size: 4096, Migration: 15}},
			Audit: []Log{{Scope: "instance", Path: "audit.db", Head: "3:" + hex.EncodeToString(make([]byte, 32)), Entries: 3}},
		}, "", "  ")
		if err != nil {
			f.Fatal(err)
		}
		return append(data, '\n')
	}
	v2, v1 := manifest(Format), manifest(FormatUnsigned)
	sig, err := signManifest(fuzzKey(), v2)
	if err != nil {
		f.Fatal(err)
	}
	for _, seed := range [][]byte{
		v2, v1, sig,
		manifest("myownpki-backup/3"),
		[]byte(`{}`),
		[]byte(`{"format":"myownpki-backup/2","created_at":"2026-11-16T10:00:00.000Z"} {}`),
		[]byte(`{"format":"myownpki-backup/2","created_at":"yesterday"}`),
		[]byte(`{"format":"myownpki-backup/2","extra":true}`),
		bytes.Replace(sig, []byte("ed25519"), []byte("rsa"), 1),
		bytes.Replace(sig, []byte(`"signature": "`), []byte(`"signature": "00`), 1),
		sig[:len(sig)/2],
		[]byte(`{"format":"myownpki-backup-signature/1","algorithm":"ed25519","public_key":"","signature":""}`),
		nil,
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		start := time.Now()
		defer func() {
			if d := time.Since(start); d > fuzzMaxTime {
				t.Errorf("one input took %v", d)
			}
		}()

		m, err := parseManifest(data)
		if err != nil {
			if len(err.Error()) > fuzzMaxError {
				t.Fatalf("the refusal is %d bytes long", len(err.Error()))
			}
		} else {
			// Accept means promise: a known format, a real time, JSON that
			// says the same after one more round, and a bounded input.
			if m.Format != Format && m.Format != FormatUnsigned {
				t.Fatalf("accepted format %q", m.Format)
			}
			if _, terr := time.Parse("2006-01-02T15:04:05.000Z", m.CreatedAt); terr != nil {
				t.Fatalf("accepted created_at %q", m.CreatedAt)
			}
			if len(data) > maxManifest {
				t.Fatalf("accepted %d bytes", len(data))
			}
			again, merr := json.Marshal(m)
			if merr != nil {
				t.Fatal(merr)
			}
			m2, perr := parseManifest(again)
			if perr != nil || !reflect.DeepEqual(m, m2) {
				t.Fatalf("round trip: %v", perr)
			}
		}

		pub, sigBytes, err := ParseSignature(data)
		if err != nil {
			if len(err.Error()) > fuzzMaxError {
				t.Fatalf("the refusal is %d bytes long", len(err.Error()))
			}
		} else {
			if len(pub) != ed25519.PublicKeySize || len(sigBytes) != ed25519.SignatureSize {
				t.Fatalf("accepted a key of %d and a signature of %d bytes", len(pub), len(sigBytes))
			}
			// Whatever the file claims, it must not verify against itself
			// unless the claim is true.
			if ed25519.Verify(pub, signedMessage(data), sigBytes) {
				if _, verr := verifySignature(data, data); verr != nil {
					t.Fatalf("a valid signature was refused: %v", verr)
				}
			} else if _, verr := verifySignature(data, data); verr == nil {
				t.Fatal("an invalid signature was accepted")
			}
		}

		// The signature binds the exact bytes: signing data verifies for data
		// and for nothing else.
		own, err := signManifest(fuzzKey(), data)
		if err != nil {
			t.Fatal(err)
		}
		got, err := verifySignature(own, data)
		if err != nil || !bytes.Equal(got, fuzzKey().Public()) {
			t.Fatalf("own signature: %v", err)
		}
		if _, err := verifySignature(own, append(append([]byte(nil), data...), ' ')); err == nil {
			t.Fatal("the signature of one manifest verified for another")
		}
	})
}
