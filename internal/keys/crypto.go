// Package keys holds the key hierarchy of the online CA keys (PLAN §5 "Keys",
// security.md "Key storage"):
//
//	passphrase --Argon2id--> KEK --AES-GCM--> root key --AES-GCM--> DEK --AES-GCM--> private key
//	recovery key --HKDF----> recovery KEK --AES-GCM--> root key (second copy)
//
// The server starts sealed. Unseal puts only the root key in memory; DEKs and
// private keys are decrypted for one signing operation at a time.
package keys

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"testing"

	"golang.org/x/crypto/argon2"
)

// ErrDecrypt means a ciphertext could not be opened: wrong key, or the
// ciphertext was changed or moved to another row.
var ErrDecrypt = errors.New("decryption failed")

const formatV1 byte = 1

const (
	nonceSize = 12
	keySize   = 32
)

// sealAEAD encrypts with AES-256-GCM. The result is version | nonce |
// ciphertext+tag. aad binds the ciphertext to its purpose and row: it is
// authenticated but not stored, so a ciphertext copied to another purpose or
// key ID no longer decrypts.
func sealAEAD(rnd io.Reader, key, plaintext []byte, aad string) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 1+nonceSize, 1+nonceSize+len(plaintext)+gcm.Overhead())
	out[0] = formatV1
	if _, err := io.ReadFull(rnd, out[1:]); err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}
	return gcm.Seal(out, out[1:], plaintext, []byte(aad)), nil
}

func openAEAD(key, blob []byte, aad string) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(blob) < 1+nonceSize+gcm.Overhead() || blob[0] != formatV1 {
		return nil, ErrDecrypt
	}
	plain, err := gcm.Open(nil, blob[1:1+nonceSize], blob[1+nonceSize:], []byte(aad))
	if err != nil {
		return nil, ErrDecrypt
	}
	return plain, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != keySize {
		return nil, fmt.Errorf("key must be %d bytes", keySize)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func randomBytes(rnd io.Reader, n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rnd, b); err != nil {
		return nil, fmt.Errorf("random: %w", err)
	}
	return b, nil
}

// Additional data per purpose. Changing a string makes old ciphertexts
// unreadable – they are part of the format (v1).
func aadRootKey(slot string, version int64) string {
	return fmt.Sprintf("myownpki/v1/root-key/%s/%d", slot, version)
}

func aadDEK(keyID string, rootVersion int64) string {
	return fmt.Sprintf("myownpki/v1/dek/%s/%d", keyID, rootVersion)
}

func aadPrivateKey(keyID, purpose, algorithm string) string {
	return fmt.Sprintf("myownpki/v1/key/%s/%s/%s", keyID, purpose, algorithm)
}

// argon2Params are stored with the passphrase slot, so a later passphrase
// change can move to stronger defaults without breaking old data.
type argon2Params struct {
	Time      uint32 `json:"t"`
	MemoryKiB uint32 `json:"m"`
	Threads   uint8  `json:"p"`
}

// defaultArgon2 (owner decision 2026-10-13): t=4, 256 MiB, p=4 – about
// 0.1 s on a 4-core server, 1–2 s on a Raspberry Pi; fits a 512 MB container.
var defaultArgon2 = argon2Params{Time: 4, MemoryKiB: 256 * 1024, Threads: 4}

// testArgon2 are the weak parameters of tests – the only place for them:
// the key ring uses them through TestKDF, the password hasher through
// auth.TestParams (both via TestArgon2). 8 MiB is the floor check accepts.
var testArgon2 = argon2Params{Time: 1, MemoryKiB: 8 * 1024, Threads: 1}

// TestArgon2 returns the weak Argon2id parameters of tests (t=1, 8 MiB,
// p=1). It panics outside a test binary: there is no way to make a server
// use them – no flag, no configuration key, no environment variable.
func TestArgon2() (timeCost, memoryKiB uint32, threads uint8) {
	if err := allowTestKDF(testing.Testing()); err != nil {
		panic(err)
	}
	return testArgon2.Time, testArgon2.MemoryKiB, testArgon2.Threads
}

func allowTestKDF(testBinary bool) error {
	if !testBinary {
		return errors.New("keys: the weak test KDF parameters are only for test binaries")
	}
	return nil
}

// checkUnsealParams refuses a passphrase slot whose parameters are below the
// production values (owner decision 2026-10-23): such a key ring was made by
// a test binary and must not protect real keys. Every key ring of v0.1.0 has
// exactly defaultArgon2 – it was the only value outside tests. Test binaries
// accept the weak values of testArgon2.
func checkUnsealParams(p argon2Params, testBinary bool) error {
	if testBinary {
		return nil
	}
	m := defaultArgon2
	if p.Time < m.Time || p.MemoryKiB < m.MemoryKiB || p.Threads < m.Threads {
		return fmt.Errorf("%w: the passphrase slot asks for Argon2id t=%d, %d MiB, p=%d; the minimum is t=%d, %d MiB, p=%d "+
			"(a key ring made by a test build) – unseal with the recovery key and set a new passphrase",
			ErrWeakKDF, p.Time, p.MemoryKiB/1024, p.Threads, m.Time, m.MemoryKiB/1024, m.Threads)
	}
	return nil
}

// check rejects stored parameters that would make one unseal attempt
// exhaust the machine (a tampered row must not become a denial of service).
func (p argon2Params) check() error {
	if p.Time < 1 || p.Time > 16 || p.MemoryKiB < 8*1024 || p.MemoryKiB > 2*1024*1024 || p.Threads < 1 || p.Threads > 16 {
		return fmt.Errorf("argon2id parameters out of bounds: %+v", p)
	}
	return nil
}

func parseArgon2Params(s string) (argon2Params, error) {
	var p argon2Params
	if err := json.Unmarshal([]byte(s), &p); err != nil {
		return p, fmt.Errorf("argon2id parameters: %w", err)
	}
	return p, p.check()
}

func (p argon2Params) json() string {
	b, _ := json.Marshal(p)
	return string(b)
}

func passphraseKEK(passphrase, salt []byte, p argon2Params) []byte {
	return argon2.IDKey(passphrase, salt, p.Time, p.MemoryKiB, p.Threads, keySize)
}

// recoveryKEK needs no slow KDF: the recovery key is 256 random bits already.
func recoveryKEK(k RecoveryKey, salt []byte) ([]byte, error) {
	return hkdf.Key(sha256.New, k[:], salt, "myownpki/v1/recovery-kek", keySize)
}

var defaultRand io.Reader = rand.Reader
