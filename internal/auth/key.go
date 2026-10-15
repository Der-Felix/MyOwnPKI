// Package auth signs users in to the admin listener (PHASE1 step 10,
// security.md "Authentication"): Argon2id passwords, TOTP (RFC 6238),
// recovery codes, server-side sessions, CSRF protection, throttling and
// lockout. Permissions are decided by internal/authz.
//
// Secrets at rest: passwords as Argon2id hashes; TOTP secrets encrypted with
// the auth key (auth.key_file), bound to user ID and purpose; recovery codes
// as HMAC with a key derived from it; sessions as SHA-256 of the cookie.
package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"runtime"
	"strings"
)

const (
	keyFileHeader = "myownpki-auth-key-v1"
	keySize       = 32
	maxKeyFile    = 4 << 10
	nonceSize     = 12
)

// ErrKeyExists: an auth key is never overwritten – every TOTP secret would
// become unreadable.
var ErrKeyExists = errors.New("the auth key file exists already – it is never overwritten")

// Key is the auth key. It lives outside the databases, so a copy of
// system.db alone holds no usable TOTP secret.
type Key struct {
	totp     cipher.AEAD
	recovery []byte // HMAC key for recovery code hashes
}

// CreateKeyFile writes a new random auth key to path (mode 0600). It never
// overwrites an existing file. rnd nil = crypto/rand.
func CreateKeyFile(path string, rnd io.Reader) error {
	raw, err := randomBytes(rnd, keySize)
	if err != nil {
		return err
	}
	defer clear(raw)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("%s: %w", path, ErrKeyExists)
	}
	if err != nil {
		return err
	}
	_, werr := fmt.Fprintf(f, "%s %s\n", keyFileHeader, base64.StdEncoding.EncodeToString(raw))
	if werr == nil {
		werr = f.Sync()
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		_ = os.Remove(path)
	}
	return werr
}

// LoadKey reads the auth key. A file others can read is allowed with a
// warning (Docker secrets are 0444 by default); a file others can write is
// refused – whoever can replace the key can lock everybody out.
func LoadKey(path string) (*Key, []string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, nil, fmt.Errorf("auth key %s: %w (myownpki init creates it; if it is lost: myownpki user reset-2fa --new-auth-key)", path, err)
	}
	var warnings []string
	if runtime.GOOS != "windows" {
		switch perm := info.Mode().Perm(); {
		case perm&0o022 != 0:
			return nil, nil, fmt.Errorf("auth key %s is writable by group or others (%v) – chmod 600 %s", path, perm, path)
		case perm&0o044 != 0:
			warnings = append(warnings, fmt.Sprintf("auth key %s is readable by group or others (%v) – chmod 600 unless it is a container secret", path, perm))
		}
	}
	if info.Size() > maxKeyFile {
		return nil, nil, fmt.Errorf("auth key %s: not an auth key file (too large)", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("auth key %s: %w", path, err)
	}
	defer clear(data)
	fields := strings.Fields(string(data))
	if len(fields) != 2 || fields[0] != keyFileHeader {
		return nil, nil, fmt.Errorf("auth key %s: not an auth key file (want %q and the key)", path, keyFileHeader)
	}
	raw, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil || len(raw) != keySize {
		return nil, nil, fmt.Errorf("auth key %s: the key is damaged", path)
	}
	defer clear(raw)
	k, err := newKey(raw)
	return k, warnings, err
}

// newKey derives one subkey per purpose (HKDF-SHA256).
func newKey(raw []byte) (*Key, error) {
	totpKey, err := hkdf.Key(sha256.New, raw, nil, "myownpki auth totp-secret v1", keySize)
	if err != nil {
		return nil, err
	}
	defer clear(totpKey)
	recovery, err := hkdf.Key(sha256.New, raw, nil, "myownpki auth recovery-code v1", keySize)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(totpKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Key{totp: aead, recovery: recovery}, nil
}

// totpAAD binds a sealed TOTP secret to its purpose and user: a secret copied
// to another user's row doesn't open.
func totpAAD(userID string) []byte { return []byte("myownpki/totp-secret/v1\x00" + userID) }

// ErrUnreadableSecret: the TOTP secret doesn't open with this auth key –
// another key file, or a damaged row.
var ErrUnreadableSecret = errors.New("the TOTP secret can't be read with this auth key – wrong auth.key_file? (lost key: myownpki user reset-2fa)")

func (k *Key) sealTOTP(rnd io.Reader, userID string, secret []byte) ([]byte, error) {
	nonce, err := randomBytes(rnd, nonceSize)
	if err != nil {
		return nil, err
	}
	return k.totp.Seal(nonce, nonce, secret, totpAAD(userID)), nil
}

func (k *Key) openTOTP(userID string, sealed []byte) ([]byte, error) {
	if len(sealed) < nonceSize+k.totp.Overhead() {
		return nil, ErrUnreadableSecret
	}
	secret, err := k.totp.Open(nil, sealed[:nonceSize], sealed[nonceSize:], totpAAD(userID))
	if err != nil {
		return nil, ErrUnreadableSecret
	}
	return secret, nil
}

// recoveryHash keys the hash of a recovery code with the auth key: with a
// copy of system.db alone the codes can't even be tried offline.
func (k *Key) recoveryHash(userID, code string) string {
	mac := hmac.New(sha256.New, k.recovery)
	mac.Write([]byte(userID))
	mac.Write([]byte{0})
	mac.Write([]byte(code))
	return hex.EncodeToString(mac.Sum(nil))
}
