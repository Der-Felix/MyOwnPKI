// Package backupkey holds the Ed25519 key that signs the manifest of every
// backup (docs/PHASE3.md section 19.3, PLAN section 5). It is a package of
// its own so that `init` (internal/setup) can create the key without
// importing internal/backup, whose tests build instances through setup.
//
// The key lives in the data directory as a file of mode 0600, outside every
// database, and is never copied into a backup: whoever holds a backup alone
// can't sign a changed one. It needs no passphrase, so the daily timer (a
// process of its own, with no unseal) can use it.
package backupkey

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// FileName is the name of the key file inside the data directory.
const FileName = "backup-signing.key"

const (
	header  = "myownpki-backup-key-v1"
	maxFile = 4 << 10
	// fingerprintBytes is how much of the SHA-256 over the public key a
	// fingerprint shows – the same 16 bytes as the checkpoint key's.
	fingerprintBytes = 16
	// MinPinDigits is the shortest fingerprint prefix that pins a key.
	MinPinDigits = 16
	// Prefix starts a fingerprint as it is shown; a pin may leave it out.
	Prefix = "SHA256:"
)

// ErrExists: a backup key is never overwritten – every backup made with it
// would lose the fingerprint noted for it.
var ErrExists = errors.New("the backup key file exists already – it is never overwritten")

// Path is where the key of the instance with this data directory lives.
func Path(dataDir string) string { return filepath.Join(dataDir, FileName) }

// Key is the private signing key.
type Key struct {
	priv ed25519.PrivateKey
}

// Public is the public half; backups carry it in manifest.sig.
func (k *Key) Public() ed25519.PublicKey {
	pub, _ := k.priv.Public().(ed25519.PublicKey) // always: ed25519.PrivateKey.Public
	return pub
}

// Fingerprint is how the key is shown, noted and pinned.
func (k *Key) Fingerprint() string { return Fingerprint(k.Public()) }

// Sign signs msg (Ed25519, deterministic).
func (k *Key) Sign(msg []byte) []byte { return ed25519.Sign(k.priv, msg) }

// Fingerprint shows a public key: "SHA256:" and the first 16 bytes of the
// SHA-256 over the raw key, in lower-case hex.
func Fingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return Prefix + hex.EncodeToString(sum[:fingerprintBytes])
}

// NormalizePin turns what an operator typed into lower-case hex digits: the
// "SHA256:" prefix is optional, at least 16 digits are required.
func NormalizePin(pin string) (string, error) {
	p := strings.TrimSpace(pin)
	if len(p) >= len(Prefix) && strings.EqualFold(p[:len(Prefix)], Prefix) {
		p = p[len(Prefix):]
	}
	p = strings.ToLower(p)
	if len(p) < MinPinDigits || len(p) > 2*sha256.Size {
		return "", fmt.Errorf("a key fingerprint has %d to %d hex digits (as printed after %q)", MinPinDigits, 2*sha256.Size, Prefix)
	}
	for _, c := range p {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return "", errors.New("a key fingerprint has hex digits only")
		}
	}
	return p, nil
}

// Matches reports whether fingerprint (as Fingerprint prints it) starts
// with the normalized pin.
func Matches(fingerprint, pin string) bool {
	return strings.HasPrefix(strings.TrimPrefix(fingerprint, Prefix), pin)
}

// Generate makes a new random key in memory. rnd nil = crypto/rand.
func Generate(rnd io.Reader) (*Key, error) {
	if rnd == nil {
		rnd = rand.Reader
	}
	seed := make([]byte, ed25519.SeedSize)
	defer clear(seed)
	if _, err := io.ReadFull(rnd, seed); err != nil {
		return nil, fmt.Errorf("backup key: %w", err)
	}
	return &Key{priv: ed25519.NewKeyFromSeed(seed)}, nil
}

// Create writes a new random key to path (mode 0600) and never overwrites an
// existing file. rnd nil = crypto/rand.
func Create(path string, rnd io.Reader) (*Key, error) {
	k, err := Generate(rnd)
	if err != nil {
		return nil, err
	}
	seed := k.priv.Seed()
	defer clear(seed)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- the key file below the configured data directory
	if errors.Is(err, fs.ErrExist) {
		return nil, fmt.Errorf("%s: %w", path, ErrExists)
	}
	if err != nil {
		return nil, fmt.Errorf("backup key: %w", err)
	}
	_, werr := fmt.Fprintf(f, "%s %s\n", header, base64.StdEncoding.EncodeToString(seed))
	if werr == nil {
		werr = f.Sync()
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		_ = os.Remove(path)
		return nil, fmt.Errorf("backup key %s: %w", path, werr)
	}
	return k, nil
}

// Load reads the key. A file that others can read is allowed with a warning;
// one that others can write is refused – whoever can replace the key signs
// the backups.
func Load(path string) (*Key, []string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, nil, fmt.Errorf("backup key %s: %w", path, err)
	}
	var warnings []string
	if runtime.GOOS != "windows" {
		switch perm := info.Mode().Perm(); {
		case perm&0o022 != 0:
			return nil, nil, fmt.Errorf("backup key %s is writable by group or others (%v) – chmod 600 %s", path, perm, path)
		case perm&0o044 != 0:
			warnings = append(warnings, fmt.Sprintf("backup key %s is readable by group or others (%v) – chmod 600 %s", path, perm, path))
		}
	}
	if info.Size() > maxFile {
		return nil, nil, fmt.Errorf("backup key %s: not a backup key file (too large)", path)
	}
	data, err := os.ReadFile(path) // #nosec G304 -- the key file below the configured data directory
	if err != nil {
		return nil, nil, fmt.Errorf("backup key %s: %w", path, err)
	}
	defer clear(data)
	fields := strings.Fields(string(data))
	if len(fields) != 2 || fields[0] != header {
		return nil, nil, fmt.Errorf("backup key %s: not a backup key file (want %q and the key) – if it is empty or damaged, delete it: the next backup makes a new key", path, header)
	}
	seed, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, nil, fmt.Errorf("backup key %s: the key is damaged – delete it: the next backup makes a new key", path)
	}
	defer clear(seed)
	return &Key{priv: ed25519.NewKeyFromSeed(seed)}, warnings, nil
}

// LoadOrCreate returns the key of the file at path, making the file when it
// doesn't exist. created tells whether it was made now: a lost file can't be
// told from a first run, so the caller says so.
func LoadOrCreate(path string, rnd io.Reader) (k *Key, created bool, warnings []string, err error) {
	k, warnings, err = Load(path)
	if err == nil {
		return k, false, warnings, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil, err
	}
	k, err = Create(path, rnd)
	switch {
	case errors.Is(err, ErrExists): // made by another process in between
		k, warnings, err = Load(path)
		return k, false, warnings, err
	case err != nil:
		return nil, false, nil, err
	}
	return k, true, nil, nil
}
