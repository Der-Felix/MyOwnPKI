package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"

	"github.com/Der-Felix/MyOwnPKI/internal/keys"
)

// Params are the Argon2id parameters of a password hash. They are stored in
// the hash (PHC string format), so stronger defaults apply to old hashes at
// the next sign-in.
type Params struct {
	Time      uint32
	MemoryKiB uint32
	Threads   uint8
}

// DefaultParams: 64 MiB, 3 passes, 1 lane – above the OWASP minimum
// (19 MiB, t=2). The unseal passphrase uses 256 MiB, but it is checked
// rarely; logins are frequent.
var DefaultParams = Params{Time: 3, MemoryKiB: 64 * 1024, Threads: 1}

// TestParams are the weak Argon2id parameters of tests – the same values as
// the key ring's test KDF, kept in one place (keys.TestArgon2). It panics
// outside a test binary.
func TestParams() Params {
	t, m, p := keys.TestArgon2()
	return Params{Time: t, MemoryKiB: m, Threads: p}
}

const (
	// MaxParallelHashes bounds the memory a login flood can take:
	// 4 x 64 MiB. The throttle refuses before a slot is taken.
	MaxParallelHashes = 4
	// HashWait is how long a request waits for a free slot before "busy".
	HashWait  = 2 * time.Second
	saltSize  = 16
	hashSize  = 32
	maxPHCLen = 512
)

// ErrBusy: all hash slots are taken – the client should retry shortly.
var ErrBusy = errors.New("the server is busy – try again in a moment")

// Hasher hashes and checks passwords with a bounded number of parallel runs.
type Hasher struct {
	params Params
	slots  chan struct{}
	wait   time.Duration
	rand   io.Reader

	dummyOnce sync.Once
	dummy     string
	dummyErr  error
}

// NewHasher returns a hasher with at most parallel concurrent runs.
func NewHasher(p Params, parallel int, wait time.Duration) *Hasher {
	return &Hasher{params: p, slots: make(chan struct{}, max(parallel, 1)), wait: wait, rand: rand.Reader}
}

func (h *Hasher) acquire(ctx context.Context) error {
	timer := time.NewTimer(h.wait)
	defer timer.Stop()
	select {
	case h.slots <- struct{}{}:
		return nil
	case <-timer.C:
		return ErrBusy
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (h *Hasher) release() { <-h.slots }

// Hash returns the PHC string of password with the hasher's parameters.
func (h *Hasher) Hash(ctx context.Context, password string) (string, error) {
	salt, err := randomBytes(h.rand, saltSize)
	if err != nil {
		return "", err
	}
	if err := h.acquire(ctx); err != nil {
		return "", err
	}
	defer h.release()
	return encodePHC(h.params, salt, h.derive([]byte(password), salt, h.params)), nil
}

// Verify checks password against encoded. rehash reports that the hash uses
// other parameters than the current defaults.
func (h *Hasher) Verify(ctx context.Context, encoded, password string) (ok, rehash bool, err error) {
	p, salt, want, err := decodePHC(encoded)
	if err != nil {
		return false, false, err
	}
	if err := h.acquire(ctx); err != nil {
		return false, false, err
	}
	defer h.release()
	got := h.derive([]byte(password), salt, p)
	return subtle.ConstantTimeCompare(got, want) == 1, p != h.params, nil
}

// VerifyDummy costs as much as a real check. It runs for unknown user names,
// so the response time doesn't tell whether a name exists.
func (h *Hasher) VerifyDummy(ctx context.Context, password string) error {
	h.dummyOnce.Do(func() {
		h.dummy, h.dummyErr = h.Hash(ctx, "dummy password for unknown users")
	})
	if h.dummyErr != nil {
		return h.dummyErr
	}
	_, _, err := h.Verify(ctx, h.dummy, password)
	return err
}

func (h *Hasher) derive(password, salt []byte, p Params) []byte {
	return argon2.IDKey(password, salt, p.Time, p.MemoryKiB, p.Threads, hashSize)
}

func encodePHC(p Params, salt, hash []byte) string {
	b64 := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, p.MemoryKiB, p.Time, p.Threads, b64.EncodeToString(salt), b64.EncodeToString(hash))
}

// errBadHash: a stored hash that is not ours or has absurd parameters – a
// tampered row must not make the server spend gigabytes on one login.
var errBadHash = errors.New("stored password hash is malformed")

func decodePHC(s string) (Params, []byte, []byte, error) {
	var p Params
	parts := strings.Split(s, "$")
	if len(s) > maxPHCLen || len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != fmt.Sprintf("v=%d", argon2.Version) {
		return p, nil, nil, errBadHash
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.MemoryKiB, &p.Time, &p.Threads); err != nil {
		return p, nil, nil, errBadHash
	}
	if p.MemoryKiB < 8*1024 || p.MemoryKiB > 1024*1024 || p.Time < 1 || p.Time > 16 || p.Threads < 1 || p.Threads > 16 {
		return p, nil, nil, errBadHash
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) < 8 || len(salt) > 64 {
		return p, nil, nil, errBadHash
	}
	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(hash) < 16 || len(hash) > 64 {
		return p, nil, nil, errBadHash
	}
	return p, salt, hash, nil
}

func randomBytes(rnd io.Reader, n int) ([]byte, error) {
	if rnd == nil {
		rnd = rand.Reader
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(rnd, b); err != nil {
		return nil, fmt.Errorf("random: %w", err)
	}
	return b, nil
}
