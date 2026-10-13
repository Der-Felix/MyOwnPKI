package keys

import (
	"context"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/clock"
	"github.com/Der-Felix/MyOwnPKI/internal/store"
	"github.com/Der-Felix/MyOwnPKI/internal/store/systemdb"
)

// Errors. ErrWrongSecret is deliberately the same for passphrase and
// recovery key and says nothing about why.
var (
	ErrSealed             = errors.New("the server is sealed – unseal it first")
	ErrAlreadyUnsealed    = errors.New("the server is already unsealed")
	ErrNotInitialized     = errors.New("no root key yet – run myownpki init")
	ErrAlreadyInitialized = errors.New("the root key exists already")
	ErrWrongSecret        = errors.New("wrong passphrase or recovery key")
	ErrWeakPassphrase     = errors.New("the passphrase must have at least 16 characters")
	ErrLocked             = errors.New("too many failed attempts")
)

// LockedError carries how long the caller must wait (HTTP 429 Retry-After).
type LockedError struct{ RetryAfter time.Duration }

func (e *LockedError) Error() string {
	return fmt.Sprintf("%v – try again in %v", ErrLocked, e.RetryAfter.Round(time.Second))
}

func (e *LockedError) Unwrap() error { return ErrLocked }

const (
	slotPassphrase = "passphrase"
	slotRecovery   = "recovery"

	minPassphraseRunes = 16
	maxPassphraseBytes = 1024
)

// Who identifies the person or process behind an operation, for the audit log.
type Who struct {
	Actor    audit.Actor
	SourceIP string
}

// Keyring holds the root key while the server is unsealed.
type Keyring struct {
	system *sql.DB // writer of system.db (unseal slots, outbox)
	audit  *sql.DB // writer of the instance audit log (direct entries)
	clock  clock.Clock
	rand   io.Reader
	params argon2Params
	// Wake, if set, is called after an audit event was written to the
	// outbox, so the deliverer picks it up at once.
	Wake func()
	// OnUnseal and BeforeSeal, if set, run right after an unseal and right
	// before a seal – the server makes audit checkpoints there (step 6a).
	OnUnseal, BeforeSeal func(context.Context)

	mu          sync.RWMutex // read: signing in progress; write: unseal, seal
	root        []byte       // nil = sealed
	rootVersion int64
	sealedSince time.Time

	attempt sync.Mutex // one secret check at a time: each Argon2id run takes 256 MiB
	lim     limiter
}

// New returns a sealed keyring. system and auditLog are the writers of
// system.db and of the instance audit log (<data>/audit.db).
func New(system, auditLog *sql.DB, clk clock.Clock) *Keyring {
	return &Keyring{system: system, audit: auditLog, clock: clk, rand: defaultRand, params: defaultArgon2, sealedSince: clk.Now()}
}

// Status is the seal state.
type Status struct {
	Sealed      bool
	SealedSince time.Time // when Sealed: since start or the last seal
}

// Status reports whether the keyring is sealed.
func (k *Keyring) Status() Status {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return Status{Sealed: k.root == nil, SealedSince: k.sealedSince}
}

// Initialized reports whether a root key exists.
func (k *Keyring) Initialized(ctx context.Context) (bool, error) {
	n, err := systemdb.New(k.system).CountUnsealSlots(ctx)
	return n > 0, err
}

// CheckPassphrase applies the passphrase rules: at least 16 characters, at
// most 1024 bytes, valid UTF-8.
func CheckPassphrase(p []byte) error {
	if !utf8.Valid(p) || len(p) > maxPassphraseBytes || utf8.RuneCount(p) < minPassphraseRunes {
		return ErrWeakPassphrase
	}
	return nil
}

// HasNonASCII reports characters that may be typed differently on another
// keyboard or system; init warns about them.
func HasNonASCII(p []byte) bool {
	for _, c := range p {
		if c > 127 {
			return true
		}
	}
	return false
}

// Init creates the root key and stores it wrapped twice: with the passphrase
// and with the recovery key. The keyring stays sealed. passphrase is cleared.
// Create the recovery key with NewRecoveryKey and let the user confirm it
// before calling Init – nothing is stored before this call.
func (k *Keyring) Init(ctx context.Context, passphrase []byte, recovery RecoveryKey, who Who) error {
	defer clear(passphrase)
	if err := CheckPassphrase(passphrase); err != nil {
		return err
	}
	root, err := randomBytes(k.rand, keySize)
	if err != nil {
		return err
	}
	defer clear(root)
	pass, err := k.wrapWithPassphrase(passphrase, root, 1)
	if err != nil {
		return err
	}
	rec, err := k.wrapWithRecovery(recovery, root, 1)
	if err != nil {
		return err
	}
	return k.inSystemTx(ctx, func(q *systemdb.Queries, tx *sql.Tx, now string) error {
		n, err := q.CountUnsealSlots(ctx)
		if err != nil {
			return err
		}
		if n > 0 {
			return ErrAlreadyInitialized
		}
		for _, s := range []systemdb.InsertUnsealSlotParams{pass, rec} {
			s.CreatedAt, s.UpdatedAt = now, now
			if err := q.InsertUnsealSlot(ctx, s); err != nil {
				return err
			}
		}
		return k.enqueue(ctx, tx, who, "system.keys_init", nil)
	})
}

// Unseal derives the KEK from passphrase, unlocks the root key and keeps it
// in memory. passphrase is cleared.
func (k *Keyring) Unseal(ctx context.Context, passphrase []byte, who Who) error {
	defer clear(passphrase)
	return k.unseal(ctx, "system.unseal", who, func(ctx context.Context) ([]byte, int64, error) {
		return k.openSlotWithPassphrase(ctx, passphrase)
	})
}

// UnsealWithRecovery unlocks the root key with the recovery key.
func (k *Keyring) UnsealWithRecovery(ctx context.Context, recovery RecoveryKey, who Who) error {
	return k.unseal(ctx, "system.unseal_recovery", who, func(ctx context.Context) ([]byte, int64, error) {
		return k.openSlotWithRecovery(ctx, recovery)
	})
}

func (k *Keyring) unseal(ctx context.Context, action string, who Who, open func(context.Context) ([]byte, int64, error)) error {
	k.attempt.Lock()
	defer k.attempt.Unlock()
	if !k.Status().Sealed {
		return ErrAlreadyUnsealed
	}
	root, version, err := k.checkSecret(ctx, action, who, open)
	if err != nil {
		return err
	}
	k.mu.Lock()
	k.root, k.rootVersion = root, version
	k.mu.Unlock()
	if err := k.direct(ctx, who, action, audit.ResultSuccess, nil); err != nil {
		return err
	}
	if k.OnUnseal != nil {
		k.OnUnseal(ctx)
	}
	return nil
}

// checkSecret runs open under the rate limit and audits failures. The caller
// holds k.attempt.
func (k *Keyring) checkSecret(ctx context.Context, action string, who Who, open func(context.Context) ([]byte, int64, error)) ([]byte, int64, error) {
	now := k.clock.Now()
	if wait := k.lim.wait(now); wait > 0 {
		_ = k.direct(ctx, who, action, audit.ResultDenied, map[string]any{"reason": "locked", "retry_after_s": int(wait.Seconds())})
		return nil, 0, &LockedError{RetryAfter: wait}
	}
	root, version, err := open(ctx)
	if errors.Is(err, ErrDecrypt) {
		k.lim.failure(now)
		if aerr := k.direct(ctx, who, action, audit.ResultFailure, nil); aerr != nil {
			return nil, 0, errors.Join(ErrWrongSecret, aerr)
		}
		return nil, 0, ErrWrongSecret
	}
	if err != nil {
		return nil, 0, err
	}
	k.lim.success()
	return root, version, nil
}

// Seal removes the root key from memory. It waits for running signing
// operations to finish. Sealing a sealed keyring does nothing.
func (k *Keyring) Seal(ctx context.Context, who Who) error {
	if k.Status().Sealed {
		return nil
	}
	if k.BeforeSeal != nil {
		k.BeforeSeal(ctx) // last checkpoint while the key is still here
	}
	k.mu.Lock()
	if k.root == nil {
		k.mu.Unlock()
		return nil
	}
	clear(k.root)
	k.root, k.sealedSince = nil, k.clock.Now()
	k.mu.Unlock()
	return k.direct(ctx, who, "system.seal", audit.ResultSuccess, nil)
}

// ChangePassphrase rewraps the root key with a new passphrase (new salt,
// current Argon2id defaults). Requires the unsealed keyring and the current
// passphrase. Both passphrases are cleared.
func (k *Keyring) ChangePassphrase(ctx context.Context, current, next []byte, who Who) error {
	defer clear(current)
	defer clear(next)
	const action = "system.passphrase_change"
	if err := CheckPassphrase(next); err != nil {
		return err
	}
	k.attempt.Lock()
	defer k.attempt.Unlock()
	if k.Status().Sealed {
		return ErrSealed
	}
	root, version, err := k.checkSecret(ctx, action, who, func(ctx context.Context) ([]byte, int64, error) {
		return k.openSlotWithPassphrase(ctx, current)
	})
	if err != nil {
		return err
	}
	defer clear(root)
	slot, err := k.wrapWithPassphrase(next, root, version)
	if err != nil {
		return err
	}
	return k.updateSlot(ctx, slot, who, action)
}

// ResetPassphrase sets a new passphrase with the recovery key – for when the
// passphrase is lost. Works sealed or unsealed and doesn't change the state.
func (k *Keyring) ResetPassphrase(ctx context.Context, recovery RecoveryKey, next []byte, who Who) error {
	defer clear(next)
	const action = "system.passphrase_reset"
	if err := CheckPassphrase(next); err != nil {
		return err
	}
	k.attempt.Lock()
	defer k.attempt.Unlock()
	root, version, err := k.checkSecret(ctx, action, who, func(ctx context.Context) ([]byte, int64, error) {
		return k.openSlotWithRecovery(ctx, recovery)
	})
	if err != nil {
		return err
	}
	defer clear(root)
	slot, err := k.wrapWithPassphrase(next, root, version)
	if err != nil {
		return err
	}
	return k.updateSlot(ctx, slot, who, action)
}

// RotateRecoveryKey replaces the recovery key; the old one stops working
// (except for backups taken before). Requires the unsealed keyring and the
// passphrase. Create next with NewRecoveryKey and let the user confirm it
// before calling.
func (k *Keyring) RotateRecoveryKey(ctx context.Context, passphrase []byte, next RecoveryKey, who Who) error {
	defer clear(passphrase)
	const action = "system.recovery_key_rotate"
	k.attempt.Lock()
	defer k.attempt.Unlock()
	if k.Status().Sealed {
		return ErrSealed
	}
	root, version, err := k.checkSecret(ctx, action, who, func(ctx context.Context) ([]byte, int64, error) {
		return k.openSlotWithPassphrase(ctx, passphrase)
	})
	if err != nil {
		return err
	}
	defer clear(root)
	slot, err := k.wrapWithRecovery(next, root, version)
	if err != nil {
		return err
	}
	return k.updateSlot(ctx, slot, who, action)
}

func (k *Keyring) updateSlot(ctx context.Context, s systemdb.InsertUnsealSlotParams, who Who, action string) error {
	return k.inSystemTx(ctx, func(q *systemdb.Queries, tx *sql.Tx, now string) error {
		n, err := q.UpdateUnsealSlot(ctx, systemdb.UpdateUnsealSlotParams{
			Kdf: s.Kdf, KdfParams: s.KdfParams, Salt: s.Salt, WrappedRootKey: s.WrappedRootKey,
			UpdatedAt: now, Slot: s.Slot, RootKeyVersion: s.RootKeyVersion,
		})
		if err != nil {
			return err
		}
		if n != 1 {
			return fmt.Errorf("unseal slot %s: %d rows updated", s.Slot, n)
		}
		return k.enqueue(ctx, tx, who, action, nil)
	})
}

func (k *Keyring) wrapWithPassphrase(passphrase, root []byte, version int64) (systemdb.InsertUnsealSlotParams, error) {
	salt, err := randomBytes(k.rand, keySize)
	if err != nil {
		return systemdb.InsertUnsealSlotParams{}, err
	}
	kek := passphraseKEK(passphrase, salt, k.params)
	defer clear(kek)
	wrapped, err := sealAEAD(k.rand, kek, root, aadRootKey(slotPassphrase, version))
	return systemdb.InsertUnsealSlotParams{
		Slot: slotPassphrase, RootKeyVersion: version, Kdf: "argon2id", KdfParams: k.params.json(), Salt: salt, WrappedRootKey: wrapped,
	}, err
}

func (k *Keyring) wrapWithRecovery(recovery RecoveryKey, root []byte, version int64) (systemdb.InsertUnsealSlotParams, error) {
	salt, err := randomBytes(k.rand, keySize)
	if err != nil {
		return systemdb.InsertUnsealSlotParams{}, err
	}
	kek, err := recoveryKEK(recovery, salt)
	if err != nil {
		return systemdb.InsertUnsealSlotParams{}, err
	}
	defer clear(kek)
	wrapped, err := sealAEAD(k.rand, kek, root, aadRootKey(slotRecovery, version))
	return systemdb.InsertUnsealSlotParams{
		Slot: slotRecovery, RootKeyVersion: version, Kdf: "hkdf-sha256", KdfParams: "{}", Salt: salt, WrappedRootKey: wrapped,
	}, err
}

func (k *Keyring) slot(ctx context.Context, name string) (systemdb.Unseal, error) {
	s, err := systemdb.New(k.system).GetUnsealSlot(ctx, name)
	if errors.Is(err, sql.ErrNoRows) {
		return s, ErrNotInitialized
	}
	return s, err
}

func (k *Keyring) openSlotWithPassphrase(ctx context.Context, passphrase []byte) ([]byte, int64, error) {
	s, err := k.slot(ctx, slotPassphrase)
	if err != nil {
		return nil, 0, err
	}
	params, err := parseArgon2Params(s.KdfParams)
	if err != nil {
		return nil, 0, err
	}
	kek := passphraseKEK(passphrase, s.Salt, params)
	defer clear(kek)
	root, err := openAEAD(kek, s.WrappedRootKey, aadRootKey(slotPassphrase, s.RootKeyVersion))
	return root, s.RootKeyVersion, err
}

func (k *Keyring) openSlotWithRecovery(ctx context.Context, recovery RecoveryKey) ([]byte, int64, error) {
	s, err := k.slot(ctx, slotRecovery)
	if err != nil {
		return nil, 0, err
	}
	kek, err := recoveryKEK(recovery, s.Salt)
	if err != nil {
		return nil, 0, err
	}
	defer clear(kek)
	root, err := openAEAD(kek, s.WrappedRootKey, aadRootKey(slotRecovery, s.RootKeyVersion))
	return root, s.RootKeyVersion, err
}

// inSystemTx runs fn in one system.db transaction and wakes the deliverer.
func (k *Keyring) inSystemTx(ctx context.Context, fn func(q *systemdb.Queries, tx *sql.Tx, now string) error) (err error) {
	tx, err := k.system.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	if err = fn(systemdb.New(tx), tx, k.clock.Now().UTC().Format(audit.TimeFormat)); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	if k.Wake != nil {
		k.Wake()
	}
	return nil
}

func (k *Keyring) entry(who Who, action string, result audit.Result, details map[string]any) audit.Entry {
	return audit.Entry{
		Time: k.clock.Now(), Actor: who.Actor, Action: action,
		Target: audit.Target{Type: "instance", ID: store.InstanceScope}, Result: result, SourceIP: who.SourceIP, Details: details,
	}
}

// enqueue writes the audit event of a system.db change into its outbox.
func (k *Keyring) enqueue(ctx context.Context, tx *sql.Tx, who Who, action string, details map[string]any) error {
	return audit.Enqueue(ctx, tx, k.clock.Now(), k.entry(who, action, audit.ResultSuccess, details))
}

// direct appends an event without a database change (unseal attempts, seal).
func (k *Keyring) direct(ctx context.Context, who Who, action string, result audit.Result, details map[string]any) error {
	_, _, err := audit.Append(ctx, k.audit, store.InstanceScope, k.entry(who, action, result, details), "")
	return err
}

// limiter slows down guessing: three failures in a row are free (each costs
// an Argon2id run anyway), then 1 minute, doubling up to 1 hour. It lives in
// memory; a restart needs access to the host.
type limiter struct {
	fails int
	until time.Time
}

const (
	freeFailures = 3
	firstLock    = time.Minute
	maxLock      = time.Hour
)

func (l *limiter) wait(now time.Time) time.Duration {
	if now.Before(l.until) {
		return l.until.Sub(now)
	}
	return 0
}

func (l *limiter) failure(now time.Time) {
	l.fails++
	if l.fails < freeFailures {
		return
	}
	d := maxLock
	if shift := l.fails - freeFailures; shift < 7 {
		d = min(firstLock<<shift, maxLock)
	}
	l.until = now.Add(d)
}

func (l *limiter) success() { *l = limiter{} }

// SignCheckpoint signs an audit checkpoint (PHASE1 step 6a) with an Ed25519
// key derived from the root key. The key exists only for this call; sealed,
// it fails with an error that wraps audit.ErrNoSigner.
func (k *Keyring) SignCheckpoint(msg []byte) ([]byte, ed25519.PublicKey, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.root == nil {
		return nil, nil, fmt.Errorf("%w (%w)", ErrSealed, audit.ErrNoSigner)
	}
	priv, err := k.checkpointKey()
	if err != nil {
		return nil, nil, err
	}
	defer clear(priv)
	pub := make(ed25519.PublicKey, ed25519.PublicKeySize)
	copy(pub, priv[ed25519.SeedSize:])
	return ed25519.Sign(priv, msg), pub, nil
}

// CheckpointKeyFingerprint is the fingerprint of the checkpoint key to note
// down (shown by init, logged at unseal; `audit verify --checkpoint-key`).
func (k *Keyring) CheckpointKeyFingerprint() (string, error) {
	_, pub, err := k.SignCheckpoint(nil)
	if err != nil {
		return "", err
	}
	return audit.KeyFingerprint(pub), nil
}

func (k *Keyring) checkpointKey() (ed25519.PrivateKey, error) {
	seed, err := hkdf.Key(sha256.New, k.root, nil, "myownpki/v1/audit-checkpoint-ed25519", ed25519.SeedSize)
	if err != nil {
		return nil, err
	}
	defer clear(seed)
	return ed25519.NewKeyFromSeed(seed), nil
}
