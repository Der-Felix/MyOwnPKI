package keys

import (
	"context"
	"crypto"
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"

	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
)

// Key purposes (keys.purpose in pki.db).
const (
	PurposeCA   = "ca"
	PurposeLeaf = "leaf"
)

// Envelope is an encrypted private key as stored in pki.db.
type Envelope struct {
	RootKeyVersion int64
	WrappedDEK     []byte // DEK encrypted with the root key
	Ciphertext     []byte // PKCS#8 encrypted with the DEK
}

// EncryptKey encrypts a PKCS#8 private key with a fresh DEK. keyID, purpose
// and algorithm are bound into the ciphertext: the same bytes in another row
// won't decrypt. The caller should clear pkcs8 afterwards.
func (k *Keyring) EncryptKey(keyID, purpose, algorithm string, pkcs8 []byte) (Envelope, error) {
	if purpose != PurposeCA && purpose != PurposeLeaf {
		return Envelope{}, fmt.Errorf("unknown key purpose %q", purpose)
	}
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.root == nil {
		return Envelope{}, ErrSealed
	}
	dek, err := randomBytes(k.rand, keySize)
	if err != nil {
		return Envelope{}, err
	}
	defer clear(dek)
	ciphertext, err := sealAEAD(k.rand, dek, pkcs8, aadPrivateKey(keyID, purpose, algorithm))
	if err != nil {
		return Envelope{}, err
	}
	wrapped, err := sealAEAD(k.rand, k.root, dek, aadDEK(keyID, k.rootVersion))
	if err != nil {
		return Envelope{}, err
	}
	return Envelope{RootKeyVersion: k.rootVersion, WrappedDEK: wrapped, Ciphertext: ciphertext}, nil
}

// WithKey decrypts the private key for the duration of fn and clears it
// afterwards. Seal waits until fn returns. fn must not keep pkcs8.
func (k *Keyring) WithKey(keyID, purpose, algorithm string, env Envelope, fn func(pkcs8 []byte) error) error {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.root == nil {
		return ErrSealed
	}
	if env.RootKeyVersion != k.rootVersion {
		return fmt.Errorf("key %s: wrapped with root key version %d, unsealed version is %d", keyID, env.RootKeyVersion, k.rootVersion)
	}
	dek, err := openAEAD(k.root, env.WrappedDEK, aadDEK(keyID, env.RootKeyVersion))
	if err != nil {
		return fmt.Errorf("key %s: %w", keyID, err)
	}
	defer clear(dek)
	pkcs8, err := openAEAD(dek, env.Ciphertext, aadPrivateKey(keyID, purpose, algorithm))
	if err != nil {
		return fmt.Errorf("key %s: %w", keyID, err)
	}
	defer clear(pkcs8)
	return fn(pkcs8)
}

// WithSigner is WithKey for signing: fn gets the parsed key. Go can't clear
// the parsed key's big numbers; the object is dropped when fn returns.
func (k *Keyring) WithSigner(keyID, purpose, algorithm string, env Envelope, fn func(crypto.Signer) error) error {
	return k.WithKey(keyID, purpose, algorithm, env, func(pkcs8 []byte) error {
		key, err := x509.ParsePKCS8PrivateKey(pkcs8)
		if err != nil {
			return fmt.Errorf("key %s: not a PKCS#8 private key", keyID)
		}
		signer, ok := key.(crypto.Signer)
		if !ok {
			return fmt.Errorf("key %s: %T can't sign", keyID, key)
		}
		return fn(signer)
	})
}

// StoredKey is a row of pki.db keys.
type StoredKey struct {
	ID, Purpose, Algorithm string
	Envelope               Envelope
}

// SaveKey stores an envelope key in pki.db. Pass the transaction that also
// stores the certificate, so key and certificate exist together or not at all.
func SaveKey(ctx context.Context, q pkidb.DBTX, key StoredKey, now string) error {
	return pkidb.New(q).InsertEnvelopeKey(ctx, pkidb.InsertEnvelopeKeyParams{
		ID: key.ID, Purpose: key.Purpose, Algorithm: key.Algorithm,
		RootKeyVersion: sql.NullInt64{Int64: key.Envelope.RootKeyVersion, Valid: true},
		WrappedDek:     key.Envelope.WrappedDEK, KeyCiphertext: key.Envelope.Ciphertext, CreatedAt: now,
	})
}

// ErrKeyDestroyed: the key was destroyed after its download (step 18).
var ErrKeyDestroyed = errors.New("the key was deleted from the server")

// ErrNoSuchKey means there is no key with that ID.
var ErrNoSuchKey = errors.New("no such key")

// LoadKey reads an envelope key from pki.db.
func LoadKey(ctx context.Context, q pkidb.DBTX, id string) (StoredKey, error) {
	row, err := pkidb.New(q).GetKey(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return StoredKey{}, fmt.Errorf("%w: %s", ErrNoSuchKey, id)
	}
	if err != nil {
		return StoredKey{}, err
	}
	if row.DestroyedAt.Valid {
		return StoredKey{}, fmt.Errorf("%w: %s (on %s)", ErrKeyDestroyed, id, row.DestroyedAt.String)
	}
	if row.Storage != "envelope" {
		return StoredKey{}, fmt.Errorf("key %s: storage %q is not supported in this build", id, row.Storage)
	}
	return StoredKey{
		ID: row.ID, Purpose: row.Purpose, Algorithm: row.Algorithm,
		Envelope: Envelope{RootKeyVersion: row.RootKeyVersion.Int64, WrappedDEK: row.WrappedDek, Ciphertext: row.KeyCiphertext},
	}, nil
}
