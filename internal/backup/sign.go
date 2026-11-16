package backup

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/Der-Felix/MyOwnPKI/internal/backup/backupkey"
)

// The signature of a backup (PHASE3 section 19.3, owner decision D1 of
// 2026-11-16). manifest.json lists the SHA-256 of every file, so whoever
// signs the manifest vouches for the whole backup. manifest.sig holds the
// algorithm, the public key and an Ed25519 signature over the exact bytes of
// manifest.json, with a context string in front so the key can never be made
// to sign anything else.
//
// A signature proves that the holder of the key made the backup. It says
// nothing about whose key it is until the operator compares the fingerprint
// with the one noted at init and passes it as --backup-key: somebody who can
// write the backup directory can also write a new key and a new signature.

// SignatureFile is written next to manifest.json in a backup of format 2.
const SignatureFile = "manifest.sig"

const (
	signatureFormat    = "myownpki-backup-signature/1"
	signatureAlgorithm = "ed25519"
	// signContext is put in front of the manifest bytes before they are signed.
	signContext = "myownpki-backup-manifest-v1\x00"
	// maxSignature bounds what is read as a signature file.
	maxSignature = 4 << 10
)

// Signature is the content of manifest.sig.
type Signature struct {
	Format    string `json:"format"`
	Algorithm string `json:"algorithm"`
	PublicKey string `json:"public_key"` // hex
	Signature string `json:"signature"`  // hex
}

// signedMessage is what is signed for the given manifest bytes.
func signedMessage(manifest []byte) []byte {
	return append([]byte(signContext), manifest...)
}

// signManifest returns the bytes of manifest.sig for these manifest bytes.
func signManifest(k *backupkey.Key, manifest []byte) ([]byte, error) {
	s := Signature{
		Format:    signatureFormat,
		Algorithm: signatureAlgorithm,
		PublicKey: hex.EncodeToString(k.Public()),
		Signature: hex.EncodeToString(k.Sign(signedMessage(manifest))),
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// ParseSignature reads manifest.sig: strict JSON, nothing after it, the one
// known algorithm, a public key and a signature of the right length. It does
// not check the signature.
func ParseSignature(data []byte) (pub ed25519.PublicKey, sig []byte, err error) {
	if len(data) > maxSignature {
		return nil, nil, fmt.Errorf("%s is larger than %d KiB", SignatureFile, maxSignature>>10)
	}
	var s Signature
	if derr := decodeStrict(data, &s); derr != nil {
		return nil, nil, fmt.Errorf("%s can't be read: %w", SignatureFile, derr)
	}
	if s.Format != signatureFormat {
		return nil, nil, fmt.Errorf("%s: format %q is not %q", SignatureFile, clip(s.Format), signatureFormat)
	}
	if s.Algorithm != signatureAlgorithm {
		return nil, nil, fmt.Errorf("%s: algorithm %q is not %q", SignatureFile, clip(s.Algorithm), signatureAlgorithm)
	}
	pub, err = hex.DecodeString(s.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, nil, fmt.Errorf("%s: the public key is not %d bytes of hex", SignatureFile, ed25519.PublicKeySize)
	}
	sig, err = hex.DecodeString(s.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, nil, fmt.Errorf("%s: the signature is not %d bytes of hex", SignatureFile, ed25519.SignatureSize)
	}
	return pub, sig, nil
}

// ErrBadSignature: the signature does not match the manifest bytes.
var ErrBadSignature = errors.New(SignatureFile + ": the signature does not match the manifest")

// verifySignature checks a manifest.sig against the exact manifest bytes and
// returns the public key that signed.
func verifySignature(sigFile, manifest []byte) (ed25519.PublicKey, error) {
	pub, sig, err := ParseSignature(sigFile)
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(pub, signedMessage(manifest), sig) {
		return nil, ErrBadSignature
	}
	return pub, nil
}

// decodeStrict decodes one JSON value into v: unknown members and anything
// after the value are errors.
func decodeStrict(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		// The text may carry a member name of the input: keep it short.
		return errors.New(clipN(err.Error(), 160))
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("there is more after the first JSON value")
	}
	return nil
}

// clip shortens attacker text that reaches an error message.
func clip(s string) string { return clipN(s, 40) }

func clipN(s string, limit int) string {
	if len(s) > limit {
		return s[:limit] + "…"
	}
	return s
}

// readSignature reads manifest.sig of a backup; nil, nil = there is none.
func readSignature(dir string) ([]byte, error) {
	path := filepath.Join(dir, SignatureFile)
	st, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", SignatureFile)
	}
	if st.Size() > maxSignature {
		return nil, fmt.Errorf("%s is larger than %d KiB", SignatureFile, maxSignature>>10)
	}
	return os.ReadFile(path) // #nosec G304 -- the signature of the backup to check
}

// Authenticity says what the signature of a checked backup proves.
type Authenticity string

const (
	// Unauthenticated: the backup has no signature (format 1, made before
	// 0.9.0, or accepted with --allow-unsigned). Nobody can tell whether it
	// was changed after it was made.
	Unauthenticated Authenticity = "unauthenticated"
	// Signed: a valid signature by a key nobody vouched for. Whoever wrote
	// the backup could have signed it with a key of his own.
	Signed Authenticity = "signed"
	// Pinned: a valid signature by the key the operator expects.
	Pinned Authenticity = "pinned"
)

// Check says how a backup is checked beyond its integrity.
type Check struct {
	// CheckpointKey is the checkpoint key fingerprint noted at init ("" = all
	// checkpoints must use the key the manifest names).
	CheckpointKey string
	// BackupKey is the fingerprint (at least 16 hex digits, "SHA256:" optional)
	// of the key that must have signed the backup. With it a backup without a
	// signature is refused, and so is one signed by another key.
	BackupKey string
	// AllowUnsigned accepts a backup of format 1 although BackupKey is set.
	// A format 2 backup without a valid signature is always refused.
	AllowUnsigned bool
}

// checkSignature decides what the manifest.sig of dir proves about raw, the
// exact bytes of manifest.json, and records it in r. pin is the normalized
// BackupKey.
func (r *Report) checkSignature(dir string, raw []byte, pin string, allowUnsigned bool) {
	switch r.Manifest.Format {
	case FormatUnsigned:
		// A stray manifest.sig is not looked at: the file walk reports it as
		// a file the manifest doesn't list.
		r.Authenticity = Unauthenticated
		if pin != "" && !allowUnsigned {
			r.problem("the backup has no signature (format 1, made before 0.9.0) but a backup key is pinned – nobody can tell whether it was changed; " +
				"restore it only if you trust where it came from, with --allow-unsigned")
			return
		}
		r.Notes = append(r.Notes, "unauthenticated – this backup has no signature (made before 0.9.0); nobody can tell whether it was changed after it was made")
	case Format:
		sig, err := readSignature(dir)
		switch {
		case err != nil:
			r.problem("%s: %v", SignatureFile, err)
			return
		case sig == nil:
			r.problem("%s is missing – a backup of format 2 is always signed, so the signature was deleted or the backup is damaged", SignatureFile)
			return
		}
		pub, err := verifySignature(sig, raw)
		if err != nil {
			r.problem("%v – the manifest was changed or the signature is damaged", err)
			return
		}
		r.SigningKey = backupkey.Fingerprint(pub)
		switch {
		case pin == "":
			r.Authenticity = Signed
			r.Notes = append(r.Notes, fmt.Sprintf("signed by key %s – compare it with the one noted at init (or at the first backup) and pass it as --backup-key; "+
				"without that, whoever could write this backup could have signed it with a key of his own", r.SigningKey))
		case !backupkey.Matches(r.SigningKey, pin):
			r.problem("signed by key %s, not by the expected key %s… – a forged backup looks like this; if the backup key of the instance was lost and made again since, pass the fingerprint you noted for that backup as --backup-key", r.SigningKey, pin)
		default:
			r.Authenticity = Pinned
		}
	}
}
