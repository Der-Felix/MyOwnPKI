package legacy

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/sha1" // #nosec G505 -- PBKDF2 with HMAC-SHA1 is the PKCS#5 default PRF; only for reading old key files
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
)

// Private keys of pki.sh come from `openssl genpkey`: PKCS#8, optionally
// encrypted with PBES2 (PBKDF2 + AES-CBC, RFC 8018) – `-aes-256-cbc`. The
// standard library parses PKCS#8 but doesn't decrypt it; this does, for the
// schemes OpenSSL writes. Nothing else (scrypt, DES, RC2) is accepted.

// ErrWrongPassphrase: the key is encrypted and the passphrase doesn't open it.
var ErrWrongPassphrase = errors.New("the passphrase doesn't open the key")

// errNoPassphrase: the key is encrypted and no passphrase was given.
var errNoPassphrase = errors.New("the key is encrypted and no passphrase was given")

var (
	oidPBES2      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidHMACSHA1   = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 7}
	oidHMACSHA224 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 8}
	oidHMACSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidHMACSHA384 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 10}
	oidHMACSHA512 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 11}
	oidAES128CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
	oidAES192CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 22}
	oidAES256CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
)

// maxIterations bounds the work an imported file can ask for.
const maxIterations = 10_000_000

type encryptedPrivateKeyInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	Data      []byte
}

type pbes2Params struct {
	KDF    pkix.AlgorithmIdentifier
	Scheme pkix.AlgorithmIdentifier
}

type pbkdf2Params struct {
	Salt       []byte
	Iterations int
	KeyLength  int                      `asn1:"optional"`
	PRF        pkix.AlgorithmIdentifier `asn1:"optional"`
}

// parsePrivateKey reads one PEM private key; passphrase opens an encrypted
// one. It reports whether the file was encrypted.
func parsePrivateKey(data, passphrase []byte) (crypto.Signer, bool, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, false, errors.New("no PEM private key found")
	}
	var der []byte
	switch block.Type {
	case "PRIVATE KEY":
		der = block.Bytes
	case "ENCRYPTED PRIVATE KEY":
		if len(passphrase) == 0 {
			return nil, true, errNoPassphrase
		}
		var err error
		if der, err = decryptPKCS8(block.Bytes, passphrase); err != nil {
			return nil, true, err
		}
		defer clear(der)
	case "RSA PRIVATE KEY", "EC PRIVATE KEY":
		if _, encrypted := block.Headers["DEK-Info"]; encrypted {
			return nil, true, errors.New("the key uses the old OpenSSL PEM encryption – convert it first: openssl pkey -in key.pem -out key-pkcs8.pem (then encrypt it again with -aes-256-cbc if you like)")
		}
		var key any
		var err error
		if block.Type == "RSA PRIVATE KEY" {
			key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		} else {
			key, err = x509.ParseECPrivateKey(block.Bytes)
		}
		if err != nil {
			return nil, false, fmt.Errorf("the key can't be parsed: %w", err)
		}
		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, false, fmt.Errorf("key type %T can't sign", key)
		}
		return signer, false, nil
	default:
		return nil, false, fmt.Errorf("PEM block %q is not a private key", clip(block.Type, 40))
	}
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		if block.Type == "ENCRYPTED PRIVATE KEY" {
			return nil, true, ErrWrongPassphrase
		}
		return nil, false, fmt.Errorf("the key can't be parsed: %w", err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, block.Type == "ENCRYPTED PRIVATE KEY", fmt.Errorf("key type %T can't sign", key)
	}
	return signer, block.Type == "ENCRYPTED PRIVATE KEY", nil
}

func decryptPKCS8(der, passphrase []byte) ([]byte, error) {
	var info encryptedPrivateKeyInfo
	if rest, err := asn1.Unmarshal(der, &info); err != nil || len(rest) > 0 {
		return nil, errors.New("the encrypted key can't be parsed")
	}
	if !info.Algorithm.Algorithm.Equal(oidPBES2) {
		return nil, fmt.Errorf("key encryption %v is not supported (only PBES2 with AES-CBC, as `openssl genpkey -aes-256-cbc` writes)", info.Algorithm.Algorithm)
	}
	var params pbes2Params
	if rest, err := asn1.Unmarshal(info.Algorithm.Parameters.FullBytes, &params); err != nil || len(rest) > 0 {
		return nil, errors.New("the PBES2 parameters can't be parsed")
	}
	if !params.KDF.Algorithm.Equal(oidPBKDF2) {
		return nil, fmt.Errorf("key derivation %v is not supported (only PBKDF2)", params.KDF.Algorithm)
	}
	var kdf pbkdf2Params
	if rest, err := asn1.Unmarshal(params.KDF.Parameters.FullBytes, &kdf); err != nil || len(rest) > 0 {
		return nil, errors.New("the PBKDF2 parameters can't be parsed")
	}
	if kdf.Iterations < 1 || kdf.Iterations > maxIterations {
		return nil, fmt.Errorf("PBKDF2 iteration count %d is out of range (1 to %d)", kdf.Iterations, maxIterations)
	}
	var prf func() hash.Hash
	switch a := kdf.PRF.Algorithm; {
	case len(a) == 0, a.Equal(oidHMACSHA1):
		prf = sha1.New
	case a.Equal(oidHMACSHA224):
		prf = sha256.New224
	case a.Equal(oidHMACSHA256):
		prf = sha256.New
	case a.Equal(oidHMACSHA384):
		prf = sha512.New384
	case a.Equal(oidHMACSHA512):
		prf = sha512.New
	default:
		return nil, fmt.Errorf("PBKDF2 function %v is not supported", a)
	}
	var keyLen int
	switch a := params.Scheme.Algorithm; {
	case a.Equal(oidAES128CBC):
		keyLen = 16
	case a.Equal(oidAES192CBC):
		keyLen = 24
	case a.Equal(oidAES256CBC):
		keyLen = 32
	default:
		return nil, fmt.Errorf("key cipher %v is not supported (only AES-CBC)", a)
	}
	if kdf.KeyLength != 0 && kdf.KeyLength != keyLen {
		return nil, errors.New("the PBKDF2 key length doesn't match the cipher")
	}
	var iv []byte
	if rest, err := asn1.Unmarshal(params.Scheme.Parameters.FullBytes, &iv); err != nil || len(rest) > 0 || len(iv) != aes.BlockSize {
		return nil, errors.New("the AES-CBC IV can't be parsed")
	}
	if len(info.Data) == 0 || len(info.Data)%aes.BlockSize != 0 {
		return nil, errors.New("the encrypted key has a broken length")
	}
	key, err := pbkdf2.Key(prf, string(passphrase), kdf.Salt, kdf.Iterations, keyLen)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	plain := make([]byte, len(info.Data))
	cipher.NewCBCDecrypter(blk, iv).CryptBlocks(plain, info.Data)
	pad := int(plain[len(plain)-1])
	if pad < 1 || pad > aes.BlockSize {
		clear(plain)
		return nil, ErrWrongPassphrase
	}
	want := make([]byte, pad)
	for i := range want {
		want[i] = byte(pad)
	}
	if subtle.ConstantTimeCompare(plain[len(plain)-pad:], want) != 1 {
		clear(plain)
		return nil, ErrWrongPassphrase
	}
	return plain[:len(plain)-pad], nil
}
