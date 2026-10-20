// Package pkcs12 writes PKCS#12 files (RFC 7292) for the key export
// (PHASE1 step 18): the private key in a PBES2-encrypted bag (PBKDF2 with
// HMAC-SHA256, AES-256-CBC), the certificates in a plain bag, and an
// HMAC-SHA256 integrity MAC – what OpenSSL 3 writes by default and what
// Windows 10 (1709+), macOS, Java and OpenSSL import. Only encoding: the
// server never reads PKCS#12 files.
package pkcs12

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- only the localKeyId attribute (an identifier, RFC 7292 convention), no security
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"unicode/utf16"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// Iterations of PBKDF2 for the key and of the PKCS#12 KDF for the MAC.
// OWASP 2023 recommends 600,000 for PBKDF2-HMAC-SHA256.
const (
	KeyIterations = 600_000
	MACIterations = 2048 // the PKCS#12 KDF runs SHA-256 this often; OpenSSL's default
	MinPassword   = 12
)

var (
	oidData               = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidCertBag            = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 3}
	oidShroudedKeyBag     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 2}
	oidX509Certificate    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 22, 1}
	oidFriendlyName       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 20}
	oidLocalKeyID         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 21}
	oidPBES2              = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2             = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidHMACWithSHA256     = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidAES256CBC          = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
	oidSHA256             = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	errPasswordTooShort   = fmt.Errorf("the PKCS#12 password needs at least %d characters", MinPassword)
	errPasswordTooLong    = errors.New("the PKCS#12 password is longer than 1024 bytes")
	errNoCertificateGiven = errors.New("no certificate")
)

// Encode builds a PKCS#12 file with the PKCS#8 key, its certificate first,
// then the chain (intermediates). name is the friendly name importers show.
// rnd nil means crypto/rand.
func Encode(rnd io.Reader, pkcs8 []byte, chain []*x509.Certificate, name, password string) ([]byte, error) {
	switch {
	case len([]rune(password)) < MinPassword:
		return nil, errPasswordTooShort
	case len(password) > 1024:
		return nil, errPasswordTooLong
	case len(chain) == 0:
		return nil, errNoCertificateGiven
	}
	if _, err := x509.ParsePKCS8PrivateKey(pkcs8); err != nil {
		return nil, fmt.Errorf("pkcs12: the key is not PKCS#8: %w", err)
	}
	if rnd == nil {
		rnd = rand.Reader
	}
	keyID := sha1.Sum(chain[0].Raw) // #nosec G401 -- localKeyId only names the pair (RFC 7292 convention)

	encKey, err := encryptKey(rnd, pkcs8, password)
	if err != nil {
		return nil, err
	}
	keyBag := bag(oidShroudedKeyBag, encKey, name, keyID[:])
	var certBags [][]byte
	for i, c := range chain {
		var cb cryptobyte.Builder
		cb.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(oidX509Certificate)
			b.AddASN1(cbasn1.Tag(0).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
				b.AddASN1OctetString(c.Raw)
			})
		})
		value := cb.BytesOrPanic()
		if i == 0 {
			certBags = append(certBags, bag(oidCertBag, value, name, keyID[:]))
		} else {
			certBags = append(certBags, bag(oidCertBag, value, "", nil))
		}
	}

	authSafe := sequence(
		dataContentInfo(sequence(certBags...)),
		dataContentInfo(sequence(keyBag)),
	)

	macSalt := make([]byte, 16)
	if _, err := io.ReadFull(rnd, macSalt); err != nil {
		return nil, err
	}
	macKey := kdf(bmpString(password), macSalt, 3, MACIterations, 32)
	mac := hmac.New(sha256.New, macKey)
	mac.Write(authSafe)
	digest := mac.Sum(nil)

	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1Int64(3)
		b.AddBytes(dataContentInfo(authSafe))
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { // MacData
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { // DigestInfo
				b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
					b.AddASN1ObjectIdentifier(oidSHA256)
					b.AddASN1NULL()
				})
				b.AddASN1OctetString(digest)
			})
			b.AddASN1OctetString(macSalt)
			b.AddASN1Int64(MACIterations)
		})
	})
	return b.Bytes()
}

// bag is a SafeBag with friendlyName and localKeyId when given.
func bag(id asn1.ObjectIdentifier, value []byte, name string, keyID []byte) []byte {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1ObjectIdentifier(id)
		b.AddASN1(cbasn1.Tag(0).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
			b.AddBytes(value)
		})
		if name == "" && keyID == nil {
			return
		}
		b.AddASN1(cbasn1.SET, func(b *cryptobyte.Builder) {
			if name != "" {
				b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
					b.AddASN1ObjectIdentifier(oidFriendlyName)
					b.AddASN1(cbasn1.SET, func(b *cryptobyte.Builder) {
						b.AddASN1(cbasn1.Tag(30), func(b *cryptobyte.Builder) { // BMPString
							b.AddBytes(bmpString(name)[:len(bmpString(name))-2])
						})
					})
				})
			}
			if keyID != nil {
				b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
					b.AddASN1ObjectIdentifier(oidLocalKeyID)
					b.AddASN1(cbasn1.SET, func(b *cryptobyte.Builder) {
						b.AddASN1OctetString(keyID)
					})
				})
			}
		})
	})
	return b.BytesOrPanic()
}

// sequence wraps already encoded elements into a SEQUENCE.
func sequence(elems ...[]byte) []byte {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		for _, e := range elems {
			b.AddBytes(e)
		}
	})
	return b.BytesOrPanic()
}

// dataContentInfo is ContentInfo { id-data, [0] OCTET STRING content }.
func dataContentInfo(content []byte) []byte {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1ObjectIdentifier(oidData)
		b.AddASN1(cbasn1.Tag(0).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
			b.AddASN1OctetString(content)
		})
	})
	return b.BytesOrPanic()
}

// encryptKey is an EncryptedPrivateKeyInfo with PBES2: PBKDF2-HMAC-SHA256
// and AES-256-CBC; the password as UTF-8 bytes (as OpenSSL does for PBES2).
func encryptKey(rnd io.Reader, pkcs8 []byte, password string) ([]byte, error) {
	salt, iv := make([]byte, 16), make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rnd, salt); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(rnd, iv); err != nil {
		return nil, err
	}
	key, err := pbkdf2.Key(sha256.New, password, salt, KeyIterations, 32)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	pad := aes.BlockSize - len(pkcs8)%aes.BlockSize
	plain := make([]byte, len(pkcs8)+pad)
	copy(plain, pkcs8)
	for i := len(pkcs8); i < len(plain); i++ {
		plain[i] = byte(pad)
	}
	defer clear(plain)
	ct := make([]byte, len(plain))
	cipher.NewCBCEncrypter(blk, iv).CryptBlocks(ct, plain)

	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { // AlgorithmIdentifier PBES2
			b.AddASN1ObjectIdentifier(oidPBES2)
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { // PBES2-params
				b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
					b.AddASN1ObjectIdentifier(oidPBKDF2)
					b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
						b.AddASN1OctetString(salt)
						b.AddASN1Int64(KeyIterations)
						b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
							b.AddASN1ObjectIdentifier(oidHMACWithSHA256)
							b.AddASN1NULL()
						})
					})
				})
				b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
					b.AddASN1ObjectIdentifier(oidAES256CBC)
					b.AddASN1OctetString(iv)
				})
			})
		})
		b.AddASN1OctetString(ct)
	})
	return b.Bytes()
}

// bmpString is the password as RFC 7292 wants it for the MAC key: UTF-16
// big endian with two zero bytes at the end.
func bmpString(s string) []byte {
	units := utf16.Encode([]rune(s))
	out := make([]byte, 0, 2*len(units)+2)
	for _, u := range units {
		out = append(out, byte(u>>8), byte(u)) // #nosec G115 -- the two bytes of a UTF-16 unit
	}
	return append(out, 0, 0)
}

// kdf is the PKCS#12 key derivation (RFC 7292 appendix B.2) with SHA-256:
// id 1 = key, 2 = IV, 3 = MAC key.
func kdf(password, salt []byte, id byte, iterations, n int) []byte {
	const v = 64 // SHA-256 block size
	fill := func(src []byte) []byte {
		if len(src) == 0 {
			return nil
		}
		out := make([]byte, v*((len(src)+v-1)/v))
		for i := range out {
			out[i] = src[i%len(src)]
		}
		return out
	}
	d := make([]byte, v)
	for i := range d {
		d[i] = id
	}
	in := append(fill(salt), fill(password)...)
	var out []byte
	for len(out) < n {
		h := sha256.New()
		h.Write(d)
		h.Write(in)
		a := h.Sum(nil)
		for range iterations - 1 {
			s := sha256.Sum256(a)
			a = s[:]
		}
		out = append(out, a...)
		if len(out) >= n {
			break
		}
		// I_j = (I_j + B + 1) mod 2^(v*8) for every block, B = a repeated.
		b := fill(a)[:v]
		for j := 0; j < len(in); j += v {
			carry := 1
			for k := v - 1; k >= 0; k-- {
				sum := int(in[j+k]) + int(b[k]) + carry
				in[j+k] = byte(sum) // #nosec G115 -- the low byte; the carry goes on
				carry = sum >> 8
			}
		}
	}
	return out[:n]
}
