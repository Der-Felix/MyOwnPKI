// Package passkeytest is a virtual WebAuthn authenticator for tests (PHASE1
// step 17): it answers the options of navigator.credentials.create() and
// .get() the way a browser with a platform authenticator does – ECDSA P-256,
// attestation "none", user verification done. Tests only.
package passkeytest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
)

// Authenticator holds the passkeys it created.
type Authenticator struct {
	Origin string
	// UserVerified is the UV flag it reports (default true via New).
	UserVerified bool
	creds        map[string]*cred
}

type cred struct {
	key        *ecdsa.PrivateKey
	rpID       string
	userHandle []byte
	counter    uint32
}

// New returns an authenticator in a browser at origin.
func New(origin string) *Authenticator {
	return &Authenticator{Origin: origin, UserVerified: true, creds: map[string]*cred{}}
}

var b64 = base64.RawURLEncoding

// Create answers PublicKeyCredentialCreationOptions ({"publicKey": …}).
func (a *Authenticator) Create(options []byte) ([]byte, error) {
	var o struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
			RP        struct {
				ID string `json:"id"`
			} `json:"rp"`
			User struct {
				ID string `json:"id"`
			} `json:"user"`
			Exclude []struct {
				ID string `json:"id"`
			} `json:"excludeCredentials"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(options, &o); err != nil {
		return nil, err
	}
	for _, e := range o.PublicKey.Exclude {
		if _, ok := a.creds[e.ID]; ok {
			return nil, errors.New("InvalidStateError: this authenticator holds an excluded credential")
		}
	}
	user, err := b64.DecodeString(o.PublicKey.User.ID)
	if err != nil {
		return nil, fmt.Errorf("user id: %w", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	id := make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	c := &cred{key: key, rpID: o.PublicKey.RP.ID, userHandle: user}
	a.creds[b64.EncodeToString(id)] = c

	cdj := a.clientData("webauthn.create", o.PublicKey.Challenge)
	auth := c.authData(a.flags() | 0x40)
	auth = append(auth, make([]byte, 16)...)                    // AAGUID: zero for "none"
	auth = binary.BigEndian.AppendUint16(auth, uint16(len(id))) // #nosec G115 -- 32 bytes
	auth = append(auth, id...)
	auth = append(auth, coseKey(&key.PublicKey)...)
	att := cborMap(
		cborText("fmt"), cborText("none"),
		cborText("attStmt"), cborMap(),
		cborText("authData"), cborBytes(auth),
	)
	return json.Marshal(map[string]any{
		"id": b64.EncodeToString(id), "rawId": b64.EncodeToString(id), "type": "public-key",
		"authenticatorAttachment": "platform", "clientExtensionResults": map[string]any{},
		"response": map[string]any{
			"clientDataJSON": b64.EncodeToString(cdj), "attestationObject": b64.EncodeToString(att),
			"transports": []string{"internal"},
		},
	})
}

// Get answers PublicKeyCredentialRequestOptions with the first allowed
// credential it holds.
func (a *Authenticator) Get(options []byte) ([]byte, error) {
	var o struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
			RPID      string `json:"rpId"`
			Allow     []struct {
				ID string `json:"id"`
			} `json:"allowCredentials"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(options, &o); err != nil {
		return nil, err
	}
	var id string
	var c *cred
	for _, al := range o.PublicKey.Allow {
		if k, ok := a.creds[al.ID]; ok {
			id, c = al.ID, k
			break
		}
	}
	if c == nil {
		return nil, errors.New("NotAllowedError: no credential for this site")
	}
	c.counter++
	cdj := a.clientData("webauthn.get", o.PublicKey.Challenge)
	auth := c.authData(a.flags())
	sum := sha256.Sum256(cdj)
	digest := sha256.Sum256(append(append([]byte{}, auth...), sum[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, c.key, digest[:])
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{
		"id": id, "rawId": id, "type": "public-key", "authenticatorAttachment": "platform",
		"clientExtensionResults": map[string]any{},
		"response": map[string]any{
			"clientDataJSON": b64.EncodeToString(cdj), "authenticatorData": b64.EncodeToString(auth),
			"signature": b64.EncodeToString(sig), "userHandle": b64.EncodeToString(c.userHandle),
		},
	})
}

// SetCounter sets the signature counter of every credential (clone tests).
func (a *Authenticator) SetCounter(n uint32) {
	for _, c := range a.creds {
		c.counter = n
	}
}

func (a *Authenticator) flags() byte {
	f := byte(0x01) // user present
	if a.UserVerified {
		f |= 0x04
	}
	return f
}

func (a *Authenticator) clientData(typ, challenge string) []byte {
	b, _ := json.Marshal(map[string]any{"type": typ, "challenge": challenge, "origin": a.Origin, "crossOrigin": false})
	return b
}

func (c *cred) authData(flags byte) []byte {
	h := sha256.Sum256([]byte(c.rpID))
	out := append([]byte{}, h[:]...)
	out = append(out, flags)
	return binary.BigEndian.AppendUint32(out, c.counter)
}

// coseKey is an EC2 P-256 key for ES256 (RFC 9053).
func coseKey(k *ecdsa.PublicKey) []byte {
	raw, _ := k.Bytes() // 0x04 || X || Y
	return cborMap(
		cborInt(1), cborInt(2), // kty: EC2
		cborInt(3), cborInt(-7), // alg: ES256
		cborInt(-1), cborInt(1), // crv: P-256
		cborInt(-2), cborBytes(raw[1:33]),
		cborInt(-3), cborBytes(raw[33:65]),
	)
}

// A minimal CBOR encoder (RFC 8949): what an attestation object needs.
func cborHead(major byte, n uint64) []byte {
	switch {
	case n < 24:
		return []byte{major<<5 | byte(n)}
	case n <= 0xff:
		return []byte{major<<5 | 24, byte(n)}
	case n <= 0xffff:
		return binary.BigEndian.AppendUint16([]byte{major<<5 | 25}, uint16(n))
	default:
		return binary.BigEndian.AppendUint32([]byte{major<<5 | 26}, uint32(n)) // #nosec G115 -- test data stays small
	}
}

func cborInt(v int) []byte {
	if v >= 0 {
		return cborHead(0, uint64(v))
	}
	return cborHead(1, uint64(-1-v))
}

func cborBytes(b []byte) []byte { return append(cborHead(2, uint64(len(b))), b...) }
func cborText(s string) []byte  { return append(cborHead(3, uint64(len(s))), s...) }

// cborMap takes key, value, key, value, … already encoded.
func cborMap(kv ...[]byte) []byte {
	out := cborHead(5, uint64(len(kv)/2))
	for _, p := range kv {
		out = append(out, p...)
	}
	return out
}
