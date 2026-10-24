package agent

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Files in the state directory (0700, every file 0600).
const (
	keyFile        = "agent.key"   // the agent's private key (PKCS#8 PEM), made on this host (ADR-11)
	certFile       = "agent.crt"   // its certificate and the chain (PEM)
	pendingKeyFile = "pending.key" // the key of an enrollment or renewal not finished yet
	enrollmentFile = "enrollment.json"
)

// state is the agent's identity on disk.
type state struct{ dir string }

// enrollmentState is an open enrollment, so `run` can wait for the
// approval after `enroll` returned.
type enrollmentState struct {
	ID      string `json:"id"`
	Handle  string `json:"handle"`
	Again   bool   `json:"again"` // with the key of the last certificate
	Message string `json:"message"`
}

func (s state) path(name string) string { return filepath.Join(s.dir, name) }

func (s state) ensure() error {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	return os.Chmod(s.dir, 0o700) //nolint:gosec // a directory: only the owner, and it needs the x bit
}

// identity loads the agent's key and certificate; os.ErrNotExist when the
// agent hasn't enrolled yet.
func (s state) identity() (*tls.Certificate, error) {
	c, err := tls.LoadX509KeyPair(s.path(certFile), s.path(keyFile))
	if err != nil {
		if _, serr := os.Stat(s.path(certFile)); errors.Is(serr, os.ErrNotExist) {
			return nil, os.ErrNotExist
		}
		return nil, err
	}
	return &c, nil
}

// install makes key and certificate (with chain) the agent's identity:
// the key first, then the certificate, each renamed into place – a crash in
// between leaves the old pair or a key whose certificate is missing, which
// identity() refuses and the next enrollment replaces.
func (s state) install(key crypto.Signer, certDER []byte, chain [][]byte) (*tls.Certificate, error) {
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	var certPEM []byte
	for _, der := range append([][]byte{certDER}, chain...) {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	if err := writeFile(s.path(keyFile), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}), 0o600); err != nil {
		return nil, err
	}
	if err := writeFile(s.path(certFile), certPEM, 0o600); err != nil {
		return nil, err
	}
	_ = os.Remove(s.path(pendingKeyFile))
	return s.identity()
}

// pendingKey loads the key of an unfinished enrollment or renewal, or makes
// and stores a new one.
func (s state) pendingKey(fresh bool) (*ecdsa.PrivateKey, error) {
	if !fresh {
		if k, err := readKey(s.path(pendingKeyFile)); err == nil {
			return k, nil
		}
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, err
	}
	if err := writeFile(s.path(pendingKeyFile), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}), 0o600); err != nil {
		return nil, err
	}
	return k, nil
}

// currentKey is the key of the agent's certificate (for enrolling again).
func (s state) currentKey() (*ecdsa.PrivateKey, error) { return readKey(s.path(keyFile)) }

func readKey(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	b, _ := pem.Decode(data)
	if b == nil {
		return nil, fmt.Errorf("%s: no PEM key", path)
	}
	k, err := x509.ParsePKCS8PrivateKey(b.Bytes)
	if err != nil {
		return nil, err
	}
	ec, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s: not an ECDSA key", path)
	}
	return ec, nil
}

func (s state) enrollment() (*enrollmentState, error) {
	data, err := os.ReadFile(s.path(enrollmentFile))
	if err != nil {
		return nil, err
	}
	var e enrollmentState
	if err := json.Unmarshal(data, &e); err != nil {
		return nil, err
	}
	return &e, nil
}

func (s state) saveEnrollment(e *enrollmentState) error {
	data, err := json.Marshal(e)
	if err != nil {
		return err
	}
	return writeFile(s.path(enrollmentFile), data, 0o600)
}

func (s state) clearEnrollment() { _ = os.Remove(s.path(enrollmentFile)) }

// writeFile writes atomically: a temporary file in the same directory,
// fsync, rename.
func writeFile(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
