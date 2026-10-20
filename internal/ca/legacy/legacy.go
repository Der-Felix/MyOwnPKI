// Package legacy reads a PKI directory of legacy/pki.sh (PHASE1 step 15):
// pki.conf, the root and intermediate CAs (ca.meta, certs/ca.crt,
// private/ca.key, index.txt, newcerts/, crlnumber, crl/ca.crl, archive/) and
// the issued certificates (issued/<name>/cert.meta, cert.pem, key.pem,
// archive/). It only reads – files are parsed, never executed – and returns
// what it found with every problem; internal/ca decides what is imported.
//
// The certificates a CA signed come from its index.txt and newcerts/:
// issued/ holds only the newest certificate of a name, newcerts/ every one.
package legacy

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"path"
	"slices"
	"strconv"
	"strings"
)

// Limits for the files of an import.
const (
	maxSmallFile = 1 << 20  // certificates, keys, meta files, CRL
	maxIndexFile = 64 << 20 // index.txt
	maxCAs       = 256
	maxIssued    = 100_000
)

// Passphrases opens encrypted keys; pki.sh takes them from PKI_CA_PASS_<NAME>,
// PKI_CA_PASS and PKI_KEY_PASS.
type Passphrases struct {
	// CA returns the passphrase of a CA key ("root" or the intermediate's name).
	CA func(name string) []byte
	// Leaf is the passphrase of the leaf keys (pki.sh uses one for all).
	Leaf []byte
}

// PKI is what Read found.
type PKI struct {
	Config        Config
	Root          *CA
	Intermediates []*CA // by name
	// Issued are the certificate directories under issued/ (current and
	// archived versions), by serial.
	Issued map[string]*IssuedFile
	// SelfSigned are issued/ certificates with CA="selfsigned".
	SelfSigned []*IssuedFile
	// LeafKeys are all leaf keys found, by SHA-256 of their public key.
	LeafKeys map[string]*Key
	// Problems block an import; Warnings don't.
	Problems, Warnings []string
}

// Config is pki.conf.
type Config struct {
	BaseURL string // AIA_BASE_URL without a trailing slash; "" = certificates without CDP/AIA
	CRLDays int    // CRL_DAYS; 0 when not set
	Org     string // PKI_ORG
	Values  map[string]string
}

// CA is pki/root or pki/intermediate/<name>.
type CA struct {
	Name string
	Dir  string
	Meta map[string]string
	Cert *x509.Certificate
	// Key is the decrypted CA key; nil with KeyProblem set when it can't be
	// read. KeyEncrypted tells whether private/ca.key is encrypted.
	Key          crypto.Signer
	KeyEncrypted bool
	KeyProblem   string
	Index        []Entry
	// Signed are the certificates of newcerts/ by serial.
	Signed map[string]*x509.Certificate
	// NextCRLNumber is the content of crlnumber (hex): the number of the
	// next CRL. 0 when the file is missing.
	NextCRLNumber int64
	CRL           *x509.RevocationList // crl/ca.crl; nil when missing
	// History are older certificates of this CA from archive/*/ca.crt.
	History []*x509.Certificate
}

// IssuedFile is one certificate under issued/ with its meta data.
type IssuedFile struct {
	Name     string // directory name under issued/
	Path     string
	Meta     map[string]string
	Cert     *x509.Certificate
	Archived bool
}

// Key is a leaf key file.
type Key struct {
	Path      string
	Signer    crypto.Signer
	Encrypted bool
}

// Read parses a pki.sh directory. A nil error means the directory was
// readable at all; what is wrong inside is in Problems and Warnings.
func Read(fsys fs.FS, pw Passphrases) (*PKI, error) {
	if _, err := fs.Stat(fsys, "root/certs/ca.crt"); err != nil {
		return nil, fmt.Errorf("no pki.sh directory: root/certs/ca.crt not found (point to the directory that pki.sh --dir names, usually ./pki)")
	}
	p := &PKI{Issued: map[string]*IssuedFile{}, LeafKeys: map[string]*Key{}}
	p.readConfig(fsys)
	p.Root = p.readCA(fsys, "root", "root", pw)
	names, err := fs.ReadDir(fsys, "intermediate")
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	for _, d := range names {
		if !d.IsDir() {
			continue
		}
		if len(p.Intermediates) >= maxCAs {
			p.problem("more than %d intermediate CAs", maxCAs)
			break
		}
		dir := path.Join("intermediate", d.Name())
		if _, serr := fs.Stat(fsys, dir+"/certs/ca.crt"); serr != nil {
			p.warn("%s has no certs/ca.crt – skipped (an aborted pki.sh run?)", dir)
			continue
		}
		p.Intermediates = append(p.Intermediates, p.readCA(fsys, d.Name(), dir, pw))
	}
	sortCAs(p.Intermediates)
	p.readIssued(fsys, pw.Leaf)
	return p, nil
}

func (p *PKI) problem(format string, a ...any) {
	p.Problems = append(p.Problems, fmt.Sprintf(format, a...))
}
func (p *PKI) warn(format string, a ...any) {
	p.Warnings = append(p.Warnings, fmt.Sprintf(format, a...))
}

// CAs returns the root and the intermediates.
func (p *PKI) CAs() []*CA {
	return append([]*CA{p.Root}, p.Intermediates...)
}

func readFile(fsys fs.FS, name string, limit int64) ([]byte, error) {
	st, err := fs.Stat(fsys, name)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", name)
	}
	if st.Size() > limit {
		return nil, fmt.Errorf("%s is larger than %d KiB", name, limit>>10)
	}
	return fs.ReadFile(fsys, name)
}

func (p *PKI) readConfig(fsys fs.FS) {
	data, err := readFile(fsys, "pki.conf", maxSmallFile)
	if err != nil {
		p.warn("pki.conf not read (%v) – the defaults of pki.sh apply", err)
		p.Config = Config{CRLDays: 30, Values: map[string]string{}}
		return
	}
	kv, notes := parseKV(data)
	for _, n := range notes {
		p.warn("pki.conf: %s", n)
	}
	p.Config = Config{Values: kv, Org: kv["PKI_ORG"], BaseURL: strings.TrimRight(kv["AIA_BASE_URL"], "/"), CRLDays: 30}
	if v := kv["CRL_DAYS"]; v != "" {
		n, aerr := strconv.Atoi(v)
		if aerr != nil || n < 1 {
			p.problem("pki.conf: CRL_DAYS %q is not a positive number", clip(v, 20))
		} else {
			p.Config.CRLDays = n
		}
	}
}

func (p *PKI) readCA(fsys fs.FS, name, dir string, pw Passphrases) *CA {
	c := &CA{Name: name, Dir: dir, Signed: map[string]*x509.Certificate{}}
	where := func(f string) string { return path.Join(dir, f) }
	if data, err := readFile(fsys, where("ca.meta"), maxSmallFile); err != nil {
		p.warn("%s: %v", where("ca.meta"), err)
		c.Meta = map[string]string{}
	} else {
		var notes []string
		c.Meta, notes = parseKV(data)
		for _, n := range notes {
			p.warn("%s: %s", where("ca.meta"), n)
		}
	}
	var err error
	if c.Cert, err = readCert(fsys, where("certs/ca.crt")); err != nil {
		p.problem("%s: %v", where("certs/ca.crt"), err)
	}

	var pass []byte
	if pw.CA != nil {
		pass = pw.CA(name)
	}
	if data, rerr := readFile(fsys, where("private/ca.key"), maxSmallFile); rerr != nil {
		c.KeyProblem = fmt.Sprintf("%s: %v", where("private/ca.key"), rerr)
	} else {
		c.Key, c.KeyEncrypted, err = parsePrivateKey(data, pass)
		clear(data)
		switch {
		case errors.Is(err, errNoPassphrase):
			c.KeyProblem = fmt.Sprintf("the key of CA %q is encrypted – set PKI_CA_PASS_%s or PKI_CA_PASS as for pki.sh", name, envName(name))
		case err != nil:
			c.KeyProblem = fmt.Sprintf("%s: %v", where("private/ca.key"), err)
		case c.Cert != nil && !publicKeyEqual(c.Key.Public(), c.Cert.PublicKey):
			c.Key, c.KeyProblem = nil, fmt.Sprintf("%s doesn't belong to certs/ca.crt", where("private/ca.key"))
		}
	}

	if data, rerr := readFile(fsys, where("index.txt"), maxIndexFile); rerr != nil {
		p.problem("%s: %v", where("index.txt"), rerr)
	} else {
		var problems []string
		c.Index, problems = parseIndex(data)
		for _, pr := range problems {
			p.problem("%s %s", where("index.txt"), pr)
		}
	}
	for _, e := range c.Index {
		f := where("newcerts/" + e.File + ".pem")
		cert, rerr := readCert(fsys, f)
		if rerr != nil {
			p.problem("%s line %d (serial %s): certificate file %s: %v", where("index.txt"), e.Line, e.Serial, f, rerr)
			continue
		}
		if serialHex(cert.SerialNumber) != e.Serial {
			p.problem("%s has serial %s, index.txt says %s", f, serialHex(cert.SerialNumber), e.Serial)
			continue
		}
		c.Signed[e.Serial] = cert
	}

	if data, rerr := readFile(fsys, where("crlnumber"), maxSmallFile); rerr == nil {
		v := strings.TrimSpace(string(data))
		n, ok := new(big.Int).SetString(v, 16)
		if !ok || n.Sign() <= 0 || !n.IsInt64() {
			p.problem("%s: %q is not a hex CRL number", where("crlnumber"), clip(v, 40))
		} else {
			c.NextCRLNumber = n.Int64()
		}
	}
	if data, rerr := readFile(fsys, where("crl/ca.crl"), maxSmallFile); rerr == nil {
		der := data
		if block, _ := pem.Decode(data); block != nil && block.Type == "X509 CRL" {
			der = block.Bytes
		}
		if c.CRL, err = x509.ParseRevocationList(der); err != nil {
			p.warn("%s can't be parsed (%v) – not kept", where("crl/ca.crl"), err)
			c.CRL = nil
		}
	}

	if arch, rerr := fs.ReadDir(fsys, where("archive")); rerr == nil {
		for _, a := range arch {
			f := where("archive/" + a.Name() + "/ca.crt")
			if _, serr := fs.Stat(fsys, f); serr != nil {
				continue
			}
			cert, cerr := readCert(fsys, f)
			if cerr != nil {
				p.warn("%s: %v – not kept", f, cerr)
				continue
			}
			c.History = append(c.History, cert)
		}
	}
	return c
}

func (p *PKI) readIssued(fsys fs.FS, leafPass []byte) {
	dirs, err := fs.ReadDir(fsys, "issued")
	if errors.Is(err, fs.ErrNotExist) {
		return
	}
	if err != nil {
		p.problem("issued: %v", err)
		return
	}
	count := 0
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		base := path.Join("issued", d.Name())
		places := []string{base}
		if arch, aerr := fs.ReadDir(fsys, base+"/archive"); aerr == nil {
			for _, a := range arch {
				if a.IsDir() {
					places = append(places, path.Join(base, "archive", a.Name()))
				}
			}
		}
		for i, dir := range places {
			if count++; count > maxIssued {
				p.problem("more than %d certificate directories under issued/", maxIssued)
				return
			}
			p.readIssuedDir(fsys, d.Name(), dir, i > 0, leafPass)
		}
	}
}

func (p *PKI) readIssuedDir(fsys fs.FS, name, dir string, archived bool, leafPass []byte) {
	if data, err := readFile(fsys, dir+"/key.pem", maxSmallFile); err == nil {
		signer, enc, kerr := parsePrivateKey(data, leafPass)
		clear(data)
		switch {
		case errors.Is(kerr, errNoPassphrase):
			p.warn("%s/key.pem is encrypted and PKI_KEY_PASS is not set – the key is not imported", dir)
		case kerr != nil:
			p.warn("%s/key.pem: %v – the key is not imported", dir, kerr)
		default:
			if h, herr := spkiHash(signer.Public()); herr == nil {
				p.LeafKeys[h] = &Key{Path: dir + "/key.pem", Signer: signer, Encrypted: enc}
			}
		}
	}
	certPath := dir + "/cert.pem"
	if _, err := fs.Stat(fsys, certPath); err != nil {
		if !archived {
			p.warn("%s has no cert.pem – skipped", dir)
		}
		return
	}
	cert, err := readCert(fsys, certPath)
	if err != nil {
		p.warn("%s: %v – skipped", certPath, err)
		return
	}
	f := &IssuedFile{Name: name, Path: dir, Cert: cert, Archived: archived, Meta: map[string]string{}}
	if data, rerr := readFile(fsys, dir+"/cert.meta", maxSmallFile); rerr == nil {
		var notes []string
		f.Meta, notes = parseKV(data)
		for _, n := range notes {
			p.warn("%s/cert.meta: %s", dir, n)
		}
	}
	if f.Meta["CA"] == "selfsigned" {
		p.SelfSigned = append(p.SelfSigned, f)
		return
	}
	serial := serialHex(cert.SerialNumber)
	// The current certificate wins over an archived copy of the same one.
	if old, ok := p.Issued[serial]; ok && !old.Archived {
		return
	}
	p.Issued[serial] = f
}

// readCert reads one PEM (or DER) certificate.
func readCert(fsys fs.FS, name string) (*x509.Certificate, error) {
	data, err := readFile(fsys, name, maxSmallFile)
	if err != nil {
		return nil, err
	}
	der := data
	if block, _ := pem.Decode(data); block != nil {
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("PEM block %q is not a certificate", clip(block.Type, 40))
		}
		der = block.Bytes
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("can't be parsed: %w", err)
	}
	return cert, nil
}

// envName is how pki.sh turns a CA name into a variable suffix.
func envName(name string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return r - 'a' + 'A'
		case r == '.' || r == '@' || r == '-':
			return '_'
		}
		return r
	}, name)
}

// EnvName is the suffix of PKI_CA_PASS_<NAME> for a CA.
func EnvName(name string) string { return envName(name) }

func serialHex(n *big.Int) string {
	s := fmt.Sprintf("%X", n)
	if len(s)%2 == 1 {
		s = "0" + s
	}
	return s
}

func publicKeyEqual(a, b crypto.PublicKey) bool {
	k, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && k.Equal(b)
}

// sortCAs keeps the intermediates in name order (fs.ReadDir sorts already;
// this keeps it true for other file systems).
func sortCAs(cas []*CA) {
	slices.SortFunc(cas, func(a, b *CA) int { return strings.Compare(a.Name, b.Name) })
}

// KeyHash is the SHA-256 of a public key's SubjectPublicKeyInfo, upper-case
// hex: how leaf keys are matched to certificates.
func KeyHash(pub crypto.PublicKey) (string, error) { return spkiHash(pub) }

func spkiHash(pub crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return strings.ToUpper(hex.EncodeToString(sum[:])), nil
}
