package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/config"
)

// Bootstrap certificate of the admin listener (PLAN §5, owner 2026-10-16):
// a self-signed end-entity certificate – CA:FALSE, digitalSignature,
// serverAuth (Firefox refuses a CA certificate as server certificate
// without even offering an exception). Its key is not encrypted: the admin
// listener must work while the server is sealed. It only protects the
// connection to the admin UI; the fingerprint on the console is the check.
const (
	bootstrapDays  = 397
	bootstrapRenew = 30 * 24 * time.Hour
	bootstrapCert  = "admin-bootstrap.crt"
	bootstrapKey   = "admin-bootstrap.key"

	acmeBootstrapCert = "acme-bootstrap.crt"
	acmeBootstrapKey  = "acme-bootstrap.key"
)

// CertInfo describes the admin certificate for the log.
type CertInfo struct {
	Source      string // "operator" or "bootstrap"
	Fingerprint string // SHA-256, colon-separated hex – as browsers show it
	NotAfter    time.Time
	DNSNames    []string
	IPs         []netip.Addr
	// Created: a new bootstrap certificate was made at this start (first
	// start, renewal or new names) – its fingerprint changed.
	Created bool
	Reason  string // why it was created
}

// adminCertificate returns the certificate of the admin listener.
func adminCertificate(cfg config.Config, hostname string, now time.Time, rnd io.Reader) (*tls.Certificate, CertInfo, error) {
	if cfg.Admin.TLSCertFile != "" {
		c, err := tls.LoadX509KeyPair(cfg.Admin.TLSCertFile, cfg.Admin.TLSKeyFile)
		if err != nil {
			return nil, CertInfo{}, fmt.Errorf("admin certificate: %w", err)
		}
		leaf, err := x509.ParseCertificate(c.Certificate[0])
		if err != nil {
			return nil, CertInfo{}, fmt.Errorf("admin certificate: %w", err)
		}
		c.Leaf = leaf
		return &c, info("operator", leaf), nil
	}
	names, ips, err := wantedNames(cfg, hostname)
	if err != nil {
		return nil, CertInfo{}, err
	}
	return bootstrap(filepath.Join(cfg.DataDir, "tls"), bootstrapCert, bootstrapKey, "MyOwnPKI admin (bootstrap)",
		"the names changed (host name, admin.listen or admin.tls_names)", names, ips, now, rnd)
}

// acmeBootstrap is the self-signed certificate of the ACME listener with
// acme.tls_issuer: what it serves until the server has issued its own (the
// first unseal), or after that one expired while sealed. ACME clients refuse
// it – that is the point: they never talk to a listener they can't verify.
func acmeBootstrap(cfg config.Config, now time.Time, rnd io.Reader) (*tls.Certificate, CertInfo, error) {
	names, ips := hostNames(config.ACMEHost(cfg.ACME.BaseURL))
	return bootstrap(filepath.Join(cfg.DataDir, "tls"), acmeBootstrapCert, acmeBootstrapKey, "MyOwnPKI ACME (bootstrap)",
		"the host of acme.base_url changed", names, ips, now, rnd)
}

// hostNames puts a host – a DNS name or an IP – into the right SAN list.
func hostNames(host string) ([]string, []netip.Addr) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return nil, []netip.Addr{ip.Unmap()}
	}
	if host == "" {
		return nil, nil
	}
	return []string{host}, nil
}

// bootstrap loads the self-signed certificate in dir/certFile, or makes a
// new one when it is missing, expires within 30 days or lacks a name.
func bootstrap(dir, certFile, keyFile, cn, namesChanged string, names []string, ips []netip.Addr, now time.Time, rnd io.Reader) (*tls.Certificate, CertInfo, error) {
	certPath, keyPath := filepath.Join(dir, certFile), filepath.Join(dir, keyFile)
	reason := "first start"
	if c, lerr := tls.LoadX509KeyPair(certPath, keyPath); lerr == nil {
		leaf, perr := x509.ParseCertificate(c.Certificate[0])
		switch {
		case perr != nil:
			reason = "the stored certificate can't be read"
		case now.Add(bootstrapRenew).After(leaf.NotAfter):
			reason = "it expires within 30 days"
		case !covers(leaf, names, ips):
			reason = namesChanged
		default:
			c.Leaf = leaf
			return &c, info("bootstrap", leaf), nil
		}
	}
	c, err := createBootstrap(dir, certPath, keyPath, cn, names, ips, now, rnd)
	if err != nil {
		return nil, CertInfo{}, err
	}
	in := info("bootstrap", c.Leaf)
	in.Created, in.Reason = true, reason
	return c, in, nil
}

// wantedNames: host name, the listen IP (if one is set), loopback and
// admin.tls_names.
func wantedNames(cfg config.Config, hostname string) ([]string, []netip.Addr, error) {
	extraNames, extraIPs, err := config.ParseTLSNames(cfg.Admin.TLSNames)
	if err != nil {
		return nil, nil, err
	}
	var names []string
	if h := strings.ToLower(strings.TrimSpace(hostname)); h != "" {
		if _, _, err := config.ParseTLSNames(h); err == nil {
			names = append(names, h)
		}
	}
	if !slices.Contains(names, "localhost") {
		names = append(names, "localhost")
	}
	ips := []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::1")}
	if host, _, err := net.SplitHostPort(cfg.Admin.Listen); err == nil && host != "" {
		if ip, err := netip.ParseAddr(host); err == nil && !ip.IsUnspecified() && !slices.Contains(ips, ip.Unmap()) {
			ips = append(ips, ip.Unmap())
		}
	}
	for _, n := range extraNames {
		if !slices.Contains(names, n) {
			names = append(names, n)
		}
	}
	for _, ip := range extraIPs {
		if !slices.Contains(ips, ip) {
			ips = append(ips, ip)
		}
	}
	return names, ips, nil
}

func covers(leaf *x509.Certificate, names []string, ips []netip.Addr) bool {
	for _, n := range names {
		if !slices.Contains(leaf.DNSNames, n) {
			return false
		}
	}
	for _, ip := range ips {
		if !slices.ContainsFunc(leaf.IPAddresses, func(have net.IP) bool {
			a, ok := netip.AddrFromSlice(have)
			return ok && a.Unmap() == ip
		}) {
			return false
		}
	}
	return true
}

func createBootstrap(dir, certPath, keyPath, cn string, names []string, ips []netip.Addr, now time.Time, rnd io.Reader) (*tls.Certificate, error) {
	if rnd == nil {
		rnd = rand.Reader
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rnd)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rnd, new(big.Int).Lsh(big.NewInt(1), 159))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial.Add(serial, big.NewInt(1)),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(bootstrapDays * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              names,
	}
	for _, ip := range ips {
		tmpl.IPAddresses = append(tmpl.IPAddresses, ip.AsSlice())
	}
	der, err := x509.CreateCertificate(rnd, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, err
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	defer clear(keyPEM)
	clear(pkcs8)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if werr := writeAtomic(keyPath, keyPEM, 0o600); werr != nil {
		return nil, werr
	}
	if werr := writeAtomic(certPath, certPEM, 0o644); werr != nil {
		return nil, werr
	}
	c, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	if c.Leaf, err = x509.ParseCertificate(der); err != nil {
		return nil, err
	}
	return &c, nil
}

// writeAtomic writes via a temporary file and a rename: a crash never
// leaves half a key behind.
func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return errors.Join(fmt.Errorf("replace %s", path), err)
	}
	return nil
}

func info(source string, leaf *x509.Certificate) CertInfo {
	in := CertInfo{Source: source, Fingerprint: Fingerprint(leaf.Raw), NotAfter: leaf.NotAfter, DNSNames: leaf.DNSNames}
	for _, ip := range leaf.IPAddresses {
		if a, ok := netip.AddrFromSlice(ip); ok {
			in.IPs = append(in.IPs, a.Unmap())
		}
	}
	return in
}

// Fingerprint is the SHA-256 of der as colon-separated upper-case hex.
func Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

// AdminCertFiles are the files of the certificates the admin listener may
// serve: the operator's file, or the bootstrap certificate – and with
// admin.tls_issuer the issued one, which replaces the bootstrap certificate
// without a restart. `myownpki healthcheck` pins the served certificate to
// one of them.
func AdminCertFiles(cfg config.Config) []string {
	if cfg.Admin.TLSCertFile != "" {
		return []string{cfg.Admin.TLSCertFile}
	}
	files := []string{filepath.Join(cfg.DataDir, "tls", bootstrapCert)}
	if cfg.Admin.TLSIssuer != "" {
		files = append(files, filepath.Join(cfg.DataDir, "tls", issuedCertFile("admin")))
	}
	return files
}
