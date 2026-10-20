package ca

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/Der-Felix/MyOwnPKI/internal/ca/legacy"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
)

// planLegacyCerts collects every certificate the CAs signed (index.txt +
// newcerts/), the ones under issued/ that are missing there, and the
// self-signed ones (as external).
func (e *Engine) planLegacyCerts(ctx context.Context, q *pkidb.Queries, p *legacyPlan) {
	caCerts := map[string]bool{}
	for _, c := range p.cas {
		caCerts[fingerprintHex(c.src.Cert.Raw)] = true
		for _, h := range c.history {
			caCerts[fingerprintHex(h.Raw)] = true
		}
	}
	seen := map[string]bool{}
	add := func(lc *legacyCert, what string) {
		seen[fingerprintHex(lc.cert.Raw)] = true
		e.legacyCertDetails(p, lc, what)
		p.certs = append(p.certs, lc)
	}
	for _, c := range p.cas {
		for _, en := range c.src.Index {
			cert := c.src.Signed[en.Serial]
			if cert == nil || caCerts[fingerprintHex(cert.Raw)] {
				continue // missing: a problem of the reader already
			}
			if cert.IsCA {
				p.warn("CA %q signed the CA certificate %q (serial %s) that has no directory under intermediate/ – not imported (pki ca-sign for another server?)",
					c.src.Name, short(cert.Subject.String()), en.Serial)
				continue
			}
			what := fmt.Sprintf("certificate %q (serial %s of CA %q)", short(cert.Subject.CommonName), en.Serial, c.src.Name)
			if err := cert.CheckSignatureFrom(c.src.Cert); err != nil {
				p.problem("%s: not signed by its CA: %v", what, err)
				continue
			}
			lc := &legacyCert{ca: c, cert: cert}
			if en.Revoked != nil {
				lc.rev = p.legacyReason(en.Revoked, false, what)
			}
			add(lc, what)
		}
	}
	// issued/ certificates that are in no index.txt.
	for _, serial := range slices.Sorted(maps.Keys(p.pki.Issued)) {
		f := p.pki.Issued[serial]
		if seen[fingerprintHex(f.Cert.Raw)] {
			continue
		}
		var ca *legacyCA
		for _, c := range p.cas {
			if c.src.Name == f.Meta["CA"] {
				ca = c
			}
		}
		what := fmt.Sprintf("%s/cert.pem (serial %s)", f.Path, serial)
		if ca == nil || f.Cert.CheckSignatureFrom(ca.src.Cert) != nil {
			p.warn("%s: not signed by a CA of this directory – not imported", what)
			continue
		}
		p.warn("%s is not in the index.txt of CA %q – imported without a revocation status (check it)", what, ca.src.Name)
		add(&legacyCert{ca: ca, cert: f.Cert}, what)
	}
	for _, f := range p.pki.SelfSigned {
		if seen[fingerprintHex(f.Cert.Raw)] {
			continue
		}
		seen[fingerprintHex(f.Cert.Raw)] = true
		p.certs = append(p.certs, &legacyCert{cert: f.Cert, preset: e.knownPreset(p, f.Meta["PRESET"], f.Path)})
	}

	for _, lc := range p.certs {
		n, err := q.CountFingerprint(ctx, fingerprintHex(lc.cert.Raw))
		switch {
		case err != nil:
			p.problem("check certificate %s: %v", SerialHex(lc.cert.SerialNumber), err)
		case n > 0:
			p.problem("certificate %q (serial %s) is on this server already", short(lc.cert.Subject.CommonName), SerialHex(lc.cert.SerialNumber))
		}
		if lc.ca == nil {
			p.rep.External++
			continue
		}
		p.rep.Certificates++
		lc.ca.rep.Certificates++
		if lc.rev != nil {
			p.rep.Revoked++
			lc.ca.rep.Revoked++
		}
	}
	p.rep.Keys = len(p.leafKeys)
}

// legacyCertDetails adds preset, customized usages and the key from issued/.
func (e *Engine) legacyCertDetails(p *legacyPlan, lc *legacyCert, what string) {
	if f := p.pki.Issued[SerialHex(lc.cert.SerialNumber)]; f != nil && f.Cert.Equal(lc.cert) {
		lc.preset = e.knownPreset(p, f.Meta["PRESET"], what)
		if lc.preset == "custom" {
			lc.custom = [2]string{f.Meta["CUSTOM_KU"], f.Meta["CUSTOM_EKU"]}
		}
	}
	h, err := legacy.KeyHash(lc.cert.PublicKey)
	if err != nil {
		return
	}
	if k, ok := p.pki.LeafKeys[h]; ok {
		lc.keyHash = h
		p.leafKeys[h] = k.Signer
	}
}

func (e *Engine) knownPreset(p *legacyPlan, name, where string) string {
	if name == "" {
		return ""
	}
	if e.Presets != nil {
		if _, ok := e.Presets.Get(name); ok {
			return name
		}
	}
	p.warn("%s: preset %q is unknown here – imported without a preset", where, short(name))
	return ""
}

// describeKey names a leaf key even when the key policy wouldn't accept it
// for a new certificate: imported certificates are records.
func describeKey(pub crypto.PublicKey) string {
	if alg, err := keyAlgorithm(pub); err == nil {
		return alg
	}
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("rsa-%d", k.N.BitLen())
	case *ecdsa.PublicKey:
		return "ecdsa-" + strings.ToLower(k.Params().Name)
	case ed25519.PublicKey:
		return AlgEd25519
	}
	return fmt.Sprintf("%T", pub)
}

// certNames are the SANs of a certificate as certificate_sans rows.
func certNames(cert *x509.Certificate) [][2]string {
	var out [][2]string
	add := func(t, v string) {
		row := [2]string{t, v}
		if !slices.Contains(out, row) {
			out = append(out, row)
		}
	}
	for _, d := range cert.DNSNames {
		add("dns", strings.ToLower(d))
	}
	for _, ip := range cert.IPAddresses {
		add("ip", ip.String())
	}
	for _, m := range cert.EmailAddresses {
		add("email", m)
	}
	for _, u := range cert.URIs {
		add("uri", u.String())
	}
	return out
}
