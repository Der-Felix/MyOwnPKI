package web

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/ca/preset"
	"github.com/Der-Felix/MyOwnPKI/internal/web/fixture"
	"github.com/Der-Felix/MyOwnPKI/internal/web/pages/certificates"
	"github.com/Der-Felix/MyOwnPKI/internal/web/view"
)

// The "Issue certificate" wizard. The checks here are what the UI shows early;
// in phase 1 the same request goes through the CA engine and policy engine,
// which check everything again (pki-rules.md) – the UI is never the gate.

var reDNSName = regexp.MustCompile(`^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

var keyAlgorithms = []view.Option{
	{Value: "ecdsa-p256", Label: "ECDSA P-256 (recommended)"},
	{Value: "ecdsa-p384", Label: "ECDSA P-384"},
	{Value: "rsa-3072", Label: "RSA 3072"},
	{Value: "rsa-4096", Label: "RSA 4096"},
	{Value: "rsa-2048", Label: "RSA 2048 (compatibility only)"},
	{Value: "ed25519", Label: "Ed25519 (not accepted by browsers for TLS servers)"},
}

func algorithmLabel(v string) string {
	if i := slices.IndexFunc(keyAlgorithms, func(o view.Option) bool { return o.Value == v }); i >= 0 {
		return keyAlgorithms[i].Label
	}
	return v
}

// signingCAs are the CAs whose key is online; an offline root can't sign here.
func signingCAs() []fixture.CA {
	var out []fixture.CA
	for _, ca := range fixture.CAs() {
		if ca.KeyMode != "offline" {
			out = append(out, ca)
		}
	}
	return out
}

func lines(s string) []string {
	var out []string
	for _, l := range strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

func issueStateFromForm(r *http.Request) certificates.IssueState {
	f := r.PostForm
	return certificates.IssueState{
		Preset: f.Get("preset"), CA: f.Get("ca"),
		CommonName: strings.TrimSpace(f.Get("cn")),
		DNS:        strings.ToLower(f.Get("dns")), IP: f.Get("ip"), Email: f.Get("email"),
		KeyMode: f.Get("keymode"), Algorithm: f.Get("alg"), CSR: f.Get("csr"),
		Days: strings.TrimSpace(f.Get("days")),
	}
}

func (p *prototype) issueStart(w http.ResponseWriter, r *http.Request) {
	st := certificates.IssueState{Preset: "server", CA: "homelab-issuing", KeyMode: "csr", Algorithm: "ecdsa-p256"}
	if ca, ok := fixture.CAByID(r.URL.Query().Get("ca")); ok && ca.KeyMode != "offline" {
		st.CA = ca.ID
	}
	p.renderIssue(w, r, certificates.StepPreset, st, nil)
}

func (p *prototype) issueStep(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	from, err := strconv.Atoi(r.PostForm.Get("from"))
	if err != nil || from < certificates.StepPreset || from > certificates.StepReview {
		http.Error(w, "invalid step", http.StatusBadRequest)
		return
	}
	st := issueStateFromForm(r)

	switch r.PostForm.Get("go") {
	case "back":
		p.renderIssue(w, r, max(certificates.StepPreset, from-1), st, nil)
	case "next":
		if errs := p.validateStep(from, &st); len(errs) > 0 {
			p.renderIssue(w, r, from, st, errs)
			return
		}
		p.renderIssue(w, r, min(certificates.StepReview, from+1), st, nil)
	case "issue":
		for step := certificates.StepPreset; step < certificates.StepReview; step++ {
			if errs := p.validateStep(step, &st); len(errs) > 0 {
				p.renderIssue(w, r, step, st, errs)
				return
			}
		}
		redirectWithMessage(w, r, "/certificates", "issued", 0)
	default:
		http.Error(w, "unknown action", http.StatusBadRequest)
	}
}

// validateStep checks the fields of one step and fills defaults for the next.
func (p *prototype) validateStep(step int, st *certificates.IssueState) map[string]string {
	errs := map[string]string{}
	pr, prOK := p.presets.Get(st.Preset)
	ca, caOK := fixture.CAByID(st.CA)
	switch step {
	case certificates.StepPreset:
		if !prOK {
			errs["preset"] = "Choose a preset."
		}
		if !caOK || ca.KeyMode == "offline" {
			errs["ca"] = "Choose a CA whose key is online."
		}
		if prOK && caOK && st.Days == "" {
			st.Days = strconv.Itoa(min(pr.ValidityDays, ca.MaxValidityDays))
		}
	case certificates.StepNames:
		if !prOK || !caOK {
			errs["cn"] = "Go back and choose a preset and a CA."
			return errs
		}
		validateNames(pr, ca, st, errs)
	case certificates.StepKey:
		validateKey(ca, st, errs)
	}
	return errs
}

func validateNames(pr *preset.Preset, ca fixture.CA, st *certificates.IssueState, errs map[string]string) {
	if st.CommonName == "" {
		errs["cn"] = "Enter a common name."
	} else if len(st.CommonName) > 64 {
		errs["cn"] = "The common name may have at most 64 characters (RFC 5280)."
	}
	offered := pr.SubjectAltNames.Offered
	dns, ips, emails := lines(st.DNS), lines(st.IP), lines(st.Email)
	if !slices.Contains(offered, preset.SANDNS) {
		dns = nil
	}
	if !slices.Contains(offered, preset.SANIP) {
		ips = nil
	}
	if !slices.Contains(offered, preset.SANEmail) {
		emails = nil
	}

	for _, n := range dns {
		switch {
		case !reDNSName.MatchString(n):
			errs["dns"] = n + " is not a valid DNS name. A wildcard may only replace the first label (*.example.lan)."
		case !permittedDNS(ca, n):
			errs["dns"] = n + " is outside the name constraints of " + ca.Name + " (permitted: " + strings.Join(ca.PermittedDNS, ", ") + ")."
		}
	}
	for _, n := range ips {
		addr, err := netip.ParseAddr(n)
		switch {
		case err != nil:
			errs["ip"] = n + " is not an IPv4 or IPv6 address."
		case !permittedIP(ca, addr):
			errs["ip"] = n + " is outside the name constraints of " + ca.Name + " (permitted: " + strings.Join(ca.PermittedIP, ", ") + ")."
		}
	}
	for _, n := range emails {
		local, domain, ok := strings.Cut(n, "@")
		if !ok || local == "" || !reDNSName.MatchString(strings.ToLower(domain)) || strings.ContainsAny(n, " <>") {
			errs["email"] = n + " is not a valid e-mail address."
		}
	}

	if req := pr.SubjectAltNames.RequiredAnyOf; len(req) > 0 {
		have := (slices.Contains(req, preset.SANDNS) && len(dns) > 0) ||
			(slices.Contains(req, preset.SANIP) && len(ips) > 0) ||
			(slices.Contains(req, preset.SANEmail) && len(emails) > 0)
		if !have {
			field := string(req[0])
			if errs[field] == "" {
				errs[field] = sanRule(pr)
			}
		}
	}
}

func permittedDNS(ca fixture.CA, name string) bool {
	if len(ca.PermittedDNS) == 0 {
		return true
	}
	name = strings.TrimPrefix(name, "*.")
	for _, c := range ca.PermittedDNS {
		if (strings.HasPrefix(c, ".") && strings.HasSuffix(name, c)) || name == strings.TrimPrefix(c, ".") {
			return true
		}
	}
	return false
}

func permittedIP(ca fixture.CA, addr netip.Addr) bool {
	if len(ca.PermittedIP) == 0 {
		return true
	}
	for _, c := range ca.PermittedIP {
		if pfx, err := netip.ParsePrefix(c); err == nil && pfx.Contains(addr) {
			return true
		}
	}
	return false
}

func validateKey(ca fixture.CA, st *certificates.IssueState, errs map[string]string) {
	switch st.KeyMode {
	case "csr":
		if _, err := parseCSR(st.CSR); err != nil {
			errs["csr"] = err.Error()
		}
	case "server":
		if !slices.ContainsFunc(keyAlgorithms, func(o view.Option) bool { return o.Value == st.Algorithm }) {
			errs["alg"] = "Choose a key algorithm."
		}
	default:
		errs["csr"] = "Choose how the key is created."
	}
	days, err := strconv.Atoi(st.Days)
	switch {
	case err != nil || days < 1:
		errs["days"] = "Enter the validity in whole days."
	case days > ca.MaxValidityDays:
		errs["days"] = "At most " + strconv.Itoa(ca.MaxValidityDays) + " days – the maximum validity of " + ca.Name + "."
	}
}

type csrError string

func (e csrError) Error() string { return string(e) }

// parseCSR checks that the text is one PKCS#10 request with a valid signature.
// Nothing else from the CSR is trusted (pki-rules.md §6).
func parseCSR(text string) (*x509.CertificateRequest, error) {
	block, rest := pem.Decode([]byte(strings.TrimSpace(text)))
	switch {
	case block == nil:
		return nil, csrError("Paste a PEM certificate request (-----BEGIN CERTIFICATE REQUEST-----).")
	case block.Type != "CERTIFICATE REQUEST" && block.Type != "NEW CERTIFICATE REQUEST":
		return nil, csrError("This is a " + block.Type + ", not a certificate request.")
	case len(strings.TrimSpace(string(rest))) > 0:
		return nil, csrError("Paste exactly one certificate request.")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, csrError("The certificate request can't be parsed.")
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, csrError("The signature of the certificate request is invalid.")
	}
	return csr, nil
}

func sanRule(pr *preset.Preset) string {
	req := pr.SubjectAltNames.RequiredAnyOf
	if len(req) == 0 {
		return "Preset " + pr.Name + " doesn't require subject alternative names."
	}
	names := map[preset.SANType]string{preset.SANDNS: "DNS name", preset.SANIP: "IP address", preset.SANEmail: "e-mail address", preset.SANURI: "URI"}
	var parts []string
	for _, t := range req {
		parts = append(parts, names[t])
	}
	return "Preset " + pr.Name + " needs at least one " + strings.Join(parts, " or ") + "."
}

func (p *prototype) renderIssue(w http.ResponseWriter, r *http.Request, step int, st certificates.IssueState, errs map[string]string) {
	d := certificates.IssueData{Step: step, State: st, Errors: errs, ServerKeyAllowed: true}
	if len(errs) > 0 {
		d.Messages = []view.Message{{Kind: view.MessageError, Text: "Please correct the marked fields."}}
	}
	for _, name := range p.presets.Names() {
		pr, _ := p.presets.Get(name)
		d.Presets = append(d.Presets, certificates.PresetOption{Name: name, Description: pr.Description, ValidityDays: pr.ValidityDays, Selected: name == st.Preset})
	}
	for _, ca := range signingCAs() {
		d.CAs = append(d.CAs, view.Option{Value: ca.ID, Label: ca.Name + " (max. " + strconv.Itoa(ca.MaxValidityDays) + " days)", Selected: ca.ID == st.CA})
	}
	d.Algorithms = withSelected(keyAlgorithms, st.Algorithm)

	pr, prOK := p.presets.Get(st.Preset)
	ca, caOK := fixture.CAByID(st.CA)
	if prOK {
		d.OfferDNS = slices.Contains(pr.SubjectAltNames.Offered, preset.SANDNS)
		d.OfferIP = slices.Contains(pr.SubjectAltNames.Offered, preset.SANIP)
		d.OfferEmail = slices.Contains(pr.SubjectAltNames.Offered, preset.SANEmail)
		d.SANRule = sanRule(pr)
	}
	if prOK && caOK {
		d.MaxDaysHint = "Preset default " + strconv.Itoa(pr.ValidityDays) + " days; " + ca.Name + " allows at most " + strconv.Itoa(ca.MaxValidityDays) + " days."
	}
	if step == certificates.StepReview && prOK && caOK {
		d.Review = p.review(pr, ca, st)
		d.Messages = append(d.Messages, view.Message{Kind: view.MessageInfo, Text: "Prototype: issuing only checks the request – nothing is signed or stored."})
	}
	pg := newPage(r, "Issue certificate", "issue", true, view.Crumb{Label: "Certificates", Href: "/certificates"})
	pg.Description = "Request a certificate from one of the online CAs. Nothing is issued before the last step."
	status := http.StatusOK
	if len(errs) > 0 {
		status = http.StatusUnprocessableEntity
	}
	render(w, r, p.log, status, certificates.Issue(pg, d))
}

// describeKey names the key type and size as admins know it (ECDSA P-256, RSA 3072).
func describeKey(pub any) string {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		return "ECDSA " + k.Curve.Params().Name
	case *rsa.PublicKey:
		return "RSA " + strconv.Itoa(k.N.BitLen())
	case ed25519.PublicKey:
		return "Ed25519"
	default:
		return "unsupported key type"
	}
}

func (p *prototype) review(pr *preset.Preset, ca fixture.CA, st certificates.IssueState) []view.KV {
	key := "From the uploaded request"
	alg := x509.ECDSA
	if st.KeyMode == "server" {
		key = "Generated on the server: " + algorithmLabel(st.Algorithm) + ", stored encrypted"
		if strings.HasPrefix(st.Algorithm, "rsa") {
			alg = x509.RSA
		}
	} else if csr, err := parseCSR(st.CSR); err == nil {
		alg = csr.PublicKeyAlgorithm
		key = "From the uploaded request: " + describeKey(csr.PublicKey)
	}
	ku := pr.KeyUsage.Other
	if alg == x509.RSA {
		ku = pr.KeyUsage.RSA
	}
	eku := strings.Join(pr.ExtKeyUsage.Usages, ", ")
	if pr.ExtKeyUsage.Critical {
		eku += " (critical)"
	}
	days, _ := strconv.Atoi(st.Days)
	until := fixture.Now.Add(time.Duration(days) * 24 * time.Hour)

	rows := []view.KV{
		{Key: "Preset", Value: pr.Name + " – " + pr.Description},
		{Key: "Issuing CA", Value: ca.Name},
		{Key: "Subject", Value: "CN=" + st.CommonName},
	}
	for _, n := range lines(st.DNS) {
		rows = append(rows, view.KV{Key: "DNS name", Value: n})
	}
	for _, n := range lines(st.IP) {
		rows = append(rows, view.KV{Key: "IP address", Value: n, Mono: true})
	}
	for _, n := range lines(st.Email) {
		rows = append(rows, view.KV{Key: "E-mail address", Value: n})
	}
	return append(rows,
		view.KV{Key: "Key", Value: key},
		view.KV{Key: "Key usage", Value: strings.Join(ku, ", ") + " (critical)"},
		view.KV{Key: "Extended key usage", Value: eku},
		view.KV{Key: "Valid", Value: view.Date(fixture.Now) + " – " + view.Date(until) + " (" + strconv.Itoa(days) + " days)"},
	)
}
