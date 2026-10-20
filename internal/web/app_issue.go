package web

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/ca/preset"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/web/pages/certificates"
	"github.com/Der-Felix/MyOwnPKI/internal/web/view"
)

// The real "Issue certificate" wizard: Preset → Key → Names → Review. The
// names of a CSR fill the name fields; issued is what the form says and the
// policy allows – never the CSR's names or extensions (owner 2026-10-17:
// the request goes with IgnoreCSRNames). The UI checks only what it must
// to show the next step; the CA engine checks everything again.

// issuableCAs are the CAs the user may issue at that can sign here.
func (a *app) issuableCAs(c *rc) ([]ca.CAInfo, error) {
	all, err := a.d.Engine.CAs(c.r.Context(), c.who())
	if err != nil {
		return nil, err
	}
	return slices.DeleteFunc(all, func(info ca.CAInfo) bool { return !c.canIssueAt(info) }), nil
}

func findCA(cas []ca.CAInfo, id string) (ca.CAInfo, bool) {
	i := slices.IndexFunc(cas, func(info ca.CAInfo) bool { return info.ID == id })
	if i < 0 {
		return ca.CAInfo{}, false
	}
	return cas[i], true
}

func (a *app) issueStart(c *rc) {
	cas, err := a.issuableCAs(c)
	if err != nil {
		c.fail(err)
		return
	}
	if len(cas) == 0 {
		c.notice(http.StatusForbidden, "Issue certificate", view.Message{Kind: view.MessageError, Text: "There is no CA where your role may issue certificates."})
		return
	}
	st := certificates.IssueState{Preset: "server", CA: cas[0].ID, KeyMode: "csr", Algorithm: ca.DefaultKeyAlgorithm}
	if info, ok := findCA(cas, c.r.URL.Query().Get("ca")); ok {
		st.CA = info.ID
	}
	a.renderIssue(c, http.StatusOK, certificates.StepPreset, st, cas, nil, nil)
}

func (a *app) issueStep(c *rc) {
	from, err := strconv.Atoi(c.r.PostFormValue("from"))
	if err != nil || from < certificates.StepPreset || from > certificates.StepReview {
		http.Error(c.w, "invalid step", http.StatusBadRequest)
		return
	}
	cas, err := a.issuableCAs(c)
	if err != nil {
		c.fail(err)
		return
	}
	st := issueStateFromForm(c.r)
	switch c.r.PostFormValue("go") {
	case "back":
		a.renderIssue(c, http.StatusOK, max(certificates.StepPreset, from-1), st, cas, nil, nil)
	case "next":
		var notes []view.Message
		if errs := a.validateIssueStep(c, from, &st, cas, &notes, true); len(errs) > 0 {
			a.renderIssue(c, http.StatusUnprocessableEntity, from, st, cas, errs, notes)
			return
		}
		a.renderIssue(c, http.StatusOK, min(certificates.StepReview, from+1), st, cas, nil, notes)
	case "issue":
		a.issue(c, st, cas)
	default:
		http.Error(c.w, "unknown action", http.StatusBadRequest)
	}
}

// issue signs, then 303 to the new certificate (Post/Redirect/Get: a reload
// never issues twice). Refusals of the engine stay on the review step.
func (a *app) issue(c *rc, st certificates.IssueState, cas []ca.CAInfo) {
	for step := certificates.StepPreset; step < certificates.StepReview; step++ {
		var notes []view.Message
		if errs := a.validateIssueStep(c, step, &st, cas, &notes, false); len(errs) > 0 {
			a.renderIssue(c, http.StatusUnprocessableEntity, step, st, cas, errs, notes)
			return
		}
	}
	info, _ := findCA(cas, st.CA)
	days, _ := strconv.Atoi(st.Days)
	req := ca.Request{
		CA: info.Name, Preset: st.Preset, Subject: ca.Subject{CommonName: st.CommonName},
		DNSNames: lines(st.DNS), IPAddresses: lines(st.IP), EmailAddresses: lines(st.Email),
		ValidityDays: days, Who: c.who(),
	}
	if st.KeyMode == "csr" {
		req.CSR, req.IgnoreCSRNames = []byte(st.CSR), true
	} else {
		req.KeyAlgorithm = st.Algorithm
	}
	out, err := a.d.Engine.Issue(c.r.Context(), req)
	var denied *ca.DeniedError
	switch {
	case err == nil:
	case errors.Is(err, keys.ErrSealed):
		a.renderIssue(c, http.StatusServiceUnavailable, certificates.StepReview, st, cas, nil,
			[]view.Message{{Kind: view.MessageError, Text: "The server is sealed – nothing was issued. An instance admin must unseal it first."}})
		return
	case errors.Is(err, authz.ErrDenied):
		c.fail(err)
		return
	case errors.As(err, &denied):
		msgs := []view.Message{{Kind: view.MessageError, Text: "Nothing was issued – the policy refused the request:"}}
		for _, r := range denied.Reasons {
			msgs = append(msgs, view.Message{Kind: view.MessageError, Text: r})
		}
		a.renderIssue(c, http.StatusUnprocessableEntity, certificates.StepReview, st, cas, nil, msgs)
		return
	default:
		a.log.ErrorContext(c.r.Context(), "issue", slog.Any("error", err))
		a.renderIssue(c, http.StatusInternalServerError, certificates.StepReview, st, cas, nil,
			[]view.Message{{Kind: view.MessageError, Text: "Issuing failed – the server log has the details."}})
		return
	}
	msgs := []view.Message{{Kind: view.MessageSuccess, Text: "Certificate issued, serial number " + out.SerialHex + "."}}
	for _, n := range out.Notes {
		msgs = append(msgs, view.Message{Kind: view.MessageInfo, Text: n + "."})
	}
	for _, w := range out.Warnings {
		msgs = append(msgs, view.Message{Kind: view.MessageWarning, Text: w + "."})
	}
	c.setFlash(msgs...)
	c.redirect("/certificates/" + out.ID)
}

// validateIssueStep checks one step and fills defaults for the next. fill:
// the user moves on from this step, so the CSR's names may fill the name
// fields – never when the final "issue" checks every step again, which would
// silently replace what the form says.
func (a *app) validateIssueStep(c *rc, step int, st *certificates.IssueState, cas []ca.CAInfo, notes *[]view.Message, fill bool) map[string]string {
	errs := map[string]string{}
	pr, prOK := a.d.Presets.Get(st.Preset)
	info, caOK := findCA(cas, st.CA)
	switch step {
	case certificates.StepPreset:
		if !prOK {
			errs["preset"] = "Choose a preset."
		}
		if !caOK {
			errs["ca"] = "Choose a CA where you may issue."
		}
		if prOK && caOK && st.Days == "" {
			st.Days = strconv.FormatInt(min(int64(pr.ValidityDays), info.MaxValidityDays), 10)
		}
	case certificates.StepKey:
		if !prOK || !caOK {
			errs["csr"] = "Go back and choose a preset and a CA."
			return errs
		}
		a.validateKey(c, pr, info, st, errs, notes, fill)
	case certificates.StepNames:
		if len([]rune(st.CommonName)) > 64 {
			errs["cn"] = "The common name may have at most 64 characters (RFC 5280)."
		}
	}
	return errs
}

func (a *app) validateKey(c *rc, pr *preset.Preset, info ca.CAInfo, st *certificates.IssueState, errs map[string]string, notes *[]view.Message, fill bool) {
	switch st.KeyMode {
	case "csr":
		if text, ok, msg := uploadedCSR(c.r); msg != "" {
			errs["csr"] = msg
			return
		} else if ok {
			st.CSR = text
		}
		csr, err := parseCSR(st.CSR)
		if err != nil {
			errs["csr"] = err.Error()
			return
		}
		if fill {
			prefill(pr, csr, st, notes)
		}
	case "server":
		allowed, err := a.serverKeygen(c)
		switch {
		case err != nil || !allowed:
			errs["alg"] = "This tenant doesn't allow keys generated on the server – upload a CSR."
		case !slices.Contains(ca.GeneratedAlgorithms, st.Algorithm):
			errs["alg"] = "Choose a key algorithm."
		}
		st.CSR, st.Prefilled = "", ""
	default:
		errs["csr"] = "Choose how the key is created."
	}
	days, err := strconv.Atoi(st.Days)
	switch {
	case err != nil || days < 1:
		errs["days"] = "Enter the validity in whole days."
	case int64(days) > info.MaxValidityDays:
		errs["days"] = "At most " + strconv.FormatInt(info.MaxValidityDays, 10) + " days – the maximum validity of " + info.Name + "."
	}
}

// uploadedCSR reads the uploaded CSR file, PEM or DER, as PEM text.
// ok = a file was uploaded; msg = what is wrong with it.
func uploadedCSR(r *http.Request) (text string, ok bool, msg string) {
	if r.MultipartForm == nil || len(r.MultipartForm.File["csrfile"]) == 0 {
		return "", false, ""
	}
	fh := r.MultipartForm.File["csrfile"][0]
	if fh.Size == 0 {
		return "", false, ""
	}
	if fh.Size > maxCSRFile {
		return "", true, "The file is larger than 64 KiB – a certificate request is a few KiB at most."
	}
	f, err := fh.Open()
	if err != nil {
		return "", true, "The file can't be read."
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxCSRFile+1))
	if err != nil || len(data) > maxCSRFile {
		return "", true, "The file can't be read."
	}
	if bytes.Contains(data, []byte("-----BEGIN")) {
		return string(data), true, ""
	}
	// DER: one request, nothing after it.
	if _, err := x509.ParseCertificateRequest(data); err != nil {
		return "", true, "The file is neither a PEM nor a DER certificate request."
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: data})), true, ""
}

// prefill puts the CSR's names into the name fields – once per CSR, so the
// user can change them afterwards. Types the preset doesn't take are left
// out and named.
func prefill(pr *preset.Preset, csr *x509.CertificateRequest, st *certificates.IssueState, notes *[]view.Message) {
	sum := sha256.Sum256(csr.Raw)
	fp := hex.EncodeToString(sum[:8])
	if st.Prefilled == fp {
		return
	}
	st.Prefilled = fp
	offered := func(t preset.SANType) bool { return slices.Contains(pr.SubjectAltNames.Offered, t) }
	var dropped []string
	take := func(t preset.SANType, names []string) string {
		if !offered(t) {
			if len(names) > 0 {
				dropped = append(dropped, strconv.Itoa(len(names))+" "+string(t))
			}
			return ""
		}
		return strings.Join(names, "\n")
	}
	var ips []string
	for _, ip := range csr.IPAddresses {
		ips = append(ips, ip.String())
	}
	st.CommonName = csr.Subject.CommonName
	st.DNS = take(preset.SANDNS, csr.DNSNames)
	st.IP = take(preset.SANIP, ips)
	st.Email = take(preset.SANEmail, csr.EmailAddresses)
	if len(csr.URIs) > 0 {
		dropped = append(dropped, strconv.Itoa(len(csr.URIs))+" uri")
	}
	text := "The names of the request fill the next step – check them: what the form says is issued, not what the request asks for."
	if len(dropped) > 0 {
		text += " Left out, the preset doesn't take them: " + strings.Join(dropped, ", ") + " name(s)."
	}
	*notes = append(*notes, view.Message{Kind: view.MessageInfo, Text: text})
}

func (a *app) renderIssue(c *rc, status, step int, st certificates.IssueState, cas []ca.CAInfo, errs map[string]string, msgs []view.Message) {
	allowed, _ := a.serverKeygen(c)
	sealed := a.d.Keys.Status().Sealed
	d := certificates.IssueData{
		Step: step, State: st, Errors: errs, ServerKeyAllowed: allowed,
		CSRF: c.sess.CSRFToken, Upload: true, CanIssue: !sealed,
		Messages: append(c.messages(), msgs...),
	}
	if len(errs) > 0 {
		d.Messages = append(d.Messages, view.Message{Kind: view.MessageError, Text: "Please correct the marked fields."})
	}
	for _, name := range a.d.Presets.Names() {
		pr, _ := a.d.Presets.Get(name)
		d.Presets = append(d.Presets, certificates.PresetOption{Name: name, Description: pr.Description, ValidityDays: pr.ValidityDays, Selected: name == st.Preset})
	}
	for _, info := range cas {
		d.CAs = append(d.CAs, view.Option{Value: info.ID, Label: info.Name + " (max. " + strconv.FormatInt(info.MaxValidityDays, 10) + " days)", Selected: info.ID == st.CA})
	}
	d.Algorithms = withSelected(keyAlgorithms, st.Algorithm)
	pr, prOK := a.d.Presets.Get(st.Preset)
	info, caOK := findCA(cas, st.CA)
	if prOK {
		d.OfferDNS = slices.Contains(pr.SubjectAltNames.Offered, preset.SANDNS)
		d.OfferIP = slices.Contains(pr.SubjectAltNames.Offered, preset.SANIP)
		d.OfferEmail = slices.Contains(pr.SubjectAltNames.Offered, preset.SANEmail)
		d.SANRule = sanRule(pr)
	}
	if prOK && caOK {
		d.MaxDaysHint = "Preset default " + strconv.Itoa(pr.ValidityDays) + " days; " + info.Name + " allows at most " + strconv.FormatInt(info.MaxValidityDays, 10) + " days."
	}
	if step == certificates.StepReview && prOK && caOK {
		d.Review = reviewRows(pr, info, st)
		if sealed {
			d.Messages = append(d.Messages, view.Message{Kind: view.MessageWarning, Text: "The server is sealed – issuing is possible after an unseal."})
		}
	}
	p := c.page("Issue certificate", "issue", view.Crumb{Label: "Certificates", Href: "/certificates"})
	p.Description = "Request a certificate from one of the online CAs. Nothing is issued before the last step."
	render(c.w, c.r, a.log, status, certificates.Issue(p, d))
}

func reviewRows(pr *preset.Preset, info ca.CAInfo, st certificates.IssueState) []view.KV {
	key := "Generated on the server: " + algorithmLabel(st.Algorithm) + ", stored encrypted"
	if st.KeyMode == "csr" {
		key = "From the uploaded request"
		if csr, err := parseCSR(st.CSR); err == nil {
			key += ": " + describeKey(csr.PublicKey)
		}
	}
	rows := []view.KV{
		{Key: "Preset", Value: pr.Name + " – " + pr.Description},
		{Key: "Issuing CA", Value: info.Name},
	}
	if st.CommonName != "" {
		rows = append(rows, view.KV{Key: "Common name", Value: st.CommonName})
	} else {
		rows = append(rows, view.KV{Key: "Common name", Value: "taken from the first name"})
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
		view.KV{Key: "Validity", Value: st.Days + " days"},
		view.KV{Key: "Extensions", Value: "from the preset " + pr.Name + " – never from the request"},
	)
}

// serverKeygen asks the tenant switch allow_server_keygen.
func (a *app) serverKeygen(c *rc) (bool, error) {
	if a.d.Engine.ServerKeygen == nil {
		return false, nil
	}
	return a.d.Engine.ServerKeygen(c.r.Context())
}
