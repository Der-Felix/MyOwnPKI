package web

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/ca/preset"
	"github.com/Der-Felix/MyOwnPKI/internal/web/components"
	"github.com/Der-Felix/MyOwnPKI/internal/web/fixture"
	"github.com/Der-Felix/MyOwnPKI/internal/web/pages/admin"
	"github.com/Der-Felix/MyOwnPKI/internal/web/pages/authorities"
	"github.com/Der-Felix/MyOwnPKI/internal/web/pages/certificates"
	"github.com/Der-Felix/MyOwnPKI/internal/web/pages/overview"
	"github.com/Der-Felix/MyOwnPKI/internal/web/view"
)

// The UI prototype (dev mode only): real pages and components, fed from the
// fixture instead of the store. Commands that would change something only
// answer with a message – nothing is issued, revoked or stored.

// maxFormBytes limits every prototype form body.
const maxFormBytes = 64 << 10

// expiringWindow marks certificates as "expires soon".
const expiringWindow = 30 * 24 * time.Hour

type prototype struct {
	log     *slog.Logger
	presets *preset.Set
}

func registerPrototype(mux *http.ServeMux, log *slog.Logger) {
	set, err := preset.Builtin()
	if err != nil {
		// The presets are embedded and tested; failing here is a build defect.
		panic(fmt.Sprintf("load built-in presets: %v", err))
	}
	p := &prototype{log: log, presets: set}

	mux.HandleFunc("GET /{$}", p.dashboard)
	mux.HandleFunc("GET /certificates", p.certificateList)
	mux.HandleFunc("POST /certificates/actions", p.certificateListAction)
	mux.HandleFunc("GET /certificates/new", p.issueStart)
	mux.HandleFunc("POST /certificates/new", p.issueStep)
	mux.HandleFunc("GET /certificates/{id}", p.certificateDetail)
	mux.HandleFunc("GET /certificates/{id}/{tab}", p.certificateDetail)
	mux.HandleFunc("POST /certificates/{id}/actions", p.certificateAction)
	mux.HandleFunc("GET /authorities", p.authorityList)
	mux.HandleFunc("POST /authorities/actions", p.authorityListAction)
	mux.HandleFunc("GET /authorities/{id}", p.authorityDetail)
	mux.HandleFunc("POST /authorities/{id}/actions", p.authorityAction)
	mux.HandleFunc("GET /admin/appearance", p.appearance)
	mux.HandleFunc("POST /admin/appearance", p.saveAppearance)
}

// ---------------------------------------------------------------- helpers

func certStatus(c fixture.Certificate) (view.Status, string) {
	switch {
	case !c.RevokedAt.IsZero():
		return view.StatusCrit, "Revoked"
	case c.NotAfter.Before(fixture.Now):
		return view.StatusCrit, "Expired"
	case c.NotAfter.Sub(fixture.Now) <= expiringWindow:
		return view.StatusWarn, "Expires soon"
	default:
		return view.StatusOK, "Valid"
	}
}

// statusKey is the filter value of a certificate's status.
func statusKey(c fixture.Certificate) string {
	switch s, _ := certStatus(c); {
	case !c.RevokedAt.IsZero():
		return "revoked"
	case s == view.StatusCrit:
		return "expired"
	case s == view.StatusWarn:
		return "expiring"
	default:
		return "valid"
	}
}

func certRow(c fixture.Certificate) view.CertRow {
	st, text := certStatus(c)
	return view.CertRow{
		ID: c.ID, CommonName: c.CommonName, Preset: c.Preset, CA: c.CAID,
		Serial:  c.Serial(),
		Expires: view.Date(c.NotAfter), ExpiresRel: view.Relative(fixture.Now, c.NotAfter),
		Status: st, StatusText: text,
	}
}

// messageFromQuery turns ?msg=<code>&n=<count> into a message bar. Only known
// codes are accepted, so no text from the URL ever reaches the page.
func messageFromQuery(q url.Values) []view.Message {
	n, _ := strconv.Atoi(q.Get("n"))
	n = max(0, min(n, 10000))
	plural := func(word string) string {
		if n == 1 {
			return "1 " + word
		}
		return strconv.Itoa(n) + " " + word + "s"
	}
	none := view.Message{Kind: view.MessageError, Text: "Select at least one certificate first."}
	var m view.Message
	switch q.Get("msg") {
	case "":
		return nil
	case "import":
		m = view.Message{Kind: view.MessageInfo, Text: "Import of a pki.sh directory or PEM files follows in phase 1. Nothing was imported."}
	case "export":
		m = view.Message{Kind: view.MessageInfo, Text: "Prototype: " + plural("certificate") + " would be exported as a ZIP with deployment guides. Nothing was exported."}
	case "renew":
		m = view.Message{Kind: view.MessageInfo, Text: "Prototype: " + plural("certificate") + " would be renewed with the same names, preset and CA. Nothing was issued."}
	case "revoke":
		m = view.Message{Kind: view.MessageWarning, Text: "Revoking " + plural("certificate") + " needs a reason and a fresh second factor (phase 1). Nothing was revoked."}
	case "download":
		m = view.Message{Kind: view.MessageInfo, Text: "Downloads follow in phase 1."}
	case "issued":
		m = view.Message{Kind: view.MessageSuccess, Text: "The request passed all checks. Prototype: nothing was issued – issuing follows in phase 1."}
	case "ca":
		m = view.Message{Kind: view.MessageInfo, Text: "CA operations follow in phase 1 (CA lifecycle). Nothing was changed."}
	case "saved":
		m = view.Message{Kind: view.MessageSuccess, Text: "Appearance saved for this browser."}
	default:
		return nil
	}
	if slices.Contains([]string{"export", "renew", "revoke"}, q.Get("msg")) && n == 0 {
		m = none
	}
	return []view.Message{m}
}

func redirectWithMessage(w http.ResponseWriter, r *http.Request, target, code string, n int) {
	v := url.Values{"msg": {code}}
	if n > 0 {
		v.Set("n", strconv.Itoa(n))
	}
	http.Redirect(w, r, target+"?"+v.Encode(), http.StatusSeeOther)
}

func keyID(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	return colonHex(sum[:20])
}

func colonHex(b []byte) string {
	h := strings.ToUpper(hex.EncodeToString(b))
	parts := make([]string, 0, len(h)/2)
	for i := 0; i < len(h); i += 2 {
		parts = append(parts, h[i:i+2])
	}
	return strings.Join(parts, ":")
}

// ---------------------------------------------------------------- dashboard

func (p *prototype) dashboard(w http.ResponseWriter, r *http.Request) {
	certs := fixture.Certificates()
	counts := map[string]int{}
	var expiring []fixture.Certificate
	for _, c := range certs {
		k := statusKey(c)
		counts[k]++
		if k == "expiring" {
			expiring = append(expiring, c)
		}
	}
	slices.SortFunc(expiring, func(a, b fixture.Certificate) int { return a.NotAfter.Compare(b.NotAfter) })

	d := overview.Data{
		Numbers: []components.Number{
			{Label: "Certificates", Value: strconv.Itoa(len(certs)), Href: "/certificates"},
			{Label: "Valid", Value: strconv.Itoa(counts["valid"]), Href: "/certificates?status=valid"},
			{Label: "Expire in 30 days", Value: strconv.Itoa(counts["expiring"]), Href: "/certificates?status=expiring", Status: view.StatusWarn},
			{Label: "Expired", Value: strconv.Itoa(counts["expired"]), Href: "/certificates?status=expired", Status: view.StatusCrit},
			{Label: "Revoked", Value: strconv.Itoa(counts["revoked"]), Href: "/certificates?status=revoked"},
			{Label: "Certificate authorities", Value: strconv.Itoa(len(fixture.CAs())), Href: "/authorities"},
		},
	}
	for _, c := range expiring {
		d.Expiring = append(d.Expiring, certRow(c))
	}
	for _, ca := range fixture.CAs() {
		if left := ca.CRLNextUpdate.Sub(fixture.Now); left > 0 && left < 3*24*time.Hour {
			d.Messages = append(d.Messages, view.Message{Kind: view.MessageWarning,
				Text: "The revocation list of " + ca.Name + " expires " + view.Relative(fixture.Now, ca.CRLNextUpdate) +
					" (" + view.DateTime(ca.CRLNextUpdate) + "). It is renewed automatically from phase 1 on."})
		}
	}
	for _, a := range fixture.RecentActivity() {
		row := view.ActivityRow{Time: view.DateTime(a.Time), Actor: a.Actor, Action: a.Action, Target: a.Target}
		switch a.Result {
		case "success":
			row.Result, row.ResultText = view.StatusOK, "Success"
		case "denied":
			row.Result, row.ResultText = view.StatusWarn, "Denied by policy"
		default:
			row.Result, row.ResultText = view.StatusCrit, "Failed"
		}
		d.Activity = append(d.Activity, row)
	}
	pg := newPage(r, "Dashboard", "dashboard", true)
	pg.Description = "Tenant " + pg.Tenant + " – sample data as of " + view.DateTime(fixture.Now) + "."
	render(w, r, p.log, http.StatusOK, overview.Page(pg, d))
}

// ---------------------------------------------------------------- certificate list

var statusFilters = []view.Option{
	{Value: "", Label: "All"}, {Value: "valid", Label: "Valid"}, {Value: "expiring", Label: "Expires soon"},
	{Value: "expired", Label: "Expired"}, {Value: "revoked", Label: "Revoked"},
}

func withSelected(opts []view.Option, value string) []view.Option {
	out := slices.Clone(opts)
	for i := range out {
		out[i].Selected = out[i].Value == value
	}
	return out
}

func (p *prototype) certificateList(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	query := strings.TrimSpace(q.Get("q"))
	status, caID, presetName := q.Get("status"), q.Get("ca"), q.Get("preset")

	all := fixture.Certificates()
	d := certificates.ListData{Query: query, Total: len(all), Messages: messageFromQuery(q)}
	for _, c := range all {
		if query != "" && !strings.Contains(strings.ToLower(c.CommonName), strings.ToLower(query)) &&
			!strings.Contains(c.Serial(), strings.ToUpper(query)) {
			continue
		}
		if (status != "" && statusKey(c) != status) || (caID != "" && c.CAID != caID) || (presetName != "" && c.Preset != presetName) {
			continue
		}
		d.Rows = append(d.Rows, certRow(c))
	}

	d.Statuses = withSelected(statusFilters, status)
	cas := []view.Option{{Value: "", Label: "All"}}
	for _, ca := range fixture.CAs() {
		cas = append(cas, view.Option{Value: ca.ID, Label: ca.Name})
	}
	d.CAs = withSelected(cas, caID)
	presets := []view.Option{{Value: "", Label: "All"}}
	for _, n := range p.presets.Names() {
		presets = append(presets, view.Option{Value: n, Label: n})
	}
	d.Presets = withSelected(presets, presetName)

	section := "certificates"
	if status == "expiring" {
		section = "expiring"
	}
	pg := newPage(r, "Certificates", section, true)
	pg.Description = "End-entity certificates of tenant " + pg.Tenant + ", newest first."
	pg.Search = query
	render(w, r, p.log, http.StatusOK, certificates.List(pg, d))
}

func (p *prototype) certificateListAction(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	n := 0
	for _, id := range r.PostForm["id"] {
		if _, ok := fixture.CertificateByID(id); ok {
			n++
		}
	}
	switch a := r.PostForm.Get("action"); a {
	case "import", "export", "renew", "revoke":
		redirectWithMessage(w, r, "/certificates", a, n)
	default:
		http.Error(w, "unknown action", http.StatusBadRequest)
	}
}

// ---------------------------------------------------------------- certificate detail

var certTabs = []struct{ key, label, suffix string }{
	{certificates.TabOverview, "Overview", ""},
	{certificates.TabExtensions, "Extensions", "/extensions"},
	{certificates.TabChain, "Chain", "/chain"},
	{certificates.TabHistory, "History", "/history"},
}

func (p *prototype) certificateDetail(w http.ResponseWriter, r *http.Request) {
	c, ok := fixture.CertificateByID(r.PathValue("id"))
	tab := cmp.Or(r.PathValue("tab"), certificates.TabOverview)
	validTab := slices.ContainsFunc(certTabs, func(t struct{ key, label, suffix string }) bool { return t.key == tab })
	if !ok || !validTab || r.PathValue("tab") == certificates.TabOverview {
		http.NotFound(w, r)
		return
	}
	ca, _ := fixture.CAByID(c.CAID)
	st, text := certStatus(c)
	d := certificates.DetailData{
		ID: c.ID, CommonName: c.CommonName, Status: st, StatusText: text, Tab: tab,
		KeyStored: c.KeyStored, Revoked: !c.RevokedAt.IsZero(), Messages: messageFromQuery(r.URL.Query()),
	}
	for _, t := range certTabs {
		d.Tabs = append(d.Tabs, view.Tab{Label: t.label, Href: "/certificates/" + c.ID + t.suffix, Active: t.key == tab})
	}

	key := "Not stored – the key was generated by the requester (CSR)"
	if c.KeyStored {
		key = "Stored encrypted on the server – export needs step-up authentication"
	}
	d.Overview = []view.KV{
		{Key: "Subject", Value: "CN=" + c.CommonName},
		{Key: "Issuer", Value: ca.Subject},
		{Key: "Serial number", Value: c.Serial(), Mono: true},
		{Key: "SHA-256 fingerprint", Value: view.Fingerprint(c.Fingerprint()), Mono: true},
		{Key: "Valid from", Value: view.DateTime(c.NotBefore)},
		{Key: "Valid until", Value: view.DateTime(c.NotAfter) + " (" + view.Relative(fixture.Now, c.NotAfter) + ")"},
		{Key: "Key algorithm", Value: c.KeyAlgorithm},
		{Key: "Preset", Value: c.Preset},
		{Key: "Private key", Value: key},
		{Key: "Requested by", Value: c.RequestedBy},
	}
	if !c.RevokedAt.IsZero() {
		d.Overview = append(d.Overview, view.KV{Key: "Revoked", Value: view.DateTime(c.RevokedAt) + ", reason: " + c.RevocationReason})
	}
	for _, n := range c.DNS {
		d.Names = append(d.Names, view.KV{Key: "DNS name", Value: n})
	}
	for _, n := range c.IP {
		d.Names = append(d.Names, view.KV{Key: "IP address", Value: n, Mono: true})
	}
	for _, n := range c.Email {
		d.Names = append(d.Names, view.KV{Key: "E-mail address", Value: n})
	}

	d.Extensions = p.extensions(c, ca)
	d.Chain = []certificates.ChainRow{{Role: "Certificate", Subject: "CN=" + c.CommonName, Expires: view.Date(c.NotAfter), Status: st, StatusText: text}}
	for id := c.CAID; id != ""; {
		a, ok := fixture.CAByID(id)
		if !ok {
			break
		}
		role := "Intermediate CA"
		if a.Kind == "root" {
			role = "Root CA"
		}
		d.Chain = append(d.Chain, certificates.ChainRow{Role: role, Subject: a.Subject, Href: "/authorities/" + a.ID,
			Expires: view.Date(a.NotAfter), Status: view.StatusOK, StatusText: "Valid"})
		id = a.ParentID
	}
	history := c.History
	if len(history) == 0 {
		history = []fixture.Event{{Time: c.NotBefore, Actor: c.RequestedBy, Action: "Issued (preset " + c.Preset + ")"}}
	}
	for _, e := range history {
		d.History = append(d.History, certificates.HistoryRow{Time: view.DateTime(e.Time), Actor: e.Actor, Event: e.Action})
	}

	pg := newPage(r, c.CommonName, "certificates", true, view.Crumb{Label: "Certificates", Href: "/certificates"})
	pg.Description = "Issued by " + ca.Name + " with preset " + c.Preset + "."
	render(w, r, p.log, http.StatusOK, certificates.Detail(pg, d))
}

// extensions lists what the CA engine would write, derived from the real preset.
func (p *prototype) extensions(c fixture.Certificate, ca fixture.CA) []certificates.ExtRow {
	rows := []certificates.ExtRow{{Name: "Basic constraints", OID: "2.5.29.19", Critical: true, Value: "CA:FALSE"}}
	if pr, ok := p.presets.Get(c.Preset); ok {
		ku := pr.KeyUsage.Other
		if strings.HasPrefix(c.KeyAlgorithm, "RSA") {
			ku = pr.KeyUsage.RSA
		}
		rows = append(rows, certificates.ExtRow{Name: "Key usage", OID: "2.5.29.15", Critical: true, Value: strings.Join(ku, ", ")})
		if len(pr.ExtKeyUsage.Usages) > 0 {
			rows = append(rows, certificates.ExtRow{Name: "Extended key usage", OID: "2.5.29.37",
				Critical: pr.ExtKeyUsage.Critical, Value: strings.Join(pr.ExtKeyUsage.Usages, ", ")})
		}
		if pr.OCSPNoCheck {
			rows = append(rows, certificates.ExtRow{Name: "OCSP no check", OID: "1.3.6.1.5.5.7.48.1.5", Value: "NULL"})
		}
	}
	var sans []string
	for _, n := range c.DNS {
		sans = append(sans, "DNS:"+n)
	}
	for _, n := range c.IP {
		sans = append(sans, "IP:"+n)
	}
	for _, n := range c.Email {
		sans = append(sans, "email:"+n)
	}
	if len(sans) > 0 {
		rows = append(rows, certificates.ExtRow{Name: "Subject alternative name", OID: "2.5.29.17", Value: strings.Join(sans, ", ")})
	}
	return append(rows,
		certificates.ExtRow{Name: "Subject key identifier", OID: "2.5.29.14", Value: keyID("ski:" + c.ID)},
		certificates.ExtRow{Name: "Authority key identifier", OID: "2.5.29.35", Value: keyID("ski:" + ca.ID)},
		certificates.ExtRow{Name: "Authority information access", OID: "1.3.6.1.5.5.7.1.1",
			Value: "CA issuers: " + ca.PublicBaseURL + "/ca/" + ca.ID + ".crt, OCSP: " + ca.PublicBaseURL + "/ocsp"},
		certificates.ExtRow{Name: "CRL distribution points", OID: "2.5.29.31", Value: ca.PublicBaseURL + "/crl/" + ca.ID + ".crl"},
	)
}

func (p *prototype) certificateAction(w http.ResponseWriter, r *http.Request) {
	c, ok := fixture.CertificateByID(r.PathValue("id"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	target := "/certificates/" + c.ID
	switch r.PostForm.Get("action") {
	case "renew":
		redirectWithMessage(w, r, target, "renew", 1)
	case "export":
		redirectWithMessage(w, r, target, "export", 1)
	case "revoke":
		redirectWithMessage(w, r, target, "revoke", 1)
	case "download-pem", "download-chain":
		redirectWithMessage(w, r, target, "download", 0)
	default:
		http.Error(w, "unknown action", http.StatusBadRequest)
	}
}

// ---------------------------------------------------------------- authorities

func caStatus(ca fixture.CA) (view.Status, string) {
	if ca.NotAfter.Sub(fixture.Now) < 365*24*time.Hour {
		return view.StatusWarn, "Expires within a year"
	}
	return view.StatusOK, "Valid"
}

func issuedBy(id string) []fixture.Certificate {
	var out []fixture.Certificate
	for _, c := range fixture.Certificates() {
		if c.CAID == id {
			out = append(out, c)
		}
	}
	return out
}

func (p *prototype) authorityList(w http.ResponseWriter, r *http.Request) {
	d := authorities.ListData{Messages: messageFromQuery(r.URL.Query())}
	for _, ca := range fixture.CAs() {
		st, text := caStatus(ca)
		d.Rows = append(d.Rows, authorities.Row{
			ID: ca.ID, Name: ca.Name, Kind: ca.Kind, Subject: ca.Subject,
			KeyAlgorithm: ca.KeyAlgorithm, KeyMode: ca.KeyMode,
			ValidUntil: view.Date(ca.NotAfter), ValidUntilRel: view.Relative(fixture.Now, ca.NotAfter),
			MaxValidity: strconv.Itoa(ca.MaxValidityDays) + " days", Issued: strconv.Itoa(len(issuedBy(ca.ID))),
			Status: st, StatusText: text,
		})
	}
	pg := newPage(r, "Certificate authorities", "authorities", true)
	pg.Description = "Root and intermediate CAs of tenant " + pg.Tenant + "."
	render(w, r, p.log, http.StatusOK, authorities.List(pg, d))
}

func (p *prototype) authorityDetail(w http.ResponseWriter, r *http.Request) {
	ca, ok := fixture.CAByID(r.PathValue("id"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	st, text := caStatus(ca)
	issuer := ca.Subject + " (self-signed)"
	if parent, ok := fixture.CAByID(ca.ParentID); ok {
		issuer = parent.Subject
	}
	d := authorities.DetailData{
		ID: ca.ID, Name: ca.Name, Status: st, StatusText: text,
		Messages: messageFromQuery(r.URL.Query()),
		CanSign:  ca.KeyMode != "offline",
		Properties: []view.KV{
			{Key: "Type", Value: ca.Kind},
			{Key: "Subject", Value: ca.Subject},
			{Key: "Issuer", Value: issuer},
			{Key: "Key algorithm", Value: ca.KeyAlgorithm},
			{Key: "Key storage", Value: ca.KeyMode},
			{Key: "Serial number", Value: ca.Serial(), Mono: true},
			{Key: "SHA-256 fingerprint", Value: view.Fingerprint(ca.Fingerprint()), Mono: true},
			{Key: "Valid from", Value: view.DateTime(ca.NotBefore)},
			{Key: "Valid until", Value: view.DateTime(ca.NotAfter) + " (" + view.Relative(fixture.Now, ca.NotAfter) + ")"},
			{Key: "Path length", Value: ca.PathLen},
			{Key: "Maximum validity", Value: strconv.Itoa(ca.MaxValidityDays) + " days for issued certificates"},
			{Key: "Public base URL", Value: ca.PublicBaseURL + " – baked into every certificate, can't change"},
		},
		CRL: []view.KV{
			{Key: "CRL number", Value: strconv.Itoa(ca.CRLNumber)},
			{Key: "This update", Value: view.DateTime(ca.CRLThisUpdate)},
			{Key: "Next update", Value: view.DateTime(ca.CRLNextUpdate) + " (" + view.Relative(fixture.Now, ca.CRLNextUpdate) + ")"},
			{Key: "Distribution point", Value: ca.PublicBaseURL + "/crl/" + ca.ID + ".crl"},
		},
	}
	if len(ca.PermittedDNS) > 0 {
		d.Constraints = append(d.Constraints, view.KV{Key: "Permitted DNS names", Value: strings.Join(ca.PermittedDNS, ", ")})
	}
	if len(ca.PermittedIP) > 0 {
		d.Constraints = append(d.Constraints, view.KV{Key: "Permitted IP ranges", Value: strings.Join(ca.PermittedIP, ", "), Mono: true})
	}
	if len(d.Constraints) > 0 {
		d.Constraints = append(d.Constraints, view.KV{Key: "Marked critical", Value: "Yes – enforced by the server before signing as well"})
	}
	for _, c := range issuedBy(ca.ID) {
		d.Issued = append(d.Issued, certRow(c))
	}
	pg := newPage(r, ca.Name, "authorities", true, view.Crumb{Label: "Certificate authorities", Href: "/authorities"})
	pg.Description = caDescription(ca)
	render(w, r, p.log, http.StatusOK, authorities.Detail(pg, d))
}

func caDescription(ca fixture.CA) string {
	if parent, ok := fixture.CAByID(ca.ParentID); ok {
		return "Intermediate CA, signed by " + parent.Name + ". Key storage: " + ca.KeyMode + "."
	}
	return "Self-signed root CA. Key storage: " + ca.KeyMode + " – it signs only on the air-gapped machine."
}

func (p *prototype) authorityListAction(w http.ResponseWriter, r *http.Request) {
	redirectWithMessage(w, r, "/authorities", "ca", 0)
}

func (p *prototype) authorityAction(w http.ResponseWriter, r *http.Request) {
	ca, ok := fixture.CAByID(r.PathValue("id"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	redirectWithMessage(w, r, "/authorities/"+ca.ID, "ca", 0)
}

// ---------------------------------------------------------------- appearance

var (
	layoutChoices = []admin.Choice{
		{Value: string(view.LayoutA), Label: "A – narrow sidebar", Help: "more room for wide tables"},
		{Value: string(view.LayoutB), Label: "B – standard sidebar", Help: "default"},
		{Value: string(view.LayoutC), Label: "C – no sidebar", Help: "main areas as one line under the header"},
	}
	themeChoices = []admin.Choice{
		{Value: string(view.ThemeLight), Label: "Light", Help: "default"},
		{Value: string(view.ThemeDark), Label: "Dark"},
		{Value: string(view.ThemeSystem), Label: "Follow the operating system"},
	}
	densityChoices = []admin.Choice{
		{Value: string(view.DensityComfortable), Label: "Comfortable"},
		{Value: string(view.DensityCompact), Label: "Compact", Help: "more rows per screen"},
	}
)

func checked(choices []admin.Choice, value string) []admin.Choice {
	out := slices.Clone(choices)
	for i := range out {
		out[i].Checked = out[i].Value == value
	}
	return out
}

func (p *prototype) appearance(w http.ResponseWriter, r *http.Request) {
	pg := newPage(r, "Appearance", "appearance", true, view.Crumb{Label: "Administration"})
	pg.Description = "Layout, color scheme and density for your user on this browser."
	d := admin.AppearanceData{
		Messages:  messageFromQuery(r.URL.Query()),
		Layouts:   checked(layoutChoices, string(pg.Prefs.Layout)),
		Themes:    checked(themeChoices, string(pg.Prefs.Theme)),
		Densities: checked(densityChoices, string(pg.Prefs.Density)),
	}
	render(w, r, p.log, http.StatusOK, admin.Appearance(pg, d))
}

func (p *prototype) saveAppearance(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	f := r.PostForm
	prefs := view.Prefs{Layout: view.Layout(f.Get("layout")), Theme: view.Theme(f.Get("theme")), Density: view.Density(f.Get("density"))}
	if !slices.Contains(view.Layouts, prefs.Layout) || !slices.Contains(view.Themes, prefs.Theme) || !slices.Contains(view.Densities, prefs.Density) {
		http.Error(w, "unknown appearance value", http.StatusBadRequest)
		return
	}
	http.SetCookie(w, prefs.Cookie(r.TLS != nil))
	redirectWithMessage(w, r, "/admin/appearance", "saved", 0)
}
