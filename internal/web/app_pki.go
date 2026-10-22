package web

import (
	"bytes"
	"cmp"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/web/components"
	"github.com/Der-Felix/MyOwnPKI/internal/web/pages/admin"
	"github.com/Der-Felix/MyOwnPKI/internal/web/pages/authorities"
	"github.com/Der-Felix/MyOwnPKI/internal/web/pages/certificates"
	"github.com/Der-Felix/MyOwnPKI/internal/web/pages/design"
	"github.com/Der-Felix/MyOwnPKI/internal/web/pages/overview"
	"github.com/Der-Felix/MyOwnPKI/internal/web/view"
)

// caWarnBefore: a CA certificate that ends within it needs attention.
const caWarnBefore = 90 * 24 * time.Hour

// ---------------------------------------------------------------- helpers

func (a *app) certStatus(i *ca.CertificateInfo) (view.Status, string) {
	switch {
	case i.Status == ca.CertRevoked:
		return view.StatusCrit, "Revoked"
	case i.Status == ca.CertExpired:
		return view.StatusCrit, "Expired"
	case i.NotAfter.Sub(a.now()) <= ca.ExpiringWindow:
		return view.StatusWarn, "Expires soon"
	default:
		return view.StatusOK, "Valid"
	}
}

func (a *app) certRow(i *ca.CertificateInfo) view.CertRow {
	st, text := a.certStatus(i)
	return view.CertRow{
		ID: i.ID, CommonName: cmp.Or(i.CommonName, i.Serial), Preset: i.Preset, CA: i.CAName, Serial: i.Serial,
		Expires: view.Date(i.NotAfter), ExpiresRel: view.Relative(a.now(), i.NotAfter), Status: st, StatusText: text,
	}
}

// genTime reads a stored generation time ("" = none).
func genTime(s string) time.Time {
	t, _ := time.Parse(time.RFC3339, s)
	return t
}

// current is the signing generation of a CA, if any.
func current(info ca.CAInfo) (ca.GenerationInfo, bool) {
	for _, g := range info.Generations {
		if g.Current {
			return g, true
		}
	}
	return ca.GenerationInfo{}, false
}

func (a *app) caStatus(info ca.CAInfo) (view.Status, string) {
	g, ok := current(info)
	switch {
	case info.Status == ca.StatusPendingSignature:
		return view.StatusInfo, "Waits for its signature"
	case info.Status != ca.StatusActive:
		return view.StatusNeutral, info.Status
	case !ok:
		return view.StatusNeutral, "No certificate"
	case g.Revoked != "":
		return view.StatusCrit, "Revoked"
	case !genTime(g.NotAfter).After(a.now()):
		return view.StatusCrit, "Expired"
	case genTime(g.NotAfter).Sub(a.now()) < caWarnBefore:
		return view.StatusWarn, "Expires soon"
	}
	return view.StatusOK, "Valid"
}

// canIssueAt: an intermediate that signs on this server, and the user may
// issue there. A root issues no end-entity certificates (owner 2026-10-18).
func (c *rc) canIssueAt(info ca.CAInfo) bool {
	_, ok := current(info)
	return ok && info.Kind != ca.KindRoot && info.Status == ca.StatusActive && info.KeyMode == ca.KeyModeOnlineEncrypted && c.may(authz.IssueCert, info.Name)
}

func pemBlocks(ders ...[]byte) []byte {
	var b bytes.Buffer
	for _, d := range ders {
		_ = pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: d})
	}
	return b.Bytes()
}

// downloadName makes a safe file name from a CN, or falls back.
func downloadName(cn, fallback string) string {
	cn = strings.ToLower(strings.ReplaceAll(cn, "*", "wildcard"))
	var b strings.Builder
	for _, r := range cn {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	if s := strings.Trim(b.String(), "._"); s != "" && len(s) <= 64 {
		return s
	}
	return fallback
}

func (c *rc) attachment(contentType, name string, data []byte) {
	h := c.w.Header()
	h.Set("Content-Type", contentType)
	h.Set("Content-Disposition", `attachment; filename="`+name+`"`)
	h.Set("Cache-Control", "no-store")
	c.w.WriteHeader(http.StatusOK)
	_, _ = c.w.Write(data) // #nosec G705 -- a download (attachment, fixed type, nosniff from SecurityHeaders), never rendered as HTML
}

// ---------------------------------------------------------------- dashboard

func (a *app) dashboard(c *rc) {
	ctx := c.r.Context()
	total, _, err := a.d.Engine.CertificateCounts(ctx, c.who())
	if err != nil {
		c.fail(err)
		return
	}
	cas, err := a.d.Engine.CAs(ctx, c.who())
	if err != nil {
		c.fail(err)
		return
	}
	n := func(v int64) string { return strconv.FormatInt(v, 10) }
	d := overview.Data{
		Real:     true,
		Messages: c.messages(),
		Numbers: []components.Number{
			{Label: "Certificates", Value: n(total.Total()), Href: "/certificates"},
			{Label: "Valid", Value: n(total.Valid), Href: "/certificates?status=valid"},
			{Label: "Expire in 30 days", Value: n(total.Expiring), Href: "/certificates?status=expiring", Status: alarm(total.Expiring, view.StatusWarn)},
			{Label: "Expired", Value: n(total.Expired), Href: "/certificates?status=expired", Status: alarm(total.Expired, view.StatusCrit)},
			{Label: "Revoked", Value: n(total.Revoked), Href: "/certificates?status=revoked"},
			{Label: "Certificate authorities", Value: strconv.Itoa(len(cas)), Href: "/authorities"},
		},
		Attention: []view.Message{},
	}
	sealed := a.d.Keys.Status().Sealed
	if a.d.ACME != nil {
		if waiting, werr := a.d.ACME.Waiting(ctx); werr == nil && waiting > 0 {
			if sealed {
				d.Attention = append(d.Attention, view.Message{Kind: view.MessageWarning, Text: strconv.FormatInt(waiting, 10) + " ACME order(s) wait for the unseal – their certificates are issued as soon as the server is unsealed.", Href: "/unseal", LinkText: "Unseal"})
			} else {
				d.Attention = append(d.Attention, view.Message{Kind: view.MessageInfo, Text: strconv.FormatInt(waiting, 10) + " ACME order(s) are being issued."})
			}
		}
	}
	for _, info := range cas {
		href := "/authorities/" + info.ID
		if info.Status == ca.StatusPendingSignature {
			d.Attention = append(d.Attention, view.Message{Kind: view.MessageInfo, Text: info.Name + " waits for the certificate from its offline root.", Href: href, LinkText: "Open"})
		}
		for _, g := range info.Generations {
			if g.CRL != nil && g.CRL.State != ca.CRLOK && g.CRL.State != ca.CRLRenewDue {
				kind := view.MessageWarning
				if g.CRL.State == ca.CRLExpired {
					kind = view.MessageError
				}
				d.Attention = append(d.Attention, view.Message{Kind: kind, Text: "CRL of " + info.Name + "/" + strconv.FormatInt(g.Generation, 10) + ": " + g.CRL.Message(sealed) + ".", Href: href, LinkText: "Open"})
			}
		}
		if st, text := a.caStatus(info); st == view.StatusWarn || st == view.StatusCrit {
			g, _ := current(info)
			d.Attention = append(d.Attention, view.Message{Kind: view.MessageWarning, Text: "The certificate of " + info.Name + ": " + strings.ToLower(text) + " (" + view.Date(genTime(g.NotAfter)) + ").", Href: href, LinkText: "Open"})
		}
	}
	page, err := a.d.Engine.Certificates(ctx, c.who(), ca.CertificateFilter{Status: ca.CertValid, ExpiresBefore: a.now().Add(ca.ExpiringWindow), Limit: 10})
	if err != nil {
		c.fail(err)
		return
	}
	for i := range page.Items {
		d.Expiring = append(d.Expiring, a.certRow(&page.Items[i]))
	}
	p := c.page("Dashboard", "dashboard")
	p.Description = "Tenant " + a.d.Tenant + " as of " + view.DateTime(a.now()) + "."
	render(c.w, c.r, a.log, http.StatusOK, overview.Page(p, d))
}

// ---------------------------------------------------------------- certificates

var realStatusFilters = []view.Option{
	{Value: "", Label: "All"}, {Value: "valid", Label: "Valid"}, {Value: "expiring", Label: "Expires soon"},
	{Value: "expired", Label: "Expired"}, {Value: "revoked", Label: "Revoked"},
}

func (a *app) certificateList(c *rc) {
	ctx := c.r.Context()
	q := c.r.URL.Query()
	query := strings.TrimSpace(q.Get("q"))
	status, caID, presetName, cursor := q.Get("status"), q.Get("ca"), q.Get("preset"), q.Get("cursor")
	if len(query) > 253 || len(cursor) > 64 || !slices.ContainsFunc(realStatusFilters, func(o view.Option) bool { return o.Value == status }) {
		c.notice(http.StatusBadRequest, "Certificates", view.Message{Kind: view.MessageError, Text: "Invalid filter."})
		return
	}
	f := ca.CertificateFilter{CAID: caID, Preset: presetName, Status: status, Search: query, Cursor: cursor}
	if status == "expiring" {
		f.Status, f.ExpiresBefore = ca.CertValid, a.now().Add(ca.ExpiringWindow)
	}
	page, err := a.d.Engine.Certificates(ctx, c.who(), f)
	if err != nil {
		c.fail(err)
		return
	}
	total, _, err := a.d.Engine.CertificateCounts(ctx, c.who())
	if err != nil {
		c.fail(err)
		return
	}
	cas, err := a.d.Engine.CAs(ctx, c.who())
	if err != nil {
		c.fail(err)
		return
	}
	d := certificates.ListData{Real: true, Query: query, Total: int(total.Total()), Messages: c.messages()}
	for i := range page.Items {
		d.Rows = append(d.Rows, a.certRow(&page.Items[i]))
	}
	if page.NextCursor != "" {
		nq := url.Values{}
		for k, v := range q {
			nq[k] = v
		}
		nq.Set("cursor", page.NextCursor)
		d.NextHref = "/certificates?" + nq.Encode()
	}
	if cursor != "" {
		fq := url.Values{}
		for k, v := range q {
			fq[k] = v
		}
		fq.Del("cursor")
		d.FirstHref = "/certificates?" + fq.Encode()
	}
	d.Statuses = withSelected(realStatusFilters, status)
	caOpts := []view.Option{{Value: "", Label: "All"}}
	for _, info := range cas {
		caOpts = append(caOpts, view.Option{Value: info.ID, Label: info.Name})
		if c.canIssueAt(info) {
			d.CanIssue = true
		}
	}
	d.CAs = withSelected(caOpts, caID)
	presetOpts := []view.Option{{Value: "", Label: "All"}}
	for _, name := range a.d.Presets.Names() {
		presetOpts = append(presetOpts, view.Option{Value: name, Label: name})
	}
	d.Presets = withSelected(presetOpts, presetName)
	section := "certificates"
	if status == "expiring" {
		section = "expiring"
	}
	p := c.page("Certificates", section)
	p.Description = "End-entity certificates of tenant " + a.d.Tenant + ", newest first."
	p.Search = query
	render(c.w, c.r, a.log, http.StatusOK, certificates.List(p, d))
}

var realCertTabs = []struct{ key, label, suffix string }{
	{certificates.TabOverview, "Overview", ""},
	{certificates.TabExtensions, "Extensions", "/extensions"},
	{certificates.TabChain, "Chain", "/chain"},
}

func (a *app) certificateDetail(c *rc) {
	ctx := c.r.Context()
	id := c.r.PathValue("id")
	tab := cmp.Or(c.r.PathValue("tab"), certificates.TabOverview)
	if !slices.ContainsFunc(realCertTabs, func(t struct{ key, label, suffix string }) bool { return t.key == tab }) || c.r.PathValue("tab") == certificates.TabOverview {
		c.fail(ca.ErrNotFound)
		return
	}
	info, err := a.d.Engine.Certificate(ctx, c.who(), id)
	if err != nil {
		c.fail(err)
		return
	}
	certDER, _, err := a.d.Engine.CertificateChain(ctx, c.who(), id)
	if err != nil {
		c.fail(err)
		return
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		c.fail(err)
		return
	}
	cas, err := a.d.Engine.CAs(ctx, c.who())
	if err != nil {
		c.fail(err)
		return
	}
	st, text := a.certStatus(info)
	d := certificates.DetailData{
		ID: info.ID, CommonName: cmp.Or(info.CommonName, info.Serial), Status: st, StatusText: text, Tab: tab,
		KeyStored: info.KeyStored, Revoked: info.Status == ca.CertRevoked, Messages: c.messages(),
		Real: &certificates.RealActions{CSRF: c.sess.CSRFToken, CanDownloadKey: info.KeyStored && c.may(authz.DownloadKey, info.CAName),
			CanRenew: info.Source != "external" && info.Preset != "" && c.may(authz.IssueCert, info.CAName), CanRevoke: info.Source != "external" && c.may(authz.RevokeCert, info.CAName)},
	}
	for _, t := range realCertTabs {
		d.Tabs = append(d.Tabs, view.Tab{Label: t.label, Href: "/certificates/" + info.ID + t.suffix, Active: t.key == tab})
	}
	key := "Not on the server – the key was made by the requester (CSR)"
	if info.KeyStored {
		key = "Stored encrypted on the server – the export needs a fresh second factor; you may delete it from the server with the export"
	}
	d.Overview = []view.KV{
		{Key: "Subject", Value: info.Subject},
		{Key: "Issuer", Value: cert.Issuer.String() + " (" + info.CAName + ")"},
		{Key: "Serial number", Value: info.Serial, Mono: true},
		{Key: "SHA-256 fingerprint", Value: view.Fingerprint(info.Fingerprint), Mono: true},
		{Key: "Valid from", Value: view.DateTime(info.NotBefore)},
		{Key: "Valid until", Value: view.DateTime(info.NotAfter) + " (" + view.Relative(a.now(), info.NotAfter) + ")"},
		{Key: "Key algorithm", Value: info.KeyAlgorithm},
		{Key: "Preset", Value: info.Preset},
		{Key: "Private key", Value: key},
		{Key: "Requested by", Value: info.RequestedBy},
	}
	if info.RevokedAt != nil {
		d.Overview = append(d.Overview, view.KV{Key: "Revoked", Value: view.DateTime(*info.RevokedAt) + ", reason: " + info.RevocationReason})
	}
	for _, n := range info.DNSNames {
		d.Names = append(d.Names, view.KV{Key: "DNS name", Value: n})
	}
	for _, n := range info.IPs {
		d.Names = append(d.Names, view.KV{Key: "IP address", Value: n, Mono: true})
	}
	for _, n := range info.Emails {
		d.Names = append(d.Names, view.KV{Key: "E-mail address", Value: n})
	}
	for _, n := range info.URIs {
		d.Names = append(d.Names, view.KV{Key: "URI", Value: n})
	}
	d.Extensions = extensionRows(cert)
	d.Chain = a.chainRows(cas, info, st, text)
	p := c.page(d.CommonName, "certificates", view.Crumb{Label: "Certificates", Href: "/certificates"})
	p.Description = "Issued by " + info.CAName + " with preset " + info.Preset + "."
	render(c.w, c.r, a.log, http.StatusOK, certificates.Detail(p, d))
}

// chainRows: the certificate, its CAs and the root. Servers send the
// certificate and the intermediates; the root is the client's trust anchor.
func (a *app) chainRows(cas []ca.CAInfo, info *ca.CertificateInfo, st view.Status, text string) []certificates.ChainRow {
	rows := []certificates.ChainRow{{Role: "Certificate", Subject: info.Subject, Expires: view.Date(info.NotAfter), Status: st, StatusText: text}}
	byName := map[string]ca.CAInfo{}
	for _, c := range cas {
		byName[c.Name] = c
	}
	name, gen := info.CAName, info.CAGeneration
	for range 8 {
		c, ok := byName[name]
		if !ok {
			rows = append(rows, certificates.ChainRow{Role: "CA", Subject: name + " (you may not see this CA)"})
			break
		}
		var g ca.GenerationInfo
		for _, x := range c.Generations {
			if x.Generation == gen {
				g = x
			}
		}
		role := "Intermediate CA – sent by the server"
		if c.Kind == ca.KindRoot {
			role = "Root CA – trust anchor, not sent"
		}
		cst, ctext := a.caStatus(c)
		rows = append(rows, certificates.ChainRow{Role: role, Subject: g.Subject, Href: "/authorities/" + c.ID, Expires: view.Date(genTime(g.NotAfter)), Status: cst, StatusText: ctext})
		parent, pgen, ok := strings.Cut(g.Issuer, "/")
		if !ok {
			break
		}
		n, err := strconv.ParseInt(pgen, 10, 64)
		if err != nil {
			break
		}
		name, gen = parent, n
	}
	return rows
}

func (a *app) certificateDownload(c *rc) {
	ctx := c.r.Context()
	id, format := c.r.PathValue("id"), c.r.PathValue("format")
	if !slices.Contains([]string{"pem", "chain", "fullchain", "der"}, format) {
		c.fail(ca.ErrNotFound)
		return
	}
	info, err := a.d.Engine.Certificate(ctx, c.who(), id)
	if err != nil {
		c.fail(err)
		return
	}
	cert, chain, err := a.d.Engine.CertificateChain(ctx, c.who(), id)
	if err != nil {
		c.fail(err)
		return
	}
	name := downloadName(info.CommonName, info.Serial)
	switch format {
	case "der":
		c.attachment("application/pkix-cert", name+".crt", cert)
	case "chain":
		c.attachment("application/pem-certificate-chain", name+"-chain.pem", pemBlocks(chain...))
	case "fullchain":
		c.attachment("application/pem-certificate-chain", name+"-fullchain.pem", pemBlocks(append([][]byte{cert}, chain...)...))
	default:
		c.attachment("application/pem-certificate-chain", name+".pem", pemBlocks(cert))
	}
}

// keyDownload is the one POST that answers with content: the key itself.
// Without a fresh second factor it goes to the step-up page and back to the
// certificate – the download is then started again by hand.
func (a *app) keyDownload(c *rc) {
	ctx := c.r.Context()
	id := c.r.PathValue("id")
	detail := "/certificates/" + url.PathEscape(id)
	key, err := a.d.Engine.ExportKey(ctx, c.who(), id)
	switch {
	case errors.Is(err, authz.ErrStepUpRequired):
		c.redirect(loginURL("/step-up", detail))
		return
	case errors.Is(err, ca.ErrNoStoredKey):
		c.setFlash(view.Message{Kind: view.MessageError, Text: ca.ErrNoStoredKey.Error() + "."})
		c.redirect(detail)
		return
	case errors.Is(err, keys.ErrSealed):
		c.setFlash(view.Message{Kind: view.MessageError, Text: "The server is sealed – the key can only be decrypted after an unseal."})
		c.redirect(detail)
		return
	case err != nil:
		c.fail(err)
		return
	}
	defer clear(key)
	info, err := a.d.Engine.Certificate(ctx, c.who(), id)
	if err != nil {
		c.fail(err)
		return
	}
	c.attachment("application/x-pem-file", downloadName(info.CommonName, info.Serial)+".key.pem", key)
}

// ---------------------------------------------------------------- authorities

func (a *app) authorityList(c *rc) {
	ctx := c.r.Context()
	cas, err := a.d.Engine.CAs(ctx, c.who())
	if err != nil {
		c.fail(err)
		return
	}
	_, perCA, err := a.d.Engine.CertificateCounts(ctx, c.who())
	if err != nil {
		c.fail(err)
		return
	}
	d := authorities.ListData{Real: true, CanManage: c.may(authz.ManageCA, ""), Messages: c.messages()}
	for _, info := range cas {
		st, text := a.caStatus(info)
		g, _ := current(info)
		row := authorities.Row{
			ID: info.ID, Name: info.Name, Kind: info.Kind, Subject: g.Subject, KeyAlgorithm: g.KeyAlgorithm, KeyMode: keyStorage(info.KeyMode),
			MaxValidity: maxValidity(info), Issued: signedText(info, perCA[info.ID].Total(), cas),
			Status: st, StatusText: text,
		}
		if t := genTime(g.NotAfter); !t.IsZero() {
			row.ValidUntil, row.ValidUntilRel = view.Date(t), view.Relative(a.now(), t)
		}
		d.Rows = append(d.Rows, row)
	}
	p := c.page("Certificate authorities", "authorities")
	p.Description = "Root and intermediate CAs of tenant " + a.d.Tenant + "."
	render(c.w, c.r, a.log, http.StatusOK, authorities.List(p, d))
}

func (a *app) authorityDetail(c *rc) {
	ctx := c.r.Context()
	info, err := a.d.Engine.CA(ctx, c.who(), c.r.PathValue("id"))
	if err != nil {
		c.fail(err)
		return
	}
	st, text := a.caStatus(*info)
	g, _ := current(*info)
	issuer := "self-signed"
	if info.Parent != "" {
		issuer = info.Parent + " (" + g.Issuer + ")"
	}
	d := authorities.DetailData{
		ID: info.ID, Name: info.Name, Status: st, StatusText: text, Messages: c.messages(),
		CanSign: info.KeyMode == ca.KeyModeOnlineEncrypted,
		Real: &authorities.RealActions{CanIssue: c.canIssueAt(*info), CanManage: c.may(authz.ManageCA, info.Name) || c.may(authz.ManageCA, info.Parent),
			Pending: info.Status == ca.StatusPendingSignature},
		Properties: []view.KV{
			{Key: "Type", Value: info.Kind},
			{Key: "Subject", Value: g.Subject},
			{Key: "Issuer", Value: issuer},
			{Key: "Key algorithm", Value: g.KeyAlgorithm},
			{Key: "Key storage", Value: keyStorage(info.KeyMode)},
			{Key: "Serial number", Value: g.Serial, Mono: true},
			{Key: "SHA-256 fingerprint", Value: view.Fingerprint(g.Fingerprint), Mono: true},
			{Key: "Valid from", Value: view.DateTime(genTime(g.NotBefore))},
			{Key: "Valid until", Value: view.DateTime(genTime(g.NotAfter)) + " (" + view.Relative(a.now(), genTime(g.NotAfter)) + ")"},
			{Key: "Public base URL", Value: info.BaseURL + " – in every certificate it issues, can't change"},
		},
	}
	if info.Kind == ca.KindRoot {
		d.IssuedEmpty = "A root CA issues no end-entity certificates – it signs intermediate CAs and CRLs."
		if subs := subCAs(info.Name, a.allCAs(c)); len(subs) > 0 {
			d.IssuedEmpty += " Signed here: " + strings.Join(subs, ", ") + "."
		}
	} else {
		d.Properties = slices.Insert(d.Properties, len(d.Properties)-1,
			view.KV{Key: "Maximum validity", Value: strconv.FormatInt(info.MaxValidityDays, 10) + " days for issued certificates"})
	}
	if info.PathLen != nil {
		d.Properties = append(d.Properties, view.KV{Key: "Path length", Value: strconv.FormatInt(*info.PathLen, 10)})
	}
	for _, nc := range info.NameConstraints {
		d.Constraints = append(d.Constraints, view.KV{Key: "Name constraint", Value: nc})
	}
	if len(info.EKULimit) > 0 {
		d.Constraints = append(d.Constraints, view.KV{Key: "Extended key usages", Value: strings.Join(info.EKULimit, ", ")})
	}
	if len(info.NameConstraints) > 0 {
		crit := "No"
		if info.NameConstraintsCritical {
			crit = "Yes – enforced by the server before signing as well"
		}
		d.Constraints = append(d.Constraints, view.KV{Key: "Marked critical", Value: crit})
	}
	if s := g.CRL; s != nil {
		d.CRL = []view.KV{
			{Key: "State", Value: crlStateText(s.State)},
			{Key: "CRL number", Value: strconv.FormatInt(s.Number, 10)},
		}
		if !s.ThisUpdate.IsZero() {
			d.CRL = append(d.CRL,
				view.KV{Key: "This update", Value: view.DateTime(s.ThisUpdate)},
				view.KV{Key: "Next update", Value: view.DateTime(s.NextUpdate) + " (" + view.Relative(a.now(), s.NextUpdate) + ")"})
		}
		if msg := s.Message(a.d.Keys.Status().Sealed); msg != "" {
			d.CRL = append(d.CRL, view.KV{Key: "Note", Value: msg})
		}
		d.CRL = append(d.CRL, view.KV{Key: "Distribution point", Value: g.CRLURL})
	}
	for _, x := range info.Generations {
		v := "valid until " + view.Date(genTime(x.NotAfter))
		switch {
		case x.Pending:
			v = "waits for its signature"
		case x.Revoked != "":
			v = "revoked: " + x.Revoked
		}
		if x.Current {
			v += " (signs now)"
		}
		d.Real.Generations = append(d.Real.Generations, view.KV{Key: "Generation " + strconv.FormatInt(x.Generation, 10), Value: v})
	}
	page, err := a.d.Engine.Certificates(ctx, c.who(), ca.CertificateFilter{CAID: info.ID, Limit: 20})
	if err != nil {
		c.fail(err)
		return
	}
	for i := range page.Items {
		d.Issued = append(d.Issued, a.certRow(&page.Items[i]))
	}
	p := c.page(info.Name, "authorities", view.Crumb{Label: "Certificate authorities", Href: "/authorities"})
	if info.Parent != "" {
		p.Description = "Intermediate CA, signed by " + info.Parent + ". Key storage: " + strings.ToLower(keyStorage(info.KeyMode)) + "."
	} else {
		p.Description = "Root CA: it signs intermediate CAs and CRLs, no end-entity certificates. Key storage: " + strings.ToLower(keyStorage(info.KeyMode)) + "."
	}
	render(c.w, c.r, a.log, http.StatusOK, authorities.Detail(p, d))
}

func crlStateText(s string) string {
	switch s {
	case ca.CRLOK:
		return "Current"
	case ca.CRLRenewDue:
		return "Current – renewal due"
	case ca.CRLWarning:
		return "Ages – the renewal didn't happen"
	case ca.CRLExpired:
		return "Expired – clients that check revocation fail"
	case ca.CRLMissing:
		return "Not published yet"
	}
	return s
}

// authorityCertificate: pem = the CA certificate, chain = it and its issuers
// up to the root (for trust stores).
func (a *app) authorityCertificate(c *rc) {
	id := c.r.PathValue("id")
	format := cmp.Or(c.r.URL.Query().Get("format"), "pem")
	if format != "pem" && format != "chain" {
		c.fail(ca.ErrNotFound)
		return
	}
	chain, err := a.d.Engine.CAChain(c.r.Context(), c.who(), id)
	if err != nil {
		c.fail(err)
		return
	}
	name, err := a.d.Engine.CAName(c.r.Context(), c.who(), id)
	if err != nil {
		c.fail(err)
		return
	}
	if format == "chain" {
		c.attachment("application/pem-certificate-chain", name+"-chain.pem", pemBlocks(chain...))
		return
	}
	c.attachment("application/pem-certificate-chain", name+".pem", pemBlocks(chain[0]))
}

// ---------------------------------------------------------------- appearance, gallery

func (a *app) appearance(c *rc) {
	p := c.page("Appearance", "appearance", view.Crumb{Label: "Administration"})
	p.Description = "Layout, color scheme and density for your user on this browser."
	d := admin.AppearanceData{
		Messages:  c.messages(),
		Layouts:   checked(layoutChoices, string(p.Prefs.Layout)),
		Themes:    checked(themeChoices, string(p.Prefs.Theme)),
		Densities: checked(densityChoices, string(p.Prefs.Density)),
		CSRF:      c.sess.CSRFToken,
	}
	render(c.w, c.r, a.log, http.StatusOK, admin.Appearance(p, d))
}

func (a *app) saveAppearance(c *rc) {
	f := c.r.PostForm
	prefs := view.Prefs{Layout: view.Layout(f.Get("layout")), Theme: view.Theme(f.Get("theme")), Density: view.Density(f.Get("density"))}
	if !slices.Contains(view.Layouts, prefs.Layout) || !slices.Contains(view.Themes, prefs.Theme) || !slices.Contains(view.Densities, prefs.Density) {
		http.Error(c.w, "unknown appearance value", http.StatusBadRequest)
		return
	}
	http.SetCookie(c.w, prefs.Cookie(true))
	c.setFlash(view.Message{Kind: view.MessageSuccess, Text: "Appearance saved for this browser."})
	c.redirect("/admin/appearance")
}

func (a *app) design(c *rc) {
	p := c.page("Design system", "design", view.Crumb{Label: "Administration"})
	p.Description = "Every class of web/styles in one place. Themes change tokens only."
	render(c.w, c.r, a.log, http.StatusOK, design.Page(p))
}

// alarm colors a figure only when there is something: a red 0 alarms
// without reason.
func alarm(v int64, s view.Status) view.Status {
	if v == 0 {
		return ""
	}
	return s
}

// keyStorage names a key mode for people (ADR-09).
func keyStorage(mode string) string {
	switch mode {
	case ca.KeyModeOnlineEncrypted:
		return "Encrypted on this server"
	case ca.KeyModeOffline:
		return "Offline"
	case ca.KeyModeHSM:
		return "HSM"
	}
	return mode
}

// maxValidity is the cap for issued certificates; a root issues none.
func maxValidity(info ca.CAInfo) string {
	if info.Kind == ca.KindRoot {
		return "–"
	}
	return strconv.FormatInt(info.MaxValidityDays, 10) + " days"
}

// signedText: end-entity certificates and intermediate CAs the CA signed –
// a root counts its intermediates, not 0 (owner 2026-10-18).
func signedText(info ca.CAInfo, certs int64, all []ca.CAInfo) string {
	var subs int
	for _, c := range all {
		if c.Parent == info.Name {
			subs++
		}
	}
	plural := func(n int64, one, many string) string {
		if n == 1 {
			return "1 " + one
		}
		return strconv.FormatInt(n, 10) + " " + many
	}
	var parts []string
	if info.Kind != ca.KindRoot || certs > 0 {
		parts = append(parts, plural(certs, "certificate", "certificates"))
	}
	if subs > 0 || info.Kind == ca.KindRoot {
		parts = append(parts, plural(int64(subs), "intermediate CA", "intermediate CAs"))
	}
	return strings.Join(parts, ", ")
}

// allCAs are the CAs the user may read; nil on an error (only for texts).
func (a *app) allCAs(c *rc) []ca.CAInfo {
	cas, err := a.d.Engine.CAs(c.r.Context(), c.who())
	if err != nil {
		return nil
	}
	return cas
}

// subCAs names the CAs below parent that the user may read.
func subCAs(parent string, all []ca.CAInfo) []string {
	var out []string
	for _, c := range all {
		if c.Parent == parent {
			out = append(out, c.Name)
		}
	}
	return out
}
