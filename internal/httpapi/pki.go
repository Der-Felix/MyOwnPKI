package httpapi

import (
	"bytes"
	"encoding/pem"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/ca/preset"
	"github.com/Der-Felix/MyOwnPKI/internal/pkcs12"
)

var (
	idPattern     = regexp.MustCompile(`^[0-9A-Za-z_-]{1,64}$`)
	presetPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
)

// ---------------------------------------------------------------- presets

type presetJSON struct {
	Name         string `json:"name"`
	Description  string `json:"description"`
	Usage        string `json:"usage,omitempty"`
	Family       string `json:"family"`
	ValidityDays int    `json:"validity_days"`
	KeyUsage     struct {
		RSA   []string `json:"rsa"`
		Other []string `json:"other"`
	} `json:"key_usage"`
	ExtKeyUsage struct {
		Usages   []string `json:"usages"`
		Critical bool     `json:"critical"`
	} `json:"ext_key_usage"`
	SubjectAltNames struct {
		RequiredAnyOf []preset.SANType `json:"required_any_of"`
		Offered       []preset.SANType `json:"offered"`
	} `json:"subject_alt_names"`
	CommonNameFrom string `json:"common_name_from"`
	OpenSSLPurpose string `json:"openssl_purpose"`
	OCSPNoCheck    bool   `json:"ocsp_no_check"`
	Customizable   bool   `json:"customizable"`
	Wildcard       bool   `json:"wildcard"`
}

func toPresetJSON(p *preset.Preset) presetJSON {
	out := presetJSON{
		Name: p.Name, Description: p.Description, Usage: p.Usage, Family: string(p.Family), ValidityDays: p.ValidityDays,
		CommonNameFrom: string(p.CommonNameFrom), OpenSSLPurpose: p.OpenSSLPurpose, OCSPNoCheck: p.OCSPNoCheck,
		Customizable: p.Customizable, Wildcard: p.Wildcard,
	}
	out.KeyUsage.RSA, out.KeyUsage.Other = nonNil(p.KeyUsage.RSA), nonNil(p.KeyUsage.Other)
	out.ExtKeyUsage.Usages, out.ExtKeyUsage.Critical = nonNil(p.ExtKeyUsage.Usages), p.ExtKeyUsage.Critical
	out.SubjectAltNames.RequiredAnyOf = nonNil(p.SubjectAltNames.RequiredAnyOf)
	out.SubjectAltNames.Offered = nonNil(p.SubjectAltNames.Offered)
	return out
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

func (a *API) listPresets(c *call) error {
	out := []presetJSON{}
	for _, name := range a.d.Presets.Names() {
		p, _ := a.d.Presets.Get(name)
		out = append(out, toPresetJSON(p))
	}
	return c.reply(http.StatusOK, out)
}

func (a *API) getPreset(c *call) error {
	p, ok := a.d.Presets.Get(c.r.PathValue("presetName"))
	if !ok {
		return ca.ErrNotFound
	}
	return c.reply(http.StatusOK, toPresetJSON(p))
}

// ---------------------------------------------------------------- CAs

type nameConstraintJSON struct {
	Mode  string `json:"mode"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

type crlJSON struct {
	State       string     `json:"state"`
	Number      int64      `json:"number"`
	Source      string     `json:"source,omitempty"`
	ThisUpdate  *time.Time `json:"this_update,omitempty"`
	NextUpdate  *time.Time `json:"next_update,omitempty"`
	Unpublished int        `json:"unpublished"`
	Message     string     `json:"message,omitempty"`
}

type generationJSON struct {
	Generation     int64      `json:"generation"`
	Current        bool       `json:"current"`
	Pending        bool       `json:"pending"`
	KeyAlgorithm   string     `json:"key_algorithm"`
	Subject        string     `json:"subject"`
	Serial         string     `json:"serial,omitempty"`
	Fingerprint    string     `json:"fingerprint_sha256,omitempty"`
	NotBefore      *time.Time `json:"not_before,omitempty"`
	NotAfter       *time.Time `json:"not_after,omitempty"`
	Issuer         *string    `json:"issuer"`
	CertificateURL string     `json:"certificate_url"`
	CRLURL         string     `json:"crl_url"`
	Revoked        *string    `json:"revoked,omitempty"`
	Warnings       []string   `json:"warnings"`
	CRL            *crlJSON   `json:"crl,omitempty"`
}

type caJSON struct {
	ID                      string               `json:"id"`
	Name                    string               `json:"name"`
	Kind                    string               `json:"kind"`
	Status                  string               `json:"status"`
	KeyMode                 string               `json:"key_mode"`
	Parent                  *string              `json:"parent"`
	PublicBaseURL           string               `json:"public_base_url"`
	CRLDays                 int64                `json:"crl_days"`
	MaxValidityDays         int64                `json:"max_validity_days"`
	PathLen                 *int64               `json:"path_len"`
	NameConstraints         []nameConstraintJSON `json:"name_constraints"`
	NameConstraintsCritical bool                 `json:"name_constraints_critical"`
	EKULimit                []string             `json:"eku_limit"`
	CurrentGeneration       *int64               `json:"current_generation"`
	Generations             []generationJSON     `json:"generations"`
}

func optString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// optTime reads a stored time ("" = none).
func optTime(s string) *time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return nil
	}
	t = t.UTC()
	return &t
}

func toCAJSON(info ca.CAInfo, sealed bool) caJSON {
	out := caJSON{
		ID: info.ID, Name: info.Name, Kind: info.Kind, Status: info.Status, KeyMode: info.KeyMode, Parent: optString(info.Parent),
		PublicBaseURL: info.BaseURL, CRLDays: info.CRLDays, MaxValidityDays: info.MaxValidityDays, PathLen: info.PathLen,
		NameConstraints: []nameConstraintJSON{}, NameConstraintsCritical: info.NameConstraintsCritical,
		EKULimit: nonNil(info.EKULimit), Generations: []generationJSON{},
	}
	if info.CurrentGeneration > 0 {
		g := info.CurrentGeneration
		out.CurrentGeneration = &g
	}
	for _, nc := range info.NameConstraints {
		// "permitted dns homelab.lan"
		parts := strings.SplitN(nc, " ", 3)
		if len(parts) == 3 {
			out.NameConstraints = append(out.NameConstraints, nameConstraintJSON{Mode: parts[0], Type: parts[1], Value: parts[2]})
		}
	}
	for _, g := range info.Generations {
		gj := generationJSON{
			Generation: g.Generation, Current: g.Current, Pending: g.Pending, KeyAlgorithm: g.KeyAlgorithm, Subject: g.Subject,
			Serial: g.Serial, Fingerprint: g.Fingerprint, NotBefore: optTime(g.NotBefore), NotAfter: optTime(g.NotAfter),
			Issuer: optString(g.Issuer), CertificateURL: g.CertURL, CRLURL: g.CRLURL, Revoked: optString(g.Revoked),
			Warnings: nonNil(g.Warnings),
		}
		if st := g.CRL; st != nil {
			cj := &crlJSON{State: st.State, Number: st.Number, Source: st.Source, Unpublished: st.Unpublished, Message: st.Message(sealed)}
			if !st.ThisUpdate.IsZero() {
				t, n := st.ThisUpdate.UTC(), st.NextUpdate.UTC()
				cj.ThisUpdate, cj.NextUpdate = &t, &n
			}
			gj.CRL = cj
		}
		out.Generations = append(out.Generations, gj)
	}
	return out
}

func (a *API) listCAs(c *call) error {
	cas, err := a.d.Engine.CAs(c.ctx(), c.who())
	if err != nil {
		return err
	}
	sealed := a.d.Keys.Status().Sealed
	out := make([]caJSON, 0, len(cas))
	for _, info := range cas {
		out = append(out, toCAJSON(info, sealed))
	}
	return c.reply(http.StatusOK, out)
}

func (a *API) getCA(c *call) error {
	id := c.r.PathValue("caId")
	if !idPattern.MatchString(id) {
		return ca.ErrNotFound
	}
	info, err := a.d.Engine.CA(c.ctx(), c.who(), id)
	if err != nil {
		return err
	}
	return c.reply(http.StatusOK, toCAJSON(*info, a.d.Keys.Status().Sealed))
}

func (a *API) downloadCACertificate(c *call) error {
	id := c.r.PathValue("caId")
	if !idPattern.MatchString(id) {
		return ca.ErrNotFound
	}
	format := c.r.URL.Query().Get("format")
	if format == "" {
		format = "pem"
	}
	if format != "pem" && format != "der" && format != "chain" {
		return badRequest("format", "one of pem, der, chain")
	}
	chain, err := a.d.Engine.CAChain(c.ctx(), c.who(), id)
	if err != nil {
		return err
	}
	name, err := a.d.Engine.CAName(c.ctx(), c.who(), id)
	if err != nil {
		return err
	}
	switch format {
	case "der":
		return c.file("application/pkix-cert", name+".crt", chain[0])
	case "chain":
		return c.file("application/pem-certificate-chain", name+"-chain.pem", pemCerts(chain...))
	}
	return c.file("application/pem-certificate-chain", name+".pem", pemCerts(chain[0]))
}

func pemCerts(ders ...[]byte) []byte {
	var b bytes.Buffer
	for _, d := range ders {
		_ = pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: d})
	}
	return b.Bytes()
}

// ---------------------------------------------------------------- certificates

type sansJSON struct {
	DNS   []string `json:"dns"`
	IP    []string `json:"ip"`
	Email []string `json:"email"`
	URI   []string `json:"uri"`
}

type revocationJSON struct {
	Reason         string     `json:"reason"`
	RevokedAt      time.Time  `json:"revoked_at"`
	InvalidityDate *time.Time `json:"invalidity_date"`
}

type certificateJSON struct {
	ID           string          `json:"id"`
	CAID         *string         `json:"ca_id"`
	CAName       *string         `json:"ca_name"`
	CAGeneration *int64          `json:"ca_generation"`
	Preset       *string         `json:"preset"`
	Status       string          `json:"status"`
	Source       string          `json:"source"`
	Subject      string          `json:"subject"`
	CommonName   string          `json:"common_name"`
	SANs         sansJSON        `json:"sans"`
	Serial       string          `json:"serial"`
	NotBefore    time.Time       `json:"not_before"`
	NotAfter     time.Time       `json:"not_after"`
	KeyAlgorithm string          `json:"key_algorithm"`
	KeyStored    bool            `json:"key_stored"`
	Fingerprint  string          `json:"fingerprint_sha256"`
	Revocation   *revocationJSON `json:"revocation"`
	RenewalOf    *string         `json:"renewal_of"`
	IssuedBy     *string         `json:"issued_by"`
	CreatedAt    time.Time       `json:"created_at"`
}

func toCertificateJSON(i *ca.CertificateInfo) certificateJSON {
	out := certificateJSON{
		ID: i.ID, CAID: optString(i.CAID), CAName: optString(i.CAName), Preset: optString(i.Preset), Status: i.Status,
		Source: i.Source, Subject: i.Subject, CommonName: i.CommonName,
		SANs:   sansJSON{DNS: nonNil(i.DNSNames), IP: nonNil(i.IPs), Email: nonNil(i.Emails), URI: nonNil(i.URIs)},
		Serial: i.Serial, NotBefore: i.NotBefore, NotAfter: i.NotAfter, KeyAlgorithm: i.KeyAlgorithm, KeyStored: i.KeyStored,
		Fingerprint: i.Fingerprint, RenewalOf: optString(i.RenewalOf), IssuedBy: optString(i.RequestedBy), CreatedAt: i.CreatedAt,
	}
	if i.CAGeneration > 0 {
		g := i.CAGeneration
		out.CAGeneration = &g
	}
	if i.RevokedAt != nil {
		out.Revocation = &revocationJSON{Reason: i.RevocationReason, RevokedAt: *i.RevokedAt, InvalidityDate: i.InvalidityDate}
	}
	return out
}

func (a *API) listCertificates(c *call) error {
	q := c.r.URL.Query()
	f := ca.CertificateFilter{CAID: q.Get("ca_id"), Preset: q.Get("preset"), Status: q.Get("status"), Search: q.Get("q"), Cursor: q.Get("cursor")}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > ca.MaxPageSize {
			return badRequest("limit", "a number from 1 to %d", ca.MaxPageSize)
		}
		f.Limit = n
	}
	switch {
	case f.CAID != "" && !idPattern.MatchString(f.CAID):
		return badRequest("ca_id", "not an ID")
	case f.Preset != "" && !presetPattern.MatchString(f.Preset):
		return badRequest("preset", "not a preset name")
	case f.Status != "" && f.Status != ca.CertValid && f.Status != ca.CertRevoked && f.Status != ca.CertExpired:
		return badRequest("status", "one of valid, revoked, expired")
	case len(f.Search) > 253:
		return badRequest("q", "at most 253 characters")
	case len(f.Cursor) > 512 || (f.Cursor != "" && !idPattern.MatchString(f.Cursor)):
		return badRequest("cursor", "not a cursor of this API")
	}
	if v := q.Get("expires_before"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return badRequest("expires_before", "an RFC 3339 time, e.g. 2026-12-31T00:00:00Z")
		}
		f.ExpiresBefore = t
	}
	page, err := a.d.Engine.Certificates(c.ctx(), c.who(), f)
	if err != nil {
		return err
	}
	out := struct {
		Items      []certificateJSON `json:"items"`
		NextCursor *string           `json:"next_cursor"`
	}{Items: make([]certificateJSON, 0, len(page.Items)), NextCursor: optString(page.NextCursor)}
	for i := range page.Items {
		out.Items = append(out.Items, toCertificateJSON(&page.Items[i]))
	}
	return c.reply(http.StatusOK, out)
}

type issueRequest struct {
	CAID   string `json:"ca_id"`
	Preset string `json:"preset"`
	// Subject fields; common_name may be empty (derived from a SAN).
	Subject *struct {
		CommonName         string `json:"common_name"`
		Organization       string `json:"organization"`
		OrganizationalUnit string `json:"organizational_unit"`
		Locality           string `json:"locality"`
		State              string `json:"state"`
		Country            string `json:"country"`
	} `json:"subject"`
	SANs *struct {
		DNS   []string `json:"dns"`
		IP    []string `json:"ip"`
		Email []string `json:"email"`
		URI   []string `json:"uri"`
	} `json:"sans"`
	ValidityDays *int    `json:"validity_days"`
	CSRPEM       *string `json:"csr_pem"`
	UseCSRSANs   *bool   `json:"use_csr_sans"`
	Key          *struct {
		Algorithm string `json:"algorithm"`
	} `json:"key"`
	KeyUsage    []string `json:"key_usage"`
	ExtKeyUsage []string `json:"ext_key_usage"`
}

// issueCertificate: who may not read the CA gets 404, who may read but not
// issue 403 – the engine checks the permission and the whole policy.
func (a *API) issueCertificate(c *call) error {
	var req issueRequest
	if err := c.decode(&req); err != nil {
		return err
	}
	switch {
	case !idPattern.MatchString(req.CAID):
		return badRequest("/ca_id", "required: the ID of the issuing CA")
	case !presetPattern.MatchString(req.Preset):
		return badRequest("/preset", "required: a preset name")
	case (req.CSRPEM == nil) == (req.Key == nil):
		return badRequest("/csr_pem", "give exactly one of csr_pem (preferred) or key")
	case req.CSRPEM != nil && len(*req.CSRPEM) > 65536:
		return badRequest("/csr_pem", "at most 64 KiB")
	case req.ValidityDays != nil && *req.ValidityDays < 1:
		return badRequest("/validity_days", "at least 1")
	case req.Key != nil && req.Key.Algorithm == "":
		return badRequest("/key/algorithm", "required")
	}
	name, err := a.d.Engine.CAName(c.ctx(), c.who(), req.CAID)
	if err != nil {
		return err
	}
	r := ca.Request{CA: name, Preset: req.Preset, CustomKeyUsage: req.KeyUsage, CustomExtKeyUsage: req.ExtKeyUsage, Who: c.who()}
	if req.CSRPEM != nil {
		r.CSR = []byte(*req.CSRPEM)
		r.IgnoreCSRNames = req.UseCSRSANs != nil && !*req.UseCSRSANs
	} else {
		r.KeyAlgorithm = req.Key.Algorithm
	}
	if req.ValidityDays != nil {
		r.ValidityDays = *req.ValidityDays
	}
	if s := req.Subject; s != nil {
		r.Subject = ca.Subject{CommonName: s.CommonName, Organization: s.Organization, OrganizationalUnit: s.OrganizationalUnit,
			Locality: s.Locality, Province: s.State, Country: s.Country}
	}
	if s := req.SANs; s != nil {
		r.DNSNames, r.IPAddresses, r.EmailAddresses, r.URIs = s.DNS, s.IP, s.Email, s.URI
	}
	issued, err := a.d.Engine.Issue(c.ctx(), r)
	if err != nil {
		return err
	}
	info, err := a.d.Engine.Certificate(c.ctx(), c.who(), issued.ID)
	if err != nil {
		return err
	}
	c.w.Header().Set("Location", BasePath+"/certificates/"+issued.ID)
	return c.reply(http.StatusCreated, struct {
		certificateJSON
		Notes           []string `json:"notes"`
		Warnings        []string `json:"warnings"`
		DroppedCSRNames []string `json:"dropped_csr_names"`
	}{toCertificateJSON(info), nonNil(issued.Notes), nonNil(issued.Warnings), nonNil(issued.DroppedCSRNames)})
}

func (a *API) getCertificate(c *call) error {
	id := c.r.PathValue("certificateId")
	if !idPattern.MatchString(id) {
		return ca.ErrNotFound
	}
	info, err := a.d.Engine.Certificate(c.ctx(), c.who(), id)
	if err != nil {
		return err
	}
	return c.reply(http.StatusOK, toCertificateJSON(info))
}

func (a *API) downloadCertificate(c *call) error {
	id := c.r.PathValue("certificateId")
	if !idPattern.MatchString(id) {
		return ca.ErrNotFound
	}
	format := c.r.PathValue("format")
	if format != "pem" && format != "chain" && format != "fullchain" && format != "der" {
		return ca.ErrNotFound
	}
	info, err := a.d.Engine.Certificate(c.ctx(), c.who(), id)
	if err != nil {
		return err
	}
	cert, chain, err := a.d.Engine.CertificateChain(c.ctx(), c.who(), id)
	if err != nil {
		return err
	}
	name := fileName(info.CommonName, info.Serial)
	switch format {
	case "der":
		return c.file("application/pkix-cert", name+".crt", cert)
	case "chain":
		return c.file("application/pem-certificate-chain", name+"-chain.pem", pemCerts(chain...))
	case "fullchain":
		return c.file("application/pem-certificate-chain", name+"-fullchain.pem", pemCerts(append([][]byte{cert}, chain...)...))
	}
	return c.file("application/pem-certificate-chain", name+".pem", pemCerts(cert))
}

// exportKey hands out a server-generated key as PKCS#8 PEM (owner
// 2026-10-17): operator on the issuing CA, step-up, unsealed, audited;
// the key stays encrypted on the server.
// exportKey hands out the key of a server-generated certificate: PKCS#8
// PEM, PKCS#12 with a password, or certificate + chain + key in one PEM;
// optionally the key is deleted on the server afterwards (step 18).
func (a *API) exportKey(c *call) error {
	id := c.r.PathValue("certificateId")
	if !idPattern.MatchString(id) {
		return ca.ErrNotFound
	}
	var req struct {
		Format                 string `json:"format"`
		Password               string `json:"password"`
		DeleteKeyAfterDownload bool   `json:"delete_key_after_download"`
	}
	if err := c.decode(&req); err != nil {
		return err
	}
	if !slices.Contains(ca.ExportFormats, req.Format) {
		return badRequest("/format", "one of %s", strings.Join(ca.ExportFormats, ", "))
	}
	if req.Format == ca.ExportPKCS12 && len([]rune(req.Password)) < pkcs12.MinPassword {
		return badRequest("/password", "PKCS#12 needs a password of at least %d characters", pkcs12.MinPassword)
	}
	if req.Format != ca.ExportPKCS12 && req.Password != "" {
		return badRequest("/password", "only for pkcs12")
	}
	out, err := a.d.Engine.Export(c.ctx(), ca.ExportRequest{ID: id, Format: req.Format, Password: req.Password, DeleteKey: req.DeleteKeyAfterDownload, Who: c.who()})
	if err != nil {
		return err
	}
	defer clear(out.Data)
	if out.KeyDeleted {
		c.w.Header().Set("X-Key-Deleted", "true")
	}
	return c.file(out.ContentType, out.FileName, out.Data)
}
