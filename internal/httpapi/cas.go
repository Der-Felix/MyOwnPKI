package httpapi

import (
	"encoding/pem"
	"net/http"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/ca"
)

// CA management (step 18): create, import an offline root, the offline
// flow, renew, retire, limits, revoke, CRLs.

type subjectJSON struct {
	CommonName         string `json:"common_name"`
	Organization       string `json:"organization"`
	OrganizationalUnit string `json:"organizational_unit"`
	Locality           string `json:"locality"`
	State              string `json:"state"`
	Country            string `json:"country"`
}

func (s subjectJSON) subject() ca.Subject {
	return ca.Subject{CommonName: s.CommonName, Organization: s.Organization, OrganizationalUnit: s.OrganizationalUnit,
		Locality: s.Locality, Province: s.State, Country: s.Country}
}

type nameConstraintsJSON struct {
	PermittedDNS   []string `json:"permitted_dns"`
	ExcludedDNS    []string `json:"excluded_dns"`
	PermittedIP    []string `json:"permitted_ip"`
	ExcludedIP     []string `json:"excluded_ip"`
	PermittedEmail []string `json:"permitted_email"`
	ExcludedEmail  []string `json:"excluded_email"`
	PermittedURI   []string `json:"permitted_uri"`
	ExcludedURI    []string `json:"excluded_uri"`
	NotCritical    bool     `json:"not_critical"`
}

type offlineBundleJSON struct {
	CSRPEM       string `json:"csr_pem"`
	CSRFile      string `json:"csr_file"`
	ExtConfig    string `json:"ext_config"`
	ExtFile      string `json:"ext_file"`
	CertFile     string `json:"cert_file"`
	Days         int    `json:"days"`
	Digest       string `json:"digest"`
	Serial       string `json:"serial"`
	Instructions string `json:"instructions"`
}

func toBundleJSON(b *ca.OfflineBundle) *offlineBundleJSON {
	if b == nil {
		return nil
	}
	return &offlineBundleJSON{CSRPEM: string(b.CSRPEM), CSRFile: b.CSRFile, ExtConfig: b.ExtConfig, ExtFile: b.ExtFile,
		CertFile: b.CertFile, Days: b.Days, Digest: b.Digest, Serial: b.Serial, Instructions: b.Instructions}
}

// caChangeJSON is a CA after a change, with what the server noted.
type caChangeJSON struct {
	CA       caJSON             `json:"ca"`
	Offline  *offlineBundleJSON `json:"offline_signing"`
	Notes    []string           `json:"notes"`
	Warnings []string           `json:"warnings"`
}

func (a *API) caChange(c *call, status int, res *ca.CAResult) error {
	info, err := a.d.Engine.CA(c.ctx(), c.who(), res.ID)
	if err != nil {
		return err
	}
	if status == http.StatusCreated {
		c.w.Header().Set("Location", BasePath+"/cas/"+res.ID)
	}
	return c.reply(status, caChangeJSON{CA: toCAJSON(*info, a.d.Keys.Status().Sealed), Offline: toBundleJSON(res.Offline),
		Notes: nonNil(res.Notes), Warnings: nonNil(res.Warnings)})
}

// caPath reads {caId} and turns it into the CA's name, with the read check.
func (a *API) caPath(c *call) (string, string, error) {
	id := c.r.PathValue("caId")
	if !idPattern.MatchString(id) {
		return "", "", ca.ErrNotFound
	}
	name, err := a.d.Engine.CAName(c.ctx(), c.who(), id)
	return id, name, err
}

func (a *API) createCA(c *call) error {
	var req struct {
		Name            string               `json:"name"`
		Kind            string               `json:"kind"`
		ParentCAID      string               `json:"parent_ca_id"`
		Subject         *subjectJSON         `json:"subject"`
		KeyAlgorithm    string               `json:"key_algorithm"`
		ValidityDays    int                  `json:"validity_days"`
		PathLen         int                  `json:"path_len"`
		NameConstraints *nameConstraintsJSON `json:"name_constraints"`
		EKULimit        []string             `json:"eku_limit"`
		PublicBaseURL   string               `json:"public_base_url"`
		CRLDays         int                  `json:"crl_days"`
		MaxValidityDays int                  `json:"max_validity_days"`
	}
	if derr := c.decode(&req); derr != nil {
		return derr
	}
	switch {
	case req.Name == "":
		return badRequest("/name", "required")
	case req.Subject == nil || req.Subject.CommonName == "":
		return badRequest("/subject/common_name", "required")
	case req.PublicBaseURL == "":
		return badRequest("/public_base_url", "required – it goes into every certificate below this CA")
	case req.ValidityDays < 0 || req.PathLen < 0 || req.CRLDays < 0 || req.MaxValidityDays < 0:
		return badRequest("", "numbers must not be negative")
	}
	settings := ca.CASettings{Name: req.Name, BaseURL: req.PublicBaseURL, CRLDays: req.CRLDays, MaxValidityDays: req.MaxValidityDays}
	var res *ca.CAResult
	var err error
	switch req.Kind {
	case ca.KindRoot:
		if req.ParentCAID != "" || req.NameConstraints != nil || len(req.EKULimit) > 0 || req.PathLen != 0 {
			return badRequest("", "a root takes no parent, path length, name constraints or EKU limit")
		}
		res, err = a.d.Engine.CreateRoot(c.ctx(), ca.RootRequest{CASettings: settings, Subject: req.Subject.subject(),
			KeyAlgorithm: req.KeyAlgorithm, ValidityDays: req.ValidityDays, Who: c.who()})
	case ca.KindIntermediate:
		if !idPattern.MatchString(req.ParentCAID) {
			return badRequest("/parent_ca_id", "required for an intermediate")
		}
		parent, perr := a.d.Engine.CAName(c.ctx(), c.who(), req.ParentCAID)
		if perr != nil {
			return perr
		}
		r := ca.IntermediateRequest{CASettings: settings, Parent: parent, Subject: req.Subject.subject(), KeyAlgorithm: req.KeyAlgorithm,
			ValidityDays: req.ValidityDays, PathLen: req.PathLen, EKULimit: req.EKULimit, Who: c.who()}
		if nc := req.NameConstraints; nc != nil {
			r.NameConstraints = ca.NameConstraints{PermittedDNS: nc.PermittedDNS, ExcludedDNS: nc.ExcludedDNS, PermittedIP: nc.PermittedIP,
				ExcludedIP: nc.ExcludedIP, PermittedEmail: nc.PermittedEmail, ExcludedEmail: nc.ExcludedEmail,
				PermittedURI: nc.PermittedURI, ExcludedURI: nc.ExcludedURI, NotCritical: nc.NotCritical}
		}
		res, err = a.d.Engine.CreateIntermediate(c.ctx(), r)
	default:
		return badRequest("/kind", "root or intermediate")
	}
	if err != nil {
		return err
	}
	return a.caChange(c, http.StatusCreated, res)
}

// importCA imports the certificate of an offline root (its key stays
// offline); a known offline root with a new key gets its next generation.
func (a *API) importCA(c *call) error {
	var req struct {
		Name           string `json:"name"`
		CertificatePEM string `json:"certificate_pem"`
		PublicBaseURL  string `json:"public_base_url"`
		CRLDays        int    `json:"crl_days"`
	}
	if derr := c.decode(&req); derr != nil {
		return derr
	}
	switch {
	case req.Name == "":
		return badRequest("/name", "required")
	case req.CertificatePEM == "" || len(req.CertificatePEM) > ca.MaxCertSize:
		return badRequest("/certificate_pem", "one PEM certificate of at most 64 KiB")
	case req.CRLDays < 0:
		return badRequest("/crl_days", "at least 1")
	}
	res, err := a.d.Engine.ImportRoot(c.ctx(), ca.ImportRootRequest{
		CASettings: ca.CASettings{Name: req.Name, BaseURL: req.PublicBaseURL, CRLDays: req.CRLDays},
		CertPEM:    []byte(req.CertificatePEM), Who: c.who(),
	})
	if err != nil {
		return err
	}
	return a.caChange(c, http.StatusCreated, res)
}

func (a *API) uploadSignedCACertificate(c *call) error {
	_, name, err := a.caPath(c)
	if err != nil {
		return err
	}
	var req struct {
		CertificatePEM string `json:"certificate_pem"`
	}
	if derr := c.decode(&req); derr != nil {
		return derr
	}
	if req.CertificatePEM == "" || len(req.CertificatePEM) > ca.MaxCertSize {
		return badRequest("/certificate_pem", "one PEM certificate of at most 64 KiB")
	}
	res, err := a.d.Engine.InstallCACertificate(c.ctx(), name, []byte(req.CertificatePEM), c.who())
	if err != nil {
		return err
	}
	return a.caChange(c, http.StatusOK, res)
}

// downloadCACSR returns the offline bundle (the CSR, the extension file to
// sign it with and the instructions) of a CA that waits for its signature.
func (a *API) downloadCACSR(c *call) error {
	_, name, err := a.caPath(c)
	if err != nil {
		return err
	}
	if merr := a.manageCheck(c, name); merr != nil {
		return merr
	}
	b, err := a.d.Engine.OfflineBundleFor(c.ctx(), name)
	if err != nil {
		return err
	}
	return c.reply(http.StatusOK, toBundleJSON(b))
}

// manageCheck: viewing the offline bundle is part of managing the CA.
func (a *API) manageCheck(c *call, name string) error {
	return a.d.Engine.CheckManage(c.who(), name)
}

func (a *API) downloadCRL(c *call) error {
	id := c.r.PathValue("caId")
	if !idPattern.MatchString(id) {
		return ca.ErrNotFound
	}
	format := c.r.URL.Query().Get("format")
	if format == "" {
		format = "der"
	}
	if format != "der" && format != "pem" {
		return badRequest("format", "der or pem")
	}
	der, name, err := a.d.Engine.LatestCRL(c.ctx(), c.who(), id)
	if err != nil {
		return err
	}
	if format == "pem" {
		return c.file("application/x-pem-file", name+".crl.pem", pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der}))
	}
	return c.file("application/pkix-crl", name+".crl", der)
}

type crlSignedJSON struct {
	CA         string    `json:"ca"`
	Generation int64     `json:"generation"`
	Number     int64     `json:"number"`
	ThisUpdate time.Time `json:"this_update"`
	NextUpdate time.Time `json:"next_update"`
	Entries    int       `json:"entries"`
}

func toCRLSignedJSON(r *ca.CRLResult) crlSignedJSON {
	return crlSignedJSON{CA: r.CA, Generation: r.Generation, Number: r.Number, ThisUpdate: r.ThisUpdate.UTC(), NextUpdate: r.NextUpdate.UTC(), Entries: r.Entries}
}

func (a *API) regenerateCRL(c *call) error {
	id, _, err := a.caPath(c)
	if err != nil {
		return err
	}
	info, err := a.d.Engine.CA(c.ctx(), c.who(), id)
	if err != nil {
		return err
	}
	res, err := a.d.Engine.SignCRL(c.ctx(), id, info.CurrentGeneration, "api", c.who())
	if err != nil {
		return err
	}
	return c.reply(http.StatusOK, toCRLSignedJSON(res))
}

// uploadCRL takes the CRL the offline root signed.
func (a *API) uploadCRL(c *call) error {
	_, name, err := a.caPath(c)
	if err != nil {
		return err
	}
	var req struct {
		CRLPEM string `json:"crl_pem"`
	}
	if derr := c.decode(&req); derr != nil {
		return derr
	}
	if req.CRLPEM == "" {
		return badRequest("/crl_pem", "required: the CRL in PEM (openssl crl -outform PEM)")
	}
	res, warnings, err := a.d.Engine.UploadCRL(c.ctx(), name, []byte(req.CRLPEM), c.who())
	if err != nil {
		return err
	}
	return c.reply(http.StatusOK, struct {
		crlSignedJSON
		Warnings []string `json:"warnings"`
	}{toCRLSignedJSON(res), nonNil(warnings)})
}

func (a *API) renewCA(c *call) error {
	_, name, err := a.caPath(c)
	if err != nil {
		return err
	}
	var req struct {
		KeyAlgorithm string `json:"key_algorithm"`
		ValidityDays int    `json:"validity_days"`
	}
	if c.r.ContentLength != 0 {
		if derr := c.decode(&req); derr != nil {
			return derr
		}
	}
	if req.ValidityDays < 0 {
		return badRequest("/validity_days", "at least 1")
	}
	res, err := a.d.Engine.RenewCA(c.ctx(), ca.RenewRequest{Name: name, KeyAlgorithm: req.KeyAlgorithm, ValidityDays: req.ValidityDays, Who: c.who()})
	if err != nil {
		return err
	}
	return a.caChange(c, http.StatusOK, res)
}

func (a *API) retireCA(c *call) error {
	id, name, err := a.caPath(c)
	if err != nil {
		return err
	}
	if err := a.d.Engine.RetireCA(c.ctx(), name, c.who()); err != nil {
		return err
	}
	return a.caChange(c, http.StatusOK, &ca.CAResult{ID: id})
}

func (a *API) updateCA(c *call) error {
	id, name, err := a.caPath(c)
	if err != nil {
		return err
	}
	var req struct {
		CRLDays         int `json:"crl_days"`
		MaxValidityDays int `json:"max_validity_days"`
	}
	if derr := c.decode(&req); derr != nil {
		return derr
	}
	if req.CRLDays < 0 || req.MaxValidityDays < 0 || (req.CRLDays == 0 && req.MaxValidityDays == 0) {
		return badRequest("", "give crl_days or max_validity_days (positive)")
	}
	if err := a.d.Engine.UpdateCA(c.ctx(), ca.UpdateRequest{Name: name, CRLDays: req.CRLDays, MaxValidityDays: req.MaxValidityDays, Who: c.who()}); err != nil {
		return err
	}
	return a.caChange(c, http.StatusOK, &ca.CAResult{ID: id})
}

func (a *API) revokeCA(c *call) error {
	id, name, err := a.caPath(c)
	if err != nil {
		return err
	}
	var req struct {
		Reason         string     `json:"reason"`
		Generation     int64      `json:"generation"`
		InvalidityDate *time.Time `json:"invalidity_date"`
	}
	if derr := c.decode(&req); derr != nil {
		return derr
	}
	if req.Reason == "" {
		return badRequest("/reason", "required")
	}
	res, err := a.d.Engine.RevokeCA(c.ctx(), ca.RevokeCARequest{Name: name, Generation: req.Generation, Reason: req.Reason, InvalidityDate: req.InvalidityDate, Who: c.who()})
	if err != nil {
		return err
	}
	info, err := a.d.Engine.CA(c.ctx(), c.who(), id)
	if err != nil {
		return err
	}
	out := struct {
		CA           caJSON   `json:"ca"`
		CRLPublished bool     `json:"crl_published"`
		CRLNumber    *int64   `json:"crl_number"`
		Warnings     []string `json:"warnings"`
	}{CA: toCAJSON(*info, a.d.Keys.Status().Sealed), CRLPublished: res.Published, Warnings: nonNil(res.Warnings)}
	if res.CRL != nil {
		n := res.CRL.Number
		out.CRLNumber = &n
	}
	return c.reply(http.StatusOK, out)
}
