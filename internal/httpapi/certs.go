package httpapi

import (
	"errors"
	"net/http"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
)

// Certificate operations of part 2 (step 18): revoke, renew, CSR
// inspection, external certificates.

type revocationResultJSON struct {
	Certificate  certificateJSON `json:"certificate"`
	CRLPublished bool            `json:"crl_published"`
	CRLNumber    *int64          `json:"crl_number"`
	Warnings     []string        `json:"warnings"`
}

func (a *API) revokeCertificate(c *call) error {
	id := c.r.PathValue("certificateId")
	if !idPattern.MatchString(id) {
		return ca.ErrNotFound
	}
	var req struct {
		Reason         string     `json:"reason"`
		InvalidityDate *time.Time `json:"invalidity_date"`
	}
	if err := c.decode(&req); err != nil {
		return err
	}
	if req.Reason == "" {
		return badRequest("/reason", "required")
	}
	res, err := a.d.Engine.Revoke(c.ctx(), ca.RevokeRequest{CertificateID: id, Reason: req.Reason, InvalidityDate: req.InvalidityDate, Who: c.who()})
	if err != nil {
		return err
	}
	info, err := a.d.Engine.Certificate(c.ctx(), c.who(), id)
	if err != nil {
		return err
	}
	out := revocationResultJSON{Certificate: toCertificateJSON(info), CRLPublished: res.Published, Warnings: nonNil(res.Warnings)}
	if res.CRL != nil {
		n := res.CRL.Number
		out.CRLNumber = &n
	}
	return c.reply(http.StatusOK, out)
}

func (a *API) renewCertificate(c *call) error {
	id := c.r.PathValue("certificateId")
	if !idPattern.MatchString(id) {
		return ca.ErrNotFound
	}
	var req struct {
		CSRPEM         *string                `json:"csr_pem"`
		KeyAlgorithm   string                 `json:"key_algorithm"`
		ValidityDays   *int                   `json:"validity_days"`
		RevokePrevious *bool                  `json:"revoke_previous"`
		Predecessor    *predecessorPolicyJSON `json:"predecessor"`
	}
	if c.r.ContentLength != 0 {
		if err := c.decode(&req); err != nil {
			return err
		}
	}
	switch {
	case req.CSRPEM != nil && len(*req.CSRPEM) > ca.MaxCSRSize:
		return badRequest("/csr_pem", "at most 64 KiB")
	case req.ValidityDays != nil && *req.ValidityDays < 1:
		return badRequest("/validity_days", "at least 1")
	}
	r := ca.RenewCertRequest{ID: id, KeyAlgorithm: req.KeyAlgorithm, RevokePrevious: req.RevokePrevious, Who: c.who()}
	if req.Predecessor != nil {
		policy := req.Predecessor.value()
		if err := policy.Validate(); err != nil {
			return badRequest("/predecessor", "%s", err)
		}
		r.Predecessor = &policy
	}
	if req.CSRPEM != nil {
		r.CSR = []byte(*req.CSRPEM)
	}
	if req.ValidityDays != nil {
		r.ValidityDays = *req.ValidityDays
	}
	res, err := a.d.Engine.RenewCertificate(c.ctx(), r)
	if err != nil && res == nil {
		return err
	}
	if err != nil { // issued, but the original was not revoked
		res.Warnings = append(res.Warnings, err.Error())
	}
	info, ierr := a.d.Engine.Certificate(c.ctx(), c.who(), res.ID)
	if ierr != nil {
		return ierr
	}
	c.w.Header().Set("Location", BasePath+"/certificates/"+res.ID)
	return c.reply(http.StatusCreated, struct {
		certificateJSON
		Notes           []string `json:"notes"`
		Warnings        []string `json:"warnings"`
		DroppedCSRNames []string `json:"dropped_csr_names"`
	}{toCertificateJSON(info), nonNil(res.Notes), nonNil(res.Warnings), nonNil(res.DroppedCSRNames)})
}

// inspectCSR: an operator somewhere may preview a CSR; nothing is stored.
func (a *API) inspectCSR(c *call) error {
	if !c.session.Principal.CanIssueSomewhere() {
		return c.problem(http.StatusForbidden, "forbidden", "previewing a CSR needs the operator role on a CA", nil)
	}
	var req struct {
		CSRPEM string `json:"csr_pem"`
	}
	if err := c.decode(&req); err != nil {
		return err
	}
	if req.CSRPEM == "" || len(req.CSRPEM) > ca.MaxCSRSize {
		return badRequest("/csr_pem", "a PEM CSR of at most 64 KiB")
	}
	info, err := ca.InspectCSR([]byte(req.CSRPEM))
	if err != nil {
		return err
	}
	return c.reply(http.StatusOK, struct {
		Subject             string   `json:"subject"`
		CommonName          string   `json:"common_name"`
		SANs                sansJSON `json:"sans"`
		KeyAlgorithm        string   `json:"key_algorithm"`
		SignatureValid      bool     `json:"signature_valid"`
		RequestedExtensions []string `json:"requested_extensions"`
		Problems            []string `json:"problems"`
		Warnings            []string `json:"warnings"`
	}{info.Subject, info.CommonName, sansJSON{DNS: info.DNSNames, IP: info.IPs, Email: info.Emails, URI: info.URIs},
		info.KeyAlgorithm, info.SignatureValid, info.RequestedExtensions, info.Problems, info.Warnings})
}

func (a *API) importExternalCertificate(c *call) error {
	var req struct {
		CertificatePEM string `json:"certificate_pem"`
	}
	if err := c.decode(&req); err != nil {
		return err
	}
	if req.CertificatePEM == "" || len(req.CertificatePEM) > ca.MaxCertSize {
		return badRequest("/certificate_pem", "one PEM certificate of at most 64 KiB")
	}
	info, err := a.d.Engine.ImportExternal(c.ctx(), []byte(req.CertificatePEM), c.who())
	if err != nil {
		return err
	}
	c.w.Header().Set("Location", BasePath+"/certificates/"+info.ID)
	return c.reply(http.StatusCreated, toCertificateJSON(info))
}

func (a *API) planCertificateRevocation(c *call) error {
	id := c.r.PathValue("certificateId")
	if !idPattern.MatchString(id) {
		return ca.ErrNotFound
	}
	var req struct {
		PlannedAt time.Time `json:"planned_at"`
	}
	if err := c.decode(&req); err != nil {
		return err
	}
	if req.PlannedAt.IsZero() || !req.PlannedAt.After(a.d.Clock.Now()) {
		return badRequest("/planned_at", "a present or future RFC 3339 time is required")
	}
	if req.PlannedAt.After(a.d.Clock.Now().Add(30 * 24 * time.Hour)) {
		return badRequest("/planned_at", "at most 30 days ahead")
	}
	if err := a.d.Engine.PlanRevocation(c.ctx(), ca.PlanRevocationRequest{CertificateID: id, PlannedAt: req.PlannedAt, Who: c.who()}); err != nil {
		var denied *ca.DeniedError
		if errors.As(err, &denied) && !errors.Is(err, authz.ErrDenied) && !errors.Is(err, authz.ErrStepUpRequired) {
			return c.problem(http.StatusConflict, "conflict", err.Error(), nil)
		}
		return err
	}
	return a.getCertificate(c)
}

func (a *API) cancelCertificateRevocation(c *call) error {
	id := c.r.PathValue("certificateId")
	if !idPattern.MatchString(id) {
		return ca.ErrNotFound
	}
	if err := a.d.Engine.CancelRevocationPlan(c.ctx(), c.who(), id); err != nil {
		var denied *ca.DeniedError
		if errors.As(err, &denied) && !errors.Is(err, authz.ErrDenied) && !errors.Is(err, authz.ErrStepUpRequired) {
			return c.problem(http.StatusConflict, "conflict", err.Error(), nil)
		}
		return err
	}
	return a.getCertificate(c)
}
