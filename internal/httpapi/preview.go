package httpapi

import (
	"net/http"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/ca"
)

// previewJSON is the schema CertificatePreview: what the engine's plan says,
// as JSON data. Nothing of the request is echoed – least of all the CSR – only
// what the engine derived from it. Names and reasons may carry attacker text;
// the JSON encoder escapes it (markup characters become \u escapes) and a client
// must escape it again where it renders it.
type previewJSON struct {
	GeneratedAt         time.Time        `json:"generated_at"`
	Allowed             bool             `json:"allowed"`
	Sealed              bool             `json:"sealed"`
	Reasons             []string         `json:"reasons"`
	Checks              []checkJSON      `json:"checks"`
	StoppedAt           *string          `json:"stopped_at"`
	CA                  *planCAJSON      `json:"ca"`
	Preset              *planPresetJSON  `json:"preset"`
	Subject             *planSubjectJSON `json:"subject"`
	SubjectDN           string           `json:"subject_dn"`
	Names               []nameJSON       `json:"names"`
	DroppedCSRNames     []string         `json:"dropped_csr_names"`
	Key                 *planKeyJSON     `json:"key"`
	Validity            *planValidity    `json:"validity"`
	KeyUsage            []string         `json:"key_usage"`
	ExtKeyUsage         []string         `json:"ext_key_usage"`
	ExtKeyUsageCritical bool             `json:"ext_key_usage_critical"`
	Extensions          []extensionJSON  `json:"extensions"`
	AIAURL              *string          `json:"aia_url"`
	CDPURL              *string          `json:"cdp_url"`
	Chain               []chainLinkJSON  `json:"chain"`
	Notes               []string         `json:"notes"`
	Warnings            []string         `json:"warnings"`
}

type checkJSON struct {
	Name      string   `json:"name"`
	Title     string   `json:"title"`
	Collected bool     `json:"collected"`
	Passed    bool     `json:"passed"`
	Problems  []string `json:"problems"`
}

type planCAJSON struct {
	Name            string `json:"name"`
	Generation      int64  `json:"generation"`
	MaxValidityDays int    `json:"max_validity_days"`
}

type planPresetJSON struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type planSubjectJSON struct {
	CommonName         string `json:"common_name"`
	Organization       string `json:"organization"`
	OrganizationalUnit string `json:"organizational_unit"`
	Locality           string `json:"locality"`
	State              string `json:"state"`
	Country            string `json:"country"`
}

type planKeyJSON struct {
	Algorithm string `json:"algorithm"`
	Source    string `json:"source"`
}

type planValidity struct {
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	Days      int       `json:"days"`
}

type nameJSON struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type extensionJSON struct {
	OID      string `json:"oid"`
	Name     string `json:"name"`
	Critical bool   `json:"critical"`
	Detail   string `json:"detail"`
}

type chainLinkJSON struct {
	CA       string    `json:"ca"`
	Subject  string    `json:"subject"`
	SHA256   string    `json:"sha256"`
	NotAfter time.Time `json:"not_after"`
	Root     bool      `json:"root"`
}

// toPreviewJSON maps a plan to its schema. Lists are never null; objects and
// strings that the plan did not get as far as are null.
func toPreviewJSON(p *ca.Plan) previewJSON {
	out := previewJSON{
		GeneratedAt: p.GeneratedAt.UTC(), Allowed: p.Allowed, Sealed: p.Sealed, Reasons: nonNil(p.Reasons),
		Checks: make([]checkJSON, 0, len(p.Checks)), StoppedAt: optString(p.StoppedAt),
		SubjectDN: p.SubjectDN, Names: make([]nameJSON, 0, len(p.Names)), DroppedCSRNames: nonNil(p.DroppedCSRNames),
		KeyUsage: nonNil(p.KeyUsage), ExtKeyUsage: nonNil(p.ExtKeyUsage), ExtKeyUsageCritical: p.ExtKeyUsageCritical,
		Extensions: make([]extensionJSON, 0, len(p.Extensions)), AIAURL: optString(p.AIAURL), CDPURL: optString(p.CDPURL),
		Chain: make([]chainLinkJSON, 0, len(p.Chain)), Notes: nonNil(p.Notes), Warnings: nonNil(p.Warnings),
	}
	for _, c := range p.Checks {
		out.Checks = append(out.Checks, checkJSON{Name: c.Name, Title: c.Title(), Collected: c.Collected, Passed: len(c.Problems) == 0, Problems: nonNil(c.Problems)})
	}
	if p.CA != "" {
		out.CA = &planCAJSON{Name: p.CA, Generation: p.Generation, MaxValidityDays: p.MaxValidityDays}
	}
	if p.Preset != "" {
		out.Preset = &planPresetJSON{Name: p.Preset, Description: p.PresetDescription}
		// The subject and the names are decided together with the preset.
		s := p.Subject
		out.Subject = &planSubjectJSON{CommonName: s.CommonName, Organization: s.Organization, OrganizationalUnit: s.OrganizationalUnit,
			Locality: s.Locality, State: s.Province, Country: s.Country}
	}
	for _, n := range p.Names {
		out.Names = append(out.Names, nameJSON{Type: n.Type, Value: n.Value})
	}
	if p.KeyAlgorithm != "" {
		out.Key = &planKeyJSON{Algorithm: p.KeyAlgorithm, Source: p.KeySource}
	}
	if p.Allowed {
		out.Validity = &planValidity{NotBefore: p.NotBefore.UTC(), NotAfter: p.NotAfter.UTC(), Days: p.Days}
	}
	for _, e := range p.Extensions {
		out.Extensions = append(out.Extensions, extensionJSON{OID: e.OID, Name: e.Name, Critical: e.Critical, Detail: e.Detail})
	}
	for _, l := range p.Chain {
		out.Chain = append(out.Chain, chainLinkJSON{CA: l.CA, Subject: l.Subject, SHA256: l.SHA256, NotAfter: l.NotAfter.UTC(), Root: l.Root})
	}
	return out
}

// previewCertificate shows what issueCertificate would do with the same body:
// the request is built by the same function and decided by the same policy
// (Engine.Plan). It writes nothing – no row, no audit entry, no key, no serial.
// A refusal by the policy is an answer (200, allowed false); who may not read
// the CA gets 404 and who may read but not issue 403, exactly as for issuing.
func (a *API) previewCertificate(c *call) error {
	r, err := a.certificateRequest(c)
	if err != nil {
		return err
	}
	if a.onRequest != nil {
		a.onRequest("previewCertificate", r)
	}
	plan, err := a.d.Engine.Plan(c.ctx(), r)
	if err != nil {
		return err
	}
	return c.reply(http.StatusOK, toPreviewJSON(plan))
}
