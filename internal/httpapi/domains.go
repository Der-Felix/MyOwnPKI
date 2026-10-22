package httpapi

import (
	"net/http"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/ca"
)

// Domains (PHASE2 step 1): what ACME issues for, per name space.

type domainJSON struct {
	ID                string    `json:"id"`
	Name              string    `json:"name"`
	CAID              string    `json:"ca_id"`
	CAName            string    `json:"ca_name"`
	IncludeSubdomains bool      `json:"include_subdomains"`
	Wildcards         bool      `json:"wildcards"`
	ChallengeTypes    []string  `json:"challenge_types"`
	Approval          string    `json:"approval"`
	Preset            string    `json:"preset"`
	ValidityDays      int       `json:"validity_days"`
	AddressPolicy     string    `json:"address_policy"`
	IPRanges          []string  `json:"ip_ranges"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

func toDomainJSON(d *ca.Domain) domainJSON {
	ranges := make([]string, 0, len(d.IPRanges))
	for _, r := range d.IPRanges {
		ranges = append(ranges, r.String())
	}
	return domainJSON{
		ID: d.ID, Name: d.Name, CAID: d.CAID, CAName: d.CA, IncludeSubdomains: d.IncludeSubdomains, Wildcards: d.Wildcards,
		ChallengeTypes: d.ChallengeTypes, Approval: d.Approval, Preset: d.Preset, ValidityDays: d.EffectiveValidityDays(),
		AddressPolicy: d.AddressPolicy, IPRanges: ranges, CreatedAt: d.CreatedAt, UpdatedAt: d.UpdatedAt,
	}
}

// domainSettingsJSON is the changeable part; absent fields keep their value
// (or take the default for a new domain).
type domainSettingsJSON struct {
	CAID              *string  `json:"ca_id"`
	IncludeSubdomains *bool    `json:"include_subdomains"`
	Wildcards         *bool    `json:"wildcards"`
	ChallengeTypes    []string `json:"challenge_types"`
	Approval          *string  `json:"approval"`
	Preset            *string  `json:"preset"`
	ValidityDays      *int     `json:"validity_days"`
	AddressPolicy     *string  `json:"address_policy"`
	IPRanges          []string `json:"ip_ranges"`
}

func (a *API) domainSettings(c *call, in domainSettingsJSON) (ca.DomainSettings, error) {
	s := ca.DomainSettings{
		IncludeSubdomains: in.IncludeSubdomains, Wildcards: in.Wildcards, ChallengeTypes: in.ChallengeTypes,
		Approval: in.Approval, Preset: in.Preset, ValidityDays: in.ValidityDays, AddressPolicy: in.AddressPolicy, IPRanges: in.IPRanges,
	}
	if in.CAID != nil {
		if !idPattern.MatchString(*in.CAID) {
			return s, badRequest("/ca_id", "not an ID")
		}
		name, err := a.d.Engine.CAName(c.ctx(), c.who(), *in.CAID)
		if err != nil {
			return s, err
		}
		s.CA = &name
	}
	return s, nil
}

func (a *API) listDomains(c *call) error {
	list, err := a.d.Engine.ListDomains(c.ctx(), c.who())
	if err != nil {
		return err
	}
	out := make([]domainJSON, 0, len(list))
	for i := range list {
		out = append(out, toDomainJSON(&list[i]))
	}
	return c.reply(http.StatusOK, out)
}

func (a *API) createDomain(c *call) error {
	var req struct {
		Name string `json:"name"`
		domainSettingsJSON
	}
	if err := c.decode(&req); err != nil {
		return err
	}
	if req.CAID == nil {
		return badRequest("/ca_id", "required")
	}
	s, err := a.domainSettings(c, req.domainSettingsJSON)
	if err != nil {
		return err
	}
	d, err := a.d.Engine.CreateDomain(c.ctx(), ca.DomainRequest{Name: req.Name, DomainSettings: s, Who: c.who()})
	if err != nil {
		return err
	}
	c.w.Header().Set("Location", BasePath+"/domains/"+d.ID)
	return c.reply(http.StatusCreated, toDomainJSON(d))
}

func (a *API) domainID(c *call) (string, error) {
	id := c.r.PathValue("domainId")
	if !idPattern.MatchString(id) {
		return "", ca.ErrNotFound
	}
	return id, nil
}

func (a *API) getDomain(c *call) error {
	id, err := a.domainID(c)
	if err != nil {
		return err
	}
	d, err := a.d.Engine.GetDomain(c.ctx(), c.who(), id)
	if err != nil {
		return err
	}
	return c.reply(http.StatusOK, toDomainJSON(d))
}

func (a *API) updateDomain(c *call) error {
	id, err := a.domainID(c)
	if err != nil {
		return err
	}
	var req domainSettingsJSON
	if derr := c.decode(&req); derr != nil {
		return derr
	}
	s, err := a.domainSettings(c, req)
	if err != nil {
		return err
	}
	d, err := a.d.Engine.UpdateDomain(c.ctx(), id, s, c.who())
	if err != nil {
		return err
	}
	return c.reply(http.StatusOK, toDomainJSON(d))
}

func (a *API) deleteDomain(c *call) error {
	id, err := a.domainID(c)
	if err != nil {
		return err
	}
	if err := a.d.Engine.DeleteDomain(c.ctx(), id, c.who()); err != nil {
		return err
	}
	c.status = http.StatusNoContent
	c.w.WriteHeader(http.StatusNoContent)
	return nil
}
