package httpapi

import (
	"errors"
	"net/http"

	"github.com/Der-Felix/MyOwnPKI/internal/acme"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
)

type acmeAccountJSON struct {
	ID                   string                 `json:"id"`
	Status               string                 `json:"status"`
	Thumbprint           string                 `json:"key_thumbprint"`
	Approved             bool                   `json:"approved"`
	ApprovedBy           string                 `json:"approved_by,omitempty"`
	ApprovedAt           string                 `json:"approved_at,omitempty"`
	EABKey               string                 `json:"eab_key_id,omitempty"`
	Contacts             []string               `json:"contact"`
	CreatedAt            string                 `json:"created_at"`
	CreatedIP            string                 `json:"created_ip"`
	Predecessor          *predecessorPolicyJSON `json:"predecessor_policy"`
	EffectivePredecessor predecessorPolicyJSON  `json:"effective_predecessor"`
}

func toACMEAccountJSON(a *acme.AccountInfo) acmeAccountJSON {
	out := acmeAccountJSON{
		ID: a.ID, Status: a.Status, Thumbprint: a.Thumbprint, Approved: a.Approved,
		ApprovedBy: a.ApprovedBy, ApprovedAt: a.ApprovedAt, EABKey: a.EABKey,
		Contacts: nonNil(a.Contacts), CreatedAt: a.CreatedAt, CreatedIP: a.CreatedIP,
		EffectivePredecessor: toPredecessorPolicyJSON(a.EffectivePredecessor),
	}
	if a.Predecessor != nil {
		out.Predecessor = predecessorPolicyPtr(*a.Predecessor)
	}
	return out
}

func (a *API) acmeAccount(c *call) (*acme.AccountInfo, error) {
	if a.d.ACME == nil {
		return nil, ca.ErrNotFound
	}
	id := c.r.PathValue("accountId")
	if !idPattern.MatchString(id) {
		return nil, ca.ErrNotFound
	}
	account, err := a.d.ACME.Account(c.ctx(), c.who(), id)
	if errors.Is(err, acme.ErrNotFound) {
		return nil, ca.ErrNotFound
	}
	return account, err
}

func (a *API) getACMEAccount(c *call) error {
	account, err := a.acmeAccount(c)
	if err != nil {
		return err
	}
	return c.reply(http.StatusOK, toACMEAccountJSON(account))
}

func (a *API) getACMEPredecessorPolicy(c *call) error {
	return a.getACMEAccount(c)
}

func (a *API) setACMEPredecessorPolicy(c *call) error {
	id := c.r.PathValue("accountId")
	if !idPattern.MatchString(id) {
		return ca.ErrNotFound
	}
	var req predecessorPolicyJSON
	if err := c.decode(&req); err != nil {
		return err
	}
	policy := req.value()
	if err := policy.Validate(); err != nil {
		return badRequest("/choice", "%s", err)
	}
	if a.d.ACME == nil {
		return ca.ErrNotFound
	}
	if err := a.d.ACME.SetAccountPredecessor(c.ctx(), id, &policy, c.who()); errors.Is(err, acme.ErrNotFound) {
		return ca.ErrNotFound
	} else if err != nil {
		return err
	}
	return a.getACMEAccount(c)
}

func (a *API) clearACMEPredecessorPolicy(c *call) error {
	id := c.r.PathValue("accountId")
	if !idPattern.MatchString(id) {
		return ca.ErrNotFound
	}
	if a.d.ACME == nil {
		return ca.ErrNotFound
	}
	if err := a.d.ACME.SetAccountPredecessor(c.ctx(), id, nil, c.who()); errors.Is(err, acme.ErrNotFound) {
		return ca.ErrNotFound
	} else if err != nil {
		return err
	}
	return a.getACMEAccount(c)
}
