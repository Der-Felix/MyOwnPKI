package ca

import (
	"strings"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
)

// authorize checks the permission of who on a CA of this tenant; ca "" is an
// action on the whole tenant (creating a CA). A refusal is a *DeniedError
// whose Cause is authz.ErrDenied or authz.ErrStepUpRequired, so every caller
// audits it as denied (security.md: permissions are checked in the service
// layer, not only in HTTP handlers).
func (e *Engine) authorize(who keys.Who, perm authz.Permission, ca string, now time.Time) error {
	tenant := strings.TrimPrefix(e.Scope, "tenant:")
	if err := who.Principal.Check(perm, authz.Resource{Tenant: tenant, CA: ca}, now); err != nil {
		return &DeniedError{Reasons: []string{err.Error()}, Cause: err}
	}
	return nil
}
