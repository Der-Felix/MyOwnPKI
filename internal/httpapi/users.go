package httpapi

import (
	"errors"
	"net/http"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/auth"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/tenant"
)

// Users, the own account, API tokens and tenant settings (step 18).

type userJSON struct {
	ID            string            `json:"id"`
	Username      string            `json:"username"`
	InstanceAdmin bool              `json:"instance_admin"`
	Disabled      bool              `json:"disabled"`
	LockedUntil   *time.Time        `json:"locked_until"`
	MFA           mfaJSON           `json:"mfa"`
	Roles         []roleBindingJSON `json:"roles"`
	CreatedAt     time.Time         `json:"created_at"`
}

type mfaJSON struct {
	TOTPConfirmed bool `json:"totp_confirmed"`
	Passkeys      int  `json:"passkeys"`
}

func bindingJSON(b authz.Binding) roleBindingJSON {
	rb := roleBindingJSON{Role: string(b.Role)}
	rb.Scope.Type = "tenant"
	if b.CA != "" {
		rb.Scope.Type, rb.Scope.ID = "ca", b.CA
	}
	return rb
}

func toUserJSON(u *auth.UserInfo) userJSON {
	out := userJSON{ID: u.ID, Username: u.Username, InstanceAdmin: u.InstanceAdmin, Disabled: u.Disabled,
		MFA: mfaJSON{TOTPConfirmed: u.TOTPConfirmed, Passkeys: u.Passkeys}, Roles: []roleBindingJSON{}, CreatedAt: u.CreatedAt.UTC()}
	if !u.LockedUntil.IsZero() {
		t := u.LockedUntil.UTC()
		out.LockedUntil = &t
	}
	for _, b := range u.Roles {
		out.Roles = append(out.Roles, bindingJSON(b))
	}
	return out
}

// bindingsFrom turns API role bindings into bindings of this tenant; a CA
// scope names the CA by ID.
func (a *API) bindingsFrom(c *call, in []roleBindingJSON) ([]authz.Binding, error) {
	out := make([]authz.Binding, 0, len(in))
	for _, rb := range in {
		b := authz.Binding{Tenant: a.d.Tenant, Role: authz.Role(rb.Role)}
		switch rb.Scope.Type {
		case "tenant":
			if rb.Scope.ID != "" {
				return nil, badRequest("/roles", "a tenant scope has no id (the tenant comes from the server)")
			}
		case "ca":
			name, err := a.d.Engine.CAName(c.ctx(), c.who(), rb.Scope.ID)
			if err != nil {
				return nil, badRequest("/roles", "unknown CA %q", rb.Scope.ID)
			}
			b.CA = name
		default:
			return nil, badRequest("/roles", "scope type tenant or ca")
		}
		out = append(out, b)
	}
	return out, nil
}

// userError maps the refusals of user management.
func (c *call) userError(err error) error {
	var r *auth.RefusedError
	switch {
	case errors.Is(err, auth.ErrNoUser):
		return c.problem(http.StatusNotFound, "not-found", "no such user", nil)
	case errors.Is(err, auth.ErrNoToken):
		return c.problem(http.StatusNotFound, "not-found", auth.ErrNoToken.Error(), nil)
	case errors.As(err, &r):
		fields := make([]fieldError, 0, len(r.Reasons))
		for _, reason := range r.Reasons {
			fields = append(fields, fieldError{Message: reason})
		}
		return c.problem(http.StatusUnprocessableEntity, "policy-violation", "the request was refused", fields)
	}
	return err
}

func (a *API) listUsers(c *call) error {
	list, err := a.d.Auth.ListUsers(c.ctx(), c.who())
	if err != nil {
		return c.userError(err)
	}
	out := make([]userJSON, 0, len(list))
	for i := range list {
		out = append(out, toUserJSON(&list[i]))
	}
	return c.reply(http.StatusOK, out)
}

func (a *API) getUser(c *call) error {
	u, err := a.d.Auth.UserByID(c.ctx(), c.who(), c.r.PathValue("userId"))
	if err != nil {
		return c.userError(err)
	}
	return c.reply(http.StatusOK, toUserJSON(u))
}

// createUser: the second factor is fixed now; the instance admin hands the
// otpauth link and the recovery codes over once.
func (a *API) createUser(c *call) error {
	var req struct {
		Username      string            `json:"username"`
		Password      string            `json:"password"`
		InstanceAdmin bool              `json:"instance_admin"`
		Roles         []roleBindingJSON `json:"roles"`
	}
	if err := c.decode(&req); err != nil {
		return err
	}
	if req.Username == "" || req.Password == "" {
		return badRequest("", "username and password are required")
	}
	roles, err := a.bindingsFrom(c, req.Roles)
	if err != nil {
		return err
	}
	enr, err := a.d.Auth.CreateUser(c.ctx(), auth.NewUserRequest{Username: req.Username, Password: req.Password, InstanceAdmin: req.InstanceAdmin, Roles: roles, Who: c.who()})
	if err != nil {
		return c.userError(err)
	}
	u, err := a.d.Auth.UserByID(c.ctx(), c.who(), enr.UserID)
	if err != nil {
		return err
	}
	c.w.Header().Set("Location", BasePath+"/users/"+u.ID)
	return c.reply(http.StatusCreated, struct {
		User          userJSON `json:"user"`
		OTPAuthURI    string   `json:"otpauth_uri"`
		Secret        string   `json:"secret"`
		RecoveryCodes []string `json:"recovery_codes"`
	}{toUserJSON(u), enr.URI, enr.Secret, nonNil(enr.RecoveryCodes)})
}

func (a *API) updateUser(c *call) error {
	id := c.r.PathValue("userId")
	var req struct {
		Disabled *bool `json:"disabled"`
		Unlock   bool  `json:"unlock"`
	}
	if err := c.decode(&req); err != nil {
		return err
	}
	if req.Disabled == nil && !req.Unlock {
		return badRequest("", "give disabled or unlock")
	}
	if _, err := a.d.Auth.UserByID(c.ctx(), c.who(), id); err != nil {
		return c.userError(err)
	}
	if req.Disabled != nil {
		var err error
		if *req.Disabled {
			err = a.d.Auth.DisableUser(c.ctx(), id, c.who())
		} else {
			err = a.d.Auth.EnableUser(c.ctx(), id, c.who())
		}
		if err != nil {
			return c.userError(err)
		}
	}
	if req.Unlock {
		if err := a.d.Auth.UnlockByID(c.ctx(), id, c.who()); err != nil {
			return c.userError(err)
		}
	}
	return a.getUser(c)
}

// deleteUser disables: users are never deleted, their ID is in the audit log.
func (a *API) deleteUser(c *call) error {
	id := c.r.PathValue("userId")
	if _, err := a.d.Auth.UserByID(c.ctx(), c.who(), id); err != nil {
		return c.userError(err)
	}
	if err := a.d.Auth.DisableUser(c.ctx(), id, c.who()); err != nil {
		return c.userError(err)
	}
	c.status = http.StatusNoContent
	c.w.WriteHeader(http.StatusNoContent)
	return nil
}

func (a *API) setUserRoles(c *call) error {
	id := c.r.PathValue("userId")
	var req struct {
		Roles []roleBindingJSON `json:"roles"`
	}
	if err := c.decode(&req); err != nil {
		return err
	}
	if _, err := a.d.Auth.UserByID(c.ctx(), c.who(), id); err != nil {
		return c.userError(err)
	}
	roles, err := a.bindingsFrom(c, req.Roles)
	if err != nil {
		return err
	}
	if err := a.d.Auth.SetRoles(c.ctx(), id, a.d.Tenant, roles, c.who()); err != nil {
		return c.userError(err)
	}
	return a.getUser(c)
}

// ---------------------------------------------------------------- own account

func (a *API) changeOwnPassword(c *call) error {
	if err := c.session.Principal.FreshStepUp(a.now()); err != nil {
		return err
	}
	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := c.decode(&req); err != nil {
		return err
	}
	err := a.d.Auth.ChangePassword(c.ctx(), c.token, req.CurrentPassword, req.NewPassword, c.client.IP)
	if errors.Is(err, auth.ErrInvalidLogin) {
		return c.problem(http.StatusUnprocessableEntity, "wrong-secret", "wrong current password", nil)
	}
	var pw *auth.PolicyError
	if errors.As(err, &pw) {
		return c.problem(http.StatusUnprocessableEntity, "policy-violation", "the new password is refused", []fieldError{{Field: "/new_password", Message: pw.Error()}})
	}
	if err != nil {
		return err
	}
	c.status = http.StatusNoContent
	c.w.WriteHeader(http.StatusNoContent)
	return nil
}

func (a *API) beginTOTPEnrollment(c *call) error {
	var req struct {
		Password string `json:"password"`
	}
	if err := c.decode(&req); err != nil {
		return err
	}
	enr, err := a.d.Auth.StartTOTPChange(c.ctx(), c.token, req.Password, c.client.IP)
	if errors.Is(err, auth.ErrInvalidLogin) {
		return c.problem(http.StatusUnprocessableEntity, "wrong-secret", "wrong password", nil)
	}
	if err != nil {
		return err
	}
	return c.reply(http.StatusOK, struct {
		OTPAuthURI string `json:"otpauth_uri"`
		Secret     string `json:"secret"`
	}{enr.URI, enr.Secret})
}

func (a *API) confirmTOTPEnrollment(c *call) error {
	var req struct {
		Code string `json:"code"`
	}
	if err := c.decode(&req); err != nil {
		return err
	}
	err := a.d.Auth.ConfirmTOTPChange(c.ctx(), c.token, req.Code, c.client.IP)
	if errors.Is(err, auth.ErrInvalidCode) {
		return c.problem(http.StatusUnprocessableEntity, "wrong-secret", auth.ErrInvalidCode.Error(), nil)
	}
	if errors.Is(err, auth.ErrNoTOTPChange) {
		return c.problem(http.StatusConflict, "conflict", err.Error(), nil)
	}
	if err != nil {
		return err
	}
	c.status = http.StatusNoContent
	c.w.WriteHeader(http.StatusNoContent)
	return nil
}

func (a *API) newRecoveryCodes(c *call) error {
	var req struct {
		Password string `json:"password"`
	}
	if err := c.decode(&req); err != nil {
		return err
	}
	codes, err := a.d.Auth.NewRecoveryCodes(c.ctx(), c.token, req.Password, c.client.IP)
	if errors.Is(err, auth.ErrInvalidLogin) {
		return c.problem(http.StatusUnprocessableEntity, "wrong-secret", "wrong password", nil)
	}
	if err != nil {
		return err
	}
	return c.reply(http.StatusOK, struct {
		Codes []string `json:"codes"`
	}{codes})
}

// ---------------------------------------------------------------- tokens

type tokenJSON struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	Roles      []roleBindingJSON `json:"roles"`
	CreatedAt  time.Time         `json:"created_at"`
	ExpiresAt  time.Time         `json:"expires_at"`
	LastUsedAt *time.Time        `json:"last_used_at"`
}

func toTokenJSON(t auth.Token) tokenJSON {
	out := tokenJSON{ID: t.ID, Name: t.Name, Roles: []roleBindingJSON{}, CreatedAt: t.CreatedAt.UTC(), ExpiresAt: t.ExpiresAt.UTC()}
	for _, b := range t.Roles {
		out.Roles = append(out.Roles, bindingJSON(b))
	}
	if !t.LastUsedAt.IsZero() {
		l := t.LastUsedAt.UTC()
		out.LastUsedAt = &l
	}
	return out
}

func (a *API) listTokens(c *call) error {
	list, err := a.d.Auth.ListTokens(c.ctx(), c.token)
	if err != nil {
		return err
	}
	out := make([]tokenJSON, 0, len(list))
	for _, t := range list {
		out = append(out, toTokenJSON(t))
	}
	return c.reply(http.StatusOK, out)
}

func (a *API) createToken(c *call) error {
	if c.session.TokenID != "" {
		return c.problem(http.StatusForbidden, "forbidden", "an API token can't create tokens", nil)
	}
	if err := c.session.Principal.FreshStepUp(a.now()); err != nil {
		return err
	}
	var req struct {
		Name      string            `json:"name"`
		Roles     []roleBindingJSON `json:"roles"`
		ExpiresAt time.Time         `json:"expires_at"`
	}
	if err := c.decode(&req); err != nil {
		return err
	}
	roles, err := a.bindingsFrom(c, req.Roles)
	if err != nil {
		return err
	}
	secret, t, err := a.d.Auth.CreateToken(c.ctx(), c.token, req.Name, roles, req.ExpiresAt, c.client.IP)
	if err != nil {
		return c.userError(err)
	}
	return c.reply(http.StatusCreated, struct {
		tokenJSON
		Secret string `json:"secret"`
	}{toTokenJSON(*t), secret})
}

func (a *API) revokeToken(c *call) error {
	if err := a.d.Auth.RevokeToken(c.ctx(), c.token, c.r.PathValue("tokenId"), c.client.IP); err != nil {
		return c.userError(err)
	}
	c.status = http.StatusNoContent
	c.w.WriteHeader(http.StatusNoContent)
	return nil
}

// ---------------------------------------------------------------- settings

type settingsJSON struct {
	AllowServerKeygen bool        `json:"allow_server_keygen"`
	SubjectDefaults   subjectPart `json:"subject_defaults"`
	// Optional in a PUT (v0.1 clients don't send it): absent keeps the limits.
	ACMELimits *acmeLimitsJSON `json:"acme_limits,omitempty"`
	// Optional in a PUT (v0.2 clients don't send it): absent keeps the value.
	TrustPage *bool `json:"trust_page,omitempty"`
	// Optional in a PUT (v0.2 clients don't send it): absent keeps the mode.
	AgentEnrollment *string `json:"agent_enrollment,omitempty"`
	// Optional in a PUT (v0.3.0 clients don't send it): absent keeps the value.
	StepUpMinutes    *int                   `json:"step_up_minutes,omitempty"`
	AgentPredecessor *predecessorPolicyJSON `json:"agent_predecessor,omitempty"`
	OtherPredecessor *predecessorPolicyJSON `json:"other_predecessor,omitempty"`
}

type acmeLimitsJSON struct {
	OrdersPerAccount int `json:"orders_per_account"`
	FailedPerName    int `json:"failed_per_name"`
	AccountsPerIP    int `json:"accounts_per_ip"`
}

type subjectPart struct {
	Organization       string `json:"organization"`
	OrganizationalUnit string `json:"organizational_unit"`
	Locality           string `json:"locality"`
	State              string `json:"state"`
	Country            string `json:"country"`
}

func toSettingsJSON(s *tenant.Settings) settingsJSON {
	return settingsJSON{AllowServerKeygen: s.AllowServerKeygen, SubjectDefaults: subjectPart{
		Organization: s.Organization, OrganizationalUnit: s.OrganizationalUnit, Locality: s.Locality, State: s.State, Country: s.Country,
	},
		ACMELimits: &acmeLimitsJSON{OrdersPerAccount: s.ACME.OrdersPerAccount, FailedPerName: s.ACME.FailedPerName, AccountsPerIP: s.ACME.AccountsPerIP},
		TrustPage:  s.TrustPage, AgentEnrollment: s.AgentEnrollment, StepUpMinutes: s.StepUpMinutes,
		AgentPredecessor: predecessorPolicyPtr(*s.AgentPredecessor), OtherPredecessor: predecessorPolicyPtr(*s.OtherPredecessor)}
}

func (a *API) getSettings(c *call) error {
	s, err := a.d.Settings.Get(c.ctx(), a.d.Tenant, c.who())
	if err != nil {
		return err
	}
	return c.reply(http.StatusOK, toSettingsJSON(s))
}

func (a *API) putSettings(c *call) error {
	var req settingsJSON
	if err := c.decode(&req); err != nil {
		return err
	}
	d := req.SubjectDefaults
	v := tenant.Settings{AllowServerKeygen: req.AllowServerKeygen, Organization: d.Organization,
		OrganizationalUnit: d.OrganizationalUnit, Locality: d.Locality, State: d.State, Country: d.Country,
		TrustPage: req.TrustPage, AgentEnrollment: req.AgentEnrollment, StepUpMinutes: req.StepUpMinutes}
	if l := req.ACMELimits; l != nil {
		v.ACME = &tenant.ACMELimits{OrdersPerAccount: l.OrdersPerAccount, FailedPerName: l.FailedPerName, AccountsPerIP: l.AccountsPerIP}
	}
	if req.AgentPredecessor != nil {
		p := req.AgentPredecessor.value()
		v.AgentPredecessor = &p
	}
	if req.OtherPredecessor != nil {
		p := req.OtherPredecessor.value()
		v.OtherPredecessor = &p
	}
	err := a.d.Settings.Set(c.ctx(), a.d.Tenant, v, c.who())
	if errors.Is(err, tenant.ErrInvalid) {
		return c.problem(http.StatusUnprocessableEntity, "policy-violation", err.Error(), nil)
	}
	if err != nil {
		return err
	}
	return a.getSettings(c)
}
