package httpapi

import (
	"errors"
	"net/http"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/auth"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
)

type systemStatusJSON struct {
	Version     string     `json:"version"`
	Sealed      bool       `json:"sealed"`
	SealedSince *time.Time `json:"sealed_since"`
	Demo        bool       `json:"demo"`
	ServerTime  time.Time  `json:"server_time"`
}

func (a *API) status() systemStatusJSON {
	st := a.d.Keys.Status()
	out := systemStatusJSON{Version: a.d.Version, Sealed: st.Sealed, Demo: a.d.Demo, ServerTime: a.now().Truncate(time.Second)}
	if st.Sealed && !st.SealedSince.IsZero() {
		t := st.SealedSince.UTC()
		out.SealedSince = &t
	}
	return out
}

func (a *API) systemStatus(c *call) error { return c.reply(http.StatusOK, a.status()) }

// unseal: a signed-in instance admin and the passphrase; the keyring checks
// the permission, slows down guessing per instance and per address and
// audits every attempt.
func (a *API) unseal(c *call) error {
	var req struct {
		Passphrase string `json:"passphrase"`
	}
	if err := c.decode(&req); err != nil {
		return err
	}
	if req.Passphrase == "" || len(req.Passphrase) > 1024 {
		return badRequest("/passphrase", "1 to 1024 characters")
	}
	pass := []byte(req.Passphrase)
	defer clear(pass)
	if err := a.d.Keys.Unseal(c.ctx(), pass, c.who()); err != nil {
		return err
	}
	return c.reply(http.StatusOK, a.status())
}

func (a *API) seal(c *call) error {
	if err := a.d.Keys.Seal(c.ctx(), c.who()); err != nil {
		return err
	}
	return c.reply(http.StatusOK, a.status())
}

func (a *API) login(c *call) error {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.decode(&req); err != nil {
		return err
	}
	if req.Username == "" || len(req.Username) > 128 || req.Password == "" || len(req.Password) > 1024 {
		return auth.ErrInvalidLogin
	}
	res, err := a.d.Auth.LoginFrom(c.ctx(), req.Username, req.Password, c.client)
	if err != nil {
		return err
	}
	http.SetCookie(c.w, auth.SessionCookie(res.Token))
	return c.reply(http.StatusOK, struct {
		SecondFactorRequired bool      `json:"second_factor_required"`
		Methods              []string  `json:"methods"`
		FirstTOTP            bool      `json:"first_totp"`
		PendingExpiresAt     time.Time `json:"pending_expires_at"`
	}{true, []string{"totp"}, res.FirstTOTP, res.Session.ExpiresAt.UTC()})
}

// secondFactor completes the sign-in: a new session ID (no session
// fixation) and a renewed device cookie.
func (a *API) secondFactor(c *call) error {
	var req struct {
		Code string `json:"code"`
	}
	if err := c.decode(&req); err != nil {
		return err
	}
	res, err := a.d.Auth.SecondFactor(c.ctx(), c.token, req.Code, c.client)
	if errors.Is(err, auth.ErrInvalidCode) {
		// The pending session is valid: "wrong code", not "sign in again"
		// (owner 2026-10-17). Throttle and lockout count it as before.
		return c.problem(http.StatusUnprocessableEntity, "wrong-secret", auth.ErrInvalidCode.Error(), nil)
	}
	if err != nil {
		return err
	}
	http.SetCookie(c.w, auth.SessionCookie(res.Token))
	http.SetCookie(c.w, auth.DeviceCookie(res.DeviceCookie))
	c.session = res.Session
	out := sessionJSON(res.Session)
	if res.Factor == "recovery_code" {
		left := res.RecoveryCodesLeft
		out.RecoveryCodesLeft = &left
	}
	out.Warnings = res.Warnings
	return c.reply(http.StatusOK, out)
}

func (a *API) stepUp(c *call) error {
	var req struct {
		Code string `json:"code"`
	}
	if err := c.decode(&req); err != nil {
		return err
	}
	sess, err := a.d.Auth.StepUpFrom(c.ctx(), c.token, req.Code, c.client)
	if errors.Is(err, auth.ErrInvalidCode) {
		return c.problem(http.StatusUnprocessableEntity, "wrong-secret", auth.ErrInvalidCode.Error(), nil)
	}
	if err != nil {
		return err
	}
	return c.reply(http.StatusOK, sessionJSON(sess))
}

func (a *API) getSession(c *call) error { return c.reply(http.StatusOK, sessionJSON(c.session)) }

// logout ends the session; the device cookie stays (a known browser).
func (a *API) logout(c *call) error {
	if err := a.d.Auth.Logout(c.ctx(), c.token, c.client.IP); err != nil {
		return err
	}
	http.SetCookie(c.w, auth.ClearSessionCookie())
	c.status = http.StatusNoContent
	c.w.WriteHeader(http.StatusNoContent)
	return nil
}

type sessionUserJSON struct {
	ID            string `json:"id"`
	Username      string `json:"username"`
	InstanceAdmin bool   `json:"instance_admin"`
}

type roleBindingJSON struct {
	Role  string `json:"role"`
	Scope struct {
		Type string `json:"type"`
		ID   string `json:"id,omitempty"`
	} `json:"scope"`
}

type sessionOut struct {
	User              sessionUserJSON   `json:"user"`
	Roles             []roleBindingJSON `json:"roles"`
	IdleExpiresAt     time.Time         `json:"idle_expires_at"`
	AbsoluteExpiresAt time.Time         `json:"absolute_expires_at"`
	StepUpValidUntil  *time.Time        `json:"step_up_valid_until"`
	CSRFToken         string            `json:"csrf_token"`
	RecoveryCodesLeft *int              `json:"recovery_codes_left,omitempty"`
	Warnings          []string          `json:"warnings,omitempty"`
}

func sessionJSON(s *auth.Session) sessionOut {
	out := sessionOut{
		User:  sessionUserJSON{ID: s.UserID, Username: s.Username},
		Roles: []roleBindingJSON{}, IdleExpiresAt: s.IdleExpiresAt().UTC(), AbsoluteExpiresAt: s.ExpiresAt.UTC(),
		CSRFToken: s.CSRFToken,
	}
	if p := s.Principal; p != nil {
		out.User.InstanceAdmin = p.InstanceAdmin
		for _, b := range p.Bindings {
			rb := roleBindingJSON{Role: string(b.Role)}
			rb.Scope.Type = "tenant"
			if b.CA != "" {
				rb.Scope.Type, rb.Scope.ID = "ca", b.CA
			}
			out.Roles = append(out.Roles, rb)
		}
	}
	if !s.StepUpAt.IsZero() {
		t := s.StepUpAt.Add(authz.StepUpWindow).UTC()
		out.StepUpValidUntil = &t
	}
	return out
}
