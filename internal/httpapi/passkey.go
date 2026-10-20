package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/auth"
)

// Passkeys (PHASE1 step 17): the WebAuthn ceremonies pass the browser's
// JSON through unchanged; the service checks it.

// readRaw reads a JSON body without decoding it (the WebAuthn answer).
func (c *call) readRaw() ([]byte, error) {
	body, err := io.ReadAll(c.r.Body) // the router limits the body to MaxBody
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		return nil, &bodyError{status: http.StatusRequestEntityTooLarge, kind: "too-large", msg: fmt.Sprintf("the body is larger than %d KiB", MaxBody>>10)}
	}
	if err != nil {
		return nil, err
	}
	if !json.Valid(body) {
		return nil, badRequest("", "the body is not JSON")
	}
	return body, nil
}

func (c *call) passkeyError(err error) error {
	switch {
	case errors.Is(err, auth.ErrInvalidLogin):
		// The session is valid; the current password was wrong (decision 64).
		return c.problem(http.StatusUnprocessableEntity, "wrong-secret", "wrong password", nil)
	case errors.Is(err, auth.ErrPasskeysOff):
		return c.problem(http.StatusNotFound, "not-found", err.Error(), nil)
	case errors.Is(err, auth.ErrNoPasskey):
		return c.problem(http.StatusConflict, "conflict", err.Error(), nil)
	case errors.Is(err, auth.ErrNoCeremony), errors.Is(err, auth.ErrTooManyPasskeys):
		return c.problem(http.StatusConflict, "conflict", err.Error(), nil)
	case errors.Is(err, auth.ErrInvalidCode):
		return c.problem(http.StatusUnprocessableEntity, "wrong-secret", "the passkey was not accepted", nil)
	}
	var r *auth.RefusedError
	if errors.As(err, &r) {
		fields := make([]fieldError, 0, len(r.Reasons))
		for _, reason := range r.Reasons {
			fields = append(fields, fieldError{Message: reason})
		}
		return c.problem(http.StatusUnprocessableEntity, "policy-violation", "the passkey was refused", fields)
	}
	return err
}

func (a *API) passkeyBegin(c *call) error {
	options, err := a.d.Auth.BeginPasskeyLogin(c.ctx(), c.token, c.client)
	if err != nil {
		return c.passkeyError(err)
	}
	return c.replyRaw(http.StatusOK, options)
}

// passkeyFinish completes a sign-in (pending session: a new session ID and
// device cookie, as after a TOTP code) or a step-up (signed in).
func (a *API) passkeyFinish(c *call) error {
	body, err := c.readRaw()
	if err != nil {
		return err
	}
	res, err := a.d.Auth.FinishPasskeyLogin(c.ctx(), c.token, body, c.client)
	if err != nil {
		return c.passkeyError(err)
	}
	if res.DeviceCookie != "" {
		http.SetCookie(c.w, auth.SessionCookie(res.Token))
		http.SetCookie(c.w, auth.DeviceCookie(res.DeviceCookie))
	}
	c.session = res.Session
	return c.reply(http.StatusOK, sessionJSON(res.Session))
}

func (a *API) passkeyRegisterBegin(c *call) error {
	var req struct {
		Password string `json:"password"`
	}
	if err := c.decode(&req); err != nil {
		return err
	}
	if err := c.session.Principal.FreshStepUp(a.now()); err != nil {
		return err
	}
	options, err := a.d.Auth.BeginPasskeyRegistration(c.ctx(), c.token, req.Password, c.client.IP)
	if err != nil {
		return c.passkeyError(err)
	}
	return c.replyRaw(http.StatusOK, options)
}

func (a *API) passkeyRegisterFinish(c *call) error {
	body, err := c.readRaw()
	if err != nil {
		return err
	}
	name := c.r.URL.Query().Get("name")
	pk, err := a.d.Auth.FinishPasskeyRegistration(c.ctx(), c.token, name, body, c.client.IP)
	if err != nil {
		return c.passkeyError(err)
	}
	return c.reply(http.StatusCreated, passkeyJSON(*pk))
}

type passkeyOut struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
}

func passkeyJSON(p auth.Passkey) passkeyOut {
	out := passkeyOut{ID: p.ID, Name: p.Name, CreatedAt: p.CreatedAt.UTC()}
	if !p.LastUsedAt.IsZero() {
		t := p.LastUsedAt.UTC()
		out.LastUsedAt = &t
	}
	return out
}

func (a *API) listPasskeys(c *call) error {
	list, err := a.d.Auth.ListPasskeys(c.ctx(), c.token)
	if err != nil {
		return err
	}
	out := []passkeyOut{}
	for _, p := range list {
		out = append(out, passkeyJSON(p))
	}
	return c.reply(http.StatusOK, struct {
		Items []passkeyOut `json:"items"`
	}{out})
}

func (a *API) deletePasskey(c *call) error {
	var req struct {
		Password string `json:"password"`
	}
	if err := c.decode(&req); err != nil {
		return err
	}
	if err := c.session.Principal.FreshStepUp(a.now()); err != nil {
		return err
	}
	err := a.d.Auth.DeletePasskey(c.ctx(), c.token, c.r.PathValue("passkeyId"), req.Password, c.client.IP)
	if errors.Is(err, auth.ErrNoPasskey) {
		return c.problem(http.StatusNotFound, "not-found", "no such passkey", nil)
	}
	if err != nil {
		return c.passkeyError(err)
	}
	c.status = http.StatusNoContent
	c.w.WriteHeader(http.StatusNoContent)
	return nil
}
