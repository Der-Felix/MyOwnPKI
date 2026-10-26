package web

import (
	"errors"
	"log/slog"
	"math"
	"net/http"
	"slices"
	"strconv"

	"github.com/Der-Felix/MyOwnPKI/internal/auth"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/web/pages/signin"
	"github.com/Der-Felix/MyOwnPKI/internal/web/view"
)

// signInFailed is the one message for a wrong name, a wrong password and a
// lockout (owner 2026-10-17): the page must not tell an invented name from
// a real one that strangers locked – neither by the text nor by a wait time.
const signInFailed = "Sign-in failed. Check user name and password. After several failed attempts, sign-in pauses for a few minutes."

func (a *app) loginPage(c *rc) {
	next := safeNext(c.r.URL.Query().Get("next"))
	if _, err := a.d.Auth.Authenticate(c.r.Context(), c.token); err == nil {
		c.redirect(next)
		return
	}
	p := c.page("Sign in", "")
	p.Crumbs = nil
	render(c.w, c.r, a.log, http.StatusOK, signin.Login(p, signin.FormData{Next: next, Messages: c.messages()}))
}

func (a *app) login(c *rc) {
	next := safeNext(c.r.PostFormValue("next"))
	res, err := a.d.Auth.LoginFrom(c.r.Context(), c.r.PostFormValue("username"), c.r.PostFormValue("password"), c.client)
	var locked *auth.LockedError
	switch {
	case errors.Is(err, auth.ErrInvalidLogin) || errors.As(err, &locked):
		c.setFlash(view.Message{Kind: view.MessageError, Text: signInFailed})
		c.redirect(loginURL("/login", next))
		return
	case errors.Is(err, auth.ErrBusy):
		c.setFlash(view.Message{Kind: view.MessageError, Text: "The server is busy – try again in a moment."})
		c.redirect(loginURL("/login", next))
		return
	case err != nil:
		a.log.ErrorContext(c.r.Context(), "sign-in", slog.Any("error", err))
		c.setFlash(view.Message{Kind: view.MessageError, Text: "Sign-in is not possible right now – the server log has the details."})
		c.redirect(loginURL("/login", next))
		return
	}
	http.SetCookie(c.w, auth.SessionCookie(res.Token))
	if res.FirstTOTP {
		c.setFlash(view.Message{Kind: view.MessageInfo, Text: "This sign-in completes the setup of your authenticator app: enter its current code."})
	}
	c.redirect(loginURL("/login/code", next))
}

func (a *app) codePage(c *rc) {
	next := safeNext(c.r.URL.Query().Get("next"))
	if c.token == "" {
		c.redirect(loginURL("/login", next))
		return
	}
	p := c.page("Second factor", "")
	p.Crumbs = nil
	render(c.w, c.r, a.log, http.StatusOK, signin.Code(p, signin.FormData{Next: next, Messages: c.messages()}))
}

func (a *app) code(c *rc) {
	next := safeNext(c.r.PostFormValue("next"))
	res, err := a.d.Auth.SecondFactor(c.r.Context(), c.token, c.r.PostFormValue("code"), c.client)
	var locked *auth.LockedError
	switch {
	case errors.Is(err, auth.ErrInvalidCode):
		c.setFlash(view.Message{Kind: view.MessageError, Text: "Wrong or already used code – enter the current one."})
		c.redirect(loginURL("/login/code", next))
		return
	case errors.Is(err, auth.ErrNoSession):
		c.setFlash(view.Message{Kind: view.MessageError, Text: "The sign-in took longer than 5 minutes – please start again."})
		c.redirect(loginURL("/login", next))
		return
	case errors.Is(err, auth.ErrInvalidLogin) || errors.As(err, &locked):
		c.setFlash(view.Message{Kind: view.MessageError, Text: signInFailed})
		c.redirect(loginURL("/login", next))
		return
	case err != nil:
		a.log.ErrorContext(c.r.Context(), "second factor", slog.Any("error", err))
		c.setFlash(view.Message{Kind: view.MessageError, Text: "Sign-in is not possible right now – the server log has the details."})
		c.redirect(loginURL("/login", next))
		return
	}
	http.SetCookie(c.w, auth.SessionCookie(res.Token))
	http.SetCookie(c.w, auth.DeviceCookie(res.DeviceCookie))
	var msgs []view.Message
	if res.FirstTOTP {
		msgs = append(msgs, view.Message{Kind: view.MessageSuccess, Text: "Your authenticator app is set up."})
	}
	for _, w := range res.Warnings {
		msgs = append(msgs, view.Message{Kind: view.MessageWarning, Text: w + "."})
	}
	if len(msgs) > 0 {
		c.setFlash(msgs...)
	}
	// Sealed: an instance admin is asked to unseal first.
	if res.Session.Principal != nil && res.Session.Principal.InstanceAdmin && a.d.Keys.Status().Sealed {
		c.redirect(loginURL("/unseal", next))
		return
	}
	c.redirect(next)
}

func (a *app) logout(c *rc) {
	if err := a.d.Auth.Logout(c.r.Context(), c.token, c.client.IP); err != nil {
		a.log.ErrorContext(c.r.Context(), "sign-out", slog.Any("error", err))
	}
	http.SetCookie(c.w, auth.ClearSessionCookie())
	c.setFlash(view.Message{Kind: view.MessageSuccess, Text: "Signed out."})
	c.redirect("/login")
}

func (a *app) unsealPage(c *rc) {
	next := safeNext(c.r.URL.Query().Get("next"))
	if !c.instanceAdmin() {
		c.notice(http.StatusForbidden, "Unseal", view.Message{Kind: view.MessageError, Text: "Only an instance admin can unseal the server."})
		return
	}
	st := a.d.Keys.Status()
	if !st.Sealed {
		c.redirect(next)
		return
	}
	d := signin.UnsealData{FormData: signin.FormData{Next: next, CSRF: c.sess.CSRFToken, Messages: c.messages()}}
	d.Facts = append(d.Facts, view.KV{Key: "Sealed since", Value: view.DateTime(st.SealedSince)})
	statuses, err := ca.CRLStatuses(c.r.Context(), a.d.Engine.PKI, a.now())
	if err != nil {
		c.fail(err)
		return
	}
	for _, s := range statuses {
		if msg := s.Message(true); msg != "" {
			d.Facts = append(d.Facts, view.KV{Key: "CRL of " + s.CA + "/" + strconv.FormatInt(s.Generation, 10), Value: msg})
		}
	}
	p := c.page("Unseal", "")
	p.Description = "The online CA keys are encrypted at rest. Unsealing decrypts them into memory; signing and CRL renewal start again."
	// The page itself says "sealed": no second notice above it.
	p.Notices = slices.DeleteFunc(p.Notices, func(m view.Message) bool { return m.Href == "/unseal" })
	render(c.w, c.r, a.log, http.StatusOK, signin.Unseal(p, d))
}

func (a *app) unseal(c *rc) {
	next := safeNext(c.r.PostFormValue("next"))
	pass := []byte(c.r.PostFormValue("passphrase"))
	defer clear(pass)
	err := a.d.Keys.Unseal(c.r.Context(), pass, c.who())
	var locked *keys.LockedError
	switch {
	case err == nil:
		c.setFlash(view.Message{Kind: view.MessageSuccess, Text: "Unsealed – signing and CRL renewal are on."})
		c.redirect(next)
	case errors.Is(err, keys.ErrAlreadyUnsealed):
		c.redirect(next)
	case errors.Is(err, keys.ErrWrongSecret):
		c.setFlash(view.Message{Kind: view.MessageError, Text: "Wrong passphrase."})
		c.redirect(loginURL("/unseal", next))
	case errors.As(err, &locked):
		c.setFlash(view.Message{Kind: view.MessageError, Text: "Too many wrong passphrases – try again in " + minutes(locked.RetryAfter.Minutes()) + "."})
		c.redirect(loginURL("/unseal", next))
	case errors.Is(err, authz.ErrDenied):
		c.fail(err)
	default:
		a.log.ErrorContext(c.r.Context(), "unseal", slog.Any("error", err))
		c.setFlash(view.Message{Kind: view.MessageError, Text: "Unsealing failed – the server log has the details."})
		c.redirect(loginURL("/unseal", next))
	}
}

func minutes(m float64) string {
	n := max(1, int(math.Ceil(m)))
	if n == 1 {
		return "1 minute"
	}
	return strconv.Itoa(n) + " minutes"
}

func (a *app) seal(c *rc) {
	if err := a.d.Keys.Seal(c.r.Context(), c.who()); err != nil {
		if errors.Is(err, authz.ErrDenied) {
			c.fail(err)
			return
		}
		a.log.ErrorContext(c.r.Context(), "seal", slog.Any("error", err))
	}
	c.setFlash(view.Message{Kind: view.MessageSuccess, Text: "Sealed – signing is off until the next unseal."})
	c.redirect("/")
}

func (a *app) stepUpPage(c *rc) {
	next := safeNext(c.r.URL.Query().Get("next"))
	p := c.page("Confirm with your second factor", "")
	p.Description = "This action needs a fresh code. Afterwards you are back on the page and start the action again."
	render(c.w, c.r, a.log, http.StatusOK, signin.StepUp(p, signin.FormData{Next: next, CSRF: c.sess.CSRFToken, Messages: c.messages()}))
}

// stepUp: back to the page, never the action itself (owner 2026-10-17).
func (a *app) stepUp(c *rc) {
	next := safeNext(c.r.PostFormValue("next"))
	sess, err := a.d.Auth.StepUpFrom(c.r.Context(), c.token, c.r.PostFormValue("code"), c.client)
	var locked *auth.LockedError
	switch {
	case err == nil:
		c.setFlash(view.Message{Kind: view.MessageSuccess, Text: "Confirmed for " + minutes(sess.StepUpDuration.Minutes()) + " – start the action again."})
		c.redirect(next)
	case errors.Is(err, auth.ErrInvalidCode):
		c.setFlash(view.Message{Kind: view.MessageError, Text: "Wrong or already used code – enter the current one."})
		c.redirect(loginURL("/step-up", next))
	case errors.As(err, &locked):
		c.setFlash(view.Message{Kind: view.MessageError, Text: "Too many failed attempts – try again in " + minutes(locked.RetryAfter.Minutes()) + "."})
		c.redirect(loginURL("/step-up", next))
	default:
		a.log.ErrorContext(c.r.Context(), "step-up", slog.Any("error", err))
		c.setFlash(view.Message{Kind: view.MessageError, Text: "The confirmation failed – the server log has the details."})
		c.redirect(loginURL("/step-up", next))
	}
}
