package acme

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"strings"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/acme/jose"
	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
)

// Audit actions of the ACME server.
const (
	ActionAccountCreate     = "acme.account.create"
	ActionAccountUpdate     = "acme.account.update"
	ActionAccountDeactivate = "acme.account.deactivate"
	ActionAccountKeyChange  = "acme.account.key_change"
	ActionAccountApprove    = "acme.account.approve"
	ActionOrderCreate       = "acme.order.create"
	ActionChallenge         = "acme.challenge.validate"
	ActionAuthzDeactivate   = "acme.authz.deactivate"
	ActionNameDecide        = "acme.name.decide"
	ActionEABCreate         = "acme.eab.create"
)

// EABAlgorithm names the MAC keys in the key ring.
const EABAlgorithm = "hs256"

const maxContacts = 5

type accountJSON struct {
	Status                 string   `json:"status"`
	Contact                []string `json:"contact"`
	Orders                 string   `json:"orders"`
	ExternalAccountBinding any      `json:"externalAccountBinding,omitempty"`
}

func (s *Server) accountJSON(a *pkidb.AcmeAccount) accountJSON {
	var contact []string
	_ = json.Unmarshal([]byte(a.Contact), &contact)
	if contact == nil {
		contact = []string{}
	}
	return accountJSON{Status: a.Status, Contact: contact, Orders: s.url("/account/" + a.ID + "/orders")}
}

// checkContacts: mailto: only, plain addresses, at most five (RFC 8555
// §7.3: unsupportedContact / invalidContact).
func checkContacts(in []string) ([]string, error) {
	if len(in) > maxContacts {
		return nil, problemErr(http.StatusBadRequest, "invalidContact", "at most %d contacts", maxContacts)
	}
	out := []string{}
	for _, c := range in {
		addr, ok := strings.CutPrefix(c, "mailto:")
		if !ok {
			return nil, problemErr(http.StatusBadRequest, "unsupportedContact", "only mailto: contacts are supported")
		}
		if len(c) > 254 || strings.ContainsAny(addr, "?,<> \t\r\n") {
			return nil, problemErr(http.StatusBadRequest, "invalidContact", "%q is not a plain e-mail address", clip(c))
		}
		if a, err := mail.ParseAddress(addr); err != nil || a.Address != addr {
			return nil, problemErr(http.StatusBadRequest, "invalidContact", "%q is not a plain e-mail address", clip(c))
		}
		out = append(out, c)
	}
	return out, nil
}

func clip(s string) string {
	if len(s) > 64 {
		return s[:64] + "…"
	}
	return s
}

func (s *Server) newAccount(w http.ResponseWriter, r *http.Request) {
	req, ok := s.read(w, r, byJWK)
	if !ok {
		return
	}
	var in struct {
		Contact              []string        `json:"contact"`
		TermsOfServiceAgreed bool            `json:"termsOfServiceAgreed"`
		OnlyReturnExisting   bool            `json:"onlyReturnExisting"`
		EAB                  json.RawMessage `json:"externalAccountBinding"`
	}
	if err := payload(req, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	ctx := r.Context()
	q := pkidb.New(s.db)
	existing, err := q.GetACMEAccountByThumbprint(ctx, req.key.Thumbprint())
	switch {
	case err == nil:
		// The key has an account: answer with it (RFC 8555 §7.3.1).
		if berr := s.bindVerifiedAccount(ctx, &existing); berr != nil {
			s.fail(w, r, berr)
			return
		}
		w.Header().Set("Location", s.url("/account/"+existing.ID))
		s.reply(w, http.StatusOK, s.accountJSON(&existing))
		return
	case !errors.Is(err, sql.ErrNoRows):
		s.fail(w, r, err)
		return
	case in.OnlyReturnExisting:
		s.fail(w, r, problemErr(http.StatusBadRequest, "accountDoesNotExist", "there is no account for this key"))
		return
	}
	if allowed, wait := s.limits.allow("new-account:"+ipKey(req.ip), s.limitsNow(r.Context()).AccountsPerIP, time.Hour); !allowed {
		s.fail(w, r, rateLimited(wait, "too many new accounts from %s – try again later", req.ip))
		return
	}
	contact, err := checkContacts(in.Contact)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	now := s.now()
	id, err := s.newID("acc")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	acct := pkidb.InsertACMEAccountParams{
		ID: id, KeyThumbprint: req.key.Thumbprint(), Jwk: string(req.key.Canonical()), Status: "valid",
		CreatedAt: dbTime(now), CreatedIp: req.ip, UpdatedAt: dbTime(now),
	}
	cj, _ := json.Marshal(contact)
	acct.Contact = string(cj)
	eabID := ""
	if len(in.EAB) > 0 && !bytes.Equal(in.EAB, []byte("null")) {
		if eabID, err = s.checkEAB(ctx, in.EAB, req.key, now); err != nil {
			s.fail(w, r, err)
			return
		}
		acct.EabKeyID = sql.NullString{String: eabID, Valid: true}
		acct.ApprovedAt = sql.NullString{String: dbTime(now), Valid: true}
		acct.ApprovedBy = sql.NullString{String: "eab:" + eabID, Valid: true}
	}
	err = s.inTx(ctx, func(q *pkidb.Queries, tx *sql.Tx) error {
		if eabID != "" {
			n, uerr := q.UseACMEEABKey(ctx, pkidb.UseACMEEABKeyParams{UsedAt: sql.NullString{String: dbTime(now), Valid: true}, UsedBy: sql.NullString{String: id, Valid: true}, ID: eabID})
			if uerr != nil {
				return uerr
			}
			if n != 1 {
				return problemErr(http.StatusUnauthorized, "unauthorized", "the EAB key was used already – one key binds one account")
			}
		}
		if ierr := q.InsertACMEAccount(ctx, acct); ierr != nil {
			return ierr
		}
		created, gerr := q.GetACMEAccount(ctx, id)
		if gerr != nil {
			return gerr
		}
		if berr := s.bindAccount(ctx, q, tx, &created); berr != nil {
			return berr
		}
		return enqueue(ctx, tx, now, id, req.ip, ActionAccountCreate, audit.Target{Type: "acme_account", ID: id}, audit.ResultSuccess,
			map[string]any{"key_thumbprint": acct.KeyThumbprint, "key_algorithm": req.key.Algorithm(), "eab": eabID, "approved": created.ApprovedAt.Valid, "contacts": len(contact)})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	created, err := q.GetACMEAccount(ctx, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("Location", s.url("/account/"+id))
	s.reply(w, http.StatusCreated, s.accountJSON(&created))
}

// checkEAB verifies an external account binding against the EAB keys the
// admins created. The MAC key is encrypted by the key ring: an EAB needs an
// unsealed server.
func (s *Server) checkEAB(ctx context.Context, raw json.RawMessage, accountKey *jose.Key, now time.Time) (string, error) {
	q := pkidb.New(s.db)
	kid, err := jose.VerifyEAB(raw, accountKey, s.url("/new-account"), func(kid string) ([]byte, error) {
		k, gerr := q.GetACMEEABKey(ctx, kid)
		switch {
		case errors.Is(gerr, sql.ErrNoRows):
			return nil, problemErr(http.StatusUnauthorized, "unauthorized", "unknown EAB key")
		case gerr != nil:
			return nil, gerr
		case k.UsedAt.Valid:
			return nil, problemErr(http.StatusUnauthorized, "unauthorized", "the EAB key was used already – one key binds one account")
		case !now.Before(parseDBTime(k.ExpiresAt)):
			return nil, problemErr(http.StatusUnauthorized, "unauthorized", "the EAB key has expired – ask an admin for a new one")
		}
		var mac []byte
		werr := s.engine.Keys.WithKey(k.ID, keys.PurposeEAB, EABAlgorithm, keys.Envelope{RootKeyVersion: k.RootKeyVersion, WrappedDEK: k.WrappedDek, Ciphertext: k.MacCiphertext},
			func(plain []byte) error { mac = append([]byte(nil), plain...); return nil })
		if errors.Is(werr, keys.ErrSealed) {
			return nil, problemErr(http.StatusServiceUnavailable, "serverInternal", "the server is sealed – an EAB key can be checked only after the unseal")
		}
		return mac, werr
	})
	if err != nil {
		var ae *acmeError
		if errors.As(err, &ae) {
			return "", ae
		}
		if errors.Is(err, jose.ErrBadSignature) {
			return "", problemErr(http.StatusUnauthorized, "unauthorized", "%v", err)
		}
		if errors.Is(err, jose.ErrMalformed) || errors.Is(err, jose.ErrBadAlgorithm) || errors.Is(err, jose.ErrBadKey) {
			return "", problemErr(http.StatusBadRequest, "malformed", "%v", err)
		}
		return "", err
	}
	return kid, nil
}

// account: POST-as-GET returns the account; a payload changes the contacts
// or deactivates it (RFC 8555 §7.3.2, §7.3.6).
func (s *Server) account(w http.ResponseWriter, r *http.Request) {
	req, ok := s.read(w, r, byKID)
	if !ok {
		return
	}
	if req.account.ID != r.PathValue("id") {
		s.fail(w, r, problemErr(http.StatusUnauthorized, "unauthorized", "an account can only change itself"))
		return
	}
	ctx := r.Context()
	if len(req.jws.Payload) == 0 {
		s.reply(w, http.StatusOK, s.accountJSON(req.account))
		return
	}
	var in struct {
		Contact *[]string `json:"contact"`
		Status  string    `json:"status"`
	}
	if err := payload(req, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	now := s.now()
	id := req.account.ID
	switch {
	case in.Status == "deactivated":
		err := s.inTx(ctx, func(q *pkidb.Queries, tx *sql.Tx) error {
			if uerr := q.UpdateACMEAccountStatus(ctx, pkidb.UpdateACMEAccountStatusParams{Status: "deactivated", UpdatedAt: dbTime(now), ID: id}); uerr != nil {
				return uerr
			}
			if _, derr := q.DeactivateACMEAuthzsOfAccount(ctx, pkidb.DeactivateACMEAuthzsOfAccountParams{UpdatedAt: dbTime(now), AccountID: id}); derr != nil {
				return derr
			}
			return enqueue(ctx, tx, now, id, req.ip, ActionAccountDeactivate, audit.Target{Type: "acme_account", ID: id}, audit.ResultSuccess, nil)
		})
		if err != nil {
			s.fail(w, r, err)
			return
		}
	case in.Status != "":
		s.fail(w, r, problemErr(http.StatusBadRequest, "malformed", "an account can only set its status to \"deactivated\""))
		return
	case in.Contact != nil:
		contact, err := checkContacts(*in.Contact)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		cj, _ := json.Marshal(contact)
		err = s.inTx(ctx, func(q *pkidb.Queries, tx *sql.Tx) error {
			if uerr := q.UpdateACMEAccountContact(ctx, pkidb.UpdateACMEAccountContactParams{Contact: string(cj), UpdatedAt: dbTime(now), ID: id}); uerr != nil {
				return uerr
			}
			return enqueue(ctx, tx, now, id, req.ip, ActionAccountUpdate, audit.Target{Type: "acme_account", ID: id}, audit.ResultSuccess, map[string]any{"contacts": len(contact)})
		})
		if err != nil {
			s.fail(w, r, err)
			return
		}
	}
	acct, err := pkidb.New(s.db).GetACMEAccount(ctx, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.reply(w, http.StatusOK, s.accountJSON(&acct))
}

// accountOrders lists the account's orders (RFC 8555 §7.1.2.1), newest
// first, at most 100.
func (s *Server) accountOrders(w http.ResponseWriter, r *http.Request) {
	req, ok := s.read(w, r, byKID)
	if !ok {
		return
	}
	if req.account.ID != r.PathValue("id") {
		s.fail(w, r, problemErr(http.StatusUnauthorized, "unauthorized", "an account sees only its own orders"))
		return
	}
	rows, err := pkidb.New(s.db).ListACMEOrders(r.Context(), 1000)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	urls := []string{}
	for _, o := range rows {
		if o.AccountID == req.account.ID && len(urls) < 100 {
			urls = append(urls, s.url("/order/"+o.ID))
		}
	}
	s.reply(w, http.StatusOK, map[string]any{"orders": urls})
}

// keyChange replaces the account key (RFC 8555 §7.3.5): the outer JWS is
// signed by the account, the inner one by the new key, naming the account
// and the old key.
func (s *Server) keyChange(w http.ResponseWriter, r *http.Request) {
	req, ok := s.read(w, r, byKID)
	if !ok {
		return
	}
	inner, err := jose.ParseInner(req.jws.Payload)
	if err != nil {
		s.joseFail(w, err)
		return
	}
	if verr := inner.Verify(inner.JWK); verr != nil {
		s.joseFail(w, verr)
		return
	}
	if inner.URL != req.jws.URL {
		s.fail(w, r, problemErr(http.StatusBadRequest, "malformed", "the inner JWS must name the same url as the outer one"))
		return
	}
	var in struct {
		Account string          `json:"account"`
		OldKey  json.RawMessage `json:"oldKey"`
	}
	if jerr := json.Unmarshal(inner.Payload, &in); jerr != nil {
		s.fail(w, r, problemErr(http.StatusBadRequest, "malformed", "the inner payload must name account and oldKey"))
		return
	}
	old, err := jose.ParseJWK(in.OldKey)
	if err != nil || !old.Equal(req.key) {
		s.fail(w, r, problemErr(http.StatusBadRequest, "malformed", "oldKey is not the account's current key"))
		return
	}
	if in.Account != req.jws.KID {
		s.fail(w, r, problemErr(http.StatusBadRequest, "malformed", "account must be this account's URL"))
		return
	}
	ctx := r.Context()
	if other, gerr := pkidb.New(s.db).GetACMEAccountByThumbprint(ctx, inner.JWK.Thumbprint()); gerr == nil {
		w.Header().Set("Location", s.url("/account/"+other.ID))
		s.fail(w, r, problemErr(http.StatusConflict, "malformed", "the new key belongs to another account already"))
		return
	} else if !errors.Is(gerr, sql.ErrNoRows) {
		s.fail(w, r, gerr)
		return
	}
	now := s.now()
	id := req.account.ID
	err = s.inTx(ctx, func(q *pkidb.Queries, tx *sql.Tx) error {
		reserved, rerr := q.GetAgentByACMEThumbprint(ctx, sql.NullString{String: inner.JWK.Thumbprint(), Valid: true})
		if rerr != nil && !errors.Is(rerr, sql.ErrNoRows) {
			return rerr
		}
		if rerr == nil && (!req.account.AgentID.Valid || reserved.ID != req.account.AgentID.String) {
			return problemErr(http.StatusForbidden, "unauthorized", "the new account key belongs to another agent")
		}
		if uerr := q.UpdateACMEAccountKey(ctx, pkidb.UpdateACMEAccountKeyParams{KeyThumbprint: inner.JWK.Thumbprint(), Jwk: string(inner.JWK.Canonical()), UpdatedAt: dbTime(now), ID: id}); uerr != nil {
			return uerr
		}
		if req.account.AgentID.Valid {
			if uerr := q.SetAgentACMEThumbprint(ctx, pkidb.SetAgentACMEThumbprintParams{
				AcmeKeyThumbprint: sql.NullString{String: inner.JWK.Thumbprint(), Valid: true}, UpdatedAt: dbTime(now), ID: req.account.AgentID.String,
			}); uerr != nil {
				return uerr
			}
		}
		return enqueue(ctx, tx, now, id, req.ip, ActionAccountKeyChange, audit.Target{Type: "acme_account", ID: id}, audit.ResultSuccess,
			map[string]any{"old_thumbprint": req.key.Thumbprint(), "new_thumbprint": inner.JWK.Thumbprint(), "key_algorithm": inner.JWK.Algorithm()})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	acct, err := pkidb.New(s.db).GetACMEAccount(ctx, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.reply(w, http.StatusOK, s.accountJSON(&acct))
}

// rateLimited: 429 with the real wait as Retry-After (RFC 8555 §6.6).
func rateLimited(wait time.Duration, format string, args ...any) *acmeError {
	e := problemErr(http.StatusTooManyRequests, "rateLimited", format, args...)
	e.detail += fmt.Sprintf(" – try again in %s", (time.Duration(retrySeconds(wait)) * time.Second).String())
	e.retry = wait
	return e
}
