package acme

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
)

// Rate limits (PHASE2 step 11). Generous for a homelab, tight enough that a
// broken client loop doesn't fill the database.
const (
	limitNewAccountsPerIP     = 10  // per hour and client address
	limitOrdersPerAccount     = 300 // per hour
	limitFailedPerIdentifier  = 5   // failed validations per hour and name
	limitChallengesPerAccount = 300 // validation starts per hour
)

type identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

func (i identifier) key() string { return i.Type + ":" + i.Value }

// normalize checks one identifier: dns (LDH, punycode, lower case, a
// wildcard only as "*." in front) or ip (RFC 8738).
func normalize(id identifier) (identifier, error) {
	switch id.Type {
	case "dns":
		v, err := ca.NormalizeDNSName(id.Value, true)
		if err != nil {
			return id, problemErr(http.StatusBadRequest, "rejectedIdentifier", "%v", err)
		}
		return identifier{"dns", v}, nil
	case "ip":
		a, err := netip.ParseAddr(id.Value)
		if err != nil || a.Zone() != "" {
			return id, problemErr(http.StatusBadRequest, "malformed", "%q is not an IP address", clip(id.Value))
		}
		return identifier{"ip", a.Unmap().String()}, nil
	}
	return id, problemErr(http.StatusBadRequest, "unsupportedIdentifier", "identifier type %q (supported: dns, ip)", clip(id.Type))
}

// orderPlan is the checked new order: per identifier its domain.
type orderPlan struct {
	idents  []identifier
	domains []*ca.Domain
}

// planOrder checks every identifier against the domains and the approval
// levels; problems are collected as subproblems (RFC 8555 §6.7.1).
func (s *Server) planOrder(ctx context.Context, acct *pkidb.AcmeAccount, in []identifier) (*orderPlan, error) {
	if len(in) == 0 {
		return nil, problemErr(http.StatusBadRequest, "malformed", "an order needs at least one identifier")
	}
	if len(in) > maxIdentifiers {
		return nil, problemErr(http.StatusBadRequest, "rejectedIdentifier", "at most %d identifiers per order", maxIdentifiers)
	}
	p := &orderPlan{}
	var subs []map[string]any
	var firstType, firstDetail string
	sub := func(id identifier, typ, detail string) {
		if len(subs) == 0 {
			firstType, firstDetail = typ, detail
		}
		subs = append(subs, map[string]any{"type": "urn:ietf:params:acme:error:" + typ, "detail": detail, "identifier": id})
	}
	seen := map[string]bool{}
	approved := acct.ApprovedAt.Valid
	waitAccount := false
	for _, raw := range in {
		id, err := normalize(raw)
		if err != nil {
			var ae *acmeError
			if errors.As(err, &ae) {
				sub(raw, ae.typ, ae.detail)
				continue
			}
			return nil, err
		}
		if seen[id.key()] {
			continue
		}
		seen[id.key()] = true
		d, err := s.engine.DomainFor(ctx, id.Type, id.Value)
		if err != nil {
			return nil, err
		}
		if d == nil {
			sub(id, "rejectedIdentifier", "no domain covers "+id.Value+" – an admin of the PKI must add one")
			continue
		}
		switch d.Approval {
		case ca.ApprovalAccount:
			if !approved {
				waitAccount = true
			}
		case ca.ApprovalNewName:
			ok, nerr := s.nameApproved(ctx, acct.ID, id)
			if nerr != nil {
				return nil, nerr
			}
			if !ok {
				sub(id, "unauthorized", id.Value+" is a new name for domain "+d.Name+" and waits for approval in MyOwnPKI")
				continue
			}
		}
		p.idents = append(p.idents, id)
		p.domains = append(p.domains, d)
	}
	if waitAccount {
		return nil, problemErr(http.StatusForbidden, "unauthorized", "account %s waits for approval in MyOwnPKI (or register it with an EAB key) – try again once an admin approved it", acct.ID)
	}
	for i := 1; i < len(p.domains); i++ {
		if p.domains[i].CAID != p.domains[0].CAID || p.domains[i].Preset != p.domains[0].Preset {
			sub(p.idents[i], "rejectedIdentifier", p.idents[i].Value+" is signed by another CA or preset than "+p.idents[0].Value+" – order them separately")
		}
	}
	if len(subs) > 0 {
		e := problemErr(http.StatusBadRequest, "rejectedIdentifier", "the order names identifiers this server won't issue for")
		if len(subs) == 1 {
			e.typ, e.detail = firstType, firstDetail
			if e.typ == "unauthorized" {
				e.status = http.StatusForbidden
			}
		}
		e.extra = map[string]any{"subproblems": subs}
		return nil, e
	}
	return p, nil
}

// nameApproved: under "new_name" a name needs approval once; the first
// request records it for the admins.
func (s *Server) nameApproved(ctx context.Context, account string, id identifier) (bool, error) {
	q := pkidb.New(s.db)
	n, err := q.GetACMEName(ctx, id.key())
	switch {
	case err == nil:
		return n.Status == "approved", nil
	case !errors.Is(err, sql.ErrNoRows):
		return false, err
	}
	return false, q.RequestACMEName(ctx, pkidb.RequestACMENameParams{Name: id.key(), RequestedBy: account, RequestedAt: dbTime(s.now())})
}

// challengeTypes for one identifier: wildcards dns-01 only (RFC 8555
// §7.1.3), IPs http-01 only (RFC 8738), otherwise what the domain allows.
func challengeTypes(id identifier, d *ca.Domain) []string {
	switch {
	case id.Type == "ip":
		return []string{ca.ChallengeHTTP01}
	case strings.HasPrefix(id.Value, "*."):
		return []string{ca.ChallengeDNS01}
	}
	return slices.Clone(d.ChallengeTypes)
}

func (s *Server) newOrder(w http.ResponseWriter, r *http.Request) {
	req, ok := s.read(w, r, byKID)
	if !ok {
		return
	}
	var in struct {
		Identifiers []identifier `json:"identifiers"`
		NotBefore   string       `json:"notBefore"`
		NotAfter    string       `json:"notAfter"`
	}
	if err := payload(req, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	if in.NotBefore != "" || in.NotAfter != "" {
		s.fail(w, r, problemErr(http.StatusBadRequest, "malformed", "notBefore and notAfter are not supported – the domain sets the validity"))
		return
	}
	if allowed, wait := s.limits.allow("orders:"+req.account.ID, limitOrdersPerAccount, time.Hour); !allowed {
		s.fail(w, r, rateLimited(wait, "too many new orders for this account"))
		return
	}
	ctx := r.Context()
	plan, err := s.planOrder(ctx, req.account, in.Identifiers)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	now := s.now()
	orderID, err := s.newID("ord")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	idsJSON, _ := json.Marshal(plan.idents)
	err = s.inTx(ctx, func(q *pkidb.Queries, tx *sql.Tx) error {
		if ierr := q.InsertACMEOrder(ctx, pkidb.InsertACMEOrderParams{
			ID: orderID, AccountID: req.account.ID, Status: "pending", Identifiers: string(idsJSON),
			ExpiresAt: dbTime(now.Add(pendingLifetime)), CreatedAt: dbTime(now), UpdatedAt: dbTime(now),
		}); ierr != nil {
			return ierr
		}
		for i, id := range plan.idents {
			authzID, aerr := s.authzFor(ctx, q, req.account.ID, id, plan.domains[i], now)
			if aerr != nil {
				return aerr
			}
			if lerr := q.LinkACMEOrderAuthz(ctx, pkidb.LinkACMEOrderAuthzParams{OrderID: orderID, AuthzID: authzID}); lerr != nil {
				return lerr
			}
		}
		names := make([]string, 0, len(plan.idents))
		for _, id := range plan.idents {
			names = append(names, id.key())
		}
		return enqueue(ctx, tx, now, req.account.ID, req.ip, ActionOrderCreate, audit.Target{Type: "acme_order", ID: orderID}, audit.ResultSuccess,
			map[string]any{"identifiers": strings.Join(names, ","), "ca": plan.domains[0].CA})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	o, err := s.loadOrder(ctx, orderID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("Location", s.url("/order/"+orderID))
	s.reply(w, http.StatusCreated, s.orderJSON(ctx, o))
}

// authzFor reuses a valid or pending authorization of the account for the
// identifier, or creates one with a challenge per allowed type.
func (s *Server) authzFor(ctx context.Context, q *pkidb.Queries, account string, id identifier, d *ca.Domain, now time.Time) (string, error) {
	value, wildcard := id.Value, int64(0)
	if base, ok := strings.CutPrefix(id.Value, "*."); ok {
		value, wildcard = base, 1
	}
	if a, err := q.FindReusableACMEAuthz(ctx, pkidb.FindReusableACMEAuthzParams{
		AccountID: account, IdentifierType: id.Type, IdentifierValue: value, Wildcard: wildcard, ExpiresAt: dbTime(now),
	}); err == nil {
		return a.ID, nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	authzID, err := s.newID("az")
	if err != nil {
		return "", err
	}
	if err := q.InsertACMEAuthz(ctx, pkidb.InsertACMEAuthzParams{
		ID: authzID, AccountID: account, IdentifierType: id.Type, IdentifierValue: value, Wildcard: wildcard,
		Status: "pending", ExpiresAt: dbTime(now.Add(pendingLifetime)), CreatedAt: dbTime(now), UpdatedAt: dbTime(now),
	}); err != nil {
		return "", err
	}
	for _, typ := range challengeTypes(id, d) {
		chID, cerr := s.newID("ch")
		if cerr != nil {
			return "", cerr
		}
		token, terr := randomToken(s.rnd)
		if terr != nil {
			return "", terr
		}
		if ierr := q.InsertACMEChallenge(ctx, pkidb.InsertACMEChallengeParams{ID: chID, AuthzID: authzID, Type: typ, Token: token, Status: "pending", UpdatedAt: dbTime(now)}); ierr != nil {
			return "", ierr
		}
	}
	return authzID, nil
}

// loadOrder reads an order and brings its status up to date: pending →
// ready when every authorization is valid, → invalid when one failed or
// the order expired.
func (s *Server) loadOrder(ctx context.Context, id string) (*pkidb.AcmeOrder, error) {
	q := pkidb.New(s.db)
	o, err := q.GetACMEOrder(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, problemErr(http.StatusNotFound, "malformed", "no such order")
	}
	if err != nil {
		return nil, err
	}
	if o.Status != "pending" && o.Status != "ready" {
		return &o, nil
	}
	now := s.now()
	authzs, err := q.ListACMEAuthzsOfOrder(ctx, id)
	if err != nil {
		return nil, err
	}
	next, problem := "ready", ""
	for _, a := range authzs {
		switch {
		case a.Status == "valid" && now.Before(parseDBTime(a.ExpiresAt)):
		case a.Status == "pending" && now.Before(parseDBTime(a.ExpiresAt)):
			if next == "ready" {
				next = "pending"
			}
		default:
			next, problem = "invalid", "the authorization for "+a.IdentifierValue+" is "+effectiveAuthzStatus(a, now)
		}
	}
	if next != "invalid" && !now.Before(parseDBTime(o.ExpiresAt)) {
		next, problem = "invalid", "the order expired"
	}
	if next == o.Status {
		return &o, nil
	}
	var perr sql.NullString
	if problem != "" {
		b, _ := json.Marshal(map[string]any{"type": "urn:ietf:params:acme:error:unauthorized", "detail": problem, "status": http.StatusForbidden})
		perr = sql.NullString{String: string(b), Valid: true}
	}
	if err := q.SetACMEOrderStatus(ctx, pkidb.SetACMEOrderStatusParams{Status: next, Error: perr, UpdatedAt: dbTime(now), ID: id}); err != nil {
		return nil, err
	}
	o.Status, o.Error = next, perr
	return &o, nil
}

func effectiveAuthzStatus(a pkidb.AcmeAuthz, now time.Time) string {
	if (a.Status == "valid" || a.Status == "pending") && !now.Before(parseDBTime(a.ExpiresAt)) {
		return "expired"
	}
	return a.Status
}

func (s *Server) orderJSON(ctx context.Context, o *pkidb.AcmeOrder) map[string]any {
	var idents []identifier
	_ = json.Unmarshal([]byte(o.Identifiers), &idents)
	authzs, _ := pkidb.New(s.db).ListACMEAuthzsOfOrder(ctx, o.ID)
	urls := make([]string, 0, len(authzs))
	for _, a := range authzs {
		urls = append(urls, s.url("/authz/"+a.ID))
	}
	out := map[string]any{
		"status": o.Status, "expires": o.ExpiresAt, "identifiers": idents,
		"authorizations": urls, "finalize": s.url("/order/" + o.ID + "/finalize"),
	}
	if o.CertificateID.Valid {
		out["certificate"] = s.url("/certificate/" + o.CertificateID.String)
	}
	if o.Error.Valid {
		out["error"] = json.RawMessage(o.Error.String)
	}
	return out
}

// order: POST-as-GET of an order of the account.
func (s *Server) order(w http.ResponseWriter, r *http.Request) {
	req, ok := s.read(w, r, byKID)
	if !ok {
		return
	}
	o, err := s.ownOrder(r.Context(), req, r.PathValue("id"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if o.Status == "processing" {
		w.Header().Set("Retry-After", "30")
	}
	s.reply(w, http.StatusOK, s.orderJSON(r.Context(), o))
}

func (s *Server) ownOrder(ctx context.Context, req *request, id string) (*pkidb.AcmeOrder, error) {
	o, err := s.loadOrder(ctx, id)
	if err != nil {
		return nil, err
	}
	if o.AccountID != req.account.ID {
		return nil, problemErr(http.StatusNotFound, "malformed", "no such order")
	}
	return o, nil
}

func (s *Server) ownAuthz(ctx context.Context, req *request, id string) (*pkidb.AcmeAuthz, error) {
	a, err := pkidb.New(s.db).GetACMEAuthz(ctx, id)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && a.AccountID != req.account.ID) {
		return nil, problemErr(http.StatusNotFound, "malformed", "no such authorization")
	}
	if err != nil {
		return nil, err
	}
	return &a, nil
}

func (s *Server) authzJSON(ctx context.Context, a *pkidb.AcmeAuthz) map[string]any {
	chs, _ := pkidb.New(s.db).ListACMEChallengesOfAuthz(ctx, a.ID)
	list := make([]map[string]any, 0, len(chs))
	for i := range chs {
		list = append(list, s.challengeJSON(&chs[i]))
	}
	out := map[string]any{
		"identifier": identifier{a.IdentifierType, a.IdentifierValue}, "status": effectiveAuthzStatus(*a, s.now()),
		"expires": a.ExpiresAt, "challenges": list,
	}
	if a.Wildcard == 1 {
		out["wildcard"] = true
	}
	return out
}

func (s *Server) challengeJSON(c *pkidb.AcmeChallenge) map[string]any {
	out := map[string]any{"type": c.Type, "url": s.url("/challenge/" + c.ID), "token": c.Token, "status": c.Status}
	if c.ValidatedAt.Valid {
		out["validated"] = c.ValidatedAt.String
	}
	if c.Error.Valid {
		out["error"] = json.RawMessage(c.Error.String)
	}
	return out
}

// authz: POST-as-GET, or {"status":"deactivated"} (RFC 8555 §7.5.2).
func (s *Server) authz(w http.ResponseWriter, r *http.Request) {
	req, ok := s.read(w, r, byKID)
	if !ok {
		return
	}
	ctx := r.Context()
	a, err := s.ownAuthz(ctx, req, r.PathValue("id"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if len(req.jws.Payload) > 0 {
		var in struct {
			Status string `json:"status"`
		}
		if perr := payload(req, &in); perr != nil {
			s.fail(w, r, perr)
			return
		}
		if in.Status != "deactivated" {
			s.fail(w, r, problemErr(http.StatusBadRequest, "malformed", "an authorization can only be deactivated"))
			return
		}
		now := s.now()
		err = s.inTx(ctx, func(q *pkidb.Queries, tx *sql.Tx) error {
			if uerr := q.SetACMEAuthzStatus(ctx, pkidb.SetACMEAuthzStatusParams{Status: "deactivated", ExpiresAt: a.ExpiresAt, UpdatedAt: dbTime(now), ID: a.ID}); uerr != nil {
				return uerr
			}
			return enqueue(ctx, tx, now, req.account.ID, req.ip, ActionAuthzDeactivate, audit.Target{Type: "acme_authz", ID: a.ID}, audit.ResultSuccess,
				map[string]any{"identifier": a.IdentifierType + ":" + a.IdentifierValue})
		})
		if err != nil {
			s.fail(w, r, err)
			return
		}
		a.Status = "deactivated"
	}
	s.reply(w, http.StatusOK, s.authzJSON(ctx, a))
}

// challenge: POST-as-GET returns it; "{}" starts the validation (RFC 8555
// §7.5.1). The answer comes at once with "processing"; the client polls.
func (s *Server) challenge(w http.ResponseWriter, r *http.Request) {
	req, ok := s.read(w, r, byKID)
	if !ok {
		return
	}
	ctx := r.Context()
	q := pkidb.New(s.db)
	c, err := q.GetACMEChallenge(ctx, r.PathValue("id"))
	if errors.Is(err, sql.ErrNoRows) {
		s.fail(w, r, problemErr(http.StatusNotFound, "malformed", "no such challenge"))
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	a, err := s.ownAuthz(ctx, req, c.AuthzID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Add("Link", `<`+s.url("/authz/"+a.ID)+`>;rel="up"`)
	if len(req.jws.Payload) > 0 && c.Status == "pending" && effectiveAuthzStatus(*a, s.now()) == "pending" {
		if allowed, wait := s.limits.allow("challenges:"+req.account.ID, limitChallengesPerAccount, time.Hour); !allowed {
			s.fail(w, r, rateLimited(wait, "too many validations for this account"))
			return
		}
		if allowed, wait := s.limits.peek("failed:"+a.IdentifierValue, limitFailedPerIdentifier, time.Hour); !allowed {
			s.fail(w, r, rateLimited(wait, "too many failed validations for %s", a.IdentifierValue))
			return
		}
		n, serr := q.StartACMEChallenge(ctx, pkidb.StartACMEChallengeParams{UpdatedAt: dbTime(s.now()), ID: c.ID})
		if serr != nil {
			s.fail(w, r, serr)
			return
		}
		if n == 1 {
			c.Status = "processing"
			acct, kerr := s.accountKeyThumbprint(req)
			if kerr != nil {
				s.fail(w, r, kerr)
				return
			}
			s.valid.start(job{challenge: c, authz: *a, thumbprint: acct, account: req.account.ID, ip: req.ip})
		}
	}
	if c.Status == "processing" {
		w.Header().Set("Retry-After", "2")
	}
	s.reply(w, http.StatusOK, s.challengeJSON(&c))
}

func (s *Server) accountKeyThumbprint(req *request) (string, error) {
	if req.key == nil {
		return "", errors.New("no account key")
	}
	return req.key.Thumbprint(), nil
}
