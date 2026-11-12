package agents

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/ids"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
	"github.com/Der-Felix/MyOwnPKI/internal/tenant"
)

// Enrollment states (agent_enrollments.state); StateWaitingForUnseal is
// only reported, never stored: the enrollment is admitted, the certificate
// follows the unseal.
const (
	StateWaitingForCheck  = "waiting_for_check"
	StatePending          = "pending_approval"
	StateAdmitted         = "admitted"
	StateDenied           = "denied"
	StateExpired          = "expired"
	StateWaitingForUnseal = "waiting_for_unseal"
)

// Check methods: how the agent answers the http-01 check.
const (
	MethodStandalone = "standalone"
	MethodWebroot    = "webroot"
)

// maxCSR bounds a CSR from outside.
const maxCSR = 8 << 10

// EnrollInput is an enrollment as the transport received it.
type EnrollInput struct {
	Hostname, Token, Method, OS, Arch, Version, SourceIP string
	CSRDER                                               []byte
}

// EnrollOutput is what the agent needs for the check and the polls.
type EnrollOutput struct {
	ID, Handle, CheckToken string
}

// StatusInput is a poll of EnrollStatus.
type StatusInput struct {
	ID, Handle, SourceIP string
	CheckReady           bool
}

// Status is where an enrollment stands, for the agent.
type Status struct {
	State       string
	Message     string
	AgentID     string
	TokenValid  bool
	CheckPassed bool
	CertDER     []byte
	Chain       [][]byte // issuing CA first, without the root
}

// Enroll stores a pending enrollment. It needs no certificate: nothing but
// an enrollment that waits, limited in number and expiring, comes of it.
func (s *Service) Enroll(ctx context.Context, in EnrollInput) (*EnrollOutput, error) {
	now := s.now()
	if !s.limiter().allow("enroll:"+in.SourceIP, enrollPerWindow, 10*time.Minute, now) {
		return nil, ErrRateLimited
	}
	if s.CA == "" {
		return nil, errNoAgentCA
	}
	host, err := CheckHostname(in.Hostname)
	if err != nil {
		return nil, err
	}
	if in.Method != MethodStandalone && in.Method != MethodWebroot {
		return nil, fmt.Errorf("%w: check method: standalone or webroot", ErrInvalid)
	}
	for _, f := range []string{in.OS, in.Arch, in.Version} {
		if len(f) > 64 || strings.ContainsFunc(f, func(r rune) bool { return r < 0x20 || r > 0x7e }) {
			return nil, fmt.Errorf("%w: os, arch and version: at most 64 printable ASCII characters", ErrInvalid)
		}
	}
	spki, err := csrKey(in.CSRDER)
	if err != nil {
		return nil, err
	}
	q := pkidb.New(s.PKI)
	if _, xerr := q.ExpireEnrollments(ctx, dbTime(now)); xerr != nil {
		return nil, xerr
	}
	tc, err := s.checkToken(ctx, q, in.Token, host, now)
	if err != nil {
		return nil, err
	}
	tokenID, tokenValid, tokenProblem := tc.ID, tc.Valid, tc.Problem
	known, err := s.knownAgent(ctx, q, host, spki)
	if err != nil {
		return nil, err
	}
	if !tokenValid && known == "" {
		n, cerr := q.CountOpenWithoutToken(ctx)
		if cerr != nil {
			return nil, cerr
		}
		if n >= MaxOpenWithoutToken {
			s.Log.Warn("agent enrollment refused: the queue is full", slog.String("hostname", host), slog.String("source", in.SourceIP))
			return nil, ErrQueueFull
		}
	}
	expiry := ShortExpiry
	if tokenValid || known != "" {
		expiry = LongExpiry
	}
	id, err := ids.New("enr", now, s.rnd())
	if err != nil {
		return nil, err
	}
	handle, err := randomText(s.rnd(), 32)
	if err != nil {
		return nil, err
	}
	checkToken, err := randomText(s.rnd(), 32)
	if err != nil {
		return nil, err
	}
	who := keys.Who{Actor: audit.Actor{Type: audit.ActorAgent, ID: id, Name: host}, Principal: authz.System("agent-enrollment"), SourceIP: in.SourceIP}
	err = s.inTx(ctx, func(q *pkidb.Queries, tx *sql.Tx) error {
		use := ""
		if tokenValid {
			// The one conditional UPDATE is the rule: a use is taken only while the
			// token has one left, is not revoked and has not expired – in this
			// transaction, so concurrent enrollments cannot spend a use twice.
			used, uerr := q.UseJoinToken(ctx, pkidb.UseJoinTokenParams{Now: nullString(dbTime(now)), Enrollment: nullString(id), ID: tokenID})
			switch {
			case errors.Is(uerr, sql.ErrNoRows): // used up, revoked or expired in the meantime
				tokenValid = false
				cur, gerr := q.GetJoinToken(ctx, tokenID)
				if gerr != nil {
					return gerr
				}
				if tokenProblem = toJoinToken(cur).problem(now, host); tokenProblem == "" {
					tokenProblem = "the join token was used already"
				}
			case uerr != nil:
				return uerr
			default:
				use = useText(used.UseCount, used.MaxUses)
			}
		}
		if ierr := q.InsertEnrollment(ctx, pkidb.InsertEnrollmentParams{
			ID: id, AgentID: nullString(known), Hostname: host, CsrDer: in.CSRDER, SpkiSha256: spki, HandleHash: hashToken(handle),
			CheckToken: checkToken, CheckMethod: in.Method, TokenID: tokenRef(tokenID, tokenValid), TokenValid: boolInt(tokenValid),
			TokenProblem: nullString(tokenProblem), KnownAgent: boolInt(known != ""), Os: in.OS, Arch: in.Arch, AgentVersion: in.Version,
			SourceIp: in.SourceIP, CreatedAt: dbTime(now), ExpiresAt: dbTime(now.Add(expiry)),
		}); ierr != nil {
			return ierr
		}
		return enqueue(ctx, tx, now, who, ActionEnroll, audit.Target{Type: "agent_enrollment", ID: id}, map[string]any{
			"hostname": host, "method": in.Method, "token_valid": tokenValid, "token_problem": tokenProblem,
			"token_id": tokenID, "token_kind": tc.Kind, "use": use,
			"known_agent": known, "os": in.OS, "arch": in.Arch, "version": in.Version,
		})
	})
	if err != nil {
		return nil, err
	}
	return &EnrollOutput{ID: id, Handle: handle, CheckToken: checkToken}, nil
}

// checkToken looks a join token up. A token that doesn't count is not an
// error: the enrollment goes on without it, and the queue names why.
func (s *Service) checkToken(ctx context.Context, q *pkidb.Queries, token, host string, now time.Time) (tokenCheck, error) {
	if token == "" {
		return tokenCheck{}, nil
	}
	row, err := q.GetJoinTokenByHash(ctx, hashToken(token))
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return tokenCheck{Problem: "unknown join token"}, nil
	case err != nil:
		return tokenCheck{}, err
	}
	jt := toJoinToken(row)
	tc := tokenCheck{ID: jt.ID, Kind: jt.Kind}
	if tc.Problem = jt.problem(now, host); tc.Problem != "" {
		return tc, nil
	}
	if jt.Kind == KindPass {
		// A pass admits new hosts only: replacing a host that has an agent stays
		// a human act (a single-use token or the approval queue).
		taken, terr := s.hostTaken(ctx, q, host)
		if terr != nil {
			return tokenCheck{}, terr
		}
		if taken {
			tc.Problem = passHostTaken(host)
			return tc, nil
		}
	}
	tc.Valid = true
	return tc, nil
}

// tokenCheck is what a presented secret turned out to be. A token that
// doesn't count is no error: the enrollment goes on without it, and the
// queue names why.
type tokenCheck struct {
	ID, Kind, Problem string
	Valid             bool
}

// errHostTaken: a pass can't admit a host that has an agent.
var errHostTaken = errors.New("an agent for this host exists")

func passHostTaken(host string) string {
	return "an agent for " + host + " exists – a pass admits new hosts only; ask an admin for a single-use token"
}

// hostTaken reports whether host has an agent that is not revoked. An active
// one is the rule of docs/PHASE3.md section 11.2; a disabled one counts too:
// somebody switched it off on purpose, and a pass must not bring the host
// back under a new identity.
func (s *Service) hostTaken(ctx context.Context, q *pkidb.Queries, host string) (bool, error) {
	rows, err := q.ListAgentsByHostname(ctx, host)
	if err != nil {
		return false, err
	}
	for _, a := range rows {
		if a.Status != StatusRevoked {
			return true, nil
		}
	}
	return false, nil
}

// knownAgent finds an active agent with this hostname whose last
// certificate has exactly this public key (owner 2026-10-24): it comes back
// without a new token after a passed check. A disabled or revoked agent
// never counts.
func (s *Service) knownAgent(ctx context.Context, q *pkidb.Queries, host, spki string) (string, error) {
	rows, err := q.ListAgentsByHostname(ctx, host)
	if err != nil {
		return "", err
	}
	for _, a := range rows {
		if a.Status != StatusActive || !a.CertID.Valid {
			continue
		}
		c, err := q.GetCertificate(ctx, a.CertID.String)
		if err != nil {
			return "", err
		}
		cert, err := x509.ParseCertificate(c.CertDer)
		if err != nil {
			return "", err
		}
		if spkiHash(cert.RawSubjectPublicKeyInfo) == spki {
			return a.ID, nil
		}
	}
	return "", nil
}

// EnrollStatus reports an enrollment; with CheckReady it first runs the
// check (once) and decides. An admitted agent gets its certificate here.
func (s *Service) EnrollStatus(ctx context.Context, in StatusInput) (*Status, error) {
	now := s.now()
	if !s.limiter().allow("status:"+in.SourceIP, statusPerHour, time.Hour, now) {
		return nil, ErrRateLimited
	}
	row, err := s.enrollment(ctx, in.ID, in.Handle)
	if err != nil {
		return nil, err
	}
	open := row.State == StateWaitingForCheck || row.State == StatePending
	if open && !now.Before(parseTime(row.ExpiresAt)) {
		if _, xerr := pkidb.New(s.PKI).ExpireEnrollments(ctx, dbTime(now)); xerr != nil {
			return nil, xerr
		}
		row.State = StateExpired
	}
	if row.State == StateWaitingForCheck && in.CheckReady {
		if row, err = s.runCheck(ctx, row, now); err != nil {
			return nil, err
		}
	}
	st := &Status{State: row.State, AgentID: row.AgentID.String, TokenValid: row.TokenValid == 1, CheckPassed: row.CheckState == "passed"}
	switch row.State {
	case StateWaitingForCheck:
		st.Message = "waiting for the check file – the agent places it and reports check_ready"
	case StatePending:
		st.Message = s.pendingMessage(row)
	case StateDenied:
		st.Message = "an admin refused this enrollment"
	case StateExpired:
		st.Message = "this enrollment expired – enroll again"
	case StateAdmitted:
		return s.deliver(ctx, row, st)
	}
	return st, nil
}

// enrollment loads an enrollment by ID and handle; a wrong handle looks
// like an unknown ID (no oracle for IDs).
func (s *Service) enrollment(ctx context.Context, id, handle string) (pkidb.AgentEnrollment, error) {
	row, err := pkidb.New(s.PKI).GetEnrollment(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return row, ErrNotFound
	} else if err != nil {
		return row, err
	}
	if subtle.ConstantTimeCompare([]byte(hashToken(handle)), []byte(row.HandleHash)) != 1 {
		return pkidb.AgentEnrollment{}, ErrNotFound
	}
	return row, nil
}

// runCheck runs the http-01 check once, stores its result and decides.
func (s *Service) runCheck(ctx context.Context, row pkidb.AgentEnrollment, now time.Time) (pkidb.AgentEnrollment, error) {
	cerr := s.check(ctx, row)
	state, msg := "passed", ""
	if cerr != nil {
		state, msg = "failed", clip(cerr.Error(), 300)
		s.Log.Info("agent enrollment: check failed", slog.String("hostname", row.Hostname), slog.String("enrollment", row.ID), slog.String("error", msg))
	}
	expires := parseTime(row.ExpiresAt)
	if state == "passed" { // only junk expires after 24 hours
		expires = parseTime(row.CreatedAt).Add(LongExpiry)
	}
	q := pkidb.New(s.PKI)
	if err := q.SetEnrollmentCheck(ctx, pkidb.SetEnrollmentCheckParams{
		CheckState: state, CheckError: nullString(msg), CheckedAt: nullString(dbTime(now)), ExpiresAt: dbTime(expires), ID: row.ID,
	}); err != nil {
		return row, err
	}
	row.CheckState, row.CheckError, row.ExpiresAt = state, nullString(msg), dbTime(expires)
	mode, err := s.Mode(ctx)
	if err != nil {
		return row, err
	}
	pass, err := s.admittedByPass(ctx, q, row)
	if err != nil {
		return row, err
	}
	if admits(mode, row.TokenValid == 1, pass, row.KnownAgent == 1, state == "passed") {
		err := s.admitBy(ctx, row.ID, mode, "mode "+mode, keys.Who{
			Actor: audit.Actor{Type: audit.ActorSystem, Name: "agents"}, Principal: authz.System("agents"),
		}, pass)
		switch {
		case errors.Is(err, errHostTaken):
			// An agent for the host appeared since the pass was checked (two hosts
			// with one name, enrolling at the same time). The use stays spent; an
			// admin decides.
			if qerr := q.QueueEnrollmentWithProblem(ctx, pkidb.QueueEnrollmentWithProblemParams{TokenProblem: nullString(passHostTaken(row.Hostname)), ID: row.ID}); qerr != nil {
				return row, qerr
			}
		case err != nil && !errors.Is(err, ErrConflict):
			return row, err
		}
	} else if err := q.QueueEnrollment(ctx, row.ID); err != nil {
		return row, err
	}
	return q.GetEnrollment(ctx, row.ID)
}

// admittedByPass reports whether the valid token behind the enrollment is an
// enrollment pass.
func (s *Service) admittedByPass(ctx context.Context, q *pkidb.Queries, row pkidb.AgentEnrollment) (bool, error) {
	if row.TokenValid != 1 || !row.TokenID.Valid {
		return false, nil
	}
	t, err := q.GetJoinToken(ctx, row.TokenID.String)
	if err != nil {
		return false, err
	}
	return t.Kind == KindPass, nil
}

// check proves control of the hostname: the file at
// http://<hostname>/.well-known/acme-challenge/<token> must hold the token
// and the hash of the CSR's public key – the check is bound to the key, as
// an ACME key authorization is bound to the account (RFC 8555 §8.1). The
// hostname must lie in a domain; its address policy applies.
func (s *Service) check(ctx context.Context, row pkidb.AgentEnrollment) error {
	if s.Checker == nil {
		return errors.New("no checker configured")
	}
	d, err := s.Engine.DomainFor(ctx, "dns", row.Hostname)
	if err != nil {
		if errors.Is(err, ca.ErrNotFound) {
			return fmt.Errorf("no domain covers %s – an admin of the PKI must add one", row.Hostname)
		}
		return err
	}
	if d == nil {
		return fmt.Errorf("no domain covers %s – an admin of the PKI must add one", row.Hostname)
	}
	return s.Checker.Check(ctx, row.Hostname, row.CheckToken, row.CheckToken+"."+row.SpkiSha256, d.AddressPolicy)
}

// admits is the table of docs/PHASE3.md §6.1. A known agent (the key of its
// last certificate, not disabled or revoked) comes back with a passed check
// alone, in every mode. A valid enrollment pass is never enough on its own,
// whatever the mode (docs/PHASE3.md section 11.2): it admits only together
// with a passed check, and never in manual mode – in auto mode a passed
// check admits anyway, a pass does not widen that.
func admits(mode string, token, pass, known, passed bool) bool {
	if known && passed {
		return true
	}
	if token && pass {
		return passed && (mode == tenant.EnrollAuto || mode == tenant.EnrollVerified)
	}
	switch mode {
	case tenant.EnrollAuto:
		return token || passed
	case tenant.EnrollVerified:
		return token && passed
	}
	return false // manual, or an unknown mode
}

func (s *Service) pendingMessage(row pkidb.AgentEnrollment) string {
	var have []string
	switch {
	case row.TokenValid == 1:
		have = append(have, "a valid join token")
	case row.TokenProblem.Valid:
		have = append(have, row.TokenProblem.String)
	default:
		have = append(have, "no join token")
	}
	if row.CheckState == "passed" {
		have = append(have, "a passed check")
	} else {
		have = append(have, "a failed check ("+row.CheckError.String+")")
	}
	return "waiting for an admin to approve it in the web UI (Agents) – " + strings.Join(have, ", ")
}

// admit makes an open enrollment an agent: a new one with its names, or the
// known agent again. by is the mode or the admin, for the record.
func (s *Service) admit(ctx context.Context, enrollmentID, mode, by string, who keys.Who) error {
	return s.admitBy(ctx, enrollmentID, mode, by, who, false)
}

// admitBy is admit; guardPass is set when no person decides but the mode and
// a pass: the host must still have no agent when the transaction runs, so two
// enrollments for one name cannot both be admitted by a pass. A person who
// approves from the queue has seen the reason and may replace a host.
func (s *Service) admitBy(ctx context.Context, enrollmentID, mode, by string, who keys.Who, guardPass bool) error {
	now := s.now()
	return s.inTx(ctx, func(q *pkidb.Queries, tx *sql.Tx) error {
		row, err := q.GetEnrollment(ctx, enrollmentID)
		if err != nil {
			return err
		}
		if row.State != StateWaitingForCheck && row.State != StatePending {
			return fmt.Errorf("%w: this enrollment is %s", ErrConflict, row.State)
		}
		proof, err := json.Marshal(map[string]any{
			"enrollment": row.ID, "token": row.TokenValid == 1, "token_id": row.TokenID.String, "check": row.CheckState,
			"method": row.CheckMethod, "checked_at": row.CheckedAt.String, "known_agent": row.KnownAgent == 1, "by": by,
		})
		if err != nil {
			return err
		}
		agentID := row.AgentID.String
		if row.KnownAgent == 1 {
			a, gerr := q.GetAgent(ctx, agentID)
			if gerr != nil {
				return gerr
			}
			if a.Status != StatusActive {
				return fmt.Errorf("%w: agent %s is %s – it can't enroll again", ErrConflict, a.Hostname, a.Status)
			}
			if rerr := q.ReadmitAgent(ctx, pkidb.ReadmitAgentParams{
				EnrollmentMode: mode, Proof: string(proof), Os: row.Os, Arch: row.Arch, AgentVersion: row.AgentVersion,
				ApprovedAt: dbTime(now), ApprovedBy: by, UpdatedAt: dbTime(now), ID: agentID,
			}); rerr != nil {
				return rerr
			}
		} else {
			if guardPass {
				if taken, terr := s.hostTaken(ctx, q, row.Hostname); terr != nil {
					return terr
				} else if taken {
					return errHostTaken
				}
			}
			if agentID, err = ids.New("agt", now, s.rnd()); err != nil {
				return err
			}
			if ierr := q.InsertAgent(ctx, pkidb.InsertAgentParams{
				ID: agentID, Hostname: row.Hostname, EnrollmentMode: mode, Proof: string(proof), Os: row.Os, Arch: row.Arch,
				AgentVersion: row.AgentVersion, CreatedAt: dbTime(now), ApprovedAt: dbTime(now), ApprovedBy: by, UpdatedAt: dbTime(now),
			}); ierr != nil {
				return ierr
			}
			if nerr := s.initialNames(ctx, q, row, agentID, now); nerr != nil {
				return nerr
			}
		}
		n, err := q.DecideEnrollment(ctx, pkidb.DecideEnrollmentParams{
			State: StateAdmitted, AgentID: nullString(agentID), DecidedAt: nullString(dbTime(now)), DecidedBy: nullString(by), ID: row.ID,
		})
		if err != nil {
			return err
		}
		if n != 1 {
			return fmt.Errorf("%w: decided in the meantime", ErrConflict)
		}
		return enqueue(ctx, tx, now, who, ActionAdmit, audit.Target{Type: "agent", ID: agentID}, map[string]any{
			"hostname": row.Hostname, "enrollment": row.ID, "mode": mode, "by": by, "token_valid": row.TokenValid == 1,
			"check": row.CheckState, "known_agent": row.KnownAgent == 1,
		})
	})
}

// initialNames: the hostname and the patterns of the join token that
// admitted the agent. An enrollment pass grants the host name only: its
// patterns decide who may enroll, not what the host may order – otherwise one
// leaked pass for *.homelab.lan would give every admitted host the right to
// order every name below the domain.
func (s *Service) initialNames(ctx context.Context, q *pkidb.Queries, row pkidb.AgentEnrollment, agentID string, now time.Time) error {
	add := func(pattern, source string) error {
		return q.InsertAgentName(ctx, pkidb.InsertAgentNameParams{AgentID: agentID, Pattern: pattern, Source: source, AddedBy: "enrollment " + row.ID, AddedAt: dbTime(now)})
	}
	if err := add(row.Hostname, "hostname"); err != nil {
		return err
	}
	if row.TokenValid != 1 || !row.TokenID.Valid {
		return nil
	}
	t, err := q.GetJoinToken(ctx, row.TokenID.String)
	if err != nil {
		return err
	}
	if t.Kind == KindPass {
		return nil
	}
	for _, p := range toJoinToken(t).Patterns {
		if p == row.Hostname {
			continue
		}
		if err := add(p, "token"); err != nil {
			return err
		}
	}
	return nil
}

// deliver returns the certificate of an admitted enrollment, issuing it
// first if needed – only while unsealed.
func (s *Service) deliver(ctx context.Context, row pkidb.AgentEnrollment, st *Status) (*Status, error) {
	q := pkidb.New(s.PKI)
	certID := row.CertID.String
	if !row.CertID.Valid {
		a, err := q.GetAgent(ctx, row.AgentID.String)
		if err != nil {
			return nil, err
		}
		if a.Status != StatusActive {
			st.State, st.Message = StateDenied, "this agent is "+a.Status
			return st, nil
		}
		// Asked before Issue: a refused issuance is an audit entry, and a
		// pending agent polls every 30 seconds while the server is sealed.
		if s.Engine.Keys.Status().Sealed {
			st.State, st.Message = StateWaitingForUnseal, "admitted – the server is sealed; the certificate follows the unseal"
			return st, nil
		}
		out, err := s.issue(ctx, a, row.CsrDer, func(q *pkidb.Queries, issued *ca.Issued) error {
			again, gerr := q.GetEnrollment(ctx, row.ID)
			if gerr != nil {
				return gerr
			}
			if again.CertID.Valid {
				return fmt.Errorf("%w: issued in the meantime", ErrConflict)
			}
			return q.SetEnrollmentCert(ctx, pkidb.SetEnrollmentCertParams{CertID: nullString(issued.ID), ID: row.ID})
		})
		switch {
		case errors.Is(err, keys.ErrSealed):
			st.State, st.Message = StateWaitingForUnseal, "admitted – the server is sealed; the certificate follows the unseal"
			return st, nil
		case errors.Is(err, ErrConflict):
			return s.deliverAgain(ctx, row.ID, st)
		case err != nil:
			return nil, err
		}
		certID = out.ID
	}
	der, chain, err := s.Engine.CertificateChain(ctx, systemWho, certID)
	if err != nil {
		return nil, err
	}
	st.CertDER, st.Chain, st.Message = der, chain, "admitted"
	return st, nil
}

// deliverAgain re-reads an admitted enrollment after a concurrent
// issuance and delivers that certificate.
func (s *Service) deliverAgain(ctx context.Context, id string, st *Status) (*Status, error) {
	row, err := pkidb.New(s.PKI).GetEnrollment(ctx, id)
	if err != nil {
		return nil, err
	}
	if !row.CertID.Valid {
		return nil, errors.New("the agent certificate was not stored")
	}
	return s.deliver(ctx, row, st)
}

// systemWho reads what the service needs (chains) without a user.
var systemWho = keys.Who{Actor: audit.Actor{Type: audit.ActorSystem, Name: "agents"}, Principal: authz.System("agents")}

// issue signs a 7-day agent certificate for the key of csrDER with the
// agent CA and makes it the agent's current one – in the transaction that
// stores the certificate, together with link (ADR-06).
func (s *Service) issue(ctx context.Context, a pkidb.Agent, csrDER []byte, link func(q *pkidb.Queries, issued *ca.Issued) error) (*ca.Issued, error) {
	now := s.now()
	return s.Engine.Issue(ctx, ca.Request{
		CA: s.CA, Preset: "client", CSR: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}),
		DNSNames: []string{a.Hostname}, IgnoreCSRNames: true, Subject: ca.Subject{CommonName: a.Hostname},
		ValidityDays: CertificateDays, Who: agentWho(a, ""),
		Stored: func(ctx context.Context, tx *sql.Tx, issued *ca.Issued) error {
			q := pkidb.New(tx)
			if err := q.SetAgentCertificate(ctx, pkidb.SetAgentCertificateParams{
				CertID: nullString(issued.ID), CertSerial: nullString(issued.SerialHex), UpdatedAt: dbTime(now), ID: a.ID,
			}); err != nil {
				return err
			}
			if link != nil {
				return link(q, issued)
			}
			return nil
		},
	})
}

// csrKey checks a CSR from outside and returns the base64url SHA-256 of its
// public key. Only the key and the signature count: names and extensions
// come from the server (pki-rules).
func csrKey(der []byte) (string, error) {
	if len(der) == 0 || len(der) > maxCSR {
		return "", fmt.Errorf("%w: CSR: 1 byte to 8 KiB of DER", ErrInvalid)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return "", fmt.Errorf("%w: CSR: not a PKCS#10 request", ErrInvalid)
	}
	if err := csr.CheckSignature(); err != nil {
		return "", fmt.Errorf("%w: CSR: the signature doesn't match its key", ErrInvalid)
	}
	if !slices.Contains([]x509.PublicKeyAlgorithm{x509.ECDSA, x509.Ed25519, x509.RSA}, csr.PublicKeyAlgorithm) {
		return "", fmt.Errorf("%w: CSR: an ECDSA, Ed25519 or RSA key", ErrInvalid)
	}
	return spkiHash(csr.RawSubjectPublicKeyInfo), nil
}

func spkiHash(spki []byte) string {
	sum := sha256.Sum256(spki)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func boolInt(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

// tokenRef links an enrollment to the join token that admitted it; a token
// that didn't count is named in token_problem only, so it can still be
// withdrawn.
func tokenRef(id string, valid bool) sql.NullString {
	if !valid {
		return sql.NullString{}
	}
	return nullString(id)
}
