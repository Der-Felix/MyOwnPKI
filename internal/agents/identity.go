package agents

import (
	"bytes"
	"context"
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
)

// Caller is an authenticated agent request.
type Caller struct {
	Agent pkidb.Agent
	Who   keys.Who
}

// Identify maps the client certificate of a request to its agent – per
// request, not per handshake, so a revocation or a "disable" takes effect at
// the next call even on a resumed TLS session. Only the agent's current
// certificate and the one before it count (renewal overlap), and only as
// exactly the stored certificate.
func (s *Service) Identify(ctx context.Context, leaf *x509.Certificate, sourceIP string) (*Caller, error) {
	if leaf == nil {
		return nil, ErrUnknownAgent
	}
	q := pkidb.New(s.PKI)
	serial := ca.SerialHex(leaf.SerialNumber)
	a, err := q.GetAgentByCertSerial(ctx, sql.NullString{String: serial, Valid: true})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUnknownAgent
	} else if err != nil {
		return nil, err
	}
	if a.Status != StatusActive {
		return nil, fmt.Errorf("%w: agent %s is %s", ErrUnknownAgent, a.Hostname, a.Status)
	}
	id := a.CertID.String
	if a.CertSerial.String != serial {
		id = a.PrevCertID.String
	}
	c, err := q.GetCertificate(ctx, id)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(c.CertDer, leaf.Raw) {
		return nil, ErrUnknownAgent
	}
	now := s.now()
	if !a.LastSeenAt.Valid || now.Sub(parseTime(a.LastSeenAt.String)) >= time.Minute {
		if err := q.TouchAgent(ctx, pkidb.TouchAgentParams{LastSeenAt: nullString(dbTime(now)), ID: a.ID}); err != nil {
			return nil, err
		}
	}
	return &Caller{Agent: a, Who: agentWho(a, sourceIP)}, nil
}

// RenewCertificate gives an agent a new 7-day certificate for a new key
// (ADR-11: the same key twice is refused). The current certificate becomes
// the previous one and stays accepted until it expires.
func (s *Service) RenewCertificate(ctx context.Context, c *Caller, csrDER []byte) (der []byte, chain [][]byte, err error) {
	if s.Engine.Keys.Status().Sealed { // not tried: a refusal is an audit entry, and the agent retries
		return nil, nil, keys.ErrSealed
	}
	spki, err := csrKey(csrDER)
	if err != nil {
		return nil, nil, err
	}
	cur, err := pkidb.New(s.PKI).GetCertificate(ctx, c.Agent.CertID.String)
	if err != nil {
		return nil, nil, err
	}
	leaf, err := x509.ParseCertificate(cur.CertDer)
	if err != nil {
		return nil, nil, err
	}
	if spkiHash(leaf.RawSubjectPublicKeyInfo) == spki {
		return nil, nil, fmt.Errorf("%w: CSR: use a new key for every certificate (ADR-11)", ErrInvalid)
	}
	// An agent renews about once in 4.7 days; a loop of renewals is a bug or
	// an attack and would fill the certificate list and the audit log.
	if !s.limiter().allow("renew:"+c.Agent.ID, renewPerHour, time.Hour, s.now()) {
		return nil, nil, ErrRateLimited
	}
	out, err := s.issue(ctx, c.Agent, csrDER, nil)
	if err != nil {
		return nil, nil, err
	}
	return out.CertDER, out.Chain[:max(len(out.Chain)-1, 0)], nil
}
