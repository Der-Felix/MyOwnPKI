package acme

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/predecessor"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
)

// Admin actions on the ACME server (PHASE2 step 13): approvals and EAB
// keys. They need ca.manage on the tenant – with a fresh second factor –
// because an approval lets an account obtain certificates.

func (s *Server) authorize(who keys.Who) error {
	tenant := strings.TrimPrefix(s.engine.Scope, "tenant:")
	if err := who.Principal.Check(authz.ManageCA, authz.Resource{Tenant: tenant}, s.clk.Now()); err != nil {
		return &ca.DeniedError{Reasons: []string{err.Error()}, Cause: err}
	}
	return nil
}

// ErrNotFound: no such account, name or key.
var ErrNotFound = errors.New("not found")

// ApproveAccount lets an account order under the approval level "account".
func (s *Server) ApproveAccount(ctx context.Context, id string, who keys.Who) error {
	if err := s.authorize(who); err != nil {
		return err
	}
	now := s.now()
	return s.inTx(ctx, func(q *pkidb.Queries, tx *sql.Tx) error {
		acct, err := q.GetACMEAccount(ctx, id)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if acct.Status != "valid" {
			return &ca.DeniedError{Reasons: []string{fmt.Sprintf("account %s is %s", id, acct.Status)}}
		}
		n, err := q.ApproveACMEAccount(ctx, pkidb.ApproveACMEAccountParams{
			ApprovedAt: sql.NullString{String: dbTime(now), Valid: true}, ApprovedBy: sql.NullString{String: who.Actor.Name, Valid: true},
			UpdatedAt: dbTime(now), ID: id,
		})
		if err != nil {
			return err
		}
		if n == 0 {
			return &ca.DeniedError{Reasons: []string{fmt.Sprintf("account %s is approved already", id)}}
		}
		return audit.Enqueue(ctx, tx, now, audit.Entry{
			Time: now, Actor: who.Actor, Action: ActionAccountApprove, Target: audit.Target{Type: "acme_account", ID: id},
			Result: audit.ResultSuccess, SourceIP: who.SourceIP, Details: map[string]any{"key_thumbprint": acct.KeyThumbprint},
		})
	})
}

// DecideName approves or refuses a name waiting under "new_name" ("dns:x"
// or "ip:x"). Approving a name nobody asked for yet is allowed too.
func (s *Server) DecideName(ctx context.Context, name string, approve bool, who keys.Who) error {
	if err := s.authorize(who); err != nil {
		return err
	}
	if !strings.HasPrefix(name, "dns:") && !strings.HasPrefix(name, "ip:") {
		return &ca.DeniedError{Reasons: []string{fmt.Sprintf("%q is not dns:<name> or ip:<address>", clip(name))}}
	}
	now := s.now()
	status := "refused"
	if approve {
		status = "approved"
	}
	return s.inTx(ctx, func(q *pkidb.Queries, tx *sql.Tx) error {
		n, err := q.DecideACMEName(ctx, pkidb.DecideACMENameParams{Status: status, DecidedBy: sql.NullString{String: who.Actor.Name, Valid: true}, DecidedAt: sql.NullString{String: dbTime(now), Valid: true}, Name: name})
		if err != nil {
			return err
		}
		if n == 0 {
			if !approve {
				return ErrNotFound
			}
			if aerr := q.ApproveACMENameDirectly(ctx, pkidb.ApproveACMENameDirectlyParams{
				Name: name, RequestedBy: who.Actor.Name, RequestedAt: dbTime(now),
				DecidedBy: sql.NullString{String: who.Actor.Name, Valid: true}, DecidedAt: sql.NullString{String: dbTime(now), Valid: true},
			}); aerr != nil {
				return aerr
			}
		}
		return audit.Enqueue(ctx, tx, now, audit.Entry{
			Time: now, Actor: who.Actor, Action: ActionNameDecide, Target: audit.Target{Type: "acme_name", ID: name},
			Result: audit.ResultSuccess, SourceIP: who.SourceIP, Details: map[string]any{"decision": status},
		})
	})
}

// readable: the ACME pages need a tenant-wide role (they show every
// account of the tenant).
func (s *Server) readable(who keys.Who) error {
	tenant := strings.TrimPrefix(s.engine.Scope, "tenant:")
	if err := who.Principal.Check(authz.ReadPKI, authz.Resource{Tenant: tenant}, s.clk.Now()); err != nil {
		return &ca.DeniedError{Reasons: []string{err.Error()}, Cause: err}
	}
	return nil
}

// Pending counts what waits for an admin (dashboard).
func (s *Server) Pending(ctx context.Context) (accounts, names int64, err error) {
	q := pkidb.New(s.db)
	if accounts, err = q.CountACMEAccountsWaiting(ctx); err != nil {
		return 0, 0, err
	}
	names, err = q.CountACMENamesWaiting(ctx)
	return accounts, names, err
}

// AccountInfo is an ACME account as the UI shows it.
type AccountInfo struct {
	ID, Status, Thumbprint, CreatedAt, CreatedIP string
	Contacts                                     []string
	Approved                                     bool
	ApprovedBy, ApprovedAt, EABKey               string
	Predecessor                                  *predecessor.Policy
	EffectivePredecessor                         predecessor.Policy
}

func accountInfo(a *pkidb.AcmeAccount) AccountInfo {
	var contacts []string
	_ = json.Unmarshal([]byte(a.Contact), &contacts)
	return AccountInfo{
		ID: a.ID, Status: a.Status, Thumbprint: a.KeyThumbprint, CreatedAt: a.CreatedAt, CreatedIP: a.CreatedIp, Contacts: contacts,
		Approved: a.ApprovedAt.Valid, ApprovedBy: a.ApprovedBy.String, ApprovedAt: a.ApprovedAt.String, EABKey: a.EabKeyID.String,
	}
}

// Accounts lists the newest accounts.
func (s *Server) Accounts(ctx context.Context, who keys.Who) ([]AccountInfo, error) {
	if err := s.readable(who); err != nil {
		return nil, err
	}
	rows, err := pkidb.New(s.db).ListACMEAccounts(ctx, 500)
	if err != nil {
		return nil, err
	}
	out := make([]AccountInfo, 0, len(rows))
	for i := range rows {
		out = append(out, accountInfo(&rows[i]))
	}
	return out, nil
}

// Account returns one account.
func (s *Server) Account(ctx context.Context, who keys.Who, id string) (*AccountInfo, error) {
	if err := s.readable(who); err != nil {
		return nil, err
	}
	a, err := pkidb.New(s.db).GetACMEAccount(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	info := accountInfo(&a)
	if a.PredecessorChoice.Valid {
		policy := predecessor.Policy{Choice: a.PredecessorChoice.String, Days: int(a.PredecessorDays.Int64)}.Normalize()
		info.Predecessor = &policy
	}
	info.EffectivePredecessor, err = s.engine.EffectiveOtherPredecessor(ctx)
	if err != nil {
		return nil, err
	}
	if info.Predecessor != nil {
		info.EffectivePredecessor = *info.Predecessor
	}
	return &info, nil
}

// SetAccountPredecessor changes the non-agent account override. Nil restores
// the tenant default. It needs the same admin+step-up as other ACME admin actions.
func (s *Server) SetAccountPredecessor(ctx context.Context, id string, policy *predecessor.Policy, who keys.Who) error {
	if err := s.authorize(who); err != nil {
		return err
	}
	if policy != nil {
		normalized := policy.Normalize()
		if err := normalized.Validate(); err != nil {
			return &ca.DeniedError{Reasons: []string{err.Error()}, Cause: err}
		}
		policy = &normalized
	}
	now := s.now()
	return s.inTx(ctx, func(q *pkidb.Queries, tx *sql.Tx) error {
		account, err := q.GetACMEAccount(ctx, id)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if account.AgentID.Valid {
			return &ca.DeniedError{Reasons: []string{"agent-linked accounts use the agent/deployment predecessor settings"}}
		}
		choice, days := sql.NullString{}, sql.NullInt64{}
		if policy != nil {
			choice = sql.NullString{String: policy.Choice, Valid: true}
			if policy.Choice == predecessor.After {
				days = sql.NullInt64{Int64: int64(policy.Days), Valid: true}
			}
		}
		n, err := q.SetACMEPredecessorPolicy(ctx, pkidb.SetACMEPredecessorPolicyParams{
			PredecessorChoice: choice, PredecessorDays: days, UpdatedAt: dbTime(now), ID: id,
		})
		if err != nil {
			return err
		}
		if n != 1 {
			return ErrNotFound
		}
		details := map[string]any{"inherit": policy == nil}
		if policy != nil {
			details["choice"] = policy.Choice
			if policy.Choice == predecessor.After {
				details["days"] = policy.Days
			}
		}
		return audit.Enqueue(ctx, tx, now, audit.Entry{
			Time: now, Actor: who.Actor, Action: "acme.account.predecessor", Target: audit.Target{Type: "acme_account", ID: id},
			Result: audit.ResultSuccess, SourceIP: who.SourceIP, Details: details,
		})
	})
}

// NameInfo is a name under the approval level "new_name".
type NameInfo struct {
	Name, Status, RequestedBy, RequestedAt, DecidedBy, DecidedAt string
}

// Names lists waiting names first.
func (s *Server) Names(ctx context.Context, who keys.Who) ([]NameInfo, error) {
	if err := s.readable(who); err != nil {
		return nil, err
	}
	rows, err := pkidb.New(s.db).ListACMENames(ctx, 500)
	if err != nil {
		return nil, err
	}
	out := make([]NameInfo, 0, len(rows))
	for _, n := range rows {
		out = append(out, NameInfo{Name: n.Name, Status: n.Status, RequestedBy: n.RequestedBy, RequestedAt: n.RequestedAt,
			DecidedBy: n.DecidedBy.String, DecidedAt: n.DecidedAt.String})
	}
	return out, nil
}

// OrderInfo is an ACME order as the UI shows it.
type OrderInfo struct {
	ID, AccountID, Status, CertificateID, CreatedAt, Error string
	Identifiers                                            []string
}

// Orders lists the newest orders.
func (s *Server) Orders(ctx context.Context, who keys.Who) ([]OrderInfo, error) {
	if err := s.readable(who); err != nil {
		return nil, err
	}
	rows, err := pkidb.New(s.db).ListACMEOrders(ctx, 200)
	if err != nil {
		return nil, err
	}
	out := make([]OrderInfo, 0, len(rows))
	for _, o := range rows {
		var idents []identifier
		_ = json.Unmarshal([]byte(o.Identifiers), &idents)
		info := OrderInfo{ID: o.ID, AccountID: o.AccountID, Status: o.Status, CertificateID: o.CertificateID.String, CreatedAt: o.CreatedAt}
		for _, i := range idents {
			info.Identifiers = append(info.Identifiers, i.Value)
		}
		if o.Error.Valid {
			var p struct {
				Detail string `json:"detail"`
			}
			_ = json.Unmarshal([]byte(o.Error.String), &p)
			info.Error = p.Detail
		}
		out = append(out, info)
	}
	return out, nil
}

// EABKeyInfo is an EAB key without its secret.
type EABKeyInfo struct {
	ID, Label, ExpiresAt, UsedAt, UsedBy, CreatedBy, CreatedAt string
}

// EABKeys lists the newest keys.
func (s *Server) EABKeys(ctx context.Context, who keys.Who) ([]EABKeyInfo, error) {
	if err := s.readable(who); err != nil {
		return nil, err
	}
	rows, err := pkidb.New(s.db).ListACMEEABKeys(ctx, 200)
	if err != nil {
		return nil, err
	}
	out := make([]EABKeyInfo, 0, len(rows))
	for _, k := range rows {
		out = append(out, EABKeyInfo{ID: k.ID, Label: k.Label, ExpiresAt: k.ExpiresAt, UsedAt: k.UsedAt.String, UsedBy: k.UsedBy.String,
			CreatedBy: k.CreatedBy, CreatedAt: k.CreatedAt})
	}
	return out, nil
}

// NewEABKey is a fresh key: the MAC is shown once and never stored in
// plain text.
type NewEABKey struct {
	KID, HMAC, ExpiresAt string
}

// EAB key validity bounds in days.
const (
	DefaultEABDays = 7
	maxEABDays     = 90
)

// CreateEABKey makes an EAB key (owner Q2): 256 random bits, encrypted
// with the key ring (purpose acme-eab, so it can't be read as another
// key), usable once until it expires. It needs ca.manage with a fresh
// second factor and an unsealed server.
func (s *Server) CreateEABKey(ctx context.Context, label string, days int, who keys.Who) (*NewEABKey, error) {
	if err := s.authorize(who); err != nil {
		return nil, err
	}
	label = strings.TrimSpace(label)
	var problems []string
	if label == "" || utf8.RuneCountInString(label) > 64 || strings.ContainsFunc(label, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		problems = append(problems, "label: 1 to 64 characters, no control characters – e.g. the host that will use it")
	}
	if days < 1 || days > maxEABDays {
		problems = append(problems, fmt.Sprintf("validity: 1 to %d days", maxEABDays))
	}
	if len(problems) > 0 {
		return nil, &ca.DeniedError{Reasons: problems}
	}
	id, err := s.newID("eab")
	if err != nil {
		return nil, err
	}
	mac := make([]byte, 32)
	if _, rerr := io.ReadFull(s.rnd, mac); rerr != nil {
		return nil, rerr
	}
	defer clear(mac)
	env, err := s.engine.Keys.EncryptKey(id, keys.PurposeEAB, EABAlgorithm, mac)
	if err != nil {
		return nil, err // keys.ErrSealed while sealed
	}
	now := s.now()
	expires := now.Add(time.Duration(days) * 24 * time.Hour)
	err = s.inTx(ctx, func(q *pkidb.Queries, tx *sql.Tx) error {
		if ierr := q.InsertACMEEABKey(ctx, pkidb.InsertACMEEABKeyParams{
			ID: id, Label: label, RootKeyVersion: env.RootKeyVersion, WrappedDek: env.WrappedDEK, MacCiphertext: env.Ciphertext,
			ExpiresAt: dbTime(expires), CreatedBy: who.Actor.Name, CreatedAt: dbTime(now),
		}); ierr != nil {
			return ierr
		}
		return audit.Enqueue(ctx, tx, now, audit.Entry{
			Time: now, Actor: who.Actor, Action: ActionEABCreate, Target: audit.Target{Type: "acme_eab_key", ID: id},
			Result: audit.ResultSuccess, SourceIP: who.SourceIP, Details: map[string]any{"label": label, "expires_at": dbTime(expires)},
		})
	})
	if err != nil {
		return nil, err
	}
	return &NewEABKey{KID: id, HMAC: base64.RawURLEncoding.EncodeToString(mac), ExpiresAt: dbTime(expires)}, nil
}
