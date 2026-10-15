package ca

import (
	"context"
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
)

// RenewCA renews a CA with a new key: the next generation. An online root
// signs itself, an intermediate is signed by its parent – at once, or
// through the offline flow when the parent is offline. The old generation
// keeps its URL and goes on signing the CRL for its certificates (step 9).
// An offline root is renewed by importing its new certificate (ImportRoot).
func (e *Engine) RenewCA(ctx context.Context, req RenewRequest) (*CAResult, error) {
	now := e.now()
	out, err := e.renewCA(ctx, req, now)
	return e.finish(ctx, now, ActionCARenew, req.Who, req.Name, out, err)
}

func (e *Engine) renewCA(ctx context.Context, req RenewRequest, now time.Time) (*CAResult, error) {
	if err := e.authorize(req.Who, authz.ManageCA, short(req.Name), now); err != nil {
		return nil, err
	}
	q := pkidb.New(e.PKI)
	ca, current, err := loadActive(ctx, q, req.Name)
	if err != nil {
		return nil, err
	}
	if _, perr := q.GetPendingGeneration(ctx, ca.ID); perr == nil {
		return nil, deny("CA %q already has a generation waiting for its signature – upload that certificate first", ca.Name)
	} else if !errors.Is(perr, sql.ErrNoRows) {
		return nil, perr
	}
	cert, err := x509.ParseCertificate(current.CertDer)
	if err != nil {
		return nil, err
	}
	var parent *parentInfo
	if ca.Kind == KindRoot {
		if ca.KeyMode == KeyModeOffline {
			return nil, deny("CA %q is an offline root – renew it offline and import the new root certificate under the same name", ca.Name)
		}
	} else {
		pca, perr := q.GetCA(ctx, ca.ParentID.String)
		if perr != nil {
			return nil, perr
		}
		if parent, err = loadParent(ctx, q, pca.Name, now); err != nil {
			return nil, err
		}
	}
	plan, err := planFromCA(ctx, q, ca, parent)
	if err != nil {
		return nil, err
	}
	plan.action = ActionCARenew
	plan.subject, plan.rawSubject = cert.Subject, cert.RawSubject
	if plan.generation, err = q.MaxGeneration(ctx, ca.ID); err != nil {
		return nil, err
	}
	plan.generation++

	var reasons []string
	var p []string
	plan.alg, p = newCAAlgorithm(req.KeyAlgorithm, current.KeyAlgorithm)
	reasons = append(reasons, p...)
	if ca.Kind == KindRoot {
		plan.v = caValidity(now, req.ValidityDays, DefaultRootDays, nil)
		plan.warnings = append(plan.warnings, "a renewed root is a new trust anchor: distribute it to every trust store before certificates below it are used")
	} else {
		plan.v = caValidity(now, req.ValidityDays, DefaultIntermediateDays, parent.cert())
		reasons = append(reasons, checkUnderParent(parent, plan)...)
	}
	if plan.v.problem != "" {
		reasons = append(reasons, plan.v.problem)
	}
	if len(reasons) > 0 {
		return nil, &DeniedError{Reasons: reasons}
	}
	return e.signAndStore(ctx, now, plan, req.Who)
}

// loadActive reads an active CA and its current, signed generation.
func loadActive(ctx context.Context, q *pkidb.Queries, name string) (pkidb.Ca, pkidb.CaGeneration, error) {
	ca, err := q.GetCAByName(ctx, name)
	if errors.Is(err, sql.ErrNoRows) {
		return ca, pkidb.CaGeneration{}, deny("there is no CA named %q", short(name))
	}
	if err != nil {
		return ca, pkidb.CaGeneration{}, err
	}
	if ca.Status != StatusActive || !ca.CurrentGeneration.Valid {
		return ca, pkidb.CaGeneration{}, deny("CA %q is %s, not active", name, ca.Status)
	}
	gen, err := q.GetCAGeneration(ctx, pkidb.GetCAGenerationParams{CaID: ca.ID, Generation: ca.CurrentGeneration.Int64})
	return ca, gen, err
}

// RetireCA stops a CA from issuing. Its certificates stay valid and its
// CRLs go on until they have expired (step 9). It can't be undone.
func (e *Engine) RetireCA(ctx context.Context, name string, who keys.Who) error {
	now := e.now()
	_, err := e.finish(ctx, now, ActionCARetire, who, name, nil, e.retireCA(ctx, name, who, now))
	return err
}

func (e *Engine) retireCA(ctx context.Context, name string, who keys.Who, now time.Time) error {
	if err := e.authorize(who, authz.ManageCA, short(name), now); err != nil {
		return err
	}
	q := pkidb.New(e.PKI)
	ca, err := q.GetCAByName(ctx, name)
	if errors.Is(err, sql.ErrNoRows) {
		return deny("there is no CA named %q", short(name))
	}
	if err != nil {
		return err
	}
	if ca.Status == StatusRetired {
		return deny("CA %q is retired already", name)
	}
	return e.inTx(ctx, func(q *pkidb.Queries, tx *sql.Tx) error {
		if terr := q.SetCAStatus(ctx, pkidb.SetCAStatusParams{Status: StatusRetired, UpdatedAt: now.Format(audit.TimeFormat), ID: ca.ID}); terr != nil {
			return terr
		}
		return audit.Enqueue(ctx, tx, now, audit.Entry{
			Time: now, Actor: who.Actor, Action: ActionCARetire, Target: audit.Target{Type: "ca", ID: ca.ID},
			Result: audit.ResultSuccess, SourceIP: who.SourceIP, Details: map[string]any{"name": ca.Name, "previous_status": ca.Status},
		})
	})
}

// UpdateRequest changes the limits of a CA; zero keeps a value.
type UpdateRequest struct {
	Name            string
	CRLDays         int
	MaxValidityDays int
	Who             keys.Who
}

// UpdateCA changes CRL lifetime and maximum certificate validity. Name and
// base URL never change: they are inside certificates already.
func (e *Engine) UpdateCA(ctx context.Context, req UpdateRequest) error {
	now := e.now()
	_, err := e.finish(ctx, now, ActionCAUpdate, req.Who, req.Name, nil, e.updateCA(ctx, req, now))
	return err
}

func (e *Engine) updateCA(ctx context.Context, req UpdateRequest, now time.Time) error {
	if err := e.authorize(req.Who, authz.ManageCA, short(req.Name), now); err != nil {
		return err
	}
	q := pkidb.New(e.PKI)
	ca, err := q.GetCAByName(ctx, req.Name)
	if errors.Is(err, sql.ErrNoRows) {
		return deny("there is no CA named %q", short(req.Name))
	}
	if err != nil {
		return err
	}
	crl, maxV := ca.CrlDays, ca.MaxValidityDays
	if req.CRLDays != 0 {
		crl = int64(req.CRLDays)
	}
	if req.MaxValidityDays != 0 {
		maxV = int64(req.MaxValidityDays)
	}
	if reasons := checkLimits(int(crl), int(maxV)); len(reasons) > 0 {
		return &DeniedError{Reasons: reasons}
	}
	if crl == ca.CrlDays && maxV == ca.MaxValidityDays {
		return deny("nothing to change for CA %q", req.Name)
	}
	return e.inTx(ctx, func(q *pkidb.Queries, tx *sql.Tx) error {
		if terr := q.UpdateCALimits(ctx, pkidb.UpdateCALimitsParams{CrlDays: crl, MaxValidityDays: maxV, UpdatedAt: now.Format(audit.TimeFormat), ID: ca.ID}); terr != nil {
			return terr
		}
		return audit.Enqueue(ctx, tx, now, audit.Entry{
			Time: now, Actor: req.Who.Actor, Action: ActionCAUpdate, Target: audit.Target{Type: "ca", ID: ca.ID},
			Result: audit.ResultSuccess, SourceIP: req.Who.SourceIP, Details: map[string]any{
				"name":     ca.Name,
				"crl_days": fmt.Sprintf("%d -> %d", ca.CrlDays, crl), "max_validity_days": fmt.Sprintf("%d -> %d", ca.MaxValidityDays, maxV),
			},
		})
	})
}
