package ca

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/settingsver"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
)

// History and restore of domains (PHASE3 section 16, step 63).
//
// Reading a history needs the audit right (versions name users: admin with a
// tenant-wide role) and the right to read the domain's CA (ErrNotFound
// otherwise, as for the domain itself). A restore needs what the same change
// needs: the ordinary writers run it (createDomain for a deleted domain,
// updateDomain for one that exists), so every check of a normal change applies
// with the same reasons, and the permission and the second factor are theirs.

// authorizeChange is authorize for a change. For the dry run of a restore
// check (DomainRestoreCheck) a missing second factor is not a refusal: the
// question is whether the restore would be accepted, and the answer must not
// depend on when the admin last confirmed.
func (e *Engine) authorizeChange(o ChangeOptions, who keys.Who, perm authz.Permission, caName string, now time.Time) error {
	err := e.authorize(who, perm, caName, now)
	if err != nil && o.restore != nil && o.restore.dry && errors.Is(err, authz.ErrStepUpRequired) {
		return nil
	}
	return err
}

// historyOf is what the readers of a domain's history work on.
type historyOf struct {
	q      *pkidb.Queries
	b      settingsver.Backend
	live   *Domain // nil: the domain is deleted
	latest settingsver.Version
	// has is false when there is no version at all (a domain that was never
	// changed since the history began).
	has bool
}

// openHistory finds the domain or its deleted remains and checks that the
// caller may read the history: the CA is readable (ErrNotFound otherwise),
// then the audit right (a denial).
func (e *Engine) openHistory(ctx context.Context, who keys.Who, id string) (*historyOf, error) {
	q := pkidb.New(e.PKI)
	h := &historyOf{q: q, b: settingsver.PKIBackend(q)}
	live, err := e.currentDomain(ctx, q, h.b, who, id)
	if err != nil {
		return nil, err
	}
	h.live = live
	switch h.latest, err = h.b.Latest(ctx, settingsver.KindDomain, id); {
	case err == nil:
		h.has = true
	case !errors.Is(err, settingsver.ErrNotFound):
		return nil, err
	}
	if err = e.authorize(who, authz.ReadAudit, "", e.now()); err != nil {
		return nil, err
	}
	return h, nil
}

// caNameOf is the name of a CA by ID, "" when it does not exist (the check
// then falls back to the tenant-wide role).
func (e *Engine) caNameOf(ctx context.Context, q *pkidb.Queries, id string) string {
	c, err := q.GetCA(ctx, id)
	if err != nil {
		return ""
	}
	return c.Name
}

// current is the live state of the domain as a snapshot, nil when it is deleted.
func (h *historyOf) current() settingsver.Snapshot {
	if h.live == nil {
		return nil
	}
	return domainSnapshot(h.live)
}

// DomainVersionPage is one page of the history of a domain.
type DomainVersionPage struct {
	settingsver.Page
	// Changed holds, per version of the page, the keys of the settings it
	// changed; nil for a version whose snapshot cannot be read.
	Changed [][]string
	// Current is the newest version number, the ETag (0 = no history yet).
	Current int64
}

// ListDomainVersions returns the history of a domain, newest first. A domain
// without versions has an empty history; one that does not exist (or whose CA
// the caller may not read) is ErrNotFound.
func (e *Engine) ListDomainVersions(ctx context.Context, who keys.Who, id string, before int64, limit int) (*DomainVersionPage, error) {
	h, err := e.openHistory(ctx, who, id)
	if err != nil {
		return nil, err
	}
	page, err := settingsver.List(ctx, h.b, settingsver.KindDomain, id, before, limit)
	if err != nil {
		return nil, err
	}
	return &DomainVersionPage{Page: page, Changed: settingsver.PageChanges(ctx, h.b, page.Versions), Current: h.latest.Number}, nil
}

// DomainVersionDetail is one version of a domain with its state, a diff and the
// answer to "could it be restored now".
type DomainVersionDetail struct {
	Version    settingsver.Version
	Snapshot   settingsver.DomainSnapshot
	Comparison settingsver.Comparison
	Restore    RestoreCheck
	// Current is the newest version number, the ETag.
	Current int64
}

// RestoreCheck is the answer of a dry run: whether the restore would be
// accepted now and, if not, the reasons the restore itself would give.
type RestoreCheck struct {
	Restorable bool
	Problems   []string
}

// GetDomainVersion returns one version of a domain. against is
// settingsver.AgainstPrevious, AgainstCurrent or a version number. A snapshot
// that cannot be read is settingsver.ErrUnknownSchema or ErrCorrupt.
func (e *Engine) GetDomainVersion(ctx context.Context, who keys.Who, id string, number, against int64) (*DomainVersionDetail, error) {
	h, err := e.openHistory(ctx, who, id)
	if err != nil {
		return nil, err
	}
	v, snap, cmp, err := settingsver.Compare(ctx, h.b, settingsver.KindDomain, id, number, against, h.current(), h.latest.Number)
	if errors.Is(err, settingsver.ErrNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	check, err := e.DomainRestoreCheck(ctx, who, id, number)
	if err != nil {
		return nil, err
	}
	return &DomainVersionDetail{Version: v, Snapshot: snap.(settingsver.DomainSnapshot), Comparison: cmp, Restore: check, Current: h.latest.Number}, nil
}

// DomainRestoreCheck asks whether RestoreDomain would accept a version now,
// from the same checks and without writing: the reasons are the ones the
// restore gives. The second factor is not asked for. A caller without the
// right to restore gets that as a problem.
func (e *Engine) DomainRestoreCheck(ctx context.Context, who keys.Who, id string, version int64) (RestoreCheck, error) {
	_, err := e.restoreDomain(ctx, id, version, ChangeOptions{restore: &restoreOf{from: version, id: id, dry: true}}, who, e.now())
	var denied *DeniedError
	switch {
	case err == nil:
		return RestoreCheck{Restorable: true, Problems: []string{}}, nil
	case errors.As(err, &denied):
		return RestoreCheck{Problems: slices.Clone(denied.Reasons)}, nil
	case errors.Is(err, settingsver.ErrIdentical):
		return RestoreCheck{Problems: []string{"this version is the state the domain already has – there is nothing to restore"}}, nil
	case errors.Is(err, settingsver.ErrUnknownSchema), errors.Is(err, settingsver.ErrCorrupt):
		return RestoreCheck{Problems: []string{"this version cannot be read by this release: " + err.Error()}}, nil
	}
	return RestoreCheck{}, err
}

// RestoreDomain makes a domain look like a stored version again, as a new
// version (change "restore", restored_from = version): the settings of the
// version go through the ordinary create (a deleted domain, under its old ID)
// or update, so every check of a normal change applies with the same reasons.
// opts.ExpectedVersion is required (settingsver.ErrPreconditionRequired
// after the permission checks) and is the newest version number the caller
// saw; a different one is settingsver.ErrConflict and nothing is written. A
// version that equals the current state is settingsver.ErrIdentical. The audit
// entry is domain.restore, with version, restored_from, changed_keys and
// snapshot_sha256; a refusal is audited like any refused domain change.
func (e *Engine) RestoreDomain(ctx context.Context, id string, version int64, opts ChangeOptions, who keys.Who) (*Domain, error) {
	now := e.now()
	opts.restore = &restoreOf{from: version, id: id}
	d, err := e.restoreDomain(ctx, id, version, opts, who, now)
	return d, e.finishDomain(ctx, now, ActionDomainRestore, who, id, "", err)
}

func (e *Engine) restoreDomain(ctx context.Context, id string, version int64, opts ChangeOptions, who keys.Who, now time.Time) (*Domain, error) {
	rs := opts.restore
	q := pkidb.New(e.PKI)
	b := settingsver.PKIBackend(q)
	// The domain, or its remains: reading it needs the CA to be readable (404).
	live, err := e.currentDomain(ctx, q, b, who, id)
	if err != nil {
		return nil, err
	}
	caName := ""
	if live != nil {
		caName = live.CA
	}
	// What the same change needs: updating needs ManageCA on the CA, creating a
	// domain again needs it tenant-wide (as createDomain does). Both with the
	// second factor, and never with an API token.
	if aerr := e.authorizeChange(opts, who, authz.ManageCA, caName, now); aerr != nil {
		return nil, aerr
	}
	if opts.ExpectedVersion == nil && !rs.dry {
		return nil, settingsver.ErrPreconditionRequired
	}
	if problems := reasonProblems(opts); len(problems) > 0 {
		return nil, &DeniedError{Reasons: problems}
	}
	v, err := settingsver.Get(ctx, b, settingsver.KindDomain, id, version)
	if errors.Is(err, settingsver.ErrNotFound) || (err != nil && version < 1) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	decoded, err := v.Decoded()
	if err != nil {
		return nil, err
	}
	snap := decoded.(settingsver.DomainSnapshot)
	// Early, so a stale caller hears 412 before a list of reasons; the writer
	// checks again inside its transaction.
	if err = settingsver.CheckExpected(ctx, b, settingsver.KindDomain, id, opts.ExpectedVersion); err != nil {
		return nil, err
	}
	if live != nil && settingsver.Same(domainSnapshot(live), snap) {
		return nil, settingsver.ErrIdentical
	}
	if live != nil && live.Name != snap.Name {
		return nil, &DeniedError{Reasons: []string{fmt.Sprintf("this version is of the domain %q, not %q", short(snap.Name), short(live.Name))}}
	}

	// The CA of the version, by ID: the domain settings name it.
	ca, cerr := q.GetCA(ctx, snap.CAID)
	if errors.Is(cerr, sql.ErrNoRows) {
		return nil, &DeniedError{Reasons: []string{fmt.Sprintf("the CA of this version (%s) no longer exists", short(snap.CAID))}}
	}
	if cerr != nil {
		return nil, cerr
	}
	s := DomainSettings{
		CA: &ca.Name, IncludeSubdomains: &snap.IncludeSubdomains, Wildcards: &snap.Wildcards,
		ChallengeTypes: slices.Clone(snap.ChallengeTypes), Approval: &snap.Approval, Preset: &snap.Preset,
		ValidityDays: &snap.ValidityDays, AddressPolicy: &snap.AddressPolicy, IPRanges: slices.Clone(snap.IPRanges), Options: opts,
	}
	if live != nil {
		return e.updateDomain(ctx, id, s, who, now)
	}
	return e.createDomain(ctx, DomainRequest{Name: snap.Name, DomainSettings: s, Who: who}, now)
}

// currentDomain returns the live domain, or nil when it is deleted (the
// caller may still read the remains: the CA of its last version is readable).
// ErrNotFound for a domain that never had a version, and for one whose CA the
// caller may not read.
func (e *Engine) currentDomain(ctx context.Context, q *pkidb.Queries, b settingsver.Backend, who keys.Who, id string) (*Domain, error) {
	_, err := q.GetDomain(ctx, id)
	if err == nil {
		return e.loadDomain(ctx, q, who, id)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	latest, err := b.Latest(ctx, settingsver.KindDomain, id)
	if errors.Is(err, settingsver.ErrNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	snap, err := latest.Decoded()
	if err != nil {
		return nil, err
	}
	if e.authorize(who, authz.ReadPKI, e.caNameOf(ctx, q, snap.(settingsver.DomainSnapshot).CAID), e.now()) != nil {
		return nil, ErrNotFound
	}
	return nil, nil
}

// DeletedDomain is a domain that was deleted and can be restored.
type DeletedDomain struct {
	ID        string
	Name      string
	CAID      string
	CAName    string // "" if the CA no longer exists
	Version   int64  // the deletion: the number a restore is based on
	DeletedAt time.Time
	DeletedBy string
	Reason    string
}

// ListDeletedDomains returns the domains whose newest version is their
// deletion (and that do not exist again), newest deletion first, for CAs the
// caller may read. It needs the audit right.
func (e *Engine) ListDeletedDomains(ctx context.Context, who keys.Who) ([]DeletedDomain, error) {
	if err := e.authorize(who, authz.ReadAudit, "", e.now()); err != nil {
		return nil, err
	}
	q := pkidb.New(e.PKI)
	latest, err := settingsver.PKIBackend(q).LatestOfKind(ctx, settingsver.KindDomain)
	if err != nil {
		return nil, err
	}
	out := []DeletedDomain{}
	for _, v := range latest {
		if v.Change != settingsver.ChangeDelete {
			continue
		}
		if _, gerr := q.GetDomain(ctx, v.ObjectID); gerr == nil {
			continue // exists again (a restore, or an earlier import of the same ID)
		} else if !errors.Is(gerr, sql.ErrNoRows) {
			return nil, gerr
		}
		decoded, derr := v.Decoded()
		if derr != nil {
			continue // cannot be shown, and a restore would be refused anyway
		}
		snap := decoded.(settingsver.DomainSnapshot)
		name := e.caNameOf(ctx, q, snap.CAID)
		if e.authorize(who, authz.ReadPKI, name, e.now()) != nil {
			continue
		}
		out = append(out, DeletedDomain{
			ID: v.ObjectID, Name: snap.Name, CAID: snap.CAID, CAName: name, Version: v.Number,
			DeletedAt: v.CreatedAt, DeletedBy: v.Actor.Name, Reason: v.Reason,
		})
	}
	slices.SortStableFunc(out, func(a, b DeletedDomain) int {
		if c := b.DeletedAt.Compare(a.DeletedAt); c != 0 {
			return c
		}
		return strings.Compare(a.Name, b.Name)
	})
	return out, nil
}
