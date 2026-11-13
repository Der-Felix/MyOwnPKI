package httpapi

import (
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/settingsver"
	"github.com/Der-Felix/MyOwnPKI/internal/tenant"
)

// History and restore of domains and tenant settings (PHASE3 section 16,
// step 63). Reading needs the audit right (versions name users); a restore
// needs what the same change needs, which the services check. Actor names,
// IDs and reasons are free text: they are data here and in every client.

var (
	versionPathPattern = regexp.MustCompile(`^[0-9]{1,15}$`)
	againstPattern     = regexp.MustCompile(`^(previous|current|[0-9]{1,15})$`)
)

type versionJSON struct {
	Version        int64     `json:"version"`
	Change         string    `json:"change"`
	ActorType      string    `json:"actor_type"`
	ActorID        string    `json:"actor_id"`
	ActorName      string    `json:"actor_name"`
	Reason         string    `json:"reason"`
	RestoredFrom   *int64    `json:"restored_from"`
	CreatedAt      time.Time `json:"created_at"`
	SnapshotSHA256 string    `json:"snapshot_sha256"`
	Schema         int       `json:"schema"`
	// ChangedKeys is null when a snapshot of this version could not be read.
	ChangedKeys []string `json:"changed_keys"`
}

func toVersionJSON(v settingsver.Version, changed []string) versionJSON {
	out := versionJSON{
		Version: v.Number, Change: v.Change, ActorType: v.Actor.Type, ActorID: v.Actor.ID, ActorName: v.Actor.Name, Reason: v.Reason,
		CreatedAt: v.CreatedAt.UTC(), SnapshotSHA256: v.SHA256, Schema: v.Schema, ChangedKeys: changed,
	}
	if v.RestoredFrom > 0 {
		out.RestoredFrom = &v.RestoredFrom
	}
	return out
}

type fieldChangeJSON struct {
	Key    string   `json:"key"`
	Label  string   `json:"label"`
	Before []string `json:"before"`
	After  []string `json:"after"`
	Kind   string   `json:"kind"`
}

type diffJSON struct {
	From    int64             `json:"from"`
	To      int64             `json:"to"`
	Against string            `json:"against"`
	Changes []fieldChangeJSON `json:"changes"`
}

func toDiffJSON(c settingsver.Comparison) diffJSON {
	out := diffJSON{From: c.From, To: c.To, Against: c.Against, Changes: make([]fieldChangeJSON, 0, len(c.Changes))}
	for _, ch := range c.Changes {
		out.Changes = append(out.Changes, fieldChangeJSON{
			Key: ch.Key, Label: ch.Label, Before: emptyList(ch.Before), After: emptyList(ch.After), Kind: ch.Kind,
		})
	}
	return out
}

func emptyList(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

type versionPageJSON struct {
	Items      []versionJSON `json:"items"`
	NextBefore *int64        `json:"next_before"`
}

func toPageJSON(p settingsver.Page, changed [][]string) versionPageJSON {
	out := versionPageJSON{Items: make([]versionJSON, 0, len(p.Versions))}
	for i, v := range p.Versions {
		out.Items = append(out.Items, toVersionJSON(v, changed[i]))
	}
	if p.Next > 0 {
		out.NextBefore = &p.Next
	}
	return out
}

type versionDetailJSON struct {
	versionJSON
	Snapshot        any      `json:"snapshot"`
	Diff            diffJSON `json:"diff"`
	Restorable      bool     `json:"restorable"`
	RestoreProblems []string `json:"restore_problems"`
}

// restoreRequest is the body of a restore: only the optional reason.
type restoreRequest struct {
	Reason string `json:"reason"`
}

// versionNumber reads the {version} path parameter; anything that is not a
// positive number is no such version.
func versionNumber(c *call) (int64, error) {
	s := c.r.PathValue("version")
	if !versionPathPattern.MatchString(s) {
		return 0, ca.ErrNotFound
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 1 {
		return 0, ca.ErrNotFound
	}
	return n, nil
}

// pageQuery reads before and limit.
func pageQuery(c *call) (before int64, limit int, err error) {
	qv := c.r.URL.Query()
	if s := qv.Get("limit"); s != "" {
		n, perr := strconv.Atoi(s)
		if perr != nil || n < 1 || n > 100 {
			return 0, 0, badRequest("limit", "1 to 100")
		}
		limit = n
	}
	if s := qv.Get("before"); s != "" {
		n, perr := strconv.ParseInt(s, 10, 64)
		if perr != nil || n < 1 {
			return 0, 0, badRequest("before", "a version number")
		}
		before = n
	}
	return before, limit, nil
}

// againstQuery reads what the diff is compared with: previous (default),
// current or a version number.
func againstQuery(c *call) (int64, error) {
	s := c.r.URL.Query().Get("against")
	switch {
	case s == "" || s == "previous":
		return settingsver.AgainstPrevious, nil
	case s == "current":
		return settingsver.AgainstCurrent, nil
	case againstPattern.MatchString(s):
		n, err := strconv.ParseInt(s, 10, 64)
		if err == nil {
			return n, nil
		}
	}
	return 0, badRequest("against", "previous, current or a version number")
}

// restoreBody reads the optional reason and the required If-Match.
func restoreBody(c *call) (reason string, expected *int64, err error) {
	var req restoreRequest
	if err = c.decode(&req); err != nil {
		return "", nil, err
	}
	if expected, err = c.ifMatch(); err != nil {
		return "", nil, err
	}
	return req.Reason, expected, nil
}

// versionError maps the errors of the version history that no other mapping
// knows, and reports whether err was one.
func versionError(c *call, err error) bool {
	switch {
	case errors.Is(err, settingsver.ErrPreconditionRequired):
		_ = c.problem(http.StatusPreconditionRequired, "precondition-required",
			"send the ETag of the newest version as If-Match (the ETag header of GET .../versions)", nil)
	case errors.Is(err, settingsver.ErrIdentical):
		_ = c.problem(http.StatusConflict, "conflict", "this version is the state the object already has – there is nothing to restore", nil)
	case errors.Is(err, settingsver.ErrUnknownSchema):
		_ = c.problem(http.StatusConflict, "conflict",
			"this version was written in a snapshot format that this release does not know; it cannot be read or restored here", nil)
	case errors.Is(err, settingsver.ErrCorrupt):
		_ = c.problem(http.StatusConflict, "conflict",
			"the stored version is damaged (it does not match its checksum or its format); it cannot be read or restored", nil)
	case errors.Is(err, settingsver.ErrNotFound):
		_ = c.problem(http.StatusNotFound, "not-found", "no such object, or you may not see it", nil)
	default:
		return false
	}
	return true
}

// ---------------------------------------------------------------- domains

func (a *API) listDomainVersions(c *call) error {
	id, err := a.domainID(c)
	if err != nil {
		return err
	}
	before, limit, err := pageQuery(c)
	if err != nil {
		return err
	}
	page, err := a.d.Engine.ListDomainVersions(c.ctx(), c.who(), id, before, limit)
	if err != nil {
		return err
	}
	c.setETag(page.Current)
	return c.reply(http.StatusOK, toPageJSON(page.Page, page.Changed))
}

func (a *API) getDomainVersion(c *call) error {
	id, err := a.domainID(c)
	if err != nil {
		return err
	}
	n, err := versionNumber(c)
	if err != nil {
		return err
	}
	against, err := againstQuery(c)
	if err != nil {
		return err
	}
	d, err := a.d.Engine.GetDomainVersion(c.ctx(), c.who(), id, n, against)
	if err != nil {
		return err
	}
	c.setETag(d.Current)
	return c.reply(http.StatusOK, versionDetailJSON{
		versionJSON: toVersionJSON(d.Version, d.Changed), Snapshot: d.Snapshot, Diff: toDiffJSON(d.Comparison),
		Restorable: d.Restore.Restorable, RestoreProblems: emptyList(d.Restore.Problems),
	})
}

func (a *API) restoreDomainVersion(c *call) error {
	id, err := a.domainID(c)
	if err != nil {
		return err
	}
	n, err := versionNumber(c)
	if err != nil {
		return err
	}
	reason, expected, err := restoreBody(c)
	if err != nil {
		return err
	}
	d, err := a.d.Engine.RestoreDomain(c.ctx(), id, n, ca.ChangeOptions{ExpectedVersion: expected, Reason: reason}, c.who())
	if err != nil {
		return err
	}
	c.setETag(d.Version)
	return c.reply(http.StatusOK, toDomainJSON(d))
}

type deletedDomainJSON struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CAID      string    `json:"ca_id"`
	CAName    *string   `json:"ca_name"`
	Version   int64     `json:"version"`
	DeletedAt time.Time `json:"deleted_at"`
	DeletedBy string    `json:"deleted_by"`
	Reason    string    `json:"reason"`
}

func (a *API) listDeletedDomains(c *call) error {
	list, err := a.d.Engine.ListDeletedDomains(c.ctx(), c.who())
	if err != nil {
		return err
	}
	out := make([]deletedDomainJSON, 0, len(list))
	for _, d := range list {
		j := deletedDomainJSON{ID: d.ID, Name: d.Name, CAID: d.CAID, Version: d.Version, DeletedAt: d.DeletedAt.UTC(), DeletedBy: d.DeletedBy, Reason: d.Reason}
		if d.CAName != "" {
			name := d.CAName
			j.CAName = &name
		}
		out = append(out, j)
	}
	return c.reply(http.StatusOK, out)
}

// --------------------------------------------------------------- settings

func (a *API) listSettingsVersions(c *call) error {
	before, limit, err := pageQuery(c)
	if err != nil {
		return err
	}
	page, err := a.d.Settings.Versions(c.ctx(), a.d.Tenant, c.who(), before, limit)
	if err != nil {
		return err
	}
	c.setETag(page.Current)
	return c.reply(http.StatusOK, toPageJSON(page.Page, page.Changed))
}

func (a *API) getSettingsVersion(c *call) error {
	n, err := versionNumber(c)
	if err != nil {
		return err
	}
	against, err := againstQuery(c)
	if err != nil {
		return err
	}
	d, err := a.d.Settings.VersionDetail(c.ctx(), a.d.Tenant, c.who(), n, against)
	if err != nil {
		return err
	}
	c.setETag(d.Current)
	return c.reply(http.StatusOK, versionDetailJSON{
		versionJSON: toVersionJSON(d.Version, d.Changed), Snapshot: d.Snapshot, Diff: toDiffJSON(d.Comparison),
		Restorable: d.Restore.Restorable, RestoreProblems: emptyList(d.Restore.Problems),
	})
}

func (a *API) restoreSettingsVersion(c *call) error {
	n, err := versionNumber(c)
	if err != nil {
		return err
	}
	reason, expected, err := restoreBody(c)
	if err != nil {
		return err
	}
	_, err = a.d.Settings.Restore(c.ctx(), a.d.Tenant, n, tenant.ChangeOptions{ExpectedVersion: expected, Reason: reason}, c.who())
	if errors.Is(err, tenant.ErrInvalid) {
		return c.problem(http.StatusUnprocessableEntity, "policy-violation", err.Error(), nil)
	}
	if err != nil {
		return err
	}
	return a.getSettings(c)
}
