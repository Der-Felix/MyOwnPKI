package web

import (
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/settingsver"
	"github.com/Der-Felix/MyOwnPKI/internal/tenant"
	"github.com/Der-Felix/MyOwnPKI/internal/web/pages/admin"
	"github.com/Der-Felix/MyOwnPKI/internal/web/view"
)

// History of the domains and of the tenant settings (PHASE3 section 16, step
// 64): a table of the versions, one page per version with the diff and the
// restore form, the list of deleted domains. The engines decide who may read
// (the tenant-wide audit right) and who may restore (what the same change
// needs); the pages only offer the tab and the links to those who may read.
// Names, reasons and values come from the database: they are only ever shown
// through templ's escaping.

// historyTarget is what a history page needs to know about its object.
type historyTarget struct {
	title   string // the page title: the domain name, "Tenant settings"
	section string // navigation key of the object's pages
	// crumbs lead to the object (the list pages); the version page adds the
	// object itself and its history.
	crumbs []view.Crumb
	base   string // the object's own page: "/domains/{id}", "/admin/settings"
	exists bool   // the object has a page (a deleted domain has none)
	labels map[string]string
	// caNames shows a CA by name instead of by ID in a domain's diff.
	caNames map[string]string
	// secondFactor is the sentence about the confirmation a restore needs.
	secondFactor string
}

func (t historyTarget) history() string { return t.base + "/history" }

// historyTabs is the tab row of the object's pages.
func historyTabs(base string, onHistory bool) []view.Tab {
	return []view.Tab{{Label: "Settings", Href: base, Active: !onHistory}, {Label: "History", Href: base + "/history", Active: onHistory}}
}

// canReadHistory reports whether to offer the History tab and its links: the
// audit right, tenant-wide. The engines check it again.
func (c *rc) canReadHistory() bool { return c.may(authz.ReadAudit, "") }

// fieldLabels maps the keys of a snapshot to the labels an admin reads.
func fieldLabels(s settingsver.Snapshot) map[string]string {
	out := map[string]string{}
	for _, f := range s.Fields() {
		out[f.Key] = f.Label
	}
	return out
}

func (t historyTarget) labelOf(key string) string {
	if l, ok := t.labels[key]; ok {
		return l
	}
	return key
}

// versionNumber reads {version}: a positive number.
func versionNumber(c *rc) (int64, bool) {
	n, err := strconv.ParseInt(c.r.PathValue("version"), 10, 64)
	return n, err == nil && n >= 1
}

// pageCursor reads the paging cursor ?before=.
func pageCursor(c *rc) int64 {
	n, err := strconv.ParseInt(c.r.URL.Query().Get("before"), 10, 64)
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// historyFail answers an error of a history read.
func (c *rc) historyFail(err error, history string) {
	switch {
	case errors.Is(err, settingsver.ErrNotFound):
		c.fail(ca.ErrNotFound)
	case errors.Is(err, settingsver.ErrUnknownSchema), errors.Is(err, settingsver.ErrCorrupt):
		c.notice(http.StatusConflict, "Version cannot be read", view.Message{Kind: view.MessageError,
			Text: "This version was stored by a release this server does not know, or its data is damaged. It can't be shown or restored; the other versions are not affected.",
			Href: history, LinkText: "Back to the history"})
	default:
		c.fail(err)
	}
}

func changeText(change string) string {
	switch change {
	case settingsver.ChangeCreate:
		return "Created"
	case settingsver.ChangeUpdate:
		return "Changed"
	case settingsver.ChangeDelete:
		return "Deleted"
	case settingsver.ChangeRestore:
		return "Restored"
	case settingsver.ChangeBaseline:
		return "State before the history began"
	}
	return change
}

// actorText says who made a change: the name, and what kind of actor it is.
func actorCell(v settingsver.Version) admin.Cell {
	name := v.Actor.Name
	if name == "" {
		name = "–"
	}
	return admin.Cell{Text: name, Rel: strings.ReplaceAll(v.Actor.Type, "_", " ")}
}

// versionList is one page of a history, whichever object it is of.
type versionList struct {
	versions []settingsver.Version
	changed  [][]string // per version: the keys it changed, nil if unreadable
	current  int64
	next     int64
}

func (a *app) historyPage(c *rc, t historyTarget, l versionList) {
	now := c.a.now()
	d := admin.TableData{
		Messages: c.messages(),
		Empty:    "No changes recorded yet. The first change is kept here together with the state before it.",
		Columns: []admin.Column{{Label: "Version", Num: true}, {Label: "When"}, {Label: "Who"}, {Label: "Change"}, {Label: "Reason"},
			{Label: "Restored from"}, {Label: "Changed settings"}},
	}
	if t.exists {
		d.Tabs = historyTabs(t.base, true)
	}
	for i, v := range l.versions {
		number := strconv.FormatInt(v.Number, 10)
		num := admin.Cell{Text: number, Href: t.history() + "/" + number, Num: true, NoWrap: true}
		if t.exists && v.Number == l.current {
			num.Rel = "current"
		}
		restored := admin.Cell{Text: "–"}
		if v.RestoredFrom > 0 {
			from := strconv.FormatInt(v.RestoredFrom, 10)
			restored = admin.Cell{Text: "version " + from, Href: t.history() + "/" + from, NoWrap: true}
		}
		d.Rows = append(d.Rows, []admin.Cell{num,
			{Text: dateTime(v.CreatedAt), Rel: view.Relative(now, v.CreatedAt), NoWrap: true, Title: v.CreatedAt.UTC().Format("2006-01-02 15:04:05 UTC")},
			actorCell(v), {Text: changeText(v.Change)}, {Text: orDash(v.Reason), Break: true}, restored,
			{Text: t.changedText(v, l.changed[i]), Break: true}})
	}
	if l.next > 0 {
		d.More, d.MoreLabel = t.history()+"?before="+strconv.FormatInt(l.next, 10), "Older versions"
	}
	p := c.page(t.title, t.section, t.crumbs...)
	p.Description = "Every change of these settings: who made it and when, and the settings it changed. A version can be restored as a new version."
	render(c.w, c.r, a.log, http.StatusOK, admin.TablePage(p, d))
}

// changedText lists the settings a version changed, by label.
func (t historyTarget) changedText(v settingsver.Version, keys []string) string {
	switch {
	case v.Change == settingsver.ChangeCreate || v.Change == settingsver.ChangeBaseline:
		return "all settings"
	case keys == nil:
		return "can't be told: the version can't be read"
	}
	return orDash(t.labelList(keys))
}

func (t historyTarget) labelList(keys []string) string {
	labels := make([]string, 0, len(keys))
	for _, k := range keys {
		labels = append(labels, t.labelOf(k))
	}
	return strings.Join(labels, ", ")
}

// versionData is one version, whichever object it is of.
type versionData struct {
	version    settingsver.Version
	comparison settingsver.Comparison
	current    int64
	restorable bool
	problems   []string
	// changes is what restoring would change now (the diff of the current state
	// to this version), the table's own when it compares with the current state.
	changes []settingsver.FieldChange
}

// diffAgainst reads the query ?against=: "previous" (the default) or "current".
func diffAgainst(c *rc) (int64, string) {
	if c.r.URL.Query().Get("against") == "current" {
		return settingsver.AgainstCurrent, "current"
	}
	return settingsver.AgainstPrevious, "previous"
}

// diffRows turns changes into the rows of the table. A list (challenge types,
// IP ranges) is a set: every value on its own line, marked "added" or
// "removed" where it differs.
func (t historyTarget) diffRows(changes []settingsver.FieldChange) []admin.DiffRow {
	show := func(key, v string) string {
		if key == "ca_id" {
			if name, ok := t.caNames[v]; ok {
				return name
			}
		}
		return v
	}
	rows := make([]admin.DiffRow, 0, len(changes))
	for _, ch := range changes {
		row := admin.DiffRow{Label: ch.Label}
		list := ch.Key == "challenge_types" || ch.Key == "ip_ranges" || len(ch.Before) > 1 || len(ch.After) > 1
		for _, v := range ch.Before {
			dv := admin.DiffValue{Text: show(ch.Key, v)}
			if list && !slices.Contains(ch.After, v) {
				dv.Mark = "removed"
			}
			row.Before = append(row.Before, dv)
		}
		for _, v := range ch.After {
			dv := admin.DiffValue{Text: show(ch.Key, v)}
			if list && !slices.Contains(ch.Before, v) {
				dv.Mark = "added"
			}
			row.After = append(row.After, dv)
		}
		rows = append(rows, row)
	}
	return rows
}

func (a *app) versionPage(c *rc, t historyTarget, d versionData, against string) {
	now := c.a.now()
	v := d.version
	number := strconv.FormatInt(v.Number, 10)
	who := orDash(v.Actor.Name)
	if v.Actor.Type != "" {
		who += " (" + strings.ReplaceAll(v.Actor.Type, "_", " ") + ")"
	}
	kv := []view.KV{
		{Key: "Version", Value: number}, {Key: "Change", Value: changeText(v.Change)}, {Key: "Who", Value: who},
		{Key: "When", Value: dateTime(v.CreatedAt) + " – " + view.Relative(now, v.CreatedAt)},
		{Key: "Reason", Value: orDash(v.Reason)},
	}
	if v.RestoredFrom > 0 {
		from := strconv.FormatInt(v.RestoredFrom, 10)
		kv = append(kv, view.KV{Key: "Restored from", Value: "version " + from, Href: t.history() + "/" + from})
	} else {
		kv = append(kv, view.KV{Key: "Restored from", Value: "–"})
	}
	if t.exists && v.Number == d.current {
		kv = append(kv, view.KV{Key: "State", Value: "This is the current version."})
	}

	// The diff, with the switch between the two things it can be compared with.
	cmp := d.comparison
	diff := admin.DiffTable{Caption: "Settings that differ", AfterLabel: "Version " + number}
	title := "What this version changed"
	if against == "current" {
		title = "What restoring this version would change now"
		diff.BeforeLabel = "Now (version " + strconv.FormatInt(cmp.From, 10) + ")"
		if cmp.From == 0 {
			diff.BeforeLabel = "Now (deleted)"
		}
		diff.Empty = "This version is the current state: there is nothing to change."
	} else {
		diff.BeforeLabel = "Before (version " + strconv.FormatInt(cmp.From, 10) + ")"
		if cmp.From == 0 {
			diff.BeforeLabel = "Before (nothing)"
		}
		diff.Empty = "This version changed nothing compared with the version before it."
	}
	diff.Rows = t.diffRows(cmp.Changes)
	switchTabs := []view.Tab{
		{Label: "The previous version", Href: t.history() + "/" + number, Active: against == "previous"},
		{Label: "The current state", Href: t.history() + "/" + number + "?against=current", Active: against == "current"},
	}
	sections := []admin.Section{
		{KV: kv},
		{Title: title, Text: []string{"Compare version " + number + " with:"}, Tabs: switchTabs, Diff: &diff},
	}

	restore := admin.Section{Title: "Restore this version"}
	switch {
	case d.restorable:
		if len(d.changes) == 0 {
			restore.Text = []string{"Restoring would change nothing."}
		} else {
			restore.Text = []string{"Restoring would change: " + t.labelList(settingsver.Keys(d.changes)) + "."}
		}
		restore.Text = append(restore.Text, "The restore is saved as a new version; version "+number+" stays as it is. "+t.secondFactor)
		restore.Forms = []admin.FormData{c.form(admin.FormData{
			Action: t.history() + "/" + number + "/restore", Submit: "Restore this version", Cancel: t.history(),
			Fields: []admin.Field{
				reasonField(),
				baseVersionField(d.current),
			},
		})}
	default:
		restore.Text = []string{"This version can't be restored now:"}
		for _, p := range d.problems {
			restore.Text = append(restore.Text, "– "+p)
		}
	}
	sections = append(sections, restore)

	pageTitle := "Version " + number
	crumbs := slices.Clone(t.crumbs)
	if t.exists {
		crumbs = append(crumbs, view.Crumb{Label: t.title, Href: t.base})
	} else {
		crumbs = append(crumbs, view.Crumb{Label: t.title})
	}
	crumbs = append(crumbs, view.Crumb{Label: "History", Href: t.history()})
	data := admin.DetailData{Messages: c.messages(), Sections: sections}
	if t.exists {
		data.Tabs = historyTabs(t.base, true)
	}
	render(c.w, c.r, a.log, http.StatusOK, admin.DetailPage(c.page(pageTitle, t.section, crumbs...), data))
}

// ---------------------------------------------------------------- domains

func (a *app) caNames(c *rc) map[string]string {
	names := map[string]string{}
	if cas, err := a.d.Engine.CAs(c.r.Context(), c.who()); err == nil {
		for _, info := range cas {
			names[info.ID] = info.Name
		}
	}
	return names
}

// domainTarget describes the domain of {id}: its page when it exists, the
// remains of a deleted one otherwise.
func (a *app) domainTarget(c *rc, id string) historyTarget {
	t := historyTarget{section: "domains", base: "/domains/" + url.PathEscape(id), crumbs: domainCrumbs(),
		labels: fieldLabels(settingsver.DomainSnapshot{}), caNames: a.caNames(c),
		secondFactor: "It asks for a fresh second factor, like any change of a domain."}
	if dm, err := a.d.Engine.GetDomain(c.r.Context(), c.who(), id); err == nil {
		t.title, t.exists = dm.Name, true
		return t
	}
	t.title = "Deleted domain"
	t.crumbs = append(t.crumbs, view.Crumb{Label: "Deleted domains", Href: "/domains/deleted"})
	if list, err := a.d.Engine.ListDeletedDomains(c.r.Context(), c.who()); err == nil {
		for _, dd := range list {
			if dd.ID == id {
				t.title = dd.Name + " (deleted)"
			}
		}
	}
	return t
}

func (a *app) domainHistory(c *rc) {
	id := c.r.PathValue("id")
	page, err := a.d.Engine.ListDomainVersions(c.r.Context(), c.who(), id, pageCursor(c), 0)
	if err != nil {
		c.historyFail(err, "/domains")
		return
	}
	a.historyPage(c, a.domainTarget(c, id), versionList{versions: page.Versions, changed: page.Changed, current: page.Current, next: page.Next})
}

func (a *app) domainVersion(c *rc) {
	id := c.r.PathValue("id")
	number, ok := versionNumber(c)
	if !ok {
		c.fail(ca.ErrNotFound)
		return
	}
	against, name := diffAgainst(c)
	detail, err := a.d.Engine.GetDomainVersion(c.r.Context(), c.who(), id, number, against)
	if err != nil {
		c.historyFail(err, "/domains/"+url.PathEscape(id)+"/history")
		return
	}
	d := versionData{version: detail.Version, comparison: detail.Comparison, current: detail.Current,
		restorable: detail.Restore.Restorable, problems: detail.Restore.Problems, changes: detail.Comparison.Changes}
	if against != settingsver.AgainstCurrent {
		now, err := a.d.Engine.GetDomainVersion(c.r.Context(), c.who(), id, number, settingsver.AgainstCurrent)
		if err != nil {
			c.historyFail(err, "/domains/"+url.PathEscape(id)+"/history")
			return
		}
		d.changes = now.Comparison.Changes
	}
	a.versionPage(c, a.domainTarget(c, id), d, name)
}

func (a *app) domainRestore(c *rc) {
	id := c.r.PathValue("id")
	base := "/domains/" + url.PathEscape(id)
	number, ok := versionNumber(c)
	if !ok {
		c.fail(ca.ErrNotFound)
		return
	}
	back := base + "/history/" + strconv.FormatInt(number, 10)
	var opts ca.ChangeOptions
	var err error
	if opts.ExpectedVersion, err = baseVersion(c); err != nil {
		c.refusedAt(err, back, base+"/history")
		return
	}
	opts.Reason = reasonOf(c)
	d, err := a.d.Engine.RestoreDomain(c.r.Context(), id, number, opts, c.who())
	if err != nil {
		c.refusedAt(err, back, base+"/history")
		return
	}
	c.done(base+"/history", "Domain restored from version "+strconv.FormatInt(number, 10)+" as version "+strconv.FormatInt(d.Version, 10)+".")
}

// domainsDeleted lists the deleted domains; each can be restored from the
// page of its last version.
func (a *app) domainsDeleted(c *rc) {
	list, err := a.d.Engine.ListDeletedDomains(c.r.Context(), c.who())
	if err != nil {
		c.fail(err)
		return
	}
	now := c.a.now()
	d := admin.TableData{Messages: c.messages(),
		Empty:   "No deleted domains. A domain that is deleted is listed here and can be restored with its old settings.",
		Columns: []admin.Column{{Label: "Domain"}, {Label: "CA"}, {Label: "Deleted"}, {Label: "By"}, {Label: "Reason"}, {Label: "Version", Num: true}, {Label: "Restore"}}}
	for _, dd := range list {
		number := strconv.FormatInt(dd.Version, 10)
		history := "/domains/" + url.PathEscape(dd.ID) + "/history"
		caName := dd.CAName
		if caName == "" {
			caName = "no longer exists"
		}
		d.Rows = append(d.Rows, []admin.Cell{{Text: dd.Name, Href: history}, {Text: caName},
			{Text: dateTime(dd.DeletedAt), Rel: view.Relative(now, dd.DeletedAt), NoWrap: true}, {Text: orDash(dd.DeletedBy)},
			{Text: orDash(dd.Reason), Break: true}, {Text: number, Num: true}, {Text: "Restore", Href: history + "/" + number, NoWrap: true}})
	}
	p := c.page("Deleted domains", "domains", domainCrumbs()...)
	p.Description = "Domains that were deleted. Restoring one brings it back under its old ID with the settings it had; certificates already issued were never touched."
	render(c.w, c.r, a.log, http.StatusOK, admin.TablePage(p, d))
}

// ---------------------------------------------------------------- tenant settings

func (a *app) settingsTarget(c *rc) historyTarget {
	return historyTarget{title: "Tenant settings", section: "settings", crumbs: adminCrumbs(), base: "/admin/settings", exists: true,
		labels:       fieldLabels(settingsver.TenantSnapshot{}),
		secondFactor: "Changing the agent enrollment mode asks for a fresh second factor; every other restore needs none."}
}

func (a *app) settingsHistory(c *rc) {
	if a.d.Settings == nil {
		c.fail(ca.ErrNotFound)
		return
	}
	page, err := a.d.Settings.Versions(c.r.Context(), a.d.Tenant, c.who(), pageCursor(c), 0)
	if err != nil {
		c.historyFail(err, "/admin/settings")
		return
	}
	a.historyPage(c, a.settingsTarget(c), versionList{versions: page.Versions, changed: page.Changed, current: page.Current, next: page.Next})
}

func (a *app) settingsVersion(c *rc) {
	if a.d.Settings == nil {
		c.fail(ca.ErrNotFound)
		return
	}
	number, ok := versionNumber(c)
	if !ok {
		c.fail(ca.ErrNotFound)
		return
	}
	against, name := diffAgainst(c)
	detail, err := a.d.Settings.VersionDetail(c.r.Context(), a.d.Tenant, c.who(), number, against)
	if err != nil {
		c.historyFail(err, "/admin/settings/history")
		return
	}
	d := versionData{version: detail.Version, comparison: detail.Comparison, current: detail.Current,
		restorable: detail.Restore.Restorable, problems: detail.Restore.Problems, changes: detail.Comparison.Changes}
	if against != settingsver.AgainstCurrent {
		now, err := a.d.Settings.VersionDetail(c.r.Context(), a.d.Tenant, c.who(), number, settingsver.AgainstCurrent)
		if err != nil {
			c.historyFail(err, "/admin/settings/history")
			return
		}
		d.changes = now.Comparison.Changes
	}
	a.versionPage(c, a.settingsTarget(c), d, name)
}

func (a *app) settingsRestore(c *rc) {
	if a.d.Settings == nil {
		c.fail(ca.ErrNotFound)
		return
	}
	number, ok := versionNumber(c)
	if !ok {
		c.fail(ca.ErrNotFound)
		return
	}
	back := "/admin/settings/history/" + strconv.FormatInt(number, 10)
	var opts tenant.ChangeOptions
	var err error
	if opts.ExpectedVersion, err = baseVersion(c); err != nil {
		c.refusedAt(err, back, "/admin/settings/history")
		return
	}
	opts.Reason = reasonOf(c)
	n, err := a.d.Settings.Restore(c.r.Context(), a.d.Tenant, number, opts, c.who())
	if err != nil {
		c.refusedAt(err, back, "/admin/settings/history")
		return
	}
	c.done("/admin/settings/history", "Settings restored from version "+strconv.FormatInt(number, 10)+" as version "+strconv.FormatInt(n, 10)+".")
}
