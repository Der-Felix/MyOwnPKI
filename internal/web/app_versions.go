package web

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/settingsver"
	"github.com/Der-Felix/MyOwnPKI/internal/web/pages/admin"
	"github.com/Der-Felix/MyOwnPKI/internal/web/view"
)

// Lost-update protection of the forms that change a versioned object (a
// domain, the tenant settings; PHASE3 section 16, step 62). The edit form
// carries the version it was built from in the hidden field base_version; the
// writer refuses the change when somebody saved a newer version in the
// meantime. A post without the field (a form from before the upgrade) is not
// checked: the last writer wins, as before.

// baseVersionField is the hidden field of the version a form shows.
func baseVersionField(version int64) admin.Field {
	return admin.Field{ID: "base_version", Type: "hidden", Value: strconv.FormatInt(version, 10)}
}

// reasonField is the optional reason of a change, kept in the history.
func reasonField() admin.Field {
	return admin.Field{ID: "reason", Label: "Reason (optional)",
		Hint: "At most " + strconv.Itoa(settingsver.MaxReason) + " characters. Other admins read it in the history; it is not written to the audit log."}
}

// reasonOf reads the reason of a post.
func reasonOf(c *rc) string { return strings.TrimSpace(c.r.PostFormValue("reason")) }

// baseVersion reads base_version of a post: nil when the field is absent, an
// error for anything but a plain non-negative number (a changed form).
func baseVersion(c *rc) (*int64, error) {
	raw := strings.TrimSpace(c.r.PostFormValue("base_version"))
	if raw == "" {
		return nil, nil
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n < 0 {
		return nil, &ca.DeniedError{Reasons: []string{"This form is out of date – open the page again and repeat the change."}}
	}
	return &n, nil
}

// conflictText says that somebody changed the object after the page was
// opened, and when. The name of that person is only given to a reader who may
// read the history (the tenant-wide audit right): it is personal data.
func conflictText(ce *settingsver.ConflictError, mayName bool) string {
	if ce.Latest.Number == 0 {
		return "This object was changed after you opened this page. Reload the history and look again. Nothing was saved."
	}
	who := "somebody else"
	if name := ce.Latest.Actor.Name; mayName && name != "" {
		who = name
	}
	return "This object was changed by " + who + " at " + view.DateTime(ce.Latest.CreatedAt) +
		" after you opened this page. Reload the history and look again. Nothing was saved."
}

// conflictPage answers a change or restore that was based on an older version:
// a page of its own (409) with who changed the object and when, and a link
// back. Nothing was written. history is the object's history page; "" = back
// plus /history. Whoever may not read the history gets a link to the object.
func (c *rc) conflictPage(ce *settingsver.ConflictError, back, history string) {
	href, link := history, "Back to the history"
	if href == "" {
		href = back + "/history"
	}
	if !c.canReadHistory() {
		href, link = back, "Back to the page"
	}
	c.notice(http.StatusConflict, "Changed meanwhile", view.Message{Kind: view.MessageError, Text: conflictText(ce, c.canReadHistory()), Href: href, LinkText: link})
}
