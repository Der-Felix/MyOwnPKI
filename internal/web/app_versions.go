package web

import (
	"strconv"
	"strings"

	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/settingsver"
	"github.com/Der-Felix/MyOwnPKI/internal/web/pages/admin"
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

// conflictText says who changed the object while the form was open.
func conflictText(ce *settingsver.ConflictError) string {
	if ce.Latest.Number == 0 {
		return "This page is out of date – nothing was saved. The page now shows the current state."
	}
	who := ce.Latest.Actor.Name
	if who == "" {
		who = "somebody else"
	}
	return "Changed by " + who + " at " + ce.Latest.CreatedAt.UTC().Format("2006-01-02 15:04") +
		" UTC while you were editing – your change was not saved. The page now shows the current state."
}
