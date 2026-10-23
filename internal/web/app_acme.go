package web

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/Der-Felix/MyOwnPKI/internal/acme"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/web/pages/admin"
	"github.com/Der-Felix/MyOwnPKI/internal/web/view"
)

// ACME approvals (PHASE2 step 13, owner Q2): the account queue, the queue
// of new names, EAB keys, and the orders. The ACME server decides; these
// pages only show and ask.

// acmeOff explains why the ACME pages are empty.
func (a *app) acmeOff(c *rc, title, key string) bool {
	if a.d.ACME != nil {
		return false
	}
	render(c.w, c.r, a.log, http.StatusOK, admin.DetailPage(c.page(title, key), admin.DetailData{Sections: []admin.Section{{Text: []string{
		"The ACME server is off. It starts when acme.base_url is set in the configuration (OPERATIONS.md, chapter ACME).",
	}}}}))
	return true
}

// acmeErr maps the ACME server's not-found to the UI's.
func acmeErr(err error) error {
	if errors.Is(err, acme.ErrNotFound) {
		return ca.ErrNotFound
	}
	return err
}

func short(s string) string {
	if len(s) > 16 {
		return s[:16] + "…"
	}
	return s
}

func (a *app) acmeAccounts(c *rc) {
	if a.acmeOff(c, "ACME accounts", "acme-accounts") {
		return
	}
	list, err := a.d.ACME.Accounts(c.r.Context(), c.who())
	if err != nil {
		c.fail(acmeErr(err))
		return
	}
	cols := []admin.Column{{Label: "Account"}, {Label: "Contact"}, {Label: "Status"}, {Label: "Created"}, {Label: "From"}}
	waiting := &admin.TableData{Title: "Waiting for approval", Columns: cols, Empty: "No account waits."}
	all := &admin.TableData{Title: "Approved and closed accounts", Columns: cols, Empty: "No accounts yet."}
	var opts []admin.Option
	for _, acc := range list {
		row := []admin.Cell{{Text: acc.ID, Href: "/acme/accounts/" + acc.ID, Mono: true}, {Text: orDash(strings.Join(acc.Contacts, ", ")), Break: true},
			accountStatus(acc), {Text: acc.CreatedAt, NoWrap: true}, {Text: acc.CreatedIP, Mono: true}}
		if acc.Status == "valid" && !acc.Approved {
			waiting.Rows = append(waiting.Rows, row)
			opts = append(opts, admin.Option{Value: acc.ID, Label: acc.ID + " – " + orDash(strings.Join(acc.Contacts, ", "))})
			continue
		}
		all.Rows = append(all.Rows, row)
	}
	sections := []admin.Section{{Text: []string{
		"Under the approval level \"approved accounts\" a new account can't order until an admin approves it – or it brings an EAB key.",
		"Approve only accounts you expect: compare the contact and the address with the machine that registered.",
	}}, {Table: waiting}}
	if len(opts) > 0 && c.may(authz.ManageCA, "") {
		sections = append(sections, admin.Section{Forms: []admin.FormData{c.form(admin.FormData{
			Title: "Approve", Action: "/acme/accounts/approve", Submit: "Approve account",
			Fields: []admin.Field{{ID: "id", Label: "Account", Type: "select", Options: opts}},
		})}})
	}
	sections = append(sections, admin.Section{Table: all})
	p := c.page("ACME accounts", "acme-accounts")
	p.Description = "Clients registered at the ACME server. Approval needs a fresh second factor."
	render(c.w, c.r, a.log, http.StatusOK, admin.DetailPage(p, admin.DetailData{Messages: c.messages(), Sections: sections}))
}

func accountStatus(acc acme.AccountInfo) admin.Cell {
	switch {
	case acc.Status != "valid":
		return admin.Cell{Text: acc.Status, Status: view.StatusCrit}
	case !acc.Approved:
		return admin.Cell{Text: "waiting", Status: view.StatusWarn}
	}
	return admin.Cell{Text: "approved", Status: view.StatusOK}
}

func (a *app) acmeAccount(c *rc) {
	if a.acmeOff(c, "ACME account", "acme-accounts") {
		return
	}
	acc, err := a.d.ACME.Account(c.r.Context(), c.who(), c.r.PathValue("id"))
	if err != nil {
		c.fail(acmeErr(err))
		return
	}
	approved := "no – waiting"
	if acc.Approved {
		approved = acc.ApprovedAt + " by " + acc.ApprovedBy
	}
	sections := []admin.Section{{KV: []view.KV{
		{Key: "Account", Value: acc.ID}, {Key: "Status", Value: acc.Status}, {Key: "Approved", Value: approved},
		{Key: "Contact", Value: orDash(strings.Join(acc.Contacts, ", "))}, {Key: "Key thumbprint (RFC 7638)", Value: acc.Thumbprint},
		{Key: "EAB key", Value: orDash(acc.EABKey)}, {Key: "Created", Value: acc.CreatedAt + " from " + acc.CreatedIP},
	}}}
	if acc.Status == "valid" && !acc.Approved && c.may(authz.ManageCA, "") {
		sections = append(sections, admin.Section{Forms: []admin.FormData{c.form(admin.FormData{
			Title: "Approve", Action: "/acme/accounts/approve", Submit: "Approve account",
			Intro:  []string{"The account can then order certificates for every domain with the level \"approved accounts\"."},
			Fields: []admin.Field{{ID: "id", Type: "hidden", Value: acc.ID}},
		})}})
	}
	crumbs := []view.Crumb{{Label: "ACME accounts", Href: "/acme/accounts"}}
	render(c.w, c.r, a.log, http.StatusOK, admin.DetailPage(c.page(short(acc.ID), "acme-accounts", crumbs...), admin.DetailData{Messages: c.messages(), Sections: sections}))
}

func (a *app) acmeApprove(c *rc) {
	if a.acmeOff(c, "ACME accounts", "acme-accounts") {
		return
	}
	id := c.r.PostFormValue("id")
	if err := a.d.ACME.ApproveAccount(c.r.Context(), id, c.who()); err != nil {
		c.refused(acmeErr(err), "/acme/accounts")
		return
	}
	c.done("/acme/accounts", "Account "+short(id)+" approved.")
}

func (a *app) acmeNames(c *rc) {
	if a.acmeOff(c, "New names", "acme-names") {
		return
	}
	list, err := a.d.ACME.Names(c.r.Context(), c.who())
	if err != nil {
		c.fail(acmeErr(err))
		return
	}
	cols := []admin.Column{{Label: "Name"}, {Label: "Status"}, {Label: "Asked by"}, {Label: "Asked"}, {Label: "Decided"}}
	waiting := &admin.TableData{Title: "Waiting for a decision", Columns: cols, Empty: "No name waits."}
	decided := &admin.TableData{Title: "Decided", Columns: cols, Empty: "Nothing decided yet."}
	var opts []admin.Option
	for _, n := range list {
		st := admin.Cell{Text: n.Status, Status: view.StatusOK}
		switch n.Status {
		case "pending":
			st = admin.Cell{Text: "waiting", Status: view.StatusWarn}
		case "refused":
			st.Status = view.StatusCrit
		}
		decision := "–"
		if n.DecidedAt != "" {
			decision = n.DecidedAt + " by " + n.DecidedBy
		}
		row := []admin.Cell{{Text: n.Name, Mono: true}, st, {Text: n.RequestedBy, Mono: true}, {Text: n.RequestedAt, NoWrap: true}, {Text: decision}}
		if n.Status == "pending" {
			waiting.Rows = append(waiting.Rows, row)
			opts = append(opts, admin.Option{Value: n.Name, Label: n.Name})
			continue
		}
		decided.Rows = append(decided.Rows, row)
	}
	sections := []admin.Section{{Text: []string{
		"Under the approval level \"new names\" the first certificate for a name waits here; once approved, every later order for it passes.",
		"A client keeps asking while it waits – approve, then it continues on its next try.",
	}}, {Table: waiting}}
	if c.may(authz.ManageCA, "") {
		var forms []admin.FormData
		if len(opts) > 0 {
			forms = append(forms, c.form(admin.FormData{Title: "Decide", Action: "/acme/names/decide", Submit: "Save decision",
				Fields: []admin.Field{
					{ID: "name", Label: "Name", Type: "select", Options: opts},
					{ID: "decision", Label: "Decision", Type: "select", Options: []admin.Option{{Value: "approve", Label: "approve"}, {Value: "refuse", Label: "refuse"}}},
				}}))
		}
		forms = append(forms, c.form(admin.FormData{Title: "Approve in advance", Action: "/acme/names/decide", Submit: "Approve name",
			Intro: []string{"For a name nobody asked for yet, e.g. before a new host gets its first certificate."},
			Fields: []admin.Field{
				{ID: "name", Label: "Name", Required: true, Hint: "dns:nas.homelab.lan or ip:192.0.2.10"},
				{ID: "decision", Type: "hidden", Value: "approve"},
			}}))
		sections = append(sections, admin.Section{Forms: forms})
	}
	sections = append(sections, admin.Section{Table: decided})
	p := c.page("New names", "acme-names")
	p.Description = "Names waiting for their first certificate under the approval level \"new names\"."
	render(c.w, c.r, a.log, http.StatusOK, admin.DetailPage(p, admin.DetailData{Messages: c.messages(), Sections: sections}))
}

func (a *app) acmeDecide(c *rc) {
	if a.acmeOff(c, "New names", "acme-names") {
		return
	}
	name := strings.TrimSpace(c.r.PostFormValue("name"))
	approve := c.r.PostFormValue("decision") == "approve"
	if err := a.d.ACME.DecideName(c.r.Context(), name, approve, c.who()); err != nil {
		c.refused(acmeErr(err), "/acme/names")
		return
	}
	verb := "refused"
	if approve {
		verb = "approved"
	}
	c.done("/acme/names", name+" "+verb+".")
}

func (a *app) acmeEAB(c *rc) {
	if a.acmeOff(c, "EAB keys", "acme-eab") {
		return
	}
	list, err := a.d.ACME.EABKeys(c.r.Context(), c.who())
	if err != nil {
		c.fail(acmeErr(err))
		return
	}
	t := &admin.TableData{Title: "Keys", Empty: "No EAB keys yet.",
		Columns: []admin.Column{{Label: "Key ID"}, {Label: "Label"}, {Label: "Status"}, {Label: "Expires"}, {Label: "Created by"}}}
	now := a.now().Format("2006-01-02T15:04:05Z")
	for _, k := range list {
		st := admin.Cell{Text: "unused", Status: view.StatusOK}
		switch {
		case k.UsedAt != "":
			st = admin.Cell{Text: "used by " + k.UsedBy, Status: view.StatusNeutral}
		case k.ExpiresAt <= now:
			st = admin.Cell{Text: "expired", Status: view.StatusNeutral}
		}
		t.Rows = append(t.Rows, []admin.Cell{{Text: k.ID, Mono: true}, {Text: k.Label}, st, {Text: k.ExpiresAt, NoWrap: true}, {Text: k.CreatedBy}})
	}
	sections := []admin.Section{{Text: []string{
		"An EAB key (external account binding, RFC 8555 §7.3.4) lets one ACME account skip the approval queue: the client signs its registration with the key.",
		"Each key binds one account and expires. Its secret is shown once – hand it over like a password.",
	}}}
	if c.may(authz.ManageCA, "") {
		sections = append(sections, admin.Section{Forms: []admin.FormData{c.form(admin.FormData{
			Title: "New key", Action: "/acme/eab", Submit: "Create key",
			Fields: []admin.Field{
				{ID: "label", Label: "Label", Required: true, Hint: "What it is for, e.g. the host that will use it."},
				{ID: "days", Label: "Valid for days", Type: "number", Value: strconv.Itoa(acme.DefaultEABDays), Hint: "1 to 90; an unused key expires."},
			},
		})}})
	}
	sections = append(sections, admin.Section{Table: t})
	p := c.page("EAB keys", "acme-eab")
	p.Description = "Keys that bind a new ACME account without waiting for approval."
	render(c.w, c.r, a.log, http.StatusOK, admin.DetailPage(p, admin.DetailData{Messages: c.messages(), Sections: sections}))
}

func (a *app) acmeEABCreate(c *rc) {
	if a.acmeOff(c, "EAB keys", "acme-eab") {
		return
	}
	days, err := strconv.Atoi(strings.TrimSpace(c.r.PostFormValue("days")))
	if err != nil {
		days = 0 // refused with the range
	}
	k, err := a.d.ACME.CreateEABKey(c.r.Context(), c.r.PostFormValue("label"), days, c.who())
	if err != nil {
		c.refused(acmeErr(err), "/acme/eab")
		return
	}
	dir := a.d.ACMEDirectory
	if dir == "" {
		dir = "https://pki.example/acme/directory"
	}
	crumbs := []view.Crumb{{Label: "EAB keys", Href: "/acme/eab"}}
	c.once(c.page("New EAB key", "acme-eab", crumbs...), admin.DetailData{Sections: []admin.Section{
		{Text: []string{"Copy the key now – it is not shown again and can't be recovered. Unused, it expires " + k.ExpiresAt + "."},
			KV: []view.KV{{Key: "Key ID (kid)", Value: k.KID}, {Key: "MAC key (base64url)", Value: k.HMAC}}},
		{Title: "Use it", Pre: []admin.Pre{
			{Title: "lego", Text: "lego run --server " + dir + " --eab --eab.kid " + k.KID + " --eab.hmac " + k.HMAC + " --email admin@example.org --accept-tos --domains host.example --http"},
			{Title: "certbot", Text: "certbot certonly --server " + dir + " --eab-kid " + k.KID + " --eab-hmac-key " + k.HMAC + " -d host.example --standalone"},
		}},
	}})
}

func (a *app) acmeOrders(c *rc) {
	if a.acmeOff(c, "ACME orders", "acme-orders") {
		return
	}
	list, err := a.d.ACME.Orders(c.r.Context(), c.who())
	if err != nil {
		c.fail(acmeErr(err))
		return
	}
	d := admin.TableData{Messages: c.messages(), Empty: "No orders yet.",
		Columns: []admin.Column{{Label: "Order"}, {Label: "Names"}, {Label: "Status"}, {Label: "Account"}, {Label: "Created"}, {Label: "Result"}}}
	for _, o := range list {
		st := admin.Cell{Text: o.Status, Status: view.StatusNeutral}
		switch o.Status {
		case "valid":
			st.Status = view.StatusOK
		case "invalid":
			st.Status = view.StatusCrit
		case "processing":
			st.Status = view.StatusInfo
		}
		result := admin.Cell{Text: orDash(o.Error), Break: true}
		if o.CertificateID != "" {
			result = admin.Cell{Text: "certificate", Href: "/certificates/" + o.CertificateID}
		}
		d.Rows = append(d.Rows, []admin.Cell{{Text: o.ID, Mono: true}, {Text: strings.Join(o.Identifiers, ", ")}, st,
			{Text: o.AccountID, Href: "/acme/accounts/" + o.AccountID, Mono: true}, {Text: o.CreatedAt, NoWrap: true}, result})
	}
	p := c.page("ACME orders", "acme-orders")
	p.Description = "The newest 200 orders: what clients asked for and what came of it."
	render(c.w, c.r, a.log, http.StatusOK, admin.TablePage(p, d))
}
