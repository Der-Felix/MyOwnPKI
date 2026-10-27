package web

import (
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

func (a *app) actionSummary(c *rc, entry *pendingAction) string {
	var summary string
	switch entry.action {
	case "POST /certificates/{id}/key":
		summary = a.certificateActionSummary(c, entry, "Download private key", "")
	case "POST /certificates/{id}/revoke":
		summary = a.certificateActionSummary(c, entry, "Revoke certificate", "reason "+entry.form["reason"])
	case "POST /certificates/{id}/renew":
		policy := predecessorFromForm(func(name string) string { return entry.form[name] }, "predecessor", "predecessor_days")
		summary = a.certificateActionSummary(c, entry, "Renew certificate", predecessorText(policy))
	case "POST /certificates/{id}/revocation-plan":
		days, _ := strconv.Atoi(entry.form["days"])
		planned := entry.createdAt.Add(time.Duration(days) * 24 * time.Hour)
		summary = a.certificateActionSummary(c, entry, "Plan certificate revocation", "superseded; Revocation planned · "+planned.Format("2006-01-02"))
	case "POST /certificates/{id}/revocation-cancel":
		summary = a.certificateActionSummary(c, entry, "Cancel planned certificate revocation", "superseded; certificate otherwise unchanged")
	case "POST /certificates/{id}/export":
		detail := "format " + entry.form["format"]
		if yes(entry.form["delete"]) {
			detail += "; delete the stored key after download"
		}
		summary = a.certificateActionSummary(c, entry, "Export certificate with private key", detail)
	case "POST /authorities/new":
		parent := "no parent (new root)"
		if id := entry.form["parent"]; id != "" {
			if name, err := a.d.Engine.CAName(c.r.Context(), c.who(), id); err == nil {
				parent = "parent " + name
			} else {
				parent = "selected parent"
			}
		}
		summary = "Create CA " + entry.form["name"] + "; " + parent
	case "POST /authorities/import":
		summary = "Import offline root " + entry.form["name"]
	case "POST /authorities/{id}/certificate":
		summary = a.caActionSummary(c, entry, "Install signed CA certificate", "")
	case "POST /authorities/{id}/limits":
		summary = a.caActionSummary(c, entry, "Change CA limits", "CRL "+entry.form["crl_days"]+" days; maximum certificate validity "+entry.form["max_days"]+" days")
	case "POST /authorities/{id}/crl":
		summary = a.caActionSummary(c, entry, "Sign a new CRL", "")
	case "POST /authorities/{id}/crl-upload":
		summary = a.caActionSummary(c, entry, "Upload a new CRL", "")
	case "POST /authorities/{id}/renew":
		summary = a.caActionSummary(c, entry, "Renew CA with a new key and generation", "")
	case "POST /authorities/{id}/retire":
		summary = a.caActionSummary(c, entry, "Retire CA", "")
	case "POST /authorities/{id}/revoke":
		summary = a.caActionSummary(c, entry, "Revoke CA", "reason "+entry.form["reason"])
	case "POST /domains":
		summary = "Create domain " + entry.form["name"] + " on CA " + entry.form["ca"]
	case "POST /domains/{id}", "POST /domains/{id}/delete":
		verb := "Change domain"
		if strings.HasSuffix(entry.action, "/delete") {
			verb = "Delete domain"
		}
		if domain, err := a.d.Engine.GetDomain(c.r.Context(), c.who(), entry.path["id"]); err == nil {
			summary = verb + " " + domain.Name + " on CA " + domain.CA
		} else {
			summary = verb
		}
	case "POST /agents/enrollments/approve", "POST /agents/enrollments/deny":
		verb := "Approve enrollment"
		if strings.HasSuffix(entry.action, "/deny") {
			verb = "Refuse enrollment"
		}
		summary = verb + " for " + a.enrollmentName(c, entry.form["id"])
	case "POST /agents/tokens":
		summary = "Create join token " + orDash(entry.form["label"]) + " for " + strings.Join(strings.Fields(entry.form["names"]), ", ") + "; valid for " + entry.form["hours"] + " hours"
	case "POST /agents/install":
		summary = "Prepare guided agent installation for exact host " + entry.form["hostname"]
	case "POST /agents/tokens/delete":
		summary = "Withdraw join token " + a.joinTokenName(c, entry.form["id"])
	case "POST /agents/{id}/names":
		verb := "Add"
		if entry.form["action"] == "remove" {
			verb = "Remove"
		}
		summary = a.agentActionSummary(c, entry, verb+" allowed name", entry.form["name"])
	case "POST /agents/{id}/deployments/{name}/renew":
		policy := predecessorFromForm(func(name string) string { return entry.form[name] }, "predecessor", "predecessor_days")
		summary = a.agentActionSummary(c, entry, "Renew deployment "+entry.path["name"], predecessorText(policy))
	case "POST /agents/{id}/predecessor-policy", "POST /agents/{id}/deployments/{name}/predecessor-policy":
		detail := "inherit the parent default"
		if !yes(entry.form["inherit"]) {
			policy := predecessorFromForm(func(name string) string { return entry.form[name] }, "predecessor", "predecessor_days")
			detail = predecessorText(policy)
		}
		summary = a.agentActionSummary(c, entry, "Change predecessor default "+entry.path["name"], detail)
	case "POST /agents/{id}/{action}":
		verbs := map[string]string{"disable": "Disable agent", "enable": "Enable agent", "revoke": "Revoke agent"}
		verb := verbs[entry.path["action"]]
		if verb == "" {
			verb = "Change agent"
		}
		summary = a.agentActionSummary(c, entry, verb, "")
	case "POST /acme/accounts/approve":
		summary = "Approve ACME account " + short(entry.form["id"])
	case "POST /acme/names/decide":
		summary = "ACME name " + entry.form["name"] + ": " + entry.form["decision"]
	case "POST /acme/eab":
		summary = "Create ACME external-account-binding key " + entry.form["label"] + "; valid for " + entry.form["days"] + " days"
	case "POST /admin/users/new":
		summary = "Create user " + entry.form["username"] + "; role " + orDash(entry.form["role"]) + "; scope " + orDash(entry.form["scope"])
		if yes(entry.form["instance_admin"]) {
			summary += "; instance admin"
		}
	case "POST /admin/users/{id}/roles":
		summary = a.userActionSummary(c, entry, "Give role "+entry.form["role"]+" (scope "+orDash(entry.form["scope"])+")")
	case "POST /admin/users/{id}/roles/remove":
		summary = a.userActionSummary(c, entry, "Remove role (scope "+orDash(entry.form["scope"])+")")
	case "POST /admin/users/{id}/disable":
		summary = a.userActionSummary(c, entry, "Disable user")
	case "POST /admin/users/{id}/enable":
		summary = a.userActionSummary(c, entry, "Enable user")
	case "POST /admin/users/{id}/unlock":
		summary = a.userActionSummary(c, entry, "Unlock user")
	case "POST /admin/import":
		mode := "import"
		if yes(entry.form["dry_run"]) {
			mode = "dry run"
		}
		summary = "Legacy PKI " + mode + "; root key " + entry.form["root_key"]
	case "POST /account/password":
		summary = "Change your password"
	case "POST /account/totp":
		summary = "Set up a new authenticator"
	case "POST /account/totp/confirm":
		summary = "Confirm the new authenticator"
	case "POST /account/recovery-codes":
		summary = "Make new recovery codes"
	case "POST /account/tokens":
		summary = "Create API token " + entry.form["name"] + "; role " + entry.form["role"] + "; scope " + orDash(entry.form["scope"]) + "; valid for " + entry.form["days"] + " days"
	case "POST /account/tokens/{id}/revoke":
		name := "selected token"
		if tokens, err := a.d.Auth.ListTokens(c.r.Context(), c.token); err == nil {
			for _, token := range tokens {
				if token.ID == entry.path["id"] {
					name = token.Name
				}
			}
		}
		summary = "Revoke API token " + name
	case "POST /account/passkeys/{id}/remove":
		name := "selected passkey"
		if keys, err := a.d.Auth.ListPasskeys(c.r.Context(), c.token); err == nil {
			for _, key := range keys {
				if key.ID == entry.path["id"] {
					name = key.Name
				}
			}
		}
		summary = "Remove passkey " + name
	default:
		summary = "Confirm the protected action"
	}
	return safeActionSummary(summary)
}

func (a *app) certificateActionSummary(c *rc, entry *pendingAction, verb, detail string) string {
	info, err := a.d.Engine.Certificate(c.r.Context(), c.who(), entry.path["id"])
	if err != nil {
		return verb
	}
	summary := fmt.Sprintf("%s %s (serial %s)", verb, info.CommonName, info.Serial)
	if detail != "" {
		summary += "; " + detail
	}
	return summary
}

func (a *app) caActionSummary(c *rc, entry *pendingAction, verb, detail string) string {
	info, err := a.d.Engine.CA(c.r.Context(), c.who(), entry.path["id"])
	if err != nil {
		return verb
	}
	summary := verb + " " + info.Name
	if detail != "" {
		summary += "; " + detail
	}
	return summary
}

func (a *app) enrollmentName(c *rc, id string) string {
	if a.d.Agents != nil {
		if entries, err := a.d.Agents.ListEnrollments(c.r.Context(), c.who(), false); err == nil {
			for _, entry := range entries {
				if entry.ID == id {
					return entry.Hostname
				}
			}
		}
	}
	return "selected host"
}

func (a *app) joinTokenName(c *rc, id string) string {
	if a.d.Agents != nil {
		if tokens, err := a.d.Agents.ListJoinTokens(c.r.Context(), c.who()); err == nil {
			for _, token := range tokens {
				if token.ID == id {
					return orDash(token.Label) + " for " + strings.Join(token.Patterns, ", ")
				}
			}
		}
	}
	return "selected token"
}

func (a *app) agentActionSummary(c *rc, entry *pendingAction, verb, detail string) string {
	host := "selected agent"
	if a.d.Agents != nil {
		if agent, err := a.d.Agents.GetAgent(c.r.Context(), c.who(), entry.path["id"]); err == nil {
			host = agent.Hostname
		}
	}
	summary := verb + " on " + host
	if detail != "" {
		summary += ": " + detail
	}
	return summary
}

func (a *app) userActionSummary(c *rc, entry *pendingAction, verb string) string {
	if user, err := a.d.Auth.UserByID(c.r.Context(), c.who(), entry.path["id"]); err == nil {
		return verb + " for " + user.Username
	}
	return verb
}

func safeActionSummary(summary string) string {
	summary = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, summary)
	if utf8.RuneCountInString(summary) > 600 {
		runes := []rune(summary)
		summary = string(runes[:600]) + "…"
	}
	return summary
}
