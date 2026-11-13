package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// The UI inventory (docs/PHASE3.md step 50): every page of the real UI, shot
// light and dark against the demo instance with the inventory seeds, into an
// untracked directory. The images are read by a person who writes
// docs/UI-GAPS.md; they are never committed (every image would stay in the
// Git history).

// inventoryPage is one page of the UI. route is the pattern registerApp
// (internal/web/app.go) registers, without the method; path is what is
// requested, with the placeholders {cert} {pending} {ca} {domain} {agent}
// {account} {user} {enroll}.
type inventoryPage struct {
	name  string
	route string
	path  string
	kind  viewKind // anonymous, sealed or light (light is shot in both themes)
}

// inventoryPages is every GET page of registerApp, in the order of the
// navigation. A test fails when registerApp gains a route that is neither
// here nor in inventoryExcluded.
var inventoryPages = []inventoryPage{
	{"login", "/login", "/login", anonymous},
	{"unseal", "/unseal", "/unseal", sealed},
	{"dashboard-sealed", "/{$}", "/", sealed},
	{"step-up", "/step-up", "/step-up", light},

	{"dashboard", "/{$}", "/", light},
	{"alerts", "/alerts", "/alerts", light},
	{"reports", "/reports", "/reports", light},
	{"analysis", "/analysis", "/analysis", light},
	{"endpoints", "/endpoints", "/endpoints", light},

	{"certificates", "/certificates", "/certificates", light},
	{"certificates-filtered", "/certificates", "/certificates?status=expiring", light},
	{"certificate-new", "/certificates/new", "/certificates/new", light},
	{"certificate-detail", "/certificates/{id}", "/certificates/{cert}", light},
	{"certificate-extensions", "/certificates/{id}/{tab}", "/certificates/{cert}/extensions", light},
	{"certificate-chain", "/certificates/{id}/{tab}", "/certificates/{cert}/chain", light},
	{"certificate-renew", "/certificates/{id}/renew", "/certificates/{cert}/renew", light},
	{"certificate-export", "/certificates/{id}/export", "/certificates/{cert}/export", light},
	{"certificate-revoke", "/certificates/{id}/revoke", "/certificates/{cert}/revoke", light},
	{"certificate-revocation-plan", "/certificates/{id}/revocation-plan", "/certificates/{cert}/revocation-plan", light},

	{"authorities", "/authorities", "/authorities", light},
	{"authority-detail", "/authorities/{id}", "/authorities/{ca}", light},
	{"authority-manage", "/authorities/{id}/manage", "/authorities/{ca}/manage", light},
	{"authority-new", "/authorities/new", "/authorities/new", light},
	{"authority-import", "/authorities/import", "/authorities/import", light},
	{"authority-offline", "/authorities/{id}/offline", "/authorities/{pending}/offline", light},
	{"domains", "/domains", "/domains", light},
	{"domain-new", "/domains/new", "/domains/new", light},
	{"domain-detail", "/domains/{id}", "/domains/{domain}", light},
	{"presets", "/presets", "/presets", light},
	{"preset-detail", "/presets/{name}", "/presets/server", light},

	{"agents", "/agents", "/agents", light},
	{"agent-detail", "/agents/{id}", "/agents/{agent}", light},
	{"agent-update", "/agents/{id}/update", "/agents/{agentold}/update", light},
	{"agent-renew", "/agents/{id}/deployments/{name}/renew", "/agents/{agent}/deployments/web/renew", light},
	{"agent-install", "/agents/install", "/agents/install", light},
	{"host-add", "/hosts/add", "/hosts/add", light},
	{"host-add-progress", "/hosts/add/{host}", "/hosts/add/{enroll}", light},
	{"agent-enrollments", "/agents/enrollments", "/agents/enrollments", light},
	{"agent-tokens", "/agents/tokens", "/agents/tokens", light},

	{"acme-accounts", "/acme/accounts", "/acme/accounts", light},
	{"acme-account-detail", "/acme/accounts/{id}", "/acme/accounts/{account}", light},
	{"acme-names", "/acme/names", "/acme/names", light},
	{"acme-eab", "/acme/eab", "/acme/eab", light},
	{"acme-orders", "/acme/orders", "/acme/orders", light},

	{"users", "/admin/users", "/admin/users", light},
	{"user-new", "/admin/users/new", "/admin/users/new", light},
	{"user-detail", "/admin/users/{id}", "/admin/users/{user}", light},
	{"settings", "/admin/settings", "/admin/settings", light},
	{"audit-log", "/admin/audit", "/admin/audit", light},
	{"audit-log-instance", "/admin/audit", "/admin/audit?scope=instance", light},
	{"import", "/admin/import", "/admin/import", light},
	{"appearance", "/admin/appearance", "/admin/appearance", light},
	{"account", "/account", "/account", light},
	{"design", "/design", "/design", light},
}

// inventoryExcluded are the GET routes of registerApp that are not shot, with
// the reason. They are read from their templ source instead.
var inventoryExcluded = map[string]string{
	"/login/code":                          "needs a sign-in that waits for its second factor; without one it redirects to /login",
	"/certificates/{id}/download/{format}": "a file download, not a page",
	"/authorities/{id}/certificate":        "a file download: the CA certificate as PEM or chain",
	"/hosts/add/{host}/status":             "the htmx fragment that refreshes /hosts/add/{host}",
	"/agents/{id}/deployments":             "the htmx fragment that refreshes the deployments of /agents/{id}",
	"/admin/import/{id}":                   "the report of a finished legacy import; the demo has none (read internal/web/app_admin.go, importReport)",
}

// inventoryRoutes is the set of routes the inventory covers.
func inventoryRoutes() map[string]bool {
	m := map[string]bool{}
	for _, p := range inventoryPages {
		m[p.route] = true
	}
	for r := range inventoryExcluded {
		m[r] = true
	}
	return m
}

// pageResult is what the inventory found out about one request.
type pageResult struct {
	body   []byte // the HTML, for reading what the images do not show (closed <details>)
	status int
	final  string // the URL path after redirects, "" = the same
	err    error
}

// probe requests path like the browser will, follows redirects and reports
// the final status. The images alone would not show a 404 or a redirect.
func probe(base, path string) pageResult {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, http.NoBody)
	if err != nil {
		return pageResult{err: err}
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return pageResult{err: err}
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	r := pageResult{status: resp.StatusCode, body: body}
	if got := resp.Request.URL.RequestURI(); got != path {
		r.final = got
	}
	return r
}

// runInventory shoots every page of inventoryPages and writes manifest.txt
// (page, route, path, status) next to the images.
func runInventory(ctx context.Context, in *instance, bases map[viewKind]string, browser, out, only string, width, height int, stdout, stderr io.Writer) int {
	// Old images of an earlier run must not stay: the directory is the
	// result of this run only.
	for _, pattern := range []string{"*.png", "*.html"} {
		if only != "" {
			break // a partial run keeps the other pages
		}
		old, _ := filepath.Glob(filepath.Join(out, pattern))
		for _, f := range old {
			_ = os.Remove(f)
		}
	}
	groups := []viewKind{anonymous, sealed, light}
	var manifest strings.Builder
	manifest.WriteString("name\tstatus\troute\trequested\tfinal\n")
	failed, unsealed := false, false
	var problems []string
	for _, kind := range groups {
		if needsUnseal(kind) && !unsealed {
			if err := in.ring.Unseal(ctx, []byte(in.passphrase), console); err != nil {
				fmt.Fprintln(stderr, err)
				return 1
			}
			unsealed = true
		}
		for _, p := range inventoryPages {
			if p.kind != kind || !selected(p.name, only) {
				continue
			}
			path := strings.NewReplacer("{cert}", in.detailID, "{pending}", in.pendingID, "{ca}", in.issuingID, "{domain}", in.domainID,
				"{agent}", in.agentID, "{agentold}", in.agentOldID, "{account}", in.accountID, "{user}", in.userID, "{enroll}", in.enrollHost).Replace(p.path)
			for _, th := range themesOf(kind) {
				base := bases[th.kind]
				res := probe(base, path)
				stem := fmt.Sprintf("%02d-%s%s", numberOf(p.name), p.name, th.suffix)
				if th.suffix == "" {
					fmt.Fprintf(&manifest, "%s\t%d\t%s\t%s\t%s\n", p.name, res.status, p.route, path, res.final)
					if res.err != nil || res.status != http.StatusOK {
						problems = append(problems, fmt.Sprintf("%s: %s%s (HTTP %d%s)", p.name, path, finalNote(res), res.status, errNote(res.err)))
					}
				}
				if th.suffix == "" {
					_ = os.WriteFile(filepath.Join(out, stem+".html"), res.body, 0o600)
				}
				file := filepath.Join(out, stem+".png")
				if err := capture(browser, base+path, file, width, height); err != nil {
					fmt.Fprintf(stderr, "FAILED %s: %v\n", stem, err)
					failed = true
					continue
				}
				fmt.Fprintf(stdout, "ok     %s  (HTTP %d%s)\n", stem+".png", res.status, finalNote(res))
			}
		}
	}
	if err := os.WriteFile(filepath.Join(out, "manifest.txt"), []byte(manifest.String()), 0o600); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	notShot := make([]string, 0, len(inventoryExcluded))
	for r, why := range inventoryExcluded {
		notShot = append(notShot, fmt.Sprintf("  %s: %s", r, why))
	}
	sort.Strings(notShot)
	fmt.Fprintf(stdout, "\nnot shot:\n%s\n", strings.Join(notShot, "\n"))
	if len(problems) > 0 {
		fmt.Fprintf(stdout, "\npages that did not answer 200:\n  %s\n", strings.Join(problems, "\n  "))
	}
	fmt.Fprintf(stdout, "\nimages and manifest.txt are in %s (untracked, never commit them)\n", out)
	if failed {
		return 1
	}
	return 0
}

// theme is one view of a page: the file suffix and the server that serves it.
type theme struct {
	suffix string
	kind   viewKind
}

// themesOf are the two images of a page: light first, then dark.
func themesOf(kind viewKind) []theme {
	switch kind { //nolint:exhaustive // only these three are listed, every other kind is a light page
	case anonymous:
		return []theme{{"", anonymous}, {"-dark", anonymousDark}}
	case sealed:
		return []theme{{"", sealed}, {"-dark", sealedDark}}
	}
	return []theme{{"", light}, {"-dark", dark}}
}

// selected reports whether the page is asked for by -only (comma-separated
// name prefixes; "" = every page).
func selected(name, only string) bool {
	if only == "" {
		return true
	}
	for _, prefix := range strings.Split(only, ",") {
		if strings.HasPrefix(name, strings.TrimSpace(prefix)) {
			return true
		}
	}
	return false
}

// numberOf is the position of a page in inventoryPages, so that the files sort
// like the navigation.
func numberOf(name string) int {
	for i, p := range inventoryPages {
		if p.name == name {
			return i + 1
		}
	}
	return 0
}

func finalNote(r pageResult) string {
	if r.final == "" {
		return ""
	}
	return " -> " + r.final
}

func errNote(err error) string {
	if err == nil {
		return ""
	}
	return ", " + err.Error()
}
