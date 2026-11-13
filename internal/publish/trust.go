package publish

import (
	"bytes"
	"context"
	"crypto/sha1" // #nosec G505 -- certificate dialog comparison only; SHA-256 remains authoritative
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	brand "github.com/Der-Felix/MyOwnPKI/assets"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/clock"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
	"github.com/Der-Felix/MyOwnPKI/internal/trustkit"
	"github.com/Der-Felix/MyOwnPKI/internal/web/pages/trust"
	"github.com/Der-Felix/MyOwnPKI/internal/web/view"
	styles "github.com/Der-Felix/MyOwnPKI/web"
)

// The trust portal (the trust page of v0.2.2, extended in v0.3.9) at / of the
// public listener: every active CA (roots first) with name, common name,
// validity and fingerprints, DER and PEM downloads, and the steps and
// commands that install a root on the visitor's platform. The platform comes
// from the User-Agent (a guess, trustkit.Detect) or from ?os=. No sign-in,
// only public data, no JavaScript; a tenant setting (trust_page) switches the
// whole portal off (then / and every /trust/ file are 404).
//
//	/                                the page; ?os=<platform>|all selects a platform
//	/ca/<name>/<generation>.pem      PEM copy of /ca/<name>/<generation>.crt (always)
//	/trust/<name>/<generation>/machine.cmd, …/user.cmd   Windows helpers (roots)
//	/trust/<name>/<generation>/profile.mobileconfig      Apple configuration profile (roots)
//	/static/styles/*.css, /static/brand/*, /favicon.ico  the app's stylesheets and logo
//
// What a request can influence: the platform guess (a row of a fixed table)
// and the ?os= value (one entry of an allow-list). Nothing of either is
// echoed into the page, a header, a file name or a command; none of the
// portal's own routes redirects, and there is no log line, no counter and no
// audit entry per request. (Go's ServeMux does answer 307 for a path that is not
// clean, such as //ca/root/1.crt or /a/../ca, before a handler runs; that is the
// router, not a route of the portal.)

// PageMaxAge: the page lists the CAs – a new one shows within five minutes.
const PageMaxAge = 5 * time.Minute

// TrustCSP: nothing but the own stylesheets and images – no script at all.
const TrustCSP = "default-src 'none'; style-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

const (
	// profileFile is the file name of the Apple configuration profile under
	// /trust/<name>/<generation>/.
	profileFile = "profile.mobileconfig"
	// profileType is the media type iOS and macOS open as a configuration profile.
	profileType = "application/x-apple-aspen-config"
	// osAll is the ?os= value that shows every platform.
	osAll trustkit.Platform = "all"
)

// TrustPage configures the trust page.
type TrustPage struct {
	// Enabled reports the tenant setting; it is asked per request, so a
	// change applies at once. An error answers 500.
	Enabled func(context.Context) (bool, error)
	Clock   clock.Clock // nil = clock.System
}

// WithTrustPage adds the trust portal, the Windows helpers, the profile and the assets.
func (h *Handler) WithTrustPage(tp TrustPage) *Handler {
	if tp.Clock == nil {
		tp.Clock = clock.System{}
	}
	h.trust = &tp
	h.mux.HandleFunc("GET /{$}", h.trustPage)
	h.mux.HandleFunc("GET /trust/{name}/{gen}/{file}", h.trustFile)
	h.mux.Handle("GET /static/styles/", http.StripPrefix("/static/", assets(styles.Static)))
	h.mux.Handle("GET /static/brand/", http.StripPrefix("/static/", assets(brand.Brand)))
	h.mux.Handle("GET /favicon.ico", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r2 := r.Clone(r.Context())
		r2.URL.Path = "brand/favicon.ico"
		assets(brand.Brand).ServeHTTP(w, r2)
	}))
	return h
}

// on asks the setting; false answers 404 (the page doesn't exist then).
func (h *Handler) on(w http.ResponseWriter, r *http.Request) bool {
	if h.trust == nil {
		http.NotFound(w, r)
		return false
	}
	ok, err := h.trust.Enabled(r.Context())
	if err != nil {
		h.fail(w, r, err)
		return false
	}
	if !ok {
		http.NotFound(w, r)
	}
	return ok
}

// osChoice reads the optional ?os= query value. It must be given exactly once
// and be one of the platforms or "all"; anything else (unknown, empty,
// repeated, longer than 16 bytes) counts as not given. The result is an entry
// of the allow-list, never the input.
func osChoice(r *http.Request) (trustkit.Platform, bool) {
	values := r.URL.Query()["os"]
	if len(values) != 1 {
		return "", false
	}
	if values[0] == string(osAll) {
		return osAll, true
	}
	return trustkit.ParsePlatform(values[0])
}

// userAgentSeen reads the User-Agent. Detect looks at its first 512 bytes only.
func userAgentSeen(r *http.Request) trustkit.Detection {
	return trustkit.Detect(r.Header.Get("User-Agent"))
}

// platformsShown are the guides the page shows: the explicit choice, else the
// detected platform (both Linux families for a plain Linux).
func platformsShown(choice trustkit.Platform, explicit bool, det trustkit.Detection) []trustkit.Platform {
	switch {
	case explicit && choice == osAll:
		return trustkit.Platforms()
	case explicit:
		return []trustkit.Platform{choice}
	case det.Platform == trustkit.Linux:
		return []trustkit.Platform{trustkit.Debian, trustkit.Fedora}
	case det.Platform != "":
		return []trustkit.Platform{det.Platform}
	}
	return nil
}

func (h *Handler) trustPage(w http.ResponseWriter, r *http.Request) {
	if !h.on(w, r) {
		return // 404 or 500, before any header of this page: a switched-off portal looks like any other 404
	}
	// The answer may depend on the browser, so shared caches must ask.
	w.Header().Set("Vary", "User-Agent")
	choice, explicit := osChoice(r)
	var det trustkit.Detection
	if !explicit {
		det = userAgentSeen(r)
	}
	d, err := h.portalData(r.Context(), platformsShown(choice, explicit, det), det)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	prefs := view.DefaultPrefs()
	prefs.Theme = view.ThemeSystem // no cookie here: follow the device
	p := view.Page{Title: "Trust this PKI", Description: "Certificate authorities of this PKI, their fingerprints and how to install a root on your devices.", Prefs: prefs}
	var buf bytes.Buffer
	if rerr := trust.Page(p, d).Render(r.Context(), &buf); rerr != nil {
		h.fail(w, r, rerr)
		return
	}
	pageHeaders(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// A page that depends on the detected platform must stay with the browser
	// that asked; with an explicit choice, or when nothing was found, every
	// visitor gets the same page.
	visibility := "public"
	if !explicit && det.Found() {
		visibility = "private"
	}
	h.serveCached(w, r, visibility, PageMaxAge, buf.Bytes())
}

// pageHeaders: the strict CSP and the usual headers of a page.
func pageHeaders(w http.ResponseWriter) {
	hd := w.Header()
	hd.Set("Content-Security-Policy", TrustCSP)
	hd.Set("X-Frame-Options", "DENY")
	hd.Set("Referrer-Policy", "no-referrer")
	hd.Set("Cross-Origin-Opener-Policy", "same-origin")
	hd.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
}

// serveCached sets Cache-Control ("public" or "private") and an ETag and lets
// http.ServeContent answer conditional requests and HEAD.
func (h *Handler) serveCached(w http.ResponseWriter, r *http.Request, visibility string, maxAge time.Duration, data []byte) {
	sum := sha256.Sum256(data)
	w.Header().Set("ETag", `"`+hex.EncodeToString(sum[:16])+`"`)
	w.Header().Set("Cache-Control", visibility+", max-age="+strconv.Itoa(int(maxAge.Seconds())))
	http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(data))
}

// generationCert is one shown certificate: a CA and one of its generations.
type generationCert struct {
	info ca.CAInfo
	gen  ca.GenerationInfo
	cert *x509.Certificate
}

// file is the base name the page uses for downloads of this generation: the
// CA's name, with the generation appended for an older one.
func (s generationCert) file() string {
	if s.gen.Current {
		return s.info.Name
	}
	return s.info.Name + "-" + strconv.FormatInt(s.gen.Generation, 10)
}

// shown lists what the page shows: active CAs, every generation with a
// certificate that is valid now and not revoked (after a root renewal the
// older one still verifies older certificates), roots first, then by name,
// the current generation first.
func (h *Handler) shown(ctx context.Context) ([]generationCert, error) {
	all, err := ca.ListCAs(ctx, h.db)
	if err != nil {
		return nil, err
	}
	now := h.trust.Clock.Now()
	q := pkidb.New(h.db)
	var out []generationCert
	for _, c := range all {
		if c.Status != ca.StatusActive {
			continue
		}
		for _, g := range c.Generations {
			if g.Pending || g.Revoked != "" {
				continue
			}
			row, gerr := q.GetCAGeneration(ctx, pkidb.GetCAGenerationParams{CaID: c.ID, Generation: g.Generation})
			if errors.Is(gerr, sql.ErrNoRows) || (gerr == nil && row.CertDer == nil) {
				continue
			}
			if gerr != nil {
				return nil, gerr
			}
			cert, perr := x509.ParseCertificate(row.CertDer)
			if perr != nil || now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
				continue
			}
			out = append(out, generationCert{info: c, gen: g, cert: cert})
		}
	}
	slices.SortStableFunc(out, func(a, b generationCert) int {
		ra, rb := a.info.Kind == ca.KindRoot, b.info.Kind == ca.KindRoot
		switch {
		case ra != rb:
			if ra {
				return -1
			}
			return 1
		case a.info.Name != b.info.Name:
			return strings.Compare(a.info.Name, b.info.Name)
		case a.gen.Current != b.gen.Current:
			if a.gen.Current {
				return -1
			}
			return 1
		}
		return int(b.gen.Generation - a.gen.Generation)
	})
	return out, nil
}

// trustCA is the page's view of one shown certificate.
func trustCA(s generationCert) trust.CA {
	gen := strconv.FormatInt(s.gen.Generation, 10)
	file := s.file()
	kind := "Intermediate CA"
	root := s.info.Kind == ca.KindRoot
	if root {
		kind = "Root CA"
	}
	c := trust.CA{
		Name: s.info.Name, Kind: kind, Root: root, Generation: s.gen.Generation, Current: s.gen.Current,
		CommonName:  s.cert.Subject.CommonName,
		Valid:       s.cert.NotBefore.UTC().Format(time.DateOnly) + " – " + s.cert.NotAfter.UTC().Format(time.DateOnly),
		Fingerprint: view.Fingerprint(trustkit.ColonHex(trustkit.SHA256Hex(s.cert.Raw))),
		SHA1:        view.Fingerprint(sha1ColonHex(s.cert.Raw)),
		DER:         "/ca/" + s.info.Name + "/" + gen + ".crt", PEM: "/ca/" + s.info.Name + "/" + gen + ".pem",
		FileDER: file + ".crt", FilePEM: file + ".pem", FileCER: file + ".cer",
	}
	if root {
		c.WinMachine = "/trust/" + s.info.Name + "/" + gen + "/" + ScopeMachine + ".cmd"
		c.WinUser = "/trust/" + s.info.Name + "/" + gen + "/" + ScopeUser + ".cmd"
		c.Profile = "/trust/" + s.info.Name + "/" + gen + "/" + profileFile
		c.FileProfile = file + ".mobileconfig"
	}
	return c
}

// portalData builds the page: the roots with their steps for the platforms
// shown, the choices, and the intermediates as a downloads table. The CA's own
// data (name, base URL, certificate) is all that goes into the steps.
func (h *Handler) portalData(ctx context.Context, platforms []trustkit.Platform, det trustkit.Detection) (trust.Data, error) {
	shown, err := h.shown(ctx)
	if err != nil {
		return trust.Data{}, err
	}
	var d trust.Data
	var roots []trustkit.Root
	for _, s := range shown {
		c := trustCA(s)
		if !c.Root {
			d.Intermediates = append(d.Intermediates, c)
			continue
		}
		d.Roots = append(d.Roots, c)
		roots = append(roots, trustkit.Root{
			Name: s.info.Name, Generation: s.gen.Generation, Current: s.gen.Current,
			DER: s.cert.Raw, BaseURL: s.info.BaseURL, CommonName: s.cert.Subject.CommonName,
		})
	}
	for _, p := range platforms {
		sec := trust.Section{ID: string(p), Title: p.Label()}
		for i, r := range roots {
			sec.Roots = append(sec.Roots, trust.RootGuide{CA: d.Roots[i], Blocks: trustkit.Guide(p, r)})
		}
		d.Sections = append(d.Sections, sec)
	}
	if det.Platform != "" {
		d.Detected = det.Platform.Label()
	}
	d.FirefoxHint = det.Firefox && !slices.Contains(platforms, trustkit.Firefox)
	for _, p := range trustkit.Platforms() {
		d.Choices = append(d.Choices, trust.Choice{Label: p.Label(), Href: "/?os=" + string(p), Selected: slices.Contains(platforms, p)})
	}
	d.Choices = append(d.Choices, trust.Choice{
		Label: "All platforms", Href: "/?os=" + string(osAll), Selected: len(platforms) == len(trustkit.Platforms()),
	})
	return d, nil
}

// trustFile serves /trust/<name>/<gen>/machine.cmd, user.cmd and
// profile.mobileconfig for a root on the page.
func (h *Handler) trustFile(w http.ResponseWriter, r *http.Request) {
	name, genText, file := r.PathValue("name"), r.PathValue("gen"), r.PathValue("file")
	scope, isCmd := strings.CutSuffix(file, ".cmd")
	isCmd = isCmd && (scope == ScopeMachine || scope == ScopeUser)
	if !namePattern.MatchString(name) || (!isCmd && file != profileFile) {
		http.NotFound(w, r)
		return
	}
	gen, err := strconv.ParseInt(genText, 10, 64)
	if err != nil || gen < 1 {
		http.NotFound(w, r)
		return
	}
	if !h.on(w, r) {
		return
	}
	shown, err := h.shown(r.Context())
	if err != nil {
		h.fail(w, r, err)
		return
	}
	for _, s := range shown {
		if s.info.Name != name || s.gen.Generation != gen || s.info.Kind != ca.KindRoot {
			continue
		}
		if !isCmd {
			h.profile(w, r, s)
			return
		}
		// The name is built from the CA name and the normalized generation, never
		// from the text of the request ("+2" and "0002" both parse to 2).
		who := map[string]string{ScopeMachine: "computer", ScopeUser: "user"}[scope]
		download := name + "-trust-" + who + ".cmd"
		if !s.gen.Current {
			download = name + "-" + strconv.FormatInt(gen, 10) + "-trust-" + who + ".cmd"
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", `attachment; filename="`+download+`"`)
		h.serveCached(w, r, "public", MaxAge, windowsHelper(name, gen, s.cert.Raw, scope))
		return
	}
	http.NotFound(w, r)
}

// profile serves the Apple configuration profile of a shown root. The file
// name comes from the validated CA name and the generation number.
func (h *Handler) profile(w http.ResponseWriter, r *http.Request, s generationCert) {
	data, err := trustkit.MobileConfig(trustkit.Root{
		Name: s.info.Name, Generation: s.gen.Generation, Current: s.gen.Current,
		DER: s.cert.Raw, BaseURL: s.info.BaseURL, CommonName: s.cert.Subject.CommonName,
	})
	if err != nil {
		h.fail(w, r, err)
		return
	}
	w.Header().Set("Content-Type", profileType)
	w.Header().Set("Content-Disposition", `attachment; filename="`+s.file()+`.mobileconfig"`)
	h.serveCached(w, r, "public", MaxAge, data)
}

// pemOf is the PEM form of a DER certificate.
func pemOf(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// assetTypes: explicit types (Windows takes them from the registry, and
// nosniff refuses a wrong one).
var assetTypes = map[string]string{
	".css": "text/css; charset=utf-8",
	".svg": "image/svg+xml",
	".ico": "image/x-icon",
	".png": "image/png",
}

// assets serves embedded files, no directory listings.
func assets(files fs.FS) http.Handler {
	fileServer := http.FileServerFS(files)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "" || strings.HasSuffix(r.URL.Path, "/") {
			http.NotFound(w, r)
			return
		}
		if ct, ok := assetTypes[path.Ext(r.URL.Path)]; ok {
			w.Header().Set("Content-Type", ct)
		}
		w.Header().Set("Cache-Control", "public, max-age=3600")
		fileServer.ServeHTTP(w, r)
	})
}

// sha1ColonHex formats the legacy Windows dialog fingerprint. It is never an
// authorization value; all trust decisions use SHA-256.
func sha1ColonHex(der []byte) string {
	sum := sha1.Sum(der) // #nosec G401 -- display-only Windows certificate dialog comparison
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}
