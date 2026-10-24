package publish

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/pem"
	"errors"
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
	"github.com/Der-Felix/MyOwnPKI/internal/web/pages/trust"
	"github.com/Der-Felix/MyOwnPKI/internal/web/view"
	styles "github.com/Der-Felix/MyOwnPKI/web"
)

// The trust page (v0.2.2, owner 2026-10-24) at / of the public listener:
// every active CA (roots first) with name, common name, validity, SHA-256
// fingerprint, DER and PEM downloads, the Windows helpers of the roots, and
// install guides. No sign-in, only public data, no JavaScript; a tenant
// setting switches it off (then / and the helpers are 404).
//
//	/                                the page
//	/ca/<name>/<generation>.pem      PEM copy of /ca/<name>/<generation>.crt (always)
//	/trust/<name>/<generation>/machine.cmd, …/user.cmd   Windows helpers (roots)
//	/static/styles/*.css, /static/brand/*, /favicon.ico  the app's stylesheets and logo

// PageMaxAge: the page lists the CAs – a new one shows within five minutes.
const PageMaxAge = 5 * time.Minute

// TrustCSP: nothing but the own stylesheets and images – no script at all.
const TrustCSP = "default-src 'none'; style-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

// TrustPage configures the trust page.
type TrustPage struct {
	// Enabled reports the tenant setting; it is asked per request, so a
	// change applies at once. An error answers 500.
	Enabled func(context.Context) (bool, error)
	Clock   clock.Clock // nil = clock.System
}

// WithTrustPage adds the trust page, the Windows helpers and the assets.
func (h *Handler) WithTrustPage(tp TrustPage) *Handler {
	if tp.Clock == nil {
		tp.Clock = clock.System{}
	}
	h.trust = &tp
	h.mux.HandleFunc("GET /{$}", h.trustPage)
	h.mux.HandleFunc("GET /trust/{name}/{gen}/{file}", h.windowsHelper)
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

func (h *Handler) trustPage(w http.ResponseWriter, r *http.Request) {
	if !h.on(w, r) {
		return
	}
	d, err := h.trustData(r.Context())
	if err != nil {
		h.fail(w, r, err)
		return
	}
	prefs := view.DefaultPrefs()
	prefs.Theme = view.ThemeSystem // no cookie here: follow the device
	p := view.Page{Title: "Trust this PKI", Description: "Certificate authorities of this PKI, their fingerprints and how to install the root on your devices.", Prefs: prefs}
	var buf bytes.Buffer
	if rerr := trust.Page(p, d).Render(r.Context(), &buf); rerr != nil {
		h.fail(w, r, rerr)
		return
	}
	pageHeaders(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	h.serveCached(w, r, PageMaxAge, buf.Bytes())
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

// serveCached sets Cache-Control and an ETag and lets http.ServeContent
// answer conditional requests and HEAD.
func (h *Handler) serveCached(w http.ResponseWriter, r *http.Request, maxAge time.Duration, data []byte) {
	sum := sha256.Sum256(data)
	w.Header().Set("ETag", `"`+hex.EncodeToString(sum[:16])+`"`)
	w.Header().Set("Cache-Control", "public, max-age="+strconv.Itoa(int(maxAge.Seconds())))
	http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(data))
}

// generationCert is one shown certificate: a CA and one of its generations.
type generationCert struct {
	info ca.CAInfo
	gen  ca.GenerationInfo
	cert *x509.Certificate
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

func (h *Handler) trustData(ctx context.Context) (trust.Data, error) {
	shown, err := h.shown(ctx)
	if err != nil {
		return trust.Data{}, err
	}
	var d trust.Data
	for _, s := range shown {
		gen := strconv.FormatInt(s.gen.Generation, 10)
		file := s.info.Name
		if !s.gen.Current {
			file += "-" + gen
		}
		kind := "Intermediate CA"
		root := s.info.Kind == ca.KindRoot
		if root {
			kind = "Root CA"
		}
		c := trust.CA{
			Name: s.info.Name, Kind: kind, Root: root, Generation: s.gen.Generation, Current: s.gen.Current,
			CommonName:  s.cert.Subject.CommonName,
			Valid:       s.cert.NotBefore.UTC().Format(time.DateOnly) + " – " + s.cert.NotAfter.UTC().Format(time.DateOnly),
			Fingerprint: view.Fingerprint(colonHex(s.cert.Raw)),
			DER:         "/ca/" + s.info.Name + "/" + gen + ".crt", PEM: "/ca/" + s.info.Name + "/" + gen + ".pem",
			FileDER: file + ".crt", FilePEM: file + ".pem",
		}
		if root {
			c.WinMachine = "/trust/" + s.info.Name + "/" + gen + "/" + ScopeMachine + ".cmd"
			c.WinUser = "/trust/" + s.info.Name + "/" + gen + "/" + ScopeUser + ".cmd"
		}
		d.CAs = append(d.CAs, c)
	}
	for i := range d.CAs {
		if d.CAs[i].Root {
			d.Example = &d.CAs[i]
			break
		}
	}
	return d, nil
}

// windowsHelper serves /trust/<name>/<gen>/machine.cmd and user.cmd for a
// root on the page.
func (h *Handler) windowsHelper(w http.ResponseWriter, r *http.Request) {
	name, genText, file := r.PathValue("name"), r.PathValue("gen"), r.PathValue("file")
	scope, ok := strings.CutSuffix(file, ".cmd")
	if !namePattern.MatchString(name) || (scope != ScopeMachine && scope != ScopeUser) {
		http.NotFound(w, r)
		return
	}
	gen, err := strconv.ParseInt(genText, 10, 64)
	if !ok || err != nil || gen < 1 {
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
		if s.info.Name == name && s.gen.Generation == gen && s.info.Kind == ca.KindRoot {
			download := name + "-trust-" + map[string]string{ScopeMachine: "computer", ScopeUser: "user"}[scope] + ".cmd"
			if !s.gen.Current {
				download = name + "-" + genText + "-trust-" + map[string]string{ScopeMachine: "computer", ScopeUser: "user"}[scope] + ".cmd"
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Disposition", `attachment; filename="`+download+`"`)
			h.serveCached(w, r, MaxAge, windowsHelper(name, gen, s.cert.Raw, scope))
			return
		}
	}
	http.NotFound(w, r)
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
