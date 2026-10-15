// Package web serves the admin UI: templ pages, the embedded static assets and
// the security headers every response gets.
//
// Phase 0: the component gallery (/design) and, in dev mode only, the UI
// prototype on fixture data (prototype*.go).
package web

import (
	"bytes"
	"io/fs"
	"log/slog"
	"net/http"
	"path"
	"strings"

	"github.com/a-h/templ"

	brand "github.com/Der-Felix/MyOwnPKI/assets"
	assets "github.com/Der-Felix/MyOwnPKI/web"

	"github.com/Der-Felix/MyOwnPKI/internal/web/pages/design"
	"github.com/Der-Felix/MyOwnPKI/internal/web/view"
)

// ContentSecurityPolicy is sent with every response (security.md). No inline
// scripts or styles are possible – templates may only use the global classes.
const ContentSecurityPolicy = "default-src 'self'; script-src 'self'; style-src 'self'; " +
	"img-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"

// Options configure the handler.
type Options struct {
	// Dev shows the DEV MODE banner on every page and enables the UI
	// prototype on fixture data.
	Dev    bool
	Logger *slog.Logger
}

// NewHandler returns the admin UI handler with all routes and middleware.
func NewHandler(opts Options) (http.Handler, error) {
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}

	mux := http.NewServeMux()
	mux.Handle("GET /static/", http.StripPrefix("/static/", staticFiles(assets.Static)))
	brandFiles := staticFiles(brand.Brand)
	mux.Handle("GET /static/brand/", http.StripPrefix("/static/", brandFiles))
	// Browsers ask for /favicon.ico on their own, even with <link rel="icon">.
	mux.HandleFunc("GET /favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		r2 := r.Clone(r.Context())
		r2.URL.Path = "/brand/favicon.ico"
		brandFiles.ServeHTTP(w, r2)
	})
	mux.HandleFunc("GET /design", func(w http.ResponseWriter, r *http.Request) {
		p := newPage(r, "Design system", "design", opts.Dev, view.Crumb{Label: "Administration"})
		p.Description = "Every class of web/styles in one place. Themes change tokens only."
		render(w, r, opts.Logger, http.StatusOK, design.Page(p))
	})
	if opts.Dev {
		registerPrototype(mux, opts.Logger)
	} else {
		mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/design", http.StatusSeeOther)
		})
	}

	// Reject state-changing cross-origin requests (Sec-Fetch-Site / Origin).
	// CSRF tokens for logged-in sessions follow in phase 1 (security.md).
	csrf := http.NewCrossOriginProtection()

	return recoverer(opts.Logger, logRequests(opts.Logger, SecurityHeaders(csrf.Handler(mux)))), nil
}

// staticFiles serves the embedded assets. Content types are set explicitly:
// on Windows, Go would otherwise take them from the registry, and with
// X-Content-Type-Options: nosniff a wrong type breaks the stylesheet.
// Directory listings are not served.
var staticTypes = map[string]string{
	".css": "text/css; charset=utf-8",
	".svg": "image/svg+xml",
	".ico": "image/x-icon",
	".png": "image/png",
}

func staticFiles(files fs.FS) http.Handler {
	fileServer := http.FileServerFS(files)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "" || strings.HasSuffix(r.URL.Path, "/") {
			http.NotFound(w, r)
			return
		}
		if ct, ok := staticTypes[path.Ext(r.URL.Path)]; ok {
			w.Header().Set("Content-Type", ct)
		}
		// Asset URLs are not fingerprinted yet, so browsers must revalidate.
		w.Header().Set("Cache-Control", "no-cache")
		fileServer.ServeHTTP(w, r)
	})
}

// render writes a component into a buffer first, so a render error becomes a
// clean 500 instead of a half-written page.
func render(w http.ResponseWriter, r *http.Request, log *slog.Logger, status int, c templ.Component) {
	var buf bytes.Buffer
	if err := c.Render(r.Context(), &buf); err != nil {
		log.ErrorContext(r.Context(), "render page", slog.String("path", r.URL.Path), slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

// SecurityHeaders sets the headers of every admin response (security.md
// "Transport and headers"); the server adds HSTS on the TLS listener.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", ContentSecurityPolicy)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
		// HSTS is only meaningful over TLS: internal/server adds it there.
		next.ServeHTTP(w, r)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func logRequests(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		log.InfoContext(r.Context(), "request",
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Int("status", rec.status),
			slog.String("remote", r.RemoteAddr),
		)
	})
}

func recoverer(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				if v == http.ErrAbortHandler { //nolint:errorlint // sentinel compared as panic value, as net/http does
					panic(v)
				}
				log.ErrorContext(r.Context(), "panic in handler", slog.String("path", r.URL.Path), slog.Any("panic", v))
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}
