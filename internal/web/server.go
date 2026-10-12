// Package web serves the admin UI: templ pages, the embedded static assets and
// the security headers every response gets.
//
// Phase 0: only the component gallery (/design) exists, and only in dev mode.
package web

import (
	"bytes"
	"io/fs"
	"log/slog"
	"net/http"
	"path"
	"strings"

	"github.com/a-h/templ"

	assets "github.com/Der-Felix/MyOwnPKI/web"

	"github.com/Der-Felix/MyOwnPKI/internal/web/pages/design"
)

// ContentSecurityPolicy is sent with every response (security.md). No inline
// scripts or styles are possible – templates may only use the global classes.
const ContentSecurityPolicy = "default-src 'self'; script-src 'self'; style-src 'self'; " +
	"img-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"

// Options configure the handler.
type Options struct {
	// Dev shows the DEV MODE banner on every page.
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
	mux.Handle("GET /design", page(design.Page(opts.Dev), opts.Logger))
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/design", http.StatusSeeOther)
	})

	return recoverer(opts.Logger, logRequests(opts.Logger, securityHeaders(mux))), nil
}

// staticFiles serves the embedded assets. Content types are set explicitly:
// on Windows, Go would otherwise take them from the registry, and with
// X-Content-Type-Options: nosniff a wrong type breaks the stylesheet.
// Directory listings are not served.
func staticFiles(files fs.FS) http.Handler {
	fileServer := http.FileServerFS(files)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "" || strings.HasSuffix(r.URL.Path, "/") {
			http.NotFound(w, r)
			return
		}
		switch path.Ext(r.URL.Path) {
		case ".css":
			w.Header().Set("Content-Type", "text/css; charset=utf-8")
		case ".svg":
			w.Header().Set("Content-Type", "image/svg+xml")
		}
		// Asset URLs are not fingerprinted yet, so browsers must revalidate.
		w.Header().Set("Cache-Control", "no-cache")
		fileServer.ServeHTTP(w, r)
	})
}

// page renders a component into a buffer first, so a render error becomes a
// clean 500 instead of a half-written page.
func page(c templ.Component, log *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var buf bytes.Buffer
		if err := c.Render(r.Context(), &buf); err != nil {
			log.ErrorContext(r.Context(), "render page", slog.String("path", r.URL.Path), slog.Any("error", err))
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(buf.Bytes())
	})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", ContentSecurityPolicy)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
		// HSTS is only meaningful over TLS; it is added together with TLS in phase 1.
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
