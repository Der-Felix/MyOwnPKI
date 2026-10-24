// Package publish serves what certificates point to: CA certificates (AIA
// caIssuers) and CRLs (CRL distribution point) – plain HTTP on the public
// listener, no login (PHASE1 step 9; wired into the listener in step 12).
//
//	/ca/<name>/<generation>.crt   DER, application/pkix-cert (RFC 2585)
//	/ca/<name>/<generation>.pem   the same as PEM (v0.2.2)
//	/crl/<name>/<generation>.crl  DER, application/pkix-crl, the newest CRL
//	/<name>.crt, /<name>.crl      legacy URLs of imported CAs: generation 1
//
// With WithTrustPage also the trust page at / (trust.go).
//
// Caching: a short max-age (15 minutes) plus ETag and Last-Modified, so a
// new CRL after a revocation gets through proxies quickly while unchanged
// files cost a 304. HEAD and conditional requests come from
// http.ServeContent.
package publish

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
)

// MaxAge is how long proxies and clients may reuse a file without asking.
const MaxAge = 15 * time.Minute

var (
	namePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)
	genPattern  = regexp.MustCompile(`^([1-9][0-9]{0,8})\.(crt|crl|pem)$`)
)

// Handler serves one tenant's CA certificates and CRLs.
type Handler struct {
	db    *sql.DB // read connection of tenants/<t>/pki.db
	log   *slog.Logger
	mux   *http.ServeMux
	trust *TrustPage // nil: no trust page
}

// New returns the handler. db should be a read-only connection.
func New(db *sql.DB, log *slog.Logger) *Handler {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	h := &Handler{db: db, log: log, mux: http.NewServeMux()}
	h.mux.HandleFunc("GET /ca/{name}/{file}", h.caFile("crt"))
	h.mux.HandleFunc("GET /crl/{name}/{file}", h.caFile("crl"))
	h.mux.HandleFunc("GET /{file}", h.legacyFile)
	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	h.mux.ServeHTTP(w, r)
}

// caFile serves /ca/<name>/<gen>.crt or /crl/<name>/<gen>.crl.
func (h *Handler) caFile(kind string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		m := genPattern.FindStringSubmatch(r.PathValue("file"))
		if !namePattern.MatchString(name) || m == nil || (m[2] != kind && (kind != "crt" || m[2] != "pem")) {
			http.NotFound(w, r)
			return
		}
		gen, _ := strconv.ParseInt(m[1], 10, 64)
		h.serve(w, r, name, gen, m[2], false)
	}
}

// legacyFile serves /<name>.crt|.crl for CAs imported with legacy URLs.
func (h *Handler) legacyFile(w http.ResponseWriter, r *http.Request) {
	file := r.PathValue("file")
	var name, kind string
	ok := false
	for _, ext := range []string{".crt", ".crl"} {
		if base, found := strings.CutSuffix(file, ext); found {
			name, kind, ok = base, ext[1:], true
		}
	}
	if !ok || !namePattern.MatchString(name) || (kind != "crt" && kind != "crl") {
		http.NotFound(w, r)
		return
	}
	h.serve(w, r, name, 1, kind, true)
}

func (h *Handler) serve(w http.ResponseWriter, r *http.Request, name string, gen int64, kind string, legacy bool) {
	ctx := r.Context()
	q := pkidb.New(h.db)
	ca, err := q.GetCAByName(ctx, name)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && legacy && ca.LegacyUrls != 1) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		h.fail(w, r, err)
		return
	}
	var data []byte
	var modified time.Time
	switch kind {
	case "crt", "pem":
		g, err := q.GetCAGeneration(ctx, pkidb.GetCAGenerationParams{CaID: ca.ID, Generation: gen})
		if errors.Is(err, sql.ErrNoRows) || (err == nil && g.CertDer == nil) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			h.fail(w, r, err)
			return
		}
		data, modified = g.CertDer, parseStamp(g.CreatedAt)
		w.Header().Set("Content-Type", "application/pkix-cert")
		if kind == "pem" {
			data = pemOf(data)
			w.Header().Set("Content-Type", "application/x-pem-file")
		}
	case "crl":
		c, err := q.GetLatestCRL(ctx, pkidb.GetLatestCRLParams{CaID: ca.ID, Generation: gen})
		if errors.Is(err, sql.ErrNoRows) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			h.fail(w, r, err)
			return
		}
		data, modified = c.CrlDer, parseStamp(c.CreatedAt)
		w.Header().Set("Content-Type", "application/pkix-crl")
	}
	sum := sha256.Sum256(data)
	w.Header().Set("ETag", `"`+hex.EncodeToString(sum[:16])+`"`)
	w.Header().Set("Cache-Control", "public, max-age="+strconv.Itoa(int(MaxAge.Seconds())))
	http.ServeContent(w, r, "", modified, bytes.NewReader(data))
}

func (h *Handler) fail(w http.ResponseWriter, r *http.Request, err error) {
	h.log.ErrorContext(r.Context(), "publish", slog.String("path", r.URL.Path), slog.String("error", err.Error()))
	http.Error(w, "internal error", http.StatusInternalServerError)
}

func parseStamp(s string) time.Time {
	t, err := time.Parse(audit.TimeFormat, s)
	if err != nil {
		return time.Time{}
	}
	return t
}
