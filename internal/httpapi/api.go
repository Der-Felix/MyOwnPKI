// Package httpapi is the REST API of the admin listener (api/openapi.yaml,
// PHASE1 step 13): hand-written on net/http and encoding/json. The spec
// comes first; every route here is an operation of it, and the contract
// tests check both against each other.
//
// Every request runs through the same chain: request ID and access log,
// cross-origin protection, the session (or 401), the CSRF token for changes,
// the JSON body rules – then the handler, which calls the services. The
// services check the permissions themselves (security.md); the handlers only
// translate between HTTP and them.
package httpapi

import (
	"context"
	"log/slog"
	"net/http"
	"net/netip"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/auth"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/ca/preset"
	"github.com/Der-Felix/MyOwnPKI/internal/clock"
	"github.com/Der-Felix/MyOwnPKI/internal/ids"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
)

// BasePath is where the API lives on the admin listener.
const BasePath = "/api/v1"

// MaxBody is the size limit of a request body (CSRs fit easily).
const MaxBody = 128 << 10

// Deps are the services the API calls.
type Deps struct {
	Auth    *auth.Service
	Engine  *ca.Engine
	Keys    *keys.Keyring
	Presets *preset.Set
	Clock   clock.Clock
	Log     *slog.Logger
	// TrustedProxies may set X-Forwarded-For (auth.trusted_proxies).
	TrustedProxies []netip.Prefix
	Version        string
	Demo           bool
}

// access says who may call a route.
type access int

const (
	public   access = iota // no session (login, second factor)
	signedIn               // a full session
)

// Route is one operation of the spec.
type Route struct {
	OperationID, Method, Path string // Path relative to BasePath, in spec syntax
	access                    access
	passive                   bool  // doesn't count as session activity (x-passive)
	body                      bool  // takes a JSON body
	maxBody                   int64 // 0 = MaxBody
	handle                    func(*call) error
}

// call is one request on its way through a handler.
type call struct {
	w       http.ResponseWriter
	r       *http.Request
	api     *API
	reqID   string
	client  auth.Client
	token   string // the session cookie value
	session *auth.Session
	status  int
}

// who is the caller as the services want it.
func (c *call) who() keys.Who {
	w := keys.Who{SourceIP: c.client.IP}
	if c.session != nil {
		w.Actor = audit.Actor{Type: audit.ActorUser, ID: c.session.UserID, Name: c.session.Username}
		w.Principal = c.session.Principal
	}
	return w
}

func (c *call) ctx() context.Context { return c.r.Context() }

// API is the handler of BasePath.
type API struct {
	d        Deps
	mux      *http.ServeMux
	cop      *http.CrossOriginProtection
	routes   []Route
	notFound http.Handler
}

// New returns the API handler; mount it at BasePath + "/".
func New(d Deps) *API {
	if d.Clock == nil {
		d.Clock = clock.System{}
	}
	if d.Log == nil {
		d.Log = slog.New(slog.DiscardHandler)
	}
	a := &API{d: d, mux: http.NewServeMux(), cop: http.NewCrossOriginProtection()}
	a.routes = a.table()
	a.cop.SetDenyHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := &call{w: w, r: r, api: a, reqID: w.Header().Get(requestIDHeader)}
		_ = c.problem(http.StatusForbidden, "forbidden", "cross-origin request refused", nil)
	}))
	allowed := map[string][]string{}
	for _, rt := range a.routes {
		a.mux.Handle(rt.Method+" "+BasePath+rt.Path, a.wrap(rt))
		allowed[rt.Path] = append(allowed[rt.Path], rt.Method)
	}
	// 405 per method, not one pattern for all: a method-less pattern for
	// /users/me/webauthn/finish would conflict with DELETE /users/me/webauthn/{id}.
	for path, methods := range allowed {
		allow := strings.Join(methods, ", ")
		notAllowed := a.wrap(Route{OperationID: "methodNotAllowed", access: public, handle: func(c *call) error {
			c.w.Header().Set("Allow", allow)
			return c.problem(http.StatusMethodNotAllowed, "bad-request", "method not allowed – use "+allow, nil)
		}})
		// No HEAD: a GET pattern covers HEAD and would clash with it.
		for _, m := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions} {
			if slices.Contains(methods, m) {
				continue
			}
			a.mux.Handle(m+" "+BasePath+path, notAllowed)
		}
	}
	a.notFound = a.wrap(Route{OperationID: "notFound", access: public, handle: func(c *call) error {
		return c.problem(http.StatusNotFound, "not-found", "no such API operation", nil)
	}})
	a.mux.Handle(BasePath+"/", a.notFound)
	return a
}

// Routes lists the operations this build serves (contract tests).
func (a *API) Routes() []Route { return a.routes }

func (a *API) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// ServeMux answers an unclean path ("//", "/./") with a redirect in
	// text/html; under the API it is simply no operation (owner 2026-10-17).
	if p := r.URL.Path; p != path.Clean(p) {
		a.notFound.ServeHTTP(w, r)
		return
	}
	a.mux.ServeHTTP(w, r)
}

const requestIDHeader = "X-Request-ID"

// wrap runs the chain for one route.
func (a *API) wrap(rt Route) http.Handler {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := a.d.Clock.Now()
		c := &call{w: w, r: r, api: a, reqID: w.Header().Get(requestIDHeader), status: http.StatusOK}
		c.client = auth.Client{IP: auth.ClientIP(r, a.d.TrustedProxies).String()}
		if ck, err := r.Cookie(auth.DeviceCookieName); err == nil {
			c.client.Device = ck.Value
		}
		if ck, err := r.Cookie(auth.CookieName); err == nil {
			c.token = ck.Value
		}
		err := a.serve(c, rt)
		if err != nil {
			c.fail(err)
		}
		user := ""
		if c.session != nil {
			user = c.session.UserID
		}
		// Route pattern, not the path: IDs and names stay out of the log.
		a.d.Log.Info("api request", slog.String("method", r.Method), slog.String("route", rt.Path), slog.Int("status", c.status),
			slog.Duration("duration", a.d.Clock.Now().Sub(start)), slog.String("request_id", c.reqID), slog.String("user_id", user))
	})
	// The request ID and no-store come first: the cross-origin refusal
	// carries them too.
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := ids.New("req", a.d.Clock.Now(), nil)
		if err != nil {
			id = "req_unknown"
		}
		w.Header().Set(requestIDHeader, id)
		w.Header().Set("Cache-Control", "no-store")
		a.cop.Handler(h).ServeHTTP(w, r)
	})
}

func (a *API) serve(c *call, rt Route) error {
	if rt.access == signedIn {
		authenticate := a.d.Auth.Authenticate
		if rt.passive {
			authenticate = a.d.Auth.AuthenticatePassive
		}
		sess, err := authenticate(c.ctx(), c.token)
		if err != nil {
			return err
		}
		c.session = sess
		if !auth.SafeMethod(c.r.Method) && !auth.SameCSRFToken(c.r.Header.Get(auth.CSRFHeader), sess.CSRFToken) {
			return c.problem(http.StatusForbidden, "forbidden", auth.ErrCSRF.Error(), nil)
		}
	}
	if !auth.SafeMethod(c.r.Method) {
		// A JSON body only (owner 2026-10-17): with a body or a content type,
		// it must be application/json; a POST without a body may omit it.
		if rt.body || c.r.ContentLength > 0 || c.r.Header.Get("Content-Type") != "" {
			if !isJSON(c.r.Header.Get("Content-Type")) {
				return c.problem(http.StatusUnsupportedMediaType, "unsupported-media-type", "send the body as application/json", nil)
			}
		}
		limit := int64(MaxBody)
		if rt.maxBody > 0 {
			limit = rt.maxBody
		}
		c.r.Body = http.MaxBytesReader(c.w, c.r.Body, limit)
	}
	return rt.handle(c)
}

func isJSON(ct string) bool {
	mt, _, _ := strings.Cut(ct, ";")
	return strings.EqualFold(strings.TrimSpace(mt), "application/json")
}

// now is the API's clock in UTC.
func (a *API) now() time.Time { return a.d.Clock.Now().UTC() }
