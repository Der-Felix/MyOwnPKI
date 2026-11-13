package dnsserver

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/miekg/dns"
)

// CloudflareOptions configure the Cloudflare stub.
type CloudflareOptions struct {
	// Token is the API token that may edit DNS records.
	Token string
	// ZoneToken, if set, is the only token that may list zones (the split
	// Zone:Read and DNS:Edit setup); otherwise Token does both.
	ZoneToken string
}

// CloudflareRequest is one request the stub saw.
type CloudflareRequest struct {
	Method, Path, Query string
	// Authorization is the header as sent, "Bearer <token>".
	Authorization string
}

// CloudflareStub is an httptest TLS server that speaks the part of the
// Cloudflare v4 API that the agent uses (list zones, create and delete a DNS
// record) and writes into a Store, so the ACME server's resolver sees what
// the agent "published".
type CloudflareStub struct {
	// URL is the API base, https://127.0.0.1:port/client/v4.
	URL string
	// Roots trusts the stub's certificate.
	Roots *x509.CertPool

	store *Store
	opts  CloudflareOptions

	mu          sync.Mutex
	requests    []CloudflareRequest
	next        int
	records     map[string]Record // id -> name and value
	failDelete  int
	errorText   string
	notJSONBody string
	lostCreate  string
}

// StartCloudflare starts the stub until the test ends.
func StartCloudflare(tb testing.TB, store *Store, opts CloudflareOptions) *CloudflareStub {
	tb.Helper()
	c := &CloudflareStub{store: store, opts: opts, records: map[string]Record{}}
	srv := httptest.NewTLSServer(http.HandlerFunc(c.serve))
	tb.Cleanup(srv.Close)
	c.URL = srv.URL + "/client/v4"
	c.Roots = x509.NewCertPool()
	c.Roots.AddCert(srv.Certificate())
	return c
}

// Requests returns the log.
func (c *CloudflareStub) Requests() []CloudflareRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]CloudflareRequest(nil), c.requests...)
}

// FailDeletes makes every DELETE answer with this HTTP status (0 = normal).
func (c *CloudflareStub) FailDeletes(status int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.failDelete = status
}

// ErrorText sets the message of every error answer, to test that a secret in
// an API answer does not reach a log.
func (c *CloudflareStub) ErrorText(s string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.errorText = s
}

// NotJSON makes every answer this body with status 200 (a captive portal or
// a broken proxy). "" = normal.
func (c *CloudflareStub) NotJSON(body string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.notJSONBody = body
}

// LoseCreateAnswers makes the stub create a record as usual but answer the
// request with body (HTTP 502, not JSON), as a proxy that loses the real
// answer would: the record exists, and the client never learns its ID.
func (c *CloudflareStub) LoseCreateAnswers(body string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lostCreate = body
}

func (c *CloudflareStub) answer(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func (c *CloudflareStub) fail(w http.ResponseWriter, status, code int, msg string) {
	c.mu.Lock()
	if c.errorText != "" {
		msg = c.errorText
	}
	c.mu.Unlock()
	c.answer(w, status, map[string]any{"success": false, "errors": []map[string]any{{"code": code, "message": msg}}, "result": nil})
}

func (c *CloudflareStub) serve(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	c.requests = append(c.requests, CloudflareRequest{r.Method, r.URL.Path, r.URL.RawQuery, r.Header.Get("Authorization")})
	notJSON, failDelete := c.notJSONBody, c.failDelete
	c.mu.Unlock()
	if notJSON != "" {
		_, _ = fmt.Fprint(w, notJSON)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/client/v4")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	switch {
	case r.Method == http.MethodGet && path == "/zones":
		want := c.opts.Token
		if c.opts.ZoneToken != "" {
			want = c.opts.ZoneToken
		}
		if bearer != want {
			c.fail(w, http.StatusForbidden, 9109, "Invalid access token")
			return
		}
		name := dns.Fqdn(strings.ToLower(r.URL.Query().Get("name")))
		var result []map[string]any
		for _, z := range c.store.Zones() {
			if z == name {
				result = append(result, map[string]any{"id": "zone-" + z, "name": strings.TrimSuffix(z, ".")})
			}
		}
		c.answer(w, http.StatusOK, map[string]any{"success": true, "errors": []any{}, "result": result})
	case r.Method == http.MethodPost && len(parts) == 3 && parts[0] == "zones" && parts[2] == "dns_records":
		if bearer != c.opts.Token {
			c.fail(w, http.StatusForbidden, 10000, "Authentication error")
			return
		}
		var rec struct {
			Type, Name, Content string
			TTL                 int
		}
		if err := json.NewDecoder(r.Body).Decode(&rec); err != nil || !strings.EqualFold(rec.Type, "TXT") {
			c.fail(w, http.StatusBadRequest, 9005, "Content for A record is invalid")
			return
		}
		zone := strings.TrimPrefix(parts[1], "zone-")
		name := canon(rec.Name)
		if !dns.IsSubDomain(zone, name) {
			c.fail(w, http.StatusBadRequest, 9004, "DNS record name is not in the zone")
			return
		}
		value := strings.Trim(rec.Content, `"`)
		c.store.AddTXT(name, value)
		c.mu.Lock()
		c.next++
		id := fmt.Sprintf("rec%04d", c.next)
		c.records[id] = Record{name, value}
		lost := c.lostCreate
		c.mu.Unlock()
		if lost != "" {
			w.WriteHeader(http.StatusBadGateway)
			_, _ = fmt.Fprint(w, lost)
			return
		}
		c.answer(w, http.StatusOK, map[string]any{"success": true, "errors": []any{}, "result": map[string]any{"id": id, "type": "TXT", "name": strings.TrimSuffix(name, "."), "content": rec.Content, "ttl": rec.TTL}})
	case r.Method == http.MethodDelete && len(parts) == 4 && parts[0] == "zones" && parts[2] == "dns_records":
		if bearer != c.opts.Token {
			c.fail(w, http.StatusForbidden, 10000, "Authentication error")
			return
		}
		if failDelete != 0 {
			c.fail(w, failDelete, 10000, "Internal error")
			return
		}
		c.mu.Lock()
		rec, ok := c.records[parts[3]]
		delete(c.records, parts[3])
		c.mu.Unlock()
		if !ok {
			c.fail(w, http.StatusNotFound, 81044, "Record does not exist")
			return
		}
		c.store.DeleteTXT(rec.Name, rec.Value)
		c.answer(w, http.StatusOK, map[string]any{"success": true, "errors": []any{}, "result": map[string]any{"id": parts[3]}})
	default:
		c.fail(w, http.StatusNotFound, 7000, "No route for that URI")
	}
}
