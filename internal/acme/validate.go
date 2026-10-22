package acme

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
)

// Validation is SSRF by design (security.md "ACME validation"): the server
// connects to names an ACME client chose. So:
//   - http-01 connects to port 80 only, and follows at most 10 redirects,
//     only to ports 80 and 443 (RFC 8555 §8.3);
//   - every name is resolved once, through acme.resolver, and the connection
//     goes to exactly that checked address – no DNS rebinding between the
//     check and the connection;
//   - the domain's address policy decides which addresses are allowed;
//     loopback, link-local, multicast and unspecified never are;
//   - short timeouts, 1 KiB of response body, no proxy, no credentials,
//     at most four validations at a time.
const (
	validateTimeout = 10 * time.Second
	maxRedirects    = 10
	maxHTTPBody     = 1 << 10
	parallelChecks  = 4
)

type job struct {
	challenge  pkidb.AcmeChallenge
	authz      pkidb.AcmeAuthz
	thumbprint string
	account    string
	ip         string
}

type validator struct {
	s        *Server
	resolver *net.Resolver
	sem      chan struct{}
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup

	// The network edges; tests replace them, never the rules around them.
	dial      func(ctx context.Context, network, addr string) (net.Conn, error)
	lookupIP  func(ctx context.Context, host string) ([]netip.Addr, error)
	lookupTXT func(ctx context.Context, name string) ([]string, error)
}

func newValidator(s *Server, resolverAddr string) *validator {
	r := &net.Resolver{PreferGo: true}
	if resolverAddr != "" {
		var d net.Dialer
		r.Dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return d.DialContext(ctx, network, resolverAddr) // acme.resolver, never the system's
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	v := &validator{s: s, resolver: r, sem: make(chan struct{}, parallelChecks), ctx: ctx, cancel: cancel}
	var d net.Dialer
	v.dial = d.DialContext
	v.lookupIP = func(ctx context.Context, host string) ([]netip.Addr, error) {
		return r.LookupNetIP(ctx, "ip", host)
	}
	v.lookupTXT = r.LookupTXT
	return v
}

// Close stops new work and waits for running validations.
func (s *Server) Close() {
	s.valid.cancel()
	s.valid.wg.Wait()
}

func (v *validator) start(j job) {
	v.wg.Add(1)
	go func() {
		defer v.wg.Done()
		select {
		case v.sem <- struct{}{}:
		case <-v.ctx.Done():
			return
		}
		defer func() { <-v.sem }()
		ctx, cancel := context.WithTimeout(v.ctx, 3*validateTimeout)
		defer cancel()
		err := v.validate(ctx, j)
		v.finish(j, err)
	}()
}

// validationError is a failed check with its ACME problem type.
type validationError struct {
	typ, detail string
}

func (e *validationError) Error() string { return e.typ + ": " + e.detail }

func vfail(typ, format string, args ...any) error {
	return &validationError{typ: typ, detail: fmt.Sprintf(format, args...)}
}

// keyAuthorization is RFC 8555 §8.1: token "." thumbprint.
func keyAuthorization(token, thumbprint string) string { return token + "." + thumbprint }

func (v *validator) validate(ctx context.Context, j job) error {
	value := j.authz.IdentifierValue
	lookup := value
	if j.authz.Wildcard == 1 {
		lookup = "*." + value
	}
	d, err := v.s.engine.DomainFor(ctx, j.authz.IdentifierType, lookup)
	if err != nil {
		return err
	}
	if d == nil {
		return vfail("rejectedIdentifier", "no domain covers %s any more", lookup)
	}
	keyAuth := keyAuthorization(j.challenge.Token, j.thumbprint)
	switch j.challenge.Type {
	case ca.ChallengeHTTP01:
		return v.http01(ctx, j.authz.IdentifierType, value, j.challenge.Token, keyAuth, d.AddressPolicy)
	case ca.ChallengeDNS01:
		return v.dns01(ctx, value, keyAuth)
	}
	return vfail("malformed", "unknown challenge type %q", j.challenge.Type)
}

// allowedAddr applies the address policy.
func allowedAddr(a netip.Addr, policy string) error {
	a = a.Unmap()
	switch {
	case !a.IsValid(), a.IsUnspecified(), a.IsLoopback(), a.IsLinkLocalUnicast(), a.IsLinkLocalMulticast(),
		a.IsInterfaceLocalMulticast(), a.IsMulticast():
		return fmt.Errorf("%s is never a validation target", a)
	case a.Is4() && (a.As4()[0] == 0 || a.As4()[0] >= 240):
		return fmt.Errorf("%s is a reserved address", a)
	}
	if policy == ca.AddressPublic && (a.IsPrivate() || cgnat.Contains(a)) {
		return fmt.Errorf("%s is a private address and the domain allows public addresses only", a)
	}
	return nil
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// policyDial resolves once, checks every address and connects to an
// allowed one – the address that was checked is the address connected to.
func (v *validator) policyDial(policy string) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		if port != "80" && port != "443" {
			return nil, vfail("connection", "port %s: http-01 connects to port 80 (and 443 after a redirect) only", port)
		}
		var addrs []netip.Addr
		if a, perr := netip.ParseAddr(host); perr == nil {
			addrs = []netip.Addr{a}
		} else if addrs, err = v.lookupIP(ctx, host); err != nil {
			return nil, vfail("dns", "%s doesn't resolve: %v", host, err)
		}
		var refused []string
		for _, a := range addrs {
			if perr := allowedAddr(a, policy); perr != nil {
				refused = append(refused, perr.Error())
				continue
			}
			conn, derr := v.dial(ctx, network, netip.AddrPortFrom(a.Unmap(), portNumber(port)).String())
			if derr == nil {
				return conn, nil
			}
			refused = append(refused, derr.Error())
		}
		if len(refused) == 0 {
			return nil, vfail("dns", "%s has no address", host)
		}
		return nil, vfail("connection", "%s: %s", host, strings.Join(refused, "; "))
	}
}

func portNumber(p string) uint16 {
	if p == "443" {
		return 443
	}
	return 80
}

// http01 fetches http://<identifier>/.well-known/acme-challenge/<token>
// (RFC 8555 §8.3, RFC 8738 for IPs).
func (v *validator) http01(ctx context.Context, typ, value, token, keyAuth, policy string) error {
	host := value
	if typ == "ip" {
		if a, err := netip.ParseAddr(value); err == nil && a.Is6() {
			host = "[" + value + "]"
		}
	}
	client := &http.Client{
		Timeout: validateTimeout,
		Transport: &http.Transport{
			Proxy: nil, DialContext: v.policyDial(policy), DisableKeepAlives: true,
			MaxResponseHeaderBytes: 16 << 10, ResponseHeaderTimeout: validateTimeout,
			// After a redirect to https the certificate is not checked
			// (RFC 8555 §8.3: the key authorization proves control).
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // #nosec G402 -- RFC 8555 §8.3, the content is the proof
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return vfail("connection", "more than %d redirects", maxRedirects)
			}
			port := req.URL.Port()
			switch req.URL.Scheme {
			case "http":
				if port != "" && port != "80" {
					return vfail("connection", "redirect to port %s: only 80 and 443", port)
				}
			case "https":
				if port != "" && port != "443" {
					return vfail("connection", "redirect to port %s: only 80 and 443", port)
				}
			default:
				return vfail("connection", "redirect to %s: only http and https", req.URL.Scheme)
			}
			return nil
		},
	}
	url := "http://" + host + "/.well-known/acme-challenge/" + token
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return vfail("malformed", "%v", err)
	}
	req.Header.Set("User-Agent", "MyOwnPKI-ACME-validator")
	resp, err := client.Do(req)
	if err != nil {
		var ve *validationError
		if errors.As(err, &ve) {
			return ve
		}
		return vfail("connection", "fetching %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return vfail("incorrectResponse", "%s answered %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxHTTPBody+1))
	if err != nil {
		return vfail("connection", "reading %s: %v", url, err)
	}
	if len(body) > maxHTTPBody {
		return vfail("incorrectResponse", "%s answered more than %d bytes", url, maxHTTPBody)
	}
	if got := strings.TrimSpace(string(body)); got != keyAuth {
		return vfail("incorrectResponse", "%s answered %q, not the key authorization", url, clip(got))
	}
	return nil
}

// dns01 looks for the digest of the key authorization in the TXT records
// of _acme-challenge.<name> (RFC 8555 §8.4); the resolver follows CNAMEs.
func (v *validator) dns01(ctx context.Context, name, keyAuth string) error {
	sum := sha256.Sum256([]byte(keyAuth))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	record := "_acme-challenge." + name
	ctx, cancel := context.WithTimeout(ctx, validateTimeout)
	defer cancel()
	txts, err := v.lookupTXT(ctx, record)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return vfail("dns", "%s has no TXT record", record)
		}
		return vfail("dns", "looking up %s: %v", record, err)
	}
	for _, t := range txts {
		if strings.TrimSpace(t) == want {
			return nil
		}
	}
	return vfail("incorrectResponse", "no TXT record of %s holds the digest of the key authorization (found %d record(s))", record, len(txts))
}

// finish stores the result: the challenge and its authorization become
// valid (for ValidAuthzLifetime) or invalid, with an audit entry.
func (v *validator) finish(j job, verr error) {
	s := v.s
	ctx := context.Background()
	now := s.now()
	var perr sql.NullString
	status, authzStatus, expires, result := "valid", "valid", dbTime(now.Add(ValidAuthzLifetime)), audit.ResultSuccess
	details := map[string]any{"type": j.challenge.Type, "identifier": j.authz.IdentifierType + ":" + j.authz.IdentifierValue}
	if verr != nil {
		ve := &validationError{typ: "serverInternal", detail: "the check could not run – see the server log"}
		if !errors.As(verr, &ve) {
			s.log.Error("acme validation", slog.String("challenge", j.challenge.ID), slog.Any("error", verr))
		}
		b, _ := json.Marshal(map[string]any{"type": "urn:ietf:params:acme:error:" + ve.typ, "detail": ve.detail, "status": http.StatusForbidden})
		perr = sql.NullString{String: string(b), Valid: true}
		status, authzStatus, expires, result = "invalid", "invalid", j.authz.ExpiresAt, audit.ResultFailure
		details["error"] = ve.typ + ": " + clip(ve.detail)
		s.limits.allow("failed:"+j.authz.IdentifierValue, limitFailedPerIdentifier, time.Hour)
	}
	validated := sql.NullString{}
	if verr == nil {
		validated = sql.NullString{String: dbTime(now), Valid: true}
	}
	err := s.inTx(ctx, func(q *pkidb.Queries, tx *sql.Tx) error {
		if ferr := q.FinishACMEChallenge(ctx, pkidb.FinishACMEChallengeParams{Status: status, ValidatedAt: validated, Error: perr, UpdatedAt: dbTime(now), ID: j.challenge.ID}); ferr != nil {
			return ferr
		}
		if aerr := q.SetACMEAuthzStatus(ctx, pkidb.SetACMEAuthzStatusParams{Status: authzStatus, ExpiresAt: expires, UpdatedAt: dbTime(now), ID: j.authz.ID}); aerr != nil {
			return aerr
		}
		return enqueue(ctx, tx, now, j.account, j.ip, ActionChallenge, audit.Target{Type: "acme_challenge", ID: j.challenge.ID}, result, details)
	})
	if err != nil {
		s.log.Error("acme validation result", slog.String("challenge", j.challenge.ID), slog.Any("error", err))
	}
}
