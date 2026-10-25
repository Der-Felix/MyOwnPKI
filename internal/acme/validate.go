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
	"slices"
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
	log      *slog.Logger
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
	v := newNetValidator(s.log, resolverAddr)
	v.s = s
	return v
}

// newNetValidator is the network part of the validator, without an ACME
// server behind it (HTTP01Checker).
func newNetValidator(log *slog.Logger, resolverAddr string) *validator {
	r := &net.Resolver{PreferGo: true}
	if resolverAddr != "" {
		var d net.Dialer
		r.Dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return d.DialContext(ctx, network, resolverAddr) // acme.resolver, never the system's
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	v := &validator{log: log, resolver: r, sem: make(chan struct{}, parallelChecks), ctx: ctx, cancel: cancel}
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

// SetNetwork replaces validation network edges for integration tests.
// Address, port and redirect policy checks still run unchanged.
func (s *Server) SetNetwork(dial func(context.Context, string, string) (net.Conn, error), lookupIP func(context.Context, string) ([]netip.Addr, error)) {
	s.valid.dial, s.valid.lookupIP = dial, lookupIP
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
		hosts, herr := v.orderHosts(ctx, j.authz)
		if herr != nil {
			return herr
		}
		return v.http01(ctx, j.authz.IdentifierType, value, j.challenge.Token, keyAuth, d.AddressPolicy, hosts)
	case ca.ChallengeDNS01:
		return v.dns01(ctx, value, keyAuth)
	}
	return vfail("malformed", "unknown challenge type %q", clip(j.challenge.Type))
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
			return nil, vfail("dns", "%s: %s", host, dnsProblem(err))
		}
		// The client learns counts and kinds, never addresses or what a
		// target said: with the policy "internal" this would otherwise map
		// the inside network. The server log keeps the details.
		var policyRefused, dialFailed int
		var kinds []string
		for _, a := range addrs {
			if perr := allowedAddr(a, policy); perr != nil {
				policyRefused++
				v.log.Info("acme validation: address refused", slog.String("host", host), slog.String("reason", perr.Error()))
				continue
			}
			conn, derr := v.dial(ctx, network, netip.AddrPortFrom(a.Unmap(), portNumber(port)).String())
			if derr == nil {
				return conn, nil
			}
			dialFailed++
			kinds = append(kinds, netProblem(derr))
			v.log.Info("acme validation: connect failed", slog.String("host", host), slog.String("address", a.String()), slog.String("kind", netProblem(derr)))
		}
		switch {
		case len(addrs) == 0:
			return nil, vfail("dns", "%s has no address", host)
		case dialFailed == 0:
			return nil, vfail("connection", "%s: the address policy of the domain refuses all %d address(es)", host, policyRefused)
		}
		return nil, vfail("connection", "%s: %d address(es) refused by the address policy, %d could not be reached (%s)",
			host, policyRefused, dialFailed, strings.Join(slices.Compact(kinds), ", "))
	}
}

// netProblem names the kind of a network error – never its text, which
// can carry what the target sent (a malformed HTTP response quotes it).
func netProblem(err error) string {
	var ne net.Error
	var op *net.OpError
	var rh tls.RecordHeaderError
	var alert tls.AlertError
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return "timed out"
	case errors.As(err, &rh), errors.As(err, &alert):
		return "TLS handshake failed"
	case errors.As(err, &op) && op.Op == "dial":
		return "could not connect"
	}
	return "the connection failed or the answer was not HTTP"
}

// dnsProblem names the kind of a DNS error, without the resolver's address.
func dnsProblem(err error) string {
	var de *net.DNSError
	switch {
	case errors.As(err, &de) && de.IsNotFound:
		return "no such name"
	case errors.As(err, &de) && de.IsTimeout, errors.Is(err, context.DeadlineExceeded):
		return "the DNS lookup timed out"
	}
	return "the DNS lookup failed"
}

func portNumber(p string) uint16 {
	if p == "443" {
		return 443
	}
	return 80
}

// http01 fetches http://<identifier>/.well-known/acme-challenge/<token>
// (RFC 8555 §8.3, RFC 8738 for IPs). Redirects stay within the order:
// only to hosts that are identifiers of an order this authorization
// belongs to, an IP identifier only as exactly that address. The dialer
// checks the address policy again on every hop.
func (v *validator) http01(ctx context.Context, typ, value, token, keyAuth, policy string, hosts map[string]bool) error {
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
			if !hosts[redirectHost(req.URL.Hostname())] {
				return vfail("incorrectResponse", "redirect to a host outside this order")
			}
			port := req.URL.Port()
			switch req.URL.Scheme {
			case "http":
				if port != "" && port != "80" {
					return vfail("connection", "redirect to port %s: only 80 and 443", clip(port))
				}
			case "https":
				if port != "" && port != "443" {
					return vfail("connection", "redirect to port %s: only 80 and 443", clip(port))
				}
			default:
				return vfail("connection", "redirect to a scheme other than http and https")
			}
			return nil
		},
	}
	url := "http://" + host + "/.well-known/acme-challenge/" + token
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return vfail("malformed", "the challenge URL can't be built")
	}
	req.Header.Set("User-Agent", "MyOwnPKI-ACME-validator")
	resp, err := client.Do(req)
	if err != nil {
		var ve *validationError
		if errors.As(err, &ve) {
			return ve
		}
		return vfail("connection", "fetching %s: %s", url, netProblem(err))
	}
	defer func() { _ = resp.Body.Close() }()
	// Only status and length go back to the client – what the target said
	// stays here (with the policy "internal" it may be an inside system).
	if resp.StatusCode != http.StatusOK {
		return vfail("incorrectResponse", "%s answered with status %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxHTTPBody+1))
	if err != nil {
		return vfail("connection", "reading the answer of %s: %s", url, netProblem(err))
	}
	if len(body) > maxHTTPBody {
		return vfail("incorrectResponse", "%s answered more than %d bytes", url, maxHTTPBody)
	}
	if got := strings.TrimSpace(string(body)); got != keyAuth {
		return vfail("incorrectResponse", "%s answered %d bytes that are not the key authorization", url, len(body))
	}
	return nil
}

// redirectHost is a redirect target as it is compared with identifiers:
// lower case without a trailing dot, an IP in its canonical form.
func redirectHost(h string) string {
	if a, err := netip.ParseAddr(h); err == nil {
		return "ip:" + a.Unmap().String()
	}
	return "dns:" + strings.TrimSuffix(strings.ToLower(h), ".")
}

// orderHosts are the identifiers of every order the authorization belongs
// to (an authorization can serve several orders) plus its own.
func (v *validator) orderHosts(ctx context.Context, a pkidb.AcmeAuthz) (map[string]bool, error) {
	hosts := map[string]bool{a.IdentifierType + ":" + a.IdentifierValue: true}
	q := pkidb.New(v.s.db)
	ids, err := q.ListACMEOrdersOfAuthz(ctx, a.ID)
	if err != nil {
		return nil, err
	}
	for _, id := range ids {
		o, oerr := q.GetACMEOrder(ctx, id)
		if oerr != nil {
			return nil, oerr
		}
		var idents []identifier
		if jerr := json.Unmarshal([]byte(o.Identifiers), &idents); jerr != nil {
			return nil, jerr
		}
		for _, i := range idents {
			if !strings.HasPrefix(i.Value, "*.") { // a wildcard is no host
				hosts[i.key()] = true
			}
		}
	}
	return hosts, nil
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
		return vfail("dns", "%s: %s", record, dnsProblem(err))
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
		s.limits.allow("failed:"+j.authz.IdentifierValue, s.limitsNow(ctx).FailedPerName, time.Hour)
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

// HTTP01Checker is the http-01 fetch of this validator for other proofs of
// control – the agent enrollment (ADR-18, docs/PHASE3.md §6.1) – with exactly
// the same rules: port 80 only, redirects only to 80/443 of the same host,
// one resolution through acme.resolver and a connection to exactly the
// checked address, the domain's address policy, short timeouts, 1 KiB.
type HTTP01Checker struct{ v *validator }

// NewHTTP01Checker returns a checker that resolves through resolver ("":
// the system resolver; IP or IP:port as acme.resolver).
func NewHTTP01Checker(resolver string, log *slog.Logger) *HTTP01Checker {
	return &HTTP01Checker{v: newNetValidator(log, resolver)}
}

// SetNetwork replaces the network edges – for tests only, never the rules.
func (c *HTTP01Checker) SetNetwork(dial func(ctx context.Context, network, addr string) (net.Conn, error),
	lookupIP func(ctx context.Context, host string) ([]netip.Addr, error)) {
	c.v.dial, c.v.lookupIP = dial, lookupIP
}

// Check fetches http://host/.well-known/acme-challenge/<token> and compares
// the answer with want. policy is the address policy of the domain that
// covers host ("internal" or "public"). The error says what failed – never
// what the target answered.
func (c *HTTP01Checker) Check(ctx context.Context, host, token, want, policy string) error {
	ctx, cancel := context.WithTimeout(ctx, validateTimeout)
	defer cancel()
	return c.v.http01(ctx, "dns", host, token, want, policy, map[string]bool{redirectHost(host): true})
}
