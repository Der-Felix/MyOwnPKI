package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
)

// The Cloudflare provider is lego's, with its Config filled field by field:
// the token comes from the credentials file, never from the environment, and
// the HTTP client is the agent's own (docs/PHASE3.md §13.2, decision 4).
//
// What lego does not do, this file adds around it:
//   - the context: lego's calls use context.Background(), so the transport
//     below cancels the request when the issuance is canceled (and not for
//     CleanUp, which runs on a context that is not canceled);
//   - the answer body: a non-JSON or an unexpected body never reaches an
//     error text (lego's errors embed it); only the API's error codes and
//     short messages do;
//   - the delete: lego logs a failed DELETE and returns nil; the transport
//     notes it, so the guard can record the leftover record.

const (
	cloudflareHTTPTimeout = 30 * time.Second
	maxCloudflareBody     = 1 << 20
	maxCloudflareMessage  = 200
)

type cloudflareProvider struct {
	inner *cloudflare.DNSProvider
	creds *dnsCredentials
	tr    *cloudflareTransport

	mu        sync.Mutex
	presented map[string]bool // token of every successful Present
}

var (
	_ dnsProvider          = (*cloudflareProvider)(nil)
	_ dnsContextBinder     = (*cloudflareProvider)(nil)
	_ dnsCredentialsHolder = (*cloudflareProvider)(nil)
	_ dnsIdleCloser        = (*cloudflareProvider)(nil)
)

// cloudflareTest replaces what a test must: the API address and the roots
// that vouch for it. It is nil in production; there is no configuration key
// for it.
type cloudflareTest struct {
	baseURL string
	roots   *x509.CertPool
}

func newCloudflareProvider(cfg DNSProvider, creds *dnsCredentials, proxy string, test *cloudflareTest) (*cloudflareProvider, error) {
	proxyFn, err := proxyFunc(proxy)
	if err != nil {
		return nil, errors.New("cloudflare: the proxy setting of agent.yaml is not a URL")
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12} // system roots
	baseURL := ""
	if test != nil {
		tlsConfig.RootCAs, baseURL = test.roots, test.baseURL
	}
	base := &http.Transport{
		Proxy:                  proxyFn, // agent.yaml only, never HTTPS_PROXY
		DialContext:            (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:        tlsConfig,
		TLSHandshakeTimeout:    10 * time.Second,
		ResponseHeaderTimeout:  cloudflareHTTPTimeout,
		MaxResponseHeaderBytes: 64 << 10,
		IdleConnTimeout:        30 * time.Second,
	}
	tr := &cloudflareTransport{base: base, ctx: context.Background()}
	conf := &cloudflare.Config{
		AuthToken: string(creds.APIToken.reveal()),
		BaseURL:   baseURL,
		TTL:       cfg.TTL,
		HTTPClient: &http.Client{
			Timeout:       cloudflareHTTPTimeout,
			Transport:     tr,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		PropagationTimeout: time.Duration(cfg.PropagationTimeout) * time.Second,
		PollingInterval:    2 * time.Second,
	}
	if creds.ZoneToken.isSet() {
		conf.ZoneToken = string(creds.ZoneToken.reveal())
	}
	inner, err := cloudflare.NewDNSProviderConfig(conf)
	if err != nil {
		base.CloseIdleConnections()
		return nil, creds.redact(err)
	}
	return &cloudflareProvider{inner: inner, creds: creds, tr: tr, presented: map[string]bool{}}, nil
}

func (p *cloudflareProvider) dnsCreds() *dnsCredentials { return p.creds }
func (p *cloudflareProvider) useContext(ctx context.Context) {
	p.tr.setContext(ctx)
}
func (p *cloudflareProvider) closeIdle() { p.tr.base.CloseIdleConnections() }

func (p *cloudflareProvider) Timeout() (time.Duration, time.Duration) { return p.inner.Timeout() }

// Present creates a new TXT record; lego remembers its ID for CleanUp.
func (p *cloudflareProvider) Present(domain, token, keyAuth string) error {
	if err := p.inner.Present(domain, token, keyAuth); err != nil {
		return p.creds.redact(err)
	}
	p.mu.Lock()
	p.presented[token] = true
	p.mu.Unlock()
	return nil
}

// CleanUp deletes the record by ID. It returns the failure of the DELETE,
// which lego itself swallows.
func (p *cloudflareProvider) CleanUp(domain, token, keyAuth string) error {
	p.mu.Lock()
	ok := p.presented[token]
	delete(p.presented, token)
	p.mu.Unlock()
	if !ok {
		// Present did not finish, so lego holds no record ID; whatever the
		// failed call left behind cannot be found by ID.
		return nil
	}
	_ = p.tr.takeDeleteFailure()
	err := p.inner.CleanUp(domain, token, keyAuth)
	if failure := p.tr.takeDeleteFailure(); err == nil && failure != nil {
		err = failure
	}
	return p.creds.redact(err)
}

// cloudflareTransport is the round tripper of the provider's HTTP client.
type cloudflareTransport struct {
	base *http.Transport

	mu            sync.Mutex
	ctx           context.Context //nolint:containedctx // set per phase by the guard, see dnsContextBinder
	deleteFailure error
}

func (t *cloudflareTransport) setContext(ctx context.Context) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.ctx = ctx
}

func (t *cloudflareTransport) context() context.Context {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.ctx
}

func (t *cloudflareTransport) takeDeleteFailure() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	err := t.deleteFailure
	t.deleteFailure = nil
	return err
}

func (t *cloudflareTransport) noteDeleteFailure(err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.deleteFailure = err
}

func (t *cloudflareTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := contextTransport{t.context(), t.base}.RoundTrip(r)
	if err != nil {
		if r.Method == http.MethodDelete {
			t.noteDeleteFailure(fmt.Errorf("cloudflare: deleting the TXT record failed: %w", err))
		}
		return nil, err
	}
	out, err := sanitizeCloudflare(resp)
	if err != nil {
		if r.Method == http.MethodDelete {
			t.noteDeleteFailure(fmt.Errorf("cloudflare: deleting the TXT record failed: %w", err))
		}
		return nil, err
	}
	// A record that is already gone is what a delete wants.
	if r.Method == http.MethodDelete && out.StatusCode/100 != 2 && out.StatusCode != http.StatusNotFound {
		t.noteDeleteFailure(fmt.Errorf("cloudflare: deleting the TXT record failed: HTTP status %d", out.StatusCode))
	}
	return out, nil
}

// sanitizeCloudflare replaces the body of an answer by what the agent may
// show: a successful answer must be JSON (kept as it is); an error answer
// shrinks to its error codes and short messages. Anything else, such as the
// HTML page of a captive portal or a proxy, becomes an error without the body.
func sanitizeCloudflare(resp *http.Response) (*http.Response, error) {
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxCloudflareBody+1))
	if err != nil {
		return nil, fmt.Errorf("cloudflare: reading the answer (HTTP status %d) failed", resp.StatusCode)
	}
	if len(raw) > maxCloudflareBody {
		return nil, fmt.Errorf("cloudflare: the answer (HTTP status %d) is larger than %d bytes", resp.StatusCode, maxCloudflareBody)
	}
	if !json.Valid(raw) {
		return nil, fmt.Errorf("cloudflare: HTTP status %d with an answer that is not the Cloudflare API's JSON; is a proxy or a captive portal in the way?", resp.StatusCode)
	}
	if resp.StatusCode/100 != 2 {
		var body struct {
			Errors []struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			} `json:"errors"`
		}
		_ = json.Unmarshal(raw, &body)
		if len(body.Errors) == 0 {
			return nil, fmt.Errorf("cloudflare: HTTP status %d without an error description", resp.StatusCode)
		}
		type apiError struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		}
		clean := struct {
			Success bool       `json:"success"`
			Errors  []apiError `json:"errors"`
		}{}
		for _, e := range body.Errors {
			clean.Errors = append(clean.Errors, apiError{e.Code, shortMessage(e.Message)})
		}
		raw, err = json.Marshal(clean)
		if err != nil {
			return nil, errors.New("cloudflare: cannot describe the error answer")
		}
	}
	out := *resp
	out.Body = io.NopCloser(bytes.NewReader(raw))
	out.ContentLength = int64(len(raw))
	return &out, nil
}

// shortMessage keeps the first characters of an API message that are
// printable; a message is text for people, not a place for a body.
func shortMessage(s string) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if !unicode.IsPrint(r) {
			r = ' '
		}
		if n++; n > maxCloudflareMessage {
			b.WriteString("...")
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}
