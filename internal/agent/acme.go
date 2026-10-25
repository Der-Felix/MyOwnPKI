package agent

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"slices"
	"time"

	"connectrpc.com/connect"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"

	"github.com/Der-Felix/MyOwnPKI/internal/acme/jose"
	agentv1 "github.com/Der-Felix/MyOwnPKI/internal/gen/myownpki/agent/v1"
)

// Material is an issued certificate and its host-generated key. It is
// never sent over the agent channel or encoded into a report.
type Material struct {
	Certificate []byte            `json:"-"`
	Chain       []byte            `json:"-"`
	Fullchain   []byte            `json:"-"`
	Key         []byte            `json:"-"`
	Leaf        *x509.Certificate `json:"-"`
}

func (*Material) String() string { return "certificate material (private key redacted)" }
func (*Material) LogValue() slog.Value {
	return slog.StringValue("certificate material (private key redacted)")
}

type accountUser struct {
	key *ecdsa.PrivateKey
	reg *registration.Resource
}

// ErrACMEAccountRegistration requires operator action, not a retry with
// the same key. In particular, a new enrollment has a new agent identity.
var ErrACMEAccountRegistration = errors.New("ACME account registration requires operator action")

func (u *accountUser) GetEmail() string                        { return "" }
func (u *accountUser) GetPrivateKey() crypto.PrivateKey        { return u.key }
func (u *accountUser) GetRegistration() *registration.Resource { return u.reg }

// contextTransport propagates shutdown and the pass deadline through a
// library whose public obtain API does not take a context.
type contextTransport struct {
	ctx context.Context
	rt  http.RoundTripper
}

func (t contextTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	// Preserve the HTTP client's request deadline while also honoring a
	// shutdown of the enclosing pass. Keep cancellation alive until the
	// response body has been consumed and closed by lego.
	ctx, cancel := context.WithCancel(r.Context())
	stop := context.AfterFunc(t.ctx, cancel)
	done := func() { stop(); cancel() }
	response, err := t.rt.RoundTrip(r.Clone(ctx))
	if err != nil {
		done()
		return nil, err
	}
	response.Body = &contextBody{ReadCloser: response.Body, done: done}
	return response, nil
}

type contextBody struct {
	io.ReadCloser
	done func()
}

func (b *contextBody) Close() error {
	defer b.done()
	return b.ReadCloser.Close()
}

type httpProvider struct{ responder responder }

func (p httpProvider) Present(_, token, authorization string) error {
	return p.responder.place(token, authorization)
}

func (p httpProvider) CleanUp(_, token, _ string) error {
	p.responder.remove(token)
	return nil
}

// account loads one account per directory. Changing ACME servers does not
// reuse an account key or another server's registration URL.
func (a *Agent) account() (*accountUser, string, error) {
	sum := sha256.Sum256([]byte(a.cfg.ACMEDirectory))
	base := "acme-" + hex.EncodeToString(sum[:16])
	u := &accountUser{}
	key, err := readKey(a.st.path(base + ".key"))
	if errors.Is(err, os.ErrNotExist) {
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, "", err
		}
		der, merr := x509.MarshalPKCS8PrivateKey(key)
		if merr != nil {
			return nil, "", merr
		}
		defer clear(der)
		if werr := a.durableState(base+".key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})); werr != nil {
			return nil, "", werr
		}
	} else if err != nil {
		return nil, "", err
	}
	u.key = key
	data, err := os.ReadFile(a.st.path(base + ".json"))
	switch {
	case err == nil:
		if jerr := json.Unmarshal(data, &u.reg); jerr != nil {
			return nil, "", fmt.Errorf("ACME account state is invalid: %w", jerr)
		}
	case !errors.Is(err, os.ErrNotExist):
		return nil, "", err
	}
	return u, base, nil
}

// Obtain gets a new certificate by the ordinary ACME path (ADR-19).
// Scheduled and operator-requested renewals use this same operation.
func (a *Agent) Obtain(ctx context.Context, d Deployment) (*Material, error) {
	a.passMu.Lock()
	defer a.passMu.Unlock()
	unlock, err := a.deploymentLock()
	if err != nil {
		return nil, err
	}
	defer unlock()
	return a.obtain(ctx, d)
}

func (a *Agent) obtain(ctx context.Context, d Deployment) (*Material, error) {
	u, base, err := a.account()
	if err != nil {
		return nil, err
	}
	key := u.key
	jwk, err := jose.KeyFor(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	if _, rerr := a.ch.client.RegisterACMEAccount(ctx, connect.NewRequest(&agentv1.RegisterACMEAccountRequest{KeyThumbprint: jwk.Thumbprint()})); rerr != nil {
		if connect.CodeOf(rerr) == connect.CodeFailedPrecondition {
			return nil, fmt.Errorf("%w: this key cannot be registered for the current agent identity (possibly a previous enrollment); stop the agent, remove %s.key and %s.json from state_dir, and restart: %w", ErrACMEAccountRegistration, base, base, rerr)
		}
		return nil, fmt.Errorf("register the ACME account key: %w", explainTLS(rerr))
	}
	ac, roots, closeClient, err := a.legoClient(ctx, u)
	if err != nil {
		return nil, err
	}
	defer closeClient()
	return a.obtainWithClient(ctx, d, u, base, ac, roots)
}

// legoClient is shared by issuance and ARI. Both ignore environment trust
// and proxy settings and propagate the caller's cancellation.
func (a *Agent) legoClient(ctx context.Context, u *accountUser) (*lego.Client, *x509.CertPool, func(), error) {
	roots, err := rootPool(a.cfg.CABundle)
	if err != nil {
		return nil, nil, nil, err
	}
	proxy, err := proxyFunc(a.cfg.Proxy)
	if err != nil {
		return nil, nil, nil, err
	}
	transport := &http.Transport{
		Proxy: proxy, DialContext: a.acmeDial,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
		TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 30 * time.Second,
		MaxResponseHeaderBytes: 64 << 10, IdleConnTimeout: 30 * time.Second,
	}
	client := &http.Client{Timeout: time.Minute, Transport: contextTransport{ctx, transport},
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			if r.URL.Scheme != "https" || r.URL.User != nil || len(via) >= 5 {
				return errors.New("ACME redirect: HTTPS only, no credentials, at most five hops")
			}
			return nil
		},
	}
	// Do not call lego.NewConfig: it reads LEGO_CA_* environment variables
	// and creates a ProxyFromEnvironment transport before we could replace it.
	config := &lego.Config{CADirURL: a.cfg.ACMEDirectory, User: u, UserAgent: "MyOwnPKI-agent/" + a.Version,
		HTTPClient: client, Certificate: lego.CertificateConfig{Timeout: time.Minute, DisableCommonName: true}}
	ac, err := lego.NewClient(config)
	if err != nil {
		transport.CloseIdleConnections()
		return nil, nil, nil, fmt.Errorf("ACME directory: %w", err)
	}
	return ac, roots, transport.CloseIdleConnections, nil
}

func (a *Agent) obtainWithClient(ctx context.Context, d Deployment, u *accountUser, base string, ac *lego.Client, roots *x509.CertPool) (*Material, error) {
	var err error
	if u.reg == nil {
		u.reg, err = ac.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return nil, fmt.Errorf("ACME account: %w", err)
		}
		data, merr := json.Marshal(u.reg)
		if merr != nil {
			return nil, merr
		}
		if werr := a.durableState(base+".json", data); werr != nil {
			return nil, werr
		}
	}
	r := newResponder(d.Challenge, d.Webroot, a.cfg.Paths, a.st, a.StandaloneAddr, a.log)
	if perr := ac.Challenge.SetHTTP01Provider(httpProvider{r}); perr != nil {
		return nil, perr
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{}, DNSNames: slices.Clone(d.Names),
	}, leafKey)
	if err != nil {
		return nil, err
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, err
	}
	issued, err := ac.Certificate.ObtainForCSR(certificate.ObtainForCSRRequest{CSR: csr, PrivateKey: leafKey, Bundle: true})
	if err != nil {
		return nil, fmt.Errorf("ACME issuance: %w", err)
	}
	defer clear(issued.PrivateKey)
	privateDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		return nil, err
	}
	defer clear(privateDER)
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	return checkedMaterial(issued.Certificate, privatePEM, d.Names, roots, a.Now())
}

type renewalWindow struct {
	Start, End time.Time
	RetryAfter time.Duration
}

func (a *Agent) renewalInfo(ctx context.Context, leaf *x509.Certificate) (renewalWindow, error) {
	u, _, err := a.account()
	if err != nil {
		return renewalWindow{}, err
	}
	ac, _, closeClient, err := a.legoClient(ctx, u)
	if err != nil {
		return renewalWindow{}, err
	}
	defer closeClient()
	info, err := ac.Certificate.GetRenewalInfo(certificate.RenewalInfoRequest{Cert: leaf})
	if err != nil {
		return renewalWindow{}, err
	}
	if !info.SuggestedWindow.End.After(info.SuggestedWindow.Start) {
		return renewalWindow{}, errors.New("ARI returned an invalid renewal window")
	}
	return renewalWindow{info.SuggestedWindow.Start.UTC(), info.SuggestedWindow.End.UTC(), info.RetryAfter}, nil
}

// checkedMaterial independently verifies what the ACME server returned,
// including exact SANs, the local key and the chain. Roots are never deployed.
func checkedMaterial(bundle, key []byte, names []string, roots *x509.CertPool, now time.Time) (*Material, error) {
	if len(names) == 0 {
		return nil, errors.New("ACME certificate: at least one DNS name is required")
	}
	var certs []*x509.Certificate
	for len(bytes.TrimSpace(bundle)) != 0 {
		bundle = bytes.TrimSpace(bundle)
		marker := []byte("-----BEGIN CERTIFICATE-----")
		if !bytes.HasPrefix(bundle, marker) {
			return nil, errors.New("ACME certificate: unexpected data before PEM certificate")
		}
		block, rest := pem.Decode(bundle)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, errors.New("ACME certificate: expected only PEM certificates")
		}
		if bytes.Count(bundle[:len(bundle)-len(rest)], marker) != 1 {
			return nil, errors.New("ACME certificate: malformed PEM before certificate")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, errors.New("ACME certificate: invalid X.509")
		}
		certs = append(certs, cert)
		bundle = rest
	}
	if len(certs) == 0 {
		return nil, errors.New("ACME certificate: empty chain")
	}
	leaf := certs[0]
	want, got := slices.Clone(names), slices.Clone(leaf.DNSNames)
	slices.Sort(want)
	slices.Sort(got)
	if !slices.Equal(want, got) || len(leaf.IPAddresses)+len(leaf.EmailAddresses)+len(leaf.URIs) != 0 || leaf.IsCA {
		return nil, errors.New("ACME certificate: the names or profile differ from the request")
	}
	m := &Material{Leaf: leaf, Key: key, Certificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})}
	if _, err := tls.X509KeyPair(m.Certificate, key); err != nil {
		return nil, errors.New("ACME certificate: the key does not match")
	}
	intermediates := x509.NewCertPool()
	for _, cert := range certs[1:] {
		if bytes.Equal(cert.RawIssuer, cert.RawSubject) && cert.CheckSignatureFrom(cert) == nil {
			continue
		}
		intermediates.AddCert(cert)
		m.Chain = append(m.Chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})...)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: now.UTC(), DNSName: names[0]}); err != nil {
		return nil, fmt.Errorf("ACME certificate: chain verification: %w", err)
	}
	m.Fullchain = append(append([]byte(nil), m.Certificate...), m.Chain...)
	return m, nil
}

var defaultACMEDial = (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext
