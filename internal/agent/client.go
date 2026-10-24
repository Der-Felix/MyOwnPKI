package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync/atomic"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/gen/myownpki/agent/v1/agentv1connect"
)

// channel is the connection to the agent listener: TLS 1.3, the root of
// ca_bundle as the only trust anchor, the agent certificate when there is
// one, and a proxy only when agent.yaml names one.
type channel struct {
	transport *http.Transport
	client    agentv1connect.AgentServiceClient
	cert      atomic.Pointer[tls.Certificate] // nil = none (enrollment)
}

// rootPool reads ca_bundle.
func rootPool(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("ca_bundle: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("ca_bundle %s: no PEM certificate", path)
	}
	return pool, nil
}

// proxyFunc is the configured proxy or none – never the environment
// (owner 2026-10-24): the hosts reach the PKI directly, and a proxy from
// /etc/environment would get in the way.
func proxyFunc(proxy string) (func(*http.Request) (*url.URL, error), error) {
	if proxy == "" {
		return nil, nil
	}
	u, err := url.Parse(proxy)
	if err != nil {
		return nil, err
	}
	return http.ProxyURL(u), nil
}

func newChannel(cfg *Config, roots *x509.CertPool) (*channel, error) {
	u, err := url.Parse(cfg.Server)
	if err != nil {
		return nil, err
	}
	proxy, err := proxyFunc(cfg.Proxy)
	if err != nil {
		return nil, err
	}
	ch := &channel{}
	ch.transport = &http.Transport{
		Proxy:       proxy,
		DialContext: (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: u.Hostname(),
			GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
				if c := ch.cert.Load(); c != nil {
					return c, nil
				}
				return &tls.Certificate{}, nil // none yet: Enroll and EnrollStatus need none
			},
		},
		ForceAttemptHTTP2: true, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 70 * time.Second,
		IdleConnTimeout: 90 * time.Second, MaxIdleConnsPerHost: 2,
	}
	ch.client = agentv1connect.NewAgentServiceClient(&http.Client{Transport: ch.transport, Timeout: 75 * time.Second}, cfg.Server)
	return ch, nil
}

// use makes c the client certificate of new connections; open ones keep
// the old one, which the server still accepts until it expires.
func (ch *channel) use(c *tls.Certificate) {
	ch.cert.Store(c)
	ch.transport.CloseIdleConnections()
}

// explainTLS turns a failed handshake into something an admin can act on.
func explainTLS(err error) error {
	var unknown x509.UnknownAuthorityError
	var hostErr x509.HostnameError
	switch {
	case errors.As(err, &unknown):
		return fmt.Errorf("%w – the server's certificate is not from the root in ca_bundle (is the server still sealed and serving its bootstrap certificate?)", err)
	case errors.As(err, &hostErr):
		return fmt.Errorf("%w – server in agent.yaml must use the name in the server's certificate (agent.base_url)", err)
	}
	return err
}

// SetDial replaces how the agent connects to the server – for tests only
// (the name in server still is what TLS verifies).
func (a *Agent) SetDial(dial func(ctx context.Context, network, addr string) (net.Conn, error)) {
	a.ch.transport.DialContext = dial
	a.ch.transport.CloseIdleConnections()
}
