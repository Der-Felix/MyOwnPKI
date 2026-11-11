package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/config"
)

// webhookTimeout bounds one call.
const webhookTimeout = 10 * time.Second

// SignatureHeader carries the HMAC-SHA256 of the body: "sha256=<hex>".
const SignatureHeader = "X-MyOwnPKI-Signature"

// Webhook posts a digest as JSON.
type Webhook struct {
	URL        string
	SecretFile string
	CAFile     string
	UserAgent  string
}

// NewWebhook builds the channel from notify.webhook.
func NewWebhook(c config.Webhook, userAgent string) *Webhook {
	return &Webhook{URL: c.URL, SecretFile: c.SecretFile, CAFile: c.CAFile, UserAgent: userAgent}
}

// Name is the channel in the notifications queue.
func (w *Webhook) Name() string { return "webhook" }

// Sign is the signature header value for body.
func Sign(secret, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// Send posts one digest; any 2xx answer is success. Errors name the host,
// never the full URL – its path or query may hold a token.
func (w *Webhook) Send(ctx context.Context, d Digest) error {
	u, err := config.WebhookURL(w.URL)
	if err != nil {
		return err
	}
	secret, err := readSecret(w.SecretFile)
	if err != nil {
		return err
	}
	roots, err := rootPool(w.CAFile)
	if err != nil {
		return err
	}
	body, err := d.JSON()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, webhookTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("webhook %s: %w", u.Host, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", w.UserAgent)
	req.Header.Set(SignatureHeader, Sign([]byte(secret), body))
	transport := &http.Transport{
		TLSClientConfig:   &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		Proxy:             http.ProxyFromEnvironment,
		ForceAttemptHTTP2: true,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		// A redirect could carry the signed body somewhere else.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(req) // #nosec G704 -- the operator's own webhook URL, checked by config.WebhookURL
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return fmt.Errorf("webhook %s: %w", u.Host, err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("webhook %s answered %s", u.Host, resp.Status)
	}
	return nil
}
