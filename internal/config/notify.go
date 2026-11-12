package config

import (
	"fmt"
	"net"
	"net/mail"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// Notify holds the notification channels (docs/PHASE3.md §9.3). They live
// in the configuration, not the database: a sealed server must still send
// "sealed", and it can't decrypt anything. Secrets are files the service
// user reads at each send; the configuration only names them.
type Notify struct {
	Email   Email   `yaml:"email"`
	Webhook Webhook `yaml:"webhook"`
}

// Email is the SMTP channel; off while smtp is empty.
type Email struct {
	// SMTP is host:port of the mail server.
	SMTP string `yaml:"smtp"`
	// Security: starttls (default), tls (implicit, port 465) or none (only
	// without username – a password never travels in plain text).
	Security     string `yaml:"security"`
	Username     string `yaml:"username"`
	PasswordFile string `yaml:"password_file"`
	From         string `yaml:"from"`
	// To: one or more addresses, comma-separated.
	To string `yaml:"to"`
	// CAFile: extra trusted roots for the mail server's certificate, e.g.
	// this PKI's root when the mail server has a certificate from it.
	CAFile string `yaml:"ca_file"`
}

// Webhook is the HTTP channel; off while url is empty.
type Webhook struct {
	URL string `yaml:"url"`
	// SecretFile holds the HMAC-SHA256 key of X-MyOwnPKI-Signature.
	SecretFile string `yaml:"secret_file"`
	CAFile     string `yaml:"ca_file"`
}

// Email security modes.
const (
	SMTPStartTLS = "starttls"
	SMTPTLS      = "tls"
	SMTPNone     = "none"
)

// Enabled reports whether the e-mail channel is configured.
func (e Email) Enabled() bool { return e.SMTP != "" }

// Enabled reports whether the webhook channel is configured.
func (w Webhook) Enabled() bool { return w.URL != "" }

// Mode is security with its default.
func (e Email) Mode() string {
	if e.Security == "" {
		return SMTPStartTLS
	}
	return e.Security
}

// Recipients splits to.
func (e Email) Recipients() []string {
	var out []string
	for _, r := range strings.Split(e.To, ",") {
		if r = strings.TrimSpace(r); r != "" {
			out = append(out, r)
		}
	}
	return out
}

// validateNotify checks both channels; the secret files are read at each
// send, so a missing one is a `config check` finding, not a start error.
func (c Config) validateNotify(add func(string, ...any)) {
	e := c.Notify.Email
	if !e.Enabled() {
		for _, kv := range [][2]string{{"username", e.Username}, {"password_file", e.PasswordFile}, {"from", e.From}, {"to", e.To}, {"ca_file", e.CAFile}} {
			if kv[1] != "" {
				add("notify.email.%s needs notify.email.smtp: without it no e-mail is sent", kv[0])
			}
		}
	} else {
		validateEmail(e, add)
	}
	w := c.Notify.Webhook
	if !w.Enabled() {
		for _, kv := range [][2]string{{"secret_file", w.SecretFile}, {"ca_file", w.CAFile}} {
			if kv[1] != "" {
				add("notify.webhook.%s needs notify.webhook.url: without it no webhook is called", kv[0])
			}
		}
		return
	}
	if _, err := WebhookURL(w.URL); err != nil {
		add("notify.webhook.url: %w", err)
	}
	if w.SecretFile == "" {
		add("notify.webhook.secret_file: required – the receiver checks the signature with it")
	}
	for _, kv := range [][2]string{{"secret_file", w.SecretFile}, {"ca_file", w.CAFile}} {
		if kv[1] != "" && !absoluteConfigPath(kv[1]) {
			add("notify.webhook.%s: must be an absolute path, got %q", kv[0], kv[1])
		}
	}
}

func validateEmail(e Email, add func(string, ...any)) {
	host, port, err := net.SplitHostPort(e.SMTP)
	if p, perr := strconv.Atoi(port); err != nil || host == "" || perr != nil || p < 1 || p > 65535 {
		add("notify.email.smtp: want host:port, e.g. mail.homelab.lan:587 – got %q", e.SMTP)
	}
	switch e.Mode() {
	case SMTPStartTLS, SMTPTLS:
	case SMTPNone:
		if e.Username != "" || e.PasswordFile != "" {
			add("notify.email.security: none sends the password in plain text – use starttls or tls with a username")
		}
	default:
		add("notify.email.security: starttls, tls or none – got %q", e.Security)
	}
	if (e.Username == "") != (e.PasswordFile == "") {
		add("notify.email.username and password_file: set both or neither")
	}
	if e.From == "" {
		add("notify.email.from: required with notify.email.smtp")
	} else if _, err := mail.ParseAddress(e.From); err != nil {
		add("notify.email.from: %q is not an e-mail address", e.From)
	}
	to := e.Recipients()
	if len(to) == 0 {
		add("notify.email.to: at least one address with notify.email.smtp")
	}
	for _, r := range to {
		if _, err := mail.ParseAddress(r); err != nil {
			add("notify.email.to: %q is not an e-mail address", r)
		}
	}
	for _, kv := range [][2]string{{"password_file", e.PasswordFile}, {"ca_file", e.CAFile}} {
		if kv[1] != "" && !absoluteConfigPath(kv[1]) {
			add("notify.email.%s: must be an absolute path, got %q", kv[0], kv[1])
		}
	}
}

// WebhookURL checks notify.webhook.url: https, or http to a loopback
// address (a local relay); no user info in the URL.
func WebhookURL(s string) (*url.URL, error) {
	u, err := url.Parse(s)
	if err != nil || u.Host == "" || u.Opaque != "" {
		return nil, fmt.Errorf("%q is not a URL", s)
	}
	if u.User != nil {
		return nil, fmt.Errorf("%q: no user or password in the URL – the request is signed with secret_file", s)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if a, perr := netip.ParseAddr(u.Hostname()); perr != nil || !a.IsLoopback() {
			if u.Hostname() != "localhost" {
				return nil, fmt.Errorf("%q: must be https:// (http:// only to a loopback address)", s)
			}
		}
	default:
		return nil, fmt.Errorf("%q: must be https://", s)
	}
	return u, nil
}
