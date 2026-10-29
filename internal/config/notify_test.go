package config

import (
	"strings"
	"testing"
)

func TestNotifyValid(t *testing.T) {
	t.Parallel()
	cfg := Default()
	cfg.DataDir = absDir(t)
	cfg.Notify.Email = Email{SMTP: "mail.homelab.lan:587", Security: SMTPStartTLS, Username: "pki", PasswordFile: "/etc/myownpki/smtp-password", // #nosec G101 -- test configuration, no credentials
		From: "pki@homelab.lan", To: "ops@homelab.lan, Lead <lead@homelab.lan>"}
	cfg.Notify.Webhook = Webhook{URL: "https://hooks.homelab.lan/myownpki", SecretFile: "/etc/myownpki/webhook-secret"} // #nosec G101 -- test configuration, no credentials
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if got := cfg.Notify.Email.Recipients(); len(got) != 2 || got[1] != "Lead <lead@homelab.lan>" {
		t.Errorf("recipients: %q", got)
	}
	cfg.Notify.Email = Email{SMTP: "localhost:25", Security: SMTPNone, From: "pki@homelab.lan", To: "ops@homelab.lan"}
	cfg.Notify.Webhook = Webhook{URL: "http://127.0.0.1:9000/hook", SecretFile: "/etc/myownpki/webhook-secret"} // #nosec G101 -- test configuration, no credentials
	if err := cfg.Validate(); err != nil {
		t.Errorf("relay on localhost: %v", err)
	}
}

func TestNotifyRejects(t *testing.T) {
	t.Parallel()
	mail := func(e Email) func(*Config) { return func(c *Config) { c.Notify.Email = e } }
	hook := func(w Webhook) func(*Config) { return func(c *Config) { c.Notify.Webhook = w } }
	good := Email{SMTP: "mail.homelab.lan:587", From: "pki@homelab.lan", To: "ops@homelab.lan"}
	with := func(f func(*Email)) Email { e := good; f(&e); return e }
	for name, tc := range map[string]struct {
		set  func(*Config)
		want string
	}{
		"smtp without port":     {mail(with(func(e *Email) { e.SMTP = "mail.homelab.lan" })), "notify.email.smtp: want host:port"},
		"unknown security":      {mail(with(func(e *Email) { e.Security = "ssl" })), "notify.email.security: starttls, tls or none"},
		"password in plaintext": {mail(with(func(e *Email) { e.Security, e.Username, e.PasswordFile = SMTPNone, "pki", "/p" })), "plain text"},
		"username alone":        {mail(with(func(e *Email) { e.Username = "pki" })), "set both or neither"},
		"no from":               {mail(with(func(e *Email) { e.From = "" })), "notify.email.from: required"},
		"bad to":                {mail(with(func(e *Email) { e.To = "ops@homelab.lan, not an address" })), `"not an address" is not an e-mail address`},
		"no to":                 {mail(with(func(e *Email) { e.To = " , " })), "notify.email.to: at least one"},
		"relative password":     {mail(with(func(e *Email) { e.Username, e.PasswordFile = "pki", "smtp-password" })), "must be an absolute path"},
		"from without smtp":     {mail(Email{From: "pki@homelab.lan"}), "notify.email.from needs notify.email.smtp"},
		"http webhook":          {hook(Webhook{URL: "http://hooks.homelab.lan/x", SecretFile: "/s"}), "must be https://"},
		"webhook with user":     {hook(Webhook{URL: "https://u:p@hooks.homelab.lan/x", SecretFile: "/s"}), "no user or password"}, // #nosec G101 -- test configuration, no credentials
		"webhook no secret":     {hook(Webhook{URL: "https://hooks.homelab.lan/x"}), "notify.webhook.secret_file: required"},
		"secret without url":    {hook(Webhook{SecretFile: "/s"}), "notify.webhook.secret_file needs notify.webhook.url"},
	} {
		cfg := Default()
		tc.set(&cfg)
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", name, err, tc.want)
		}
	}
}
