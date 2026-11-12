package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/config"
	"github.com/Der-Felix/MyOwnPKI/internal/server"
)

// runConfig handles `myownpki config <subcommand>`.
func runConfig(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "check" {
		_, _ = fmt.Fprintf(stderr, "Usage:\n  %s config check [--config FILE]\n", binary)
		if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
			return 2
		}
		_, _ = fmt.Fprintf(stderr, "%s config: unknown subcommand %q\n", binary, args[0])
		return 2
	}
	return runConfigCheck(args[1:], os.Environ(), stdout, stderr)
}

// runConfigCheck loads and validates the configuration exactly like the
// server will and prints the effective values with their source. Exit code
// 0 = valid, 1 = invalid, 2 = usage error.
func runConfigCheck(args, environ []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet(binary+" config check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := configFlag(fs)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() > 0 {
		_, _ = fmt.Fprintf(stderr, "%s config check: unexpected argument %q\n", binary, fs.Arg(0))
		return 2
	}
	cfg, src, err := config.Load(configPath(*path, environ), environ)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "%v\n", err)
		return 1
	}
	printConfig(stdout, cfg, src)
	checkTLSIssuers(cfg, stdout, stderr)
	if !checkNotify(cfg, stdout, stderr) {
		return 1
	}
	_, _ = fmt.Fprintln(stdout, "\nConfiguration is valid.")
	return 0
}

// checkTLSIssuers names a root CA in admin.tls_issuer or acme.tls_issuer, read
// from the CA database when it is readable. It is a warning on stderr, not
// an invalid config (exit 0): the server starts with it and serves the
// bootstrap certificate (owner 2026-10-24) – and install.sh, which hides
// stdout, still shows it.
func checkTLSIssuers(cfg config.Config, stdout, stderr io.Writer) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	problems, err := server.TLSIssuerProblems(ctx, cfg)
	if err != nil {
		_, _ = fmt.Fprintf(stdout, "\nNot checked: whether the CA of tls_issuer is a root – the CA database can't be read (%v).\n", err)
		return
	}
	for _, p := range problems {
		_, _ = fmt.Fprintf(stderr, "\nWarning: %s. Until then the listener serves the bootstrap certificate.\n", p)
	}
	agentCA, err := server.AgentCAProblems(ctx, cfg)
	if err != nil {
		_, _ = fmt.Fprintf(stdout, "\nNot checked: the agent CA – the CA database can't be read (%v).\n", err)
		return
	}
	for _, p := range agentCA {
		_, _ = fmt.Fprintf(stderr, "\nWarning: %s. Until then agents can't enroll.\n", p)
	}
}

// configFlag registers --config on a subcommand's flag set.
func configFlag(fs *flag.FlagSet) *string {
	return fs.String("config", "", "config file (default: $"+config.EnvConfigFile+", then "+
		config.DefaultPath(runtime.GOOS, os.Getenv)+")")
}

// configPath picks the config file: --config, then MYOWNPKI_CONFIG, then
// the platform default.
func configPath(flagValue string, environ []string) string {
	if flagValue != "" {
		return flagValue
	}
	if p := lookupEnv(environ, config.EnvConfigFile); p != "" {
		return p
	}
	return config.DefaultPath(runtime.GOOS, os.Getenv)
}

func lookupEnv(environ []string, name string) string {
	for _, kv := range environ {
		if k, v, ok := strings.Cut(kv, "="); ok && k == name {
			return v
		}
	}
	return ""
}

// printConfig shows the effective configuration; values set by an
// environment variable are marked, so an admin sees why a value differs
// from the file.
func printConfig(w io.Writer, cfg config.Config, src config.Source) {
	from := func(env string) string {
		if slices.Contains(src.Env, env) {
			return "   (from " + env + ")"
		}
		return ""
	}
	tls := "self-signed bootstrap certificate"
	switch {
	case cfg.Admin.TLSCertFile != "":
		tls = cfg.Admin.TLSCertFile + " + " + cfg.Admin.TLSKeyFile
	case cfg.Admin.TLSIssuer != "":
		tls = "issued by CA " + cfg.Admin.TLSIssuer + " for " + cfg.Admin.TLSNames + " (bootstrap certificate until the unseal)"
	}
	public := cfg.Public.Listen
	if public == "" {
		public = "disabled"
	}
	rows := [][2]string{
		{"data_dir", cfg.DataDir + from("MYOWNPKI_DATA_DIR")},
		{"log.level", cfg.Log.Level + from("MYOWNPKI_LOG_LEVEL")},
		{"log.format", cfg.Log.Format + from("MYOWNPKI_LOG_FORMAT")},
		{"admin.listen", cfg.Admin.Listen + from("MYOWNPKI_ADMIN_LISTEN")},
		{"admin.tls", tls + from("MYOWNPKI_ADMIN_TLS_CERT_FILE") + from("MYOWNPKI_ADMIN_TLS_KEY_FILE") + from("MYOWNPKI_ADMIN_TLS_ISSUER")},
		{"public.listen", public + from("MYOWNPKI_PUBLIC_LISTEN")},
	}
	switch {
	case cfg.ACME.BaseURL == "":
		rows = append(rows, [2]string{"acme", "off (acme.base_url is empty)"})
	case cfg.ACME.DirectTLS():
		rows = append(rows, [2]string{"acme", cfg.ACME.BaseURL + from("MYOWNPKI_ACME_BASE_URL")},
			[2]string{"acme.listen", cfg.ACME.Listen + " – its own TLS, issued by CA " + cfg.ACME.TLSIssuer + from("MYOWNPKI_ACME_TLS_ISSUER")})
	default:
		rows = append(rows, [2]string{"acme", cfg.ACME.BaseURL + from("MYOWNPKI_ACME_BASE_URL")},
			[2]string{"acme.listen", cfg.ACME.Listen + " – plain HTTP for the reverse proxy " + cfg.ACME.TrustedProxies + from("MYOWNPKI_ACME_LISTEN")})
	}
	if cfg.Agent.Enabled() {
		rows = append(rows, [2]string{"agent", cfg.Agent.BaseURL + from("MYOWNPKI_AGENT_BASE_URL")},
			[2]string{"agent.listen", cfg.Agent.Listen + " – mTLS, issued by CA " + cfg.Agent.TLSIssuer + ", agents from CA " + cfg.Agent.CA +
				from("MYOWNPKI_AGENT_LISTEN") + from("MYOWNPKI_AGENT_TLS_ISSUER") + from("MYOWNPKI_AGENT_CA")})
	} else {
		rows = append(rows, [2]string{"agent", "off (agent.base_url is empty)"})
	}
	_, _ = fmt.Fprintf(w, "Config file: %s\n\n", src.File)
	for _, r := range rows {
		_, _ = fmt.Fprintf(w, "  %-14s %s\n", r[0], r[1])
	}
	printMonitoring(w, cfg, src)
}

// printMonitoring shows the notification channels and the alert thresholds
// in effect: e-mail by server, security and number of recipients, the
// webhook by host only (its path or query may hold a token), never a
// password, a secret or a file's content.
func printMonitoring(w io.Writer, cfg config.Config, src config.Source) {
	from := func(envs ...string) string {
		var out string
		for _, env := range envs {
			if slices.Contains(src.Env, env) {
				out += "   (from " + env + ")"
			}
		}
		return out
	}
	email := "off (notify.email.smtp is empty)"
	if e := cfg.Notify.Email; e.Enabled() {
		email = fmt.Sprintf("%s, %s, %s", e.SMTP, e.Mode(), plural(len(e.Recipients()), "recipient"))
	}
	hook := "off (notify.webhook.url is empty)"
	if cfg.Notify.Webhook.Enabled() {
		hook = "no valid URL"
		if u, err := config.WebhookURL(cfg.Notify.Webhook.URL); err == nil {
			hook = u.Host + ", signed with HMAC-SHA256"
		}
	}
	rows := [][2]string{
		{"e-mail", email + from("MYOWNPKI_NOTIFY_EMAIL_SMTP", "MYOWNPKI_NOTIFY_EMAIL_SECURITY", "MYOWNPKI_NOTIFY_EMAIL_TO")},
		{"webhook", hook + from("MYOWNPKI_NOTIFY_WEBHOOK_URL")},
	}
	_, _ = fmt.Fprintf(w, "\nNotifications (notify:)\n")
	for _, r := range rows {
		_, _ = fmt.Fprintf(w, "  %-16s %s\n", r[0], r[1])
	}
	v, err := cfg.Monitor.Values()
	if err != nil {
		return // validated by Load
	}
	days := func(d time.Duration) string { return plural(int(d/(24*time.Hour)), "day") }
	rows = [][2]string{
		{"certificates", "warning " + days(v.ExpiryWarn) + ", critical " + days(v.ExpiryCrit) + " before they end" + from("MYOWNPKI_MONITOR_EXPIRY_DAYS")},
		{"CA certificates", "warning " + days(v.CAWarn) + ", critical " + days(v.CACrit) + " before they end" + from("MYOWNPKI_MONITOR_CA_EXPIRY_DAYS")},
		{"sealed server", "alert after " + shortDuration(v.SealedAfter) + from("MYOWNPKI_MONITOR_SEALED_AFTER")},
		{"silent agent", "alert after " + shortDuration(v.AgentSilent) + from("MYOWNPKI_MONITOR_AGENT_SILENT_AFTER")},
		{"reminder", "every " + shortDuration(v.RepeatEvery) + " while an alert is open" + from("MYOWNPKI_MONITOR_REPEAT_EVERY")},
	}
	if sv, serr := cfg.Monitor.Scan(); serr == nil {
		scan := "off (monitor.scan_interval) – endpoints are kept, nothing connects" + from("MYOWNPKI_MONITOR_SCAN_INTERVAL")
		if !sv.Off() {
			scan = "every " + shortDuration(sv.Interval) + ", timeout " + shortDuration(sv.Timeout) +
				from("MYOWNPKI_MONITOR_SCAN_INTERVAL", "MYOWNPKI_MONITOR_SCAN_TIMEOUT")
		}
		ports := make([]string, len(sv.Ports))
		for i, p := range sv.Ports {
			ports[i] = strconv.Itoa(p)
		}
		limits := fmt.Sprintf("%s, unreachable after %s, mismatch after %s", plural(sv.MaxEndpoints, "endpoint"),
			plural(sv.UnreachableAfter, "failed scan"), shortDuration(sv.MismatchAfter))
		rows = append(rows,
			[2]string{"TLS scan", scan},
			[2]string{"scan ports", strings.Join(ports, ", ") + from("MYOWNPKI_MONITOR_SCAN_PORTS")},
			[2]string{"scan limits", limits + from("MYOWNPKI_MONITOR_SCAN_MAX_ENDPOINTS", "MYOWNPKI_MONITOR_SCAN_UNREACHABLE_AFTER", "MYOWNPKI_MONITOR_SCAN_MISMATCH_AFTER")},
		)
	}
	_, _ = fmt.Fprintf(w, "\nAlert thresholds (monitor:)\n")
	for _, r := range rows {
		_, _ = fmt.Fprintf(w, "  %-16s %s\n", r[0], r[1])
	}
}

// checkNotify reports what would stop a message at the first send. A
// secret or CA file that is missing, unreadable or empty is an error (exit
// 1): every digest would fail and be dropped after its retries – while the
// server itself starts and keeps the alerts. No channel at all is only a
// warning, on stdout: it is the state of every new installation, and stderr
// is where install.sh looks for what is wrong.
func checkNotify(cfg config.Config, stdout, stderr io.Writer) bool {
	if !cfg.Notify.Email.Enabled() && !cfg.Notify.Webhook.Enabled() {
		_, _ = fmt.Fprintln(stdout, "\nWarning: no notification channel is configured – alerts are shown in the UI, nobody is notified. Set notify.email or notify.webhook.")
		return true
	}
	problems := cfg.NotifyFileProblems()
	for _, p := range problems {
		_, _ = fmt.Fprintf(stderr, "\nError: %s.\n", p)
	}
	if len(problems) > 0 {
		_, _ = fmt.Fprintln(stderr, "\nNotifications would fail until this is fixed. Check as the service user; the files are read at each send, so no restart is needed.")
	}
	return len(problems) == 0
}

func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

// shortDuration prints 10m instead of 10m0s and 24h instead of 24h0m0s.
func shortDuration(d time.Duration) string {
	s := d.String()
	if strings.HasSuffix(s, "m0s") {
		s = strings.TrimSuffix(s, "0s")
	}
	if strings.HasSuffix(s, "h0m") {
		s = strings.TrimSuffix(s, "0m")
	}
	return s
}
