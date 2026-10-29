package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Der-Felix/MyOwnPKI/internal/clock"
	"github.com/Der-Felix/MyOwnPKI/internal/config"
	"github.com/Der-Felix/MyOwnPKI/internal/notify"
	"github.com/Der-Felix/MyOwnPKI/internal/server"
	"github.com/Der-Felix/MyOwnPKI/internal/version"
)

// runNotify handles `myownpki notify test`: one test message through every
// configured channel, with the server's configuration and secret files –
// run it as the service user, so it reads the files the server reads.
func runNotify(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	usage := func() {
		_, _ = fmt.Fprintf(stderr, "Usage:\n  %s notify test [--config FILE] [--channel email|webhook]\n", binary)
	}
	if len(args) == 0 || args[0] != "test" {
		usage()
		if len(args) > 0 && args[0] != "-h" && args[0] != "--help" {
			_, _ = fmt.Fprintf(stderr, "%s notify: unknown subcommand %q\n", binary, args[0])
		}
		return 2
	}
	fs := flag.NewFlagSet(binary+" notify test", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := configFlag(fs)
	only := fs.String("channel", "", "send only through this channel: email or webhook")
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() > 0 || (*only != "" && *only != "email" && *only != "webhook") {
		usage()
		return 2
	}
	environ := os.Environ()
	cfg, _, err := config.Load(configPath(*path, environ), environ)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "%v\n", err)
		return 1
	}
	hostname, _ := os.Hostname()
	var channels []notify.Channel
	for _, c := range server.NotifyChannels(cfg, hostname, version.Get().Version) {
		if *only == "" || c.Name() == *only {
			channels = append(channels, c)
		}
	}
	if len(channels) == 0 {
		_, _ = fmt.Fprintln(stderr, "No notification channel is configured: set notify.email.smtp or notify.webhook.url (or choose another --channel).")
		return 1
	}
	digest := notify.TestDigest(hostname, clock.System{}.Now())
	failed := 0
	for _, c := range channels {
		if err := c.Send(ctx, digest); err != nil {
			failed++
			_, _ = fmt.Fprintf(stderr, "%-8s FAILED: %v\n", c.Name(), err)
			continue
		}
		_, _ = fmt.Fprintf(stdout, "%-8s sent%s\n", c.Name(), target(cfg, c.Name()))
	}
	if failed > 0 {
		return 1
	}
	return 0
}

// target names where the test went, without secrets.
func target(cfg config.Config, channel string) string {
	switch channel {
	case "email":
		return " to " + strings.Join(cfg.Notify.Email.Recipients(), ", ") + " via " + cfg.Notify.Email.SMTP
	case "webhook":
		if u, err := config.WebhookURL(cfg.Notify.Webhook.URL); err == nil {
			return " to " + u.Host
		}
	}
	return ""
}
