// Command myownpki-agent keeps certificates in place on a host
// (docs/PHASE3.md): it enrolls with the MyOwnPKI server (ADR-18), keeps its
// agent certificate, and gets and deploys certificates by ACME.
//
//	myownpki-agent enroll [--token-file FILE]   enroll this host (once)
//	myownpki-agent run                          the service (systemd)
//	myownpki-agent status                       what the agent knows about itself
//	myownpki-agent config check                 check agent.yaml
//	myownpki-agent --version
//
// Released for Linux; it builds for Windows, macOS and FreeBSD too.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/agent"
	"github.com/Der-Felix/MyOwnPKI/internal/version"
)

const binary = "myownpki-agent"

// EnvConfig names agent.yaml when --config is not given.
const EnvConfig = "MYOWNPKI_AGENT_CONFIG"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

// run parses the arguments and returns the process exit code
// (0 success, 1 failure, 2 usage error).
func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet(binary, flag.ContinueOnError)
	fs.SetOutput(stderr)
	showVersion := fs.Bool("version", false, "print version information and exit")
	fs.Usage = func() {
		_, _ = fmt.Fprintf(stderr, "usage: %s enroll [--token-file FILE] | run | status | config check  [--config FILE]\n", binary)
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *showVersion {
		_, _ = fmt.Fprintln(stdout, version.Get().String(binary))
		return 0
	}
	rest := fs.Args()
	if len(rest) == 0 {
		fs.Usage()
		return 2
	}
	switch rest[0] {
	case "enroll":
		return cmdEnroll(ctx, rest[1:], stdout, stderr)
	case "run":
		return cmdRun(ctx, rest[1:], stderr)
	case "status":
		return cmdStatus(rest[1:], stdout, stderr)
	case "config":
		if len(rest) > 1 && rest[1] == "check" {
			return cmdConfigCheck(rest[2:], stdout, stderr)
		}
	}
	fs.Usage()
	return 2
}

// subFlags is the flag set of a command with --config.
func subFlags(name string, stderr io.Writer) (*flag.FlagSet, *string) {
	fs := flag.NewFlagSet(binary+" "+name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	def := os.Getenv(EnvConfig)
	if def == "" {
		def = agent.DefaultConfigPath
	}
	return fs, fs.String("config", def, "agent.yaml (default $"+EnvConfig+", then "+agent.DefaultConfigPath+")")
}

func load(path string, stderr io.Writer) (*agent.Config, *slog.Logger, bool) {
	cfg, err := agent.LoadConfig(path)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return nil, nil, false
	}
	var level slog.Level
	_ = level.UnmarshalText([]byte(cfg.LogLevel))
	return cfg, slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: level})), true
}

func cmdEnroll(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs, path := subFlags("enroll", stderr)
	tokenFile := fs.String("token-file", "", "file with the join token (read once; delete it afterwards)")
	if fs.Parse(args) != nil || fs.NArg() != 0 {
		return 2
	}
	cfg, log, ok := load(*path, stderr)
	if !ok {
		return 1
	}
	token := ""
	if *tokenFile != "" {
		data, err := os.ReadFile(*tokenFile)
		if err != nil {
			_, _ = fmt.Fprintln(stderr, "token file:", err)
			return 1
		}
		token = strings.TrimSpace(string(data))
	}
	a, err := agent.New(cfg, log, version.Get().Version)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	res, err := a.Enroll(ctx, token)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	switch {
	case res.Admitted():
		_, _ = fmt.Fprintf(stdout, "Enrolled %s as agent %s. Start the service: systemctl enable --now myownpki-agent\n", cfg.Hostname, res.AgentID)
	case strings.HasSuffix(res.State.String(), "DENIED"), strings.HasSuffix(res.State.String(), "EXPIRED"):
		_, _ = fmt.Fprintf(stderr, "Enrollment of %s ended: %s\n", cfg.Hostname, res.Message)
		return 1
	default:
		_, _ = fmt.Fprintf(stdout, "Enrollment of %s waits: %s\nThe service finishes it once it is approved: systemctl enable --now myownpki-agent\n", cfg.Hostname, res.Message)
	}
	return 0
}

func cmdRun(ctx context.Context, args []string, stderr io.Writer) int {
	fs, path := subFlags("run", stderr)
	if fs.Parse(args) != nil || fs.NArg() != 0 {
		return 2
	}
	cfg, log, ok := load(*path, stderr)
	if !ok {
		return 1
	}
	a, err := agent.New(cfg, log, version.Get().Version)
	if err != nil {
		log.Error("start", slog.Any("error", err))
		return 1
	}
	log.Info("myownpki-agent starting", slog.String("version", version.Get().Version), slog.String("hostname", cfg.Hostname), slog.String("server", cfg.Server))
	if err := a.Run(ctx); err != nil {
		log.Error("stopped", slog.Any("error", err))
		return 1
	}
	log.Info("stopped")
	return 0
}

func cmdStatus(args []string, stdout, stderr io.Writer) int {
	fs, path := subFlags("status", stderr)
	if fs.Parse(args) != nil || fs.NArg() != 0 {
		return 2
	}
	cfg, log, ok := load(*path, stderr)
	if !ok {
		return 1
	}
	a, err := agent.New(cfg, log, version.Get().Version)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	s := a.Status()
	_, _ = fmt.Fprintf(stdout, "hostname     %s\nserver       %s\n", s.Hostname, cfg.Server)
	if s.Enrolled {
		_, _ = fmt.Fprintf(stdout, "agent        %s\ncertificate  serial %s, valid until %s\n", s.AgentID, s.Serial, s.NotAfter.Format(time.DateTime+" MST"))
	} else {
		_, _ = fmt.Fprintln(stdout, "agent        not enrolled")
	}
	if s.Enrollment != "" {
		_, _ = fmt.Fprintf(stdout, "enrollment   %s\n", s.Enrollment)
	}
	return 0
}

func cmdConfigCheck(args []string, stdout, stderr io.Writer) int {
	fs, path := subFlags("config check", stderr)
	if fs.Parse(args) != nil || fs.NArg() != 0 {
		return 2
	}
	cfg, err := agent.LoadConfig(*path)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "Config file: %s\n\n  hostname      %s\n  server        %s\n  enrollment    %s %s\n  deployments   %d\n  hooks         %d\n  paths         %s\n\nConfiguration is valid.\n",
		*path, cfg.Hostname, cfg.Server, cfg.Enrollment.Challenge, cfg.Enrollment.Webroot, len(cfg.Deployments), len(cfg.Hooks), strings.Join(cfg.Paths, ", "))
	return 0
}
