package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/Der-Felix/MyOwnPKI/internal/config"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/server"
	"github.com/Der-Felix/MyOwnPKI/internal/version"
)

// unsealTries at the console; after that the server stays sealed (the
// keyring's lockout from step 6 applies as well).
const unsealTries = 3

// runServer is `myownpki serve`: both listeners with TLS on the admin side,
// the background jobs, and – with --unseal – the passphrase prompt once the
// listeners run, so CRLs are served while the operator types.
func runServer(ctx context.Context, path string, unseal bool, environ []string, stderr io.Writer) int {
	if unseal && !keys.IsTerminal(os.Stdin) {
		_, _ = fmt.Fprintf(stderr, "%s serve --unseal needs a terminal – without one, unseal through the API (step 13)\n", binary)
		return exitUsage
	}
	cfg, _, err := config.Load(configPath(path, environ), environ)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "%v\n", err)
		return exitProblem
	}
	log := newLogger(cfg, stderr)
	srv, err := server.Open(ctx, server.Options{Config: cfg, Log: log, Version: version.Get().String(binary)})
	if err != nil {
		log.Error("start", slog.Any("error", err))
		return exitProblem
	}
	if err := srv.Listen(ctx); err != nil {
		log.Error("start", slog.Any("error", err))
		_ = srv.Shutdown(context.WithoutCancel(ctx))
		return exitProblem
	}
	if keys.IsTerminal(os.Stderr) {
		printAdminBanner(stderr, srv)
	}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx) }()
	if unseal {
		consoleUnseal(ctx, srv, stderr)
	}
	if err := <-done; err != nil {
		log.Error("server stopped", slog.Any("error", err))
		return exitProblem
	}
	return exitOK
}

// consoleUnseal asks for the passphrase without echo. A wrong one leaves
// the server running sealed; the keyring's lockout applies.
func consoleUnseal(ctx context.Context, srv *server.Server, stderr io.Writer) {
	for i := range unsealTries {
		pass, err := readHidden("Unseal passphrase: ", stderr)
		if err != nil || ctx.Err() != nil {
			return
		}
		err = srv.Unseal(ctx, pass, consoleWho())
		var locked *keys.LockedError
		switch {
		case err == nil:
			_, _ = fmt.Fprintln(stderr, "Unsealed.")
			return
		case errors.As(err, &locked):
			_, _ = fmt.Fprintf(stderr, "%v – the server keeps running sealed.\n", err)
			return
		case i < unsealTries-1:
			_, _ = fmt.Fprintf(stderr, "%v\n", err)
		default:
			_, _ = fmt.Fprintf(stderr, "%v – the server keeps running sealed.\n", err)
		}
	}
}

func newLogger(cfg config.Config, w io.Writer) *slog.Logger {
	var level slog.Level
	_ = level.UnmarshalText([]byte(cfg.Log.Level))
	opts := &slog.HandlerOptions{Level: level, ReplaceAttr: utcTime}
	if cfg.Log.Format == "text" {
		return slog.New(slog.NewTextHandler(w, opts))
	}
	return slog.New(slog.NewJSONHandler(w, opts))
}

func printAdminBanner(w io.Writer, srv *server.Server) {
	ci := srv.ServedAdminCertificate()
	_, _ = fmt.Fprintf(w, `
  ==============================================================
    Admin:  https://%s/
    TLS certificate (%s), SHA-256 fingerprint – compare it
    when the browser asks:
      %s
    Public: %s
  ==============================================================

`, srv.AdminAddr(), ci.Source, ci.Fingerprint, srv.PublicAddr())
}
