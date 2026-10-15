package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/web"
)

const defaultDevListen = "127.0.0.1:9443"

var (
	devLoopbackV4 = netip.MustParseAddr("127.0.0.1")
	devLoopbackV6 = netip.MustParseAddr("::1")
)

// runServe starts the server (runServer: TLS, both listeners, jobs) or, with
// --dev, the UI prototype: plain HTTP,
// no login, bound to the loopback address. --dev exists only as a command-line
// flag – never as a config file setting – so it can't be switched on by
// accident through a copied config.
func runServe(ctx context.Context, args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet(binary+" serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dev := fs.Bool("dev", false, "development mode: plain HTTP, no authentication, loopback only")
	listen := fs.String("listen", defaultDevListen, "listen address in dev mode: 127.0.0.1:<port> or [::1]:<port>")
	path := configFlag(fs)
	unseal := fs.Bool("unseal", false, "ask for the unseal passphrase on this terminal once the listeners run")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() > 0 {
		_, _ = fmt.Fprintf(stderr, "%s serve: unexpected argument %q\n", binary, fs.Arg(0))
		return 2
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	if !*dev {
		if set["listen"] {
			_, _ = fmt.Fprintf(stderr, "%s serve: --listen is for --dev only; the listeners come from admin.listen and public.listen\n", binary)
			return 2
		}
		return runServer(ctx, *path, *unseal, os.Environ(), stderr)
	}
	if set["config"] || set["unseal"] {
		_, _ = fmt.Fprintf(stderr, "%s serve --dev: no --config or --unseal – dev mode shows the prototype on sample data\n", binary)
		return 2
	}
	if err := validateDevListen(*listen); err != nil {
		_, _ = fmt.Fprintf(stderr, "%s serve: --listen: %v\n", binary, err)
		return 2
	}

	log := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelInfo, ReplaceAttr: utcTime}))
	handler, err := web.NewHandler(web.Options{Dev: true, Logger: log})
	if err != nil {
		log.Error("build handler", slog.Any("error", err))
		return 1
	}

	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", *listen)
	if err != nil {
		log.Error("listen", slog.String("addr", *listen), slog.Any("error", err))
		return 1
	}
	printDevBanner(stderr, ln.Addr().String())

	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	return serveUntilDone(ctx, srv, ln, log)
}

func serveUntilDone(ctx context.Context, srv *http.Server, ln net.Listener, log *slog.Logger) int {
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()

	select {
	case err := <-errc:
		log.Error("server stopped", slog.Any("error", err))
		return 1
	case <-ctx.Done():
	}

	log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Error("shutdown", slog.Any("error", err))
		return 1
	}
	if err := <-errc; err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("server stopped", slog.Any("error", err))
		return 1
	}
	return 0
}

// validateDevListen accepts only the loopback IP literals 127.0.0.1 and ::1.
// Host names – even "localhost" – are rejected: a name can resolve to a
// non-loopback address (hosts file, DNS), which would expose an
// unauthenticated server to the network.
func validateDevListen(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("%q is not host:port: %w", addr, err)
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("%q must be the IP address 127.0.0.1 or ::1, not a host name", host)
	}
	if ip.Zone() != "" || (ip != devLoopbackV4 && ip != devLoopbackV6) {
		return fmt.Errorf("%s is not allowed in dev mode: only 127.0.0.1 or ::1 (no TLS, no login)", host)
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil || n == 0 {
		return fmt.Errorf("port %q must be a number between 1 and 65535", port)
	}
	return nil
}

// utcTime writes log timestamps in UTC, like everything else (go-conventions.md),
// so logs from servers in different time zones line up.
func utcTime(_ []string, a slog.Attr) slog.Attr {
	if a.Key == slog.TimeKey && a.Value.Kind() == slog.KindTime {
		a.Value = slog.TimeValue(a.Value.Time().UTC())
	}
	return a
}

func printDevBanner(w io.Writer, addr string) {
	_, _ = fmt.Fprintf(w, `
  ==============================================================
    DEV MODE – no TLS, no auth
    Component gallery: http://%s/design
    Only reachable from this machine. Stop with Ctrl+C.
  ==============================================================

`, addr)
}
