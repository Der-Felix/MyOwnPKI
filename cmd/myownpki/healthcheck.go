package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/config"
	"github.com/Der-Felix/MyOwnPKI/internal/server"
)

// runHealthcheck handles `myownpki healthcheck` (PHASE1 step 20): it asks
// the admin listener's /healthz on this machine and exits 0 when the
// answer is "ok", 1 otherwise. Made for the container HEALTHCHECK and for
// monitoring: no curl in a distroless image.
//
// The connection is checked against the certificate file the server
// serves (bootstrap or operator certificate), not against a CA: the
// bootstrap certificate is self-signed, and a check that skipped TLS
// verification would talk to anything that listens on the port.
func runHealthcheck(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fset := flag.NewFlagSet(binary+" healthcheck", flag.ContinueOnError)
	fset.SetOutput(stderr)
	path := configFlag(fset)
	timeout := fset.Duration("timeout", 5*time.Second, "give up after this long")
	if err := fset.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if fset.NArg() != 0 {
		_, _ = fmt.Fprintf(stderr, "%s: no arguments expected, got %q\n", fset.Name(), fset.Args())
		return exitUsage
	}
	cfg, code := loadConfig(*path, os.Environ(), stderr)
	if code >= 0 {
		return code
	}
	if err := healthcheck(ctx, cfg, *timeout); err != nil {
		_, _ = fmt.Fprintf(stderr, "unhealthy: %v\n", err)
		return exitProblem
	}
	_, _ = fmt.Fprintln(stdout, "ok")
	return exitOK
}

func healthcheck(ctx context.Context, cfg config.Config, timeout time.Duration) error {
	// One file, or with admin.tls_issuer two: the bootstrap and the issued
	// certificate (the server switches between them without a restart). The
	// issued one is missing until the first unseal.
	files := server.AdminCertFiles(cfg)
	var want [][]byte
	for i, f := range files {
		der, ferr := firstCertificate(f)
		switch {
		case ferr == nil:
			want = append(want, der)
		case i == 0 || !errors.Is(ferr, fs.ErrNotExist):
			return ferr
		}
	}
	addr, err := localAddr(cfg.Admin.Listen)
	if err != nil {
		return err
	}
	pinned := func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 || !slices.ContainsFunc(want, func(w []byte) bool { return bytes.Equal(cs.PeerCertificates[0].Raw, w) }) {
			return fmt.Errorf("the admin listener serves another certificate than %s (changed without a restart?)", strings.Join(files, " or "))
		}
		return nil
	}
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy: nil, // never through a proxy: the check is about this machine
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				// The chain is not checked against a CA; VerifyConnection pins
				// the exact certificate from the file instead.
				InsecureSkipVerify: true, // #nosec G402 -- pinned by VerifyConnection
				VerifyConnection:   pinned,
			},
		},
	}
	defer client.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+addr+"/healthz", nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("%s: %w (is the server running, and is 127.0.0.1 in admin.allowed_networks?)", addr, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64))
	if err != nil {
		return fmt.Errorf("%s: %w", addr, err)
	}
	if resp.StatusCode != http.StatusOK || string(body) != "ok\n" {
		return fmt.Errorf("%s/healthz answered %d %q", addr, resp.StatusCode, body)
	}
	return nil
}

// firstCertificate reads the first certificate of a PEM file (the leaf).
func firstCertificate(path string) ([]byte, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- the configured certificate file
	if err != nil {
		return nil, fmt.Errorf("admin certificate: %w", err)
	}
	for {
		var b *pem.Block
		b, data = pem.Decode(data)
		if b == nil {
			return nil, fmt.Errorf("admin certificate %s: no certificate in the file", path)
		}
		if b.Type == "CERTIFICATE" {
			return b.Bytes, nil
		}
	}
}

// localAddr turns admin.listen into an address on this machine: a listener
// on every interface is asked on loopback.
func localAddr(listen string) (string, error) {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return "", fmt.Errorf("admin.listen %q: %w", listen, err)
	}
	switch host {
	case "", "0.0.0.0":
		host = "127.0.0.1"
	case "::":
		host = "::1"
	}
	return net.JoinHostPort(host, port), nil
}
