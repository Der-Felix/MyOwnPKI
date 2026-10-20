package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/ca/legacy"
	"github.com/Der-Felix/MyOwnPKI/internal/ca/preset"
	"github.com/Der-Felix/MyOwnPKI/internal/clock"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/store"
)

// runImport handles `myownpki import legacy DIR` (PHASE1 step 15): a
// legacy/pki.sh directory into the default tenant. The API and the UI get
// import jobs in steps 18/19.
func runImport(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	usage := func() {
		_, _ = fmt.Fprintf(stderr, "Usage:\n  %s import legacy DIR [--config FILE] [--dry-run] [--base-url URL] [--root-key offline|online]\n"+
			"      DIR is the pki.sh directory (the one with root/, intermediate/, issued/).\n"+
			"      Reads the unseal passphrase (not for --dry-run); encrypted keys of pki.sh open with\n"+
			"      PKI_CA_PASS_<NAME>, PKI_CA_PASS and PKI_KEY_PASS as for pki.sh.\n", binary)
	}
	if len(args) == 0 || args[0] != "legacy" {
		if len(args) > 0 && (args[0] == "-h" || args[0] == "--help") {
			usage()
			return exitOK
		}
		usage()
		return exitUsage
	}
	uio := userIO{stdin: os.Stdin, stdinTerminal: keys.IsTerminal(os.Stdin), stdoutTerminal: keys.IsTerminal(os.Stdout), stdout: stdout, stderr: stderr,
		hidden: func(p string) ([]byte, error) { return readHidden(p, stderr) }}
	return runImportLegacy(ctx, args[1:], os.Environ(), uio)
}

func runImportLegacy(ctx context.Context, args, environ []string, uio userIO) int {
	fset := flag.NewFlagSet(binary+" import legacy", flag.ContinueOnError)
	fset.SetOutput(uio.stderr)
	path := configFlag(fset)
	dryRun := fset.Bool("dry-run", false, "check everything and show what would be imported; writes nothing")
	baseURL := fset.String("base-url", "", "public base URL for new certificates (default: AIA_BASE_URL of pki.conf)")
	rootKey := fset.String("root-key", "offline", "offline: import the root's certificate only (pki.sh stays the offline root); online: import its key encrypted")
	dir, code := parseUserArgs(fset, args, uio.stderr)
	if code >= 0 {
		return code
	}
	if *rootKey != "offline" && *rootKey != "online" {
		_, _ = fmt.Fprintf(uio.stderr, "--root-key: want offline or online, got %q\n", *rootKey)
		return exitUsage
	}
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		_, _ = fmt.Fprintf(uio.stderr, "%s is not a directory\n", dir)
		return exitUsage
	}

	pw := legacy.Passphrases{
		CA: func(name string) []byte {
			if v := lookupEnv(environ, "PKI_CA_PASS_"+legacy.EnvName(name)); v != "" {
				return []byte(v)
			}
			return []byte(lookupEnv(environ, "PKI_CA_PASS"))
		},
		Leaf: []byte(lookupEnv(environ, "PKI_KEY_PASS")),
	}
	src, err := legacy.Read(os.DirFS(dir), pw)
	if err != nil {
		_, _ = fmt.Fprintf(uio.stderr, "%v\n", err)
		return exitProblem
	}

	var secret []byte
	if !*dryRun {
		if uio.stdinTerminal {
			secret, err = uio.hidden("Unseal passphrase: ")
		} else {
			secret, err = readSecretLine(uio.stdin)
		}
		if err != nil {
			_, _ = fmt.Fprintf(uio.stderr, "%v\n", err)
			return exitUsage
		}
		defer clear(secret)
	}

	d, code := openConsoleDBs(ctx, *path, environ, uio)
	if code >= 0 {
		return code
	}
	defer d.close()
	l := store.Layout{DataDir: d.cfg.DataDir}
	open := func(kind store.Kind) (*store.DB, error) {
		file, ferr := l.TenantDB(store.DefaultTenant, kind)
		if ferr != nil {
			return nil, ferr
		}
		return store.Open(ctx, file)
	}
	pkiDB, err := open(store.KindPKI)
	if err != nil {
		_, _ = fmt.Fprintf(uio.stderr, "%v\n", err)
		return exitProblem
	}
	defer func() { _ = pkiDB.Close() }()
	ta, err := open(store.KindAudit)
	if err != nil {
		_, _ = fmt.Fprintf(uio.stderr, "%v\n", err)
		return exitProblem
	}
	defer func() { _ = ta.Close() }()
	presets, err := preset.Builtin()
	if err != nil {
		_, _ = fmt.Fprintf(uio.stderr, "%v\n", err)
		return exitProblem
	}

	who := consoleWho()
	ring := keys.New(d.sys.Write, d.ia.Write, clock.System{})
	scope := store.TenantScope(store.DefaultTenant)
	e := &ca.Engine{PKI: pkiDB.Write, Audit: ta.Write, Scope: scope, Keys: ring, Presets: presets, Clock: clock.System{}}
	if !*dryRun {
		if uerr := ring.Unseal(ctx, secret, who); uerr != nil {
			_, _ = fmt.Fprintf(uio.stderr, "%v\n", uerr)
			d.deliver(ctx, uio.stderr)
			return exitProblem
		}
	}
	rep, err := e.ImportLegacy(ctx, ca.LegacyImportRequest{PKI: src, BaseURL: *baseURL, RootOnline: *rootKey == "online", DryRun: *dryRun, Who: who})
	if !*dryRun {
		if serr := ring.Seal(ctx, who); serr != nil {
			_, _ = fmt.Fprintf(uio.stderr, "seal: %v\n", serr)
		}
		tenant := &audit.Deliverer{
			Routes: []audit.Route{{Source: "pki", From: pkiDB.Write, To: ta.Write, Scope: scope}},
			Clock:  clock.System{}, Log: slog.New(slog.DiscardHandler),
		}
		if _, derr := tenant.DeliverPending(ctx); derr != nil {
			_, _ = fmt.Fprintf(uio.stderr, "note: the audit entries stay in the outbox until the server delivers them: %v\n", derr)
		}
		d.deliver(ctx, uio.stderr)
	}
	printImportReport(uio.stdout, rep)
	var denied *ca.DeniedError
	switch {
	case errors.As(err, &denied):
		_, _ = fmt.Fprintf(uio.stdout, "\nNot imported – fix the problems above (nothing was written).\n")
		return exitProblem
	case err != nil:
		_, _ = fmt.Fprintf(uio.stderr, "%v\n", err)
		return exitProblem
	case *dryRun:
		_, _ = fmt.Fprintf(uio.stdout, "\nDry run: nothing was written. Run again without --dry-run to import.\n")
	default:
		_, _ = fmt.Fprintf(uio.stdout, "\nImported. Keep the pki.sh directory as it is: it is the offline root and the evidence of the old PKI.\n")
	}
	return exitOK
}

func printImportReport(w io.Writer, rep *ca.LegacyImportReport) {
	if rep == nil {
		return
	}
	_, _ = fmt.Fprintf(w, "Base URL for new certificates: %s", orDash(rep.BaseURL))
	if rep.LegacyURLs {
		_, _ = fmt.Fprint(w, " (the pki.sh URLs <base>/<name>.crt|.crl stay served)")
	}
	_, _ = fmt.Fprintln(w)
	for _, c := range rep.CAs {
		_, _ = fmt.Fprintf(w, "CA %-16s %-12s %-16s %4d certificates, %d revoked, last CRL number %d",
			c.Name, c.Kind, c.KeyMode, c.Certificates, c.Revoked, c.LastCRLNumber)
		if c.History > 0 {
			_, _ = fmt.Fprintf(w, ", %d older certificate(s) of the same key", c.History)
		}
		if c.Status != ca.StatusActive {
			_, _ = fmt.Fprintf(w, " [%s]", c.Status)
		}
		_, _ = fmt.Fprintln(w)
	}
	_, _ = fmt.Fprintf(w, "Certificates: %d (%d revoked), private keys: %d, self-signed (external): %d\n", rep.Certificates, rep.Revoked, rep.Keys, rep.External)
	for _, crl := range rep.CRLs {
		_, _ = fmt.Fprintf(w, "CRL signed: %s number %d, %d entries, next update %s\n", crl.CA, crl.Number, crl.Entries, crl.NextUpdate.Format("2006-01-02 15:04 MST"))
	}
	section := func(title string, list []string) {
		if len(list) == 0 {
			return
		}
		_, _ = fmt.Fprintf(w, "\n%s (%d):\n", title, len(list))
		for _, s := range list {
			_, _ = fmt.Fprintf(w, "  - %s\n", strings.ReplaceAll(s, "\n", " "))
		}
	}
	section("Problems", rep.Problems)
	section("Warnings", rep.Warnings)
}
