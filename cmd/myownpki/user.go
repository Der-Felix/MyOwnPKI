package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"os/user"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/auth"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/clock"
	"github.com/Der-Felix/MyOwnPKI/internal/config"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/store"
)

// userIO is what the user commands read and write; tests replace it.
type userIO struct {
	stdin                         io.Reader
	stdinTerminal, stdoutTerminal bool
	// hidden reads a secret at the terminal without echo.
	hidden         func(prompt string) ([]byte, error)
	stdout, stderr io.Writer
}

// runUser handles the console emergencies `myownpki user unlock` and
// `myownpki user reset-2fa` (PHASE1 step 10). Everyday user management comes
// with the API and the UI (steps 18/19).
func runUser(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	usage := func() {
		_, _ = fmt.Fprintf(stderr, "Usage:\n  %s user unlock NAME [--config FILE]\n"+
			"  %s user reset-2fa NAME [--config FILE] [--recovery-key] [--new-auth-key] [--otpauth-file PATH]\n"+
			"      reads the unseal passphrase (or with --recovery-key the recovery key) from standard input\n", binary, binary)
	}
	if len(args) == 0 {
		usage()
		return exitUsage
	}
	uio := userIO{stdin: os.Stdin, stdinTerminal: keys.IsTerminal(os.Stdin), stdoutTerminal: keys.IsTerminal(os.Stdout), stdout: stdout, stderr: stderr,
		hidden: func(p string) ([]byte, error) { return readHidden(p, stderr) }}
	switch args[0] {
	case "unlock":
		return runUserUnlock(ctx, args[1:], os.Environ(), uio)
	case "reset-2fa":
		return runUserReset2FA(ctx, args[1:], os.Environ(), uio)
	case "-h", "--help":
		usage()
		return exitOK
	}
	_, _ = fmt.Fprintf(stderr, "%s user: unknown subcommand %q\n", binary, args[0])
	usage()
	return exitUsage
}

// parseUserArgs parses flags before or after the one user name.
func parseUserArgs(fset *flag.FlagSet, args []string, stderr io.Writer) (string, int) {
	var rest []string
	for len(args) > 0 {
		if err := fset.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return "", exitOK
			}
			return "", exitUsage
		}
		args = fset.Args()
		if len(args) > 0 {
			rest = append(rest, args[0])
			args = args[1:]
		}
	}
	if len(rest) != 1 {
		_, _ = fmt.Fprintf(stderr, "%s: want one user name, got %d argument(s)\n", fset.Name(), len(rest))
		return "", exitUsage
	}
	return rest[0], -1
}

// consoleDBs opens system.db and the instance audit log for writing.
type consoleDBs struct {
	cfg       config.Config
	sys, ia   *store.DB
	deliverer *audit.Deliverer
}

func openConsoleDBs(ctx context.Context, path string, environ []string, uio userIO) (*consoleDBs, int) {
	cfg, _, err := config.Load(configPath(path, environ), environ)
	if err != nil {
		_, _ = fmt.Fprintf(uio.stderr, "%v\n", err)
		return nil, exitProblem
	}
	l := store.Layout{DataDir: cfg.DataDir}
	if _, serr := os.Stat(l.SystemDB()); errors.Is(serr, fs.ErrNotExist) {
		_, _ = fmt.Fprintf(uio.stdout, "The system database doesn't exist yet (run `%s db migrate`).\n", binary)
		return nil, exitPending
	}
	d := &consoleDBs{cfg: cfg}
	if d.sys, err = store.Open(ctx, l.SystemDB()); err != nil {
		_, _ = fmt.Fprintf(uio.stderr, "%v\n", err)
		return nil, exitProblem
	}
	if d.ia, err = store.Open(ctx, l.InstanceAuditDB()); err != nil {
		_ = d.sys.Close()
		_, _ = fmt.Fprintf(uio.stderr, "%v\n", err)
		return nil, exitProblem
	}
	d.deliverer = &audit.Deliverer{
		Routes: []audit.Route{{Source: "system", From: d.sys.Write, To: d.ia.Write, Scope: store.InstanceScope}},
		Clock:  clock.System{}, Log: slog.New(slog.DiscardHandler),
	}
	return d, -1
}

func (d *consoleDBs) close() {
	_ = d.sys.Close()
	_ = d.ia.Close()
}

// deliver moves the audit events of this command from the outbox into the
// audit log at once; a running server would do the same (deduplicated).
func (d *consoleDBs) deliver(ctx context.Context, stderr io.Writer) {
	if _, err := d.deliverer.DeliverPending(ctx); err != nil {
		_, _ = fmt.Fprintf(stderr, "note: the audit entry stays in the outbox until the server delivers it: %v\n", err)
	}
}

// consoleWho is the operator at the console; the OS account goes into the
// audit entry.
func consoleWho() keys.Who {
	name := "console"
	if u, err := user.Current(); err == nil && u.Username != "" {
		name = "console:" + u.Username
	}
	return keys.Who{Actor: audit.Actor{Type: audit.ActorUser, Name: name}, Principal: authz.Console()}
}

func runUserUnlock(ctx context.Context, args, environ []string, uio userIO) int {
	fset := flag.NewFlagSet(binary+" user unlock", flag.ContinueOnError)
	fset.SetOutput(uio.stderr)
	path := configFlag(fset)
	name, code := parseUserArgs(fset, args, uio.stderr)
	if code >= 0 {
		return code
	}
	d, code := openConsoleDBs(ctx, *path, environ, uio)
	if code >= 0 {
		return code
	}
	defer d.close()
	svc := auth.NewService(d.sys.Write, d.ia.Write, nil, clock.System{})
	if err := svc.Unlock(ctx, name, consoleWho()); err != nil {
		_, _ = fmt.Fprintf(uio.stderr, "%v\n", err)
		return exitProblem
	}
	d.deliver(ctx, uio.stderr)
	_, _ = fmt.Fprintf(uio.stdout, "User %q unlocked. A running server may still slow down new attempts for up to 15 minutes.\n", name)
	return exitOK
}

// runUserReset2FA is the way out when a phone or the auth key is lost. Shell
// access alone is not enough: it needs the unseal passphrase or the recovery
// key (owner decision). The user gets a new TOTP secret and new recovery
// codes and confirms the secret at the next sign-in.
func runUserReset2FA(ctx context.Context, args, environ []string, uio userIO) int {
	fset := flag.NewFlagSet(binary+" user reset-2fa", flag.ContinueOnError)
	fset.SetOutput(uio.stderr)
	path := configFlag(fset)
	withRecovery := fset.Bool("recovery-key", false, "prove with the recovery key instead of the unseal passphrase")
	newKey := fset.Bool("new-auth-key", false, "create a new auth key first (the old one is lost); every user then needs reset-2fa")
	outFile := fset.String("otpauth-file", "", "write the new secret and recovery codes to this new file (mode 0600) instead of the terminal")
	name, code := parseUserArgs(fset, args, uio.stderr)
	if code >= 0 {
		return code
	}
	if *outFile == "" && !uio.stdoutTerminal {
		_, _ = fmt.Fprintf(uio.stderr, "%v\n", auth.ErrEnrollmentNeedsFile)
		return exitUsage
	}
	if *outFile != "" {
		if _, serr := os.Lstat(*outFile); serr == nil {
			_, _ = fmt.Fprintf(uio.stderr, "%s exists already – it is never overwritten; choose another file\n", *outFile)
			return exitUsage
		}
	}
	var secret []byte
	var err error
	if uio.stdinTerminal {
		prompt := "Unseal passphrase: "
		if *withRecovery {
			prompt = "Recovery key: "
		}
		secret, err = uio.hidden(prompt)
	} else {
		secret, err = readSecretLine(uio.stdin)
	}
	if err != nil {
		_, _ = fmt.Fprintf(uio.stderr, "%v\n", err)
		return exitUsage
	}
	defer clear(secret)

	d, code := openConsoleDBs(ctx, *path, environ, uio)
	if code >= 0 {
		return code
	}
	defer d.close()
	who := consoleWho()
	ring := keys.New(d.sys.Write, d.ia.Write, clock.System{})
	if *withRecovery {
		rk, perr := keys.ParseRecoveryKey(string(secret))
		if perr != nil {
			_, _ = fmt.Fprintf(uio.stderr, "%v\n", perr)
			return exitProblem
		}
		err = ring.VerifyRecoveryKey(ctx, rk, who)
	} else {
		err = ring.VerifyPassphrase(ctx, secret, who)
	}
	if err != nil {
		_, _ = fmt.Fprintf(uio.stderr, "%v\n", err)
		return exitProblem
	}

	keyFile := d.cfg.AuthKeyFile()
	if *newKey {
		if kerr := auth.CreateKeyFile(keyFile, nil); kerr != nil {
			_, _ = fmt.Fprintf(uio.stderr, "%v\n(move the old file away yourself if you are sure it is lost or broken)\n", kerr)
			return exitProblem
		}
		_, _ = fmt.Fprintf(uio.stdout, "New auth key written to %s. Every user needs `%s user reset-2fa` now.\n", keyFile, binary)
	}
	key, warnings, err := auth.LoadKey(keyFile)
	if err != nil {
		_, _ = fmt.Fprintf(uio.stderr, "%v\n", err)
		return exitProblem
	}
	for _, w := range warnings {
		_, _ = fmt.Fprintf(uio.stderr, "warning: %s\n", w)
	}
	svc := auth.NewService(d.sys.Write, d.ia.Write, key, clock.System{})
	enr, err := svc.ResetTOTP(ctx, name, who)
	if err != nil {
		_, _ = fmt.Fprintf(uio.stderr, "%v\n", err)
		return exitProblem
	}
	d.deliver(ctx, uio.stderr)
	if *outFile != "" {
		if err := auth.WriteEnrollmentFile(*outFile, enr); err != nil {
			// The reset is done: without the file nobody knows the secret.
			_, _ = fmt.Fprintf(uio.stderr, "%v\nThe reset is stored, but the secret is lost – run reset-2fa again with another file.\n", err)
			return exitProblem
		}
		_, _ = fmt.Fprintf(uio.stdout, "Two-factor sign-in of %q reset; all sessions ended. Secret and recovery codes: %s (hand it over, then delete it).\n", name, *outFile)
		return exitOK
	}
	_, _ = fmt.Fprintf(uio.stdout, "Two-factor sign-in of %q reset; all sessions ended. The next sign-in confirms the new secret.\n\n%s", name, enr.Text())
	return exitOK
}

// readSecretLine reads one line (at most 1 KiB) without the line break.
func readSecretLine(r io.Reader) ([]byte, error) {
	line, err := bufio.NewReader(io.LimitReader(r, 1025)).ReadBytes('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	line = bytes.TrimRight(line, "\r\n")
	if len(line) == 0 || len(line) > 1024 {
		return nil, errors.New("no passphrase or recovery key on standard input (one line, at most 1024 bytes)")
	}
	return line, nil
}
