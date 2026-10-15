package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/Der-Felix/MyOwnPKI/internal/config"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/setup"
)

// termUI is init at a terminal: secrets are typed without echo.
type termUI struct {
	in  *bufio.Reader
	out io.Writer
	fd  int
}

func (u *termUI) Printf(format string, args ...any) { _, _ = fmt.Fprintf(u.out, format, args...) }

func (u *termUI) ReadLine(prompt string) (string, error) {
	_, _ = fmt.Fprint(u.out, prompt)
	line, err := u.in.ReadString('\n')
	if err != nil && (!errors.Is(err, io.EOF) || line == "") {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func (u *termUI) ReadSecret(prompt string) ([]byte, error) {
	_, _ = fmt.Fprint(u.out, prompt)
	b, err := term.ReadPassword(u.fd)
	_, _ = fmt.Fprintln(u.out)
	return b, err
}

// readHidden asks for a secret on the terminal without echo.
func readHidden(prompt string, out io.Writer) ([]byte, error) {
	_, _ = fmt.Fprint(out, prompt)
	b, err := term.ReadPassword(int(os.Stdin.Fd())) // #nosec G115 -- a file descriptor fits in int
	_, _ = fmt.Fprintln(out)
	return b, err
}

// runInit is myownpki init (PHASE1 step 11).
func runInit(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	stdinTerm, stdoutTerm := keys.IsTerminal(os.Stdin), keys.IsTerminal(os.Stdout)
	var ui setup.UI
	opt, code := parseInit(args, os.Environ(), stderr)
	if code >= 0 {
		return code
	}
	switch opt.Mode {
	case setup.Interactive:
		if !stdinTerm || !stdoutTerm {
			_, _ = fmt.Fprintf(stderr, "%s init: no interactive terminal – use --stdin for automation or --demo to try it out\n", binary)
			return exitUsage
		}
		ui = &termUI{in: bufio.NewReader(os.Stdin), out: stdout, fd: int(os.Stdin.Fd())} // #nosec G115 -- a file descriptor fits in int
	case setup.Stdin:
		if stdinTerm {
			_, _ = fmt.Fprintf(stderr, "%s init --stdin reads passphrase and password from a pipe, not from a terminal (they would be shown while typing) – run init without --stdin\n", binary)
			return exitUsage
		}
		ui = setup.NewLineInput(os.Stdin, stdout)
	case setup.Demo:
		ui = setup.NewLineInput(strings.NewReader(""), stdout)
	}
	return finishInit(ctx, opt, ui, stdout, stderr)
}

func parseInit(args, environ []string, stderr io.Writer) (setup.Options, int) {
	fset := flag.NewFlagSet(binary+" init", flag.ContinueOnError)
	fset.SetOutput(stderr)
	path := configFlag(fset)
	stdin := fset.Bool("stdin", false, "automation: unseal passphrase and admin password as two lines on standard input")
	demo := fset.Bool("demo", false, "try it out: generate every secret into one file; the instance stays marked as a demo")
	var opt setup.Options
	fset.StringVar(&opt.AdminUser, "admin-user", "", "name of the first user (--stdin; --demo: default demo)")
	fset.StringVar(&opt.RecoveryKeyFile, "recovery-key-file", "", "write the recovery key to this new file (--stdin)")
	fset.StringVar(&opt.OTPAuthFile, "otpauth-file", "", "write the TOTP setup and recovery codes to this new file (--stdin)")
	fset.StringVar(&opt.DemoSecretsFile, "demo-secrets-file", "", "file for the generated secrets (--demo; default <data_dir>/init-demo-secrets.txt)")
	fset.BoolVar(&opt.WithCA, "with-ca", false, "create an online root + intermediate CA for testing")
	fset.StringVar(&opt.CABaseURL, "ca-base-url", "", "public base URL of the test CA (part of every certificate, can't be changed)")
	if err := fset.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return opt, exitOK
		}
		return opt, exitUsage
	}
	if fset.NArg() > 0 {
		_, _ = fmt.Fprintf(stderr, "%s init: unexpected argument %q\n", binary, fset.Arg(0))
		return opt, exitUsage
	}
	switch {
	case *stdin && *demo:
		_, _ = fmt.Fprintf(stderr, "%s init: --stdin and --demo exclude each other\n", binary)
		return opt, exitUsage
	case *stdin:
		opt.Mode = setup.Stdin
	case *demo:
		opt.Mode = setup.Demo
	default:
		opt.Mode = setup.Interactive
	}
	cfg, _, err := config.Load(configPath(*path, environ), environ)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "%v\n", err)
		return opt, exitProblem
	}
	opt.Config = cfg
	opt.Who = consoleWho()
	return opt, -1
}

// finishInit runs init and prints what to keep where.
func finishInit(ctx context.Context, opt setup.Options, ui setup.UI, stdout, stderr io.Writer) int {
	res, err := setup.Run(ctx, opt, ui)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "%v\n", err)
		if errors.Is(err, setup.ErrInitialized) {
			return exitProblem
		}
		return exitProblem
	}
	out := func(format string, args ...any) { _, _ = fmt.Fprintf(stdout, format, args...) }
	if res.Resumed {
		out("\nThe earlier init is finished now.\n")
	}
	if res.Enrollment != nil && opt.Mode == setup.Interactive {
		out("\nRecovery codes of %s – each works once instead of a TOTP code. Keep them offline, apart from the phone:\n", res.Enrollment.Username)
		for _, c := range res.Enrollment.RecoveryCodes {
			out("    %s\n", c)
		}
	}
	for _, w := range res.Warnings {
		out("WARNING: %s\n", w)
	}
	if len(res.CAs) > 0 {
		out("\nTest CA created: %s (online root – for tests and a homelab only).\n", strings.Join(res.CAs, ", "))
	}
	out("\nCheckpoint key fingerprint – note it down; `%s audit verify --checkpoint-key` checks the audit log against it:\n    %s\n",
		binary, res.CheckpointFingerprint)
	out("\nKeep apart: the unseal passphrase, the recovery key and the backups. A backup plus either of them is the whole CA.\n")
	out("The auth key %s encrypts the TOTP secrets; keep it with the backups (lost: `%s user reset-2fa --new-auth-key`).\n", opt.Config.AuthKeyFile(), binary)
	switch opt.Mode {
	case setup.Stdin:
		if opt.RecoveryKeyFile != "" && !res.Resumed {
			out("Recovery key: %s – store it offline and delete the file from this server.\n", opt.RecoveryKeyFile)
		}
		if res.Enrollment != nil {
			out("TOTP setup and recovery codes: %s – hand it to the user, then delete it. The first sign-in confirms the authenticator.\n", opt.OTPAuthFile)
		}
	case setup.Demo:
		out("\n*** %s ***\nSecrets: %s\nFor production set up a new instance with `%s init`.\n", setup.DemoWarning, res.DemoSecretsFile, binary)
	case setup.Interactive:
	}
	return exitOK
}
