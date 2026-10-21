package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/Der-Felix/MyOwnPKI/internal/clock"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
)

// runPassphrase handles `myownpki passphrase change` and `passphrase reset`
// (PHASE1 step 20): a new unseal passphrase with the current one, or with
// the recovery key when the passphrase is lost (PLAN §5 "Recovery key").
// Both work while the server runs and don't change its seal state; old
// backups keep the passphrase that was valid when they were taken.
func runPassphrase(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	usage := func() {
		_, _ = fmt.Fprintf(stderr, "Usage:\n  %s passphrase change [--config FILE]  new unseal passphrase, proven with the current one\n"+
			"  %s passphrase reset [--config FILE]   new unseal passphrase, proven with the recovery key\n"+
			"Without a terminal: the current passphrase (or the recovery key) and the new passphrase as two lines on standard input.\n", binary, binary)
	}
	if len(args) == 0 || (args[0] != "change" && args[0] != "reset") {
		usage()
		if len(args) > 0 && (args[0] == "-h" || args[0] == "--help") {
			return exitOK
		}
		return exitUsage
	}
	uio := userIO{stdin: os.Stdin, stdinTerminal: keys.IsTerminal(os.Stdin), stdoutTerminal: keys.IsTerminal(os.Stdout), stdout: stdout, stderr: stderr,
		hidden: func(p string) ([]byte, error) { return readHidden(p, stderr) }}
	return runPassphraseWith(ctx, args[0], args[1:], os.Environ(), uio)
}

func runPassphraseWith(ctx context.Context, mode string, args, environ []string, uio userIO) int {
	fset := flag.NewFlagSet(binary+" passphrase "+mode, flag.ContinueOnError)
	fset.SetOutput(uio.stderr)
	path := configFlag(fset)
	if err := fset.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if fset.NArg() != 0 {
		_, _ = fmt.Fprintf(uio.stderr, "%s: no arguments expected, got %q\n", fset.Name(), fset.Args())
		return exitUsage
	}
	proofPrompt := "Current unseal passphrase: "
	if mode == "reset" {
		proofPrompt = "Recovery key: "
	}
	proof, next, err := readPassphrasePair(uio, proofPrompt)
	if err != nil {
		_, _ = fmt.Fprintf(uio.stderr, "%v\n", err)
		return exitUsage
	}
	defer clear(proof)
	defer clear(next)
	if cerr := keys.CheckPassphrase(next); cerr != nil {
		_, _ = fmt.Fprintf(uio.stderr, "%v\n", cerr)
		return exitUsage
	}

	d, code := openConsoleDBs(ctx, *path, environ, uio)
	if code >= 0 {
		return code
	}
	defer d.close()
	ring := keys.New(d.sys.Write, d.ia.Write, clock.System{})
	who := consoleWho()
	if mode == "reset" {
		rk, perr := keys.ParseRecoveryKey(string(proof))
		if perr != nil {
			_, _ = fmt.Fprintf(uio.stderr, "%v\n", perr)
			return exitProblem
		}
		err = ring.ResetPassphrase(ctx, rk, bytes.Clone(next), who)
	} else {
		// The key ring changes the passphrase only while unsealed: this
		// process unseals with the current one, changes it and seals again
		// (all three audited). A running server is not affected.
		if err = ring.Unseal(ctx, bytes.Clone(proof), who); err == nil {
			err = ring.ChangePassphrase(ctx, bytes.Clone(proof), bytes.Clone(next), who)
			err = errors.Join(err, ring.Seal(ctx, who))
		}
	}
	d.deliver(ctx, uio.stderr)
	if err != nil {
		_, _ = fmt.Fprintf(uio.stderr, "%v\n", err)
		return exitProblem
	}
	_, _ = fmt.Fprintf(uio.stdout, "Unseal passphrase changed. The next unseal needs the new one.\n"+
		"Backups made before now still open with the old passphrase – keep it until they have aged out.\n")
	return exitOK
}

// readPassphrasePair reads the proof (current passphrase or recovery key)
// and the new passphrase: hidden and the new one twice at a terminal, two
// lines from a pipe.
func readPassphrasePair(uio userIO, proofPrompt string) (proof, next []byte, err error) {
	if !uio.stdinTerminal {
		r := bufio.NewReader(io.LimitReader(uio.stdin, 2*1026))
		if proof, err = readLine(r); err != nil {
			return nil, nil, err
		}
		if next, err = readLine(r); err != nil {
			clear(proof)
			return nil, nil, err
		}
		return proof, next, nil
	}
	if proof, err = uio.hidden(proofPrompt); err != nil {
		return nil, nil, err
	}
	if next, err = uio.hidden("New unseal passphrase (at least 16 characters): "); err != nil {
		clear(proof)
		return nil, nil, err
	}
	again, err := uio.hidden("The new passphrase again: ")
	if err != nil {
		clear(proof)
		clear(next)
		return nil, nil, err
	}
	defer clear(again)
	if !bytes.Equal(next, again) {
		clear(proof)
		clear(next)
		return nil, nil, errors.New("the two entries of the new passphrase differ – nothing was changed")
	}
	return proof, next, nil
}

func readLine(r *bufio.Reader) ([]byte, error) {
	line, err := r.ReadBytes('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	line = bytes.TrimRight(line, "\r\n")
	if len(line) == 0 || len(line) > 1024 {
		return nil, errors.New("standard input wants two lines: the current passphrase (or the recovery key), then the new passphrase (at most 1024 bytes each)")
	}
	return line, nil
}
