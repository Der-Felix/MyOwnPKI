// Package setup is myownpki init (PHASE1 step 11): unseal passphrase,
// recovery key, auth key, the first user with TOTP and – optionally – an
// online test CA.
//
// Rules:
//   - Everything is asked and confirmed first, then written in one go: an
//     abort before that (wrong confirmation, Ctrl+C) leaves nothing behind.
//   - Files that hand out a secret (recovery key, otpauth, demo secrets) are
//     written before the database refers to that secret.
//   - A run that broke off while writing is resumed by running init again:
//     it proves the unseal passphrase and creates only the missing parts.
package setup

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/auth"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/ca/preset"
	"github.com/Der-Felix/MyOwnPKI/internal/clock"
	"github.com/Der-Felix/MyOwnPKI/internal/config"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/store"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
	"github.com/Der-Felix/MyOwnPKI/internal/store/systemdb"
)

// Mode is how init gets its input.
type Mode int

// Modes.
const (
	// Interactive: a person at a terminal; secrets are typed hidden.
	Interactive Mode = iota + 1
	// Stdin: automation – passphrase and password as two lines on standard
	// input; recovery key and TOTP go to files.
	Stdin
	// Demo: everything is generated and written to one file. For trying out
	// only: the instance is marked as a demo for good.
	Demo
)

// Errors.
var (
	ErrInitialized  = errors.New("this instance is initialized already")
	ErrAborted      = errors.New("init aborted – nothing was written")
	ErrNeedsFile    = errors.New("without a terminal the secrets need files")
	ErrSameSecret   = errors.New("the admin password must differ from the unseal passphrase (also in upper/lower case) – they protect different things and must not fall together")
	ErrBaseURLEmpty = errors.New("the test CA needs a public base URL (for example http://pki.homelab.lan) – it is part of every certificate and can't be changed later")
)

// UI is the console. Tests script it.
type UI interface {
	// Printf writes a message.
	Printf(format string, args ...any)
	// ReadLine asks for a visible answer.
	ReadLine(prompt string) (string, error)
	// ReadSecret asks for a hidden answer (in Stdin mode: the next line).
	ReadSecret(prompt string) ([]byte, error)
}

// Options are the command-line choices.
type Options struct {
	Config          config.Config
	Mode            Mode
	AdminUser       string // Stdin and Demo; Interactive asks
	RecoveryKeyFile string // Stdin: required for a new key
	OTPAuthFile     string // Stdin: required for a new user
	DemoSecretsFile string // Demo: "" = <data_dir>/init-demo-secrets.txt
	WithCA          bool   // create the test CA without asking
	CABaseURL       string
	Hostname        string      // O of the test CA; "" = os.Hostname
	Clock           clock.Clock // nil = clock.System
	Rand            io.Reader   // nil = crypto/rand
	Who             keys.Who    // the console operator

	// argon replaces the Argon2id parameters of the auth service in tests.
	argon *auth.Params
	// failAfter stops after a write step (tests of the resume path).
	failAfter string
}

// Result is what init reports at the end.
type Result struct {
	Resumed               bool
	CheckpointFingerprint string
	CAs                   []string // created now
	Warnings              []string
	DemoSecretsFile       string
	// Enrollment of the new user (interactive): the recovery codes to show
	// at the end. nil when no user was created.
	Enrollment *auth.Enrollment
}

// Defaults of the test CA.
const (
	TestRootName         = "root"
	TestIntermediateName = "issuing"
)

type run struct {
	opt   Options
	ui    UI
	clk   clock.Clock
	rnd   io.Reader
	l     store.Layout
	res   Result
	state state

	// collected before writing
	passphrase []byte
	recovery   *keys.RecoveryKey
	username   string
	password   string
	draft      *auth.Draft
	caSuffix   string
	caOrg      string
	wantCA     bool
	demoFile   string
}

// state is what exists already (resume).
type state struct {
	systemExists bool
	initialized  bool // root key exists
	users        int64
	cas          map[string]bool
}

// Run is myownpki init.
func Run(ctx context.Context, opt Options, ui UI) (*Result, error) {
	r := &run{opt: opt, ui: ui, clk: opt.Clock, rnd: opt.Rand, l: store.Layout{DataDir: opt.Config.DataDir}}
	if r.clk == nil {
		r.clk = clock.System{}
	}
	if r.rnd == nil {
		r.rnd = rand.Reader
	}
	if r.opt.Who.Principal == nil {
		return nil, errors.New("setup: no console principal")
	}
	if err := r.readState(ctx); err != nil {
		return nil, err
	}
	if err := r.collect(ctx); err != nil {
		return nil, err
	}
	defer clear(r.passphrase)
	if r.draft != nil {
		defer r.draft.Clear()
	}
	if err := r.write(ctx); err != nil {
		return &r.res, err
	}
	return &r.res, nil
}

// readState looks at the data directory without changing it – migrations
// come with the writes, after everything was asked.
func (r *run) readState(ctx context.Context) error {
	r.state.cas = map[string]bool{}
	if _, err := os.Stat(r.l.SystemDB()); errors.Is(err, fs.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	r.state.systemExists = true
	// An existing system.db may be older: bring it up to date first.
	if _, err := store.Migrate(ctx, r.l, store.DefaultTenant, r.clk.Now); err != nil {
		return err
	}
	sys, err := store.OpenReadOnly(ctx, r.l.SystemDB())
	if err != nil {
		return err
	}
	defer func() { _ = sys.Close() }()
	q := systemdb.New(sys.Read)
	if inst, ierr := q.GetInstance(ctx); ierr == nil {
		return fmt.Errorf("%w (%s)", ErrInitialized, inst.InitializedAt)
	} else if !errors.Is(ierr, sql.ErrNoRows) {
		return ierr
	}
	n, err := q.CountUnsealSlots(ctx)
	if err != nil {
		return err
	}
	r.state.initialized = n > 0
	if r.state.users, err = q.CountUsers(ctx); err != nil {
		return err
	}
	if r.state.users > 0 && !r.state.initialized {
		return errors.New("users exist but no root key – this data directory was not made by init; set up a new one")
	}
	pkiPath, err := r.l.TenantDB(store.DefaultTenant, store.KindPKI)
	if err != nil {
		return err
	}
	pki, err := store.OpenReadOnly(ctx, pkiPath)
	if err != nil {
		return err
	}
	defer func() { _ = pki.Close() }()
	for _, name := range []string{TestRootName, TestIntermediateName} {
		if _, err := pkidb.New(pki.Read).GetCAByName(ctx, name); err == nil {
			r.state.cas[name] = true
		} else if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
	}
	r.res.Resumed = r.state.initialized
	return nil
}

// collect asks for everything that is still missing. Nothing is written.
func (r *run) collect(ctx context.Context) error {
	if err := r.checkFiles(); err != nil {
		return err
	}
	if r.state.initialized {
		if err := r.proveOperator(ctx); err != nil {
			return err
		}
	} else if err := r.collectPassphrase(); err != nil {
		return err
	}
	if r.state.users == 0 {
		if err := r.collectUser(); err != nil {
			return err
		}
	}
	return r.collectCA()
}

// checkFiles refuses before anything is asked when a secret file can't be
// written: files are never overwritten.
func (r *run) checkFiles() error {
	var files []string
	switch r.opt.Mode {
	case Stdin:
		if !r.state.initialized {
			if r.opt.RecoveryKeyFile == "" {
				return fmt.Errorf("%w: --recovery-key-file is required with --stdin", ErrNeedsFile)
			}
			files = append(files, r.opt.RecoveryKeyFile)
		}
		if r.state.users == 0 {
			if r.opt.OTPAuthFile == "" {
				return fmt.Errorf("%w: --otpauth-file is required with --stdin", ErrNeedsFile)
			}
			if r.opt.AdminUser == "" {
				return errors.New("--admin-user is required with --stdin")
			}
			files = append(files, r.opt.OTPAuthFile)
		}
	case Demo:
		r.demoFile = r.opt.DemoSecretsFile
		if r.demoFile == "" {
			r.demoFile = filepath.Join(r.l.DataDir, "init-demo-secrets.txt")
		}
		if r.state.initialized {
			// The first run's file holds the passphrase; the missing parts
			// go to a second file.
			r.demoFile += ".resumed"
		}
		files = append(files, r.demoFile)
	case Interactive:
	default:
		return errors.New("setup: unknown mode")
	}
	for _, f := range files {
		if _, err := os.Lstat(f); err == nil {
			return fmt.Errorf("%s exists already – secret files are never overwritten; move it away (if it is left from an aborted init, its secret was never used)", f)
		}
	}
	return nil
}

// proveOperator: resuming needs the unseal passphrase – the root key exists
// already, and whoever continues must be allowed to use it.
func (r *run) proveOperator(ctx context.Context) error {
	var pass []byte
	var err error
	switch r.opt.Mode {
	case Demo:
		pass, err = demoPassphrase(r.opt.DemoSecretsFile, r.l.DataDir)
	default:
		r.ui.Printf("An earlier init stopped half-way. To finish it, prove that you may use the root key.\n")
		pass, err = r.ui.ReadSecret("Unseal passphrase: ")
	}
	if err != nil {
		return err
	}
	if err := r.writeDBs(ctx, func(sys, ia *store.DB) error {
		return keys.New(sys.Write, ia.Write, r.clk).VerifyPassphrase(ctx, append([]byte(nil), pass...), r.opt.Who)
	}); err != nil {
		clear(pass)
		return err
	}
	r.passphrase = pass
	return nil
}

func (r *run) collectPassphrase() error {
	switch r.opt.Mode {
	case Demo:
		r.passphrase = []byte(randomGroups(r.rnd, 6, 5))
	case Stdin:
		p, err := r.ui.ReadSecret("")
		if err != nil {
			return err
		}
		if err := keys.CheckPassphrase(p); err != nil {
			return err
		}
		r.passphrase = p
	case Interactive:
		r.ui.Printf("The unseal passphrase unlocks the CA keys after every start. At least %d characters.\n"+
			"Keep it apart from the backups: a backup plus the passphrase is the whole CA.\n", 16)
		p, err := r.askTwice("Unseal passphrase: ", "Repeat the passphrase: ", keys.CheckPassphrase)
		if err != nil {
			return err
		}
		if keys.HasNonASCII(p) {
			r.ui.Printf("Note: the passphrase has characters beyond ASCII – make sure you can type them on every keyboard you may need.\n")
		}
		r.passphrase = p
	}
	k, err := keys.NewRecoveryKey(r.rnd)
	if err != nil {
		return err
	}
	r.recovery = &k
	if r.opt.Mode == Interactive {
		return r.confirmRecoveryKey()
	}
	return nil
}

// askTwice reads a secret twice; check runs on the first. Three tries.
func (r *run) askTwice(prompt, again string, check func([]byte) error) ([]byte, error) {
	for range 3 {
		a, err := r.ui.ReadSecret(prompt)
		if err != nil {
			return nil, err
		}
		if cerr := check(a); cerr != nil {
			r.ui.Printf("%v\n", cerr)
			clear(a)
			continue
		}
		b, err := r.ui.ReadSecret(again)
		if err != nil {
			clear(a)
			return nil, err
		}
		same := string(a) == string(b)
		clear(b)
		if same {
			return a, nil
		}
		clear(a)
		r.ui.Printf("The two entries differ.\n")
	}
	return nil, ErrAborted
}

// confirmRecoveryKey shows the key and lets the user type two groups of it
// again (as in step 6): proof that it was written down.
func (r *run) confirmRecoveryKey() error {
	r.ui.Printf("\nRecovery key – the second way to unlock the CA keys if the passphrase is lost.\n"+
		"Write it down now and keep it offline, apart from the passphrase and the backups:\n\n    %s\n\n", r.recovery.Reveal())
	idx, err := keys.ConfirmIndexes(r.rnd)
	if err != nil {
		return err
	}
	typed := map[int]string{}
	for _, i := range idx {
		g, err := r.ui.ReadLine(fmt.Sprintf("Type group %d of the recovery key: ", i+1))
		if err != nil {
			return err
		}
		typed[i] = g
	}
	if !r.recovery.CheckGroups(typed) {
		return fmt.Errorf("%w: the typed groups don't match the recovery key", ErrAborted)
	}
	return nil
}

func (r *run) collectUser() error {
	svc := r.authService(nil)
	switch r.opt.Mode {
	case Interactive:
		r.ui.Printf("\nThe first user signs in to the web UI. It becomes instance admin and admin of the default tenant.\n")
		for i := 0; ; i++ {
			name, err := r.ui.ReadLine("User name (lower case a-z, 0-9, . _ @ -): ")
			if err != nil {
				return err
			}
			if err := auth.CheckUsername(name); err == nil {
				r.username = name
				break
			} else if i == 2 {
				return fmt.Errorf("%w: %w", ErrAborted, err)
			} else {
				r.ui.Printf("%v\n", err)
			}
		}
		p, err := r.askTwice("Password: ", "Repeat the password: ", func(p []byte) error {
			if err := auth.CheckPassword(r.username, string(p)); err != nil {
				return err
			}
			if strings.EqualFold(string(p), string(r.passphrase)) {
				return ErrSameSecret
			}
			return nil
		})
		if err != nil {
			return err
		}
		r.password = string(p)
		clear(p)
	case Stdin:
		r.username = r.opt.AdminUser
		p, err := r.ui.ReadSecret("")
		if err != nil {
			return err
		}
		r.password = string(p)
		clear(p)
	case Demo:
		r.username = r.opt.AdminUser
		if r.username == "" {
			r.username = "demo"
		}
		for {
			r.password = randomGroups(r.rnd, 4, 5)
			if auth.CheckPassword(r.username, r.password) == nil {
				break
			}
		}
	}
	if err := auth.CheckUsername(r.username); err != nil {
		return err
	}
	if err := auth.CheckPassword(r.username, r.password); err != nil {
		return err
	}
	if strings.EqualFold(r.password, string(r.passphrase)) {
		return ErrSameSecret
	}
	draft, err := svc.NewDraft(r.username)
	if err != nil {
		return err
	}
	r.draft = draft
	if r.opt.Mode != Interactive {
		return nil // confirmed at the first login
	}
	r.ui.Printf("\nAdd the account to an authenticator app (Aegis, Google or Microsoft Authenticator, 1Password …):\n"+
		"  link:   %s\n  secret: %s\n", draft.Enrollment.URI, draft.Enrollment.Secret)
	for range 3 {
		code, err := r.ui.ReadLine("Code shown by the app: ")
		if err != nil {
			return err
		}
		if draft.Confirm(code, r.clk.Now()) {
			return nil
		}
		r.ui.Printf("That code doesn't match – is the clock of the phone right? Wait for the next code.\n")
	}
	return fmt.Errorf("%w: three wrong codes – check the time on the phone and start again", ErrAborted)
}

func (r *run) collectCA() error {
	if r.state.cas[TestRootName] && r.state.cas[TestIntermediateName] {
		return nil
	}
	if r.state.cas[TestRootName] || r.state.cas[TestIntermediateName] {
		r.wantCA = true // an earlier run started it: finish it
	} else {
		switch r.opt.Mode {
		case Interactive:
			r.wantCA = r.opt.WithCA
			if !r.wantCA {
				a, err := r.ui.ReadLine("\nCreate an online root + intermediate CA for testing? Its root key is on this server – fine for tests and a homelab. [y/N] ")
				if err != nil {
					return err
				}
				r.wantCA = strings.EqualFold(strings.TrimSpace(a), "y") || strings.EqualFold(strings.TrimSpace(a), "yes")
			}
		case Stdin:
			r.wantCA = r.opt.WithCA
		case Demo:
			r.wantCA = r.opt.WithCA || r.opt.CABaseURL != ""
		}
	}
	if !r.wantCA {
		return nil
	}
	if r.opt.CABaseURL == "" && r.opt.Mode == Interactive {
		u, err := r.ui.ReadLine("Public base URL for CRLs and CA certificates (for example http://pki.homelab.lan): ")
		if err != nil {
			return err
		}
		r.opt.CABaseURL = strings.TrimSpace(u)
	}
	if r.opt.CABaseURL == "" {
		return ErrBaseURLEmpty
	}
	r.caSuffix = randomGroups(r.rnd, 1, 4)
	r.caOrg = caOrganization(r.opt.Hostname)
	return nil
}

// write does every missing part in order; failAfter stops there (tests).
func (r *run) write(ctx context.Context) error {
	steps := []struct {
		name string
		fn   func(context.Context) error
	}{
		{"files", r.writeFiles},
		{"migrate", r.migrate},
		{"auth-key", r.authKey},
		{"root-key", r.rootKey},
		{"user", r.createUser},
		{"finish", r.unsealPart},
	}
	for _, s := range steps {
		if err := s.fn(ctx); err != nil {
			return fmt.Errorf("init (%s): %w – run init again to finish", s.name, err)
		}
		if r.opt.failAfter == s.name {
			return fmt.Errorf("test stop after %s", s.name)
		}
	}
	return nil
}

func (r *run) writeFiles(context.Context) error {
	switch r.opt.Mode {
	case Stdin:
		if r.recovery != nil {
			if err := keys.WriteRecoveryKeyFile(r.opt.RecoveryKeyFile, *r.recovery); err != nil {
				return err
			}
		}
		if r.draft != nil {
			if err := auth.WriteEnrollmentFile(r.opt.OTPAuthFile, r.draft.Enrollment); err != nil {
				return err
			}
		}
	case Demo:
		if err := os.MkdirAll(r.l.DataDir, 0o700); err != nil {
			return err
		}
		if err := writeDemoFile(r.demoFile, r); err != nil {
			return err
		}
		r.res.DemoSecretsFile = r.demoFile
	case Interactive:
	}
	return nil
}

func (r *run) migrate(ctx context.Context) error {
	_, err := store.Migrate(ctx, r.l, store.DefaultTenant, r.clk.Now)
	return err
}

func (r *run) authKey(context.Context) error {
	path := r.opt.Config.AuthKeyFile()
	if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
		if r.state.users > 0 {
			return fmt.Errorf("the auth key %s is missing although users exist – myownpki user reset-2fa --new-auth-key", path)
		}
		return auth.CreateKeyFile(path, r.rnd)
	}
	_, warnings, err := auth.LoadKey(path)
	r.res.Warnings = append(r.res.Warnings, warnings...)
	return err
}

func (r *run) rootKey(ctx context.Context) error {
	if r.state.initialized {
		return nil
	}
	return r.writeDBs(ctx, func(sys, ia *store.DB) error {
		pass := append([]byte(nil), r.passphrase...) // Init clears its copy
		return keys.New(sys.Write, ia.Write, r.clk).Init(ctx, pass, *r.recovery, r.opt.Who)
	})
}

func (r *run) createUser(ctx context.Context) error {
	if r.draft == nil {
		return nil
	}
	key, _, err := auth.LoadKey(r.opt.Config.AuthKeyFile())
	if err != nil {
		return err
	}
	return r.writeDBs(ctx, func(sys, ia *store.DB) error {
		svc := r.authService(key)
		svc.System, svc.Audit = sys.Write, ia.Write
		enr, err := svc.CreateUser(ctx, auth.NewUserRequest{
			Username: r.username, Password: r.password, InstanceAdmin: true, Draft: r.draft, Who: r.opt.Who,
			Roles: []authz.Binding{{Tenant: store.DefaultTenant, Role: authz.Admin}},
		})
		r.res.Enrollment = enr
		return err
	})
}

// unsealPart unseals once: the checkpoint key fingerprint to note down, the
// test CA if wanted, then the instance row with system.init – while still
// unsealed, so the checkpoint before the seal signs it at once (owner
// 2026-10-16); only system.seal comes after, by design.
func (r *run) unsealPart(ctx context.Context) error {
	return r.writeTenantDBs(ctx, func(sys, ia, pki, ta *store.DB) error {
		ring := keys.New(sys.Write, ia.Write, r.clk)
		deliverer := &audit.Deliverer{
			Routes: []audit.Route{
				{Source: "system", From: sys.Write, To: ia.Write, Scope: store.InstanceScope},
				{Source: "pki", From: pki.Write, To: ta.Write, Scope: store.TenantScope(store.DefaultTenant)},
			},
			Clock: r.clk, Log: slog.New(slog.DiscardHandler),
		}
		cp := &audit.Checkpointer{
			Logs:   []audit.CheckpointLog{{DB: ia.Write, Scope: store.InstanceScope}, {DB: ta.Write, Scope: store.TenantScope(store.DefaultTenant)}},
			Signer: ring, Clock: r.clk, Log: slog.New(slog.DiscardHandler),
		}
		ring.OnUnseal = func(ctx context.Context) {
			_, _ = deliverer.DeliverPending(ctx)
			_ = cp.MakeAll(ctx, "unseal")
		}
		ring.BeforeSeal = func(ctx context.Context) {
			_, _ = deliverer.DeliverPending(ctx)
			_ = cp.MakeAll(ctx, "seal")
		}
		if err := ring.Unseal(ctx, append([]byte(nil), r.passphrase...), r.opt.Who); err != nil {
			return err
		}
		sealed := false
		defer func() {
			if !sealed {
				_ = ring.Seal(ctx, r.opt.Who)
			}
		}()
		fp, err := ring.CheckpointKeyFingerprint()
		if err != nil {
			return err
		}
		r.res.CheckpointFingerprint = fp
		if r.wantCA {
			if err := r.createCA(ctx, ring, pki, ta); err != nil {
				return err
			}
		}
		if r.opt.failAfter == "ca" {
			return errors.New("test stop before the instance row")
		}
		if err := r.finish(ctx, sys); err != nil {
			return err
		}
		sealed = true
		return ring.Seal(ctx, r.opt.Who)
	})
}

func (r *run) createCA(ctx context.Context, ring *keys.Keyring, pki, ta *store.DB) error {
	presets, err := preset.Builtin()
	if err != nil {
		return err
	}
	e := &ca.Engine{PKI: pki.Write, Audit: ta.Write, Scope: store.TenantScope(store.DefaultTenant), Keys: ring, Presets: presets, Clock: r.clk}
	if !r.state.cas[TestRootName] {
		res, err := e.CreateRoot(ctx, ca.RootRequest{
			CASettings: ca.CASettings{Name: TestRootName, BaseURL: r.opt.CABaseURL},
			Subject:    ca.Subject{CommonName: "MyOwnPKI Test Root CA " + r.suffix(ctx, pki), Organization: r.caOrg},
			Who:        r.opt.Who,
		})
		if err != nil {
			return err
		}
		r.res.CAs = append(r.res.CAs, TestRootName)
		r.res.Warnings = append(r.res.Warnings, res.Warnings...)
		if r.opt.failAfter == "ca-root" {
			return errors.New("test stop after the root CA")
		}
	}
	if !r.state.cas[TestIntermediateName] {
		res, err := e.CreateIntermediate(ctx, ca.IntermediateRequest{
			CASettings: ca.CASettings{Name: TestIntermediateName, BaseURL: r.opt.CABaseURL},
			Parent:     TestRootName,
			Subject:    ca.Subject{CommonName: "MyOwnPKI Test Issuing CA " + r.suffix(ctx, pki), Organization: r.caOrg},
			Who:        r.opt.Who,
		})
		if err != nil {
			return err
		}
		r.res.CAs = append(r.res.CAs, TestIntermediateName)
		r.res.Warnings = append(r.res.Warnings, res.Warnings...)
	}
	return nil
}

// suffix keeps the random tag of an existing test root, so root and
// intermediate always carry the same one – also after a resume.
func (r *run) suffix(ctx context.Context, pki *store.DB) string {
	q := pkidb.New(pki.Write)
	root, err := q.GetCAByName(ctx, TestRootName)
	if err != nil || !root.CurrentGeneration.Valid {
		return r.caSuffix
	}
	g, err := q.GetCAGeneration(ctx, pkidb.GetCAGenerationParams{CaID: root.ID, Generation: root.CurrentGeneration.Int64})
	if err != nil {
		return r.caSuffix
	}
	if i := strings.LastIndex(g.SubjectDn, "MyOwnPKI Test Root CA "); i >= 0 {
		tag := g.SubjectDn[i+len("MyOwnPKI Test Root CA "):]
		if j := strings.IndexAny(tag, ",+"); j >= 0 {
			tag = tag[:j]
		}
		if len(tag) == 4 {
			return tag
		}
	}
	return r.caSuffix
}

// finish writes the instance row – the mark that init is complete – with
// the system.init audit event in the same transaction. The seal that
// follows delivers it and signs it in the checkpoint.
func (r *run) finish(ctx context.Context, sys *store.DB) error {
	now := r.clk.Now().UTC()
	tx, err := sys.Write.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	demo := int64(0)
	if r.opt.Mode == Demo {
		demo = 1
	}
	if err := systemdb.New(tx).InsertInstance(ctx, systemdb.InsertInstanceParams{Demo: demo, InitializedAt: now.Format(time.RFC3339)}); err != nil {
		return err
	}
	details := map[string]any{"demo": r.opt.Mode == Demo, "resumed": r.res.Resumed, "test_ca": r.wantCA, "mode": modeName(r.opt.Mode)}
	if err := audit.Enqueue(ctx, tx, now, audit.Entry{
		Time: now, Actor: r.opt.Who.Actor, Action: "system.init", Target: audit.Target{Type: "instance", ID: store.InstanceScope},
		Result: audit.ResultSuccess, SourceIP: r.opt.Who.SourceIP, Details: details,
	}); err != nil {
		return err
	}
	return tx.Commit()
}

func modeName(m Mode) string {
	switch m {
	case Stdin:
		return "stdin"
	case Demo:
		return "demo"
	case Interactive:
	}
	return "interactive"
}

func (r *run) authService(key *auth.Key) *auth.Service {
	svc := auth.NewService(nil, nil, key, r.clk)
	svc.Rand = r.rnd
	if r.opt.argon != nil {
		svc.Hasher = auth.NewHasher(*r.opt.argon, auth.MaxParallelHashes, auth.HashWait)
	}
	return svc
}

// writeDBs opens system.db and the instance audit log for one step.
func (r *run) writeDBs(ctx context.Context, fn func(sys, ia *store.DB) error) error {
	sys, err := store.Open(ctx, r.l.SystemDB())
	if err != nil {
		return err
	}
	defer func() { _ = sys.Close() }()
	ia, err := store.Open(ctx, r.l.InstanceAuditDB())
	if err != nil {
		return err
	}
	defer func() { _ = ia.Close() }()
	return fn(sys, ia)
}

// writeTenantDBs adds pki.db and the audit log of the default tenant.
func (r *run) writeTenantDBs(ctx context.Context, fn func(sys, ia, pki, ta *store.DB) error) error {
	return r.writeDBs(ctx, func(sys, ia *store.DB) error {
		pkiPath, err := r.l.TenantDB(store.DefaultTenant, store.KindPKI)
		if err != nil {
			return err
		}
		auditPath, err := r.l.TenantDB(store.DefaultTenant, store.KindAudit)
		if err != nil {
			return err
		}
		pki, err := store.Open(ctx, pkiPath)
		if err != nil {
			return err
		}
		defer func() { _ = pki.Close() }()
		ta, err := store.Open(ctx, auditPath)
		if err != nil {
			return err
		}
		defer func() { _ = ta.Close() }()
		return fn(sys, ia, pki, ta)
	})
}
