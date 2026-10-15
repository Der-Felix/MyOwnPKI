package setup

import (
	"crypto/hmac"
	"crypto/sha1" // #nosec G505 -- TOTP test codes (RFC 6238)
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/auth"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/clock"
	"github.com/Der-Felix/MyOwnPKI/internal/config"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/store"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
	"github.com/Der-Felix/MyOwnPKI/internal/store/systemdb"
)

var t0 = time.Date(2026, 10, 15, 8, 0, 0, 0, time.UTC)

const (
	passphrase = "correct horse battery staple unseal"
	password   = "a different long admin password"
	baseURL    = "http://pki.homelab.lan"
)

var console = keys.Who{Actor: audit.Actor{Type: audit.ActorUser, Name: "console:test"}, Principal: authz.Console()}

// The tests share the production Argon2id cost of the keyring (256 MiB):
// they don't run in parallel.

func options(t *testing.T, mode Mode) Options {
	t.Helper()
	cfg := config.Default()
	cfg.DataDir = filepath.Join(t.TempDir(), "data")
	return Options{
		Config: cfg, Mode: mode, Clock: clock.NewFake(t0), Hostname: "pki01.homelab.lan", Who: console,
		argon: &auth.Params{Time: 1, MemoryKiB: 8 * 1024, Threads: 1},
	}
}

// script answers prompts in order; an answer may look at what was printed.
type script struct {
	t       *testing.T
	answers []func(out string) string
	out     strings.Builder
}

func (s *script) Printf(format string, args ...any) { fmt.Fprintf(&s.out, format, args...) }

func (s *script) next(prompt string) (string, error) {
	s.out.WriteString(prompt)
	if len(s.answers) == 0 {
		return "", fmt.Errorf("unexpected question %q", prompt)
	}
	a := s.answers[0]
	s.answers = s.answers[1:]
	return a(s.out.String()), nil
}

func (s *script) ReadLine(prompt string) (string, error) { return s.next(prompt) }

func (s *script) ReadSecret(prompt string) ([]byte, error) {
	a, err := s.next(prompt)
	return []byte(a), err
}

func say(v string) func(string) string { return func(string) string { return v } }

// group answers "Type group N" with that group of the printed recovery key.
func group(out string) string {
	key := regexp.MustCompile(`(?m)^    ([0-9A-Z]{6}(?:-[0-9A-Z]{6}){8})$`).FindStringSubmatch(out)
	n := regexp.MustCompile(`Type group (\d)`).FindAllStringSubmatch(out, -1)
	if key == nil || n == nil {
		return "?"
	}
	var i int
	_, _ = fmt.Sscanf(n[len(n)-1][1], "%d", &i)
	return strings.Split(key[1], "-")[i-1]
}

// totp answers with the current code of the printed secret.
func totp(clk *clock.Fake) func(string) string {
	return func(out string) string {
		m := regexp.MustCompile(`secret: ([A-Z2-7 ]+)\n`).FindStringSubmatch(out)
		if m == nil {
			return "000000"
		}
		secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ReplaceAll(m[1], " ", ""))
		if err != nil {
			return "000000"
		}
		mac := hmac.New(sha1.New, secret)
		var msg [8]byte
		binary.BigEndian.PutUint64(msg[:], uint64(clk.Now().Unix()/30)) // #nosec G115 -- positive test time
		mac.Write(msg[:])
		sum := mac.Sum(nil)
		off := sum[len(sum)-1] & 0x0f
		return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[off:off+4])&0x7fffffff)%1_000_000)
	}
}

func interactiveAnswers(clk *clock.Fake, user string) []func(string) string {
	return []func(string) string{
		say(passphrase), say(passphrase), group, group,
		say(user), say(password), say(password), totp(clk),
		say("y"), say(baseURL),
	}
}

// db opens a database of the data directory read-only.
func db(t *testing.T, opt Options, kind string) *store.DB {
	t.Helper()
	l := store.Layout{DataDir: opt.Config.DataDir}
	path := l.SystemDB()
	switch kind {
	case "ia":
		path = l.InstanceAuditDB()
	case "pki":
		path, _ = l.TenantDB(store.DefaultTenant, store.KindPKI)
	}
	d, err := store.OpenReadOnly(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return d
}

func actions(t *testing.T, opt Options) string {
	t.Helper()
	rows, err := db(t, opt, "ia").Read.QueryContext(t.Context(), `SELECT action || '/' || result || ' ' || details_json FROM audit_entries ORDER BY seq`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return strings.Join(out, "\n")
}

func TestInteractiveInit(t *testing.T) {
	opt := options(t, Interactive)
	clk, _ := opt.Clock.(*clock.Fake)
	ui := &script{t: t, answers: interactiveAnswers(clk, "felix")}
	res, err := Run(t.Context(), opt, ui)
	if err != nil {
		t.Fatalf("%v\n%s", err, ui.out.String())
	}
	if len(res.CheckpointFingerprint) == 0 || strings.Join(res.CAs, ",") != "root,issuing" || res.Resumed {
		t.Errorf("result %+v", res)
	}

	q := systemdb.New(db(t, opt, "sys").Read)
	u, err := q.GetUserByName(t.Context(), "felix")
	if err != nil {
		t.Fatal(err)
	}
	bindings, _ := q.ListRoleBindings(t.Context(), u.ID)
	if u.InstanceAdmin != 1 || !u.TotpConfirmedAt.Valid || len(bindings) != 1 || bindings[0].Role != "admin" || bindings[0].TenantID != store.DefaultTenant {
		t.Errorf("first user: %+v %+v", u, bindings)
	}
	if inst, err := q.GetInstance(t.Context()); err != nil || inst.Demo != 0 {
		t.Errorf("instance row: %+v %v", inst, err)
	}
	if _, err := os.Stat(opt.Config.AuthKeyFile()); err != nil {
		t.Errorf("auth key: %v", err)
	}

	// Test CA: unique tag per installation, O = host name.
	pq := pkidb.New(db(t, opt, "pki").Read)
	var tags []string
	for _, name := range []string{TestRootName, TestIntermediateName} {
		c, err := pq.GetCAByName(t.Context(), name)
		if err != nil {
			t.Fatal(err)
		}
		g, _ := pq.GetCAGeneration(t.Context(), pkidb.GetCAGenerationParams{CaID: c.ID, Generation: 1})
		m := regexp.MustCompile(`^CN=MyOwnPKI Test (?:Root|Issuing) CA ([0-9A-Z]{4}),O=pki01\.homelab\.lan$`).FindStringSubmatch(g.SubjectDn)
		if m == nil {
			t.Fatalf("subject %q", g.SubjectDn)
		}
		tags = append(tags, m[1])
	}
	if tags[0] != tags[1] {
		t.Errorf("root and intermediate tags differ: %v", tags)
	}

	got := actions(t, opt)
	for _, want := range []string{"system.keys_init/success", `"totp_confirmed":true`, "system.unseal/success", "audit.checkpoint/success",
		"system.seal/success", `system.init/success {"demo":false,"mode":"interactive","resumed":false,"test_ca":true}`} {
		if !strings.Contains(got, want) {
			t.Errorf("audit lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, passphrase) || strings.Contains(got, password) {
		t.Error("a secret is in the audit log")
	}
	// Recovery codes are shown at the end, the key and the fingerprint too.
	if !strings.Contains(ui.out.String(), "Recovery key") {
		t.Errorf("output:\n%s", ui.out.String())
	}

	if _, err := Run(t.Context(), opt, &script{t: t}); !errors.Is(err, ErrInitialized) {
		t.Errorf("second init: %v", err)
	}
}

// TestAbortsWriteNothing: until all questions are answered, nothing exists.
func TestAbortsWriteNothing(t *testing.T) {
	cases := map[string]func(clk *clock.Fake) []func(string) string{
		"wrong recovery key group": func(*clock.Fake) []func(string) string {
			return []func(string) string{say(passphrase), say(passphrase), say("AAAAAA"), say("AAAAAA")}
		},
		"three wrong TOTP codes": func(*clock.Fake) []func(string) string {
			return []func(string) string{say(passphrase), say(passphrase), group, group, say("felix"), say(password), say(password),
				say("000000"), say("000000"), say("000000")}
		},
		"password equals the passphrase": func(*clock.Fake) []func(string) string {
			same := strings.ToUpper(passphrase)
			return []func(string) string{say(passphrase), say(passphrase), group, group, say("felix"), say(same), say(same), say(same)}
		},
		"base URL missing": func(clk *clock.Fake) []func(string) string {
			a := interactiveAnswers(clk, "felix")
			return append(a[:len(a)-1], say(""))
		},
	}
	for name, answers := range cases {
		opt := options(t, Interactive)
		clk, _ := opt.Clock.(*clock.Fake)
		ui := &script{t: t, answers: answers(clk)}
		_, err := Run(t.Context(), opt, ui)
		if err == nil {
			t.Errorf("%s: init succeeded", name)
		}
		if _, serr := os.Stat(opt.Config.DataDir); !errors.Is(serr, os.ErrNotExist) {
			t.Errorf("%s: the data directory was created (%v)", name, err)
		}
		if name == "password equals the passphrase" && !strings.Contains(ui.out.String(), "must differ from the unseal passphrase") {
			t.Errorf("%s: no reason given:\n%s", name, ui.out.String())
		}
	}
}

// TestStdinInit: automation; a passphrase ending in a space stays as it is.
func TestStdinInit(t *testing.T) {
	opt := options(t, Stdin)
	dir := t.TempDir()
	opt.AdminUser, opt.RecoveryKeyFile, opt.OTPAuthFile = "ops", filepath.Join(dir, "recovery.txt"), filepath.Join(dir, "otpauth.txt")
	pass := passphrase + " "
	in := NewLineInput(strings.NewReader(pass+"\r\n"+password+"\n"), &strings.Builder{})
	if _, err := Run(t.Context(), opt, in); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{opt.RecoveryKeyFile, opt.OTPAuthFile} {
		if data, err := os.ReadFile(f); err != nil || len(data) == 0 {
			t.Errorf("%s: %v", f, err)
		}
	}
	u, err := systemdb.New(db(t, opt, "sys").Read).GetUserByName(t.Context(), "ops")
	if err != nil || u.TotpConfirmedAt.Valid {
		t.Errorf("user: %+v %v (TOTP is confirmed at the first login)", u, err)
	}
	ring := func() *keys.Keyring {
		sys, _ := store.Open(t.Context(), store.Layout{DataDir: opt.Config.DataDir}.SystemDB())
		ia, _ := store.Open(t.Context(), store.Layout{DataDir: opt.Config.DataDir}.InstanceAuditDB())
		t.Cleanup(func() { _ = sys.Close(); _ = ia.Close() })
		return keys.New(sys.Write, ia.Write, clock.NewFake(t0))
	}()
	if err := ring.VerifyPassphrase(t.Context(), []byte(pass), console); err != nil {
		t.Errorf("passphrase with its trailing space: %v", err)
	}
	if err := ring.VerifyPassphrase(t.Context(), []byte(passphrase), console); !errors.Is(err, keys.ErrWrongSecret) {
		t.Errorf("the trailing space was trimmed: %v", err)
	}

	for name, o := range map[string]func(*Options){
		"no recovery key file": func(o *Options) { o.RecoveryKeyFile = "" },
		"no otpauth file":      func(o *Options) { o.OTPAuthFile = "" },
	} {
		o2 := options(t, Stdin)
		o2.AdminUser, o2.RecoveryKeyFile, o2.OTPAuthFile = "ops", filepath.Join(t.TempDir(), "r"), filepath.Join(t.TempDir(), "o")
		o(&o2)
		if _, err := Run(t.Context(), o2, NewLineInput(strings.NewReader(passphrase+"\n"+password+"\n"), &strings.Builder{})); !errors.Is(err, ErrNeedsFile) {
			t.Errorf("%s: %v", name, err)
		}
	}
	o3 := options(t, Stdin)
	o3.AdminUser, o3.RecoveryKeyFile, o3.OTPAuthFile = "ops", filepath.Join(t.TempDir(), "r"), filepath.Join(t.TempDir(), "o")
	if _, err := Run(t.Context(), o3, NewLineInput(strings.NewReader(passphrase+"\n"+strings.ToUpper(passphrase)+"\n"), &strings.Builder{})); !errors.Is(err, ErrSameSecret) {
		t.Errorf("same secret: %v", err)
	}
}

// TestDemoInit: everything generated into one file; the demo mark stays.
func TestDemoInit(t *testing.T) {
	opt := options(t, Demo)
	opt.CABaseURL = baseURL
	res, err := Run(t.Context(), opt, &script{t: t})
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(res.DemoSecretsFile)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"DEMO instance", "unseal passphrase: ", "recovery key: ", "admin user: demo", "admin password: ", "otpauth://totp/", "recovery code: "} {
		if !strings.Contains(string(data), want) {
			t.Errorf("demo file lacks %q", want)
		}
	}
	if len(res.CAs) != 2 {
		t.Errorf("CAs %v", res.CAs)
	}
	sys := db(t, opt, "sys")
	if inst, ierr := systemdb.New(sys.Read).GetInstance(t.Context()); ierr != nil || inst.Demo != 1 {
		t.Errorf("demo mark: %+v %v", inst, ierr)
	}
	w, err := store.Open(t.Context(), store.Layout{DataDir: opt.Config.DataDir}.SystemDB())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = w.Close() }()
	for _, stmt := range []string{`UPDATE instance SET demo = 0`, `DELETE FROM instance`} {
		if _, err := w.Write.ExecContext(t.Context(), stmt); err == nil {
			t.Errorf("%s: the demo mark can be removed", stmt)
		}
	}
	if !strings.Contains(actions(t, opt), `"demo":true,"mode":"demo"`) {
		t.Error("the audit entry of init doesn't say demo")
	}
}

// TestResumeAfterEachStep: init stops after every write step; running it
// again (with the passphrase as proof) finishes only what is missing.
func TestResumeAfterEachStep(t *testing.T) {
	for _, stop := range []string{"files", "migrate", "auth-key", "root-key", "user", "ca-root", "ca"} {
		t.Run(stop, func(t *testing.T) {
			opt := options(t, Stdin)
			dir := t.TempDir()
			opt.AdminUser, opt.WithCA, opt.CABaseURL = "ops", true, baseURL
			opt.RecoveryKeyFile, opt.OTPAuthFile = filepath.Join(dir, "recovery.txt"), filepath.Join(dir, "otpauth.txt")
			opt.failAfter = stop
			input := func() UI { return NewLineInput(strings.NewReader(passphrase+"\n"+password+"\n"), &strings.Builder{}) }
			if _, err := Run(t.Context(), opt, input()); err == nil {
				t.Fatal("no stop")
			}
			keyBefore, _ := os.ReadFile(opt.Config.AuthKeyFile())

			opt.failAfter = ""
			res, err := Run(t.Context(), opt, input())
			if err != nil && strings.Contains(err.Error(), "exists already") {
				// Files of a run that never reached the database: the
				// message tells the operator to move them away.
				for _, f := range []string{opt.RecoveryKeyFile, opt.OTPAuthFile} {
					_ = os.Remove(f)
				}
				res, err = Run(t.Context(), opt, input())
			}
			if err != nil {
				t.Fatalf("resume: %v", err)
			}
			sq := systemdb.New(db(t, opt, "sys").Read)
			if n, _ := sq.CountUsers(t.Context()); n != 1 {
				t.Errorf("%d users", n)
			}
			if n, _ := sq.CountUnsealSlots(t.Context()); n != 2 {
				t.Errorf("%d unseal slots", n)
			}
			if _, err := sq.GetInstance(t.Context()); err != nil {
				t.Errorf("instance row: %v", err)
			}
			if keyBefore != nil {
				if keyAfter, _ := os.ReadFile(opt.Config.AuthKeyFile()); string(keyAfter) != string(keyBefore) {
					t.Error("the auth key was replaced")
				}
			}
			var cas int
			if err := db(t, opt, "pki").Read.QueryRowContext(t.Context(), `SELECT count(*) FROM cas`).Scan(&cas); err != nil || cas != 2 {
				t.Errorf("%d CAs, %v", cas, err)
			}
			subjects := caTags(t, opt)
			if len(subjects) != 1 {
				t.Errorf("root and intermediate tags differ after resume: %v", subjects)
			}
			wantResumed := stop != "files" && stop != "migrate" && stop != "auth-key"
			if res.Resumed != wantResumed {
				t.Errorf("resumed %v, want %v", res.Resumed, wantResumed)
			}
			if wantResumed && !strings.Contains(actions(t, opt), "system.secret_verify/success") {
				t.Error("resume without passphrase proof")
			}
		})
	}
}

// caTags returns the random tags in the subjects of all CA generations.
func caTags(t *testing.T, opt Options) map[string]bool {
	t.Helper()
	rows, err := db(t, opt, "pki").Read.QueryContext(t.Context(), `SELECT subject_dn FROM ca_generations`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	tags := map[string]bool{}
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		if m := regexp.MustCompile(` CA ([0-9A-Z]{4}),`).FindStringSubmatch(s); m != nil {
			tags[m[1]] = true
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return tags
}

// TestInitIsSigned: the checkpoint made before the seal covers system.init –
// verified with the noted checkpoint key; only system.seal comes after it.
func TestInitIsSigned(t *testing.T) {
	opt := options(t, Demo)
	res, err := Run(t.Context(), opt, &script{t: t})
	if err != nil {
		t.Fatal(err)
	}
	ia := db(t, opt, "ia")
	rep, err := audit.VerifyWith(t.Context(), ia.Read, store.InstanceScope, audit.VerifyOptions{CheckpointKey: res.CheckpointFingerprint})
	if err != nil || rep.Break != nil || rep.LastCheckpoint == nil {
		t.Fatalf("verify: %+v %v", rep, err)
	}
	var initSeq int64
	if serr := ia.Read.QueryRowContext(t.Context(), `SELECT seq FROM audit_entries WHERE action = 'system.init'`).Scan(&initSeq); serr != nil {
		t.Fatal(serr)
	}
	var after []string
	rows, err := ia.Read.QueryContext(t.Context(), `SELECT action FROM audit_entries WHERE seq > ? ORDER BY seq`, rep.LastCheckpoint.Seq)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			t.Fatal(err)
		}
		after = append(after, a)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if initSeq >= rep.LastCheckpoint.Seq || strings.Join(after, ",") != "system.seal" {
		t.Errorf("system.init at %d, last checkpoint at %d, after it: %v", initSeq, rep.LastCheckpoint.Seq, after)
	}
}
