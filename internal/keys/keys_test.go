package keys

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/clock"
	"github.com/Der-Felix/MyOwnPKI/internal/store"
)

var t0 = time.Date(2026, 10, 13, 8, 0, 0, 0, time.UTC)

// testParams keep tests fast; the production values are checked separately.
var testParams = argon2Params{Time: 1, MemoryKiB: 8 * 1024, Threads: 1}

// admin is a signed-in instance admin (unseal needs no step-up).
var admin = Who{
	Actor: audit.Actor{Type: audit.ActorUser, ID: "u-1", Name: "it-admin"}, SourceIP: "192.0.2.10",
	Principal: &authz.Principal{Kind: authz.KindUser, UserID: "u-1", Username: "it-admin", InstanceAdmin: true},
}

type env struct {
	k                *Keyring
	clk              *clock.Fake
	l                store.Layout
	system, ia, pki  *sql.DB
	deliver          func()
	pkiPath, sysPath string
	passphrase       string
	recovery         RecoveryKey
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{clk: clock.NewFake(t0), l: store.Layout{DataDir: t.TempDir()}, passphrase: "correct horse battery staple"}
	if _, err := store.Migrate(t.Context(), e.l, store.DefaultTenant, e.clk.Now); err != nil {
		t.Fatal(err)
	}
	open := func(path string) *sql.DB {
		db, err := store.Open(t.Context(), path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		return db.Write
	}
	e.sysPath = e.l.SystemDB()
	e.pkiPath, _ = e.l.TenantDB(store.DefaultTenant, store.KindPKI)
	e.system, e.ia, e.pki = open(e.sysPath), open(e.l.InstanceAuditDB()), open(e.pkiPath)
	e.k = New(e.system, e.ia, e.clk)
	e.k.params = testParams
	d := &audit.Deliverer{
		Routes: []audit.Route{{Source: "system", From: e.system, To: e.ia, Scope: store.InstanceScope}},
		Clock:  e.clk, Log: slog.New(slog.DiscardHandler),
	}
	e.deliver = func() {
		if _, err := d.DeliverPending(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	var err error
	if e.recovery, err = NewRecoveryKey(nil); err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *env) init(t *testing.T) {
	t.Helper()
	if err := e.k.Init(t.Context(), []byte(e.passphrase), e.recovery, admin); err != nil {
		t.Fatal(err)
	}
}

func (e *env) unseal(t *testing.T) {
	t.Helper()
	if err := e.k.Unseal(t.Context(), []byte(e.passphrase), admin); err != nil {
		t.Fatal(err)
	}
}

// actions lists action/result of the instance audit log, after delivering the outbox.
func (e *env) actions(t *testing.T) []string {
	t.Helper()
	e.deliver()
	rows, err := e.ia.QueryContext(t.Context(), `SELECT action, result, details_json FROM audit_entries ORDER BY seq`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var a, r, d string
		if err := rows.Scan(&a, &r, &d); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(d, e.passphrase) || strings.Contains(d, e.recovery.Reveal()) {
			t.Errorf("secret in audit details: %s", d)
		}
		out = append(out, a+"/"+r)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestInitUnsealSeal(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	if err := e.k.Unseal(t.Context(), []byte(e.passphrase), admin); !errors.Is(err, ErrNotInitialized) {
		t.Errorf("unseal before init: %v", err)
	}
	pass := []byte(e.passphrase)
	if err := e.k.Init(t.Context(), pass, e.recovery, admin); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pass, make([]byte, len(pass))) {
		t.Error("Init did not clear the passphrase buffer")
	}
	if err := e.k.Init(t.Context(), []byte(e.passphrase), e.recovery, admin); !errors.Is(err, ErrAlreadyInitialized) {
		t.Errorf("second init: %v", err)
	}
	if !e.k.Status().Sealed {
		t.Error("keyring unsealed right after init")
	}
	e.unseal(t)
	if e.k.Status().Sealed {
		t.Error("still sealed after unseal")
	}
	if err := e.k.Unseal(t.Context(), []byte(e.passphrase), admin); !errors.Is(err, ErrAlreadyUnsealed) {
		t.Errorf("unseal twice: %v", err)
	}
	e.clk.Advance(time.Hour)
	if err := e.k.Seal(t.Context(), admin); err != nil {
		t.Fatal(err)
	}
	if st := e.k.Status(); !st.Sealed || !st.SealedSince.Equal(t0.Add(time.Hour)) {
		t.Errorf("after seal: %+v", st)
	}
	if err := e.k.Seal(t.Context(), admin); err != nil {
		t.Error(err)
	}
	want := "system.unseal/success system.seal/success system.keys_init/success"
	if got := strings.Join(e.actions(t), " "); got != want {
		t.Errorf("audit = %s\nwant    %s (keys_init arrives via the outbox)", got, want)
	}
}

func TestWrongPassphraseAndLockout(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.init(t)
	wrong := func() error { return e.k.Unseal(t.Context(), []byte("this is not the passphrase"), admin) }
	for i := range 3 {
		if err := wrong(); !errors.Is(err, ErrWrongSecret) {
			t.Fatalf("attempt %d: %v", i+1, err)
		}
	}
	// Locked now – even the right passphrase is refused without a check.
	err := e.k.Unseal(t.Context(), []byte(e.passphrase), admin)
	var locked *LockedError
	if !errors.As(err, &locked) || locked.RetryAfter != time.Minute {
		t.Fatalf("after 3 failures: %v, want locked for 1m", err)
	}
	e.clk.Advance(61 * time.Second)
	if err := wrong(); !errors.Is(err, ErrWrongSecret) {
		t.Fatal(err)
	}
	if err := e.k.Unseal(t.Context(), []byte(e.passphrase), admin); !errors.As(err, &locked) || locked.RetryAfter != 2*time.Minute {
		t.Fatalf("after 4 failures: %v, want 2m", err)
	}
	e.clk.Advance(2*time.Minute + time.Second)
	e.unseal(t)
	if e.k.lim != (limiter{}) {
		t.Error("success did not reset the counter")
	}
	got := strings.Join(e.actions(t), " ")
	want := "system.unseal/failure system.unseal/failure system.unseal/failure system.unseal/denied " +
		"system.unseal/failure system.unseal/denied system.unseal/success system.keys_init/success"
	if got != want {
		t.Errorf("audit = %s\nwant    %s", got, want)
	}
}

func TestLimiterCapsAtOneHour(t *testing.T) {
	t.Parallel()
	var l limiter
	for range 40 {
		l.failure(t0)
	}
	if w := l.wait(t0); w != time.Hour {
		t.Errorf("wait after 40 failures = %v, want 1h", w)
	}
}

func TestPassphraseRules(t *testing.T) {
	t.Parallel()
	for p, ok := range map[string]bool{
		"fifteen chars!!":                   false,
		"sixteen chars!!!":                  true,
		"äöüßäöüßäöüßäöüß":                  true, // 16 characters, 32 bytes
		"\xff\xfe invalid utf-8 bytes ....": false,
		strings.Repeat("x", 1025):           false,
	} {
		if err := CheckPassphrase([]byte(p)); (err == nil) != ok {
			t.Errorf("%q: err = %v, want ok=%v", p, err, ok)
		}
	}
	if !HasNonASCII([]byte("pässphrase")) || HasNonASCII([]byte("passphrase")) {
		t.Error("HasNonASCII")
	}
	e := newEnv(t)
	if err := e.k.Init(t.Context(), []byte("too short"), e.recovery, admin); !errors.Is(err, ErrWeakPassphrase) {
		t.Errorf("weak passphrase at init: %v", err)
	}
}

func TestRecoveryKeyPaths(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.init(t)

	other, _ := NewRecoveryKey(nil)
	if err := e.k.UnsealWithRecovery(t.Context(), other, admin); !errors.Is(err, ErrWrongSecret) {
		t.Errorf("wrong recovery key: %v", err)
	}
	if err := e.k.UnsealWithRecovery(t.Context(), e.recovery, admin); err != nil {
		t.Fatal(err)
	}
	if err := e.k.Seal(t.Context(), admin); err != nil {
		t.Fatal(err)
	}

	// Lost passphrase: reset with the recovery key while sealed.
	newPass := "a brand new passphrase 2026"
	if err := e.k.ResetPassphrase(t.Context(), e.recovery, []byte(newPass), admin); err != nil {
		t.Fatal(err)
	}
	if !e.k.Status().Sealed {
		t.Error("reset unsealed the keyring")
	}
	if err := e.k.Unseal(t.Context(), []byte(e.passphrase), admin); !errors.Is(err, ErrWrongSecret) {
		t.Errorf("old passphrase after reset: %v", err)
	}
	if err := e.k.Unseal(t.Context(), []byte(newPass), admin); err != nil {
		t.Fatalf("new passphrase after reset: %v", err)
	}

	// Rotate the recovery key: needs the passphrase; the old key stops working.
	next, _ := NewRecoveryKey(nil)
	if err := e.k.RotateRecoveryKey(t.Context(), []byte("not the passphrase at all"), next, admin); !errors.Is(err, ErrWrongSecret) {
		t.Errorf("rotate with wrong passphrase: %v", err)
	}
	if err := e.k.RotateRecoveryKey(t.Context(), []byte(newPass), next, admin); err != nil {
		t.Fatal(err)
	}
	if err := e.k.Seal(t.Context(), admin); err != nil {
		t.Fatal(err)
	}
	if err := e.k.RotateRecoveryKey(t.Context(), []byte(newPass), next, admin); !errors.Is(err, ErrSealed) {
		t.Errorf("rotate while sealed: %v", err)
	}
	if err := e.k.UnsealWithRecovery(t.Context(), e.recovery, admin); !errors.Is(err, ErrWrongSecret) {
		t.Errorf("old recovery key after rotation: %v", err)
	}
	if err := e.k.UnsealWithRecovery(t.Context(), next, admin); err != nil {
		t.Errorf("new recovery key: %v", err)
	}

	for _, want := range []string{"system.unseal_recovery/failure", "system.unseal_recovery/success", "system.passphrase_reset/success",
		"system.recovery_key_rotate/failure", "system.recovery_key_rotate/success"} {
		if !strings.Contains(strings.Join(e.actions(t), " "), want) {
			t.Errorf("audit lacks %s", want)
		}
	}
}

func TestChangePassphraseKeepsKeysReadable(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.init(t)
	newPass := "another long passphrase!"
	if err := e.k.ChangePassphrase(t.Context(), []byte(e.passphrase), []byte(newPass), admin); !errors.Is(err, ErrSealed) {
		t.Errorf("change while sealed: %v", err)
	}
	e.unseal(t)
	env, pkcs8 := encryptTestKey(t, e, "k-1")
	if err := e.k.ChangePassphrase(t.Context(), []byte("wrong current passphrase"), []byte(newPass), admin); !errors.Is(err, ErrWrongSecret) {
		t.Errorf("wrong current passphrase: %v", err)
	}
	if err := e.k.ChangePassphrase(t.Context(), []byte(e.passphrase), []byte(newPass), admin); err != nil {
		t.Fatal(err)
	}
	if err := e.k.Seal(t.Context(), admin); err != nil {
		t.Fatal(err)
	}
	if err := e.k.Unseal(t.Context(), []byte(e.passphrase), admin); !errors.Is(err, ErrWrongSecret) {
		t.Errorf("old passphrase still works: %v", err)
	}
	if err := e.k.Unseal(t.Context(), []byte(newPass), admin); err != nil {
		t.Fatal(err)
	}
	err := e.k.WithKey("k-1", PurposeCA, "ecdsa-p384", env, func(got []byte) error {
		if !bytes.Equal(got, pkcs8) {
			return errors.New("different key")
		}
		return nil
	})
	if err != nil {
		t.Errorf("key after passphrase change: %v", err)
	}
	if !strings.Contains(strings.Join(e.actions(t), " "), "system.passphrase_change/success") {
		t.Error("passphrase change not audited")
	}
}

func encryptTestKey(t *testing.T, e *env, id string) (Envelope, []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	env, err := e.k.EncryptKey(id, PurposeCA, "ecdsa-p384", pkcs8)
	if err != nil {
		t.Fatal(err)
	}
	return env, pkcs8
}

func TestEnvelopeSignsAndIsBoundToItsRow(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.init(t)
	if _, err := e.k.EncryptKey("k-1", PurposeCA, "ecdsa-p384", []byte("x")); !errors.Is(err, ErrSealed) {
		t.Errorf("encrypt while sealed: %v", err)
	}
	e.unseal(t)
	env, _ := encryptTestKey(t, e, "k-1")

	digest := sha256.Sum256([]byte("tbs certificate"))
	err := e.k.WithSigner("k-1", PurposeCA, "ecdsa-p384", env, func(s crypto.Signer) error {
		sig, err := s.Sign(rand.Reader, digest[:], crypto.SHA256)
		if err != nil {
			return err
		}
		pub, ok := s.Public().(*ecdsa.PublicKey)
		if !ok || !ecdsa.VerifyASN1(pub, digest[:], sig) {
			return errors.New("signature does not verify")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	for name, call := range map[string]func() error{
		"other key id":    func() error { return e.k.WithKey("k-2", PurposeCA, "ecdsa-p384", env, noop) },
		"other purpose":   func() error { return e.k.WithKey("k-1", PurposeLeaf, "ecdsa-p384", env, noop) },
		"other algorithm": func() error { return e.k.WithKey("k-1", PurposeCA, "ecdsa-p256", env, noop) },
	} {
		if err := call(); !errors.Is(err, ErrDecrypt) {
			t.Errorf("%s: err = %v, want ErrDecrypt", name, err)
		}
	}
	if err := e.k.Seal(t.Context(), admin); err != nil {
		t.Fatal(err)
	}
	if err := e.k.WithKey("k-1", PurposeCA, "ecdsa-p384", env, noop); !errors.Is(err, ErrSealed) {
		t.Errorf("use while sealed: %v", err)
	}
}

func noop([]byte) error { return nil }

func TestSealWaitsForRunningSignature(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.init(t)
	e.unseal(t)
	env, _ := encryptTestKey(t, e, "k-1")

	inside, release, sealed := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		_ = e.k.WithKey("k-1", PurposeCA, "ecdsa-p384", env, func([]byte) error {
			close(inside)
			<-release
			return nil
		})
	}()
	<-inside
	go func() { sealed <- e.k.Seal(t.Context(), admin) }()
	select {
	case <-sealed:
		t.Fatal("seal returned while a signature was still running")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	if err := <-sealed; err != nil {
		t.Fatal(err)
	}
	if !e.k.Status().Sealed {
		t.Error("not sealed after the signature finished")
	}
}

// PHASE1 step 6: no plaintext key bytes in the database files.
func TestNoPlaintextKeyInDatabaseFiles(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.init(t)
	e.unseal(t)
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	env, err := e.k.EncryptKey("ca-1", PurposeCA, "ecdsa-p384", pkcs8)
	if err != nil {
		t.Fatal(err)
	}
	if err = SaveKey(t.Context(), e.pki, StoredKey{ID: "ca-1", Purpose: PurposeCA, Algorithm: "ecdsa-p384", Envelope: env}, "2026-10-13T08:00:00.000Z"); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadKey(t.Context(), e.pki, "ca-1")
	if err != nil || !bytes.Equal(loaded.Envelope.Ciphertext, env.Ciphertext) {
		t.Fatalf("load: %v", err)
	}

	secrets := map[string][]byte{
		"PKCS#8 key":      pkcs8,
		"private scalar":  mustBytes(t, priv),
		"root key":        append([]byte(nil), e.k.root...),
		"passphrase":      []byte(e.passphrase),
		"recovery key":    e.recovery[:],
		"recovery string": []byte(e.recovery.Reveal()),
	}
	for _, base := range []string{e.pkiPath, e.sysPath, e.l.InstanceAuditDB()} {
		for _, suffix := range []string{"", "-wal", "-shm"} {
			data, err := os.ReadFile(base + suffix)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				t.Fatal(err)
			}
			for name, s := range secrets {
				// Any 16-byte window of the secret would already be a leak.
				for i := 0; i+16 <= len(s); i += 8 {
					if bytes.Contains(data, s[i:i+16]) {
						t.Errorf("%s: contains bytes of the %s", filepath.Base(base+suffix), name)
						break
					}
				}
			}
		}
	}
}

func TestTamperedParamsAreRejected(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.init(t)
	if _, err := e.system.ExecContext(t.Context(), `UPDATE unseal SET kdf_params = '{"t":4,"m":1073741824,"p":4}' WHERE slot = 'passphrase'`); err != nil {
		t.Fatal(err)
	}
	if err := e.k.Unseal(t.Context(), []byte(e.passphrase), admin); err == nil || !strings.Contains(err.Error(), "out of bounds") {
		t.Errorf("huge Argon2 memory accepted: %v", err)
	}
}

func TestSwappedSlotsDontOpen(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.init(t)
	// Copy the recovery wrap into the passphrase slot: the additional data
	// (purpose "passphrase") no longer matches.
	if _, err := e.system.ExecContext(t.Context(),
		`UPDATE unseal SET wrapped_root_key = (SELECT wrapped_root_key FROM unseal WHERE slot = 'recovery') WHERE slot = 'passphrase'`); err != nil {
		t.Fatal(err)
	}
	if err := e.k.Unseal(t.Context(), []byte(e.passphrase), admin); !errors.Is(err, ErrWrongSecret) {
		t.Errorf("swapped slot: %v", err)
	}
}

func TestProductionArgon2Parameters(t *testing.T) {
	t.Parallel()
	if defaultArgon2 != (argon2Params{Time: 4, MemoryKiB: 256 * 1024, Threads: 4}) {
		t.Errorf("defaults changed: %+v (owner decision: t=4, 256 MiB, p=4)", defaultArgon2)
	}
	if err := defaultArgon2.check(); err != nil {
		t.Error(err)
	}
	if testing.Short() {
		t.Skip("one real derivation takes 256 MiB")
	}
	start := time.Now()
	kek := passphraseKEK([]byte("benchmark passphrase"), make([]byte, 32), defaultArgon2)
	t.Logf("Argon2id t=4 m=256MiB p=4 on %d CPUs: %v", runtime.NumCPU(), time.Since(start).Round(time.Millisecond))
	if len(kek) != keySize {
		t.Error("KEK length")
	}
}

func TestRecoveryKeyFormat(t *testing.T) {
	t.Parallel()
	k := RecoveryKey(sha256.Sum256([]byte("fixed test recovery key")))
	text := k.Reveal()
	groups := strings.Split(text, "-")
	if len(groups) != 9 {
		t.Fatalf("%d groups: %s", len(groups), text)
	}
	for _, g := range groups {
		if len(g) != 6 || strings.ContainsAny(g, "ILOU") {
			t.Errorf("group %q", g)
		}
	}
	for _, typed := range []string{
		text,
		strings.ToLower(text),
		strings.ReplaceAll(text, "-", " "),
		strings.NewReplacer("0", "O", "1", "I").Replace(text),
		strings.NewReplacer("1", "l").Replace(text),
	} {
		got, err := ParseRecoveryKey(typed)
		if err != nil || !got.equal(k) {
			t.Errorf("parse %q: %v", typed, err)
		}
	}
	// Every single-character typo is caught by the check characters.
	plain := strings.ReplaceAll(text, "-", "")
	for i := range plain {
		repl := byte('A')
		if plain[i] == 'A' {
			repl = 'B'
		}
		typo := plain[:i] + string(repl) + plain[i+1:]
		if _, err := ParseRecoveryKey(typo); !errors.Is(err, ErrRecoveryKeyFormat) {
			t.Errorf("typo at position %d not detected", i)
		}
	}
	for _, bad := range []string{"", "ABC", plain + "A", strings.Replace(plain, plain[:1], "U", 1)} {
		if _, err := ParseRecoveryKey(bad); !errors.Is(err, ErrRecoveryKeyFormat) {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestRecoveryKeyNeverPrintsByAccident(t *testing.T) {
	t.Parallel()
	k, _ := NewRecoveryKey(nil)
	secret := k.Reveal()
	var logBuf bytes.Buffer
	slog.New(slog.NewTextHandler(&logBuf, nil)).Info("init", slog.Any("recovery", k))
	js, _ := json.Marshal(map[string]any{"k": k})
	for name, s := range map[string]string{
		"%v": fmt.Sprintf("%v", k), "String": k.String(), "%+v": fmt.Sprintf("%+v", k), "%#v": fmt.Sprintf("%#v", k),
		"json": string(js), "slog": logBuf.String(),
	} {
		if strings.Contains(s, secret[:6]) || !strings.Contains(s, "redacted") {
			t.Errorf("%s shows the key: %s", name, s)
		}
	}
}

func TestConfirmGroups(t *testing.T) {
	t.Parallel()
	k, _ := NewRecoveryKey(nil)
	g := k.Groups()
	for range 50 {
		idx, err := ConfirmIndexes(nil)
		if err != nil || idx[0] >= idx[1] || idx[0] < 0 || idx[1] > 8 {
			t.Fatalf("indexes %v, %v", idx, err)
		}
	}
	if !k.CheckGroups(map[int]string{2: strings.ToLower(g[2]), 7: g[7]}) {
		t.Error("correct groups rejected")
	}
	for name, typed := range map[string]map[int]string{
		"wrong group":    {2: g[3], 7: g[7]},
		"nothing typed":  {},
		"out of range":   {9: g[0]},
		"one wrong char": {2: g[2][:5] + "X", 7: g[7]},
	} {
		if g[2][5] == 'X' && name == "one wrong char" {
			continue
		}
		if k.CheckGroups(typed) {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestRecoveryKeyOutput(t *testing.T) {
	t.Parallel()
	tests := []struct {
		interactive bool
		file        string
		want        RecoveryOutput
		wantErr     error
	}{
		{true, "", ShowOnTerminal, nil},
		{false, "", 0, ErrRecoveryKeyNeedsFile}, // Docker, systemd, pipe
		{false, "/secure/recovery.txt", WriteToFile, nil},
		{true, "/secure/recovery.txt", WriteToFile, nil},
	}
	for _, tt := range tests {
		got, err := ChooseRecoveryOutput(tt.interactive, tt.file)
		if got != tt.want || !errors.Is(err, tt.wantErr) {
			t.Errorf("interactive=%v file=%q: %v, %v", tt.interactive, tt.file, got, err)
		}
	}

	k, _ := NewRecoveryKey(nil)
	path := filepath.Join(t.TempDir(), "recovery.txt")
	if err := WriteRecoveryKeyFile(path, k); err != nil {
		t.Fatal(err)
	}
	if err := WriteRecoveryKeyFile(path, k); err == nil {
		t.Error("existing recovery key file overwritten")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Errorf("mode %v, want 0600", info.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var keyLine string
	for _, line := range strings.Split(string(data), "\n") {
		if line != "" && !strings.HasPrefix(line, "#") {
			keyLine = line
		}
	}
	if got, err := ParseRecoveryKey(keyLine); err != nil || !got.equal(k) {
		t.Errorf("file does not hold the key: %v", err)
	}
	if !strings.Contains(string(data), "delete this file from the server") {
		t.Error("file lacks the handling hint")
	}
}

func mustBytes(t *testing.T, k *ecdsa.PrivateKey) []byte {
	t.Helper()
	b, err := k.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestCheckpointKey(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.init(t)
	if _, _, err := e.k.SignCheckpoint([]byte("m")); !errors.Is(err, ErrSealed) || !errors.Is(err, audit.ErrNoSigner) {
		t.Errorf("sealed: %v, want ErrSealed and audit.ErrNoSigner", err)
	}
	e.unseal(t)
	first, err := e.k.CheckpointKeyFingerprint()
	if err != nil || len(first) != 32 {
		t.Fatalf("fingerprint %q, %v", first, err)
	}
	sig, pub, err := e.k.SignCheckpoint([]byte("checkpoint"))
	if err != nil || !ed25519.Verify(pub, []byte("checkpoint"), sig) {
		t.Fatalf("signature: %v", err)
	}
	if err := e.k.Seal(t.Context(), admin); err != nil {
		t.Fatal(err)
	}
	if err := e.k.UnsealWithRecovery(t.Context(), e.recovery, admin); err != nil {
		t.Fatal(err)
	}
	if again, _ := e.k.CheckpointKeyFingerprint(); again != first {
		t.Error("checkpoint key changed across seal/unseal – it must follow from the root key alone")
	}

	other := newEnv(t)
	other.init(t)
	other.unseal(t)
	if fp, _ := other.k.CheckpointKeyFingerprint(); fp == first {
		t.Error("two root keys give the same checkpoint key")
	}
}

func TestUnsealAndSealMakeCheckpoints(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	tenantLog, _ := e.l.TenantDB(store.DefaultTenant, store.KindAudit)
	tdb, err := store.Open(t.Context(), tenantLog)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tdb.Close() }()
	cp := &audit.Checkpointer{
		Logs:   []audit.CheckpointLog{{DB: e.ia, Scope: store.InstanceScope}, {DB: tdb.Write, Scope: store.TenantScope(store.DefaultTenant)}},
		Signer: e.k, Clock: e.clk, Log: slog.New(slog.DiscardHandler),
	}
	var hooks []string
	e.k.OnUnseal = func(ctx context.Context) {
		hooks = append(hooks, "unseal")
		if mErr := cp.MakeAll(ctx, "unseal"); mErr != nil {
			t.Error(mErr)
		}
	}
	e.k.BeforeSeal = func(ctx context.Context) {
		hooks = append(hooks, "seal")
		if mErr := cp.MakeAll(ctx, "seal"); mErr != nil {
			t.Error(mErr)
		}
	}
	e.init(t)
	e.deliver()
	e.unseal(t) // checkpoint covers keys_init + unseal
	e.clk.Advance(time.Hour)
	fp, _ := e.k.CheckpointKeyFingerprint()
	if err = e.k.Seal(t.Context(), admin); err != nil { // checkpoint before the key leaves
		t.Fatal(err)
	}
	if strings.Join(hooks, ",") != "unseal,seal" {
		t.Errorf("hooks = %v", hooks)
	}
	r, err := audit.VerifyWith(t.Context(), e.ia, store.InstanceScope, audit.VerifyOptions{CheckpointKey: fp})
	if err != nil || r.Break != nil {
		t.Fatalf("verify: %+v, %v", r.Break, err)
	}
	// keys_init, unseal, checkpoint – then the seal hook found nothing new;
	// the seal entry itself comes after the key is gone.
	if r.Checkpoints != 1 || r.LastCheckpoint.Seq != 3 || r.Entries != 4 {
		t.Errorf("report = %+v", r)
	}
}

// TestOnlyInstanceAdminsUnseal: unseal = signed-in instance admin + passphrase
// (PHASE1 step 10). A tenant admin with the right passphrase is refused, and
// the refusal is audited without trying the passphrase.
func TestOnlyInstanceAdminsUnseal(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.init(t)
	tenantAdmin := Who{
		Actor: audit.Actor{Type: audit.ActorUser, ID: "u-2", Name: "pki-admin"}, SourceIP: "192.0.2.11",
		Principal: &authz.Principal{Kind: authz.KindUser, UserID: "u-2", Username: "pki-admin",
			Bindings: []authz.Binding{{Tenant: store.DefaultTenant, Role: authz.Admin}}},
	}
	for name, who := range map[string]Who{"tenant admin": tenantAdmin, "nobody": {Actor: tenantAdmin.Actor}} {
		if err := e.k.Unseal(t.Context(), []byte(e.passphrase), who); !errors.Is(err, authz.ErrDenied) {
			t.Errorf("%s unseals: %v", name, err)
		}
		if err := e.k.ResetPassphrase(t.Context(), e.recovery, []byte("another long passphrase"), who); !errors.Is(err, authz.ErrDenied) {
			t.Errorf("%s resets the passphrase: %v", name, err)
		}
	}
	if !e.k.Status().Sealed {
		t.Fatal("unsealed by a tenant admin")
	}
	console := Who{Actor: audit.Actor{Type: audit.ActorUser, Name: "console"}, Principal: authz.Console()}
	if err := e.k.Unseal(t.Context(), []byte(e.passphrase), console); err != nil {
		t.Errorf("console: %v", err)
	}
	got := strings.Join(e.actions(t), " ")
	if strings.Count(got, "system.unseal/denied") != 2 || strings.Contains(got, "system.unseal/failure") {
		t.Errorf("audit: %s", got)
	}
}

// TestVerifyKeepsTheSealState: the console proof for reset-2fa checks the
// secret, leaves the keyring as it is and is audited.
func TestVerifyKeepsTheSealState(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.init(t)
	if err := e.k.VerifyPassphrase(t.Context(), []byte("wrong passphrase, long enough"), admin); !errors.Is(err, ErrWrongSecret) {
		t.Errorf("wrong passphrase: %v", err)
	}
	if err := e.k.VerifyPassphrase(t.Context(), []byte(e.passphrase), admin); err != nil {
		t.Fatal(err)
	}
	if err := e.k.VerifyRecoveryKey(t.Context(), e.recovery, admin); err != nil {
		t.Fatal(err)
	}
	if !e.k.Status().Sealed {
		t.Error("verify unsealed the keyring")
	}
	e.unseal(t)
	if err := e.k.VerifyPassphrase(t.Context(), []byte(e.passphrase), admin); err != nil || e.k.Status().Sealed {
		t.Errorf("verify while unsealed: %v, sealed %v", err, e.k.Status().Sealed)
	}
	got := strings.Join(e.actions(t), " ")
	if strings.Count(got, "system.secret_verify/success") != 3 || !strings.Contains(got, "system.secret_verify/failure") {
		t.Errorf("audit: %s", got)
	}
}

// TestUnsealIsFailClosed: when the audit entry can't be written, there is no
// unseal (owner 2026-10-16); a seal still happens and reports the error.
func TestUnsealIsFailClosed(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.init(t)
	ro, err := store.OpenReadOnly(t.Context(), e.l.InstanceAuditDB())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ro.Close() })
	k := New(e.system, ro.Read, e.clk)
	k.params = testParams
	if err := k.Unseal(t.Context(), []byte(e.passphrase), admin); err == nil || !strings.Contains(err.Error(), "audit entry can't be written") {
		t.Errorf("unseal without audit: %v", err)
	}
	if !k.Status().Sealed {
		t.Fatal("unsealed although the audit entry failed")
	}
	if _, err := k.CheckpointKeyFingerprint(); err == nil {
		t.Error("the root key is usable after a refused unseal")
	}
	// Seal: the key goes even when the entry fails.
	w := New(e.system, e.ia, e.clk)
	w.params = testParams
	if err := w.Unseal(t.Context(), []byte(e.passphrase), admin); err != nil {
		t.Fatal(err)
	}
	w.audit = ro.Read
	if err := w.Seal(t.Context(), admin); err == nil {
		t.Error("seal without audit reported no error")
	}
	if !w.Status().Sealed {
		t.Error("the key stayed in memory because the audit entry failed")
	}
}
