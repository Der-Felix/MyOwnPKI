package auth

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/auth/passkeytest"
)

// passkeyEnv: alice and bob have one registered passkey each, held by the
// virtual authenticators authn and bob.
type passkeyEnv struct {
	*env
	authn, bob *passkeytest.Authenticator
}

func newPasskeyEnv(t *testing.T) *passkeyEnv {
	t.Helper()
	v := newEnv(t)
	withPasskeys(t, v)
	v.create(t, "alice", false)
	v.create(t, "bob", false)
	p := &passkeyEnv{env: v, authn: passkeytest.New(browserOrigin), bob: passkeytest.New(browserOrigin)}
	register(t, v, v.login(t, "alice"), p.authn)
	register(t, v, v.login(t, "bob"), p.bob)
	return p
}

// ceremonyKind is one of the two places a passkey assertion is accepted: as
// the second factor of a sign-in (pending session) and as a step-up (full
// session). Both must refuse the same things.
type ceremonyKind struct {
	name string
	// open returns the token of a session of user waiting for the ceremony.
	open func(t *testing.T, p *passkeyEnv, user string) string
}

var ceremonyKinds = []ceremonyKind{
	{"sign-in", func(t *testing.T, p *passkeyEnv, user string) string {
		t.Helper()
		p.clk.Advance(time.Minute)
		res, err := p.s.Login(t.Context(), user, password, ip)
		if err != nil {
			t.Fatal(err)
		}
		return res.Token
	}},
	{"step-up", func(t *testing.T, p *passkeyEnv, user string) string { t.Helper(); return p.login(t, user) }},
}

func (p *passkeyEnv) begin(t *testing.T, token string) []byte {
	t.Helper()
	p.clk.Advance(time.Minute) // the throttle of earlier failures has passed
	options, err := p.s.BeginPasskeyLogin(t.Context(), token, Client{IP: ip})
	if err != nil {
		t.Fatal(err)
	}
	return options
}

// answer runs begin and the authenticator.
func (p *passkeyEnv) answer(t *testing.T, a *passkeytest.Authenticator, token string) []byte {
	t.Helper()
	out, err := a.Get(p.begin(t, token))
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func (p *passkeyEnv) finish(t *testing.T, token string, answer []byte) (*LoginResult, error) {
	t.Helper()
	return p.s.FinishPasskeyLogin(t.Context(), token, answer, Client{IP: ip})
}

func (p *passkeyEnv) signCount(t *testing.T, user string) int64 {
	t.Helper()
	var n int64
	if err := p.sys.QueryRowContext(t.Context(), `SELECT sign_count FROM webauthn_credentials WHERE user_id = ?`, mustUserID(t, p.env, user)).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// stepUpAt is the proof time of a full session (zero for a pending one).
func (p *passkeyEnv) stepUpAt(t *testing.T, token string) time.Time {
	t.Helper()
	sess, err := p.s.Authenticate(t.Context(), token)
	if errors.Is(err, ErrNoSession) {
		return time.Time{}
	}
	if err != nil {
		t.Fatal(err)
	}
	return sess.StepUpAt
}

// notProven checks that a refused ceremony gave nothing: a pending session
// is still pending, a full session's step-up time did not move.
func (p *passkeyEnv) notProven(t *testing.T, token string, before time.Time) {
	t.Helper()
	if now := p.stepUpAt(t, token); !now.Equal(before) {
		t.Errorf("the refused passkey changed the session: step-up %v, was %v", now, before)
	}
}

// logged tells whether the audit log has an entry "action/result" whose
// details contain every part.
func logged(t *testing.T, v *env, actionResult string, parts ...string) bool {
	t.Helper()
next:
	for _, line := range v.actions(t) {
		if !strings.HasPrefix(line, actionResult+" ") {
			continue
		}
		for _, part := range parts {
			if !strings.Contains(line, part) {
				continue next
			}
		}
		return true
	}
	return false
}

// TestPasskeyAnswerRefusals: every answer that is not exactly the one fresh
// answer of the authenticator the server offered is refused with the same
// error, the reason lands in the audit log, and nothing is granted.
func TestPasskeyAnswerRefusals(t *testing.T) {
	t.Parallel()
	const evil = "https://pki.homelab.lan.evil.example"
	type refusal struct {
		name   string
		reason string // in the audit log
		// run returns the error of the refused finish; token is the session
		// that waits for the ceremony.
		run func(t *testing.T, p *passkeyEnv, k ceremonyKind, token string) error
	}
	finishErr := func(t *testing.T, p *passkeyEnv, token string, answer []byte) error {
		t.Helper()
		res, err := p.finish(t, token, answer)
		if res != nil {
			t.Errorf("a refused answer returned a result: %+v", res)
		}
		return err
	}
	tests := []refusal{
		{"answer from another origin", "passkey not accepted", func(t *testing.T, p *passkeyEnv, _ ceremonyKind, token string) error {
			t.Helper()
			p.authn.Origin = evil
			return finishErr(t, p, token, p.answer(t, p.authn, token))
		}},
		{"answer without user verification", "passkey not accepted", func(t *testing.T, p *passkeyEnv, _ ceremonyKind, token string) error {
			t.Helper()
			p.authn.UserVerified = false
			return finishErr(t, p, token, p.answer(t, p.authn, token))
		}},
		{"answer to an earlier challenge", "passkey not accepted", func(t *testing.T, p *passkeyEnv, _ ceremonyKind, token string) error {
			t.Helper()
			old := p.answer(t, p.authn, token)
			p.begin(t, token) // a new challenge replaces the open one
			return finishErr(t, p, token, old)
		}},
		{"a passkey the server did not offer", "passkey not accepted", func(t *testing.T, p *passkeyEnv, k ceremonyKind, _ string) error {
			t.Helper()
			bobsToken := k.open(t, p, "bob")
			bobBefore := p.stepUpAt(t, bobsToken)
			options := p.begin(t, bobsToken)
			answer, err := p.authn.GetAny(options) // alice's key, bob's challenge
			if err != nil {
				t.Fatal(err)
			}
			err = finishErr(t, p, bobsToken, answer)
			p.notProven(t, bobsToken, bobBefore)
			return err
		}},
		{"a passkey removed after the challenge", "passkey not accepted", func(t *testing.T, p *passkeyEnv, _ ceremonyKind, token string) error {
			t.Helper()
			answer := p.answer(t, p.authn, token)
			if _, err := p.sys.ExecContext(t.Context(), `DELETE FROM webauthn_credentials WHERE user_id = ?`, mustUserID(t, p.env, "alice")); err != nil {
				t.Fatal(err)
			}
			return finishErr(t, p, token, answer)
		}},
		{"garbage", "unreadable passkey answer", func(t *testing.T, p *passkeyEnv, _ ceremonyKind, token string) error {
			t.Helper()
			p.begin(t, token)
			return finishErr(t, p, token, []byte("not json"))
		}},
		{"empty answer", "unreadable passkey answer", func(t *testing.T, p *passkeyEnv, _ ceremonyKind, token string) error {
			t.Helper()
			p.begin(t, token)
			return finishErr(t, p, token, nil)
		}},
		{"answer of the wrong shape", "unreadable passkey answer", func(t *testing.T, p *passkeyEnv, _ ceremonyKind, token string) error {
			t.Helper()
			p.begin(t, token)
			return finishErr(t, p, token, []byte(`{"id":"x","rawId":"x","type":"public-key","response":{}}`))
		}},
		{"oversized answer", "passkey answer too large", func(t *testing.T, p *passkeyEnv, _ ceremonyKind, token string) error {
			t.Helper()
			p.begin(t, token)
			return finishErr(t, p, token, []byte(strings.Repeat("a", maxPasskeyBody+1)))
		}},
	}
	for _, k := range ceremonyKinds {
		for _, tc := range tests {
			t.Run(k.name+"/"+tc.name, func(t *testing.T) {
				t.Parallel()
				p := newPasskeyEnv(t)
				token := k.open(t, p, "alice")
				before := p.stepUpAt(t, token)
				count := p.signCount(t, "alice")
				err := tc.run(t, p, k, token)
				if !errors.Is(err, ErrInvalidCode) {
					t.Fatalf("error %v, want ErrInvalidCode", err)
				}
				p.notProven(t, token, before)
				if tc.name != "a passkey removed after the challenge" {
					if got := p.signCount(t, "alice"); got != count {
						t.Errorf("sign counter %d, was %d", got, count)
					}
				}
				action := map[string]string{"sign-in": "user.login/failure", "step-up": "user.step_up/failure"}[k.name]
				if !logged(t, p.env, action, `"reason":"`+tc.reason+`"`) {
					t.Errorf("audit log lacks %s with reason %q:\n%s", action, tc.reason, strings.Join(p.actions(t), "\n"))
				}
			})
		}
	}
}

// TestPasskeyChallengeIsUsedOnce: whatever the outcome, a challenge is
// answered at most once, and it belongs to the session that asked.
func TestPasskeyChallengeIsUsedOnce(t *testing.T) {
	t.Parallel()
	for _, k := range ceremonyKinds {
		t.Run(k.name+"/a failed attempt burns the challenge", func(t *testing.T) {
			t.Parallel()
			p := newPasskeyEnv(t)
			token := k.open(t, p, "alice")
			answer := p.answer(t, p.authn, token)
			bad := append([]byte{}, answer...)
			bad[len(bad)/2] ^= 0x01 // a damaged copy
			if _, err := p.finish(t, token, bad); !errors.Is(err, ErrInvalidCode) {
				t.Fatalf("damaged answer: %v", err)
			}
			if _, err := p.finish(t, token, answer); !errors.Is(err, ErrNoCeremony) {
				t.Errorf("the right answer after a failed one: %v, want ErrNoCeremony", err)
			}
		})
		t.Run(k.name+"/the same answer twice", func(t *testing.T) {
			t.Parallel()
			p := newPasskeyEnv(t)
			token := k.open(t, p, "alice")
			answer := p.answer(t, p.authn, token)
			res, err := p.finish(t, token, answer)
			if err != nil {
				t.Fatal(err)
			}
			if k.name == "sign-in" && res.Token == token {
				t.Error("the session ID was not renewed after the passkey")
			}
			// Replay on the same session and on its successor.
			for _, replay := range []string{token, res.Token} {
				if _, err := p.finish(t, replay, answer); err == nil {
					t.Errorf("the replayed answer was accepted on %.8s", replay)
				}
			}
		})
		t.Run(k.name+"/a finished answer replayed against a new challenge", func(t *testing.T) {
			t.Parallel()
			p := newPasskeyEnv(t)
			first := k.open(t, p, "alice")
			old := p.answer(t, p.authn, first)
			if _, err := p.finish(t, first, old); err != nil {
				t.Fatal(err)
			}
			second := k.open(t, p, "alice")
			p.begin(t, second)
			if _, err := p.finish(t, second, old); !errors.Is(err, ErrInvalidCode) {
				t.Errorf("replay against a new challenge: %v", err)
			}
		})
		t.Run(k.name+"/another session's challenge", func(t *testing.T) {
			t.Parallel()
			p := newPasskeyEnv(t)
			a := k.open(t, p, "alice")
			b := k.open(t, p, "alice")
			answer := p.answer(t, p.authn, a)
			if _, err := p.finish(t, b, answer); !errors.Is(err, ErrNoCeremony) {
				t.Errorf("session B answered the challenge of session A: %v", err)
			}
			if _, err := p.finish(t, a, answer); err != nil {
				t.Errorf("session A lost its challenge to a stranger: %v", err)
			}
		})
		t.Run(k.name+"/no challenge at all", func(t *testing.T) {
			t.Parallel()
			p := newPasskeyEnv(t)
			token := k.open(t, p, "alice")
			answer := p.answer(t, p.authn, k.open(t, p, "alice"))
			if _, err := p.finish(t, token, answer); !errors.Is(err, ErrNoCeremony) {
				t.Errorf("answer without a challenge: %v", err)
			}
		})
	}
}

// TestPasskeyChallengeExpires: a challenge lives ceremonyTTL, to the second.
func TestPasskeyChallengeExpires(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		wait  time.Duration
		valid bool
	}{
		{"just in time", ceremonyTTL, true},
		{"a second late", ceremonyTTL + time.Second, false},
		{"much later", 20 * time.Minute, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := newPasskeyEnv(t)
			token := p.login(t, "alice") // a full session: the pending one ends after 5 minutes anyway
			options, err := p.s.BeginPasskeyLogin(t.Context(), token, Client{IP: ip})
			if err != nil {
				t.Fatal(err)
			}
			answer, err := p.authn.Get(options)
			if err != nil {
				t.Fatal(err)
			}
			p.clk.Advance(tc.wait)
			_, err = p.finish(t, token, answer)
			switch {
			case tc.valid && err != nil:
				t.Errorf("refused: %v", err)
			case !tc.valid && !errors.Is(err, ErrNoCeremony):
				t.Errorf("error %v, want ErrNoCeremony", err)
			}
		})
	}
}

// TestPasskeyCounter: the signature counter must grow; equal or lower is a
// cloned authenticator. Only a growing value is stored.
func TestPasskeyCounter(t *testing.T) {
	t.Parallel()
	for _, k := range ceremonyKinds {
		t.Run(k.name, func(t *testing.T) {
			t.Parallel()
			p := newPasskeyEnv(t)
			steps := []struct {
				name  string
				set   uint32 // the authenticator's counter before the next answer (it adds one)
				clone bool
				want  int64 // stored counter afterwards
			}{
				{"first use", 4, false, 5},
				{"counter lower", 1, true, 5},
				{"counter equal", 4, true, 5},
				{"counter far lower", 0, true, 5},
				{"after a refusal the real authenticator still works", 9, false, 10},
				{"counter jumps", 1000, false, 1001},
				{"equal again", 1000, true, 1001},
			}
			for _, st := range steps {
				token := k.open(t, p, "alice")
				p.authn.SetCounter(st.set)
				answer := p.answer(t, p.authn, token)
				before := p.stepUpAt(t, token)
				res, err := p.finish(t, token, answer)
				if st.clone {
					if err == nil || !strings.Contains(err.Error(), "cloned") || res != nil {
						t.Fatalf("%s: %v %+v, want the cloned-authenticator refusal", st.name, err, res)
					}
					p.notProven(t, token, before)
				} else if err != nil {
					t.Fatalf("%s: %v", st.name, err)
				}
				if got := p.signCount(t, "alice"); got != st.want {
					t.Fatalf("%s: stored counter %d, want %d", st.name, got, st.want)
				}
			}
			if log := strings.Join(p.actions(t), "\n"); strings.Count(log, `"reason":"cloned"`) != 4 {
				t.Errorf("want 4 clone refusals in the audit log:\n%s", log)
			}
		})
	}
}

// TestPasskeyCounterZero: authenticators that never count (always 0) stay
// usable; a counter that was 0 and starts counting is fine too.
func TestPasskeyCounterZero(t *testing.T) {
	t.Parallel()
	p := newPasskeyEnv(t)
	// The virtual authenticator adds one before answering, so a fresh answer
	// is never 0; make the stored value 0 by hand and answer with 1.
	if _, err := p.sys.ExecContext(t.Context(), `UPDATE webauthn_credentials SET sign_count = 0`); err != nil {
		t.Fatal(err)
	}
	token := ceremonyKinds[1].open(t, p, "alice")
	p.authn.SetCounter(0)
	if _, err := p.finish(t, token, p.answer(t, p.authn, token)); err != nil {
		t.Errorf("counter 0 to 1: %v", err)
	}
}
