package auth

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/store"
)

// tokenEnv: alice is operator for the whole default tenant and admin of the
// single CA "ca-a"; a second tenant "other" exists but alice has no role there.
func tokenEnv(t *testing.T) (*env, string) {
	t.Helper()
	v := newEnv(t)
	if _, err := v.sys.ExecContext(t.Context(), `INSERT INTO tenants (id, name, created_at) VALUES ('other', 'other', '2026-10-15T00:00:00.000Z')`); err != nil {
		t.Fatal(err)
	}
	enr, err := v.s.CreateUser(t.Context(), NewUserRequest{
		Username: "alice", Password: password,
		Roles: []authz.Binding{
			{Tenant: store.DefaultTenant, Role: authz.Operator},
			{Tenant: store.DefaultTenant, CA: "ca-a", Role: authz.Admin},
		},
		Who: console,
	})
	if err != nil {
		t.Fatal(err)
	}
	v.remember(t, enr)
	session := v.login(t, "alice")
	return v, session
}

func tokenCount(t *testing.T, v *env, token string) int {
	t.Helper()
	list, err := v.s.ListTokens(t.Context(), token)
	if err != nil {
		t.Fatal(err)
	}
	return len(list)
}

// TestCreateTokenScope: a token never gets more than its owner has (same
// tenant, the whole tenant or the same CA, a role as high or higher), and a
// refused request creates nothing.
func TestCreateTokenScope(t *testing.T) {
	t.Parallel()
	d := store.DefaultTenant
	tests := []struct {
		name  string
		roles []authz.Binding
		want  string // "" = allowed; else a part of the refusal reason
	}{
		{"viewer of the tenant", []authz.Binding{{Tenant: d, Role: authz.Viewer}}, ""},
		{"operator of the tenant", []authz.Binding{{Tenant: d, Role: authz.Operator}}, ""},
		{"admin of the tenant is more than operator", []authz.Binding{{Tenant: d, Role: authz.Admin}}, "you don't have the role admin for tenant default"},
		{"admin of the CA the user administers", []authz.Binding{{Tenant: d, CA: "ca-a", Role: authz.Admin}}, ""},
		{"operator of another CA is covered by the tenant role", []authz.Binding{{Tenant: d, CA: "ca-b", Role: authz.Operator}}, ""},
		{"admin of another CA", []authz.Binding{{Tenant: d, CA: "ca-b", Role: authz.Admin}}, `you don't have the role admin for CA "ca-b" in tenant default`},
		{"a tenant the user has no role in", []authz.Binding{{Tenant: "other", Role: authz.Viewer}}, "you don't have the role viewer for tenant other"},
		{"a tenant that does not exist", []authz.Binding{{Tenant: "nowhere", Role: authz.Viewer}}, "you don't have the role viewer for tenant nowhere"},
		{"an unknown role", []authz.Binding{{Tenant: d, Role: "root"}}, `unknown role "root"`},
		{"an empty role", []authz.Binding{{Tenant: d}}, `unknown role ""`},
		{"no role at all", nil, "a token needs at least one role"},
		{"one good and one too high role", []authz.Binding{{Tenant: d, Role: authz.Viewer}, {Tenant: d, Role: authz.Admin}}, "you don't have the role admin"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			v, session := tokenEnv(t)
			secret, tok, err := v.s.CreateToken(t.Context(), session, "ci", tc.roles, v.clk.Now().Add(24*time.Hour), ip)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				if !strings.HasPrefix(secret, TokenPrefix) || tok == nil || len(tok.Roles) != len(tc.roles) {
					t.Errorf("secret %q token %+v", secret, tok)
				}
				if n := tokenCount(t, v, session); n != 1 {
					t.Errorf("%d tokens stored, want 1", n)
				}
				return
			}
			var re *RefusedError
			if !errors.As(err, &re) || !strings.Contains(strings.Join(re.Reasons, "|"), tc.want) {
				t.Fatalf("error %v, want a refusal containing %q", err, tc.want)
			}
			if secret != "" || tok != nil {
				t.Errorf("a refused request returned a token: %q %+v", secret, tok)
			}
			if n := tokenCount(t, v, session); n != 0 {
				t.Errorf("%d tokens stored after a refusal", n)
			}
		})
	}
}

// TestCreateTokenExpiry: an end is mandatory, in the future and at most 366
// days away; the boundaries are exact.
func TestCreateTokenExpiry(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		expires func(now time.Time) time.Time
		want    string
	}{
		{"no end", func(time.Time) time.Time { return time.Time{} }, "a token needs an end"},
		{"in the past", func(now time.Time) time.Time { return now.Add(-time.Hour) }, "expires_at is in the past"},
		{"right now", func(now time.Time) time.Time { return now }, "expires_at is in the past"},
		{"one second from now", func(now time.Time) time.Time { return now.Add(time.Second) }, ""},
		{"exactly the maximum", func(now time.Time) time.Time { return now.Add(MaxTokenLife) }, ""},
		{"one second over the maximum", func(now time.Time) time.Time { return now.Add(MaxTokenLife + time.Second) }, "a token lives at most one year"},
		{"ten years", func(now time.Time) time.Time { return now.AddDate(10, 0, 0) }, "a token lives at most one year"},
		{"a zone does not matter", func(now time.Time) time.Time {
			return now.Add(time.Hour).In(time.FixedZone("x", 5*3600+1800))
		}, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			v, session := tokenEnv(t)
			roles := []authz.Binding{{Tenant: store.DefaultTenant, Role: authz.Viewer}}
			end := tc.expires(v.clk.Now())
			secret, tok, err := v.s.CreateToken(t.Context(), session, "ci", roles, end, ip)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				if !tok.ExpiresAt.Equal(end) || tok.ExpiresAt.Location() != time.UTC {
					t.Errorf("expires %v, want %v in UTC", tok.ExpiresAt, end)
				}
				if _, aerr := v.s.AuthenticateToken(t.Context(), secret); aerr != nil {
					t.Errorf("a fresh token does not work: %v", aerr)
				}
				return
			}
			var re *RefusedError
			if !errors.As(err, &re) || !strings.Contains(strings.Join(re.Reasons, "|"), tc.want) {
				t.Fatalf("error %v, want a refusal containing %q", err, tc.want)
			}
		})
	}
}

// TestCreateTokenNameAndLimit: the name rules and at most MaxTokens per user.
func TestCreateTokenNameAndLimit(t *testing.T) {
	t.Parallel()
	roles := []authz.Binding{{Tenant: store.DefaultTenant, Role: authz.Viewer}}
	names := []struct {
		name, token string
		ok          bool
	}{
		{"plain", "backup job", true},
		{"padded name is trimmed", "  ci  ", true},
		{"64 characters", strings.Repeat("a", 64), true},
		{"64 multi-byte characters", strings.Repeat("ä", 64), true},
		{"65 characters", strings.Repeat("a", 65), false},
		{"empty", "", false},
		{"only blanks", "   ", false},
		{"newline inside", "a\nb", false},
		{"escape character", "a\x1bb", false},
		{"C1 control character", "a\u0085b", false},
	}
	for _, tc := range names {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			v, session := tokenEnv(t)
			_, tok, err := v.s.CreateToken(t.Context(), session, tc.token, roles, v.clk.Now().Add(time.Hour), ip)
			if tc.ok {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				if tok.Name != strings.TrimSpace(tc.token) {
					t.Errorf("name %q", tok.Name)
				}
				return
			}
			var re *RefusedError
			if !errors.As(err, &re) || !strings.Contains(re.Error(), "the token name must be 1 to 64 characters") {
				t.Errorf("error %v", err)
			}
		})
	}

	t.Run("limit", func(t *testing.T) {
		t.Parallel()
		v, session := tokenEnv(t)
		for i := range MaxTokens {
			if _, _, err := v.s.CreateToken(t.Context(), session, "t"+string(rune('a'+i)), roles, v.clk.Now().Add(time.Hour), ip); err != nil {
				t.Fatalf("token %d: %v", i+1, err)
			}
		}
		_, _, err := v.s.CreateToken(t.Context(), session, "one too many", roles, v.clk.Now().Add(time.Hour), ip)
		var re *RefusedError
		if !errors.As(err, &re) || !strings.Contains(re.Error(), "at most 20 tokens per user") {
			t.Fatalf("the 21st token: %v", err)
		}
		// Revoking one makes room.
		list, _ := v.s.ListTokens(t.Context(), session)
		if err := v.s.RevokeToken(t.Context(), session, list[0].ID, ip); err != nil {
			t.Fatal(err)
		}
		if _, _, err := v.s.CreateToken(t.Context(), session, "fits again", roles, v.clk.Now().Add(time.Hour), ip); err != nil {
			t.Errorf("after a revoke: %v", err)
		}
	})
}

// TestNoTokenForAToken: a bearer secret is not a session, so it can't create
// tokens, list them or revoke them – and neither can a pending (password
// only) session or a made-up one.
func TestNoTokenForAToken(t *testing.T) {
	t.Parallel()
	v, session := tokenEnv(t)
	roles := []authz.Binding{{Tenant: store.DefaultTenant, Role: authz.Viewer}}
	secret, tok, err := v.s.CreateToken(t.Context(), session, "first", roles, v.clk.Now().Add(time.Hour), ip)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := v.s.Login(t.Context(), "alice", password, ip)
	if err != nil {
		t.Fatal(err)
	}
	for name, bearer := range map[string]string{"the token secret": secret, "a pending session": pending.Token, "garbage": "x", "empty": ""} {
		if _, _, cerr := v.s.CreateToken(t.Context(), bearer, "second", roles, v.clk.Now().Add(time.Hour), ip); !errors.Is(cerr, ErrNoSession) {
			t.Errorf("%s created a token: %v", name, cerr)
		}
		if _, lerr := v.s.ListTokens(t.Context(), bearer); !errors.Is(lerr, ErrNoSession) {
			t.Errorf("%s listed tokens: %v", name, lerr)
		}
		if rerr := v.s.RevokeToken(t.Context(), bearer, tok.ID, ip); !errors.Is(rerr, ErrNoSession) {
			t.Errorf("%s revoked a token: %v", name, rerr)
		}
	}
	if n := tokenCount(t, v, session); n != 1 {
		t.Errorf("%d tokens, want the one", n)
	}
	// The secret reaches only the token path, which is not a session.
	if _, err := v.s.Authenticate(t.Context(), secret); !errors.Is(err, ErrNoSession) {
		t.Errorf("a token authenticates as a session: %v", err)
	}
}

// TestTokenIsStoredHashedAndAudited: the database holds the SHA-256 only and
// the audit entry names the token, never the secret.
func TestTokenIsStoredHashedAndAudited(t *testing.T) {
	t.Parallel()
	v, session := tokenEnv(t)
	roles := []authz.Binding{{Tenant: store.DefaultTenant, Role: authz.Viewer}}
	secret, tok, err := v.s.CreateToken(t.Context(), session, "ci", roles, v.clk.Now().Add(time.Hour), ip)
	if err != nil {
		t.Fatal(err)
	}
	if len(secret) != len(TokenPrefix)+52 { // 32 random bytes in unpadded base32
		t.Errorf("secret %q has length %d", secret, len(secret))
	}
	var hash, rolesJSON string
	if err := v.sys.QueryRowContext(t.Context(), `SELECT token_hash, roles_json FROM api_tokens WHERE id = ?`, tok.ID).Scan(&hash, &rolesJSON); err != nil {
		t.Fatal(err)
	}
	if hash != tokenHash(secret) || len(hash) != 64 || strings.Contains(hash, secret) {
		t.Errorf("stored hash %q", hash)
	}
	if want := `[{"tenant":"default","role":"viewer"}]`; rolesJSON != want {
		t.Errorf("roles_json %s, want %s", rolesJSON, want)
	}
	log := strings.Join(v.actions(t), "\n")
	if !strings.Contains(log, "user.token_create/success alice") || !strings.Contains(log, tok.ID) || strings.Contains(log, secret) {
		t.Errorf("audit log:\n%s", log)
	}
}

// TestAuthenticateToken: what a bearer secret turns into – exactly the
// requested roles, never an instance admin, never a step-up – and when it
// stops working.
func TestAuthenticateToken(t *testing.T) {
	t.Parallel()
	d := store.DefaultTenant

	t.Run("expiry is exact", func(t *testing.T) {
		t.Parallel()
		v, session := tokenEnv(t)
		end := v.clk.Now().Add(2 * time.Hour)
		secret, _, err := v.s.CreateToken(t.Context(), session, "ci", []authz.Binding{{Tenant: d, Role: authz.Viewer}}, end, ip)
		if err != nil {
			t.Fatal(err)
		}
		v.clk.Set(end.Add(-time.Millisecond))
		if _, err := v.s.AuthenticateToken(t.Context(), secret); err != nil {
			t.Errorf("one millisecond before the end: %v", err)
		}
		v.clk.Set(end)
		if _, err := v.s.AuthenticateToken(t.Context(), secret); !errors.Is(err, ErrNoSession) {
			t.Errorf("at the end: %v", err)
		}
		v.clk.Set(end.Add(24 * time.Hour))
		if _, err := v.s.AuthenticateToken(t.Context(), secret); !errors.Is(err, ErrNoSession) {
			t.Errorf("a day after the end: %v", err)
		}
	})

	t.Run("roles and flags", func(t *testing.T) {
		t.Parallel()
		v := newEnv(t)
		v.create(t, "root", true, authz.Admin)
		session := v.login(t, "root")
		want := []authz.Binding{{Tenant: d, Role: authz.Admin}}
		secret, tok, err := v.s.CreateToken(t.Context(), session, "ci", want, v.clk.Now().Add(time.Hour), ip)
		if err != nil {
			t.Fatal(err)
		}
		sess, err := v.s.AuthenticateToken(t.Context(), secret)
		if err != nil {
			t.Fatal(err)
		}
		p := sess.Principal
		if !p.ViaToken || p.InstanceAdmin || !p.StepUpAt.IsZero() || p.Username != "root" || len(p.Bindings) != 1 || p.Bindings[0] != want[0] {
			t.Errorf("principal %+v", p)
		}
		if sess.TokenID != tok.ID || sess.TokenName != "ci" {
			t.Errorf("session %+v", sess)
		}
		// A step-up action is refused for the token although its owner is an
		// instance admin with a fresh second factor.
		if cerr := p.Check(authz.ManageUsers, authz.Resource{}, v.clk.Now()); cerr == nil {
			t.Error("an admin token of an instance admin may manage users")
		}
	})

	t.Run("a role the owner lost is gone", func(t *testing.T) {
		t.Parallel()
		v, session := tokenEnv(t)
		secret, _, err := v.s.CreateToken(t.Context(), session, "ci", []authz.Binding{
			{Tenant: d, Role: authz.Operator}, {Tenant: d, CA: "ca-a", Role: authz.Admin},
		}, v.clk.Now().Add(time.Hour), ip)
		if err != nil {
			t.Fatal(err)
		}
		if rerr := v.s.RemoveRole(t.Context(), mustUserID(t, v, "alice"), d, "ca-a", console); rerr != nil {
			t.Fatal(rerr)
		}
		sess, err := v.s.AuthenticateToken(t.Context(), secret)
		if err != nil {
			t.Fatal(err)
		}
		if got := sess.Principal.Bindings; len(got) != 1 || got[0] != (authz.Binding{Tenant: d, Role: authz.Operator}) {
			t.Errorf("bindings %+v, want only the operator role", got)
		}
		// Lowered from operator to viewer: the token keeps nothing above viewer.
		if rerr := v.s.SetRole(t.Context(), mustUserID(t, v, "alice"), authz.Binding{Tenant: d, Role: authz.Viewer}, console); rerr != nil {
			t.Fatal(rerr)
		}
		sess, err = v.s.AuthenticateToken(t.Context(), secret)
		if err != nil {
			t.Fatal(err)
		}
		if got := sess.Principal.Bindings; len(got) != 0 {
			t.Errorf("bindings %+v, want none", got)
		}
	})

	t.Run("disabled owner and revoked token", func(t *testing.T) {
		t.Parallel()
		v, session := tokenEnv(t)
		roles := []authz.Binding{{Tenant: d, Role: authz.Viewer}}
		secret, tok, err := v.s.CreateToken(t.Context(), session, "ci", roles, v.clk.Now().Add(time.Hour), ip)
		if err != nil {
			t.Fatal(err)
		}
		other, _, err := v.s.CreateToken(t.Context(), session, "other", roles, v.clk.Now().Add(time.Hour), ip)
		if err != nil {
			t.Fatal(err)
		}
		if err := v.s.RevokeToken(t.Context(), session, tok.ID, ip); err != nil {
			t.Fatal(err)
		}
		if _, err := v.s.AuthenticateToken(t.Context(), secret); !errors.Is(err, ErrNoSession) {
			t.Errorf("a revoked token works: %v", err)
		}
		if err := v.s.RevokeToken(t.Context(), session, tok.ID, ip); !errors.Is(err, ErrNoToken) {
			t.Errorf("revoking twice: %v", err)
		}
		if _, err := v.s.AuthenticateToken(t.Context(), other); err != nil {
			t.Fatalf("the other token: %v", err)
		}
		if err := v.s.DisableUser(t.Context(), mustUserID(t, v, "alice"), console); err != nil {
			t.Fatal(err)
		}
		if _, err := v.s.AuthenticateToken(t.Context(), other); !errors.Is(err, ErrNoSession) {
			t.Errorf("a token of a disabled user works: %v", err)
		}
	})

	t.Run("not a token", func(t *testing.T) {
		t.Parallel()
		v, session := tokenEnv(t)
		secret, _, err := v.s.CreateToken(t.Context(), session, "ci", []authz.Binding{{Tenant: d, Role: authz.Viewer}}, v.clk.Now().Add(time.Hour), ip)
		if err != nil {
			t.Fatal(err)
		}
		for name, bad := range map[string]string{
			"empty":              "",
			"no prefix":          strings.TrimPrefix(secret, TokenPrefix),
			"the session cookie": session,
			"changed last char":  secret[:len(secret)-1] + "x",
			"upper case":         strings.ToUpper(secret),
			"too long":           secret + strings.Repeat("a", 128),
			"prefix only":        TokenPrefix,
		} {
			if bad == secret {
				continue
			}
			if _, err := v.s.AuthenticateToken(t.Context(), bad); !errors.Is(err, ErrNoSession) {
				t.Errorf("%s: %v", name, err)
			}
		}
	})
}
