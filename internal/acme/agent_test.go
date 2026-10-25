package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Der-Felix/MyOwnPKI/internal/agents"
	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
	"github.com/Der-Felix/MyOwnPKI/internal/testinstance"
)

// reserveAgent creates the mTLS registration's stored result. The RPC and
// its authentication are tested in internal/agents and internal/server.
func reserveAgent(t *testing.T, v *env, c *client, id string) {
	t.Helper()
	q := pkidb.New(v.PKIDB.Write)
	now := dbTime(v.Clock.Now())
	if err := q.InsertAgent(t.Context(), pkidb.InsertAgentParams{ID: id, Hostname: "nas.homelab.lan", EnrollmentMode: "verified",
		Proof: "{}", Os: "linux", Arch: "amd64", AgentVersion: "test", CreatedAt: now, ApprovedAt: now, ApprovedBy: "test", UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := q.SetAgentACMEThumbprint(t.Context(), pkidb.SetAgentACMEThumbprintParams{ID: id,
		AcmeKeyThumbprint: sql.NullString{String: c.thumbprint(), Valid: true}, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []struct{ pattern, source string }{
		{"nas.homelab.lan", "hostname"}, {"*.apps.homelab.lan", "token"}, {"web.homelab.lan", "admin"},
	} {
		if err := q.InsertAgentName(t.Context(), pkidb.InsertAgentNameParams{AgentID: id, Pattern: name.pattern, Source: name.source, AddedBy: "test", AddedAt: now}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAgentAccountPolicyAndOrdinaryClient(t *testing.T) {
	t.Parallel()
	v := newEnv(t, ca.ApprovalOpen)
	c := v.client(t)
	reserveAgent(t, v, c, "agent-one")
	if r := c.register(); r.code != http.StatusCreated {
		t.Fatalf("register: %d %s", r.code, r.body)
	}
	if r := c.order("nas.homelab.lan", "web.homelab.lan", "one.apps.homelab.lan"); r.code != http.StatusCreated {
		t.Fatalf("allowed names: %d %s", r.code, r.body)
	}
	for _, name := range []string{"elsewhere.homelab.lan", "apps.homelab.lan", "192.0.2.10"} {
		if r := c.order(name); r.problem() != "rejectedIdentifier" {
			t.Errorf("outside agent names: %s: %d %s", name, r.code, r.body)
		}
	}
	// Same domain, same identifier, ordinary unlinked account: no agent
	// restriction is applied. This is the accepted ACME trust boundary.
	plain := v.client(t)
	plain.register()
	order := plain.order("elsewhere.homelab.lan")
	if order.code != http.StatusCreated {
		t.Fatalf("ordinary account: %d %s", order.code, order.body)
	}
	plain.solve(order, "http-01")
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if r := plain.finalize(order, csrFor(t, key, "", []string{"elsewhere.homelab.lan"}, nil)); r.json["status"] != "valid" {
		t.Fatalf("ordinary client issuance: %d %s", r.code, r.body)
	}
	q := pkidb.New(v.PKIDB.Write)
	for _, state := range []string{"disabled", "revoked"} {
		if _, err := q.SetAgentStatus(t.Context(), pkidb.SetAgentStatusParams{ID: "agent-one", Status: state, UpdatedAt: dbTime(v.Clock.Now())}); err != nil {
			t.Fatal(err)
		}
		if r := c.order("nas.homelab.lan"); r.problem() != "unauthorized" {
			t.Fatalf("%s orders: %d %s", state, r.code, r.body)
		}
	}
}

func TestAgentApprovalSourcesAndExistingAccount(t *testing.T) {
	t.Parallel()
	for _, level := range []string{ca.ApprovalAccount, ca.ApprovalNewName} {
		t.Run(level, func(t *testing.T) {
			t.Parallel()
			v := newEnv(t, level)
			c := v.client(t)
			reserveAgent(t, v, c, "agent-one")
			// Simulate an interrupted response after the account was created.
			// Only a verified newAccount request can bind this existing row.
			if r := c.register(); r.code != http.StatusCreated {
				t.Fatalf("newAccount: %d %s", r.code, r.body)
			}
			if _, err := v.PKIDB.Write.ExecContext(t.Context(), `UPDATE acme_accounts SET agent_id = NULL, approved_at = NULL, approved_by = NULL WHERE id = ?`, strings.TrimPrefix(c.kid, testBase+"/account/")); err != nil {
				t.Fatal(err)
			}
			// Reopen only the protocol server: the account reservation must
			// survive independently of its nonce cache and in-memory state.
			v.s.Close()
			reopened, rerr := New(v.s.opt)
			if rerr != nil {
				t.Fatal(rerr)
			}
			v.s = reopened
			t.Cleanup(reopened.Close)
			v.ts = httptest.NewServer(reopened)
			t.Cleanup(v.ts.Close)
			c.nonce = ""
			if r := c.post(c.kid, nil); r.code != http.StatusOK {
				t.Fatalf("account read: %d %s", r.code, r.body)
			}
			row, err := pkidb.New(v.PKIDB.Write).GetACMEAccountByThumbprint(t.Context(), c.thumbprint())
			if err != nil || row.AgentID.Valid {
				t.Fatal("an ordinary ACME request bound the account")
			}
			if r := c.register(); r.code != http.StatusOK {
				t.Fatalf("newAccount repeated: %d %s", r.code, r.body)
			}
			if r := c.order("nas.homelab.lan", "web.homelab.lan", "one.apps.homelab.lan"); r.code != http.StatusCreated {
				t.Fatalf("all sources approved: %d %s", r.code, r.body)
			}
			row, err = pkidb.New(v.PKIDB.Write).GetACMEAccountByThumbprint(t.Context(), c.thumbprint())
			if err != nil || row.AgentID.String != "agent-one" || !row.ApprovedAt.Valid {
				t.Fatalf("existing account not linked and approved: %v", err)
			}
			if r := c.register(); r.code != http.StatusOK {
				t.Fatalf("newAccount repeated: %d %s", r.code, r.body)
			}
			if level == ca.ApprovalNewName {
				plain := v.client(t)
				plain.register()
				if r := plain.order("nas.homelab.lan"); r.problem() != "unauthorized" {
					t.Fatalf("agent approval leaked to an ordinary account: %d %s", r.code, r.body)
				}
			}
		})
	}
}

func TestAgentCannotReserveExistingUnlinkedAccount(t *testing.T) {
	t.Parallel()
	v := newEnv(t, ca.ApprovalOpen)
	plain := v.client(t)
	plain.register()
	attacker := v.client(t)
	reserveAgent(t, v, attacker, "agent-one")
	q := pkidb.New(v.PKIDB.Write)
	if err := q.SetAgentACMEThumbprint(t.Context(), pkidb.SetAgentACMEThumbprintParams{ID: "agent-one", UpdatedAt: dbTime(v.Clock.Now())}); err != nil {
		t.Fatal(err)
	}
	row, err := q.GetAgent(t.Context(), "agent-one")
	if err != nil {
		t.Fatal(err)
	}
	service := &agents.Service{PKI: v.PKIDB.Write, Engine: v.Engine, Clock: v.Clock}
	caller := &agents.Caller{Agent: row, Who: keys.Who{Actor: audit.Actor{Type: audit.ActorAgent, ID: row.ID, Name: row.Hostname}}}
	if registerErr := service.RegisterACMEAccount(t.Context(), caller, plain.thumbprint()); !errors.Is(registerErr, agents.ErrConflict) {
		t.Fatalf("reservation of an existing account: %v", registerErr)
	}
	// Exercise both newAccount and a normal by-KID request after the refusal.
	if r := plain.register(); r.code != http.StatusOK {
		t.Fatalf("ordinary newAccount: %d %s", r.code, r.body)
	}
	order := plain.order("elsewhere.homelab.lan")
	if order.code != http.StatusCreated {
		t.Fatalf("ordinary account was restricted by agent_names: %d %s", order.code, order.body)
	}
	plain.solve(order, "http-01")
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if r := plain.finalize(order, csrFor(t, key, "", []string{"elsewhere.homelab.lan"}, nil)); r.json["status"] != "valid" {
		t.Fatalf("ordinary issuance: %d %s", r.code, r.body)
	}
	account, err := q.GetACMEAccountByThumbprint(t.Context(), plain.thumbprint())
	if err != nil || account.AgentID.Valid {
		t.Fatal("the existing account was captured")
	}
	row, err = q.GetAgent(t.Context(), row.ID)
	if err != nil || row.AcmeKeyThumbprint.Valid {
		t.Fatal("the denied reservation was stored")
	}
	v.Deliver(t)
	var denied int
	if err := v.TenantAudit.Read.QueryRowContext(t.Context(), `SELECT count(*) FROM audit_entries WHERE action = 'agent.acme.register' AND result = 'denied' AND actor_id = ?`, row.ID).Scan(&denied); err != nil || denied != 1 {
		t.Fatalf("reservation denial audit: count=%d, error=%v", denied, err)
	}
}

func TestAgentNameRemovedAfterSigningRollsBackCertificate(t *testing.T) {
	t.Parallel()
	v := newEnv(t, ca.ApprovalOpen)
	c := v.client(t)
	reserveAgent(t, v, c, "agent-one")
	c.register()
	order := c.order("nas.homelab.lan")
	c.solve(order, "http-01")
	// The engine has signed and verified the certificate before its INSERT.
	// This deterministic boundary removes permission after all earlier checks
	// and before the ACME Stored callback, without a production test hook.
	if _, err := v.PKIDB.Write.ExecContext(t.Context(), `CREATE TRIGGER remove_agent_name_before_storing
		BEFORE INSERT ON certificates BEGIN
		DELETE FROM agent_names WHERE agent_id = 'agent-one' AND pattern = 'nas.homelab.lan';
		END`); err != nil {
		t.Fatal(err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	result := c.finalize(order, csrFor(t, key, "", []string{"nas.homelab.lan"}, nil))
	if result.json["status"] != "invalid" || result.json["certificate"] != nil || !strings.Contains(string(result.body), "allowed names") {
		t.Fatalf("post-signature refusal: %d %s", result.code, result.body)
	}
	accountID := strings.TrimPrefix(c.kid, testBase+"/account/")
	var stored int
	if err := v.PKIDB.Read.QueryRowContext(t.Context(), `SELECT count(*) FROM certificates WHERE requested_by = ?`, accountID).Scan(&stored); err != nil || stored != 0 {
		t.Fatalf("certificate survived the storing rollback: count=%d, error=%v", stored, err)
	}
	v.Deliver(t)
	var denied, success int
	if err := v.TenantAudit.Read.QueryRowContext(t.Context(), `SELECT count(*) FROM audit_entries WHERE action = 'certificate.issue' AND result = 'denied' AND actor_id = ?`, accountID).Scan(&denied); err != nil || denied != 1 {
		t.Fatalf("issuance denial audit: count=%d, error=%v", denied, err)
	}
	if err := v.TenantAudit.Read.QueryRowContext(t.Context(), `SELECT count(*) FROM audit_entries WHERE action = 'certificate.issue' AND result = 'success' AND actor_id = ?`, accountID).Scan(&success); err != nil || success != 0 {
		t.Fatalf("rolled-back success audit: count=%d, error=%v", success, err)
	}
}

func TestAgentPolicyRecheckedAtFinalizeAndUnseal(t *testing.T) {
	t.Parallel()
	for _, when := range []string{"finalize", "unseal"} {
		for _, change := range []string{"name", "disabled", "revoked"} {
			t.Run(when+"/"+change, func(t *testing.T) {
				t.Parallel()
				v := newEnv(t, ca.ApprovalOpen)
				c := v.client(t)
				reserveAgent(t, v, c, "agent-one")
				c.register()
				order := c.order("nas.homelab.lan")
				c.solve(order, "http-01")
				key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				csr := csrFor(t, key, "", []string{"nas.homelab.lan"}, nil)
				if when == "unseal" {
					if err := v.Ring.Seal(t.Context(), testinstance.Console); err != nil {
						t.Fatal(err)
					}
					if r := c.finalize(order, csr); r.json["status"] != "processing" {
						t.Fatalf("sealed: %d %s", r.code, r.body)
					}
				}
				q := pkidb.New(v.PKIDB.Write)
				if change == "name" {
					if _, err := q.DeleteAgentName(t.Context(), pkidb.DeleteAgentNameParams{AgentID: "agent-one", Pattern: "nas.homelab.lan"}); err != nil {
						t.Fatal(err)
					}
				} else if _, err := q.SetAgentStatus(t.Context(), pkidb.SetAgentStatusParams{ID: "agent-one", Status: change, UpdatedAt: dbTime(v.Clock.Now())}); err != nil {
					t.Fatal(err)
				}
				if when == "unseal" {
					v.Unseal(t)
					if err := v.s.ProcessPending(t.Context()); err != nil {
						t.Fatal(err)
					}
				} else if r := c.finalize(order, csr); r.problem() != "rejectedIdentifier" && r.problem() != "unauthorized" {
					t.Fatalf("finalize not refused: %d %s", r.code, r.body)
				}
				result := c.post(order.header.Get("Location"), nil)
				if result.json["status"] != "invalid" || result.json["certificate"] != nil || result.json["error"] == nil {
					t.Fatalf("order not invalid with a clear error: %s", result.body)
				}
			})
		}
	}
}

func TestAgentAccountKeyChange(t *testing.T) {
	t.Parallel()
	v := newEnv(t, ca.ApprovalOpen)
	c := v.client(t)
	reserveAgent(t, v, c, "agent-one")
	c.register()
	next := v.client(t)
	url := testBase + "/key-change"
	inner := signedBody(t, next.key, map[string]any{"alg": "ES256", "url": url, "jwk": rawJSON(next.jwk)},
		map[string]any{"account": c.kid, "oldKey": rawJSON(c.jwk)})
	if r := c.post(url, rawBytes(inner)); r.code != http.StatusOK {
		t.Fatalf("keyChange: %d %s", r.code, r.body)
	}
	c.key, c.jwk = next.key, next.jwk
	a, err := pkidb.New(v.PKIDB.Write).GetAgent(t.Context(), "agent-one")
	if err != nil || a.AcmeKeyThumbprint.String != c.thumbprint() {
		t.Fatalf("agent thumbprint not changed: %v", err)
	}
	account, err := pkidb.New(v.PKIDB.Write).GetACMEAccount(t.Context(), strings.TrimPrefix(c.kid, testBase+"/account/"))
	if err != nil || account.AgentID.String != "agent-one" {
		t.Fatalf("binding lost: %v", err)
	}
	if r := c.order("elsewhere.homelab.lan"); r.problem() != "rejectedIdentifier" {
		t.Fatalf("rotation escaped names: %d %s", r.code, r.body)
	}
	other := v.client(t)
	reserveAgent(t, v, other, "agent-two")
	inner = signedBody(t, other.key, map[string]any{"alg": "ES256", "url": url, "jwk": rawJSON(other.jwk)},
		map[string]any{"account": c.kid, "oldKey": rawJSON(c.jwk)})
	if r := c.post(url, rawBytes(inner)); r.problem() != "unauthorized" {
		t.Fatalf("rotation into foreign reservation: %d %s", r.code, r.body)
	}
}
