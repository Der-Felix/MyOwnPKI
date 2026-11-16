package ca

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Der-Felix/MyOwnPKI/internal/keys"
)

// storeCounts are the rows a CA change writes, per table.
func (v *env) storeCounts(t *testing.T) map[string]int {
	t.Helper()
	out := map[string]int{}
	for _, table := range []string{"cas", "ca_generations", "ca_name_constraints", "keys", "crls", "outbox"} {
		var n int
		if err := v.pki.QueryRowContext(t.Context(), `SELECT count(*) FROM `+table).Scan(&n); err != nil {
			t.Fatal(err)
		}
		out[table] = n
	}
	return out
}

func sameCounts(a, b map[string]int) bool {
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// TestSignAndStoreLeavesNothingHalfDone: when the store fails after the
// certificate was signed – at any of the writes of the transaction – there is
// no CA row, no generation, no key, no CRL and no event. The audit log
// records the failure, the name is free again and the same request works as
// soon as the store does.
func TestSignAndStoreLeavesNothingHalfDone(t *testing.T) {
	t.Parallel()
	type action struct {
		name string
		run  func(context.Context, *env) (*CAResult, error)
	}
	root := action{"create root", func(ctx context.Context, v *env) (*CAResult, error) {
		return v.e.CreateRoot(ctx, RootRequest{CASettings: CASettings{Name: "newroot", BaseURL: baseURL}, Subject: Subject{CommonName: "New Root"}, Who: tester})
	}}
	intermediate := action{"create intermediate", func(ctx context.Context, v *env) (*CAResult, error) {
		return v.e.CreateIntermediate(ctx, IntermediateRequest{
			CASettings: CASettings{Name: "newinter", BaseURL: baseURL}, Parent: "root", Subject: Subject{CommonName: "New Intermediate"},
			NameConstraints: NameConstraints{PermittedDNS: []string{"homelab.lan"}}, Who: tester,
		})
	}}
	renew := action{"renew", func(ctx context.Context, v *env) (*CAResult, error) {
		return v.e.RenewCA(ctx, RenewRequest{Name: "issuing", Who: tester})
	}}
	// every write of the transaction, in the order signAndStore makes them
	triggers := []struct{ name, table, event string }{
		{"the key", "keys", "INSERT"},
		{"the CA row", "cas", "INSERT"},
		{"a name constraint", "ca_name_constraints", "INSERT"},
		{"the generation", "ca_generations", "INSERT"},
		{"the current generation", "cas", "UPDATE"},
		{"the audit event", "outbox", "INSERT"},
		{"the first CRL", "crls", "INSERT"},
	}
	for _, a := range []action{root, intermediate, renew} {
		for _, trig := range triggers {
			if trig.table == "ca_name_constraints" && a.name != "create intermediate" {
				continue
			}
			if trig.table == "cas" && trig.event == "INSERT" && a.name == "renew" {
				continue
			}
			t.Run(a.name+"/fails at "+trig.name, func(t *testing.T) {
				t.Parallel()
				v := newEnv(t)
				v.chain(t, caOpts{})
				before := v.storeCounts(t)
				if _, err := v.pki.ExecContext(t.Context(), `CREATE TRIGGER fail_write BEFORE `+trig.event+` ON `+trig.table+
					` BEGIN SELECT RAISE(ABORT, 'simulated write failure'); END`); err != nil {
					t.Fatal(err)
				}
				out, err := a.run(t.Context(), v)
				if err == nil || out != nil || errors.Is(err, ErrDenied) || !strings.Contains(err.Error(), "simulated write failure") {
					t.Fatalf("with a failing store: %+v %v", out, err)
				}
				if after := v.storeCounts(t); !sameCounts(before, after) {
					t.Errorf("rows before %v, after the failure %v", before, after)
				}
				var current int
				if err = v.pki.QueryRowContext(t.Context(), `SELECT current_generation FROM cas WHERE name = 'issuing'`).Scan(&current); err != nil || current != 1 {
					t.Errorf("current generation of issuing: %d (%v)", current, err)
				}
				// A CA that was not stored can't have an audit success.
				for _, row := range v.auditRows(t) {
					if row.result == "success" {
						t.Errorf("a success entry for a change that failed: %+v", row)
					}
				}
				if _, err = v.pki.ExecContext(t.Context(), `DROP TRIGGER fail_write`); err != nil {
					t.Fatal(err)
				}
				res, err := a.run(t.Context(), v)
				if err != nil || res.CertDER == nil || res.CRL == nil {
					t.Fatalf("the same request when the store works: %+v %v", res, err)
				}
			})
		}
	}
}

// TestOfflineParentCreationWhileSealed: the CSR of a CA below an offline root
// needs no unsealed key to be signed, but its key is stored encrypted – so
// the server must be unsealed, and nothing is stored when it isn't.
func TestOfflineParentCreationWhileSealed(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	off := newOfflineRoot(t, "Offline Root", t0.Add(-day))
	v.importRoot(t, "offline-root", off)
	before := v.storeCounts(t)
	v.e.Keys = keys.New(nil, nil, v.clk)
	_, err := v.e.CreateIntermediate(t.Context(), IntermediateRequest{
		CASettings: CASettings{Name: "issuing", BaseURL: baseURL}, Parent: "offline-root", Subject: Subject{CommonName: "Issuing"}, Who: tester,
	})
	if !errors.Is(err, keys.ErrSealed) {
		t.Fatalf("creating a CA with a sealed key ring: %v", err)
	}
	if after := v.storeCounts(t); !sameCounts(before, after) {
		t.Errorf("rows before %v, after the failure %v", before, after)
	}
}
