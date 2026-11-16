//go:build e2etest

package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"testing"
)

// stagedFaultPass deploys once, then runs a second pass that damages the staged
// key (the fault of TestNginxStagedFaultRollsBack) and returns the outcome
// with the number of reloads the second pass issued.
func stagedFaultPass(t *testing.T, h *serviceHarness, serial int64) ([]DeploymentResult, int, error) {
	t.Helper()
	d := h.d
	if _, err := h.r.a.RunPass(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	before := reloadCount(t, h.marker)
	if before != 1 {
		t.Fatalf("the first pass issued %d reloads, want 1", before)
	}
	h.r.a.obtainForTest = func(context.Context, Deployment) (*Material, error) {
		return testMaterial(t, d.Names[0], serial), nil
	}
	if err := os.WriteFile(h.r.a.st.path(stagedFaultMarker), []byte("next pass\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	results, passErr := h.r.a.RunPass(t.Context(), nil)
	if passErr == nil || len(results) != 1 {
		t.Fatalf("the staged fault did not fail the pass: %+v, %v", results, passErr)
	}
	if _, err := os.Stat(h.r.a.st.path(stagedFaultMarker)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("one-shot staged fault marker remains")
	}
	// Whatever the service did, the files are the previous deployment again.
	h.r.assertFiles(t, h.r.next)
	return results, reloadCount(t, h.marker) - before, passErr
}

// TestApacheStagedFaultRollsBack damages the staged key before the test hook
// runs. When configtest rejects it nothing is reloaded. When configtest lets
// it through, the graceful reload runs with a broken key, and the test records
// whether Apache survived it and the rollback restored service (the risk of
// PHASE3 17.5, row "A reload with a broken key takes Apache down").
func TestApacheStagedFaultRollsBack(t *testing.T) {
	h := newApacheHarness(t)
	results, reloads, passErr := stagedFaultPass(t, h, apacheMismatchSerial)
	_, serveErr := h.r.a.checkServed(t.Context(), h.d, fingerprint(h.r.next[h.d.Name].Leaf.Raw))
	t.Logf("OBSERVED Apache after the staged fault: result %q, %d reloads issued by the pass, process alive %t, serves the previous certificate %t, error %s",
		results[0].State, reloads, h.svc.alive(), serveErr == nil, oneLine(fmt.Sprint(passErr)))
	if reloads == 0 {
		// configtest rejected the damaged key: the service never saw it.
		if results[0].State != "rolled_back" || serveErr != nil {
			t.Fatalf("configtest stopped the pass, yet the result is %q and the serving check says: %v", results[0].State, serveErr)
		}
		t.Log("configtest stopped the pass before any reload; what a reload with a broken key does was not exercised")
		return
	}
	survived := h.svc.alive() && serveErr == nil && results[0].State == "rolled_back"
	result := "the reload with the damaged key was followed by a rollback and Apache serves the previous certificate"
	if !survived {
		result = fmt.Sprintf("after the reload with the damaged key Apache did not recover through the rollback (result %q, process alive %t)", results[0].State, h.svc.alive())
	}
	noteClaim{
		recipe: "apache2", topic: "graceful reload with a broken key", result: result,
		seen: survived, ifSeen: apacheNoteSurvives, ifNot: apacheNoteStops,
	}.check(t)
}

// TestHAProxyStagedFaultRollsBack: haproxy -c must refuse the damaged combined
// file, so that nothing is reloaded, the files are restored and HAProxy keeps
// serving the previous certificate.
func TestHAProxyStagedFaultRollsBack(t *testing.T) {
	h := newHAProxyHarness(t)
	results, reloads, passErr := stagedFaultPass(t, h, haproxyMismatchSer)
	t.Logf("OBSERVED HAProxy after the staged fault: result %q, %d reloads issued by the pass, error %s", results[0].State, reloads, oneLine(fmt.Sprint(passErr)))
	if results[0].State != "rolled_back" {
		t.Fatalf("the staged fault ended in %q, want rolled_back", results[0].State)
	}
	if reloads != 0 {
		t.Errorf("haproxy -c let the damaged combined file through (%d reloads): the recipe's test hook does not guard the key; see TestHAProxyCheckOnKeyMismatch", reloads)
	}
	if _, err := h.r.a.checkServed(t.Context(), h.d, fingerprint(h.r.next[h.d.Name].Leaf.Raw)); err != nil {
		t.Fatal(err)
	}
}

func (s *realService) alive() bool {
	select {
	case <-s.exited:
		return false
	default:
		return true
	}
}

// The fault for the one-file target keeps the staged certificates and swaps
// the key, so that the file still parses and only the pair is wrong.
func TestSwapKeyBlockKeepsTheCertificatesAndBreaksThePair(t *testing.T) {
	t.Parallel()
	m, other := testMaterial(t, "swap.homelab.lan", 1), testMaterial(t, "swap.homelab.lan", 2)
	swapped := swapKeyBlock(combinedPEM(m), other.Key)
	if bytes.Contains(swapped, m.Key) || !bytes.Contains(swapped, m.Fullchain) || !bytes.HasSuffix(swapped, other.Key) {
		t.Fatal("the swapped file is not the certificates followed by the other key")
	}
	if _, err := tls.X509KeyPair(swapped, swapped); err == nil {
		t.Fatal("the swapped file still holds a matching pair")
	}
}
