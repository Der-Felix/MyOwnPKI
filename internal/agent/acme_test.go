package agent

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestACMEAccountKeySurvivesRestartAndCorruptionIsRefused(t *testing.T) {
	t.Parallel()
	a := &Agent{cfg: &Config{ACMEDirectory: "https://pki.homelab.lan/acme/directory"}, st: state{t.TempDir()}}
	first, base, err := a.account()
	if err != nil {
		t.Fatal(err)
	}
	restarted := &Agent{cfg: a.cfg, st: a.st}
	second, again, err := restarted.account()
	if err != nil || base != again || !first.key.Equal(second.key) {
		t.Fatal("the account key did not survive restart")
	}
	a.cfg.ACMEDirectory = "https://pki.homelab.lan:443/other/directory"
	other, otherBase, err := a.account()
	if err != nil || otherBase == base || first.key.Equal(other.key) {
		t.Fatal("different directories reused an account key")
	}
	a.cfg.ACMEDirectory = "https://pki.homelab.lan/acme/directory"
	path := a.st.path(base + ".key")
	invalid := []byte("invalid state; never replace without understanding it")
	if werr := os.WriteFile(path, invalid, 0o600); werr != nil {
		t.Fatal(werr)
	}
	if _, _, aerr := a.account(); aerr == nil {
		t.Fatal("a corrupt account key was silently replaced")
	}
	data, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(data, invalid) {
		t.Fatal("the corrupt file was overwritten")
	}
}

func TestCertificateMaterialIsRedacted(t *testing.T) {
	t.Parallel()
	m := testMaterial(t, "service.homelab.lan", 42)
	data, err := json.Marshal(m)
	if err != nil || string(data) != "{}" {
		t.Fatal("certificate material reached JSON")
	}
	if strings.Contains(fmt.Sprint(m), "PRIVATE KEY") {
		t.Fatal("private key reached formatted output")
	}
	var log bytes.Buffer
	slog.New(slog.NewJSONHandler(&log, nil)).Info("material", slog.Any("result", m))
	if bytes.Contains(log.Bytes(), m.Key) || strings.Contains(log.String(), "PRIVATE KEY") {
		t.Fatal("private key reached a log")
	}
}

func TestACMEPEMRejectsIgnoredGarbage(t *testing.T) {
	t.Parallel()
	m := testMaterial(t, "service.homelab.lan", 42)
	roots := x509.NewCertPool()
	roots.AddCert(m.Leaf)
	if _, err := checkedMaterial(m.Certificate, m.Key, m.Leaf.DNSNames, roots, m.Leaf.NotBefore.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	for _, data := range [][]byte{
		append([]byte("ignored data\n"), m.Certificate...),
		append(bytes.Clone(m.Certificate), []byte("trailing data")...),
		append([]byte("-----BEGIN CERTIFICATE-----\ninvalid\n"), m.Certificate...),
	} {
		if _, err := checkedMaterial(data, m.Key, m.Leaf.DNSNames, roots, m.Leaf.NotBefore.Add(time.Hour)); err == nil {
			t.Fatal("malformed certificate PEM was accepted")
		}
	}
	path := filepath.Join(t.TempDir(), "account.key")
	for _, data := range [][]byte{append([]byte("ignored data\n"), m.Key...), append(bytes.Clone(m.Key), []byte("trailing data")...)} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readKey(path); err == nil {
			t.Fatal("malformed private key PEM was accepted")
		}
	}
}

type testRoundTripper func(*http.Request) (*http.Response, error)

func (f testRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestACMETransportPreservesTimeoutAndPassCancellation(t *testing.T) {
	t.Parallel()
	parent, cancelParent := context.WithCancel(t.Context())
	defer cancelParent()
	requestContext, cancelRequest := context.WithTimeout(t.Context(), time.Hour)
	defer cancelRequest()
	request, err := http.NewRequestWithContext(requestContext, http.MethodGet, "https://pki.homelab.lan/acme/directory", nil)
	if err != nil {
		t.Fatal(err)
	}
	var captured context.Context
	transport := contextTransport{ctx: parent, rt: testRoundTripper(func(r *http.Request) (*http.Response, error) {
		captured = r.Context()
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("body"))}, nil
	})}
	response, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	want, _ := requestContext.Deadline()
	if deadline, ok := captured.Deadline(); !ok || !deadline.Equal(want) {
		t.Fatal("the HTTP request timeout was discarded")
	}
	if _, err := io.ReadAll(response.Body); err != nil {
		t.Fatal(err)
	}
	if captured.Err() != nil {
		t.Fatal("the response context was canceled before its body was closed")
	}
	cancelParent()
	select {
	case <-captured.Done():
	case <-time.After(time.Second):
		t.Fatal("the pass cancellation did not reach the request")
	}
}
