package web

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net/http/httptest"
	"strings"
	"testing"
)

// uploadCSR sends data as the wizard's csrfile field and returns what uploadedCSR makes of it.
func uploadCSR(t *testing.T, data []byte) (text string, ok bool, msg string) {
	t.Helper()
	req := multipartRequest(t, data)
	c := &rc{w: httptest.NewRecorder(), r: req}
	if !c.parseForm(maxUIForm) {
		t.Fatalf("the form of a %d byte file was refused", len(data))
	}
	return uploadedCSR(req)
}

// beginText is what a PEM file starts with. A request may carry it as text in
// its subject: the subject is chosen by whoever made the request.
const beginText = "-----BEGIN CERTIFICATE REQUEST-----"

// TestUploadedCSRDecidesDERByParsing: a file is DER when it parses as one
// certificate request, whatever text its bytes hold; only a file that is not
// DER and has a PEM header is taken as PEM text, as before (openssl req -text
// writes text before the block). Searching the bytes for "-----BEGIN" first
// sent a valid DER request whose subject contains that text on as PEM, and the
// wizard then said "Paste a PEM certificate request" about a file it could
// have read.
func TestUploadedCSRDecidesDERByParsing(t *testing.T) {
	t.Parallel()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	makeDER := func(subject pkix.Name) []byte {
		der, cerr := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: subject, DNSNames: []string{"nas.homelab.lan"}}, key)
		if cerr != nil {
			t.Fatal(cerr)
		}
		return der
	}
	block := func(b []byte) []byte { return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: b}) }
	plain := makeDER(pkix.Name{CommonName: "nas.homelab.lan"})
	marked := makeDER(pkix.Name{CommonName: beginText, Organization: []string{beginText}})
	if !bytes.Contains(marked, []byte(beginText)) {
		t.Fatal("the test request does not carry the text in its bytes")
	}
	if _, perr := x509.ParseCertificateRequest(marked); perr != nil {
		t.Fatalf("the test request is not a request: %v", perr)
	}
	good := block(plain)
	trailing := append(bytes.Clone(marked), 0)

	tests := []struct {
		name string
		data []byte
		want string // the text handed on; "" = a refusal
	}{
		{"a DER request", plain, string(good)},
		{"a DER request whose subject contains the PEM header", marked, string(block(marked))},
		{"a PEM request", good, string(good)},
		{"a PEM request behind the text of openssl req -text", append([]byte("Certificate Request:\n    Data:\n        Subject: CN=nas.homelab.lan\n"), good...), "Certificate Request:\n    Data:\n        Subject: CN=nas.homelab.lan\n" + string(good)},
		{"two PEM requests", append(bytes.Clone(good), good...), string(good) + string(good)},
		{"DER with a byte after it", append(bytes.Clone(plain), 0), ""},
		{"DER with a byte after it, header text inside", trailing, string(trailing)}, // not DER, has the header: goes on as text, parseCSR refuses it
		{"a cut DER request", plain[:len(plain)/2], ""},
		{"not a request", []byte("not a request"), ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			text, ok, msg := uploadCSR(t, tt.data)
			if !ok {
				t.Fatal("the file was not seen")
			}
			if tt.want == "" {
				if text != "" || msg == "" {
					t.Fatalf("accepted as %.80q (message %q)", text, msg)
				}
				if !strings.Contains(msg, "neither a PEM nor a DER certificate request") {
					t.Errorf("message %q", msg)
				}
				return
			}
			if msg != "" || text != tt.want {
				t.Fatalf("text %.80q, message %q; want text %.80q", text, msg, tt.want)
			}
		})
	}

	// The wizard's next call: the DER request that carries the header text
	// is read as the same request, and two requests stay refused.
	text, _, _ := uploadCSR(t, marked)
	csr, err := parseCSR(text)
	if err != nil {
		t.Fatalf("parseCSR of the converted request: %v", err)
	}
	if csr.Subject.CommonName != beginText || !bytes.Equal(csr.Raw, marked) {
		t.Errorf("the converted request is %q, not the uploaded one", csr.Subject.CommonName)
	}
	if text, _, _ = uploadCSR(t, trailing); text == "" {
		t.Error("a file with header text and a byte after the request was not handed on")
	} else if _, err = parseCSR(text); err == nil {
		t.Error("parseCSR took a request with a byte after it")
	}
	text, _, _ = uploadCSR(t, append(bytes.Clone(good), good...))
	if _, err = parseCSR(text); err == nil || !strings.Contains(err.Error(), "exactly one certificate request") {
		t.Errorf("two PEM requests: %v", err)
	}
}
