package web

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// csrFileLimit is the size limit of an uploaded CSR file written as a
// number, so a change of maxCSRFile shows up here.
const csrFileLimit = 64 * 1024

// FuzzUploadedCSR is the target of docs/PHASE3.md section 18.1 step 86: the
// file of the issue wizard's "upload a CSR" field. The request is built the
// way a browser sends it and read by the production parseForm with the
// production limit, then uploadedCSR is called unchanged.
//
// What uploadedCSR promises (and what it leaves to the next call): a DER file
// is checked here and returned as one PEM block; a file that has a PEM
// header is returned as it is and checked by parseCSR of the same wizard
// step, so the target runs both and states the promise of the pair.
func FuzzUploadedCSR(f *testing.F) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	makeDER := func(cn string, mutate func(*x509.CertificateRequest)) []byte {
		tpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}, DNSNames: []string{"nas.homelab.lan"}}
		if mutate != nil {
			mutate(tpl)
		}
		der, err := x509.CreateCertificateRequest(rand.Reader, tpl, key)
		if err != nil {
			f.Fatal(err)
		}
		return der
	}
	der := makeDER("nas.homelab.lan", nil)
	block := func(typ string, b []byte) []byte { return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: b}) }
	good := block("CERTIFICATE REQUEST", der)
	badSig := append([]byte(nil), der...)
	badSig[len(badSig)-3] ^= 0x55

	f.Add(good)
	f.Add(der)
	f.Add(block("NEW CERTIFICATE REQUEST", der))
	f.Add(block("CERTIFICATE", der))
	f.Add(block("CERTIFICATE REQUEST", badSig))
	f.Add(badSig)
	f.Add(append(append([]byte(nil), good...), good...))                    // two requests
	f.Add(append(append([]byte(nil), good...), []byte("trailing text")...)) // data after it
	f.Add(append([]byte("leading text\n"), good...))                        // data before it
	f.Add(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"}, Bytes: der}))
	f.Add(append(append([]byte(nil), der...), 0))                                                                         // DER with a byte after it
	f.Add(der[:len(der)/2])                                                                                               // cut DER
	f.Add(makeDER("-----BEGIN not a pem", nil))                                                                           // a DER request whose text looks like a header
	f.Add(makeDER("<script>alert(1)</script>", nil))                                                                      // markup in the name
	f.Add(makeDER("a", func(c *x509.CertificateRequest) { c.DNSNames = []string{strings.Repeat("a", 60_000) + ".lan"} })) // large, still under the limit
	f.Add([]byte("-----BEGIN CERTIFICATE REQUEST-----"))
	f.Add([]byte("-----BEGIN CERTIFICATE REQUEST-----\n!!!\n-----END CERTIFICATE REQUEST-----\n"))
	f.Add([]byte("\x00\x01\x02-----BEGIN"))
	f.Add([]byte{0x30, 0x00})
	f.Add([]byte{})
	f.Add([]byte("x"))
	f.Add(append(append([]byte(nil), good...), bytes.Repeat([]byte(" "), csrFileLimit-len(good))...))   // exactly 64 KiB
	f.Add(append(append([]byte(nil), good...), bytes.Repeat([]byte(" "), csrFileLimit-len(good)+1)...)) // one byte more
	f.Add(bytes.Repeat([]byte{0xff}, csrFileLimit+1))
	f.Add(bytes.Repeat([]byte("-----BEGIN "), 6000))

	f.Fuzz(func(t *testing.T, data []byte) {
		req := multipartRequest(t, data)
		rec := httptest.NewRecorder()
		c := &rc{w: rec, r: req}
		if !c.parseForm(maxUIForm) {
			// The router refuses the form before the wizard sees it; only a
			// body over the form limit can end up here.
			if len(data) < maxUIForm-1024 {
				t.Fatalf("the form of a %d byte file was refused", len(data))
			}
			return
		}

		start := time.Now()
		text, ok, msg := uploadedCSR(req)
		if d := time.Since(start); d > 2*time.Second {
			t.Fatalf("uploadedCSR took %v for %d bytes", d, len(data))
		}

		switch {
		case len(data) == 0:
			if ok || msg != "" || text != "" {
				t.Fatalf("an empty file counts as no file: %v %q %q", ok, text, msg)
			}
			return
		case !ok:
			t.Fatalf("a file of %d bytes was not seen", len(data))
		case len(data) > csrFileLimit:
			if msg == "" || text != "" {
				t.Fatalf("%d bytes accepted (limit %d)", len(data), csrFileLimit)
			}
		}
		if msg != "" {
			if text != "" {
				t.Fatalf("a refusal that also returns text: %q", msg)
			}
			if len(msg) > 200 || !strings.HasSuffix(msg, ".") {
				t.Fatalf("refusal text %q", msg)
			}
			return
		}

		// Accepted. A file without a PEM header must have been a DER request.
		if !bytes.Contains(data, []byte("-----BEGIN")) {
			b, rest := pem.Decode([]byte(text))
			if b == nil || len(rest) != 0 || b.Type != "CERTIFICATE REQUEST" || len(b.Headers) != 0 || !bytes.Equal(b.Bytes, data) {
				t.Fatalf("a DER file came back as %.80q", text)
			}
			if _, err := x509.ParseCertificateRequest(data); err != nil {
				t.Fatalf("accepted DER that does not parse: %v", err)
			}
		} else if text != string(data) {
			t.Fatal("a PEM file was changed")
		}

		// The pair: what the wizard's next call (parseCSR) takes from the
		// text is one signed request in one PEM block.
		csr, err := parseCSR(text)
		if err != nil {
			return
		}
		b, rest := pem.Decode([]byte(strings.TrimSpace(text)))
		if b == nil || strings.TrimSpace(string(rest)) != "" || (b.Type != "CERTIFICATE REQUEST" && b.Type != "NEW CERTIFICATE REQUEST") {
			t.Fatalf("parseCSR took text that is not one request block: %.80q", text)
		}
		again, err := x509.ParseCertificateRequest(b.Bytes)
		if err != nil || again.CheckSignature() != nil {
			t.Fatalf("parseCSR took a request that does not parse or verify: %v", err)
		}
		if !bytes.Equal(again.Raw, csr.Raw) {
			t.Fatal("parseCSR returned another request than the block holds")
		}
	})
}

// multipartRequest builds the POST a browser sends for the upload field.
func multipartRequest(t *testing.T, data []byte) *http.Request {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, err := mw.CreateFormFile("csrfile", "request.csr")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = fw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err = mw.Close(); err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://pki.homelab.lan/certificates/new", &body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	return req
}
