package agent

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/Der-Felix/MyOwnPKI/internal/testutil/dnsserver"
)

func TestRFC2136ProviderWorksWithEveryTSIGAlgorithm(t *testing.T) {
	for _, alg := range []string{"hmac-sha256", "hmac-sha384", "hmac-sha512"} {
		t.Run(alg, func(t *testing.T) {
			h := newDNSHarness(t, dnsserver.Key{Name: "acme-agent", Secret: testTSIGSecret, Algorithm: alg})
			creds := tsigCreds(testTSIGSecret)
			creds.TSIGAlgorithm = alg
			p := h.provider(creds)
			if err := p.Present("homelab.lan", "t", "ka"); err != nil {
				t.Fatal(err)
			}
			if got := h.store.TXT(testChallenge); len(got) != 1 {
				t.Fatalf("values: %v", got)
			}
			if err := p.CleanUp("homelab.lan", "t", "ka"); err != nil {
				t.Fatal(err)
			}
			h.wantNoChallengeRecords()
		})
	}
}

func TestRFC2136UnsignedSuccessIsNotAccepted(t *testing.T) {
	h := newDNSHarness(t)
	// A server that holds no key answers a signed update without a signature:
	// somebody in the path could do the same.
	h.srv = dnsserver.Start(t, h.store)
	h.cfg.Nameserver = h.srv.Addr()
	p := h.provider(tsigCreds(testTSIGSecret))
	err := p.Present("homelab.lan", "t", "ka")
	if err == nil {
		t.Fatal("an unsigned answer was accepted as success")
	}
	if !strings.Contains(err.Error(), "not signed") && !strings.Contains(err.Error(), "NOTAUTH") && !strings.Contains(err.Error(), "signed with a key") {
		t.Fatalf("error: %v", err)
	}
}

func TestRFC2136ProviderStopsWhenTheContextIsCanceled(t *testing.T) {
	// A server that accepts the connection and never answers.
	var lc net.ListenConfig
	l, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, aerr := l.Accept()
			if aerr != nil {
				return
			}
			t.Cleanup(func() { _ = c.Close() })
		}
	}()
	h := newDNSHarness(t) // lego's CNAME lookup needs a resolver that answers
	h.cfg.Nameserver, h.cfg.Zone = l.Addr().String(), "homelab.lan"
	p := h.provider(tsigCreds(testTSIGSecret))
	p.timeout = 30 * time.Second
	ctx, cancel := context.WithCancel(t.Context())
	p.useContext(ctx)
	time.AfterFunc(100*time.Millisecond, cancel)
	start := time.Now()
	err = p.Present("homelab.lan", "t", "ka")
	if err == nil || time.Since(start) > 5*time.Second {
		t.Fatalf("after %v: %v", time.Since(start), err)
	}
}

func TestRFC2136ErrorsNeverContainTheSecret(t *testing.T) {
	h := newDNSHarness(t)
	for _, tc := range []struct {
		name   string
		secret string
	}{{"wrong secret", base64.StdEncoding.EncodeToString([]byte("a-different-key-of-some-length-1"))}} {
		p := h.provider(tsigCreds(tc.secret))
		err := p.Present("homelab.lan", "t", "ka")
		if err == nil {
			t.Fatalf("%s: accepted", tc.name)
		}
		for _, text := range []string{err.Error(), tc.secret, "a-different-key"} {
			if text != err.Error() && strings.Contains(err.Error(), text) {
				t.Fatalf("%s: the error contains the secret: %v", tc.name, err)
			}
		}
	}
	// A provider error that does embed a value is cleaned by redact.
	creds := tsigCreds(testTSIGSecret)
	err := creds.redact(errors.New("something " + testTSIGSecret + " went wrong"))
	if strings.Contains(err.Error(), testTSIGSecret) {
		t.Fatal("redact left the secret")
	}
}

func TestRFC2136KeyNameIsFullyQualifiedAndCaseInsensitive(t *testing.T) {
	creds := tsigCreds(testTSIGSecret)
	creds.TSIGKeyName = "Acme-Agent"
	p, err := newRFC2136Provider(DNSProvider{Nameserver: "192.0.2.53", TTL: 120}, creds, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if p.key.name != "acme-agent." || p.nameserver != "192.0.2.53:53" {
		t.Fatalf("key %q, nameserver %q", p.key.name, p.nameserver)
	}
	if p.key.algorithm != dns.HmacSHA256 {
		t.Fatalf("algorithm %q", p.key.algorithm)
	}
	p, err = newRFC2136Provider(DNSProvider{Nameserver: "2001:db8::53", TTL: 120}, creds, time.Now)
	if err != nil || p.nameserver != "[2001:db8::53]:53" {
		t.Fatalf("%v, %v", p, err)
	}
	// The key takes either spelling of its own name, and no other name.
	tsig := &dns.TSIG{Hdr: dns.RR_Header{Name: "ACME-agent."}, Algorithm: "HMAC-SHA256."}
	if _, err := p.key.Generate([]byte("x"), tsig); err != nil {
		t.Fatalf("own name: %v", err)
	}
	tsig.Hdr.Name = "other-key."
	if _, err := p.key.Generate([]byte("x"), tsig); err == nil {
		t.Fatal("signed for another key name")
	}
}

func TestRFC2136KeyRefusesWeakAlgorithms(t *testing.T) {
	creds := tsigCreds(testTSIGSecret)
	p, err := newRFC2136Provider(DNSProvider{Nameserver: "192.0.2.53", TTL: 120}, creds, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	// An answer cannot downgrade the algorithm: hmac-sha1 and md5 never verify.
	for _, alg := range []string{dns.HmacSHA1, dns.HmacMD5, dns.HmacSHA512, "hmac-sha224."} {
		tsig := &dns.TSIG{Hdr: dns.RR_Header{Name: "acme-agent."}, Algorithm: alg, MAC: "00"}
		if err := p.key.Verify([]byte("x"), tsig); err == nil {
			t.Errorf("%s verified", alg)
		}
	}
	creds.TSIGAlgorithm = "hmac-sha1"
	if _, err := newRFC2136Provider(DNSProvider{Nameserver: "192.0.2.53", TTL: 120}, creds, time.Now); err == nil {
		t.Fatal("hmac-sha1 accepted")
	}
}

func TestRFC2136SecretIsWipedWithTheCredentials(t *testing.T) {
	h := newDNSHarness(t)
	creds := tsigCreds(testTSIGSecret)
	p := h.provider(creds)
	if err := p.Present("homelab.lan", "t", "ka"); err != nil {
		t.Fatal(err)
	}
	creds.wipe()
	// A wiped key cannot sign: nothing is sent with an empty secret.
	before := len(h.srv.Messages())
	if err := p.Present("homelab.lan", "t2", "ka2"); err == nil {
		t.Fatal("signed with a wiped secret")
	}
	for _, m := range h.srv.Messages()[before:] {
		if m.Opcode == "UPDATE" {
			t.Fatalf("an update was sent: %+v", m)
		}
	}
}
