package notify

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/config"
	"github.com/Der-Felix/MyOwnPKI/internal/testinstance"
)

var t0 = time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)

func digest() Digest {
	return Digest{Server: "pki01", Created: t0, Events: []Event{
		{Kind: "sealed", Subject: "Server sealed", Severity: "warning", State: Opened, Since: t0, Detail: "Sealed for 11 minutes.", Link: "https://pki.homelab.lan:9443/unseal"},
		{Kind: "cert_expiry", Subject: "www.homelab.lan\r\nBcc: evil@example.com", Severity: "critical", State: Raised, Since: t0, Detail: "Expires in 2 days.\n.\nRCPT TO:<x>"},
		{Kind: "agent_silent", Subject: "Agent proxy1", Severity: "warning", State: Resolved, Since: t0.Add(-time.Hour)},
	}}
}

// TestDigestText: the subject counts per state; names from certificates
// can't add header lines or end the SMTP data early.
func TestDigestText(t *testing.T) {
	t.Parallel()
	d := digest()
	if got, want := d.Subject(), "[MyOwnPKI] pki01: 1 new, 1 now critical, 1 resolved"; got != want {
		t.Errorf("subject = %q, want %q", got, want)
	}
	text := d.Text()
	for _, want := range []string{"NEW\n", "[warning] Server sealed", "https://pki.homelab.lan:9443/unseal", "NOW CRITICAL", "RESOLVED", "Agent proxy1 (open since 2026-10-29 11:00 UTC)"} {
		if !strings.Contains(text, want) {
			t.Errorf("text lacks %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "\r") || strings.Contains(text, "\n.\n") || strings.Contains(text, "lan\nBcc") {
		t.Errorf("control characters survived:\n%q", text)
	}
	if s := TestDigest("pki01", t0).Subject(); s != "[MyOwnPKI] pki01: test message" {
		t.Errorf("test subject = %q", s)
	}
}

// ---------------------------------------------------------------- e-mail

type mail struct {
	from   string
	to     []string
	data   string
	tls    bool
	authed bool
}

// smtpServer is just enough SMTP for net/smtp: EHLO, STARTTLS, AUTH PLAIN,
// MAIL, RCPT, DATA, QUIT.
type smtpServer struct {
	addr     string
	tls      *tls.Config
	implicit bool // TLS from the first byte (port 465)
	starttls bool // offers STARTTLS
	user     string
	password string

	mu    sync.Mutex
	mails []mail
	auths []string // what AUTH saw, to check the password stayed in TLS
}

func newSMTP(t *testing.T, cert tls.Certificate, configure func(*smtpServer)) *smtpServer {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &smtpServer{addr: ln.Addr().String(), tls: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}}
	configure(s)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.handle(c)
		}
	}()
	return s
}

func (s *smtpServer) handle(c net.Conn) {
	defer func() { _ = c.Close() }()
	isTLS := s.implicit
	if s.implicit {
		c = tls.Server(c, s.tls)
	}
	tp := textproto.NewConn(c)
	_ = tp.PrintfLine("220 test ESMTP")
	var m mail
	for {
		line, err := tp.ReadLine()
		if err != nil {
			return
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		switch strings.ToUpper(fields[0]) {
		case "EHLO", "HELO":
			lines := []string{"test"}
			if s.starttls && !isTLS {
				lines = append(lines, "STARTTLS")
			}
			lines = append(lines, "AUTH PLAIN")
			for i, l := range lines {
				sep := "-"
				if i == len(lines)-1 {
					sep = " "
				}
				_ = tp.PrintfLine("250%s%s", sep, l)
			}
		case "STARTTLS":
			_ = tp.PrintfLine("220 go ahead")
			tc := tls.Server(c, s.tls)
			if tc.HandshakeContext(context.Background()) != nil {
				return
			}
			c, tp, isTLS = tc, textproto.NewConn(tc), true
		case "AUTH":
			dec, _ := base64.StdEncoding.DecodeString(fields[len(fields)-1])
			parts := strings.Split(string(dec), "\x00")
			s.mu.Lock()
			s.auths = append(s.auths, string(dec))
			s.mu.Unlock()
			if len(parts) == 3 && parts[1] == s.user && parts[2] == s.password {
				m.authed = true
				_ = tp.PrintfLine("235 ok")
			} else {
				_ = tp.PrintfLine("535 authentication failed")
			}
		case "MAIL":
			m.from = strings.TrimSuffix(strings.TrimPrefix(fields[1], "FROM:<"), ">")
			_ = tp.PrintfLine("250 ok")
		case "RCPT":
			m.to = append(m.to, strings.TrimSuffix(strings.TrimPrefix(fields[1], "TO:<"), ">"))
			_ = tp.PrintfLine("250 ok")
		case "DATA":
			_ = tp.PrintfLine("354 go ahead")
			data, err := tp.ReadDotBytes()
			if err != nil {
				return
			}
			m.data, m.tls = string(data), isTLS
			s.mu.Lock()
			s.mails = append(s.mails, m)
			s.mu.Unlock()
			_ = tp.PrintfLine("250 queued")
		case "QUIT":
			_ = tp.PrintfLine("221 bye")
			return
		default:
			_ = tp.PrintfLine("502 not implemented")
		}
	}
}

func (s *smtpServer) received() []mail {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]mail(nil), s.mails...)
}

// testTLS borrows the 127.0.0.1 certificate of httptest and writes its PEM
// as a ca_file.
func testTLS(t *testing.T) (tls.Certificate, string) {
	t.Helper()
	ts := httptest.NewTLSServer(http.NotFoundHandler())
	cert := ts.TLS.Certificates[0]
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	ts.Close()
	return cert, path
}

func secretFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

const password = "correct horse battery staple"

func TestEmail(t *testing.T) {
	t.Parallel()
	cert, caFile := testTLS(t)
	for _, tc := range []struct {
		name     string
		security string
		server   func(*smtpServer)
		user     bool
	}{
		{"starttls with password", config.SMTPStartTLS, func(s *smtpServer) { s.starttls, s.user, s.password = true, "pki", password }, true},
		{"implicit tls with password", config.SMTPTLS, func(s *smtpServer) { s.implicit, s.user, s.password = true, "pki", password }, true},
		{"none without password", config.SMTPNone, func(*smtpServer) {}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv := newSMTP(t, cert, tc.server)
			e := &Email{Addr: srv.addr, Security: tc.security, From: "pki@homelab.lan", To: []string{"ops@homelab.lan", "lead@homelab.lan"}, CAFile: caFile, Hello: "pki01"}
			if tc.user {
				e.Username, e.PasswordFile = "pki", secretFile(t, password+"\n")
			}
			if err := e.Send(t.Context(), digest()); err != nil {
				t.Fatal(err)
			}
			got := srv.received()
			if len(got) != 1 {
				t.Fatalf("mails: %+v", got)
			}
			m := got[0]
			if m.from != "pki@homelab.lan" || len(m.to) != 2 || m.authed != tc.user || m.tls != (tc.security != config.SMTPNone) {
				t.Errorf("mail: %+v", m)
			}
			if !strings.Contains(m.data, "Subject: [MyOwnPKI] pki01: 1 new, 1 now critical, 1 resolved") || !strings.Contains(m.data, "Auto-Submitted: auto-generated") ||
				strings.Contains(m.data, "\nBcc:") {
				t.Errorf("message:\n%s", m.data)
			}
		})
	}
}

// TestEmailRefusals: no STARTTLS offered = no mail (no silent downgrade); a
// wrong password fails without naming it; an untrusted certificate fails.
func TestEmailRefusals(t *testing.T) {
	t.Parallel()
	cert, caFile := testTLS(t)

	plain := newSMTP(t, cert, func(s *smtpServer) { s.user, s.password = "pki", password })
	e := &Email{Addr: plain.addr, Security: config.SMTPStartTLS, Username: "pki", PasswordFile: secretFile(t, password), From: "a@b.lan", To: []string{"c@b.lan"}, CAFile: caFile}
	if err := e.Send(t.Context(), digest()); err == nil || !strings.Contains(err.Error(), "does not offer STARTTLS") {
		t.Errorf("no STARTTLS: %v", err)
	}
	plain.mu.Lock()
	auths := len(plain.auths)
	plain.mu.Unlock()
	if auths != 0 || len(plain.received()) != 0 {
		t.Errorf("the password or mail went out in plain text (%d AUTH)", auths)
	}

	tlsSrv := newSMTP(t, cert, func(s *smtpServer) { s.starttls, s.user, s.password = true, "pki", "another password" })
	e.Addr = tlsSrv.addr
	err := e.Send(t.Context(), digest())
	if err == nil || !strings.Contains(err.Error(), "authentication as pki") || strings.Contains(err.Error(), password) {
		t.Errorf("wrong password: %v", err)
	}

	e.CAFile = ""
	if err := e.Send(t.Context(), digest()); err == nil || !strings.Contains(err.Error(), "STARTTLS") {
		t.Errorf("untrusted certificate: %v", err)
	}

	e.CAFile, e.PasswordFile = caFile, filepath.Join(t.TempDir(), "missing")
	if err := e.Send(t.Context(), digest()); err == nil || !strings.Contains(err.Error(), "secret file") {
		t.Errorf("missing password file: %v", err)
	}
}

// ---------------------------------------------------------------- webhook

func TestWebhook(t *testing.T) {
	t.Parallel()
	const secret = "s3cret-hmac-key"
	var (
		mu     sync.Mutex
		bodies [][]byte
		sigs   []string
	)
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies, sigs = append(bodies, body), append(sigs, r.Header.Get(SignatureHeader))
		mu.Unlock()
		switch r.URL.Path {
		case "/fail":
			http.Error(w, "nope", http.StatusInternalServerError)
		case "/redirect":
			http.Redirect(w, r, "https://elsewhere.example/", http.StatusFound)
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	t.Cleanup(ts.Close)
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	w := &Webhook{URL: ts.URL + "/hook", SecretFile: secretFile(t, secret+"\n"), CAFile: caFile, UserAgent: "MyOwnPKI/test"}
	d := digest()
	if err := w.Send(t.Context(), d); err != nil {
		t.Fatal(err)
	}
	want, _ := d.JSON()
	if !bytes.Equal(bodies[0], want) || sigs[0] != Sign([]byte(secret), want) || !strings.HasPrefix(sigs[0], "sha256=") {
		t.Errorf("body %s, signature %s", bodies[0], sigs[0])
	}
	parsed, err := ParseDigest(bodies[0])
	if err != nil || len(parsed.Events) != 3 || parsed.Events[0].State != Opened {
		t.Errorf("parsed: %+v, %v", parsed, err)
	}

	w.URL = ts.URL + "/fail?token=hidden-token"
	if err := w.Send(t.Context(), d); err == nil || !strings.Contains(err.Error(), "500") || strings.Contains(err.Error(), "hidden-token") {
		t.Errorf("failing receiver: %v", err)
	}
	w.URL = ts.URL + "/redirect"
	if err := w.Send(t.Context(), d); err == nil || !strings.Contains(err.Error(), "302") {
		t.Errorf("redirect followed: %v", err)
	}
	w.URL, w.CAFile = ts.URL+"/hook?token=hidden-token", ""
	if err := w.Send(t.Context(), d); err == nil || strings.Contains(err.Error(), "hidden-token") {
		t.Errorf("untrusted certificate: %v", err)
	}
}

// ---------------------------------------------------------------- queue

type fakeChannel struct {
	name  string
	fails int // fail this many times, then succeed
	sent  []Digest
}

func (f *fakeChannel) Name() string { return f.name }

func (f *fakeChannel) Send(_ context.Context, d Digest) error {
	if f.fails > 0 {
		f.fails--
		return errors.New("connection refused")
	}
	f.sent = append(f.sent, d)
	return nil
}

type logBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuf) Write(p []byte) (int, error) { l.mu.Lock(); defer l.mu.Unlock(); return l.b.Write(p) }
func (l *logBuf) String() string              { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

// TestQueueRetries: 1, 5, 30 minutes and 2 hours between attempts, then
// dropped; a working channel is not held up by a broken one.
func TestQueueRetries(t *testing.T) {
	t.Parallel()
	inst := testinstance.New(t, testinstance.Options{})
	db := inst.SystemDB.Write
	var logs logBuf
	broken := &fakeChannel{name: "email", fails: 100}
	working := &fakeChannel{name: "webhook"}
	q := &Queue{DB: db, Log: slog.New(slog.NewJSONHandler(&logs, nil)), Channels: []Channel{broken, working}}
	enqueue := func(now time.Time) {
		tx, err := db.BeginTx(t.Context(), nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := Enqueue(t.Context(), tx, now, digest(), q.Names()); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	enqueue(t0)
	now := t0
	deliver := func() {
		if err := q.Deliver(t.Context(), now); err != nil {
			t.Fatal(err)
		}
	}
	deliver()
	if len(working.sent) != 1 || strings.Count(logs.String(), "will retry") != 1 {
		t.Fatalf("first run: sent %d\n%s", len(working.sent), logs.String())
	}
	for i, wait := range Retries {
		now = now.Add(wait - time.Second)
		deliver()
		if n := strings.Count(logs.String(), `"channel":"email"`); n != i+1 {
			t.Fatalf("retry %d ran early (%d log lines)", i+1, n)
		}
		now = now.Add(time.Second)
		deliver()
	}
	l := logs.String()
	if strings.Count(l, "will retry") != 4 || strings.Count(l, "notification dropped after the last retry") != 1 || !strings.Contains(l, `"attempts":5`) {
		t.Errorf("retry log:\n%s", l)
	}
	now = now.Add(24 * time.Hour)
	deliver()
	if strings.Count(logs.String(), `"channel":"email"`) != 5 || len(working.sent) != 1 {
		t.Errorf("a dropped message came back:\n%s", logs.String())
	}

	// Pruning removes the finished rows.
	n, err := q.Prune(t.Context(), now.Add(time.Second))
	if err != nil || n != 2 {
		t.Errorf("prune: %d, %v", n, err)
	}

	// A channel that recovers delivers on the next attempt.
	recovering := &fakeChannel{name: "email", fails: 1}
	q.Channels = []Channel{recovering}
	enqueue(now)
	deliver()
	now = now.Add(time.Minute)
	deliver()
	if len(recovering.sent) != 1 || !strings.Contains(logs.String(), `"msg":"notification sent","channel":"email","attempt":2`) {
		t.Errorf("recovery: sent %d\n%s", len(recovering.sent), logs.String())
	}
}
