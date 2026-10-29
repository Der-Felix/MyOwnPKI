package notify

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/smtp"
	"os"
	"strings"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/config"
)

// emailTimeout bounds one delivery: connect, TLS, authentication, data.
const emailTimeout = 20 * time.Second

// Email sends a digest over SMTP.
type Email struct {
	Addr         string // host:port
	Security     string // config.SMTPStartTLS, SMTPTLS or SMTPNone
	Username     string
	PasswordFile string
	From         string
	To           []string
	CAFile       string // extra roots; "" = the system roots
	Hello        string // name for EHLO; "" = localhost
}

// NewEmail builds the channel from notify.email.
func NewEmail(c config.Email, hello string) *Email {
	return &Email{Addr: c.SMTP, Security: c.Mode(), Username: c.Username, PasswordFile: c.PasswordFile,
		From: c.From, To: c.Recipients(), CAFile: c.CAFile, Hello: hello}
}

// Name is the channel in the notifications queue.
func (e *Email) Name() string { return "email" }

// Send delivers one message. The password is read from its file now, so a
// changed password needs no restart; it never appears in an error.
func (e *Email) Send(ctx context.Context, d Digest) error {
	ctx, cancel := context.WithTimeout(ctx, emailTimeout)
	defer cancel()
	host, _, err := net.SplitHostPort(e.Addr)
	if err != nil {
		return fmt.Errorf("smtp %q: %w", e.Addr, err)
	}
	roots, err := rootPool(e.CAFile)
	if err != nil {
		return err
	}
	tlsConfig := &tls.Config{ServerName: host, RootCAs: roots, MinVersion: tls.VersionTLS12}
	dialer := &net.Dialer{}
	var conn net.Conn
	if e.Security == config.SMTPTLS {
		conn, err = (&tls.Dialer{NetDialer: dialer, Config: tlsConfig}).DialContext(ctx, "tcp", e.Addr)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", e.Addr)
	}
	if err != nil {
		return fmt.Errorf("smtp %s: %w", e.Addr, err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("smtp %s: %w", e.Addr, err)
	}
	defer func() { _ = c.Close() }()
	if e.Hello != "" {
		if err = c.Hello(e.Hello); err != nil {
			return fmt.Errorf("smtp %s: EHLO: %w", e.Addr, err)
		}
	}
	if e.Security == config.SMTPStartTLS {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return fmt.Errorf("smtp %s: the server does not offer STARTTLS – set notify.email.security to tls or none", e.Addr)
		}
		if err = c.StartTLS(tlsConfig); err != nil {
			return fmt.Errorf("smtp %s: STARTTLS: %w", e.Addr, err)
		}
	}
	if e.Username != "" {
		password, perr := readSecret(e.PasswordFile)
		if perr != nil {
			return perr
		}
		// PlainAuth itself refuses a connection without TLS.
		if err = c.Auth(smtp.PlainAuth("", e.Username, password, host)); err != nil {
			return fmt.Errorf("smtp %s: authentication as %s: %w", e.Addr, e.Username, err)
		}
	}
	if err = c.Mail(e.From); err != nil {
		return fmt.Errorf("smtp %s: MAIL FROM: %w", e.Addr, err)
	}
	for _, to := range e.To {
		if err = c.Rcpt(to); err != nil {
			return fmt.Errorf("smtp %s: RCPT TO %s: %w", e.Addr, to, err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("smtp %s: DATA: %w", e.Addr, err)
	}
	if _, err = w.Write(e.message(d)); err != nil {
		return fmt.Errorf("smtp %s: DATA: %w", e.Addr, err)
	}
	if err = w.Close(); err != nil {
		return fmt.Errorf("smtp %s: DATA: %w", e.Addr, err)
	}
	return c.Quit()
}

// message is the RFC 5322 message: plain text, UTF-8.
func (e *Email) message(d Digest) []byte {
	var b bytes.Buffer
	header := func(k, v string) { b.WriteString(k + ": " + clean(v) + "\r\n") }
	header("From", e.From)
	header("To", strings.Join(e.To, ", "))
	header("Subject", mime.QEncoding.Encode("utf-8", d.Subject()))
	header("Date", d.Created.UTC().Format(time.RFC1123Z))
	header("MIME-Version", "1.0")
	header("Content-Type", "text/plain; charset=utf-8")
	header("Content-Transfer-Encoding", "8bit")
	header("Auto-Submitted", "auto-generated")
	b.WriteString("\r\n")
	b.WriteString(strings.ReplaceAll(d.Text(), "\n", "\r\n"))
	return b.Bytes()
}

// readSecret reads a password or key file; surrounding white space (the
// newline of `echo > file`) is not part of it.
func readSecret(path string) (string, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- a path from the operator's configuration
	if err != nil {
		return "", fmt.Errorf("secret file: %w", err)
	}
	s := strings.TrimSpace(string(data))
	if s == "" {
		return "", fmt.Errorf("secret file %s is empty", path)
	}
	return s, nil
}

// rootPool is the system roots plus the PEM certificates of file.
func rootPool(file string) (*x509.CertPool, error) {
	if file == "" {
		return nil, nil
	}
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	data, err := os.ReadFile(file) // #nosec G304 -- a path from the operator's configuration
	if err != nil {
		return nil, fmt.Errorf("ca_file: %w", err)
	}
	if !pool.AppendCertsFromPEM(data) {
		return nil, errors.New("ca_file " + file + ": no PEM certificate in it")
	}
	return pool, nil
}
