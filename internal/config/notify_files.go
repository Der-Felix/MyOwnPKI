package config

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"os"
)

// NotifyFileProblems reads the files that the configured notification
// channels need and names each one that is missing, unreadable or useless:
// the password and secret files and the extra CA files. The server reads
// them at each send, so a problem here is no start error (the alerts still
// open); `config check` reports it, because every message would fail.
// Contents are checked, never returned or printed. Run as the service
// user: a file only root can read is a finding too.
func (c Config) NotifyFileProblems() []string {
	var out []string
	check := func(key, path string, secret bool) {
		if path == "" {
			return
		}
		if problem := fileProblem(path, secret); problem != "" {
			out = append(out, fmt.Sprintf("%s %s: %s", key, path, problem))
		}
	}
	if e := c.Notify.Email; e.Enabled() {
		check("notify.email.password_file", e.PasswordFile, true)
		check("notify.email.ca_file", e.CAFile, false)
	}
	if w := c.Notify.Webhook; w.Enabled() {
		check("notify.webhook.secret_file", w.SecretFile, true)
		check("notify.webhook.ca_file", w.CAFile, false)
	}
	return out
}

// fileProblem is "" when path is usable: a secret file with content, or a
// file with at least one PEM certificate.
func fileProblem(path string, secret bool) string {
	data, err := os.ReadFile(path) // #nosec G304 -- a path from the operator's configuration
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "the file does not exist"
		}
		var pe *fs.PathError
		if errors.As(err, &pe) {
			err = pe.Err
		}
		return "the file can't be read (" + err.Error() + ") – the service user must be able to read it"
	}
	if secret {
		if len(bytes.TrimSpace(data)) == 0 {
			return "the file is empty"
		}
		return ""
	}
	if !x509.NewCertPool().AppendCertsFromPEM(data) {
		return "the file holds no PEM certificate"
	}
	return ""
}
