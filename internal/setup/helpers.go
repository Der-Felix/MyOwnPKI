package setup

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// randomGroups returns groups of size Crockford Base32 characters joined by
// "-" (5 bits each, one random byte per character: no bias).
func randomGroups(rnd io.Reader, groups, size int) string {
	b := make([]byte, groups*size)
	if _, err := io.ReadFull(rnd, b); err != nil {
		panic(fmt.Sprintf("random: %v", err)) // crypto/rand does not fail
	}
	var s strings.Builder
	for i, x := range b {
		if i > 0 && i%size == 0 {
			s.WriteByte('-')
		}
		s.WriteByte(crockford[x&31])
	}
	return s.String()
}

// caOrganization is the O of the test CA: the host name, so test CAs of
// several machines can be told apart. Left out when it isn't a plain name.
func caOrganization(host string) string {
	if host == "" {
		host, _ = os.Hostname()
	}
	host = strings.TrimSpace(host)
	if host == "" || len(host) > 64 {
		return ""
	}
	for _, c := range host {
		if c < 0x21 || c > 0x7e {
			return ""
		}
	}
	return host
}

const (
	demoHeader        = "# MyOwnPKI DEMO instance – every secret of this instance is in this one file."
	demoPassphraseKey = "unseal passphrase: " // #nosec G101 -- a label in the demo file, not a credential
)

// writeDemoFile writes the generated secrets (mode 0600, never overwriting).
func writeDemoFile(path string, r *run) (err error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("demo secrets file: %w", err)
	}
	defer func() {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}()
	w := bufio.NewWriter(f)
	_, _ = fmt.Fprintf(w, "%s\n# For trying out only – do not use in production: set up a new instance with myownpki init.\n", demoHeader)
	_, _ = fmt.Fprintf(w, "%s%s\n", demoPassphraseKey, r.passphrase)
	if r.recovery != nil {
		_, _ = fmt.Fprintf(w, "recovery key: %s\n", r.recovery.Reveal())
	}
	if r.draft != nil {
		_, _ = fmt.Fprintf(w, "admin user: %s\nadmin password: %s\n", r.username, r.password)
		_, _ = w.WriteString(r.draft.Enrollment.Text())
	}
	return w.Flush()
}

// demoPassphrase reads the passphrase from the first run's demo file, to
// finish an interrupted demo init.
func demoPassphrase(path, dataDir string) ([]byte, error) {
	if path == "" {
		path = filepath.Join(dataDir, "init-demo-secrets.txt")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("the demo init stopped half-way and its secrets file can't be read: %w", err)
	}
	defer clear(data)
	for line := range strings.SplitSeq(string(data), "\n") {
		if p, ok := strings.CutPrefix(strings.TrimRight(line, "\r"), demoPassphraseKey); ok {
			return []byte(p), nil
		}
	}
	return nil, errors.New("no unseal passphrase in the demo secrets file")
}
