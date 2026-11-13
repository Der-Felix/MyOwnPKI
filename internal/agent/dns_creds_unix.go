//go:build unix

package agent

import (
	"errors"
	"os"
	"syscall"
)

// credsEnforcePermissions: POSIX modes and owners exist, so the credentials
// file is held to them (dns_creds.go).
const credsEnforcePermissions = true

// openCredentialsFile opens without following a symbolic link in the last
// path element (O_NOFOLLOW) and without blocking on a pipe (O_NONBLOCK); the
// caller checks what was opened, not what the path said.
func openCredentialsFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}

// isSymlinkOpenError: O_NOFOLLOW on a link fails with ELOOP (Linux, macOS)
// or EMLINK (FreeBSD).
func isSymlinkOpenError(err error) bool {
	return errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.EMLINK)
}

func fileUID(fi os.FileInfo) (int, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int(st.Uid), true
}

func effectiveUID() int { return os.Geteuid() }
