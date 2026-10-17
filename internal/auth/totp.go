package auth

import (
	"crypto/hmac"
	"crypto/sha1" // #nosec G505 -- TOTP (RFC 6238) uses HMAC-SHA1; every authenticator app supports it, and HMAC-SHA1 is not broken
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"time"
)

// TOTP parameters (RFC 6238): the defaults every authenticator app
// understands (Aegis, Google, Microsoft, 1Password).
const (
	TOTPSecretSize = 20 // 160 bits, as RFC 4226 recommends
	totpDigits     = 6
	totpPeriod     = 30 // seconds
	totpSkew       = 1  // steps before and after: ±30 s clock difference
)

var totpBase32 = base32.StdEncoding.WithPadding(base32.NoPadding)

func newTOTPSecret(rnd io.Reader) ([]byte, error) { return randomBytes(rnd, TOTPSecretSize) }

// hotp is RFC 4226 section 5.3: HMAC-SHA1 over the counter, dynamic
// truncation, modulo 10^digits.
func hotp(secret []byte, counter uint64, digits int) string {
	mac := hmac.New(sha1.New, secret)
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	mod := uint32(1)
	for range digits {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, bin%mod)
}

func totpStep(t time.Time) int64 { return t.Unix() / totpPeriod }

// matchTOTP checks code against the steps around now and returns the step
// it matched. Only steps after lastStep count: a code works once. All
// candidates are compared, in constant time each.
func matchTOTP(secret []byte, code string, now time.Time, lastStep int64) (int64, bool) {
	if len(code) != totpDigits || strings.Trim(code, "0123456789") != "" {
		return 0, false
	}
	var found int64
	cur := totpStep(now)
	for step := cur - totpSkew; step <= cur+totpSkew; step++ {
		if step <= lastStep || step < 0 {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(hotp(secret, uint64(step), totpDigits)), []byte(code)) == 1 && found == 0 {
			found = step
		}
	}
	return found, found != 0
}

// normalizeTOTPCode drops the spaces apps show in the middle ("123 456").
func normalizeTOTPCode(code string) string {
	return strings.ReplaceAll(strings.TrimSpace(code), " ", "")
}

// looksLikeTOTP: six digits (spaces allowed) are a TOTP code; anything else
// is a recovery code.
func looksLikeTOTP(code string) bool {
	c := normalizeTOTPCode(code)
	if len(c) != totpDigits {
		return false
	}
	for _, r := range c {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// Enrollment is what a user needs to set up an authenticator app. Show it
// once; it is never shown again.
type Enrollment struct {
	UserID   string
	Username string
	// URI is the otpauth:// link (QR code or a file for the Docker demo).
	URI string
	// Secret is the same secret for typing in, in groups of four.
	Secret string
	// RecoveryCodes, when new ones were made (user creation, reset-2fa).
	RecoveryCodes []string
}

func newEnrollment(issuer, userID, username string, secret []byte) *Enrollment {
	enc := totpBase32.EncodeToString(secret)
	var groups []string
	for i := 0; i < len(enc); i += 4 {
		groups = append(groups, enc[i:min(i+4, len(enc))])
	}
	v := url.Values{}
	v.Set("secret", enc)
	v.Set("issuer", issuer)
	v.Set("algorithm", "SHA1")
	v.Set("digits", fmt.Sprint(totpDigits))
	v.Set("period", fmt.Sprint(totpPeriod))
	label := url.PathEscape(issuer) + ":" + url.PathEscape(username)
	return &Enrollment{
		UserID: userID, Username: username, Secret: strings.Join(groups, " "),
		URI: "otpauth://totp/" + label + "?" + v.Encode(),
	}
}

// ErrEnrollmentNeedsFile: without an interactive terminal (Docker, systemd, a
// pipe) the secret would end up in a log, so it may only go to a file.
var ErrEnrollmentNeedsFile = errors.New("standard output is not an interactive terminal – " +
	"the TOTP secret and recovery codes would end up in a log; use --otpauth-file <path>")

// WriteEnrollmentFile writes e to a new file with mode 0600 – for setups
// without a terminal (Docker demo). An existing file is never overwritten.
func WriteEnrollmentFile(path string, e *Enrollment) (err error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("enrollment file: %w", err)
	}
	defer func() {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}()
	_, err = io.WriteString(f, e.Text())
	return err
}

// Text is the enrollment for a person: what to do, the link, the secret
// and the recovery codes.
func (e *Enrollment) Text() string {
	var s strings.Builder
	fmt.Fprintf(&s, "# MyOwnPKI sign-in for %q – shown once. Delete this after setting up the app.\n", e.Username)
	fmt.Fprintf(&s, "# Add the account to an authenticator app (Aegis, Google or Microsoft Authenticator, 1Password …):\n")
	fmt.Fprintf(&s, "# open the link, or type the secret. The first code at sign-in confirms it.\n")
	fmt.Fprintf(&s, "otpauth link: %s\n", e.URI)
	fmt.Fprintf(&s, "secret:       %s\n", e.Secret)
	if len(e.RecoveryCodes) > 0 {
		fmt.Fprintf(&s, "# Recovery codes – each works once instead of a TOTP code. Keep them offline, apart from the phone.\n")
		for _, c := range e.RecoveryCodes {
			fmt.Fprintf(&s, "recovery code: %s\n", c)
		}
	}
	return s.String()
}
