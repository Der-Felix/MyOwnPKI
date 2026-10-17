package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/store/systemdb"
)

// Device cookies (OWASP "device cookies", PHASE1 step 13, owner 2026-10-17).
// The lockout of step 10 lets anybody who knows a user name lock that user
// out again and again. A browser that completed a sign-in (password and
// second factor) gets a signed cookie; attempts that bring it are judged by
// their own counter, not by the user lockout strangers trigger – the real
// admin keeps getting in. The cookie names user, random value and end; its
// HMAC also covers the user's credentials epoch (system 0006), so a new
// password, a new or reset second factor and user unlock void it.

const (
	// DeviceCookieName is the cookie of a known device.
	DeviceCookieName = "__Host-myownpki_device"
	// DeviceCookieTTL: a device stays known this long after its last sign-in.
	DeviceCookieTTL = 365 * 24 * time.Hour
	// DeviceLockAfter failures with one device cookie lock that cookie for
	// DeviceLockFor; it then counts like an unknown browser.
	DeviceLockAfter = 10
	DeviceLockFor   = 15 * time.Minute

	deviceNonceBytes = 16
	devicePrefix     = "v1"
)

// deviceRule: free failures up to DeviceLockAfter, then the cookie is locked
// for DeviceLockFor; the counter is forgotten DeviceLockFor after the last
// failure. The lock list lives in memory only (owner 2026-10-17): a thief of
// the cookie still needs password and second factor.
var deviceRule = rule{free: DeviceLockAfter, base: DeviceLockFor, limit: DeviceLockFor, forget: DeviceLockFor}

// Client is where a sign-in attempt comes from.
type Client struct {
	IP string
	// Device is the value of the device cookie; "" = none.
	Device string
}

// DeviceCookie is the cookie for value (from LoginResult.DeviceCookie).
func DeviceCookie(value string) *http.Cookie {
	return &http.Cookie{
		Name: DeviceCookieName, Value: value, Path: "/", MaxAge: int(DeviceCookieTTL.Seconds()),
		Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	}
}

func (k *Key) deviceMAC(userID, nonce string, expires, epoch int64) []byte {
	mac := hmac.New(sha256.New, k.device)
	mac.Write([]byte("myownpki/device-cookie/v1\x00" + userID + "\x00" + nonce + "\x00" +
		strconv.FormatInt(expires, 10) + "\x00" + strconv.FormatInt(epoch, 10)))
	return mac.Sum(nil)
}

// newDevice returns a new device cookie value for the user.
func (k *Key) newDevice(rnd io.Reader, u systemdb.User, now time.Time) (string, error) {
	b, err := randomBytes(rnd, deviceNonceBytes)
	if err != nil {
		return "", err
	}
	nonce := base64.RawURLEncoding.EncodeToString(b)
	expires := now.Add(DeviceCookieTTL).Unix()
	mac := base64.RawURLEncoding.EncodeToString(k.deviceMAC(u.ID, nonce, expires, u.CredentialsEpoch))
	return strings.Join([]string{devicePrefix, u.ID, nonce, strconv.FormatInt(expires, 10), mac}, "."), nil
}

// checkDevice checks a device cookie value for u and returns its random value as
// the key of its counter; "" = no valid cookie of this user.
func (k *Key) checkDevice(value string, u systemdb.User, now time.Time) string {
	parts := strings.Split(value, ".")
	if len(parts) != 5 || parts[0] != devicePrefix || parts[1] != u.ID || len(parts[2]) == 0 || len(parts[2]) > 64 {
		return ""
	}
	expires, err := strconv.ParseInt(parts[3], 10, 64)
	if err != nil || now.Unix() >= expires {
		return ""
	}
	got, err := base64.RawURLEncoding.DecodeString(parts[4])
	if err != nil || !hmac.Equal(got, k.deviceMAC(u.ID, parts[2], expires, u.CredentialsEpoch)) {
		return ""
	}
	return parts[2]
}

// trustedDevice returns the counter key of c's device cookie for u, or ""
// when there is none, it is invalid, or it is locked right now.
func (s *Service) trustedDevice(c Client, u systemdb.User, now time.Time) string {
	if c.Device == "" {
		return ""
	}
	nonce := s.Key.checkDevice(c.Device, u, now)
	if nonce == "" || s.Throttle.DeviceLocked(nonce, now) {
		return ""
	}
	return nonce
}
