// Package fixture provides fixed sample data for the UI prototype in dev mode.
// Nothing here is a real certificate or key: serials and fingerprints are
// derived from names so they are stable across runs. Phase 1 replaces this
// package with the store; the pages don't change.
package fixture

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strings"
	"time"
)

// Now is the fixed reference time of the sample data, so relative dates
// ("in 83 days") and screenshots are reproducible.
var Now = time.Date(2026, 10, 13, 8, 0, 0, 0, time.UTC)

// Tenants are the sample tenants for the header switch.
var Tenants = []string{"homelab", "lab-2"}

// User is the signed-in sample user.
const User = "it-admin"

// CA is a sample certificate authority.
type CA struct {
	ID, Name, Kind, ParentID string
	Subject                  string
	KeyAlgorithm, KeyMode    string
	NotBefore, NotAfter      time.Time
	PathLen                  string
	PermittedDNS             []string
	PermittedIP              []string
	MaxValidityDays          int
	CRLNumber                int
	CRLThisUpdate            time.Time
	CRLNextUpdate            time.Time
	PublicBaseURL            string
}

// Serial is a stable, fake serial number.
func (c CA) Serial() string { return fakeHex("ca-serial:"+c.Name, 16) }

// Fingerprint is a stable, fake SHA-256 fingerprint.
func (c CA) Fingerprint() string { return fakeHex("ca-fp:"+c.Name, 32) }

// FingerprintSHA1 is a stable, fake display-only SHA-1 fingerprint.
func (c CA) FingerprintSHA1() string { return fakeHex("ca-sha1:"+c.Name, 20) }

// Event is one entry of a certificate's history.
type Event struct {
	Time   time.Time
	Actor  string
	Action string
}

// Certificate is a sample end-entity certificate.
type Certificate struct {
	ID, CommonName, Preset, CAID string
	NotBefore, NotAfter          time.Time
	KeyAlgorithm                 string
	DNS, IP, Email               []string
	KeyStored                    bool
	RequestedBy                  string
	RevokedAt                    time.Time // zero if not revoked
	RevocationReason             string
	History                      []Event
}

// Serial is a stable, fake serial number.
func (c Certificate) Serial() string { return fakeHex("serial:"+c.ID, 16) }

// Fingerprint is a stable, fake SHA-256 fingerprint.
func (c Certificate) Fingerprint() string { return fakeHex("fp:"+c.ID, 32) }

// Activity is one entry of the recent-activity list.
type Activity struct {
	Time                  time.Time
	Actor, Action, Target string
	Result                string // success | denied | failure
}

func fakeHex(seed string, n int) string {
	sum := sha256.Sum256([]byte(seed))
	b := sum[:n]
	b[0] &= 0x7f // positive, like a real serial
	return strings.ToUpper(hex.EncodeToString(b))
}

func day(y int, m time.Month, d int) time.Time { return time.Date(y, m, d, 9, 30, 0, 0, time.UTC) }

var cas = []CA{
	{
		ID: "homelab-root", Name: "homelab-root", Kind: "root",
		Subject:      "CN=Homelab Root CA 2026, O=Homelab, C=DE",
		KeyAlgorithm: "ECDSA P-384", KeyMode: "offline",
		NotBefore: day(2026, 1, 10), NotAfter: day(2041, 1, 10),
		PathLen: "1", MaxValidityDays: 3650,
		CRLNumber: 4, CRLThisUpdate: day(2026, 7, 1), CRLNextUpdate: day(2027, 1, 1),
		PublicBaseURL: "http://pki.homelab.lan",
	},
	{
		ID: "homelab-issuing", Name: "homelab-issuing", Kind: "intermediate", ParentID: "homelab-root",
		Subject:      "CN=Homelab Issuing CA 1, O=Homelab, C=DE",
		KeyAlgorithm: "ECDSA P-384", KeyMode: "online, encrypted",
		NotBefore: day(2026, 1, 12), NotAfter: day(2031, 1, 12),
		PathLen: "0", PermittedDNS: []string{".homelab.lan", "homelab.lan"}, PermittedIP: []string{"10.0.0.0/8", "192.168.0.0/16", "fd00::/8"},
		MaxValidityDays: 397,
		CRLNumber:       42, CRLThisUpdate: day(2026, 10, 12), CRLNextUpdate: day(2026, 10, 19),
		PublicBaseURL: "http://pki.homelab.lan",
	},
	{
		ID: "homelab-users", Name: "homelab-users", Kind: "intermediate", ParentID: "homelab-root",
		Subject:      "CN=Homelab User CA 1, O=Homelab, C=DE",
		KeyAlgorithm: "ECDSA P-384", KeyMode: "online, encrypted",
		NotBefore: day(2026, 1, 12), NotAfter: day(2031, 1, 12),
		PathLen: "0", MaxValidityDays: 730,
		CRLNumber: 7, CRLThisUpdate: day(2026, 10, 8), CRLNextUpdate: day(2026, 10, 15),
		PublicBaseURL: "http://pki.homelab.lan",
	},
}

var certificates = []Certificate{
	{ID: "c-0101", CommonName: "nas.homelab.lan", Preset: "server", CAID: "homelab-issuing",
		NotBefore: day(2025, 12, 3), NotAfter: day(2027, 1, 4), KeyAlgorithm: "ECDSA P-256",
		DNS: []string{"nas.homelab.lan"}, IP: []string{"192.168.10.20"}, RequestedBy: "it-admin",
		History: []Event{
			{day(2025, 12, 3), "it-admin", "Issued (preset server, CSR uploaded)"},
			{day(2025, 12, 3), "it-admin", "Downloaded fullchain.pem"},
		}},
	{ID: "c-0102", CommonName: "proxmox.homelab.lan", Preset: "server", CAID: "homelab-issuing",
		NotBefore: day(2025, 10, 1), NotAfter: day(2026, 11, 2), KeyAlgorithm: "ECDSA P-256",
		DNS: []string{"proxmox.homelab.lan", "pve.homelab.lan"}, KeyStored: true, RequestedBy: "it-admin",
		History: []Event{
			{day(2025, 10, 1), "it-admin", "Issued (preset server, key generated on server)"},
			{day(2025, 10, 1), "it-admin", "Exported PKCS#12 (step-up confirmed)"},
		}},
	{ID: "c-0103", CommonName: "*.apps.homelab.lan", Preset: "wildcard", CAID: "homelab-issuing",
		NotBefore: day(2026, 2, 14), NotAfter: day(2027, 3, 18), KeyAlgorithm: "ECDSA P-256",
		DNS: []string{"*.apps.homelab.lan", "apps.homelab.lan"}, RequestedBy: "it-admin"},
	{ID: "c-0104", CommonName: "radius.homelab.lan", Preset: "server-client", CAID: "homelab-issuing",
		NotBefore: day(2026, 4, 20), NotAfter: day(2027, 5, 21), KeyAlgorithm: "RSA 3072",
		DNS: []string{"radius.homelab.lan"}, RequestedBy: "it-admin",
		RevokedAt: day(2026, 9, 2), RevocationReason: "superseded",
		History: []Event{
			{day(2026, 4, 20), "it-admin", "Issued (preset server-client)"},
			{day(2026, 9, 2), "it-admin", "Revoked (superseded), CRL 41 published"},
		}},
	{ID: "c-0105", CommonName: "vpn.homelab.lan", Preset: "vpn-server", CAID: "homelab-issuing",
		NotBefore: day(2025, 9, 12), NotAfter: day(2027, 9, 12), KeyAlgorithm: "RSA 3072",
		DNS: []string{"vpn.homelab.lan"}, IP: []string{"203.0.113.17"}, RequestedBy: "it-admin"},
	{ID: "c-0106", CommonName: "git.homelab.lan", Preset: "server", CAID: "homelab-issuing",
		NotBefore: day(2026, 1, 20), NotAfter: day(2026, 10, 28), KeyAlgorithm: "ECDSA P-256",
		DNS: []string{"git.homelab.lan"}, RequestedBy: "acme:traefik"},
	{ID: "c-0107", CommonName: "grafana.homelab.lan", Preset: "server", CAID: "homelab-issuing",
		NotBefore: day(2026, 7, 15), NotAfter: day(2026, 10, 13).Add(13 * time.Hour), KeyAlgorithm: "ECDSA P-256",
		DNS: []string{"grafana.homelab.lan"}, RequestedBy: "acme:traefik"},
	{ID: "c-0108", CommonName: "unifi.homelab.lan", Preset: "server", CAID: "homelab-issuing",
		NotBefore: day(2025, 8, 30), NotAfter: day(2026, 8, 30), KeyAlgorithm: "RSA 2048",
		DNS: []string{"unifi.homelab.lan"}, IP: []string{"192.168.10.2"}, KeyStored: true, RequestedBy: "it-admin"},
	{ID: "c-0109", CommonName: "ldap.homelab.lan", Preset: "server", CAID: "homelab-issuing",
		NotBefore: day(2026, 3, 1), NotAfter: day(2027, 4, 2), KeyAlgorithm: "ECDSA P-256",
		DNS: []string{"ldap.homelab.lan", "dc1.homelab.lan"}, RequestedBy: "it-admin"},
	{ID: "c-0110", CommonName: "mqtt.homelab.lan", Preset: "server-client", CAID: "homelab-issuing",
		NotBefore: day(2026, 5, 5), NotAfter: day(2027, 6, 6), KeyAlgorithm: "ECDSA P-256",
		DNS: []string{"mqtt.homelab.lan"}, RequestedBy: "agent:iot-gw"},
	{ID: "c-0111", CommonName: "it-admin@homelab.lan", Preset: "smime", CAID: "homelab-users",
		NotBefore: day(2024, 8, 30), NotAfter: day(2026, 8, 30), KeyAlgorithm: "RSA 3072",
		Email: []string{"it-admin@homelab.lan"}, KeyStored: true, RequestedBy: "it-admin"},
	{ID: "c-0112", CommonName: "laptop-07", Preset: "client", CAID: "homelab-users",
		NotBefore: day(2026, 6, 1), NotAfter: day(2028, 6, 1), KeyAlgorithm: "ECDSA P-256",
		DNS: []string{"laptop-07.homelab.lan"}, RequestedBy: "it-admin"},
	{ID: "c-0113", CommonName: "backup-signing", Preset: "codesign", CAID: "homelab-users",
		NotBefore: day(2026, 2, 1), NotAfter: day(2029, 2, 1), KeyAlgorithm: "ECDSA P-256",
		RequestedBy: "it-admin"},
	{ID: "c-0114", CommonName: "ocsp.homelab.lan", Preset: "ocsp", CAID: "homelab-issuing",
		NotBefore: day(2026, 9, 1), NotAfter: day(2026, 11, 9), KeyAlgorithm: "ECDSA P-256",
		RequestedBy: "system"},
}

var activity = []Activity{
	{Now.Add(-25 * time.Minute), "acme:traefik", "certificate.issue", "grafana.homelab.lan", "success"},
	{Now.Add(-2 * time.Hour), "it-admin", "system.unseal", "homelab", "success"},
	{Now.Add(-3 * time.Hour), "acme:unknown", "certificate.issue", "nas.example.org", "denied"},
	{Now.Add(-20 * time.Hour), "system", "crl.publish", "homelab-issuing #42", "success"},
	{Now.Add(-26 * time.Hour), "it-admin", "user.login", "it-admin", "success"},
	{Now.Add(-27 * time.Hour), "unknown", "user.login", "admin", "failure"},
	{Now.Add(-41 * 24 * time.Hour), "it-admin", "certificate.revoke", "radius.homelab.lan", "success"},
}

// CAs returns all sample CAs.
func CAs() []CA { return slices.Clone(cas) }

// CAByID returns one CA.
func CAByID(id string) (CA, bool) {
	i := slices.IndexFunc(cas, func(c CA) bool { return c.ID == id })
	if i < 0 {
		return CA{}, false
	}
	return cas[i], true
}

// Certificates returns all sample certificates, newest first.
func Certificates() []Certificate {
	list := slices.Clone(certificates)
	slices.SortStableFunc(list, func(a, b Certificate) int { return b.NotBefore.Compare(a.NotBefore) })
	return list
}

// CertificateByID returns one certificate.
func CertificateByID(id string) (Certificate, bool) {
	i := slices.IndexFunc(certificates, func(c Certificate) bool { return c.ID == id })
	if i < 0 {
		return Certificate{}, false
	}
	return certificates[i], true
}

// RecentActivity returns the activity list, newest first.
func RecentActivity() []Activity { return slices.Clone(activity) }
