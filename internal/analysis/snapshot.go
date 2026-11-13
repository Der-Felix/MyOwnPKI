package analysis

import (
	"crypto/x509"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/ca"
)

// Snapshot is what the server knows at one moment, as plain values. The rules
// read nothing else, and never the clock: Now is the time of the snapshot.
//
// Every name in it (certificate names, host names, versions) is attacker
// input and stays a raw string; see the package comment.
type Snapshot struct {
	Now time.Time
	// ServerVersion is the running version; "dev" for a development build.
	ServerVersion string

	// Certificates are the valid end-entity certificates, whatever their
	// source (agent identity certificates are left out).
	Certificates []Certificate
	// Recent are the certificates created within RecentWindow of Now, valid
	// or not: a revoked or expired one still counts as something a client got.
	Recent []Certificate
	// Names are the DNS names and IPs of every certificate of the tenant,
	// whatever its status.
	Names []ca.CertName

	CAs     []CA
	Domains []ca.Domain
	// Accounts are the ACME accounts that were read, newest first. If there
	// are more than the engine reads, AccountsLimit is how many it did read and
	// the older accounts are not in the list; 0 = every account is.
	Accounts      []Account
	AccountsLimit int
	Agents        []Agent
	Endpoints     []Endpoint

	// Missing says why a section is not there ("" = it is).
	Missing Missing
}

// RecentWindow is how far back Snapshot.Recent reaches.
const RecentWindow = 7 * 24 * time.Hour

// Missing names the input a rule cannot do without, when Load could not get
// it. A rule that depends on it answers "unknown" with this reason.
type Missing struct {
	// Agents: the agent listener is off, so there is no agent data.
	Agents string
	// Scan: the TLS scan is off, so no endpoint was scanned.
	Scan string
}

// Certificate is an end-entity certificate of the tenant.
type Certificate struct {
	ID, Serial, Fingerprint string
	// Source is the certificates.source column: issued, imported or external.
	Source string
	CAID   string
	CAName string
	// DNSNames and IPs are the names; CommonName is used when there are none.
	DNSNames, IPs []string
	CommonName    string
	// Class and IssuerKey say who issued it (ca.SourceUI, ca.SourceACME,
	// ca.SourceAgent; "ui", "acme:<account>", "agent:<id>"). Both are "" for
	// an imported or external certificate, and for an issued one whose origin
	// could not be read.
	Class, IssuerKey               string
	NotBefore, NotAfter, CreatedAt time.Time
	// Traits is nil when the DER could not be parsed.
	Traits *ca.Traits
}

// CA is a certificate authority of the tenant.
type CA struct {
	ID, Name string
	// Issuing: active, with a key that is not offline, so it signs
	// end-entity certificates.
	Issuing bool
	// MaxValidityDays caps the validity of the leaves the CA issues; the
	// engine shortens a longer default to it. 0 = not known, no cap assumed.
	MaxValidityDays int
	Generations     []Generation
}

// Generation is one key and certificate of a CA.
type Generation struct {
	Number  int64
	Current bool
	// Signed: the certificate exists (a pending generation has none).
	Signed  bool
	Revoked bool
	// Intermediate: the CA certificate has an issuer; a root signs itself.
	Intermediate bool
	NotAfter     time.Time
	Signature    x509.SignatureAlgorithm
}

// Agent is an enrolled agent with its deployments.
type Agent struct {
	ID, Hostname, Version string
	// Status is active, disabled or revoked.
	Status      string
	Deployments []Deployment
}

// Deployment is a certificate an agent keeps on its host.
type Deployment struct {
	Name, State, Serial, CertificateID, Fingerprint string
	Removed                                         bool
}

// Endpoint is a TLS endpoint the scan visits, with its last scan.
type Endpoint struct {
	ID, Host string
	Port     int
	// Name is the name the certificate is expected for (SNI, else the host).
	Name string
	// LastOKAt is the last successful scan; zero = never. Fingerprint is the
	// leaf it served then (it stays while later scans fail) and
	// FingerprintSince the first successful scan that saw it.
	LastOKAt         time.Time
	Fingerprint      string
	FingerprintSince time.Time
}

// Account is an ACME account with its last order.
type Account struct {
	ID, Status  string
	AgentLinked bool
	CreatedAt   time.Time
	// LastOrderAt is zero when the account never ordered.
	LastOrderAt time.Time
}
