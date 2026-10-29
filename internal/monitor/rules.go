// Package monitor finds what needs an admin – expiring certificates, CA
// certificates and CRLs, a sealed server, silent agents, failed deployments –
// keeps it as alerts in system.db and (step 23) tells someone about it
// (docs/PHASE3.md §9). Everything here works while the server is sealed:
// it reads pki.db and the keyring state and decrypts nothing.
package monitor

import (
	"time"
)

// Severities of an alert.
const (
	Warning  = "warning"
	Critical = "critical"
)

// Kinds of alerts (docs/PHASE3.md §9.2).
const (
	KindCertExpiry       = "cert_expiry"
	KindCAExpiry         = "ca_expiry"
	KindCRL              = "crl"
	KindSealed           = "sealed"
	KindAgentSilent      = "agent_silent"
	KindAgentCertificate = "agent_certificate"
	KindDeployFailed     = "deploy_failed"
)

// Rules are the thresholds of the evaluation (configuration `monitor:`).
type Rules struct {
	// End-entity certificates: warning and critical before they expire.
	ExpiryWarn, ExpiryCrit time.Duration
	// CA certificates.
	CAWarn, CACrit time.Duration
	// A sealed server: warning after SealedAfter; critical once a CRL's
	// next update is closer than CRLHorizon (a sealed server can't sign).
	SealedAfter, CRLHorizon time.Duration
	// Agents: warning and critical after this long without a report.
	AgentSilentWarn, AgentSilentCrit time.Duration
	// An active agent's own certificate: critical below this.
	AgentCertificate time.Duration
	// ExpiredFor: an expired, not superseded certificate stays an alert this
	// long after its end, then the alert is closed.
	ExpiredFor time.Duration
	// RepeatEvery: a reminder for an open alert (step 23).
	RepeatEvery time.Duration
}

// DefaultRules are the owner-approved defaults (Q7, 2026-10-29).
func DefaultRules() Rules {
	return Rules{
		ExpiryWarn: 14 * day, ExpiryCrit: 3 * day,
		CAWarn: 90 * day, CACrit: 30 * day,
		SealedAfter: 10 * time.Minute, CRLHorizon: 24 * time.Hour,
		AgentSilentWarn: time.Hour, AgentSilentCrit: 24 * time.Hour,
		AgentCertificate: 48 * time.Hour,
		ExpiredFor:       30 * day,
		RepeatEvery:      24 * time.Hour,
	}
}

const day = 24 * time.Hour
