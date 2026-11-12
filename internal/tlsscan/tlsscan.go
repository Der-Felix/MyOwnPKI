// Package tlsscan connects to the TLS endpoints an admin entered, reads the
// certificate each one serves and compares it with what this PKI issued for
// the name (docs/PHASE3.md §10) – it finds the renewal that never reached the
// web server.
//
// The remote end is attacker input. A scan is one TCP connection and one TLS
// handshake, then close: no application data, no HTTP request. Trust is
// decided afterwards, against the CAs of this PKI. What is stored is clipped
// metadata of the served leaf – never the DER, a key or a SAN list – and the
// error is a kind from a fixed vocabulary, never what the remote end said.
// Everything works while the server is sealed: nothing is decrypted.
package tlsscan

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Der-Felix/MyOwnPKI/internal/ca"
)

// Sources of an endpoint. Nothing writes SourceAgent yet (docs/PHASE3.md
// §10.3); the value exists so that it needs no table rebuild.
const (
	SourceManual = "manual"
	SourceAgent  = "agent"
)

// Chain states: the served chain, verified against the CAs of this PKI.
const (
	ChainTrusted    = "trusted"    // leaf and the served intermediates lead to a root of this PKI
	ChainIncomplete = "incomplete" // it leads there only with this PKI's own intermediates: the endpoint forgot to send them
	ChainUntrusted  = "untrusted"  // it does not lead to this PKI
)

// Error kinds of a failed scan: a fixed vocabulary. What the remote end said
// is never stored, quoted or logged.
const (
	KindDNS             = "dns"
	KindTimeout         = "timed out"
	KindConnRefused     = "connection refused"
	KindCouldNotConnect = "could not connect"
	KindHandshake       = "TLS handshake failed"
	KindNoCertificate   = "no certificate"
	KindClientCert      = "client certificate required"
	// Refusals are no outage: the page says why.
	KindRefusedPolicy = "refused by the address policy"
	KindRefusedDomain = "no domain covers the host"
	KindRefusedPort   = "port is not in monitor.scan_ports"
)

// IsRefusal reports whether kind is one of the refusals (the endpoint is not
// scanned, which is not an outage).
func IsRefusal(kind string) bool {
	return kind == KindRefusedPolicy || kind == KindRefusedDomain || kind == KindRefusedPort
}

// Counts reports whether a failed scan of this kind counts toward
// scan_unreachable. A refusal does not (nothing was tried); a client
// certificate demand does not either (the service is up and answers).
func Counts(kind string) bool {
	switch kind {
	case KindDNS, KindTimeout, KindConnRefused, KindCouldNotConnect, KindHandshake, KindNoCertificate:
		return true
	}
	return false
}

// Defaults and limits of the scan (docs/PHASE3.md §10.2).
const (
	DefaultWorkers  = 4
	MaxTries        = 4               // addresses tried per scan
	TryTimeout      = 3 * time.Second // each of them
	ChainTimeout    = 5 * time.Second // the database work after a handshake, apart from the scan's own deadline
	DispatchEvery   = 30 * time.Second
	ScanNowEvery    = 60 * time.Second // per endpoint
	MaxIntermediate = 8                // served intermediates that are looked at
	MaxText         = 256              // bytes of a stored subject or issuer
)

// Settings are the monitor.scan_* keys of the configuration that the scan
// itself needs (internal/config.ScanValues).
type Settings struct {
	Interval     time.Duration // 0 = scanning is off
	Timeout      time.Duration
	Ports        []int
	MaxEndpoints int
	Workers      int // 0 = DefaultWorkers
}

// Off reports whether scanning is switched off (monitor.scan_interval: off).
func (s Settings) Off() bool { return s.Interval <= 0 }

func (s Settings) portAllowed(p int) bool {
	for _, a := range s.Ports {
		if a == p {
			return true
		}
	}
	return false
}

// Endpoint is one row of the endpoints table with its last scan.
type Endpoint struct {
	ID, Host    string
	Port        int
	SNI         string // "" = the host
	Source      string
	CreatedAt   time.Time
	CreatedBy   string
	NextScanAt  time.Time
	RequestedAt time.Time // the last "scan now"; zero = never
	LastScanAt  time.Time // zero = never scanned
	LastOKAt    time.Time
	FailStreak  int
	// LastErrorKind and LastError describe the last failed scan, if the
	// last scan failed: a kind of the vocabulary and a fixed short message.
	LastErrorKind, LastError string
	// The served leaf of the last good scan (it stays while scans fail).
	Fingerprint, Serial, Subject, Issuer string
	NotBefore, NotAfter                  time.Time
	ChainLen                             int
	ChainState                           string
	TLSVersion                           string
	SameCount                            int // successful scans in a row that saw Fingerprint
	FingerprintSince                     time.Time
}

// Name is the name the certificate is expected for: the SNI, else the host.
func (e *Endpoint) Name() string {
	if e.SNI != "" {
		return e.SNI
	}
	return e.Host
}

// IsIP reports whether the host is an IP literal.
func (e *Endpoint) IsIP() bool {
	_, err := netip.ParseAddr(e.Host)
	return err == nil
}

// Target is "host:port", IPv6 in brackets.
func (e *Endpoint) Target() string { return net.JoinHostPort(e.Host, strconv.Itoa(e.Port)) }

// Scanned reports whether a scan has run.
func (e *Endpoint) Scanned() bool { return !e.LastScanAt.IsZero() }

// Errors the transports map to their codes.
var (
	ErrNotFound = ca.ErrNotFound
	ErrInvalid  = errors.New("invalid request")
	ErrConflict = errors.New("conflict")
	// ErrOff: scanning is switched off in the configuration.
	ErrOff = fmt.Errorf("%w: scanning is switched off (monitor.scan_interval: off)", ErrConflict)
)

// InvalidError is a refused input. It names the field and the rule, never an
// address that was resolved.
type InvalidError struct{ Field, Rule string }

func (e *InvalidError) Error() string { return e.Field + ": " + e.Rule }

// Is makes errors.Is(err, ErrInvalid) true.
func (e *InvalidError) Is(target error) bool { return target == ErrInvalid }

// WaitError refuses a scan that comes too soon after the previous request for
// the same endpoint.
type WaitError struct{ RetryAfter time.Duration }

func (e *WaitError) Error() string {
	return fmt.Sprintf("this endpoint was scanned on request a moment ago – try again in %d seconds", int(e.RetryAfter.Seconds())+1)
}

// clean returns s as stored text: valid UTF-8, control, format and line
// separator characters replaced, at most limit bytes (cut at a character).
func clean(s string, limit int) string {
	s = strings.ToValidUTF8(s, "?")
	var b strings.Builder
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r) {
			r = '?'
		}
		if b.Len()+utf8.RuneLen(r) > limit {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}
