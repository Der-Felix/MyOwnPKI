// Package dnsserver is an in-process DNS server for tests: an authoritative
// server with a small zone store, RFC 2136 UPDATE with TSIG, and a log of
// every message it received. It is imported by tests only; it listens on
// 127.0.0.1 with random ports, needs no privileges and runs the same on
// Linux, macOS and Windows.
//
// The Store is what the tests of the agent and of the ACME server share: the
// agent writes TXT records into it through RFC 2136 (or through the Cloudflare
// stub of this package), and the ACME server reads them through this server
// as its resolver.
package dnsserver

import (
	"slices"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

// ChallengeLabel is the first label of every dns-01 record name.
const ChallengeLabel = "_acme-challenge."

// Store holds the zones and records of the test server. It is safe for
// concurrent use. Names are compared in canonical form (lower case, fully
// qualified), so callers may pass "Host.Example.lan" or "host.example.lan.".
type Store struct {
	mu    sync.Mutex
	zones []string
	txt   map[string][]string
	cname map[string]string
	// serial grows with every change, like a real zone's SOA serial.
	serial uint32
}

// NewStore returns a store that is authoritative for the given zones.
func NewStore(zones ...string) *Store {
	s := &Store{txt: map[string][]string{}, cname: map[string]string{}, serial: 1}
	for _, z := range zones {
		s.AddZone(z)
	}
	return s
}

func canon(name string) string { return dns.CanonicalName(name) }

// AddZone makes the store authoritative for a zone.
func (s *Store) AddZone(zone string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	z := canon(zone)
	if !slices.Contains(s.zones, z) {
		s.zones = append(s.zones, z)
	}
}

// Zones returns the zones the store is authoritative for.
func (s *Store) Zones() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.zones)
}

// ZoneOf returns the longest zone that contains name.
func (s *Store) ZoneOf(name string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.zoneOf(canon(name))
}

func (s *Store) zoneOf(name string) (string, bool) {
	best := ""
	for _, z := range s.zones {
		if dns.IsSubDomain(z, name) && len(z) > len(best) {
			best = z
		}
	}
	return best, best != ""
}

// Serial is the current SOA serial.
func (s *Store) Serial() uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.serial
}

// AddTXT adds a TXT value; an identical value is kept once (RFC 2136 §2.5.1).
func (s *Store) AddTXT(name, value string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := canon(name)
	if !slices.Contains(s.txt[n], value) {
		s.txt[n] = append(s.txt[n], value)
		s.serial++
	}
}

// DeleteTXT removes one value (RFC 2136 §2.5.4) and reports whether it existed.
func (s *Store) DeleteTXT(name, value string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := canon(name)
	i := slices.Index(s.txt[n], value)
	if i < 0 {
		return false
	}
	s.txt[n] = slices.Delete(s.txt[n], i, i+1)
	if len(s.txt[n]) == 0 {
		delete(s.txt, n)
	}
	s.serial++
	return true
}

// DeleteTXTSet removes all TXT values of a name (RFC 2136 §2.5.2).
func (s *Store) DeleteTXTSet(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n := canon(name); len(s.txt[n]) > 0 {
		delete(s.txt, n)
		s.serial++
	}
}

// TXT returns the values of a name.
func (s *Store) TXT(name string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.txt[canon(name)])
}

// SetCNAME makes name an alias of target (CNAME delegation of
// _acme-challenge). An empty target removes the alias.
func (s *Store) SetCNAME(name, target string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if target == "" {
		delete(s.cname, canon(name))
	} else {
		s.cname[canon(name)] = canon(target)
	}
	s.serial++
}

// CNAME returns the target of an alias.
func (s *Store) CNAME(name string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.cname[canon(name)]
	return t, ok
}

// Record is one TXT value at one name.
type Record struct{ Name, Value string }

// ChallengeRecords returns every TXT record whose name starts with
// _acme-challenge., sorted. A test that ends with an empty result proves the
// agent cleaned up.
func (s *Store) ChallengeRecords() []Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Record
	for name, values := range s.txt {
		if strings.HasPrefix(name, ChallengeLabel) {
			for _, v := range values {
				out = append(out, Record{name, v})
			}
		}
	}
	slices.SortFunc(out, func(a, b Record) int {
		if c := strings.Compare(a.Name, b.Name); c != 0 {
			return c
		}
		return strings.Compare(a.Value, b.Value)
	})
	return out
}

// exists reports whether any record lives at name (for NXDOMAIN versus NODATA).
func (s *Store) exists(name string) bool {
	if len(s.txt[name]) > 0 {
		return true
	}
	_, ok := s.cname[name]
	return ok
}

// HasName reports whether any record lives at name.
func (s *Store) HasName(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.exists(canon(name))
}
