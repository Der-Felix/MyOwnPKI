package agent

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/miekg/dns"
)

// The RFC 2136 provider is the agent's own, on github.com/miekg/dns
// (docs/PHASE3.md §13.2): lego's provider would bring a Kerberos stack for a
// feature (GSS-TSIG) this release does not offer.
//
// One UPDATE message per Present and per CleanUp, over TCP (a signed update
// has no business on UDP), signed with a TSIG key from the credentials file.
// A success needs an answer whose own TSIG verifies: an unsigned "all good"
// from somebody in the path is not accepted.

const (
	rfc2136Timeout = 10 * time.Second
	tsigFudge      = 300 // seconds, the BIND default
)

// rfc2136Provider writes and removes the challenge TXT record.
type rfc2136Provider struct {
	nameserver string // host:port
	zone       string // fully qualified, or "" to look it up
	ttl        uint32
	creds      *dnsCredentials
	key        tsigKey
	timeout    time.Duration
	now        func() time.Time

	pollTimeout, pollInterval time.Duration

	mu    sync.Mutex
	ctx   context.Context //nolint:containedctx // set per phase by the guard, see dnsContextBinder
	zones map[string]string
}

var (
	_ dnsProvider          = (*rfc2136Provider)(nil)
	_ dnsContextBinder     = (*rfc2136Provider)(nil)
	_ dnsCredentialsHolder = (*rfc2136Provider)(nil)
)

func newRFC2136Provider(cfg DNSProvider, creds *dnsCredentials, now func() time.Time) (*rfc2136Provider, error) {
	alg, ok := tsigAlgorithmName(creds.TSIGAlgorithm)
	if !ok {
		return nil, errors.New("rfc2136: unsupported TSIG algorithm")
	}
	ns := cfg.Nameserver
	if _, _, err := net.SplitHostPort(ns); err != nil {
		ns = net.JoinHostPort(strings.Trim(ns, "[]"), "53")
	}
	p := &rfc2136Provider{
		nameserver: ns, ttl: uint32(cfg.TTL), // #nosec G115 -- validated: 30 to 3600
		creds:   creds,
		key:     tsigKey{name: dns.CanonicalName(creds.TSIGKeyName), algorithm: alg, secret: creds.TSIGSecret},
		timeout: rfc2136Timeout, now: now,
		pollTimeout:  time.Duration(cfg.PropagationTimeout) * time.Second,
		pollInterval: dns01.DefaultPollingInterval,
		ctx:          context.Background(),
		zones:        map[string]string{},
	}
	if cfg.Zone != "" {
		p.zone = dns.Fqdn(cfg.Zone)
	}
	return p, nil
}

func (p *rfc2136Provider) dnsCreds() *dnsCredentials { return p.creds }

func (p *rfc2136Provider) useContext(ctx context.Context) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.ctx = ctx
}

func (p *rfc2136Provider) context() context.Context {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.ctx
}

// Timeout is lego's propagation timeout and polling interval; the guard
// overrides it with the configured values.
func (p *rfc2136Provider) Timeout() (time.Duration, time.Duration) {
	return p.pollTimeout, p.pollInterval
}

// Present adds the TXT record; an identical record is kept once, so a second
// call is harmless.
func (p *rfc2136Provider) Present(domain, _, keyAuth string) error {
	err := p.update(domain, keyAuth, true)
	return p.creds.redact(err)
}

// CleanUp removes exactly this run's value (RFC 2136 §2.5.4); other values of
// the same name stay. Removing a value that is not there succeeds.
func (p *rfc2136Provider) CleanUp(domain, _, keyAuth string) error {
	err := p.update(domain, keyAuth, false)
	return p.creds.redact(err)
}

func (p *rfc2136Provider) update(domain, keyAuth string, add bool) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)
	fqdn := dns.CanonicalName(info.EffectiveFQDN)
	zone, err := p.zoneFor(fqdn)
	if err != nil {
		return fmt.Errorf("rfc2136: %w", err)
	}
	rr := &dns.TXT{Hdr: dns.RR_Header{Name: fqdn, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: p.ttl}, Txt: []string{info.Value}}
	m := new(dns.Msg)
	m.SetUpdate(zone)
	what := "adding"
	if add {
		m.Insert([]dns.RR{rr})
	} else {
		m.Remove([]dns.RR{rr})
		what = "removing"
	}
	m.SetTsig(p.key.name, p.key.algorithm, tsigFudge, p.now().Unix())
	r, err := p.exchange(m, true)
	if err != nil {
		return fmt.Errorf("rfc2136: %s the TXT record at %s: %w", what, p.nameserver, err)
	}
	if r.Rcode != dns.RcodeSuccess {
		return fmt.Errorf("rfc2136: %s the TXT record: %s", what, p.rcodeProblem(r))
	}
	return nil
}

// rcodeProblem explains a refusal in operations terms.
func (p *rfc2136Provider) rcodeProblem(r *dns.Msg) string {
	name := dns.RcodeToString[r.Rcode]
	signed := r.IsTsig() != nil
	switch r.Rcode {
	case dns.RcodeNotAuth:
		if !signed {
			return name + " from " + p.nameserver + ": the server does not accept the TSIG key or its secret, or is not authoritative for the zone"
		}
		return name + " from " + p.nameserver + ": the server is not authoritative for the zone"
	case dns.RcodeRefused:
		return name + " from " + p.nameserver + ": the server refuses this key to change this name (check its update policy and allow-update)"
	case dns.RcodeNotZone:
		return name + " from " + p.nameserver + ": the name is not inside the zone being updated"
	default:
		return name + " from " + p.nameserver
	}
}

// zoneFor returns the zone to update: zone from the configuration (which must
// contain the name), else the nearest ancestor for which the nameserver
// answers with its SOA record.
func (p *rfc2136Provider) zoneFor(fqdn string) (string, error) {
	if p.zone != "" {
		if !dns.IsSubDomain(p.zone, fqdn) {
			return "", fmt.Errorf("zone mismatch: %s is not inside the configured zone %s (with a CNAME delegation of _acme-challenge, leave zone unset so that the target's zone is found)",
				strings.TrimSuffix(fqdn, "."), strings.TrimSuffix(p.zone, "."))
		}
		return p.zone, nil
	}
	p.mu.Lock()
	z, ok := p.zones[fqdn]
	p.mu.Unlock()
	if ok {
		return z, nil
	}
	var last string
	for _, i := range dns.Split(fqdn) {
		name := fqdn[i:]
		q := new(dns.Msg)
		q.SetQuestion(name, dns.TypeSOA)
		r, err := p.exchange(q, false)
		if err != nil {
			return "", fmt.Errorf("zone lookup at %s: %w", p.nameserver, err)
		}
		last = dns.RcodeToString[r.Rcode]
		if r.Rcode != dns.RcodeSuccess {
			continue
		}
		for _, rr := range r.Answer {
			if soa, ok := rr.(*dns.SOA); ok && dns.CanonicalName(soa.Hdr.Name) == name {
				p.mu.Lock()
				p.zones[fqdn] = name
				p.mu.Unlock()
				return name, nil
			}
		}
	}
	return "", fmt.Errorf("zone lookup: %s has no SOA record for %s or a parent (last answer %s); is it authoritative? set zone to skip the lookup",
		p.nameserver, strings.TrimSuffix(fqdn, "."), last)
}

// exchange sends one message over TCP. A signed exchange accepts only an
// answer whose TSIG verifies; a refusal the server sends unsigned (a key it
// does not know) comes back as an ordinary answer with its response code, and
// the caller must not treat that as success.
func (p *rfc2136Provider) exchange(m *dns.Msg, signed bool) (*dns.Msg, error) {
	ctx, cancel := context.WithTimeout(p.context(), p.timeout)
	defer cancel()
	c := &dns.Client{Net: "tcp", Timeout: p.timeout}
	if signed {
		c.TsigProvider = p.key
	}
	conn, err := c.DialContext(ctx, p.nameserver)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	// miekg honors the deadline of ctx but not its cancellation: closing the
	// connection ends a read at once when the issuance is canceled.
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	r, _, err := c.ExchangeWithConnContext(ctx, m, conn)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		switch {
		case errors.Is(err, dns.ErrSig):
			return nil, errors.New("the answer's TSIG signature is wrong: not from the server that holds this key, or the secret differs")
		case errors.Is(err, dns.ErrSecret):
			return nil, errors.New("the answer is signed with a key that is not this one")
		case errors.Is(err, dns.ErrTime):
			return nil, errors.New("the answer's TSIG time differs too much from this host's clock; check NTP")
		case errors.Is(err, dns.ErrKeyAlg):
			return nil, errors.New("the answer's TSIG algorithm is not the configured one")
		}
		return nil, err
	}
	if !signed {
		return r, nil
	}
	t := r.IsTsig()
	if r.Rcode == dns.RcodeSuccess {
		if t == nil {
			return nil, errors.New("the answer is not signed (TSIG record missing); a success is not accepted without it")
		}
		if dns.CanonicalName(t.Hdr.Name) != p.key.name || t.Error != dns.RcodeSuccess {
			return nil, errors.New("the answer's TSIG record does not match the request")
		}
	}
	return r, nil
}

// tsigKey signs and verifies with one key. It replaces miekg's secret map to
// keep the base64 text in the wipeable secret (a map would copy it into a
// string), to fix the algorithm (a signed answer may not downgrade to
// hmac-sha1) and to compare key names case-insensitively.
type tsigKey struct {
	name      string // canonical
	algorithm string // canonical, with the trailing dot
	secret    secret // base64
}

func tsigAlgorithmName(alg string) (string, bool) {
	switch alg {
	case "hmac-sha256":
		return dns.HmacSHA256, true
	case "hmac-sha384":
		return dns.HmacSHA384, true
	case "hmac-sha512":
		return dns.HmacSHA512, true
	}
	return "", false
}

func (k tsigKey) mac(msg []byte, alg string) ([]byte, error) {
	if dns.CanonicalName(alg) != k.algorithm {
		return nil, dns.ErrKeyAlg
	}
	var h func() hash.Hash
	switch k.algorithm {
	case dns.HmacSHA256:
		h = sha256.New
	case dns.HmacSHA384:
		h = sha512.New384
	case dns.HmacSHA512:
		h = sha512.New
	default:
		return nil, dns.ErrKeyAlg
	}
	// A copy: the guard may wipe the secret while this runs in the goroutine of
	// a CleanUp that timed out.
	text := k.secret.snapshot()
	defer clear(text)
	raw := make([]byte, base64.StdEncoding.DecodedLen(len(text)))
	defer clear(raw)
	n, err := base64.StdEncoding.Decode(raw, text)
	if err != nil || n == 0 {
		return nil, dns.ErrSecret
	}
	m := hmac.New(h, raw[:n])
	m.Write(msg)
	return m.Sum(nil), nil
}

// Generate implements dns.TsigProvider.
func (k tsigKey) Generate(msg []byte, t *dns.TSIG) ([]byte, error) {
	if dns.CanonicalName(t.Hdr.Name) != k.name {
		return nil, dns.ErrSecret
	}
	return k.mac(msg, t.Algorithm)
}

// Verify implements dns.TsigProvider.
func (k tsigKey) Verify(msg []byte, t *dns.TSIG) error {
	if dns.CanonicalName(t.Hdr.Name) != k.name {
		return dns.ErrSecret
	}
	want, err := k.mac(msg, t.Algorithm)
	if err != nil {
		return err
	}
	got, err := hex.DecodeString(t.MAC)
	if err != nil {
		return dns.ErrSig
	}
	if !hmac.Equal(want, got) {
		return dns.ErrSig
	}
	return nil
}
