package dnsserver

import (
	"context"
	"encoding/hex"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/Der-Felix/MyOwnPKI/internal/clock"
)

// Key is a TSIG key the server accepts for UPDATE.
type Key struct {
	// Name is the key name, e.g. "acme-agent".
	Name string
	// Secret is the base64 secret, as in BIND's key statement.
	Secret string
	// Algorithm is "hmac-sha256" (default), "hmac-sha384" or "hmac-sha512".
	Algorithm string
	// Allow limits the names this key may change (BIND's update-policy). Nil
	// allows every name in the zone. A refused name makes the whole UPDATE
	// REFUSED.
	Allow func(name string) bool
}

// Message is one request the server received.
type Message struct {
	Network string // "udp" or "tcp"
	Opcode  string // "QUERY" or "UPDATE"
	Name    string // the question name, or the zone of an UPDATE
	Type    string // the question type
	Rcode   string // the answer's response code
	Signed  bool   // the request carried a TSIG record
	TSIGOK  bool   // ... and it verified
	Updates int    // records in the update section
}

// Server is the running test server.
type Server struct {
	// Store holds the zones; tests read and write it directly.
	Store *Store

	addr string
	keys map[string]*Key

	mu     sync.Mutex
	log    []Message
	hidden func(name, value string) bool
	forged atomic.Bool
	now    func() time.Time
}

// Start runs a server on 127.0.0.1 (the same random port for UDP and TCP)
// until the test ends. Without keys, UPDATE needs no signature.
func Start(tb testing.TB, store *Store, keys ...Key) *Server {
	tb.Helper()
	s := &Server{Store: store, keys: map[string]*Key{}, now: clock.System{}.Now}
	secrets := map[string]string{}
	for i := range keys {
		k := keys[i]
		if k.Algorithm == "" {
			k.Algorithm = "hmac-sha256"
		}
		s.keys[canon(k.Name)] = &k
		secrets[canon(k.Name)] = k.Secret
	}
	var lc net.ListenConfig
	var (
		l   net.Listener
		pc  net.PacketConn
		err error
	)
	// The same number for UDP and TCP: lego and the agent use host:port for both.
	for range 20 {
		if l, err = lc.Listen(context.Background(), "tcp", "127.0.0.1:0"); err != nil {
			tb.Fatalf("dnsserver: %v", err)
		}
		if pc, err = lc.ListenPacket(context.Background(), "udp", l.Addr().String()); err == nil {
			break
		}
		_ = l.Close()
	}
	if err != nil {
		tb.Fatalf("dnsserver: no port free for UDP and TCP: %v", err)
	}
	s.addr = l.Addr().String()
	handler := dns.HandlerFunc(s.serve)
	started := make(chan struct{}, 2)
	notify := func() { started <- struct{}{} }
	tcp := &dns.Server{Listener: l, Handler: handler, TsigSecret: secrets, NotifyStartedFunc: notify, MsgAcceptFunc: acceptUpdates, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second}
	udp := &dns.Server{PacketConn: pc, Handler: handler, TsigSecret: secrets, NotifyStartedFunc: notify, MsgAcceptFunc: acceptUpdates, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second}
	go func() { _ = tcp.ActivateAndServe() }()
	go func() { _ = udp.ActivateAndServe() }()
	for range 2 {
		select {
		case <-started:
		case <-time.After(10 * time.Second):
			tb.Fatal("dnsserver: did not start")
		}
	}
	tb.Cleanup(func() {
		_ = tcp.Shutdown()
		_ = udp.Shutdown()
	})
	return s
}

// Addr is host:port of the server (UDP and TCP).
func (s *Server) Addr() string { return s.addr }

// Host is the IP address of the server.
func (s *Server) Host() string {
	host, _, _ := net.SplitHostPort(s.addr)
	return host
}

// Messages returns a copy of the log.
func (s *Server) Messages() []Message {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Message(nil), s.log...)
}

// Updates counts the UPDATE messages that were applied.
func (s *Server) Updates() int {
	n := 0
	for _, m := range s.Messages() {
		if m.Opcode == "UPDATE" && m.Rcode == "NOERROR" {
			n++
		}
	}
	return n
}

// Queries returns the QUERY messages for a name and type ("" = any).
func (s *Server) Queries(name, qtype string) []Message {
	var out []Message
	for _, m := range s.Messages() {
		if m.Opcode == "QUERY" && (name == "" || m.Name == canon(name)) && (qtype == "" || m.Type == qtype) {
			out = append(out, m)
		}
	}
	return out
}

// HideTXT makes TXT answers skip the records the function selects, while an
// UPDATE still stores them: the record "never appears" for a checker but
// does exist, so a test can still see whether it was cleaned up. Nil shows
// everything again.
func (s *Server) HideTXT(f func(name, value string) bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hidden = f
}

// ForgeResponseMAC makes every signed answer carry a wrong MAC.
func (s *Server) ForgeResponseMAC(on bool) { s.forged.Store(on) }

func (s *Server) record(m Message) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.log = append(s.log, m)
}

func network(w dns.ResponseWriter) string {
	if _, ok := w.LocalAddr().(*net.TCPAddr); ok {
		return "tcp"
	}
	return "udp"
}

// acceptUpdates is miekg's default accept function with UPDATE allowed (the
// default refuses it, because an update carries many records).
func acceptUpdates(dh dns.Header) dns.MsgAcceptAction {
	if dh.Bits&(1<<15) != 0 { // a response
		return dns.MsgIgnore
	}
	opcode := int(dh.Bits>>11) & 0xF
	if opcode != dns.OpcodeQuery && opcode != dns.OpcodeUpdate {
		return dns.MsgRejectNotImplemented
	}
	if dh.Qdcount != 1 {
		return dns.MsgReject
	}
	if dh.Ancount > 50 || dh.Nscount > 50 || dh.Arcount > 50 {
		return dns.MsgReject
	}
	return dns.MsgAccept
}

func (s *Server) serve(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	logged := Message{Network: network(w), Opcode: dns.OpcodeToString[r.Opcode]}
	if len(r.Question) > 0 {
		logged.Name, logged.Type = canon(r.Question[0].Name), dns.TypeToString[r.Question[0].Qtype]
	}
	tsig := r.IsTsig()
	logged.Signed = tsig != nil
	logged.TSIGOK = tsig != nil && w.TsigStatus() == nil
	logged.Updates = len(r.Ns)
	switch {
	case len(r.Question) != 1:
		m.Rcode = dns.RcodeFormatError
	case r.Opcode == dns.OpcodeQuery:
		s.query(m, r.Question[0])
	case r.Opcode == dns.OpcodeUpdate:
		s.update(m, r, tsig, w.TsigStatus())
	default:
		m.Rcode = dns.RcodeNotImplemented
	}
	logged.Rcode = dns.RcodeToString[m.Rcode]
	s.record(logged)

	// Sign the answer only when the request's signature was valid (BIND
	// answers a bad signature unsigned, with a TSIG error).
	if tsig != nil && w.TsigStatus() == nil {
		if s.forged.Load() {
			forged := &dns.TSIG{
				Hdr:        dns.RR_Header{Name: tsig.Hdr.Name, Rrtype: dns.TypeTSIG, Class: dns.ClassANY},
				Algorithm:  tsig.Algorithm,
				TimeSigned: uint64(s.now().Unix()), // #nosec G115 -- the clock is after 1970
				Fudge:      300,
				MACSize:    32,
				MAC:        hex.EncodeToString(make([]byte, 32)),
				OrigId:     r.Id,
			}
			m.Extra = append(m.Extra, forged)
			if buf, err := m.Pack(); err == nil {
				_, _ = w.Write(buf)
			}
			return
		}
		m.SetTsig(tsig.Hdr.Name, tsig.Algorithm, 300, s.now().Unix())
	}
	_ = w.WriteMsg(m)
}

func (s *Server) query(m *dns.Msg, q dns.Question) {
	name := canon(q.Name)
	zone, ok := s.Store.ZoneOf(name)
	if !ok {
		m.Rcode = dns.RcodeRefused
		return
	}
	m.Authoritative, m.RecursionAvailable = true, true
	// Follow aliases inside the store, like a resolver would: the ACME server
	// reads the target's TXT through this server.
	cur := name
	for range 8 {
		target, isAlias := s.Store.CNAME(cur)
		if !isAlias || q.Qtype == dns.TypeCNAME {
			break
		}
		m.Answer = append(m.Answer, &dns.CNAME{Hdr: hdr(cur, dns.TypeCNAME), Target: target})
		cur = target
	}
	switch q.Qtype {
	case dns.TypeSOA:
		if cur == zone {
			m.Answer = append(m.Answer, s.soa(zone))
		}
	case dns.TypeTXT:
		for _, v := range s.Store.TXT(cur) {
			if s.isHidden(cur, v) {
				continue
			}
			m.Answer = append(m.Answer, &dns.TXT{Hdr: hdr(cur, dns.TypeTXT), Txt: []string{v}})
		}
	case dns.TypeCNAME:
		if target, isAlias := s.Store.CNAME(cur); isAlias {
			m.Answer = append(m.Answer, &dns.CNAME{Hdr: hdr(cur, dns.TypeCNAME), Target: target})
		}
	}
	if len(m.Answer) == 0 {
		m.Ns = append(m.Ns, s.soa(zone))
		if cur != zone && !s.Store.HasName(cur) {
			m.Rcode = dns.RcodeNameError
		}
	}
}

func (s *Server) isHidden(name, value string) bool {
	s.mu.Lock()
	f := s.hidden
	s.mu.Unlock()
	return f != nil && f(name, value)
}

func hdr(name string, rrtype uint16) dns.RR_Header {
	return dns.RR_Header{Name: name, Rrtype: rrtype, Class: dns.ClassINET, Ttl: 60}
}

func (s *Server) soa(zone string) dns.RR {
	return &dns.SOA{Hdr: hdr(zone, dns.TypeSOA), Ns: "ns1." + zone, Mbox: "hostmaster." + zone,
		Serial: s.Store.Serial(), Refresh: 3600, Retry: 600, Expire: 86400, Minttl: 60}
}

// update applies an RFC 2136 UPDATE. Prerequisites are not supported.
func (s *Server) update(m, r *dns.Msg, tsig *dns.TSIG, status error) {
	q := r.Question[0]
	zone := canon(q.Name)
	if q.Qtype != dns.TypeSOA || q.Qclass != dns.ClassINET {
		m.Rcode = dns.RcodeFormatError
		return
	}
	var key *Key
	if len(s.keys) > 0 {
		switch {
		case tsig == nil:
			m.Rcode = dns.RcodeRefused
			return
		case status != nil:
			m.Rcode = dns.RcodeNotAuth // BADKEY, BADSIG, BADTIME: BIND answers NOTAUTH
			return
		}
		key = s.keys[canon(tsig.Hdr.Name)]
	}
	if z, ok := s.Store.ZoneOf(zone); !ok || z != zone {
		m.Rcode = dns.RcodeNotAuth
		return
	}
	if len(r.Answer) > 0 {
		m.Rcode = dns.RcodeNotImplemented
		return
	}
	for _, rr := range r.Ns {
		name := canon(rr.Header().Name)
		if !dns.IsSubDomain(zone, name) {
			m.Rcode = dns.RcodeNotZone
			return
		}
		if key != nil && key.Allow != nil && !key.Allow(name) {
			m.Rcode = dns.RcodeRefused
			return
		}
	}
	for _, rr := range r.Ns {
		s.apply(rr)
	}
}

func (s *Server) apply(rr dns.RR) {
	h := rr.Header()
	name := canon(h.Name)
	switch h.Class {
	case dns.ClassINET:
		switch v := rr.(type) {
		case *dns.TXT:
			s.Store.AddTXT(name, joinTXT(v.Txt))
		case *dns.CNAME:
			s.Store.SetCNAME(name, v.Target)
		}
	case dns.ClassNONE: // delete this record
		if v, ok := rr.(*dns.TXT); ok {
			s.Store.DeleteTXT(name, joinTXT(v.Txt))
		}
	case dns.ClassANY: // delete the RRset
		if h.Rrtype == dns.TypeTXT || h.Rrtype == dns.TypeANY {
			s.Store.DeleteTXTSet(name)
		}
	}
}

func joinTXT(parts []string) string {
	out := ""
	for _, p := range parts {
		out += p
	}
	return out
}
