// Command stubdns is a tiny DNS server for the upgrade test (PHASE3 §19.5): it
// answers A queries for one zone with one address, so an old MyOwnPKI server
// (acme.resolver) finds the test names without /etc/hosts and without root.
// It is a test tool: it never recurses, never forwards and never logs a query.
//
//	stubdns --listen 127.0.0.1:5353 --zone upgrade.lan --ip 192.0.2.10
//
// Every name at or below the zone gets the address (TTL 1 second); AAAA and
// every other type of such a name is an empty answer (NODATA, so a client does
// not wait for an IPv6 address); a name outside the zone is REFUSED.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/miekg/dns"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("stubdns", flag.ContinueOnError)
	fs.SetOutput(stderr)
	listen := fs.String("listen", "127.0.0.1:5353", "host:port for UDP and TCP")
	zone := fs.String("zone", "", "the zone to answer for, e.g. upgrade.lan")
	ip := fs.String("ip", "", "the IPv4 address every name of the zone resolves to")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	addr, err := netip.ParseAddr(*ip)
	if err != nil || !addr.Is4() || *zone == "" {
		_, _ = fmt.Fprintln(stderr, "stubdns: need --zone NAME and --ip IPV4")
		return 2
	}
	srv, err := start(*listen, *zone, addr)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "stubdns: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "stubdns: %s answers *.%s with %s\n", srv.addr, strings.Trim(*zone, "."), addr)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	srv.close()
	return 0
}

// server is the running pair of listeners.
type server struct {
	addr string
	udp  *dns.Server
	tcp  *dns.Server
}

// start opens UDP and TCP on the same port (port 0 searches a port that is free
// for both) and serves until close.
func start(listen, zone string, ip netip.Addr) (*server, error) {
	host, portText, err := net.SplitHostPort(listen)
	if err != nil {
		return nil, fmt.Errorf("--listen %q: %w", listen, err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 0 || port > 65535 {
		return nil, fmt.Errorf("--listen %q: not a port", listen)
	}
	attempts := 1
	if port == 0 {
		attempts = 50
	}
	var lc net.ListenConfig
	var lastErr error
	for range attempts {
		l, err := lc.Listen(context.Background(), "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
		if err != nil {
			lastErr = err
			continue
		}
		pc, err := lc.ListenPacket(context.Background(), "udp", l.Addr().String())
		if err != nil {
			_ = l.Close()
			lastErr = err
			continue
		}
		h := handler(zone, ip)
		s := &server{
			addr: l.Addr().String(),
			udp:  &dns.Server{PacketConn: pc, Handler: h},
			tcp:  &dns.Server{Listener: l, Handler: h},
		}
		started := make(chan struct{}, 2)
		s.udp.NotifyStartedFunc = func() { started <- struct{}{} }
		s.tcp.NotifyStartedFunc = func() { started <- struct{}{} }
		go func() { _ = s.udp.ActivateAndServe() }()
		go func() { _ = s.tcp.ActivateAndServe() }()
		<-started
		<-started
		return s, nil
	}
	return nil, fmt.Errorf("cannot listen on %s (UDP and TCP): %w", listen, errors.Join(lastErr))
}

func (s *server) close() {
	_ = s.udp.Shutdown()
	_ = s.tcp.Shutdown()
}

// handler answers for zone with ip.
func handler(zone string, ip netip.Addr) dns.HandlerFunc {
	apex := dns.Fqdn(strings.ToLower(zone))
	return func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if len(r.Question) != 1 || r.Opcode != dns.OpcodeQuery {
			m.Rcode = dns.RcodeFormatError
			_ = w.WriteMsg(m)
			return
		}
		q := r.Question[0]
		name := strings.ToLower(q.Name)
		if name != apex && !strings.HasSuffix(name, "."+apex) {
			m.Rcode = dns.RcodeRefused
			_ = w.WriteMsg(m)
			return
		}
		m.Authoritative = true
		if q.Qtype == dns.TypeA {
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1},
				A:   ip.AsSlice(),
			})
		}
		_ = w.WriteMsg(m)
	}
}
