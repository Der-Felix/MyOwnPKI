// Package netguard is the one place that decides where the server may
// connect on behalf of somebody else's input (security.md "ACME validation
// = outbound requests to attacker-chosen names"). The http-01 validator, the
// agent enrollment check and the TLS scan all dial through it, so there is
// one address policy and one set of tests:
//   - a name is resolved once and the connection goes to exactly the
//     address that was checked – no DNS rebinding between check and connect;
//   - the address policy of a domain decides which addresses are allowed;
//     loopback, link-local, multicast, unspecified and reserved addresses
//     never are;
//   - the caller decides which ports are allowed (CheckPort); without that
//     function every port is refused;
//   - the client learns counts and kinds of failures, never addresses or what
//     a target said – the server log keeps the details.
package netguard

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Address policies of a domain (internal/ca: AddressInternal, AddressPublic).
const (
	PolicyInternal = "internal" // private networks are allowed (the default)
	PolicyPublic   = "public"   // public addresses only
)

// Kinds of an *Error.
const (
	KindDNS        = "dns"        // the name could not be resolved
	KindConnection = "connection" // no address could be reached or was allowed
)

// Error is a refused or failed connect with text that is safe to show to
// the client who asked for it: counts and kinds, never an address.
type Error struct {
	Kind, Detail string
	// Refused: every usable address was refused by the address policy.
	Refused bool
	// Err is the last underlying error. It is not part of the text (it can
	// carry what the target sent); callers classify it with errors.Is/As.
	Err error
}

func (e *Error) Error() string { return e.Kind + ": " + e.Detail }

// Unwrap returns the last underlying error, if any.
func (e *Error) Unwrap() error { return e.Err }

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// embeddingPrefixes are the IPv6 ranges that carry an IPv4 address inside
// (or tunnel to one). A client or a router may translate such an address to
// the embedded IPv4 one, so "::7f00:1" or "64:ff9b::7f00:1" can reach
// 127.0.0.1 although the IPv6 address itself looks global. Judging the
// embedded address would need one parser per format; none of these ranges is
// a place anybody's TLS endpoint or ACME client lives, so they are refused
// entirely. IPv4-mapped (::ffff:0:0/96) is not here: it is unmapped first and
// judged as the IPv4 address it is.
var embeddingPrefixes = []struct {
	prefix netip.Prefix
	name   string
}{
	{netip.MustParsePrefix("::/96"), "an IPv4-compatible address (::/96)"},
	{netip.MustParsePrefix("64:ff9b::/96"), "a NAT64 address (64:ff9b::/96)"},
	{netip.MustParsePrefix("64:ff9b:1::/48"), "a local-use NAT64 address (64:ff9b:1::/48)"},
	{netip.MustParsePrefix("2002::/16"), "a 6to4 address (2002::/16)"},
	{netip.MustParsePrefix("2001::/32"), "a Teredo address (2001::/32)"},
}

// Allowed applies the address policy: nil if a may be connected to under
// policy ("internal" or "public"). The error names the address and the rule
// – for the log, not for the client.
func Allowed(a netip.Addr, policy string) error {
	a = a.Unmap()
	switch {
	case !a.IsValid(), a.IsUnspecified(), a.IsLoopback(), a.IsLinkLocalUnicast(), a.IsLinkLocalMulticast(),
		a.IsInterfaceLocalMulticast(), a.IsMulticast():
		return fmt.Errorf("%s is never a validation target", a)
	case a.Zone() != "":
		return fmt.Errorf("%s has a zone and is never a validation target", a)
	case a.Is4() && (a.As4()[0] == 0 || a.As4()[0] >= 240):
		return fmt.Errorf("%s is a reserved address", a)
	}
	if a.Is6() {
		for _, e := range embeddingPrefixes {
			if e.prefix.Contains(a) {
				return fmt.Errorf("%s is %s that can embed an IPv4 address and is never a validation target", a, e.name)
			}
		}
	}
	if policy == PolicyPublic && (a.IsPrivate() || cgnat.Contains(a)) {
		return fmt.Errorf("%s is a private address and the domain allows public addresses only", a)
	}
	return nil
}

// DialFunc and LookupFunc are the network edges. Tests replace them, never
// the rules around them.
type (
	DialFunc   func(ctx context.Context, network, addr string) (net.Conn, error)
	LookupFunc func(ctx context.Context, host string) ([]netip.Addr, error)
)

// Dialer resolves once, checks every address and connects to an allowed one.
type Dialer struct {
	Policy   string
	Dial     DialFunc   // nil = net.Dialer
	LookupIP LookupFunc // required for names (an IP literal needs none)
	// CheckPort decides which ports may be dialed; its error is returned as
	// is, before anything is resolved. nil refuses every port.
	CheckPort func(port uint16) error
	// Log gets one line per refused or failed address, with LogName as the
	// start of the message ("acme validation"). nil = no log.
	Log      *slog.Logger
	LogName  string
	LogLevel slog.Level // the zero value is Info
	// MaxTries limits the addresses that are dialed (0 = all); TryTimeout
	// limits each dial (0 = only the context).
	MaxTries   int
	TryTimeout time.Duration
}

// DialContext has the signature of http.Transport.DialContext.
func (d *Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, portText, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, perr := strconv.ParseUint(portText, 10, 16)
	if perr != nil || port == 0 || strconv.FormatUint(port, 10) != portText {
		return nil, &Error{Kind: KindConnection, Detail: fmt.Sprintf("port %s is not a port number", clip(portText))}
	}
	if d.CheckPort == nil {
		return nil, &Error{Kind: KindConnection, Detail: fmt.Sprintf("port %d is not allowed", port)}
	}
	if cerr := d.CheckPort(uint16(port)); cerr != nil {
		return nil, cerr
	}
	var addrs []netip.Addr
	if a, perr := netip.ParseAddr(host); perr == nil {
		addrs = []netip.Addr{a}
	} else {
		if d.LookupIP == nil {
			return nil, &Error{Kind: KindDNS, Detail: host + ": the DNS lookup failed"}
		}
		if addrs, err = d.LookupIP(ctx, host); err != nil {
			return nil, &Error{Kind: KindDNS, Detail: host + ": " + DNSProblem(err), Err: err}
		}
	}
	dial := d.Dial
	if dial == nil {
		var nd net.Dialer
		dial = nd.DialContext
	}
	var policyRefused, dialFailed int
	var kinds []string
	var last error
	for _, a := range addrs {
		if perr := Allowed(a, d.Policy); perr != nil {
			policyRefused++
			d.logf(": address refused", slog.String("host", host), slog.String("reason", perr.Error()))
			continue
		}
		if d.MaxTries > 0 && dialFailed >= d.MaxTries {
			break
		}
		conn, derr := d.dialOne(ctx, dial, network, netip.AddrPortFrom(a.Unmap(), uint16(port)).String())
		if derr == nil {
			return conn, nil
		}
		dialFailed++
		last = derr
		kinds = append(kinds, NetProblem(derr))
		d.logf(": connect failed", slog.String("host", host), slog.String("address", a.String()), slog.String("kind", NetProblem(derr)))
	}
	switch {
	case len(addrs) == 0:
		return nil, &Error{Kind: KindDNS, Detail: host + " has no address"}
	case dialFailed == 0:
		return nil, &Error{Kind: KindConnection, Refused: true,
			Detail: fmt.Sprintf("%s: the address policy of the domain refuses all %d address(es)", host, policyRefused)}
	}
	return nil, &Error{Kind: KindConnection, Err: last,
		Detail: fmt.Sprintf("%s: %d address(es) refused by the address policy, %d could not be reached (%s)",
			host, policyRefused, dialFailed, strings.Join(slices.Compact(kinds), ", "))}
}

func (d *Dialer) dialOne(ctx context.Context, dial DialFunc, network, addr string) (net.Conn, error) {
	if d.TryTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, d.TryTimeout)
		defer cancel()
	}
	return dial(ctx, network, addr)
}

func (d *Dialer) logf(suffix string, attrs ...slog.Attr) {
	if d.Log == nil {
		return
	}
	// The message is the caller's constant prefix plus one of two fixed suffixes: operators keep the log lines they know.
	d.Log.LogAttrs(context.Background(), d.LogLevel, d.LogName+suffix, attrs...) //nolint:sloglint // message = fixed prefix of the caller + fixed suffix
}

// NewResolver returns the resolver for names the server connects to:
// resolverAddr ("IP:port") instead of the system's when set (acme.resolver).
func NewResolver(resolverAddr string) *net.Resolver {
	r := &net.Resolver{PreferGo: true}
	if resolverAddr != "" {
		var d net.Dialer
		r.Dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return d.DialContext(ctx, network, resolverAddr) // acme.resolver, never the system's
		}
	}
	return r
}

// NetProblem names the kind of a network error – never its text, which can
// carry what the target sent (a malformed HTTP response quotes it).
func NetProblem(err error) string {
	var ne net.Error
	var op *net.OpError
	var rh tls.RecordHeaderError
	var alert tls.AlertError
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return "timed out"
	case errors.As(err, &rh), errors.As(err, &alert):
		return "TLS handshake failed"
	case errors.As(err, &op) && op.Op == "dial":
		return "could not connect"
	}
	return "the connection failed or the answer was not HTTP"
}

// DNSProblem names the kind of a DNS error, without the resolver's address.
func DNSProblem(err error) string {
	var de *net.DNSError
	switch {
	case errors.As(err, &de) && de.IsNotFound:
		return "no such name"
	case errors.As(err, &de) && de.IsTimeout, errors.Is(err, context.DeadlineExceeded):
		return "the DNS lookup timed out"
	}
	return "the DNS lookup failed"
}

func clip(s string) string {
	if len(s) > 16 {
		return s[:16] + "..."
	}
	return s
}
