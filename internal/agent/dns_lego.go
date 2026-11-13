package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	legolog "github.com/go-acme/lego/v4/log"
	"github.com/miekg/dns"
)

// What connects a DNS provider to lego's dns-01 solver (docs/PHASE3.md §13.2,
// decisions 3 and 8).
//
// lego keeps the resolver list and the DNS timeout in package variables, and
// its default list is two public resolvers. The agent sets them before every
// issuance (the issuances are serialized by passMu) and refuses to issue when
// it has no resolver of its own: a silent fallback would send the names of an
// internal network to the internet.

const (
	defaultResolvConf = "/etc/resolv.conf"
	dnsQueryTimeout   = 10 * time.Second
)

// dnsResolvers returns the resolvers for SOA, CNAME and propagation queries:
// the configured one, else the ones in resolvConf, else an error.
func dnsResolvers(cfg DNSProvider, resolvConf string) ([]string, error) {
	if cfg.Resolver != "" {
		return dns01.ParseNameservers([]string{cfg.Resolver}), nil
	}
	conf, err := dns.ClientConfigFromFile(resolvConf)
	if err != nil || len(conf.Servers) == 0 {
		return nil, fmt.Errorf("dns-01 needs a resolver of its own and %s has none: set resolver: <IP> under dns_providers (the agent never falls back to public resolvers)", resolvConf)
	}
	out := make([]string, 0, len(conf.Servers))
	for _, s := range conf.Servers {
		out = append(out, net.JoinHostPort(s, conf.Port))
	}
	return out, nil
}

// dnsChallengeOptions are the options of lego's dns-01 solver for one
// issuance: the resolvers, the query timeout, and the propagation check of
// the configured mode. The check looks at ctx in every poll and stops at once
// when the issuance is canceled.
func dnsChallengeOptions(ctx context.Context, cfg DNSProvider, resolvers []string) []dns01.ChallengeOption {
	opts := []dns01.ChallengeOption{
		dns01.AddRecursiveNameservers(resolvers),
		dns01.AddDNSTimeout(dnsQueryTimeout),
	}
	mode := cfg.Propagation
	switch mode {
	case PropagationResolver:
		opts = append(opts, dns01.DisableAuthoritativeNssPropagationRequirement(), dns01.RecursiveNSsPropagationRequirement())
	case PropagationWait:
		opts = append(opts, dns01.DisableAuthoritativeNssPropagationRequirement())
	case PropagationAuthoritative, "":
		// lego's default: every authoritative name server of the zone.
	}
	wait := time.Duration(cfg.PropagationWait) * time.Second
	var mu sync.Mutex
	waited := map[string]bool{}
	return append(opts, dns01.WrapPreCheck(func(_, fqdn, value string, check dns01.PreCheckFunc) (bool, error) {
		if err := ctx.Err(); err != nil {
			return true, fmt.Errorf("dns-01: stopped while waiting for the record: %w", err)
		}
		// propagation_wait comes once, before the first check of a record.
		key := fqdn + "\x00" + value
		mu.Lock()
		first := !waited[key]
		waited[key] = true
		mu.Unlock()
		if first && wait > 0 {
			t := time.NewTimer(wait)
			select {
			case <-t.C:
			case <-ctx.Done():
				t.Stop()
				return true, fmt.Errorf("dns-01: stopped while waiting for the record: %w", ctx.Err())
			}
		}
		if mode == PropagationWait {
			return true, nil
		}
		return check(fqdn, value)
	}))
}

// setLegoDNS sets lego's package variables without a challenge, for tests
// that call lego functions directly.
func setLegoDNS(resolvers []string) {
	for _, o := range []dns01.ChallengeOption{dns01.AddRecursiveNameservers(resolvers), dns01.AddDNSTimeout(dnsQueryTimeout)} {
		_ = o(nil)
	}
}

// ScrubProviderEnvironment removes the variables lego and its providers read
// (LEGO_*, CLOUDFLARE_*, CF_*, RFC2136_*) from the process environment, so
// that nothing outside agent.yaml and the credentials file can configure a DNS
// provider or turn on lego's debug output. It returns the names it removed,
// never the values.
func ScrubProviderEnvironment() []string {
	var removed []string
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		upper := strings.ToUpper(name)
		for _, prefix := range []string{"LEGO_", "CLOUDFLARE_", "CF_", "RFC2136_"} {
			if strings.HasPrefix(upper, prefix) {
				if os.Unsetenv(name) == nil {
					removed = append(removed, name)
				}
				break
			}
		}
	}
	slices.Sort(removed)
	return removed
}

// legoLog is lego's logger while a dns-01 issuance runs: its lines go to the
// agent's log at a level that fits, with the provider's secrets removed. lego
// logs to stderr by default, with no redaction.
type legoLog struct {
	log     *slog.Logger
	secrets []secret
}

func (l legoLog) emit(args string) {
	if l.log == nil {
		return
	}
	text := strings.TrimSpace(redactText(args, l.secrets...))
	switch {
	case strings.HasPrefix(text, "[INFO]"):
		l.log.Debug("lego", slog.String("message", strings.TrimSpace(strings.TrimPrefix(text, "[INFO]"))))
	case strings.HasPrefix(text, "[WARN]"):
		l.log.Warn("lego", slog.String("message", strings.TrimSpace(strings.TrimPrefix(text, "[WARN]"))))
	default:
		l.log.Warn("lego", slog.String("message", text))
	}
}

func (l legoLog) Print(args ...any)                 { l.emit(fmt.Sprint(args...)) }
func (l legoLog) Println(args ...any)               { l.emit(fmt.Sprintln(args...)) }
func (l legoLog) Printf(format string, args ...any) { l.emit(fmt.Sprintf(format, args...)) }

// Fatal in a library must not end the agent: it is logged as an error.
func (l legoLog) Fatal(args ...any)                 { l.emit(fmt.Sprint(args...)) }
func (l legoLog) Fatalln(args ...any)               { l.emit(fmt.Sprintln(args...)) }
func (l legoLog) Fatalf(format string, args ...any) { l.emit(fmt.Sprintf(format, args...)) }

// routeLegoLog sends lego's log to the agent's log until the returned
// function runs. The issuances are serialized by passMu, so the package
// variable has one writer at a time.
func routeLegoLog(log *slog.Logger, g *dnsGuard) func() {
	prev := legolog.Logger
	var secrets []secret
	if h, ok := g.inner.(dnsCredentialsHolder); ok && h.dnsCreds() != nil {
		secrets = h.dnsCreds().secrets()
	}
	legolog.Logger = legoLog{log: log, secrets: secrets}
	return func() { legolog.Logger = prev }
}

// connectDNS01 connects the guarded provider to the lego client of one
// issuance, with the agent's own resolvers.
func (a *Agent) connectDNS01(ctx context.Context, set func(challenge.Provider, ...dns01.ChallengeOption) error, g *dnsGuard, cfg DNSProvider) error {
	if g == nil {
		return errors.New("dns-01: no DNS provider")
	}
	resolvConf := a.dns.resolvConf
	if resolvConf == "" {
		resolvConf = defaultResolvConf
	}
	resolvers, err := dnsResolvers(cfg, resolvConf)
	if err != nil {
		return err
	}
	// A previous provider's records in lego's SOA cache must not decide where
	// this one writes.
	dns01.ClearFqdnCache()
	return set(g, dnsChallengeOptions(ctx, cfg, resolvers)...)
}
