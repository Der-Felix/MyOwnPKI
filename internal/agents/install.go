package agents

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/agentdist"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/clock"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
)

// Trust is the root the agents are told to trust before anything else: its
// DER fingerprints and the plain-HTTP URL of its PEM. Only SHA-256
// authorizes an installation; SHA-1 is for comparing with the Windows
// certificate dialog.
type Trust struct {
	SHA256, SHA1, URL string
}

// TLSTrust finds the root of the agent TLS issuer (agent.tls_issuer) among
// the CAs who may read. The guided installation (web) and the install facts
// (API) share it, so both name the same root.
func TLSTrust(ctx context.Context, engine *ca.Engine, who keys.Who, issuerName string) (Trust, error) {
	cas, err := engine.CAs(ctx, who)
	if err != nil {
		return Trust{}, err
	}
	var issuer *ca.CAInfo
	for i := range cas {
		if cas[i].Name == issuerName {
			issuer = &cas[i]
			break
		}
	}
	if issuer == nil {
		return Trust{}, ca.ErrNotFound
	}
	chain, err := engine.CAChain(ctx, who, issuer.ID)
	if err != nil || len(chain) == 0 {
		return Trust{}, errors.Join(ca.ErrNotFound, err)
	}
	rootDER := chain[len(chain)-1]
	root, err := x509.ParseCertificate(rootDER)
	if err != nil || !root.IsCA || root.CheckSignatureFrom(root) != nil {
		return Trust{}, errors.New("agent TLS issuer chain has no valid self-signed root")
	}
	for i := range cas {
		if cas[i].Kind != ca.KindRoot {
			continue
		}
		for _, generation := range cas[i].Generations {
			fingerprint := strings.ReplaceAll(strings.ToLower(generation.Fingerprint), ":", "")
			sum := sha256.Sum256(rootDER)
			if generation.Generation > 0 && fingerprint == hex.EncodeToString(sum[:]) {
				rootURL := fmt.Sprintf("%s/ca/%s/%d.pem", strings.TrimRight(cas[i].BaseURL, "/"), cas[i].Name, generation.Generation)
				u, parseErr := url.Parse(rootURL)
				if parseErr != nil || u.Scheme != "http" || u.Hostname() == "" || u.RawQuery != "" || u.Fragment != "" {
					return Trust{}, errors.New("agent TLS root has no exact public HTTP PEM URL")
				}
				return Trust{SHA256: fingerprint, SHA1: generation.FingerprintSHA1, URL: rootURL}, nil
			}
		}
	}
	return Trust{}, ca.ErrNotFound
}

// InstallSource holds what the install facts are made of: the server's agent
// address, the packages of this release, the agent TLS issuer and the ACME
// directory. Everything in it is already visible to a viewer (the packages
// and the root are served without a login); the facts only gather it.
type InstallSource struct {
	Dist      *agentdist.Store
	BaseURL   string // agent.base_url
	TLSIssuer string // agent.tls_issuer
	// ACMEDirectory returns the directory URL of the ACME server, "" while ACME is off.
	ACMEDirectory func() string
	Clock         clock.Clock

	mu       sync.Mutex
	packages []Package
	cachedAt time.Time
}

// Package is one file of the agent distribution.
type Package struct {
	Name, Format, Arch string // Format "checksums" for checksums.txt
	Size               int64
	SHA256             string // hex
	URL                string
}

// InstallFacts is everything a script needs to install the agent on a host
// without a browser: the independent values of the guided installation.
type InstallFacts struct {
	ServerURL     string
	ACMEDirectory string // "" = ACME is off
	Version       string // the agent release that matches this server
	Root          Trust
	Packages      []Package
}

// PackagesTTL: the packages of a release are immutable, but hashing six of
// them is not free and any viewer, API tokens included, may ask.
const PackagesTTL = time.Minute

// Facts gathers the install facts. It fails with ErrNotFound while there is
// no agent TLS root or no package directory for this release.
func (s *InstallSource) Facts(ctx context.Context, engine *ca.Engine, who keys.Who) (*InstallFacts, error) {
	trust, err := TLSTrust(ctx, engine, who, s.TLSIssuer)
	if err != nil {
		return nil, err
	}
	pkgs, err := s.manifest()
	if err != nil {
		return nil, err
	}
	f := &InstallFacts{ServerURL: strings.TrimRight(s.BaseURL, "/"), Version: s.Dist.Version(), Root: trust, Packages: pkgs}
	if s.ACMEDirectory != nil {
		f.ACMEDirectory = s.ACMEDirectory()
	}
	return f, nil
}

func (s *InstallSource) manifest() ([]Package, error) {
	if s.Dist == nil {
		return nil, ErrNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if now := s.Clock.Now(); s.packages != nil && now.Sub(s.cachedAt) < PackagesTTL && !now.Before(s.cachedAt) {
		return s.packages, nil
	}
	list, err := s.Dist.Manifest()
	if err != nil {
		return nil, fmt.Errorf("%w: no agent packages for this release", ErrNotFound)
	}
	base := strings.TrimRight(s.BaseURL, "/") + agentdist.BasePath
	out := make([]Package, 0, len(list))
	for _, a := range list {
		format := a.Format
		if format == agentdist.Checksums {
			format = "checksums"
		}
		out = append(out, Package{Name: a.Name, Format: format, Arch: a.Arch, Size: a.Size, SHA256: a.SHA256, URL: base + a.Name})
	}
	s.packages, s.cachedAt = out, s.Clock.Now()
	return out, nil
}

// InstallFacts returns the install facts for anyone who may read the PKI
// (viewer and up, API tokens included): they hold no secret, only what the
// agent distribution and the public root already show.
func (s *Service) InstallFacts(ctx context.Context, who keys.Who) (*InstallFacts, error) {
	if err := s.authorize(who, authz.ReadPKI); err != nil {
		return nil, err
	}
	if s.Install == nil {
		return nil, ErrNotFound
	}
	return s.Install.Facts(ctx, s.Engine, who)
}
