package ca

import (
	"context"
	"crypto/elliptic"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"errors"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
)

var acmeWho = keys.Who{Actor: audit.Actor{Type: audit.ActorACMEAccount, ID: "acc-1", Name: "acme_account:acc-1"}, Principal: authz.System("acme")}

func acmeCSR(t *testing.T, dns []string, ips []net.IP) []byte {
	t.Helper()
	return makeCSR(t, mustKey(t, elliptic.P256()), &x509.CertificateRequest{Subject: pkix.Name{CommonName: "ignored.example"}, DNSNames: dns, IPAddresses: ips})
}

func TestACMEIssuanceFollowsTheDomains(t *testing.T) {
	t.Parallel()
	v := domainEnv(t)
	ctx := t.Context()
	if _, err := v.e.CreateDomain(ctx, DomainRequest{Name: "homelab.lan", DomainSettings: DomainSettings{CA: ptr("issuing"), IPRanges: []string{"10.1.0.0/16"}, ValidityDays: ptr(30)}, Who: tester}); err != nil {
		t.Fatal(err)
	}
	if _, err := v.e.CreateDomain(ctx, DomainRequest{Name: "lab.example", DomainSettings: DomainSettings{CA: ptr("open")}, Who: tester}); err != nil {
		t.Fatal(err)
	}
	stored := false
	out, err := v.e.Issue(ctx, Request{
		CSR: acmeCSR(t, []string{"nas.homelab.lan", "evil.example"}, nil), DNSNames: []string{"NAS.homelab.lan"}, IPAddresses: []string{"10.1.2.3"}, Who: acmeWho,
		ACME: &ACMEOrder{OrderID: "ord-1", AccountID: "acc-1", Stored: func(_ context.Context, tx *sql.Tx, is *Issued) error {
			// Inside the storing transaction: the certificate is visible there.
			if _, gerr := pkidb.New(tx).GetCertificate(ctx, is.ID); gerr != nil {
				return gerr
			}
			stored = true
			return nil
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	cert := parse(t, out.CertDER)
	if !stored || !slices.Equal(cert.DNSNames, []string{"nas.homelab.lan"}) || len(cert.IPAddresses) != 1 || !cert.IPAddresses[0].Equal(net.ParseIP("10.1.2.3")) {
		t.Errorf("stored %v, names %v %v", stored, cert.DNSNames, cert.IPAddresses)
	}
	if days := cert.NotAfter.Sub(cert.NotBefore).Round(time.Hour); days != 30*24*time.Hour {
		t.Errorf("validity %v, want the domain's 30 days", days)
	}
	if cert.Issuer.CommonName != "Homelab issuing" {
		t.Errorf("issuer %s, want the domain's CA", cert.Issuer)
	}

	// Refusals, each with its reason; nothing is stored.
	for name, tc := range map[string]struct {
		req  Request
		want string
	}{
		"no domain":     {Request{DNSNames: []string{"nas.elsewhere.example"}}, "no domain covers"},
		"two CAs":       {Request{DNSNames: []string{"nas.homelab.lan", "web.lab.example"}}, "need one CA"},
		"wildcard off":  {Request{DNSNames: []string{"*.homelab.lan"}}, "no domain covers"},
		"IP outside":    {Request{IPAddresses: []string{"10.2.0.1"}}, "no domain covers"},
		"CA by caller":  {Request{CA: "open", DNSNames: []string{"nas.homelab.lan"}}, "come from the domains"},
		"no names":      {Request{}, "at least one identifier"},
		"e-mail":        {Request{DNSNames: []string{"nas.homelab.lan"}, EmailAddresses: []string{"a@homelab.lan"}}, "DNS names and IP addresses only"},
		"without a CSR": {Request{DNSNames: []string{"nas.homelab.lan"}}, "with a CSR"},
	} {
		tc.req.Who, tc.req.ACME = acmeWho, &ACMEOrder{OrderID: "ord-x"}
		if name != "without a CSR" {
			tc.req.CSR = acmeCSR(t, nil, nil)
		}
		if _, ierr := v.e.Issue(ctx, tc.req); !deniedWith(ierr, tc.want) {
			t.Errorf("%s: %v, want %q", name, ierr, tc.want)
		}
	}

	// The hook fails: the whole issuance is rolled back.
	before := countRows(t, v, "certificates")
	boom := errors.New("order store failed")
	_, err = v.e.Issue(ctx, Request{CSR: acmeCSR(t, nil, nil), DNSNames: []string{"web.homelab.lan"}, Who: acmeWho,
		ACME: &ACMEOrder{OrderID: "ord-2", Stored: func(context.Context, *sql.Tx, *Issued) error { return boom }}})
	if !errors.Is(err, boom) || countRows(t, v, "certificates") != before {
		t.Errorf("failing hook: %v, certificates %d -> %d", err, before, countRows(t, v, "certificates"))
	}

	// A CA maximum lowered after the domain was made caps the validity.
	if uerr := v.e.UpdateCA(ctx, UpdateRequest{Name: "issuing", MaxValidityDays: 10, Who: tester}); uerr != nil {
		t.Fatal(uerr)
	}
	out, err = v.e.Issue(ctx, Request{CSR: acmeCSR(t, nil, nil), DNSNames: []string{"web.homelab.lan"}, Who: acmeWho, ACME: &ACMEOrder{OrderID: "ord-3"}})
	if err != nil {
		t.Fatal(err)
	}
	if c := parse(t, out.CertDER); c.NotAfter.Sub(c.NotBefore).Round(time.Hour) != 10*24*time.Hour {
		t.Errorf("validity %v, want the CA's 10 days", c.NotAfter.Sub(c.NotBefore))
	}
}

func countRows(t *testing.T, v *env, table string) int {
	t.Helper()
	var n int
	// #nosec G202 -- test: a fixed table name
	if err := v.pki.QueryRowContext(t.Context(), "SELECT count(*) FROM "+table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}
