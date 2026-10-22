package ca

import (
	"context"
	"fmt"
	"strings"

	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
)

// acmeRequest applies the domain policy to the issuance of an ACME order
// (PHASE2 step 2): every name lies in a domain, all of one CA and one
// preset; CA, preset and validity come from those domains, never from the
// caller. The names are exactly the order's identifiers – the ACME layer has
// matched them with the CSR – so the CSR's own names are ignored.
func (e *Engine) acmeRequest(ctx context.Context, req Request) (Request, error) {
	switch {
	case req.CSR == nil:
		return req, deny("an ACME order is finalized with a CSR")
	case req.CA != "" || req.Preset != "" || req.ValidityDays != 0:
		return req, deny("CA, preset and validity of an ACME issuance come from the domains")
	case len(req.EmailAddresses)+len(req.URIs) > 0:
		return req, deny("an ACME order names DNS names and IP addresses only")
	case len(req.DNSNames)+len(req.IPAddresses) == 0:
		return req, deny("an ACME order needs at least one identifier")
	}
	type ident struct{ typ, value string }
	var idents []ident
	for _, n := range req.DNSNames {
		idents = append(idents, ident{"dns", n})
	}
	for _, n := range req.IPAddresses {
		idents = append(idents, ident{"ip", n})
	}
	var first *Domain
	var firstName string
	var reasons []string
	days := 0
	for _, id := range idents {
		d, err := e.DomainFor(ctx, id.typ, id.value)
		if err != nil {
			return req, err
		}
		switch {
		case d == nil:
			reasons = append(reasons, fmt.Sprintf("no domain covers %q – an admin must create one first", short(id.value)))
			continue
		case first == nil:
			first, firstName = d, id.value
		case d.CAID != first.CAID:
			reasons = append(reasons, fmt.Sprintf("%q belongs to domain %s (CA %s), %q to domain %s (CA %s) – the names of one order need one CA",
				short(firstName), first.Name, first.CA, short(id.value), d.Name, d.CA))
		case d.Preset != first.Preset:
			reasons = append(reasons, fmt.Sprintf("%q belongs to domain %s (preset %s), %q to domain %s (preset %s) – the names of one order need one preset",
				short(firstName), first.Name, first.Preset, short(id.value), d.Name, d.Preset))
		}
		if v := d.EffectiveValidityDays(); days == 0 || v < days {
			days = v
		}
	}
	if len(reasons) > 0 {
		return req, &DeniedError{Reasons: reasons}
	}
	// The CA's maximum may have been lowered after the domain was made.
	ca, err := pkidb.New(e.PKI).GetCA(ctx, first.CAID)
	if err != nil {
		return req, err
	}
	if int64(days) > ca.MaxValidityDays {
		days = int(ca.MaxValidityDays)
	}
	req.CA, req.Preset, req.ValidityDays = first.CA, first.Preset, days
	req.IgnoreCSRNames = true
	req.DNSNames = lowerAll(req.DNSNames)
	return req, nil
}

func lowerAll(names []string) []string {
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = strings.ToLower(n)
	}
	return out
}
