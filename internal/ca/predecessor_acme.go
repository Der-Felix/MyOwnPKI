package ca

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/netip"
	"strings"

	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/predecessor"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
)

// ACMENameSet parses the normalized, duplicate-free identifier set stored on
// an order. The keys have the same dns:/ip: form as ACME's identifier.key().
func ACMENameSet(raw string) (map[string]struct{}, error) {
	var identifiers []struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	}
	if err := json.Unmarshal([]byte(raw), &identifiers); err != nil {
		return nil, err
	}
	out := make(map[string]struct{}, len(identifiers))
	for _, id := range identifiers {
		switch id.Type {
		case "dns":
			name, err := NormalizeDNSName(id.Value, true)
			if err != nil {
				return nil, err
			}
			out["dns:"+name] = struct{}{}
		case "ip":
			address, err := netip.ParseAddr(id.Value)
			if err != nil {
				return nil, err
			}
			out["ip:"+address.Unmap().String()] = struct{}{}
		}
	}
	return out, nil
}

// SameACMENameSet compares a stored order with an already normalized set.
func SameACMENameSet(raw string, want map[string]struct{}) (bool, error) {
	got, err := ACMENameSet(raw)
	if err != nil {
		return false, err
	}
	if len(got) != len(want) {
		return false, nil
	}
	for name := range want {
		if _, ok := got[name]; !ok {
			return false, nil
		}
	}
	return true, nil
}

// ApplyACMEPredecessor handles every unambiguous older certificate of the
// same account with exactly the successor's name set. It never selects by
// hostname alone or across accounts.
func (e *Engine) ApplyACMEPredecessor(ctx context.Context, q *pkidb.Queries, tx *sql.Tx, accountID, successorID string,
	names map[string]struct{}, policy predecessor.Policy, who keys.Who) (revocations []*RevokeResult, ambiguous []string, err error) {
	successor, err := q.GetCertificate(ctx, successorID)
	if err != nil {
		return nil, nil, err
	}
	rows, err := q.ListAgentPredecessorCandidates(ctx, pkidb.ListAgentPredecessorCandidatesParams{ID: accountID, CreatedAt: successor.CreatedAt})
	if err != nil {
		return nil, nil, err
	}
	type candidate struct {
		id         string
		duplicated bool
	}
	matches := map[string]*candidate{}
	for _, row := range rows {
		same, err := SameACMENameSet(row.Identifiers, names)
		if err != nil {
			ambiguous = append(ambiguous, row.ID)
			continue
		}
		if !same {
			continue
		}
		if matches[row.ID] == nil {
			matches[row.ID] = &candidate{id: row.ID}
		} else {
			matches[row.ID].duplicated = true
		}
	}
	for _, match := range matches {
		if match.duplicated {
			ambiguous = append(ambiguous, match.id)
			continue
		}
		results, err := e.ApplyPredecessor(ctx, q, tx, match.id, successorID, policy, "acme", who, e.now())
		if err != nil {
			return nil, ambiguous, err
		}
		revocations = append(revocations, results...)
	}
	return revocations, ambiguous, nil
}

// DeploymentNameSet normalizes the DNS names reported for an agent deployment.
func DeploymentNameSet(names []string) (map[string]struct{}, error) {
	out := make(map[string]struct{}, len(names))
	for _, raw := range names {
		name, err := NormalizeDNSName(strings.TrimSpace(raw), true)
		if err != nil {
			return nil, err
		}
		out["dns:"+name] = struct{}{}
	}
	return out, nil
}
