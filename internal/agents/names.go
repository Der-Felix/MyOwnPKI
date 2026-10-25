package agents

import (
	"fmt"
	"strings"
)

// CheckHostname checks a host name an agent claims: a fully qualified DNS
// name (at least two labels), lower case, letters, digits and hyphens, no
// wildcard, no IP address. It returns the name in lower case.
func CheckHostname(s string) (string, error) {
	h := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
	if err := checkDNSName(h); err != nil {
		return "", fmt.Errorf("%w: hostname %q: %w", ErrInvalid, clip(s, 64), err)
	}
	return h, nil
}

// CheckPattern checks an entry of a name list or of a join token: an exact
// name or "*.suffix" – every name below suffix.
func CheckPattern(s string) (string, error) {
	p := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
	rest, wild := strings.CutPrefix(p, "*.")
	if err := checkDNSName(rest); err != nil {
		return "", fmt.Errorf("%w: name %q: %w", ErrInvalid, clip(s, 64), err)
	}
	if wild && !strings.Contains(rest, ".") {
		return "", fmt.Errorf("%w: name %q: a pattern covers names below a domain with at least two labels, e.g. *.homelab.lan", ErrInvalid, clip(s, 64))
	}
	return p, nil
}

func checkDNSName(h string) error {
	if len(h) == 0 || len(h) > 253 {
		return fmt.Errorf("1 to 253 characters")
	}
	labels := strings.Split(h, ".")
	if len(labels) < 2 {
		return fmt.Errorf("want a fully qualified name such as proxy1.homelab.lan")
	}
	for _, l := range labels {
		if len(l) == 0 || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return fmt.Errorf("every label 1 to 63 characters, not starting or ending with '-'")
		}
		for _, r := range l {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return fmt.Errorf("only letters, digits, '-' and '.'")
			}
		}
	}
	if strings.Trim(labels[len(labels)-1], "0123456789") == "" {
		return fmt.Errorf("an IP address is not a host name")
	}
	return nil
}

// Matches reports whether name is covered by pattern: the same name, or
// below the suffix of "*.suffix". A wildcard name ("*.x") is only covered by
// the identical pattern – an agent never gets a wildcard by accident.
func Matches(pattern, name string) bool {
	if pattern == name {
		return true
	}
	if strings.HasPrefix(name, "*.") {
		return false
	}
	suffix, ok := strings.CutPrefix(pattern, "*.")
	return ok && strings.HasSuffix(name, "."+suffix)
}

// MatchesAny reports whether one of the patterns covers name.
func MatchesAny(patterns []string, name string) bool {
	for _, p := range patterns {
		if Matches(p, name) {
			return true
		}
	}
	return false
}
