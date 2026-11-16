package ca

import (
	"strings"
	"testing"
)

// Found by fuzzing: "::ffff:10.0.0.0/104" was accepted as a name constraint. checkIP turns the IPv4-mapped
// address of a name into IPv4, and a certificate verifier compares the length of the two addresses, so such a
// constraint never applied to anything; and reading it back from the certificate (ncFromCert) gave
// "invalid Prefix".
func TestNameConstraintRefusesAnIPv4MappedPrefix(t *testing.T) {
	t.Parallel()
	for _, v := range []string{"::ffff:10.0.0.0/104", "::ffff:0.0.0.0/96"} {
		if _, err := ncPrefix(v); err == nil || !strings.Contains(err.Error(), "IPv4-mapped") {
			t.Errorf("%s: %v", v, err)
		}
		if _, problems := checkNameConstraints(NameConstraints{ExcludedIP: []string{v}}); len(problems) != 1 {
			t.Errorf("%s: problems %v", v, problems)
		}
	}
	for _, v := range []string{"10.0.0.0/8", "fd00::/8", "::/96", "64:ff9b::/96"} {
		got, err := ncPrefix(v)
		if err != nil || got != v {
			t.Errorf("%s: %q, %v", v, got, err)
		}
	}
}
