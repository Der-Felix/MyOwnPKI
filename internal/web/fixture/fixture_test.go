package fixture

import "testing"

// The sample data must be internally consistent, or the prototype shows broken links.
func TestConsistency(t *testing.T) {
	t.Parallel()
	ids := map[string]bool{}
	for _, c := range Certificates() {
		if ids[c.ID] {
			t.Errorf("duplicate certificate ID %s", c.ID)
		}
		ids[c.ID] = true
		if _, ok := CAByID(c.CAID); !ok {
			t.Errorf("%s: unknown CA %q", c.ID, c.CAID)
		}
		if !c.NotBefore.Before(c.NotAfter) {
			t.Errorf("%s: notBefore is not before notAfter", c.ID)
		}
		if len(c.Serial()) != 32 || c.Serial()[0] > '7' {
			t.Errorf("%s: serial %s is not 16 bytes with the high bit clear", c.ID, c.Serial())
		}
	}
	for _, ca := range CAs() {
		if ca.ParentID != "" {
			if _, ok := CAByID(ca.ParentID); !ok {
				t.Errorf("%s: unknown parent %q", ca.ID, ca.ParentID)
			}
		}
	}
}
