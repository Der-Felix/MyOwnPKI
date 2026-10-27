package version

import "testing"

func TestCompareSemver(t *testing.T) {
	t.Parallel()
	tests := []struct {
		left, right string
		want        int
	}{
		{"0.3.0", "v0.3.1", -1},
		{"v0.3.1", "0.3.1", 0},
		{"0.3.2", "0.3.1", 1},
		{"0.3.1-alpha.1", "0.3.1", -1},
		{"0.3.0", "0.3.1-alpha.1", -1},
		{"0.3.1", "0.3.0-alpha.1", 1},
		{"0.3.1-alpha.1", "0.3.0", 1},
		{"0.3.0-alpha.1", "0.3.1", -1},
		{"0.3.1-alpha.2", "0.3.1-alpha.10", -1},
		{"0.3.1-alpha.10", "0.3.1-alpha.2", 1},
		{"0.3.1-alpha", "0.3.1-alpha.1", -1},
		{"0.3.1-1", "0.3.1-alpha", -1},
		{"0.3.1+build.2", "0.3.1+build.1", 0},
		{"10.0.0", "2.0.0", 1},
		{"99999999999999999999.0.0", "2.0.0", 1},
	}
	for _, tt := range tests {
		got, err := Compare(tt.left, tt.right)
		if err != nil || got != tt.want {
			t.Errorf("Compare(%q, %q) = %d, %v; want %d", tt.left, tt.right, got, err, tt.want)
		}
	}
}

func TestCompareRejectsNonSemver(t *testing.T) {
	t.Parallel()
	for _, value := range []string{"", "dev", "1.2", "1.2.3.4", "01.2.3", "1.02.3", "1.2.03", "1.2.3-01", "1.2.3-", "1.2.3+", "v1.2.3_4"} {
		if _, err := Compare(value, "1.2.3"); err == nil {
			t.Errorf("accepted %q", value)
		}
	}
}
