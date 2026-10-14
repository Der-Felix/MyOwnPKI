package ca

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestCheckDNSName(t *testing.T) {
	t.Parallel()
	ok := map[string]string{
		"NAS.Homelab.LAN":                "nas.homelab.lan",
		"nas":                            "nas", // single-label intranet names stay possible (legacy)
		"xn--mnchen-3ya.example":         "xn--mnchen-3ya.example",
		"a-b.c-d.e":                      "a-b.c-d.e",
		strings.Repeat("a", 63) + ".lan": strings.Repeat("a", 63) + ".lan",
	}
	for in, want := range ok {
		if got, err := checkDNSName(in, false); err != nil || got != want {
			t.Errorf("%q: %q, %v", in, got, err)
		}
	}
	bad := map[string]string{
		"":                               "empty",
		"münchen.example":                "punycode",
		"host.lan.":                      "end with a dot",
		"10.0.0.1":                       "IP SAN",
		"1.2.3":                          "all digits",
		"a..b":                           "empty label",
		"-a.lan":                         "may only contain",
		"a_b.lan":                        "may only contain",
		"a b.lan":                        "may only contain",
		"ab--cd.lan":                     "reserved",
		"xn--.lan":                       "may only contain",
		"*.homelab.lan":                  "wildcard preset",
		strings.Repeat("a", 64) + ".lan": "longer than 63",
		strings.Repeat("a.", 127) + "aa": "longer than 253",
		"host\x00.lan":                   "may only contain",
	}
	for in, want := range bad {
		if _, err := checkDNSName(in, false); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v, want %q", in, err, want)
		}
	}
	if _, err := checkDNSName("*.homelab.lan", true); err != nil {
		t.Error(err)
	}
}

func TestCheckOtherNames(t *testing.T) {
	t.Parallel()
	if ip, err := checkIP("::ffff:192.0.2.1"); err != nil || ip.String() != "192.0.2.1" {
		t.Errorf("mapped: %v %v", ip, err)
	}
	for _, s := range []string{"0.0.0.0", "::", "fe80::1%eth0", "10.0.0", "host"} {
		if _, err := checkIP(s); err == nil {
			t.Errorf("IP %q accepted", s)
		}
	}
	if e, err := checkEmail("Felix.M+pki@Homelab.LAN"); err != nil || e != "Felix.M+pki@homelab.lan" {
		t.Errorf("email: %q %v", e, err)
	}
	for _, s := range []string{"felix", "@homelab.lan", "a..b@homelab.lan", `"a b"@homelab.lan`, "felix@", "félix@homelab.lan", "a@b@homelab.lan", "a@*.lan"} {
		if _, err := checkEmail(s); err == nil {
			t.Errorf("email %q accepted", s)
		}
	}
	for _, s := range []string{"https://svc.homelab.lan/api", "spiffe://homelab.lan/ns/web", "urn:uuid:6e8bc430-9c3a-11d9-9669-0800200c9a66"} {
		if _, err := checkURI(s); err != nil {
			t.Errorf("URI %q: %v", s, err)
		}
	}
	for _, s := range []string{"/relative", "https://user:pw@host/", "https://host/ space", "https://host/ä", "1http://x"} {
		if _, err := checkURI(s); err == nil {
			t.Errorf("URI %q accepted", s)
		}
	}
}

func TestCheckNamesDeduplicatesAndCollects(t *testing.T) {
	t.Parallel()
	n, problems := checkNames(nameInput{DNS: []string{"A.lan", "a.lan", "bad_name"}, IPs: []string{"10.0.0.1", "::ffff:10.0.0.1"}}, false)
	if len(n.DNS) != 1 || len(n.IPs) != 1 || len(problems) != 1 {
		t.Errorf("names %+v problems %v", n, problems)
	}
	many := make([]string, maxSANs+1)
	for i := range many {
		many[i] = fmt.Sprintf("h%d.lan", i)
	}
	if _, p := checkNames(nameInput{DNS: many}, false); len(p) != 1 || !strings.Contains(p[0], "at most 100") {
		t.Errorf("101 names: %v", p)
	}
}

func TestMatchConstraints(t *testing.T) {
	t.Parallel()
	tests := []struct {
		match       func(name, value string) bool
		name, value string
		want        bool
	}{
		{matchDNS, "homelab.lan", "homelab.lan", true},
		{matchDNS, "a.homelab.lan", "homelab.lan", true},
		{matchDNS, "evilhomelab.lan", "homelab.lan", false},
		{matchDNS, "homelab.lan", ".homelab.lan", false},
		{matchDNS, "a.homelab.lan", ".homelab.lan", true},
		{matchDNS, "*.homelab.lan", "homelab.lan", true},
		{matchDNS, "*.homelab.lan", "a.homelab.lan", false},
		{matchIP, "10.1.2.3", "10.0.0.0/8", true},
		{matchIP, "11.0.0.1", "10.0.0.0/8", false},
		{matchIP, "fd00::1", "fd00::/8", true},
		{matchIP, "10.1.2.3", "fd00::/8", false},
		{matchEmail, "felix@homelab.lan", "homelab.lan", true},
		{matchEmail, "felix@mail.homelab.lan", "homelab.lan", false},
		{matchEmail, "felix@mail.homelab.lan", ".homelab.lan", true},
		{matchEmail, "felix@homelab.lan", "felix@homelab.lan", true},
		{matchEmail, "other@homelab.lan", "felix@homelab.lan", false},
		{matchURI, "https://svc.homelab.lan/x", "svc.homelab.lan", true},
		{matchURI, "https://a.svc.homelab.lan/x", ".homelab.lan", true},
		{matchURI, "urn:uuid:1", "homelab.lan", false},
		{matchURI, "https://10.0.0.1/", "10.0.0.1", false},
	}
	for _, tt := range tests {
		if got := tt.match(tt.name, tt.value); got != tt.want {
			t.Errorf("%q against %q: %v, want %v", tt.name, tt.value, got, tt.want)
		}
	}
	if !wildcardCovers("*.homelab.lan", "secret.homelab.lan") || wildcardCovers("*.homelab.lan", "a.secret.homelab.lan") ||
		wildcardCovers("*.homelab.lan", ".secret.homelab.lan") {
		t.Error("wildcardCovers")
	}
}

func TestComputeValidity(t *testing.T) {
	t.Parallel()
	caStart, caEnd := t0.AddDate(-1, 0, 0), t0.AddDate(2, 0, 0)
	v := computeValidity(t0, 0, 397, 825, caStart, caEnd)
	if v.problem != "" || v.days != 397 || !v.notBefore.Equal(t0.Add(-5*time.Minute)) || v.notAfter.Sub(v.notBefore) != 397*day-time.Second {
		t.Errorf("default: %+v", v)
	}
	// A brand-new CA: notBefore is never before the CA's own start.
	if v := computeValidity(t0, 0, 30, 825, t0.Add(-time.Minute), caEnd); !v.notBefore.Equal(t0.Add(-time.Minute)) {
		t.Errorf("backdate before the CA start: %v", v.notBefore)
	}
	if v := computeValidity(t0, -1, 397, 825, caStart, caEnd); v.problem == "" {
		t.Error("negative days accepted")
	}
}
