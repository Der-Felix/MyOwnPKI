package preset

import (
	"bufio"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The legacy Bash suite is the reference for the built-in presets (PLAN §9.1).
// This test reads legacy/lib/presets.sh and fails on any difference, so the
// YAML port can't silently drift from the original.

const legacyPresetsFile = "../../../legacy/lib/presets.sh"

var (
	reLegacyList   = regexp.MustCompile(`^PRESETS="([^"]*)"`)
	reLegacyFunc   = regexp.MustCompile(`^(load_preset|preset_family)\(\)`)
	reLegacyCase   = regexp.MustCompile(`^\s+([a-z-]+)\)\s*$`)
	reLegacyAssign = regexp.MustCompile(`^\s+P_([A-Z_]+)=(.*)$`)
	reLegacyFamily = regexp.MustCompile(`^\s+([a-z|*-]+)\)\s+echo\s+(\S+)\s*;;`)
)

type legacyPresets struct {
	names    []string
	values   map[string]map[string]string // preset -> P_* variable -> value
	families map[string]string            // pattern -> family ("$1" = preset name)
}

func parseLegacyPresets(t *testing.T) legacyPresets {
	t.Helper()
	f, err := os.Open(legacyPresetsFile)
	if err != nil {
		t.Fatalf("open legacy presets: %v", err)
	}
	defer func() { _ = f.Close() }()

	lp := legacyPresets{values: map[string]map[string]string{}, families: map[string]string{}}
	defaults := map[string]string{}
	var fn, current string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if m := reLegacyList.FindStringSubmatch(line); m != nil {
			lp.names = strings.Fields(m[1])
			continue
		}
		if m := reLegacyFunc.FindStringSubmatch(line); m != nil {
			fn, current = m[1], ""
			continue
		}
		switch fn {
		case "load_preset":
			if m := reLegacyCase.FindStringSubmatch(line); m != nil {
				current = m[1]
				lp.values[current] = map[string]string{}
				for k, v := range defaults {
					lp.values[current][k] = v
				}
				continue
			}
			if m := reLegacyAssign.FindStringSubmatch(line); m != nil {
				v := strings.Trim(m[2], `"`)
				if current == "" {
					defaults[m[1]] = v
				} else {
					lp.values[current][m[1]] = v
				}
				continue
			}
			if strings.TrimSpace(line) == ";;" {
				current = ""
			}
		case "preset_family":
			if m := reLegacyFamily.FindStringSubmatch(line); m != nil {
				lp.families[m[1]] = strings.Trim(m[2], `"`)
			}
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("read legacy presets: %v", err)
	}
	if len(lp.names) == 0 || len(lp.values) == 0 || len(lp.families) == 0 {
		t.Fatalf("legacy parser found nothing – did the format of %s change?", legacyPresetsFile)
	}
	return lp
}

// family reproduces legacy preset_family().
func (lp legacyPresets) family(name string) string {
	for pattern, fam := range lp.families {
		if pattern == "*" {
			continue
		}
		if slices.Contains(strings.Split(pattern, "|"), name) {
			if fam == "$1" {
				return name
			}
			return fam
		}
	}
	return lp.families["*"]
}

func splitList(s, sep string) []string {
	var out []string
	for _, part := range strings.Split(s, sep) {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

// canonicalEKU turns a legacy or YAML EKU token into its dotted OID.
func canonicalEKU(t *testing.T, token string) string {
	t.Helper()
	if oid, ok := extKeyUsageOID[token]; ok {
		return oid.String()
	}
	if oid, ok := parseOID(token); ok {
		return oid.String()
	}
	t.Fatalf("cannot canonicalise EKU %q", token)
	return ""
}

func sanTypes2Strings(list []SANType) []string {
	out := make([]string, len(list))
	for i, s := range list {
		out[i] = string(s)
	}
	return out
}

func TestLegacyParity(t *testing.T) {
	t.Parallel()
	lp := parseLegacyPresets(t)
	set, err := Builtin()
	if err != nil {
		t.Fatalf("Builtin(): %v", err)
	}

	if got, want := set.Names(), slices.Sorted(slices.Values(lp.names)); !slices.Equal(got, want) {
		t.Fatalf("preset names differ\n yaml:   %v\n legacy: %v", got, want)
	}

	for _, name := range lp.names {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			l := lp.values[name]
			p, _ := set.Get(name)

			check := func(field string, got, want any) {
				t.Helper()
				if !equalAny(got, want) {
					t.Errorf("%s: yaml %q, legacy %q", field, got, want)
				}
			}
			check("description", p.Description, l["DESC"])
			check("usage", p.Usage, l["USE"])
			check("family", string(p.Family), lp.family(name))
			check("validity_days", strconv.Itoa(p.ValidityDays), l["DAYS"])
			check("key_usage.rsa", p.KeyUsage.RSA, splitList(l["KU_RSA"], ","))
			check("key_usage.other", p.KeyUsage.Other, splitList(l["KU_ED"], ","))

			var yamlEKU, legacyEKU []string
			for _, u := range p.ExtKeyUsage.Usages {
				yamlEKU = append(yamlEKU, canonicalEKU(t, u))
			}
			for _, u := range splitList(l["EKU"], ",") {
				legacyEKU = append(legacyEKU, canonicalEKU(t, u))
			}
			check("ext_key_usage.usages", yamlEKU, legacyEKU)
			check("ext_key_usage.critical", p.ExtKeyUsage.Critical, l["EKU_CRIT"] == "yes")

			check("subject_alt_names.required_any_of", sanTypes2Strings(p.SubjectAltNames.RequiredAnyOf), splitList(l["SAN_REQ"], "|"))
			check("subject_alt_names.offered", sanTypes2Strings(p.SubjectAltNames.Offered), splitList(l["SAN_ASK"], " "))
			check("common_name_from", string(p.CommonNameFrom), l["CN_AUTO"])
			check("openssl_purpose", p.OpenSSLPurpose, l["PURPOSE"])
			check("ocsp_no_check", p.OCSPNoCheck, strings.Contains(l["EXTRA"], "noCheck"))
			check("customizable", p.Customizable, name == "custom")
		})
	}
}

func equalAny(a, b any) bool {
	switch av := a.(type) {
	case []string:
		bv, _ := b.([]string)
		return slices.Equal(av, bv)
	default:
		return a == b
	}
}
