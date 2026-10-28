package version

import (
	"errors"
	"strings"
)

var ErrInvalidSemver = errors.New("not a strict semantic version")

type semanticVersion struct {
	core       [3]string
	prerelease []string
}

// Compare compares two strict SemVer 2.0 versions. An optional leading v is
// accepted for MyOwnPKI release strings; development versions are rejected.
func Compare(left, right string) (int, error) {
	a, err := parseSemver(left)
	if err != nil {
		return 0, err
	}
	b, err := parseSemver(right)
	if err != nil {
		return 0, err
	}
	for i := range a.core {
		if cmp := compareNumeric(a.core[i], b.core[i]); cmp != 0 {
			return cmp, nil
		}
	}
	switch {
	case len(a.prerelease) == 0 && len(b.prerelease) != 0:
		return 1, nil
	case len(a.prerelease) != 0 && len(b.prerelease) == 0:
		return -1, nil
	}
	for i := 0; i < min(len(a.prerelease), len(b.prerelease)); i++ {
		aID, bID := a.prerelease[i], b.prerelease[i]
		aNum, bNum := numericIdentifier(aID), numericIdentifier(bID)
		switch {
		case aNum && bNum:
			if cmp := compareNumeric(aID, bID); cmp != 0 {
				return cmp, nil
			}
		case aNum != bNum:
			if aNum {
				return -1, nil
			}
			return 1, nil
		default:
			if cmp := strings.Compare(aID, bID); cmp != 0 {
				return cmp, nil
			}
		}
	}
	switch {
	case len(a.prerelease) < len(b.prerelease):
		return -1, nil
	case len(a.prerelease) > len(b.prerelease):
		return 1, nil
	default:
		return 0, nil
	}
}

func parseSemver(value string) (semanticVersion, error) {
	var out semanticVersion
	value = strings.TrimPrefix(value, "v")
	if value == "" || value == "dev" || strings.Count(value, "+") > 1 {
		return out, ErrInvalidSemver
	}
	main, build, hasBuild := strings.Cut(value, "+")
	if hasBuild && !validIdentifiers(build, false) {
		return out, ErrInvalidSemver
	}
	core, pre, hasPre := strings.Cut(main, "-")
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return out, ErrInvalidSemver
	}
	for i, part := range parts {
		if !numericIdentifier(part) {
			return out, ErrInvalidSemver
		}
		out.core[i] = part
	}
	if hasPre {
		if !validIdentifiers(pre, true) {
			return out, ErrInvalidSemver
		}
		out.prerelease = strings.Split(pre, ".")
	}
	return out, nil
}

func validIdentifiers(value string, prerelease bool) bool {
	if value == "" {
		return false
	}
	for _, id := range strings.Split(value, ".") {
		if id == "" {
			return false
		}
		for _, r := range id {
			if (r < '0' || r > '9') && (r < 'A' || r > 'Z') && (r < 'a' || r > 'z') && r != '-' {
				return false
			}
		}
		if prerelease && len(id) > 1 && id[0] == '0' && allDigits(id) {
			return false
		}
	}
	return true
}

func allDigits(value string) bool {
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return value != ""
}

func numericIdentifier(value string) bool {
	if value == "" || len(value) > 1 && value[0] == '0' {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func compareNumeric(a, b string) int {
	if len(a) != len(b) {
		if len(a) < len(b) {
			return -1
		}
		return 1
	}
	return strings.Compare(a, b)
}
