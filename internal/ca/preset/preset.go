// Package preset loads and validates certificate presets – profiles such as
// "server" or "smime" that decide which key usages, extended key usages and
// subject alternative names an end-entity certificate gets.
//
// These values always come from the preset, never from a CSR: copying
// extensions from a request could, for example, turn a leaf into a CA
// (.claude/skills/myownpki/references/pki-rules.md §6).
//
// The built-in presets live in /presets/*.yaml (see presets/README.md for the
// file format) and were ported from legacy/lib/presets.sh.
package preset

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/Der-Felix/MyOwnPKI/presets"
)

// MaxFileSize limits a single preset file. Presets are small; the limit keeps a
// malformed or hostile file from exhausting memory once presets can be uploaded.
const MaxFileSize = 64 << 10

// ErrInvalid is wrapped by every error about a malformed or inconsistent preset.
var ErrInvalid = errors.New("invalid preset")

// SANType is a kind of subject alternative name.
type SANType string

// Subject alternative name types.
const (
	SANDNS   SANType = "dns"
	SANIP    SANType = "ip"
	SANEmail SANType = "email"
	SANURI   SANType = "uri"
)

// Family groups presets that share deployment guides and config examples
// (legacy preset_family).
type Family string

// Preset families.
const (
	FamilyServer    Family = "server"
	FamilyVPNServer Family = "vpnserver"
	FamilyClient    Family = "client"
	FamilyCodeSign  Family = "codesign"
	FamilyOCSP      Family = "ocsp"
	FamilyTimestamp Family = "timestamp"
	FamilyCustom    Family = "custom"
)

// Preset is one certificate profile. Values returned by a Set must not be modified.
type Preset struct {
	Name            string      `yaml:"name"`
	Description     string      `yaml:"description"`
	Usage           string      `yaml:"usage"`
	Family          Family      `yaml:"family"`
	ValidityDays    int         `yaml:"validity_days"`
	KeyUsage        KeyUsage    `yaml:"key_usage"`
	ExtKeyUsage     ExtKeyUsage `yaml:"ext_key_usage"`
	SubjectAltNames SANRules    `yaml:"subject_alt_names"`
	// CommonNameFrom names the SAN type the CN is derived from ("" = entered freely).
	CommonNameFrom SANType `yaml:"common_name_from"`
	// OpenSSLPurpose is the `openssl verify -purpose` that certificates of this
	// preset must pass ("any" = no purpose check).
	OpenSSLPurpose string `yaml:"openssl_purpose"`
	// OCSPNoCheck adds id-pkix-ocsp-nocheck (RFC 6960 §4.2.2.2.1).
	OCSPNoCheck bool `yaml:"ocsp_no_check"`
	// Customizable allows key usage and EKU to be chosen per certificate.
	Customizable bool `yaml:"customizable"`

	// Resolved during validation.
	keyUsageRSA     x509.KeyUsage
	keyUsageOther   x509.KeyUsage
	extKeyUsageStd  []x509.ExtKeyUsage
	extKeyUsageRest []asn1.ObjectIdentifier
	extKeyUsageAll  []asn1.ObjectIdentifier
}

// KeyUsage lists key usage names per key type.
type KeyUsage struct {
	RSA   []string `yaml:"rsa"`
	Other []string `yaml:"other"` // ECDSA and Ed25519
}

// ExtKeyUsage lists extended key usages by name or dotted OID.
type ExtKeyUsage struct {
	Usages   []string `yaml:"usages"`
	Critical bool     `yaml:"critical"`
}

// SANRules says which subject alternative names a certificate needs and may have.
type SANRules struct {
	// RequiredAnyOf: at least one SAN of one of these types is required.
	RequiredAnyOf []SANType `yaml:"required_any_of"`
	Offered       []SANType `yaml:"offered"`
}

// KeyUsageFor returns the key usage bits for a certificate whose public key
// uses alg: RSA keys get the "rsa" list, all other keys the "other" list.
func (p *Preset) KeyUsageFor(alg x509.PublicKeyAlgorithm) x509.KeyUsage {
	if alg == x509.RSA {
		return p.keyUsageRSA
	}
	return p.keyUsageOther
}

// ExtKeyUsages returns the EKUs crypto/x509 knows by constant and, separately,
// the remaining ones as OIDs (for x509.Certificate.UnknownExtKeyUsage).
func (p *Preset) ExtKeyUsages() ([]x509.ExtKeyUsage, []asn1.ObjectIdentifier) {
	return slices.Clone(p.extKeyUsageStd), cloneOIDs(p.extKeyUsageRest)
}

// ExtKeyUsageOIDs returns every EKU as an OID, in file order. Needed when the
// extension must be marked critical, which crypto/x509 can't do by itself.
func (p *Preset) ExtKeyUsageOIDs() []asn1.ObjectIdentifier {
	return cloneOIDs(p.extKeyUsageAll)
}

func cloneOIDs(in []asn1.ObjectIdentifier) []asn1.ObjectIdentifier {
	if in == nil {
		return nil
	}
	out := make([]asn1.ObjectIdentifier, len(in))
	for i, oid := range in {
		out[i] = slices.Clone(oid)
	}
	return out
}

// Parse decodes and validates one preset file. filename is only used in error
// messages. Unknown fields are errors, so a typo can't silently drop a setting.
func Parse(filename string, data []byte) (*Preset, error) {
	if len(data) > MaxFileSize {
		return nil, fmt.Errorf("%s: %w: file is larger than %d bytes", filename, ErrInvalid, MaxFileSize)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)

	var p Preset
	if err := dec.Decode(&p); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("%s: %w: file is empty", filename, ErrInvalid)
		}
		return nil, fmt.Errorf("%s: %w: %w", filename, ErrInvalid, err)
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%s: %w: only one YAML document per file is allowed", filename, ErrInvalid)
	}

	if problems := p.validate(); len(problems) > 0 {
		return nil, fmt.Errorf("%s: %w:\n  - %s", filename, ErrInvalid, strings.Join(problems, "\n  - "))
	}
	return &p, nil
}

// Set is a validated collection of presets, keyed by name.
type Set struct {
	byName map[string]*Preset
	names  []string
}

// Builtin loads the presets shipped in the binary.
func Builtin() (*Set, error) {
	return Load(presets.FS)
}

// Load reads and validates every *.yaml file in the root of fsys. The preset
// name must match the file name. All problems are reported together.
func Load(fsys fs.FS) (*Set, error) {
	files, err := fs.Glob(fsys, "*.yaml")
	if err != nil {
		return nil, fmt.Errorf("list presets: %w", err)
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("%w: no *.yaml files found", ErrInvalid)
	}

	s := &Set{byName: make(map[string]*Preset, len(files))}
	var errs []error
	for _, file := range files {
		p, err := loadFile(fsys, file)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		s.byName[p.Name] = p
		s.names = append(s.names, p.Name)
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	slices.Sort(s.names)
	return s, nil
}

func loadFile(fsys fs.FS, file string) (*Preset, error) {
	info, err := fs.Stat(fsys, file)
	if err != nil {
		return nil, fmt.Errorf("read preset %s: %w", file, err)
	}
	if info.Size() > MaxFileSize {
		return nil, fmt.Errorf("%s: %w: file is larger than %d bytes", file, ErrInvalid, MaxFileSize)
	}
	data, err := fs.ReadFile(fsys, file)
	if err != nil {
		return nil, fmt.Errorf("read preset %s: %w", file, err)
	}
	p, err := Parse(file, data)
	if err != nil {
		return nil, err
	}
	if want := strings.TrimSuffix(file, ".yaml"); p.Name != want {
		return nil, fmt.Errorf("%s: %w: name %q must match the file name (%q)", file, ErrInvalid, p.Name, want)
	}
	return p, nil
}

// Get returns the preset with the given name.
func (s *Set) Get(name string) (*Preset, bool) {
	p, ok := s.byName[name]
	return p, ok
}

// Names returns all preset names, sorted.
func (s *Set) Names() []string {
	return slices.Clone(s.names)
}
