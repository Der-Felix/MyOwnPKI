package agent

// fileField is one target of the file profile: the key it has in agent.yaml
// (and, with "--" in front, the flag of "deployment add") and its path.
type fileField struct {
	Name string
	Path string
}

// fields lists every target of the file profile in one fixed order, empty
// ones included. Every place that has to look at all targets goes through
// this list (or through Targets, CertPath, KeyPath and Map built on it), so a
// new target is added in one place.
func (f Files) fields() []fileField {
	return []fileField{
		{"certificate", f.Certificate}, {"chain", f.Chain},
		{"fullchain", f.Fullchain}, {"key", f.Key}, {"combined", f.Combined},
	}
}

// Targets are the paths the deployment writes, in the fixed order of fields,
// without the empty ones.
func (f Files) Targets() []string {
	var out []string
	for _, field := range f.fields() {
		if field.Path != "" {
			out = append(out, field.Path)
		}
	}
	return out
}

// CertPath is the file that starts with the certificate: the combined file
// (certificate chain first, key last), else the full chain, else the
// certificate alone. The agent reads it back for the expiry, the leaf and the
// previous pair.
func (f Files) CertPath() string {
	if f.Combined != "" {
		return f.Combined
	}
	if f.Fullchain != "" {
		return f.Fullchain
	}
	return f.Certificate
}

// KeyPath is the file that holds the private key: the combined file, else the
// key file.
func (f Files) KeyPath() string {
	if f.Combined != "" {
		return f.Combined
	}
	return f.Key
}

// Map returns the files with fn applied to every path (empty ones stay
// empty if fn keeps them so).
func (f Files) Map(fn func(string) string) Files {
	return Files{Certificate: fn(f.Certificate), Chain: fn(f.Chain), Fullchain: fn(f.Fullchain), Key: fn(f.Key), Combined: fn(f.Combined)}
}
