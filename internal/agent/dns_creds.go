package agent

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"unicode"

	"go.yaml.in/yaml/v3"
)

// Credentials files of the DNS providers (docs/PHASE3.md §13.2, decision 2).
//
// A TSIG key or an API token decides who may change the zone, so the agent
// treats the file like a private key: it is opened without following a
// symbolic link, everything is checked on the open descriptor, the content is
// parsed with strict keys, and the values live in the type secret, which
// prints as [redacted] wherever a Go program might print it. A failing check
// names the problem and the path, never the content.

const (
	// maxCredentialsSize bounds the read; a token or a key is a few hundred bytes.
	maxCredentialsSize = 4 << 10
	redacted           = "[redacted]"
)

// Credentials file states, as `config check` reports them.
const (
	credOK         = "ok"
	credMissing    = "missing"
	credWrongMode  = "wrong mode"
	credWrongOwner = "wrong owner"
	credUnsafeDir  = "unsafe directory"
	credSymlink    = "symbolic link"
	credNotRegular = "not a regular file"
	credTooLarge   = "too large"
	credUnreadable = "unreadable"
	credInvalid    = "invalid"
)

// credentialsError says what is wrong with a credentials file. Neither field
// ever holds a value of the file.
type credentialsError struct {
	State  string // one of the cred* constants
	Path   string
	Detail string
}

func (e *credentialsError) Error() string {
	if e.Detail == "" {
		return fmt.Sprintf("credentials file %s: %s", e.Path, e.State)
	}
	return fmt.Sprintf("credentials file %s: %s: %s", e.Path, e.State, e.Detail)
}

// secret is a value that must never reach a log, an error, a report or a
// `%v` of any struct. Every way Go has to print it yields [redacted]; the
// bytes are reachable only through reveal and snapshot.
//
// The bytes are held by closures, not by a field. fmt prints a struct in
// an unexported field by reflection, bypassing every method, and it prints
// what a pointer to a struct or a slice points to for verbs like %s and %q;
// a func value prints as an address only. So no spelling of a struct that
// holds a secret shows a byte of it. A secret is not comparable (== does not
// compile), which is intended.
//
// A guard may wipe the secret while a timed-out CleanUp is still running in
// its own goroutine. The closures share a lock, and code that can run at that
// time (the TSIG signature, the redaction) reads a snapshot, a copy made under
// the lock, so that no read overlaps the overwriting.
type secret struct {
	read  func() []byte
	snap  func() []byte
	erase func()
}

func newSecret(b []byte) secret {
	var mu sync.RWMutex
	buf := bytes.Clone(b)
	return secret{
		read: func() []byte {
			mu.RLock()
			defer mu.RUnlock()
			return buf
		},
		snap: func() []byte {
			mu.RLock()
			defer mu.RUnlock()
			return bytes.Clone(buf)
		},
		erase: func() {
			mu.Lock()
			defer mu.Unlock()
			clear(buf)
			buf = nil
		},
	}
}

// reveal returns the bytes themselves, which wipe overwrites. Use it only
// where nothing can wipe the secret at the same time; otherwise use snapshot.
func (s secret) reveal() []byte {
	if s.read == nil {
		return nil
	}
	return s.read()
}

// snapshot returns a copy of the value, safe against a concurrent wipe. The
// caller clears it when it is done; after a wipe it is nil.
func (s secret) snapshot() []byte {
	if s.snap == nil {
		return nil
	}
	return s.snap()
}

func (s secret) isSet() bool { return len(s.reveal()) > 0 }

// wipe overwrites the value for every copy of s.
func (s secret) wipe() {
	if s.erase != nil {
		s.erase()
	}
}

func (secret) String() string               { return redacted }
func (secret) GoString() string             { return redacted }
func (secret) Format(f fmt.State, _ rune)   { _, _ = io.WriteString(f, redacted) }
func (secret) LogValue() slog.Value         { return slog.StringValue(redacted) }
func (secret) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }
func (secret) MarshalText() ([]byte, error) { return []byte(redacted), nil }
func (secret) MarshalYAML() (any, error)    { return redacted, nil }

// dnsCredentials is the content of a credentials file. Only the fields of its
// provider type are set.
type dnsCredentials struct {
	Type string

	// rfc2136
	TSIGKeyName   string
	TSIGAlgorithm string
	TSIGSecret    secret // base64, as in BIND's key statement

	// cloudflare
	APIToken  secret
	ZoneToken secret // optional: only if Zone:Read is split from DNS:Edit
}

func (c dnsCredentials) String() string   { return "DNS credentials (secrets redacted)" }
func (c dnsCredentials) GoString() string { return c.String() }
func (c dnsCredentials) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, c.String())
}
func (c dnsCredentials) LogValue() slog.Value { return slog.StringValue(c.String()) }
func (c dnsCredentials) MarshalJSON() ([]byte, error) {
	return []byte(`"` + c.String() + `"`), nil
}

func (c *dnsCredentials) secrets() []secret {
	return []secret{c.TSIGSecret, c.APIToken, c.ZoneToken}
}

// wipe overwrites every secret; call it when the issuance is over.
func (c *dnsCredentials) wipe() {
	for _, s := range c.secrets() {
		s.wipe()
	}
}

// redact removes the secrets of c from the text of err.
func (c *dnsCredentials) redact(err error) error { return redact(err, c.secrets()...) }

// redactText replaces every occurrence of a secret in s. The longest secret
// goes first, so one that contains another is removed whole.
func redactText(s string, secrets ...secret) string {
	values := make([]string, 0, len(secrets))
	for _, sec := range secrets {
		if v := sec.snapshot(); len(v) > 0 {
			values = append(values, string(v))
			clear(v)
		}
	}
	slices.SortFunc(values, func(a, b string) int { return len(b) - len(a) })
	for _, v := range values {
		s = strings.ReplaceAll(s, v, redacted)
	}
	return s
}

// redactedError carries the text of an error with the secrets removed. It
// still answers errors.Is and errors.As for the original, but offers no
// Unwrap: a caller that walks the chain would print the unredacted text.
type redactedError struct {
	msg   string
	cause error
}

func (e *redactedError) Error() string { return e.msg }
func (e *redactedError) Is(target error) bool {
	return errors.Is(e.cause, target)
}
func (e *redactedError) As(target any) bool { return errors.As(e.cause, target) }
func (e *redactedError) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, e.msg)
}

// redact returns err with the secrets removed from its text; nil stays nil.
// Every error of a DNS provider goes through it before it is logged, stored
// or reported.
func redact(err error, secrets ...secret) error {
	if err == nil {
		return nil
	}
	return &redactedError{msg: redactText(err.Error(), secrets...), cause: err}
}

// credsEnv is what loadDNSCredentials asks the operating system; tests
// replace parts of it (a foreign owner needs no root that way).
type credsEnv struct {
	// enforce: check mode, owner and directory. False where the platform has no
	// POSIX modes (Windows), like the check of the enrollment token file.
	enforce bool
	// uidOf is the owner of a file or directory; ok is false without uids.
	uidOf func(os.FileInfo) (uid int, ok bool)
	// euid is the user the agent runs as.
	euid int
	// statDir stats the directory that holds the file.
	statDir func(path string) (os.FileInfo, error)
}

func defaultCredsEnv() credsEnv {
	return credsEnv{enforce: credsEnforcePermissions, uidOf: fileUID, euid: effectiveUID(), statDir: os.Stat}
}

// loadDNSCredentials reads and checks the credentials file of a provider of
// the given type. Call it when an issuance starts, so a changed file works
// at the next renewal, and wipe the result when the issuance is over.
func loadDNSCredentials(path, typ string) (*dnsCredentials, error) {
	return loadDNSCredentialsEnv(path, typ, defaultCredsEnv())
}

func loadDNSCredentialsEnv(path, typ string, env credsEnv) (*dnsCredentials, error) {
	if !slices.Contains([]string{DNSTypeRFC2136, DNSTypeCloudflare}, typ) {
		return nil, &credentialsError{State: credInvalid, Path: path, Detail: "unknown provider type"}
	}
	f, err := openCredentialsFile(path)
	if err != nil {
		return nil, openCredentialsProblem(path, err)
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return nil, &credentialsError{State: credUnreadable, Path: path, Detail: errnoText(err)}
	}
	if !fi.Mode().IsRegular() {
		return nil, &credentialsError{State: credNotRegular, Path: path, Detail: "want a plain file, not a directory, device or pipe"}
	}
	if problem := env.check(path, fi); problem != nil {
		return nil, problem
	}
	if fi.Size() > maxCredentialsSize {
		return nil, &credentialsError{State: credTooLarge, Path: path, Detail: fmt.Sprintf("more than %d bytes", maxCredentialsSize)}
	}
	data, err := io.ReadAll(io.LimitReader(f, maxCredentialsSize+1))
	defer clear(data)
	if err != nil {
		return nil, &credentialsError{State: credUnreadable, Path: path, Detail: errnoText(err)}
	}
	if len(data) > maxCredentialsSize {
		return nil, &credentialsError{State: credTooLarge, Path: path, Detail: fmt.Sprintf("more than %d bytes", maxCredentialsSize)}
	}
	return parseDNSCredentials(path, typ, data)
}

// check applies the rules of the file that was opened: mode 0600 or 0400
// without special bits, owner root or the agent's user, and a parent
// directory that group and others cannot write and that root or the agent's
// user owns. Anyone who can write the directory can replace the file.
func (e credsEnv) check(path string, fi os.FileInfo) *credentialsError {
	if !e.enforce {
		return nil
	}
	mode := fi.Mode()
	if special := mode & (os.ModeSetuid | os.ModeSetgid | os.ModeSticky); special != 0 {
		return &credentialsError{State: credWrongMode, Path: path, Detail: "setuid, setgid or sticky bit is set, want 0600 or 0400"}
	}
	if perm := mode.Perm(); perm != 0o600 && perm != 0o400 {
		return &credentialsError{State: credWrongMode, Path: path, Detail: fmt.Sprintf("is %04o, want 0600 or 0400", perm)}
	}
	if problem := e.ownerProblem(fi); problem != "" {
		return &credentialsError{State: credWrongOwner, Path: path, Detail: problem}
	}
	dir := filepath.Dir(path)
	di, err := e.statDir(dir)
	if err != nil {
		return &credentialsError{State: credUnsafeDir, Path: path, Detail: "directory " + dir + ": " + errnoText(err)}
	}
	if !di.IsDir() {
		return &credentialsError{State: credUnsafeDir, Path: path, Detail: dir + " is not a directory"}
	}
	if perm := di.Mode().Perm(); perm&0o022 != 0 {
		return &credentialsError{State: credUnsafeDir, Path: path, Detail: fmt.Sprintf("directory %s has mode %04o and can be written by group or others", dir, perm)}
	}
	if problem := e.ownerProblem(di); problem != "" {
		return &credentialsError{State: credUnsafeDir, Path: path, Detail: "directory " + dir + ": " + problem}
	}
	return nil
}

func (e credsEnv) ownerProblem(fi os.FileInfo) string {
	uid, ok := e.uidOf(fi)
	switch {
	case !ok:
		return "the owner cannot be determined"
	case uid != 0 && uid != e.euid:
		return fmt.Sprintf("owned by uid %d, want root or the agent's user (uid %d)", uid, e.euid)
	}
	return ""
}

// openCredentialsProblem turns the error of the open into a state.
func openCredentialsProblem(path string, err error) *credentialsError {
	switch {
	case errors.Is(err, os.ErrNotExist):
		return &credentialsError{State: credMissing, Path: path, Detail: "no such file"}
	case isSymlinkOpenError(err):
		return &credentialsError{State: credSymlink, Path: path, Detail: "the agent does not follow links; set credentials_file to the real file"}
	case errors.Is(err, os.ErrPermission):
		return &credentialsError{State: credUnreadable, Path: path, Detail: "permission denied (run as root or the agent's user)"}
	}
	return &credentialsError{State: credUnreadable, Path: path, Detail: errnoText(err)}
}

// errnoText is the operating system's text without the path of a PathError.
func errnoText(err error) string {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return pe.Err.Error()
	}
	return err.Error()
}

var (
	keyShapeRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	lineRE     = regexp.MustCompile(`line (\d+)`)
	tsigNameRE = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,252}$`)
)

// credentialKeys are the keys of a file, by provider type; the first group is
// required.
var credentialKeys = map[string]struct{ required, optional []string }{
	DNSTypeRFC2136:    {required: []string{"tsig_key_name", "tsig_secret"}, optional: []string{"tsig_algorithm"}},
	DNSTypeCloudflare: {required: []string{"api_token"}, optional: []string{"zone_token"}},
}

var tsigAlgorithms = []string{"hmac-sha256", "hmac-sha384", "hmac-sha512"}

// parseDNSCredentials decodes a credentials file with strict keys. It does
// not decode into a struct: the YAML library puts the offending value into
// some of its error texts, and this text must never hold part of a secret.
func parseDNSCredentials(path, typ string, data []byte) (*dnsCredentials, error) {
	bad := func(format string, args ...any) error {
		return &credentialsError{State: credInvalid, Path: path, Detail: fmt.Sprintf(format, args...)}
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, bad("the file is empty")
		}
		if m := lineRE.FindStringSubmatch(err.Error()); m != nil {
			return nil, bad("not valid YAML near line %s", m[1])
		}
		return nil, bad("not valid YAML")
	}
	var second yaml.Node
	if err := dec.Decode(&second); !errors.Is(err, io.EOF) {
		return nil, bad("want one YAML document")
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, bad("the top level must be a mapping of keys to values")
	}
	keys := credentialKeys[typ]
	allowed := append(slices.Clone(keys.required), keys.optional...)
	values := map[string]string{}
	pairs := doc.Content[0].Content
	for i := 0; i+1 < len(pairs); i += 2 {
		key, val := pairs[i], pairs[i+1]
		if key.Kind != yaml.ScalarNode || key.Anchor != "" || val.Anchor != "" || val.Kind == yaml.AliasNode {
			return nil, bad("anchors, aliases and complex keys are not supported")
		}
		name := key.Value
		if !slices.Contains(allowed, name) {
			// A key that looks like a name is shown, anything else is not: a
			// file with a pasted secret on the key side must not leak it.
			if keyShapeRE.MatchString(name) {
				return nil, bad("unknown key %q; a %s file has %s", name, typ, strings.Join(allowed, ", "))
			}
			return nil, bad("an unknown key; a %s file has %s", typ, strings.Join(allowed, ", "))
		}
		if _, dup := values[name]; dup {
			return nil, bad("key %s appears twice", name)
		}
		if val.Kind != yaml.ScalarNode {
			return nil, bad("%s: the value must be text", name)
		}
		v := strings.TrimSpace(val.Value)
		switch {
		case val.Tag == "!!null" || v == "":
			return nil, bad("%s: the value is empty", name)
		case strings.IndexFunc(v, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0:
			return nil, bad("%s: the value contains white space or control characters", name)
		}
		values[name] = v
	}
	for _, name := range keys.required {
		if _, ok := values[name]; !ok {
			return nil, bad("%s: required for %s", name, typ)
		}
	}
	c := &dnsCredentials{Type: typ}
	switch typ {
	case DNSTypeCloudflare:
		c.APIToken = newSecret([]byte(values["api_token"]))
		if v, ok := values["zone_token"]; ok {
			c.ZoneToken = newSecret([]byte(v))
		}
	case DNSTypeRFC2136:
		if !tsigNameRE.MatchString(values["tsig_key_name"]) {
			return nil, bad("tsig_key_name: a DNS name such as acme-agent")
		}
		c.TSIGKeyName = values["tsig_key_name"]
		c.TSIGAlgorithm = "hmac-sha256"
		if v, ok := values["tsig_algorithm"]; ok {
			c.TSIGAlgorithm = strings.ToLower(v)
			if !slices.Contains(tsigAlgorithms, c.TSIGAlgorithm) {
				return nil, bad("tsig_algorithm: %s (hmac-md5 and hmac-sha1 are refused)", strings.Join(tsigAlgorithms, ", "))
			}
		}
		raw, err := base64.StdEncoding.DecodeString(values["tsig_secret"])
		clear(raw)
		if err != nil || len(raw) == 0 {
			return nil, bad("tsig_secret: not valid base64, as in BIND's key statement")
		}
		c.TSIGSecret = newSecret([]byte(values["tsig_secret"]))
	}
	return c, nil
}

// DNSProviderStatus is the state of one provider's credentials file, for
// `config check`. It holds no content of the file.
type DNSProviderStatus struct {
	Name   string
	Type   string
	Path   string
	State  string   // ok, missing, wrong mode, ...
	Detail string   // what to change; never a value
	Users  []string // deployments that use the provider
}

// OK reports whether the credentials file can be used.
func (s DNSProviderStatus) OK() bool { return s.State == credOK }

// DNSProviderStatuses loads the credentials file of every provider once to
// see whether it can be used, wipes the result at once, and never reports
// content. The providers come in the order of their names.
func (c *Config) DNSProviderStatuses() []DNSProviderStatus {
	users := map[string][]string{}
	for _, d := range c.Deployments {
		if d.Challenge == ChallengeDNS01 {
			users[d.DNSProvider] = append(users[d.DNSProvider], d.Name)
		}
	}
	var out []DNSProviderStatus
	for _, name := range slices.Sorted(maps.Keys(c.DNSProviders)) {
		p := c.DNSProviders[name]
		st := DNSProviderStatus{Name: name, Type: p.Type, Path: p.CredentialsFile, State: credOK, Users: users[name]}
		creds, err := loadDNSCredentials(p.CredentialsFile, p.Type)
		if err != nil {
			var ce *credentialsError
			if errors.As(err, &ce) {
				st.State, st.Detail = ce.State, ce.Detail
			} else {
				st.State, st.Detail = credInvalid, "cannot be read"
			}
		} else {
			creds.wipe()
		}
		out = append(out, st)
	}
	return out
}
