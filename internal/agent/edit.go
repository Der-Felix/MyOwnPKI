package agent

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

// The editor of agent.yaml for "deployment add|remove" and "sandbox sync".
// It works on the yaml.Node tree of go.yaml.in/yaml/v3, so comments and the
// order of keys stay. What the library cannot keep:
//
//   - blank lines are dropped; the ones between top-level blocks are put
//     back (restoreBlankLines), the ones inside a block are not
//   - the space before a trailing comment becomes one space
//   - a file that uses anchors, aliases, merge keys or several documents is
//     refused, because an edit could not tell which copy it changes
//
// The caller always checks the result with ParseConfig before it writes a byte.

// errYAMLFeatures is the one message for everything the editor refuses.
var errYAMLFeatures = errors.New("agent.yaml uses anchors, aliases or several documents – edit it by hand and run config check")

// topLevelOrder is the order in which new top-level keys are inserted: before
// the first existing key that comes later in this list, else at the end.
var topLevelOrder = []string{"server", "ca_bundle", "hostname", "acme_directory", "proxy", "state_dir", "log_level",
	"enrollment", "dns_providers", "hooks", "paths", "sandbox", "system_trust", "deployments"}

type yamlEditor struct {
	orig    []byte
	doc     yaml.Node
	root    *yaml.Node
	changed bool
	// plain: the file writes its scalars unquoted, so new ones are too.
	plain bool
}

func openYAMLEditor(data []byte) (*yamlEditor, error) {
	e := &yamlEditor{orig: data}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&e.doc); err != nil {
		return nil, fmt.Errorf("agent.yaml: %w", err)
	}
	var second yaml.Node
	if err := dec.Decode(&second); !errors.Is(err, io.EOF) {
		return nil, errYAMLFeatures
	}
	if e.doc.Kind != yaml.DocumentNode || len(e.doc.Content) != 1 || e.doc.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("agent.yaml: the top level must be a mapping")
	}
	e.root = e.doc.Content[0]
	for _, key := range []string{"hostname", "server"} {
		if v := mapGet(e.root, key); v != nil && v.Kind == yaml.ScalarNode {
			e.plain = v.Style == 0
			break
		}
	}
	unsupported := false
	var walk func(*yaml.Node)
	walk = func(n *yaml.Node) {
		if n.Anchor != "" || n.Kind == yaml.AliasNode || n.Tag == "!!merge" {
			unsupported = true
		}
		for _, c := range n.Content {
			walk(c)
		}
	}
	walk(&e.doc)
	if unsupported {
		return nil, errYAMLFeatures
	}
	return e, nil
}

// bytes renders the document; an unchanged document returns the input.
func (e *yamlEditor) bytes() ([]byte, error) {
	if !e.changed {
		return e.orig, nil
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&e.doc); err != nil {
		return nil, fmt.Errorf("render agent.yaml: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("render agent.yaml: %w", err)
	}
	return restoreBlankLines(e.orig, buf.Bytes()), nil
}

var plainSafe = regexp.MustCompile(`^[a-z][a-z0-9.-]*$`)

// str is a new string value in the style of the file: plain (names, profiles,
// owners – never paths or commands) where the file
// writes its host name plain and the value cannot be mistaken for another
// type, double-quoted otherwise (as "myownpki-agent setup" writes it).
func (e *yamlEditor) str(v string) *yaml.Node {
	n := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: v, Style: yaml.DoubleQuotedStyle}
	if e.plain && plainSafe.MatchString(v) && !slices.Contains([]string{"true", "false", "null", "yes", "no", "on", "off", "y", "n"}, strings.ToLower(v)) {
		n.Style = 0
	}
	return n
}

// flowList is a flow sequence; a command line is always quoted, so that its
// words cannot be mistaken for anything else.
func (e *yamlEditor) flowList(quoted bool, values ...string) *yaml.Node {
	n := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Style: yaml.FlowStyle}
	for _, v := range values {
		item := e.str(v)
		if quoted {
			item.Style = yaml.DoubleQuotedStyle
		}
		n.Content = append(n.Content, item)
	}
	return n
}

func plainKey(k string) *yaml.Node { return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: k} }

func boolNode(v bool) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: fmt.Sprint(v)}
}

// mapGet returns the value node of a mapping entry (nil: no such key).
func mapGet(m *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

func isNull(n *yaml.Node) bool { return n.Kind == yaml.ScalarNode && n.Tag == "!!null" }

// insertPos is where a new top-level key goes.
func (e *yamlEditor) insertPos(key string) int {
	rank := slices.Index(topLevelOrder, key)
	if rank >= 0 {
		for i := 0; i+1 < len(e.root.Content); i += 2 {
			if slices.Index(topLevelOrder, e.root.Content[i].Value) > rank {
				return i
			}
		}
	}
	return len(e.root.Content)
}

func newCollection(kind yaml.Kind) *yaml.Node {
	if kind == yaml.SequenceNode {
		return &yaml.Node{Kind: kind, Tag: "!!seq"}
	}
	return &yaml.Node{Kind: kind, Tag: "!!map"}
}

// ensure returns the value of key as a collection of the wanted kind,
// creating it (a new top-level key in canonical order) or replacing an empty
// one. A different kind is an error: the operator wrote something we do not
// understand.
func (e *yamlEditor) ensure(m *yaml.Node, key string, kind yaml.Kind) (*yaml.Node, error) {
	v := mapGet(m, key)
	switch {
	case v != nil && v.Kind == kind:
		return v, nil
	case v != nil && isNull(v):
		*v = *newCollection(kind)
	case v != nil:
		name := "mapping"
		if kind == yaml.SequenceNode {
			name = "list"
		}
		return nil, fmt.Errorf("agent.yaml: %q is not a %s – edit it by hand", key, name)
	default:
		v = newCollection(kind)
		pos := len(m.Content)
		if m == e.root {
			pos = e.insertPos(key)
		}
		m.Content = slices.Insert(m.Content, pos, plainKey(key), v)
	}
	e.changed = true
	return v, nil
}

// block turns an empty flow collection ([] or {}) into a block collection,
// which is what an appended deployment or hook needs.
func block(n *yaml.Node) {
	if len(n.Content) == 0 {
		n.Style = 0
	}
}

// setScalar sets a top-level string.
func (e *yamlEditor) setScalar(key, value string) {
	if v := mapGet(e.root, key); v != nil && v.Kind == yaml.ScalarNode {
		if v.Value != value || isNull(v) {
			*v = *e.str(value)
			e.changed = true
		}
		return
	}
	e.root.Content = slices.Insert(e.root.Content, e.insertPos(key), plainKey(key), e.str(value))
	e.changed = true
}

// addStrings appends the values that the list under parent[key] does not hold.
func (e *yamlEditor) addStrings(parent *yaml.Node, key string, values ...string) error {
	if len(values) == 0 {
		return nil
	}
	seq, err := e.ensure(parent, key, yaml.SequenceNode)
	if err != nil {
		return err
	}
	for _, v := range values {
		if slices.ContainsFunc(seq.Content, func(n *yaml.Node) bool { return n.Value == v }) {
			continue
		}
		seq.Content = append(seq.Content, e.str(v))
		e.changed = true
	}
	return nil
}

func (e *yamlEditor) addPaths(paths ...string) error {
	return e.addStrings(e.root, "paths", paths...)
}

// removePaths removes the entries (compared after Clean) from paths.
func (e *yamlEditor) removePaths(paths ...string) {
	seq := mapGet(e.root, "paths")
	if seq == nil || seq.Kind != yaml.SequenceNode {
		return
	}
	n := len(seq.Content)
	seq.Content = slices.DeleteFunc(seq.Content, func(item *yaml.Node) bool {
		return slices.ContainsFunc(paths, func(p string) bool { return filepath.Clean(p) == filepath.Clean(item.Value) })
	})
	if len(seq.Content) != n {
		e.changed = true
		if len(seq.Content) == 0 {
			seq.Style = yaml.FlowStyle
		}
	}
}

func (e *yamlEditor) sandbox() (*yaml.Node, error) {
	m, err := e.ensure(e.root, "sandbox", yaml.MappingNode)
	if err == nil {
		block(m)
	}
	return m, err
}

func (e *yamlEditor) addSandboxWrite(dirs ...string) error {
	if len(dirs) == 0 {
		return nil
	}
	m, err := e.sandbox()
	if err != nil {
		return err
	}
	return e.addStrings(m, "write", dirs...)
}

// setLowPortsTrue records sandbox.low_ports: true.
func (e *yamlEditor) setLowPortsTrue() error {
	m, err := e.sandbox()
	if err != nil {
		return err
	}
	if v := mapGet(m, "low_ports"); v != nil {
		if v.Value != "true" {
			*v = *boolNode(true)
			e.changed = true
		}
		return nil
	}
	m.Content = append(m.Content, plainKey("low_ports"), boolNode(true))
	e.changed = true
	return nil
}

// setSystemTrust records system_trust.root_sha256 (lower-case hex), always
// double-quoted so that a hash of digits only cannot be read as a number.
func (e *yamlEditor) setSystemTrust(pin string) error {
	m, err := e.ensure(e.root, trustConfigKey, yaml.MappingNode)
	if err != nil {
		return err
	}
	block(m)
	node := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: pin, Style: yaml.DoubleQuotedStyle}
	if v := mapGet(m, "root_sha256"); v != nil {
		if !strings.EqualFold(v.Value, pin) || v.Tag != "!!str" {
			*v = *node
			e.changed = true
		}
		return nil
	}
	m.Content = append(m.Content, plainKey("root_sha256"), node)
	e.changed = true
	return nil
}

// removeSystemTrust deletes the key; there is nothing to do without one.
func (e *yamlEditor) removeSystemTrust() {
	for i := 0; i+1 < len(e.root.Content); i += 2 {
		if e.root.Content[i].Value == trustConfigKey {
			e.root.Content = slices.Delete(e.root.Content, i, i+2)
			e.changed = true
			return
		}
	}
}

// addHook defines a hook; the caller has already checked that the name is free.
func (e *yamlEditor) addHook(name string, command []string) error {
	m, err := e.ensure(e.root, "hooks", yaml.MappingNode)
	if err != nil {
		return err
	}
	block(m)
	m.Content = append(m.Content, plainKey(name), e.flowList(true, command...))
	e.changed = true
	return nil
}

// deploymentNode is the block mapping of a new deployment, keys in the
// order of docs/OPERATIONS.md §12.3.
func (e *yamlEditor) deploymentNode(d Deployment) *yaml.Node {
	m := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	addStr := func(parent *yaml.Node, k, v string) {
		if v != "" {
			parent.Content = append(parent.Content, plainKey(k), e.str(v))
		}
	}
	addStr(m, "name", d.Name)
	addStr(m, "profile", d.Profile)
	m.Content = append(m.Content, plainKey("names"), e.flowList(false, d.Names...))
	addStr(m, "challenge", d.Challenge)
	addStr(m, "webroot", d.Webroot)
	addStr(m, "dns_provider", d.DNSProvider)
	addStr(m, "dir", d.Dir)
	if d.Files != (Files{}) {
		files := newCollection(yaml.MappingNode)
		addStr(files, "certificate", d.Files.Certificate)
		addStr(files, "chain", d.Files.Chain)
		addStr(files, "fullchain", d.Files.Fullchain)
		addStr(files, "key", d.Files.Key)
		m.Content = append(m.Content, plainKey("files"), files)
	}
	addStr(m, "owner", d.Owner)
	addStr(m, "group", d.Group)
	addStr(m, "key_mode", d.KeyMode)
	addStr(m, "test_hook", d.TestHook)
	addStr(m, "reload_hook", d.ReloadHook)
	addStr(m, "check", d.Check)
	addStr(m, "check_name", d.CheckName)
	return m
}

// addDNSProvider adds the entry dns_providers.<name>; the caller has already
// checked that the name is free. Only the keys that were given are written, so
// ttl and propagation stay at their defaults until somebody sets them.
func (e *yamlEditor) addDNSProvider(name string, p DNSProvider) error {
	m, err := e.ensure(e.root, "dns_providers", yaml.MappingNode)
	if err != nil {
		return err
	}
	block(m)
	if mapGet(m, name) != nil {
		return fmt.Errorf("agent.yaml: dns_providers.%s exists – edit it by hand", name)
	}
	entry := newCollection(yaml.MappingNode)
	for _, kv := range []struct{ key, value string }{{"type", p.Type}, {"credentials_file", p.CredentialsFile},
		{"nameserver", p.Nameserver}, {"zone", p.Zone}, {"resolver", p.Resolver}} {
		if kv.value != "" {
			entry.Content = append(entry.Content, plainKey(kv.key), e.str(kv.value))
		}
	}
	m.Content = append(m.Content, plainKey(name), entry)
	e.changed = true
	return nil
}

func (e *yamlEditor) addDeployment(d Deployment) error {
	seq, err := e.ensure(e.root, "deployments", yaml.SequenceNode)
	if err != nil {
		return err
	}
	block(seq)
	seq.Content = append(seq.Content, e.deploymentNode(d))
	e.changed = true
	return nil
}

// removeDeployment deletes the entry called name; false: there is none.
func (e *yamlEditor) removeDeployment(name string) bool {
	seq := mapGet(e.root, "deployments")
	if seq == nil || seq.Kind != yaml.SequenceNode {
		return false
	}
	for i, item := range seq.Content {
		if v := mapGet(item, "name"); v != nil && v.Value == name {
			seq.Content = slices.Delete(seq.Content, i, i+1)
			if len(seq.Content) == 0 {
				seq.Style = yaml.FlowStyle
			}
			e.changed = true
			return true
		}
	}
	return false
}

var topLevelLine = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_-]*):`)

// anchorOf is how restoreBlankLines recognizes the start of a block: the key
// name of a top-level line, or the text of a top-level comment.
func anchorOf(line string) (string, bool) {
	if m := topLevelLine.FindStringSubmatch(line); m != nil {
		return m[1] + ":", true
	}
	if strings.HasPrefix(line, "#") {
		return strings.TrimRight(line, " \t\r"), true
	}
	return "", false
}

// restoreBlankLines puts back the blank line before a top-level key or
// comment block that had one in the original file (yaml.v3 drops them all).
func restoreBlankLines(orig, out []byte) []byte {
	anchors := map[string]bool{}
	lines := strings.Split(string(orig), "\n")
	for i := 1; i < len(lines); i++ {
		if strings.TrimSpace(lines[i-1]) != "" {
			continue
		}
		if a, ok := anchorOf(lines[i]); ok {
			anchors[a] = true
		}
	}
	if len(anchors) == 0 {
		return out
	}
	var res []string
	for _, line := range strings.Split(string(out), "\n") {
		if a, ok := anchorOf(line); ok && anchors[a] && len(res) > 0 && strings.TrimSpace(res[len(res)-1]) != "" {
			res = append(res, "")
		}
		res = append(res, line)
	}
	return []byte(strings.Join(res, "\n"))
}
