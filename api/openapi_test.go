package api

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// No OpenAPI linter is a project dependency yet, so this test enforces the
// structural rules that matter for us: valid YAML, OpenAPI 3.1, resolvable
// $refs, unique operation IDs, and the project's security conventions
// (every operation states its role, errors are problem+json, secrets are
// write-only and never travel in URLs).

type node = map[string]any

func loadSpec(t *testing.T) node {
	t.Helper()
	var doc node
	if err := yaml.Unmarshal(Spec, &doc); err != nil {
		t.Fatalf("openapi.yaml is not valid YAML: %v", err)
	}
	return doc
}

func get(n any, path ...string) any {
	for _, p := range path {
		m, ok := n.(node)
		if !ok {
			return nil
		}
		n = m[p]
	}
	return n
}

var httpMethods = []string{"get", "put", "post", "patch", "delete", "head", "options", "trace"}

type operation struct {
	method, path string
	op           node
}

func operations(doc node) []operation {
	var ops []operation
	paths, _ := doc["paths"].(node)
	for path, item := range paths {
		for _, m := range httpMethods {
			if op, ok := get(item, m).(node); ok {
				ops = append(ops, operation{m, path, op})
			}
		}
	}
	slices.SortFunc(ops, func(a, b operation) int { return strings.Compare(a.path+a.method, b.path+b.method) })
	return ops
}

func TestSpecBasics(t *testing.T) {
	t.Parallel()
	doc := loadSpec(t)
	if v, _ := doc["openapi"].(string); !strings.HasPrefix(v, "3.1.") {
		t.Errorf("openapi = %q, want 3.1.x (ADR-05)", v)
	}
	if get(doc, "info", "title") == nil || get(doc, "info", "version") == nil {
		t.Error("info.title and info.version are required")
	}
	if len(operations(doc)) == 0 {
		t.Fatal("no operations found")
	}
}

// TestSpecRefsResolve walks the whole document and resolves every local $ref.
func TestSpecRefsResolve(t *testing.T) {
	t.Parallel()
	doc := loadSpec(t)
	var walk func(n any, where string)
	walk = func(n any, where string) {
		switch v := n.(type) {
		case node:
			if ref, ok := v["$ref"].(string); ok {
				if !strings.HasPrefix(ref, "#/") {
					t.Errorf("%s: only local refs allowed, got %q", where, ref)
				} else if get(doc, strings.Split(strings.TrimPrefix(ref, "#/"), "/")...) == nil {
					t.Errorf("%s: unresolved $ref %q", where, ref)
				}
			}
			for k, child := range v {
				walk(child, where+"/"+k)
			}
		case []any:
			for i, child := range v {
				walk(child, fmt.Sprintf("%s[%d]", where, i))
			}
		}
	}
	walk(doc, "#")
}

func TestSpecOperations(t *testing.T) {
	t.Parallel()
	doc := loadSpec(t)
	opID := regexp.MustCompile(`^[a-z][a-zA-Z0-9]+$`)
	roles := []string{"none", "viewer", "operator", "admin"}
	declaredTags := map[string]bool{}
	topTags, _ := get(doc, "tags").([]any)
	for _, tag := range topTags {
		if name, ok := get(tag, "name").(string); ok {
			declaredTags[name] = true
		}
	}

	seen := map[string]string{}
	for _, o := range operations(doc) {
		where := strings.ToUpper(o.method) + " " + o.path
		id, _ := o.op["operationId"].(string)
		switch {
		case !opID.MatchString(id):
			t.Errorf("%s: operationId %q must be lowerCamelCase", where, id)
		case seen[id] != "":
			t.Errorf("%s: operationId %q already used by %s", where, id, seen[id])
		}
		seen[id] = where

		if s, _ := o.op["summary"].(string); s == "" {
			t.Errorf("%s: summary missing", where)
		}
		tags, _ := o.op["tags"].([]any)
		if len(tags) == 0 {
			t.Errorf("%s: at least one tag required", where)
		}
		for _, tag := range tags {
			if name, _ := tag.(string); !declaredTags[name] {
				t.Errorf("%s: tag %q not declared in top-level tags", where, tag)
			}
		}

		// Every operation states its minimum role; "none" only together with security: [].
		role, _ := o.op["x-required-role"].(string)
		if !slices.Contains(roles, role) {
			t.Errorf("%s: x-required-role %q must be one of %v", where, role, roles)
		}
		sec, hasSec := o.op["security"].([]any)
		public := hasSec && len(sec) == 0
		if public != (role == "none") {
			t.Errorf("%s: x-required-role none <=> security: [] (got role %q, public %v)", where, role, public)
		}

		responses, _ := o.op["responses"].(node)
		if len(responses) == 0 {
			t.Errorf("%s: no responses", where)
		}
		if !public {
			if _, ok := responses["401"]; !ok {
				t.Errorf("%s: authenticated operation must document 401", where)
			}
		}
		if o.op["x-step-up"] == true {
			if _, ok := responses["403"]; !ok {
				t.Errorf("%s: step-up operation must document 403 (step-up-required)", where)
			}
		}
		if o.op["requestBody"] != nil {
			if _, ok := responses["400"]; !ok {
				t.Errorf("%s: operation with a request body must document 400", where)
			}
		}
		// Secrets in a query string end up in proxy logs and browser history.
		for _, p := range paramsOf(o.op) {
			name, _ := get(p, "name").(string)
			if strings.Contains(strings.ToLower(name), "password") || strings.Contains(strings.ToLower(name), "passphrase") {
				t.Errorf("%s: parameter %q carries a secret in the URL", where, name)
			}
		}
	}
}

func paramsOf(op node) []any {
	params, _ := op["parameters"].([]any)
	return params
}

// TestSpecErrorResponses: all 4xx/5xx responses are RFC 9457 problem documents.
func TestSpecErrorResponses(t *testing.T) {
	t.Parallel()
	doc := loadSpec(t)
	responses, _ := get(doc, "components", "responses").(node)
	for name, r := range responses {
		content, _ := get(r, "content").(node)
		for mediaType := range content {
			if mediaType != "application/problem+json" {
				t.Errorf("components/responses/%s: media type %q, want application/problem+json", name, mediaType)
			}
		}
	}
	for _, o := range operations(doc) {
		opResponses, _ := o.op["responses"].(node)
		for code, r := range opResponses {
			if code[0] != '4' && code[0] != '5' {
				continue
			}
			if _, ok := get(r, "$ref").(string); !ok {
				t.Errorf("%s %s: error response %s must $ref a shared problem response", o.method, o.path, code)
			}
		}
	}
}

// TestSpecSecretsWriteOnly: password-like properties are never returned by the API.
func TestSpecSecretsWriteOnly(t *testing.T) {
	t.Parallel()
	doc := loadSpec(t)
	var walk func(n any, where string)
	walk = func(n any, where string) {
		m, ok := n.(node)
		if !ok {
			if list, ok := n.([]any); ok {
				for i, c := range list {
					walk(c, fmt.Sprintf("%s[%d]", where, i))
				}
			}
			return
		}
		if props, ok := m["properties"].(node); ok {
			for name, p := range props {
				if get(p, "format") == "password" && get(p, "writeOnly") != true {
					t.Errorf("%s.%s: format password must be writeOnly", where, name)
				}
			}
		}
		for k, c := range m {
			walk(c, where+"/"+k)
		}
	}
	walk(get(doc, "components", "schemas"), "#/components/schemas")
}
