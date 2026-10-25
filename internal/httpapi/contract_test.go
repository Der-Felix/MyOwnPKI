package httpapi

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/fs"
	"maps"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"go.yaml.in/yaml/v3"

	"github.com/Der-Felix/MyOwnPKI/api"
	"github.com/Der-Felix/MyOwnPKI/internal/agents"
	"github.com/Der-Felix/MyOwnPKI/internal/auth/passkeytest"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/ca/legacy/legacytest"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
	"github.com/Der-Felix/MyOwnPKI/internal/testinstance"
)

// The contract tests (PHASE1 step 13) read api/openapi.yaml and check the
// API against it: every route is an operation of the spec with the same
// method, path, access and body; every answer has a status and content type
// the spec documents and a body valid against its schema; and each operation
// is exercised without a session (401), without read access (404), with read
// access but a too low role (403) and without a fresh second factor
// (step-up-required), as far as the spec's x-required-role and x-step-up ask.

const specURL = "file:///openapi.json"

type contract struct {
	doc      map[string]any
	compiler *jsonschema.Compiler
	mu       sync.Mutex
	schemas  map[string]*jsonschema.Schema
}

var (
	contractOnce sync.Once
	contractSpec *contract
	errContract  error
)

func loadContract(t *testing.T) *contract {
	t.Helper()
	contractOnce.Do(func() {
		var y any
		if errContract = yaml.Unmarshal(api.Spec, &y); errContract != nil {
			return
		}
		data, err := json.Marshal(y)
		if err != nil {
			errContract = err
			return
		}
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
		if err != nil {
			errContract = err
			return
		}
		c := jsonschema.NewCompiler()
		c.DefaultDraft(jsonschema.Draft2020)
		if errContract = c.AddResource(specURL, doc); errContract != nil {
			return
		}
		m, _ := doc.(map[string]any)
		contractSpec = &contract{doc: m, compiler: c, schemas: map[string]*jsonschema.Schema{}}
	})
	if errContract != nil {
		t.Fatalf("load the spec: %v", errContract)
	}
	return contractSpec
}

// node walks the document by keys.
func node(n any, keys ...string) any {
	for _, k := range keys {
		m, ok := n.(map[string]any)
		if !ok {
			return nil
		}
		n = m[k]
	}
	return n
}

// resolve follows a local $ref.
func (s *contract) resolve(n any) (any, string) {
	ref, ok := node(n, "$ref").(string)
	if !ok {
		return n, ""
	}
	parts := strings.Split(strings.TrimPrefix(ref, "#/"), "/")
	return node(s.doc, parts...), strings.TrimPrefix(ref, "#")
}

func pointer(keys ...string) string {
	var b strings.Builder
	for _, k := range keys {
		b.WriteString("/" + strings.ReplaceAll(strings.ReplaceAll(k, "~", "~0"), "/", "~1"))
	}
	return b.String()
}

func (s *contract) schema(t *testing.T, ptr string) *jsonschema.Schema {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if sch, ok := s.schemas[ptr]; ok {
		return sch
	}
	sch, err := s.compiler.Compile(specURL + "#" + ptr)
	if err != nil {
		t.Fatalf("compile %s: %v", ptr, err)
	}
	s.schemas[ptr] = sch
	return sch
}

// operation is the spec entry of a route.
func (s *contract) operation(rt Route) map[string]any {
	op, _ := node(s.doc, "paths", rt.Path, strings.ToLower(rt.Method)).(map[string]any)
	return op
}

func (s *contract) routeOf(t *testing.T, a *API, opID string) Route {
	t.Helper()
	for _, rt := range a.Routes() {
		if rt.OperationID == opID {
			return rt
		}
	}
	t.Fatalf("no route %s", opID)
	return Route{}
}

// check validates one answer against the spec.
func (s *contract) check(t *testing.T, rt Route, r *resp) {
	t.Helper()
	where := rt.OperationID
	code := strconv.Itoa(r.Code)
	responses := node(s.operation(rt), "responses")
	entry := node(responses, code)
	if entry == nil {
		t.Errorf("%s: status %d is not documented: %s", where, r.Code, r.Body.String())
		return
	}
	entry, refPtr := s.resolve(entry)
	if r.Header().Get(requestIDHeader) == "" || r.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("%s: X-Request-ID or Cache-Control missing", where)
	}
	content, _ := node(entry, "content").(map[string]any)
	if len(content) == 0 {
		if r.Body.Len() != 0 {
			t.Errorf("%s %d: body where the spec has none: %q", where, r.Code, r.Body.String())
		}
		return
	}
	ct, _, _ := strings.Cut(r.Header().Get("Content-Type"), ";")
	if _, ok := content[ct]; !ok {
		t.Errorf("%s %d: content type %q not documented", where, r.Code, ct)
		return
	}
	if ct != "application/json" && ct != "application/problem+json" {
		return
	}
	base := pointer("paths", rt.Path, strings.ToLower(rt.Method), "responses", code)
	if refPtr != "" {
		base = refPtr
	}
	schPtr := base + pointer("content", ct, "schema")
	if _, ref := s.resolve(node(content, ct, "schema")); ref != "" {
		schPtr = ref
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(r.Body.Bytes()))
	if err != nil {
		t.Errorf("%s: %v", where, err)
		return
	}
	if verr := s.schema(t, schPtr).Validate(inst); verr != nil {
		t.Errorf("%s %d: body doesn't match %s: %v\n%s", where, r.Code, schPtr, verr, r.Body.String())
	}
	// The schemas allow more properties than they list; the API must not
	// send any: a renamed field would pass the schema otherwise.
	for _, f := range s.unknownFields(node(content, ct, "schema"), inst, "") {
		t.Errorf("%s %d: field %s is not in the spec", where, r.Code, f)
	}
	if ct == "application/problem+json" && !strings.HasPrefix(fmt.Sprint(r.body["type"]), problemPrefix) {
		t.Errorf("%s: problem type %v", where, r.body["type"])
	}
}

// unknownFields lists the object keys in inst that schema doesn't name
// (following $ref, allOf, oneOf and anyOf; additionalProperties: true allows
// everything).
func (s *contract) unknownFields(schema, inst any, path string) []string {
	props := map[string]any{}
	open := false
	var collect func(n any)
	collect = func(n any) {
		n, _ = s.resolve(n)
		m, ok := n.(map[string]any)
		if !ok {
			return
		}
		if ap, ok := m["additionalProperties"].(bool); ok && ap {
			open = true
		}
		if p, ok := m["properties"].(map[string]any); ok {
			for k, v := range p {
				props[k] = v
			}
		}
		for _, key := range []string{"allOf", "oneOf", "anyOf"} {
			list, _ := m[key].([]any)
			for _, sub := range list {
				collect(sub)
			}
		}
		if items, ok := m["items"]; ok {
			props["[]"] = items
		}
	}
	collect(schema)
	var out []string
	switch v := inst.(type) {
	case map[string]any:
		if open {
			return nil
		}
		for k, val := range v {
			sub, ok := props[k]
			if !ok {
				out = append(out, path+"/"+k)
				continue
			}
			out = append(out, s.unknownFields(sub, val, path+"/"+k)...)
		}
	case []any:
		for i, val := range v {
			out = append(out, s.unknownFields(props["[]"], val, fmt.Sprintf("%s/%d", path, i))...)
		}
	}
	return out
}

// TestRoutesFollowTheSpec: every route is an operation of the spec, with the
// same access rules, passive flag and body.
func TestRoutesFollowTheSpec(t *testing.T) {
	t.Parallel()
	s := loadContract(t)
	a := New(Deps{})
	for _, rt := range a.Routes() {
		op := s.operation(rt)
		if op == nil {
			t.Errorf("%s %s: not in the spec", rt.Method, rt.Path)
			continue
		}
		if id, _ := op["operationId"].(string); id != rt.OperationID {
			t.Errorf("%s %s: operationId %q, route says %q", rt.Method, rt.Path, id, rt.OperationID)
		}
		role, _ := op["x-required-role"].(string)
		if (role == "none") != (rt.access == public) {
			t.Errorf("%s: x-required-role %q, route access %v", rt.OperationID, role, rt.access)
		}
		if passive, _ := op["x-passive"].(bool); passive != rt.passive {
			t.Errorf("%s: x-passive %v, route %v", rt.OperationID, passive, rt.passive)
		}
		if (op["requestBody"] != nil) != rt.body {
			t.Errorf("%s: requestBody in the spec %v, route %v", rt.OperationID, op["requestBody"] != nil, rt.body)
		}
	}
}

// contractCase is one request of the contract run.
type contractCase struct {
	op     string
	as     *client
	method string // "" = the route's
	path   string // the concrete path
	body   any
	want   int
	kind   string   // problem type, if any
	note   string   // what it shows: "", "no-session", "no-read", "low-role", "step-up", "token"
	header []string // extra request headers (a token)
	detail string   // the problem detail must start with this, if set
}

// TestContract runs every operation of the route table in the situations
// the spec promises and checks each answer against it.
func TestContract(t *testing.T) {
	t.Parallel()
	s := loadContract(t)
	v := newEnv(t)
	v.unseal(t)
	issuing, root := v.caIDs["issuing"], v.caIDs["root"]
	v.user(t, "viewer", false, authz.Binding{Role: authz.Viewer})
	v.user(t, "rootview", false, authz.Binding{CA: "root", Role: authz.Viewer}) // may not read "issuing"
	v.user(t, "op", false, authz.Binding{CA: "issuing", Role: authz.Operator})
	v.user(t, "nobody", false)

	admin := v.client("192.0.2.1")
	admin.signIn(t, "demo", v.demoPass)
	viewer, rootview, op, nobody := v.client("192.0.2.2"), v.client("192.0.2.3"), v.client("192.0.2.4"), v.client("192.0.2.5")
	viewer.signIn(t, "viewer", testPassword)
	rootview.signIn(t, "rootview", testPassword)
	nobody.signIn(t, "nobody", testPassword)
	op.signIn(t, "op", testPassword)
	anon := v.client("192.0.2.9")

	// Certificates to look at: a server-generated key and a CSR.
	keyed := admin.do(t, http.MethodPost, "/certificates", map[string]any{"ca_id": issuing, "preset": "server", "sans": map[string]any{"dns": []string{"nas.homelab.lan"}}, "key": map[string]string{"algorithm": "ecdsa-p256"}})
	if keyed.Code != http.StatusCreated {
		t.Fatalf("issue: %d %s", keyed.Code, keyed.Body.String())
	}
	keyedID, _ := keyed.body["id"].(string)
	revokable := admin.do(t, http.MethodPost, "/certificates", map[string]any{"ca_id": issuing, "preset": "server", "sans": map[string]any{"dns": []string{"old.homelab.lan"}}, "key": map[string]string{"algorithm": "ecdsa-p256"}})
	revokableID, _ := revokable.body["id"].(string)
	extKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	extTmpl := &x509.Certificate{SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: "router.example.org"}, DNSNames: []string{"router.example.org"},
		NotBefore: v.clk.Now().Add(-time.Hour), NotAfter: v.clk.Now().Add(90 * 24 * time.Hour)}
	extDER, _ := x509.CreateCertificate(rand.Reader, extTmpl, extTmpl, &extKey.PublicKey, extKey)
	extPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: extDER}))
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "web.homelab.lan"}, DNSNames: []string{"web.homelab.lan"}}, priv)
	csrPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
	issue := func(dns string) map[string]any {
		return map[string]any{"ca_id": issuing, "preset": "server", "sans": map[string]any{"dns": []string{dns}}, "key": map[string]string{"algorithm": "ecdsa-p256"}}
	}
	// The sign-in counted as a step-up; let it run out, so the step-up case
	// shows the refusal. The successful export follows a fresh step-up below.
	v.clk.Advance(authz.StepUpWindow + time.Second)

	cases := []contractCase{
		{op: "getSystemStatus", as: viewer, want: 200},
		{op: "getSystemStatus", as: nobody, want: 200},
		{op: "getSystemStatus", as: anon, want: 401, kind: "unauthorized", note: "no-session"},
		{op: "seal", as: viewer, want: 403, kind: "forbidden", note: "low-role"},
		{op: "seal", as: anon, want: 401, note: "no-session"},
		{op: "seal", as: admin, want: 200},
		{op: "unseal", as: anon, body: map[string]string{"passphrase": "x"}, want: 401, note: "no-session"},
		{op: "unseal", as: viewer, body: map[string]string{"passphrase": v.passphrase}, want: 403, kind: "forbidden", note: "low-role"},
		{op: "unseal", as: admin, body: map[string]string{"passphrase": "not the passphrase at all"}, want: 422, kind: "wrong-secret"},
		{op: "unseal", as: admin, body: map[string]string{"passphrase": v.passphrase}, want: 200},
		{op: "unseal", as: admin, body: map[string]string{"passphrase": v.passphrase}, want: 409, kind: "conflict"},
		{op: "unseal", as: admin, body: map[string]any{"passphrase": v.passphrase, "extra": 1}, want: 400, kind: "bad-request"},
		{op: "unseal", as: admin, body: `{"passphrase":"x"}`, want: 415, kind: "unsupported-media-type"},

		{op: "login", as: anon, body: map[string]string{"username": "viewer", "password": "wrong password, long enough"}, want: 401, kind: "unauthorized"},
		{op: "login", as: anon, body: map[string]string{"username": "viewer"}, want: 401},
		{op: "login", as: anon, body: "not json", want: 415},
		{op: "verifyTOTP", as: anon, body: map[string]string{"code": "123456"}, want: 401, note: "no-session"},
		{op: "stepUp", as: anon, body: map[string]string{"code": "123456"}, want: 401, note: "no-session"},
		{op: "stepUp", as: viewer, body: map[string]string{"code": "000000"}, want: 422, kind: "wrong-secret"},
		{op: "getSession", as: viewer, want: 200},
		{op: "getSession", as: anon, want: 401, note: "no-session"},
		{op: "logout", as: anon, want: 401, note: "no-session"},

		{op: "listPresets", as: nobody, want: 200},
		{op: "listPresets", as: anon, want: 401, note: "no-session"},
		{op: "getPreset", as: viewer, path: "/presets/server", want: 200},
		{op: "getPreset", as: viewer, path: "/presets/nope", want: 404, kind: "not-found"},
		{op: "getPreset", as: anon, path: "/presets/server", want: 401, note: "no-session"},

		{op: "listCAs", as: viewer, want: 200},
		{op: "listCAs", as: nobody, want: 200},
		{op: "listCAs", as: anon, want: 401, note: "no-session"},
		{op: "getCA", as: viewer, path: "/cas/" + issuing, want: 200},
		{op: "getCA", as: rootview, path: "/cas/" + issuing, want: 404, kind: "not-found", note: "no-read"},
		{op: "getCA", as: anon, path: "/cas/" + issuing, want: 401, note: "no-session"},
		{op: "downloadCACertificate", as: viewer, path: "/cas/" + root + "/certificate", want: 200},
		{op: "downloadCACertificate", as: viewer, path: "/cas/" + issuing + "/certificate?format=chain", want: 200},
		{op: "downloadCACertificate", as: viewer, path: "/cas/" + issuing + "/certificate?format=der", want: 200},
		{op: "downloadCACertificate", as: rootview, path: "/cas/" + issuing + "/certificate", want: 404, note: "no-read"},
		{op: "downloadCACertificate", as: anon, path: "/cas/" + root + "/certificate", want: 401, note: "no-session"},

		{op: "listCertificates", as: viewer, want: 200},
		{op: "listCertificates", as: viewer, path: "/certificates?limit=101", want: 400, kind: "bad-request"},
		{op: "listCertificates", as: rootview, path: "/certificates?ca_id=" + issuing, want: 404, note: "no-read"},
		{op: "listCertificates", as: anon, want: 401, note: "no-session"},
		{op: "issueCertificate", as: op, body: issue("a.homelab.lan"), want: 201},
		{op: "issueCertificate", as: op, body: map[string]any{"ca_id": issuing, "preset": "server", "csr_pem": csrPEM}, want: 201},
		{op: "issueCertificate", as: op, body: issue("a.example.org.invalid..name"), want: 422, kind: "policy-violation"},
		{op: "issueCertificate", as: op, body: map[string]any{"ca_id": issuing, "preset": "server"}, want: 400, kind: "bad-request"},
		{op: "issueCertificate", as: viewer, body: issue("b.homelab.lan"), want: 403, kind: "forbidden", note: "low-role"},
		{op: "issueCertificate", as: rootview, body: issue("b.homelab.lan"), want: 404, note: "no-read"},
		{op: "issueCertificate", as: anon, body: issue("b.homelab.lan"), want: 401, note: "no-session"},
		{op: "getCertificate", as: viewer, path: "/certificates/" + keyedID, want: 200},
		{op: "getCertificate", as: rootview, path: "/certificates/" + keyedID, want: 404, note: "no-read"},
		{op: "getCertificate", as: viewer, path: "/certificates/crt_nothere", want: 404},
		{op: "getCertificate", as: anon, path: "/certificates/" + keyedID, want: 401, note: "no-session"},
		{op: "downloadCertificate", as: viewer, path: "/certificates/" + keyedID + "/download/fullchain", want: 200},
		{op: "downloadCertificate", as: viewer, path: "/certificates/" + keyedID + "/download/der", want: 200},
		{op: "downloadCertificate", as: rootview, path: "/certificates/" + keyedID + "/download/pem", want: 404, note: "no-read"},
		{op: "downloadCertificate", as: anon, path: "/certificates/" + keyedID + "/download/pem", want: 401, note: "no-session"},
		{op: "exportCertificateWithKey", as: viewer, path: "/certificates/" + keyedID + "/export", body: map[string]string{"format": "pkcs8-pem"}, want: 403, kind: "forbidden", note: "low-role"},
		{op: "exportCertificateWithKey", as: op, path: "/certificates/" + keyedID + "/export", body: map[string]string{"format": "pkcs8-pem"}, want: 403, kind: "step-up-required", note: "step-up"},
		{op: "exportCertificateWithKey", as: rootview, path: "/certificates/" + keyedID + "/export", body: map[string]string{"format": "pkcs8-pem"}, want: 404, note: "no-read"},
		{op: "exportCertificateWithKey", as: anon, path: "/certificates/" + keyedID + "/export", body: map[string]string{"format": "pkcs8-pem"}, want: 401, note: "no-session"},
		{op: "exportCertificateWithKey", as: op, path: "/certificates/" + keyedID + "/export", body: map[string]string{"format": "pkcs12"}, want: 400},

		{op: "revokeCertificate", as: anon, path: "/certificates/" + revokableID + "/revoke", body: map[string]string{"reason": "superseded"}, want: 401, note: "no-session"},
		{op: "revokeCertificate", as: viewer, path: "/certificates/" + revokableID + "/revoke", body: map[string]string{"reason": "superseded"}, want: 403, kind: "forbidden", note: "low-role"},
		{op: "revokeCertificate", as: rootview, path: "/certificates/" + revokableID + "/revoke", body: map[string]string{"reason": "superseded"}, want: 404, note: "no-read"},
		{op: "revokeCertificate", as: op, path: "/certificates/" + revokableID + "/revoke", body: map[string]string{"reason": "superseded"}, want: 403, kind: "step-up-required", note: "step-up"},
		{op: "revokeCertificate", as: op, path: "/certificates/" + revokableID + "/revoke", body: map[string]string{}, want: 400},
		{op: "renewCertificate", as: anon, path: "/certificates/" + keyedID + "/renew", body: map[string]any{}, want: 401, note: "no-session"},
		{op: "renewCertificate", as: viewer, path: "/certificates/" + keyedID + "/renew", body: map[string]any{}, want: 403, kind: "forbidden", note: "low-role"},
		{op: "renewCertificate", as: rootview, path: "/certificates/" + keyedID + "/renew", body: map[string]any{}, want: 404, note: "no-read"},
		{op: "renewCertificate", as: op, path: "/certificates/" + keyedID + "/renew", body: map[string]any{}, want: 201},
		{op: "renewCertificate", as: op, path: "/certificates/" + keyedID + "/renew", body: map[string]any{"csr_pem": csrPEM}, want: 422, kind: "policy-violation"},
		{op: "inspectCSR", as: anon, body: map[string]string{"csr_pem": csrPEM}, want: 401, note: "no-session"},
		{op: "inspectCSR", as: viewer, body: map[string]string{"csr_pem": csrPEM}, want: 403, kind: "forbidden", note: "low-role"},
		{op: "inspectCSR", as: op, body: map[string]string{"csr_pem": csrPEM}, want: 200},
		{op: "inspectCSR", as: op, body: map[string]string{"csr_pem": "-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n"}, want: 422, kind: "policy-violation"},
		{op: "importExternalCertificate", as: anon, body: map[string]string{"certificate_pem": extPEM}, want: 401, note: "no-session"},
		{op: "importExternalCertificate", as: op, body: map[string]string{"certificate_pem": extPEM}, want: 403, kind: "forbidden", note: "low-role"},
		{op: "importExternalCertificate", as: admin, body: map[string]string{"certificate_pem": extPEM}, want: 201},
		{op: "importExternalCertificate", as: admin, body: map[string]string{"certificate_pem": extPEM}, want: 422, kind: "policy-violation"},
	}

	seen := map[string]map[string]bool{}
	mark := func(opID, what string) {
		if seen[opID] == nil {
			seen[opID] = map[string]bool{}
		}
		seen[opID][what] = true
	}
	// The step-up cases, replayed with an API token at the end.
	var stepUpCases []contractCase
	run := func(cc contractCase) {
		t.Helper()
		if cc.note == "step-up" {
			stepUpCases = append(stepUpCases, cc)
		}
		rt := s.routeOf(t, v.api, cc.op)
		method, path := cc.method, cc.path
		if method == "" {
			method = rt.Method
		}
		if path == "" {
			path = rt.Path
		}
		r := cc.as.do(t, method, path, cc.body, cc.header...)
		detail, _ := r.body["detail"].(string)
		if r.Code != cc.want || (cc.kind != "" && r.problemType() != cc.kind) || !strings.HasPrefix(detail, cc.detail) {
			t.Errorf("%s %s as %s: %d %s, want %d %s\n%s", method, path, cc.as.ip, r.Code, r.problemType(), cc.want, cc.kind, r.Body.String())
		}
		s.check(t, rt, r)
		if r.Code < 300 {
			mark(cc.op, "success")
		}
		if cc.note != "" && r.Code == cc.want {
			mark(cc.op, cc.note)
		}
	}
	for _, cc := range cases {
		run(cc)
	}
	// The rest needs a sequence: step-up, export, second factor, logout.
	op.stepUp(t, "op")
	run(contractCase{op: "exportCertificateWithKey", as: op, path: "/certificates/" + keyedID + "/export", body: map[string]string{"format": "pkcs8-pem"}, want: 200})
	run(contractCase{op: "revokeCertificate", as: op, path: "/certificates/" + revokableID + "/revoke", body: map[string]string{"reason": "superseded"}, want: 200})
	run(contractCase{op: "revokeCertificate", as: op, path: "/certificates/" + revokableID + "/revoke", body: map[string]string{"reason": "superseded"}, want: 422, kind: "policy-violation"})
	run(contractCase{op: "stepUp", as: viewer, body: map[string]string{"code": func() string { v.clk.Advance(30 * time.Second); return v.code("viewer") }()}, want: 200})
	fresh := v.client("192.0.2.20")
	v.clk.Advance(30 * time.Second)
	run(contractCase{op: "login", as: fresh, body: map[string]string{"username": "viewer", "password": testPassword}, want: 200})
	run(contractCase{op: "verifyTOTP", as: fresh, body: map[string]string{"code": "000000"}, want: 422, kind: "wrong-secret"})
	run(contractCase{op: "verifyTOTP", as: fresh, body: map[string]string{"code": v.code("viewer")}, want: 200})
	run(contractCase{op: "logout", as: fresh, want: 204})

	// Passkeys (step 17) with a virtual authenticator: register as the
	// viewer, sign in with it, remove it.
	authn := passkeytest.New(testinstance.BrowserOrigin)
	pw := map[string]string{"password": testPassword}
	v.clk.Advance(authz.StepUpWindow + time.Second)
	run(contractCase{op: "listWebAuthnCredentials", as: anon, want: 401, note: "no-session"})
	run(contractCase{op: "beginWebAuthnRegistration", as: anon, body: pw, want: 401, note: "no-session"})
	run(contractCase{op: "beginWebAuthnRegistration", as: viewer, body: pw, want: 403, kind: "step-up-required", note: "step-up"})
	run(contractCase{op: "deleteWebAuthnCredential", as: viewer, path: "/users/me/webauthn/pk_x/remove", body: pw, want: 403, kind: "step-up-required", note: "step-up"})
	run(contractCase{op: "deleteWebAuthnCredential", as: anon, path: "/users/me/webauthn/pk_x/remove", body: pw, want: 401, note: "no-session"})
	run(contractCase{op: "finishWebAuthnRegistration", as: anon, body: map[string]any{}, want: 401, note: "no-session"})
	run(contractCase{op: "beginWebAuthnLogin", as: anon, want: 401})
	viewer.stepUp(t, "viewer")
	run(contractCase{op: "beginWebAuthnRegistration", as: viewer, body: map[string]string{"password": "not the password at all"}, want: 422, kind: "wrong-secret"})
	run(contractCase{op: "finishWebAuthnRegistration", as: viewer, body: map[string]any{}, want: 409, kind: "conflict"})
	begin := viewer.do(t, http.MethodPost, "/users/me/webauthn/begin", pw)
	s.check(t, s.routeOf(t, v.api, "beginWebAuthnRegistration"), begin)
	if begin.Code == http.StatusOK {
		mark("beginWebAuthnRegistration", "success")
	}
	created, err := authn.Create(begin.Body.Bytes())
	if err != nil {
		t.Fatalf("virtual authenticator: %v (%s)", err, begin.Body.String())
	}
	run(contractCase{op: "finishWebAuthnRegistration", as: viewer, path: "/users/me/webauthn/finish?name=Laptop", body: json.RawMessage(created), want: 201})
	list := viewer.do(t, http.MethodGet, "/users/me/webauthn", nil)
	run(contractCase{op: "listWebAuthnCredentials", as: viewer, want: 200})
	items, _ := list.body["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("passkeys: %s", list.Body.String())
	}
	pkID, _ := items[0].(map[string]any)["id"].(string)

	pk := v.client("192.0.2.21")
	v.clk.Advance(30 * time.Second)
	if r := pk.do(t, http.MethodPost, "/auth/login", map[string]string{"username": "viewer", "password": testPassword}); r.Code != 200 || !strings.Contains(r.Body.String(), `"webauthn"`) {
		t.Fatalf("login of a user with a passkey: %d %s", r.Code, r.Body.String())
	}
	assertion := pk.do(t, http.MethodPost, "/auth/webauthn/begin", nil)
	s.check(t, s.routeOf(t, v.api, "beginWebAuthnLogin"), assertion)
	if assertion.Code == http.StatusOK {
		mark("beginWebAuthnLogin", "success")
	}
	answer, err := authn.Get(assertion.Body.Bytes())
	if err != nil {
		t.Fatalf("virtual authenticator: %v (%s)", err, assertion.Body.String())
	}
	run(contractCase{op: "finishWebAuthnLogin", as: pk, body: json.RawMessage(answer), want: 200})
	run(contractCase{op: "finishWebAuthnLogin", as: pk, body: json.RawMessage(answer), want: 409, kind: "conflict"}) // used once
	run(contractCase{op: "deleteWebAuthnCredential", as: viewer, path: "/users/me/webauthn/pk_nothere/remove", body: pw, want: 404})
	run(contractCase{op: "deleteWebAuthnCredential", as: viewer, path: "/users/me/webauthn/" + pkID + "/remove", body: pw, want: 204})

	// CA management (step 18). The admin's step-up has run out by now.
	v.clk.Advance(authz.StepUpWindow + time.Second)
	labCA := map[string]any{"name": "lab-ca", "kind": "intermediate", "parent_ca_id": root, "subject": map[string]string{"common_name": "Lab CA"}, "public_base_url": "http://pki.homelab.lan"}
	offKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	offTmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "Offline Root"}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, NotBefore: v.clk.Now().Add(-time.Hour), NotAfter: v.clk.Now().AddDate(10, 0, 0)}
	offDER, _ := x509.CreateCertificate(rand.Reader, offTmpl, offTmpl, &offKey.PublicKey, offKey)
	offCert, _ := x509.ParseCertificate(offDER)
	offPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: offDER}))
	importOff := map[string]any{"name": "offline", "certificate_pem": offPEM, "public_base_url": "http://pki.homelab.lan"}
	for _, cc := range []contractCase{
		{op: "createCA", as: anon, body: labCA, want: 401, note: "no-session"},
		{op: "createCA", as: viewer, body: labCA, want: 403, kind: "forbidden", note: "low-role"},
		{op: "createCA", as: admin, body: labCA, want: 403, kind: "step-up-required", note: "step-up"},
		{op: "importCA", as: anon, body: importOff, want: 401, note: "no-session"},
		{op: "importCA", as: viewer, body: importOff, want: 403, kind: "forbidden", note: "low-role"},
		{op: "importCA", as: admin, body: importOff, want: 403, kind: "step-up-required", note: "step-up"},
		{op: "updateCA", as: anon, path: "/cas/" + issuing, body: map[string]int{"crl_days": 5}, want: 401, note: "no-session"},
		{op: "updateCA", as: viewer, path: "/cas/" + issuing, body: map[string]int{"crl_days": 5}, want: 403, kind: "forbidden", note: "low-role"},
		{op: "updateCA", as: rootview, path: "/cas/" + issuing, body: map[string]int{"crl_days": 5}, want: 404, note: "no-read"},
		{op: "updateCA", as: admin, path: "/cas/" + issuing, body: map[string]int{"crl_days": 5}, want: 403, kind: "step-up-required", note: "step-up"},
		{op: "renewCA", as: anon, path: "/cas/" + issuing + "/renew", body: map[string]any{}, want: 401, note: "no-session"},
		{op: "renewCA", as: viewer, path: "/cas/" + issuing + "/renew", body: map[string]any{}, want: 403, kind: "forbidden", note: "low-role"},
		{op: "renewCA", as: rootview, path: "/cas/" + issuing + "/renew", body: map[string]any{}, want: 404, note: "no-read"},
		{op: "renewCA", as: admin, path: "/cas/" + issuing + "/renew", body: map[string]any{}, want: 403, kind: "step-up-required", note: "step-up"},
		{op: "retireCA", as: anon, path: "/cas/" + issuing + "/retire", want: 401, note: "no-session"},
		{op: "retireCA", as: viewer, path: "/cas/" + issuing + "/retire", want: 403, kind: "forbidden", note: "low-role"},
		{op: "retireCA", as: rootview, path: "/cas/" + issuing + "/retire", want: 404, note: "no-read"},
		{op: "retireCA", as: admin, path: "/cas/" + issuing + "/retire", want: 403, kind: "step-up-required", note: "step-up"},
		{op: "revokeCA", as: anon, path: "/cas/" + issuing + "/revoke", body: map[string]string{"reason": "superseded"}, want: 401, note: "no-session"},
		{op: "revokeCA", as: viewer, path: "/cas/" + issuing + "/revoke", body: map[string]string{"reason": "superseded"}, want: 403, kind: "forbidden", note: "low-role"},
		{op: "revokeCA", as: rootview, path: "/cas/" + issuing + "/revoke", body: map[string]string{"reason": "superseded"}, want: 404, note: "no-read"},
		{op: "revokeCA", as: admin, path: "/cas/" + issuing + "/revoke", body: map[string]string{"reason": "superseded"}, want: 403, kind: "step-up-required", note: "step-up"},
		{op: "uploadSignedCACertificate", as: anon, path: "/cas/" + issuing + "/certificate", body: map[string]string{"certificate_pem": offPEM}, want: 401, note: "no-session"},
		{op: "uploadSignedCACertificate", as: viewer, path: "/cas/" + issuing + "/certificate", body: map[string]string{"certificate_pem": offPEM}, want: 403, kind: "forbidden", note: "low-role"},
		{op: "uploadSignedCACertificate", as: rootview, path: "/cas/" + issuing + "/certificate", body: map[string]string{"certificate_pem": offPEM}, want: 404, note: "no-read"},
		{op: "uploadSignedCACertificate", as: admin, path: "/cas/" + issuing + "/certificate", body: map[string]string{"certificate_pem": offPEM}, want: 403, kind: "step-up-required", note: "step-up"},
		{op: "downloadCACSR", as: anon, path: "/cas/" + issuing + "/csr", want: 401, note: "no-session"},
		{op: "downloadCACSR", as: viewer, path: "/cas/" + issuing + "/csr", want: 403, kind: "forbidden", note: "low-role"},
		{op: "downloadCACSR", as: rootview, path: "/cas/" + issuing + "/csr", want: 404, note: "no-read"},
		{op: "downloadCACSR", as: admin, path: "/cas/" + issuing + "/csr", want: 422, kind: "policy-violation"}, // not waiting for a signature
		{op: "downloadCRL", as: anon, path: "/cas/" + issuing + "/crl", want: 401, note: "no-session"},
		{op: "downloadCRL", as: rootview, path: "/cas/" + issuing + "/crl", want: 404, note: "no-read"},
		{op: "downloadCRL", as: viewer, path: "/cas/" + issuing + "/crl", want: 200},
		{op: "downloadCRL", as: viewer, path: "/cas/" + issuing + "/crl?format=pem", want: 200},
		{op: "regenerateCRL", as: anon, path: "/cas/" + issuing + "/crl", want: 401, note: "no-session"},
		{op: "regenerateCRL", as: viewer, path: "/cas/" + issuing + "/crl", want: 403, kind: "forbidden", note: "low-role"},
		{op: "regenerateCRL", as: rootview, path: "/cas/" + issuing + "/crl", want: 404, note: "no-read"},
		{op: "regenerateCRL", as: admin, path: "/cas/" + issuing + "/crl", want: 403, kind: "step-up-required", note: "step-up"},
		{op: "uploadCRL", as: anon, path: "/cas/" + root + "/crl", body: map[string]string{"crl_pem": "x"}, want: 401, note: "no-session"},
		{op: "uploadCRL", as: viewer, path: "/cas/" + issuing + "/crl", body: map[string]string{"crl_pem": "x"}, want: 403, kind: "forbidden", note: "low-role"},
		{op: "uploadCRL", as: rootview, path: "/cas/" + issuing + "/crl", body: map[string]string{"crl_pem": "x"}, want: 404, note: "no-read"},
		{op: "uploadCRL", as: admin, path: "/cas/" + root + "/crl", body: map[string]string{"crl_pem": "x"}, want: 403, kind: "step-up-required", note: "step-up"},
	} {
		run(cc)
	}
	admin.stepUp(t, "demo")
	createdCA := admin.do(t, http.MethodPost, "/cas", labCA)
	run(contractCase{op: "createCA", as: admin, body: map[string]any{"name": "lab-ca", "kind": "intermediate", "parent_ca_id": root, "subject": map[string]string{"common_name": "Lab CA 2"}, "public_base_url": "http://pki.homelab.lan"}, want: 422, kind: "policy-violation"})
	s.check(t, s.routeOf(t, v.api, "createCA"), createdCA)
	if createdCA.Code != http.StatusCreated {
		t.Fatalf("create lab-ca: %d %s", createdCA.Code, createdCA.Body.String())
	}
	mark("createCA", "success")
	labID, _ := createdCA.body["ca"].(map[string]any)["id"].(string)
	run(contractCase{op: "updateCA", as: admin, path: "/cas/" + labID, body: map[string]int{"crl_days": 5}, want: 200})
	run(contractCase{op: "updateCA", as: admin, path: "/cas/" + labID, body: map[string]int{}, want: 400})
	run(contractCase{op: "renewCA", as: admin, path: "/cas/" + labID + "/renew", body: map[string]any{}, want: 200})
	run(contractCase{op: "revokeCA", as: admin, path: "/cas/" + labID + "/revoke", body: map[string]any{"reason": "superseded", "generation": 1}, want: 200})
	run(contractCase{op: "retireCA", as: admin, path: "/cas/" + labID + "/retire", want: 200})
	run(contractCase{op: "regenerateCRL", as: admin, path: "/cas/" + issuing + "/crl", want: 200})
	imported := admin.do(t, http.MethodPost, "/cas/import", importOff)
	s.check(t, s.routeOf(t, v.api, "importCA"), imported)
	if imported.Code != http.StatusCreated {
		t.Fatalf("import the offline root: %d %s", imported.Code, imported.Body.String())
	}
	mark("importCA", "success")
	offID, _ := imported.body["ca"].(map[string]any)["id"].(string)
	// The offline root signs its CRL and an intermediate, as pki.sh would.
	crlDER, _ := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: v.clk.Now().Add(-time.Minute), NextUpdate: v.clk.Now().AddDate(0, 0, 30)}, offCert, offKey)
	run(contractCase{op: "uploadCRL", as: admin, path: "/cas/" + offID + "/crl", body: map[string]string{"crl_pem": string(pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDER}))}, want: 200})
	run(contractCase{op: "uploadCRL", as: admin, path: "/cas/" + offID + "/crl", body: map[string]string{"crl_pem": string(pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDER}))}, want: 422, kind: "policy-violation"})
	pending := admin.do(t, http.MethodPost, "/cas", map[string]any{"name": "below-offline", "kind": "intermediate", "parent_ca_id": offID, "subject": map[string]string{"common_name": "Below Offline"}, "public_base_url": "http://pki.homelab.lan"})
	if pending.Code != http.StatusCreated || pending.body["offline_signing"] == nil {
		t.Fatalf("intermediate below the offline root: %d %s", pending.Code, pending.Body.String())
	}
	pendingID, _ := pending.body["ca"].(map[string]any)["id"].(string)
	run(contractCase{op: "downloadCACSR", as: admin, path: "/cas/" + pendingID + "/csr", want: 200})
	bundle, _ := pending.body["offline_signing"].(map[string]any)
	signed := signOffline(t, bundle, offCert, offKey, v.clk.Now())
	run(contractCase{op: "uploadSignedCACertificate", as: admin, path: "/cas/" + pendingID + "/certificate", body: map[string]string{"certificate_pem": signed}, want: 200})
	run(contractCase{op: "uploadSignedCACertificate", as: admin, path: "/cas/" + pendingID + "/certificate", body: map[string]string{"certificate_pem": signed}, want: 422, kind: "policy-violation"})

	// Users, the own account, tokens, settings (step 18).
	v.user(t, "self", false, authz.Binding{CA: "issuing", Role: authz.Operator})
	self := v.client("192.0.2.30")
	self.signIn(t, "self", testPassword)
	v.clk.Advance(authz.StepUpWindow + time.Second)
	newUser := map[string]any{"username": "worker", "password": "a long password for the new colleague", "roles": []map[string]any{{"role": "viewer", "scope": map[string]string{"type": "tenant"}}}}
	selfID := v.in.UserID(t, "self")
	tokenReq := map[string]any{"name": "ci", "roles": []map[string]any{{"role": "operator", "scope": map[string]string{"type": "ca", "id": issuing}}}, "expires_at": v.clk.Now().Add(30 * 24 * time.Hour).Format(time.RFC3339)}
	settings := map[string]any{"allow_server_keygen": true, "subject_defaults": map[string]string{"organization": "Homelab", "organizational_unit": "", "locality": "", "state": "", "country": "DE"}}
	pwChange := map[string]string{"current_password": testPassword, "new_password": "a different long passphrase"}
	for _, cc := range []contractCase{
		{op: "listUsers", as: anon, want: 401, note: "no-session"},
		{op: "listUsers", as: viewer, want: 403, kind: "forbidden", note: "low-role"},
		{op: "listUsers", as: admin, want: 200},
		{op: "getUser", as: anon, path: "/users/" + selfID, want: 401, note: "no-session"},
		{op: "getUser", as: viewer, path: "/users/" + selfID, want: 403, kind: "forbidden", note: "low-role"},
		{op: "getUser", as: admin, path: "/users/" + selfID, want: 200},
		{op: "getUser", as: admin, path: "/users/usr_nothere", want: 404},
		{op: "createUser", as: anon, body: newUser, want: 401, note: "no-session"},
		{op: "createUser", as: viewer, body: newUser, want: 403, kind: "forbidden", note: "low-role"},
		{op: "createUser", as: admin, body: newUser, want: 403, kind: "step-up-required", note: "step-up"},
		{op: "updateUser", as: anon, path: "/users/" + selfID, body: map[string]bool{"unlock": true}, want: 401, note: "no-session"},
		{op: "updateUser", as: viewer, path: "/users/" + selfID, body: map[string]bool{"unlock": true}, want: 403, kind: "forbidden", note: "low-role"},
		{op: "updateUser", as: admin, path: "/users/" + selfID, body: map[string]bool{"unlock": true}, want: 403, kind: "step-up-required", note: "step-up"},
		{op: "deleteUser", as: anon, path: "/users/" + selfID, want: 401, note: "no-session"},
		{op: "deleteUser", as: viewer, path: "/users/" + selfID, want: 403, kind: "forbidden", note: "low-role"},
		{op: "deleteUser", as: admin, path: "/users/" + selfID, want: 403, kind: "step-up-required", note: "step-up"},
		{op: "setUserRoles", as: anon, path: "/users/" + selfID + "/roles", body: map[string]any{"roles": []any{}}, want: 401, note: "no-session"},
		{op: "setUserRoles", as: viewer, path: "/users/" + selfID + "/roles", body: map[string]any{"roles": []any{}}, want: 403, kind: "forbidden", note: "low-role"},
		{op: "setUserRoles", as: admin, path: "/users/" + selfID + "/roles", body: map[string]any{"roles": []any{}}, want: 403, kind: "step-up-required", note: "step-up"},
		{op: "changeOwnPassword", as: anon, body: pwChange, want: 401, note: "no-session"},
		{op: "changeOwnPassword", as: self, body: pwChange, want: 403, kind: "step-up-required", note: "step-up"},
		{op: "beginTOTPEnrollment", as: anon, body: map[string]string{"password": testPassword}, want: 401, note: "no-session"},
		{op: "beginTOTPEnrollment", as: self, body: map[string]string{"password": "not the password"}, want: 422, kind: "wrong-secret"},
		{op: "confirmTOTPEnrollment", as: anon, body: map[string]string{"code": "123456"}, want: 401, note: "no-session"},
		{op: "confirmTOTPEnrollment", as: self, body: map[string]string{"code": "123456"}, want: 409, kind: "conflict"},
		{op: "newRecoveryCodes", as: anon, body: map[string]string{"password": testPassword}, want: 401, note: "no-session"},
		{op: "newRecoveryCodes", as: self, body: map[string]string{"password": testPassword}, want: 200},
		{op: "listTokens", as: anon, want: 401, note: "no-session"},
		{op: "listTokens", as: self, want: 200},
		{op: "createToken", as: anon, body: tokenReq, want: 401, note: "no-session"},
		{op: "createToken", as: self, body: tokenReq, want: 403, kind: "step-up-required", note: "step-up"},
		{op: "revokeToken", as: anon, path: "/tokens/tok_x", want: 401, note: "no-session"},
		{op: "revokeToken", as: self, path: "/tokens/tok_x", want: 404},
		{op: "getSettings", as: anon, want: 401, note: "no-session"},
		{op: "getSettings", as: viewer, want: 200},
		{op: "updateSettings", as: anon, body: settings, want: 401, note: "no-session"},
		{op: "updateSettings", as: viewer, body: settings, want: 403, kind: "forbidden", note: "low-role"},
		{op: "updateSettings", as: admin, body: settings, want: 200},
		{op: "updateSettings", as: admin, body: map[string]any{"allow_server_keygen": true, "subject_defaults": map[string]string{"organization": "", "organizational_unit": "", "locality": "", "state": "", "country": "Germany"}}, want: 422, kind: "policy-violation"},
		{op: "updateSettings", as: admin, body: withLimits(settings, 100, 3, 20), want: 200, note: "acme-limits"},
		{op: "updateSettings", as: admin, body: withLimits(settings, 0, 3, 20), want: 422, kind: "policy-violation", note: "acme-limits"},
		{op: "updateSettings", as: admin, body: withTrustPage(settings, false), want: 200, note: "trust-page"},
		{op: "updateSettings", as: admin, body: withTrustPage(settings, true), want: 200, note: "trust-page"},
	} {
		run(cc)
	}
	admin.stepUp(t, "demo")
	run(contractCase{op: "createUser", as: admin, body: newUser, want: 201})
	run(contractCase{op: "createUser", as: admin, body: newUser, want: 422, kind: "policy-violation"})
	workerID := v.in.UserID(t, "worker")
	run(contractCase{op: "setUserRoles", as: admin, path: "/users/" + workerID + "/roles", body: map[string]any{"roles": []map[string]any{{"role": "operator", "scope": map[string]string{"type": "ca", "id": issuing}}}}, want: 200})
	run(contractCase{op: "updateUser", as: admin, path: "/users/" + workerID, body: map[string]bool{"disabled": true}, want: 200})
	run(contractCase{op: "updateUser", as: admin, path: "/users/" + workerID, body: map[string]bool{"disabled": false}, want: 200})
	run(contractCase{op: "deleteUser", as: admin, path: "/users/" + workerID, want: 204})
	self.stepUp(t, "self")
	tok := self.do(t, http.MethodPost, "/tokens", tokenReq)
	s.check(t, s.routeOf(t, v.api, "createToken"), tok)
	if tok.Code != http.StatusCreated {
		t.Fatalf("create token: %d %s", tok.Code, tok.Body.String())
	}
	mark("createToken", "success")
	tokID, _ := tok.body["id"].(string)
	run(contractCase{op: "createToken", as: self, body: map[string]any{"name": "too much", "roles": []map[string]any{{"role": "admin", "scope": map[string]string{"type": "tenant"}}}, "expires_at": tokenReq["expires_at"]}, want: 422, kind: "policy-violation"})
	run(contractCase{op: "revokeToken", as: self, path: "/tokens/" + tokID, want: 204})
	enroll := self.do(t, http.MethodPost, "/users/me/totp", map[string]string{"password": testPassword})
	s.check(t, s.routeOf(t, v.api, "beginTOTPEnrollment"), enroll)
	if enroll.Code != http.StatusOK {
		t.Fatalf("begin TOTP change: %d %s", enroll.Code, enroll.Body.String())
	}
	mark("beginTOTPEnrollment", "success")
	newSecret, _ := enroll.body["secret"].(string)
	v.clk.Advance(30 * time.Second)
	run(contractCase{op: "confirmTOTPEnrollment", as: self, body: map[string]string{"code": totpCode(t, newSecret, v.clk.Now())}, want: 204})
	v.clk.Advance(30 * time.Second)
	self.do(t, http.MethodPost, "/auth/step-up", map[string]string{"code": totpCode(t, newSecret, v.clk.Now())})
	run(contractCase{op: "changeOwnPassword", as: self, body: map[string]string{"current_password": testPassword, "new_password": "short"}, want: 422, kind: "policy-violation"})
	run(contractCase{op: "changeOwnPassword", as: self, body: pwChange, want: 204})

	// Legacy import over the API and the audit log (step 18). The fixture's
	// CA names (root, issuing) exist here already: the import is refused as
	// a whole and recorded as a failed job.
	fixtureDir := filepath.Join(t.TempDir(), "pki")
	legacytest.Write(t, fixtureDir, v.clk.Now())
	archive := map[string]any{"archive": tarGzBase64(t, fixtureDir), "dry_run": true}
	v.clk.Advance(authz.StepUpWindow + time.Second)
	for _, cc := range []contractCase{
		{op: "startLegacyImport", as: anon, body: archive, want: 401, note: "no-session"},
		{op: "startLegacyImport", as: viewer, body: archive, want: 403, kind: "forbidden", note: "low-role"},
		{op: "startLegacyImport", as: admin, body: archive, want: 403, kind: "step-up-required", note: "step-up"},
		{op: "getImport", as: anon, path: "/imports/imp_x", want: 401, note: "no-session"},
		{op: "getImport", as: viewer, path: "/imports/imp_x", want: 403, kind: "forbidden", note: "low-role"},
		{op: "getImport", as: rootview, path: "/imports/imp_x", want: 404, note: "no-read"},
		{op: "getImport", as: admin, path: "/imports/imp_nothere", want: 404},
		{op: "listAuditEntries", as: anon, want: 401, note: "no-session"},
		{op: "listAuditEntries", as: viewer, want: 403, kind: "forbidden", note: "low-role"},
		{op: "listAuditEntries", as: admin, path: "/audit?limit=2", want: 200},
		{op: "listAuditEntries", as: admin, path: "/audit?scope=instance&action=user.login&result=success", want: 200},
		{op: "listAuditEntries", as: admin, path: "/audit?limit=500", want: 400},
		{op: "verifyAuditChain", as: anon, body: map[string]any{}, want: 401, note: "no-session"},
		{op: "verifyAuditChain", as: viewer, body: map[string]any{}, want: 403, kind: "forbidden", note: "low-role"},
		{op: "verifyAuditChain", as: admin, body: map[string]any{}, want: 200},
		{op: "verifyAuditChain", as: admin, body: map[string]string{"scope": "instance"}, want: 200},
	} {
		run(cc)
	}
	admin.stepUp(t, "demo")
	job := admin.do(t, http.MethodPost, "/imports/legacy", archive)
	s.check(t, s.routeOf(t, v.api, "startLegacyImport"), job)
	if job.Code != http.StatusCreated || job.body["status"] != "failed" || !strings.Contains(job.Body.String(), "exists already") {
		t.Fatalf("import into an instance with the same CA names: %d %s", job.Code, job.Body.String())
	}
	mark("startLegacyImport", "success")
	jobID, _ := job.body["id"].(string)
	run(contractCase{op: "getImport", as: admin, path: "/imports/" + jobID, want: 200})
	run(contractCase{op: "startLegacyImport", as: admin, body: map[string]any{"archive": "bm90IGFuIGFyY2hpdmU="}, want: 422, kind: "policy-violation"})

	// Domains (PHASE2 step 1): two domains – one stays for the token replay
	// below, the other is deleted.
	admin.stepUp(t, "demo")
	newDomain := func(name string) string {
		t.Helper()
		r := admin.do(t, http.MethodPost, "/domains", map[string]any{"name": name, "ca_id": issuing, "approval": "open", "ip_ranges": []string{}})
		s.check(t, s.routeOf(t, v.api, "createDomain"), r)
		if r.Code != http.StatusCreated {
			t.Fatalf("create domain %s: %d %s", name, r.Code, r.Body.String())
		}
		id, _ := r.body["id"].(string)
		return id
	}
	keepID, dropID := newDomain("homelab.lan"), newDomain("other.lan")
	mark("createDomain", "success")
	domainBody := map[string]any{"name": "third.lan", "ca_id": issuing}
	for _, cc := range []contractCase{
		{op: "createDomain", as: admin, body: map[string]any{"name": "homelab.lan", "ca_id": issuing}, want: 422, kind: "policy-violation"},
		{op: "createDomain", as: admin, body: map[string]any{"name": "x.lan", "ca_id": issuing, "approval": "never"}, want: 422, kind: "policy-violation"},
		{op: "createDomain", as: admin, body: map[string]any{"name": "x.lan"}, want: 400},
		{op: "listDomains", as: anon, want: 401, note: "no-session"},
		{op: "listDomains", as: viewer, want: 200},
		{op: "listDomains", as: rootview, want: 200},
		{op: "getDomain", as: anon, path: "/domains/" + keepID, want: 401, note: "no-session"},
		{op: "getDomain", as: viewer, path: "/domains/" + keepID, want: 200},
		{op: "getDomain", as: rootview, path: "/domains/" + keepID, want: 404, note: "no-read"},
		{op: "getDomain", as: viewer, path: "/domains/dom_doesnotexist0000000000", want: 404},
		{op: "updateDomain", as: admin, path: "/domains/" + keepID, body: map[string]any{"wildcards": true}, want: 200},
		{op: "updateDomain", as: admin, path: "/domains/" + keepID, body: map[string]any{"preset": "nope"}, want: 422, kind: "policy-violation"},
		{op: "updateDomain", as: admin, path: "/domains/" + keepID, body: map[string]any{"wildcard": true}, want: 400},
		{op: "deleteDomain", as: admin, path: "/domains/" + dropID, want: 204},
	} {
		run(cc)
	}
	v.clk.Advance(authz.StepUpWindow + time.Second)
	for _, cc := range []contractCase{
		{op: "createDomain", as: anon, body: domainBody, want: 401, note: "no-session"},
		{op: "createDomain", as: viewer, body: domainBody, want: 403, kind: "forbidden", note: "low-role"},
		{op: "createDomain", as: admin, body: domainBody, want: 403, kind: "step-up-required", note: "step-up"},
		{op: "updateDomain", as: anon, path: "/domains/" + keepID, body: map[string]any{"wildcards": false}, want: 401, note: "no-session"},
		{op: "updateDomain", as: viewer, path: "/domains/" + keepID, body: map[string]any{"wildcards": false}, want: 403, kind: "forbidden", note: "low-role"},
		{op: "updateDomain", as: rootview, path: "/domains/" + keepID, body: map[string]any{"wildcards": false}, want: 404, note: "no-read"},
		{op: "updateDomain", as: admin, path: "/domains/" + keepID, body: map[string]any{"wildcards": false}, want: 403, kind: "step-up-required", note: "step-up"},
		{op: "deleteDomain", as: anon, path: "/domains/" + keepID, want: 401, note: "no-session"},
		{op: "deleteDomain", as: viewer, path: "/domains/" + keepID, want: 403, kind: "forbidden", note: "low-role"},
		{op: "deleteDomain", as: rootview, path: "/domains/" + keepID, want: 404, note: "no-read"},
		{op: "deleteDomain", as: admin, path: "/domains/" + keepID, want: 403, kind: "step-up-required", note: "step-up"},
	} {
		run(cc)
	}

	// Agents (v0.3): the agent CA, an admitted agent (join token and check,
	// verified), two enrollments in the queue, and join tokens.
	admin.stepUp(t, "demo")
	if _, cerr := v.engine.CreateIntermediate(t.Context(), ca.IntermediateRequest{
		CASettings: ca.CASettings{Name: "agent-ca", BaseURL: "http://pki.homelab.lan"}, Parent: "root",
		Subject: ca.Subject{CommonName: "Agent CA"}, EKULimit: []string{"clientAuth"}, Who: console,
	}); cerr != nil {
		t.Fatal(cerr)
	}
	enrollAgent := func(host, token string) (string, string) {
		t.Helper()
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		csr, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
		out, eerr := v.agents.Enroll(t.Context(), agents.EnrollInput{Hostname: host, Token: token, Method: agents.MethodWebroot, SourceIP: "192.0.2.50", CSRDER: csr})
		if eerr != nil {
			t.Fatal(eerr)
		}
		st, serr := v.agents.EnrollStatus(t.Context(), agents.StatusInput{ID: out.ID, Handle: out.Handle, CheckReady: true, SourceIP: "192.0.2.50"})
		if serr != nil {
			t.Fatal(serr)
		}
		return out.ID, st.AgentID
	}
	agentTok, _, err := v.agents.CreateJoinToken(t.Context(), console, "contract", []string{"proxy1.homelab.lan"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, agentID := enrollAgent("proxy1.homelab.lan", agentTok)
	if agentID == "" {
		t.Fatal("the agent was not admitted")
	}
	approveID, _ := enrollAgent("proxy2.homelab.lan", "")
	denyID, _ := enrollAgent("proxy3.homelab.lan", "")
	_, unused, err := v.agents.CreateJoinToken(t.Context(), console, "unused", []string{"*.homelab.lan"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	tokens, _ := v.agents.ListJoinTokens(t.Context(), console)
	usedTokenID := ""
	for _, jt := range tokens {
		if !jt.UsedAt.IsZero() {
			usedTokenID = jt.ID
		}
	}
	agentPath := "/agents/" + agentID
	if err := v.agents.Report(t.Context(), &agents.Caller{Agent: pkidb.Agent{ID: agentID}, Who: console}, agents.ReportInput{Deployments: []agents.DeploymentReport{{Name: "proxy", State: "deployed"}}}); err != nil {
		t.Fatal(err)
	}
	for _, cc := range []contractCase{
		{op: "renewAgentDeployment", as: admin, path: agentPath + "/deployments/proxy/renew", want: 202},
		{op: "renewAgentDeployment", as: admin, path: agentPath + "/deployments/proxy/renew", want: 409},
		{op: "renewAgentDeployment", as: viewer, path: agentPath + "/deployments/proxy/renew", want: 403, note: "low-role"},
		{op: "renewAgentDeployment", as: rootview, path: agentPath + "/deployments/proxy/renew", want: 403, note: "no-read"},
		{op: "renewAgentDeployment", as: anon, path: agentPath + "/deployments/proxy/renew", want: 401, note: "no-session"},
		{op: "withdrawAgentDeployment", as: admin, path: agentPath + "/deployments/proxy/renew", want: 200},
		{op: "withdrawAgentDeployment", as: admin, path: agentPath + "/deployments/proxy/renew", want: 409},
		{op: "withdrawAgentDeployment", as: viewer, path: agentPath + "/deployments/proxy/renew", want: 403, note: "low-role"},
		{op: "withdrawAgentDeployment", as: rootview, path: agentPath + "/deployments/proxy/renew", want: 403, note: "no-read"},
		{op: "withdrawAgentDeployment", as: anon, path: agentPath + "/deployments/proxy/renew", want: 401, note: "no-session"},
		{op: "listAgents", as: viewer, want: 200},
		{op: "listAgents", as: anon, want: 401, note: "no-session"},
		{op: "getAgent", as: viewer, path: agentPath, want: 200},
		{op: "getAgent", as: viewer, path: "/agents/agt_nothere", want: 404, kind: "not-found"},
		{op: "getAgent", as: rootview, path: agentPath, want: 403, kind: "forbidden", note: "no-read"},
		{op: "getAgent", as: anon, path: agentPath, want: 401, note: "no-session"},
		{op: "changeAgentNames", as: admin, path: agentPath + "/names", body: map[string]any{"add": []string{"*.apps.homelab.lan"}}, want: 200},
		{op: "changeAgentNames", as: admin, path: agentPath + "/names", body: map[string]any{"add": []string{"bad name"}}, want: 422, kind: "policy-violation"},
		{op: "changeAgentNames", as: admin, path: agentPath + "/names", body: map[string]any{"bogus": 1}, want: 400, kind: "bad-request"},
		{op: "changeAgentNames", as: viewer, path: agentPath + "/names", body: map[string]any{"add": []string{"x.homelab.lan"}}, want: 403, kind: "forbidden", note: "low-role"},
		{op: "changeAgentNames", as: rootview, path: agentPath + "/names", body: map[string]any{"add": []string{"x.homelab.lan"}}, want: 403, note: "no-read"},
		{op: "changeAgentNames", as: anon, path: agentPath + "/names", body: map[string]any{"add": []string{"x.homelab.lan"}}, want: 401, note: "no-session"},
		{op: "disableAgent", as: admin, path: agentPath + "/disable", want: 200},
		{op: "disableAgent", as: admin, path: agentPath + "/disable", want: 409, kind: "conflict"},
		{op: "disableAgent", as: viewer, path: agentPath + "/disable", want: 403, kind: "forbidden", note: "low-role"},
		{op: "disableAgent", as: rootview, path: agentPath + "/disable", want: 403, note: "no-read"},
		{op: "disableAgent", as: anon, path: agentPath + "/disable", want: 401, note: "no-session"},
		{op: "enableAgent", as: admin, path: agentPath + "/enable", want: 200},
		{op: "enableAgent", as: viewer, path: agentPath + "/enable", want: 403, kind: "forbidden", note: "low-role"},
		{op: "enableAgent", as: rootview, path: agentPath + "/enable", want: 403, note: "no-read"},
		{op: "enableAgent", as: anon, path: agentPath + "/enable", want: 401, note: "no-session"},
		{op: "listAgentEnrollments", as: viewer, want: 200},
		{op: "listAgentEnrollments", as: viewer, path: "/agent-enrollments?state=all", want: 200},
		{op: "listAgentEnrollments", as: viewer, path: "/agent-enrollments?state=bad", want: 400, kind: "bad-request"},
		{op: "listAgentEnrollments", as: anon, want: 401, note: "no-session"},
		{op: "approveAgentEnrollment", as: admin, path: "/agent-enrollments/" + approveID + "/approve", want: 204},
		{op: "approveAgentEnrollment", as: admin, path: "/agent-enrollments/" + approveID + "/approve", want: 409, kind: "conflict"},
		{op: "approveAgentEnrollment", as: viewer, path: "/agent-enrollments/" + denyID + "/approve", want: 403, kind: "forbidden", note: "low-role"},
		{op: "approveAgentEnrollment", as: rootview, path: "/agent-enrollments/" + denyID + "/approve", want: 403, note: "no-read"},
		{op: "approveAgentEnrollment", as: anon, path: "/agent-enrollments/" + denyID + "/approve", want: 401, note: "no-session"},
		{op: "denyAgentEnrollment", as: viewer, path: "/agent-enrollments/" + denyID + "/deny", want: 403, kind: "forbidden", note: "low-role"},
		{op: "denyAgentEnrollment", as: rootview, path: "/agent-enrollments/" + denyID + "/deny", want: 403, note: "no-read"},
		{op: "denyAgentEnrollment", as: anon, path: "/agent-enrollments/" + denyID + "/deny", want: 401, note: "no-session"},
		{op: "denyAgentEnrollment", as: admin, path: "/agent-enrollments/" + denyID + "/deny", want: 204},
		{op: "listAgentJoinTokens", as: viewer, want: 200},
		{op: "listAgentJoinTokens", as: anon, want: 401, note: "no-session"},
		{op: "createAgentJoinToken", as: admin, body: map[string]any{"label": "web", "names": []string{"web1.homelab.lan"}, "valid_hours": 2}, want: 201},
		{op: "createAgentJoinToken", as: admin, body: map[string]any{"label": "web"}, want: 400, kind: "bad-request"},
		{op: "createAgentJoinToken", as: admin, body: map[string]any{"names": []string{"*"}}, want: 422, kind: "policy-violation"},
		{op: "createAgentJoinToken", as: viewer, body: map[string]any{"names": []string{"web2.homelab.lan"}}, want: 403, kind: "forbidden", note: "low-role"},
		{op: "createAgentJoinToken", as: anon, body: map[string]any{"names": []string{"web2.homelab.lan"}}, want: 401, note: "no-session"},
		{op: "deleteAgentJoinToken", as: admin, path: "/agent-join-tokens/" + usedTokenID, want: 409, kind: "conflict"},
		{op: "deleteAgentJoinToken", as: viewer, path: "/agent-join-tokens/" + unused.ID, want: 403, kind: "forbidden", note: "low-role"},
		{op: "deleteAgentJoinToken", as: rootview, path: "/agent-join-tokens/" + unused.ID, want: 403, note: "no-read"},
		{op: "deleteAgentJoinToken", as: anon, path: "/agent-join-tokens/" + unused.ID, want: 401, note: "no-session"},
		{op: "deleteAgentJoinToken", as: admin, path: "/agent-join-tokens/" + unused.ID, want: 204},
		{op: "revokeAgent", as: viewer, path: agentPath + "/revoke", want: 403, kind: "forbidden", note: "low-role"},
		{op: "revokeAgent", as: rootview, path: agentPath + "/revoke", want: 403, note: "no-read"},
		{op: "revokeAgent", as: anon, path: agentPath + "/revoke", want: 401, note: "no-session"},
	} {
		run(cc)
	}
	// The step-up cases, after the step-up ran out; the revocation last.
	v.clk.Advance(authz.StepUpWindow + time.Second)
	for _, cc := range []contractCase{
		{op: "changeAgentNames", as: admin, path: agentPath + "/names", body: map[string]any{"add": []string{"y.homelab.lan"}}, want: 403, kind: "step-up-required", note: "step-up"},
		{op: "disableAgent", as: admin, path: agentPath + "/disable", want: 403, kind: "step-up-required", note: "step-up"},
		{op: "enableAgent", as: admin, path: agentPath + "/enable", want: 403, kind: "step-up-required", note: "step-up"},
		{op: "revokeAgent", as: admin, path: agentPath + "/revoke", want: 403, kind: "step-up-required", note: "step-up"},
		{op: "approveAgentEnrollment", as: admin, path: "/agent-enrollments/" + denyID + "/approve", want: 403, kind: "step-up-required", note: "step-up"},
		{op: "denyAgentEnrollment", as: admin, path: "/agent-enrollments/" + denyID + "/deny", want: 403, kind: "step-up-required", note: "step-up"},
		{op: "createAgentJoinToken", as: admin, body: map[string]any{"names": []string{"web3.homelab.lan"}}, want: 403, kind: "step-up-required", note: "step-up"},
		{op: "deleteAgentJoinToken", as: admin, path: "/agent-join-tokens/" + usedTokenID, want: 403, kind: "step-up-required", note: "step-up"},
	} {
		run(cc)
	}
	admin.stepUp(t, "demo")
	run(contractCase{op: "revokeAgent", as: admin, path: agentPath + "/revoke", want: 200})

	// Every step-up operation once more with an API token of the admin: a
	// plain refusal (forbidden), never step-up-required – no POST
	// /auth/step-up can make a token fresh.
	admin.stepUp(t, "demo")
	tokResp := admin.do(t, http.MethodPost, "/tokens", map[string]any{"name": "contract", "expires_at": v.clk.Now().Add(24 * time.Hour).Format(time.RFC3339),
		"roles": []map[string]any{{"role": "admin", "scope": map[string]string{"type": "tenant"}}}})
	if tokResp.Code != http.StatusCreated {
		t.Fatalf("token: %d %s", tokResp.Code, tokResp.Body.String())
	}
	tokSecret, _ := tokResp.body["secret"].(string)
	bot := v.client("192.0.2.77")
	for _, cc := range stepUpCases {
		cc.as, cc.header = bot, []string{"Authorization", "Bearer " + tokSecret}
		cc.want, cc.kind, cc.note, cc.detail = http.StatusForbidden, "forbidden", "token", "an API token can't "
		run(cc)
	}

	// What every operation must have shown, by the spec.
	for _, rt := range v.api.Routes() {
		o := s.operation(rt)
		role, _ := o["x-required-role"].(string)
		need := []string{"success"}
		if role != "none" {
			need = append(need, "no-session")
		}
		if role == "instance-admin" {
			need = append(need, "low-role")
		}
		if o["x-step-up"] == true {
			need = append(need, "step-up", "token")
		}
		if slices.Contains([]string{"viewer", "operator", "admin"}, role) && strings.Contains(rt.Path, "{") {
			need = append(need, "no-read")
		}
		if slices.Contains([]string{"operator", "admin"}, role) {
			need = append(need, "low-role")
		}
		for _, n := range need {
			if !seen[rt.OperationID][n] {
				t.Errorf("%s: the contract run lacks the %q case", rt.OperationID, n)
			}
		}
	}
}

// signOffline plays the offline root: it signs the CSR of the bundle with
// exactly what the extension file orders (CA:TRUE pathlen 0, the key usage,
// AIA and CDP of the root), with the bundle's serial.
func signOffline(t *testing.T, bundle map[string]any, root *x509.Certificate, key *ecdsa.PrivateKey, now time.Time) string {
	t.Helper()
	csrPEM, _ := bundle["csr_pem"].(string)
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		t.Fatalf("bundle without CSR: %v", bundle)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	serialHex, _ := bundle["serial"].(string)
	extConfig, _ := bundle["ext_config"].(string)
	serial, ok := new(big.Int).SetString(serialHex, 16)
	if !ok {
		t.Fatalf("serial %v", bundle["serial"])
	}
	days, _ := bundle["days"].(float64)
	var aia, cdp string
	for _, l := range strings.Split(extConfig, "\n") {
		if v, found := strings.CutPrefix(l, "authorityInfoAccess    = caIssuers;URI:"); found {
			aia = v
		}
		if v, found := strings.CutPrefix(l, "crlDistributionPoints  = URI:"); found {
			cdp = v
		}
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial, RawSubject: csr.RawSubject, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Duration(days) * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IssuingCertificateURL: []string{aia}, CRLDistributionPoints: []string{cdp},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, root, csr.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func totpCode(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	code := testinstance.TOTP(secret, at)
	if code == "" {
		t.Fatalf("secret %q is not Base32", secret)
	}
	return code
}

// tarGzBase64 packs a directory (with its own name as the top folder) as a
// base64 .tar.gz, the way the legacy import over the API takes it.
func tarGzBase64(t *testing.T, dir string) string {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		rel, _ := filepath.Rel(filepath.Dir(dir), p)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			return tw.WriteHeader(&tar.Header{Name: rel + "/", Typeflag: tar.TypeDir, Mode: 0o700})
		}
		body, rerr := os.ReadFile(p) // #nosec G304 G122 -- the test's own fixture in a temp dir
		if rerr != nil {
			return rerr
		}
		if herr := tw.WriteHeader(&tar.Header{Name: rel, Typeflag: tar.TypeReg, Mode: 0o600, Size: int64(len(body))}); herr != nil {
			return herr
		}
		_, werr = tw.Write(body)
		return werr
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

// TestEverySpecOperationIsServed (step 18): the spec and the route table
// match in both directions – no operation is only on paper.
func TestEverySpecOperationIsServed(t *testing.T) {
	t.Parallel()
	var spec struct {
		Paths map[string]map[string]any `yaml:"paths"`
	}
	if err := yaml.Unmarshal(api.Spec, &spec); err != nil {
		t.Fatal(err)
	}
	served := map[string]bool{}
	for _, rt := range New(Deps{}).Routes() {
		served[rt.Method+" "+rt.Path] = true
	}
	n := 0
	for path, ops := range spec.Paths {
		for method := range ops {
			m := strings.ToUpper(method)
			if !slices.Contains([]string{"GET", "POST", "PUT", "PATCH", "DELETE"}, m) {
				continue
			}
			n++
			if !served[m+" "+path] {
				t.Errorf("%s %s is in the spec but not served", m, path)
			}
		}
	}
	if n != len(served) {
		t.Errorf("%d operations in the spec, %d routes", n, len(served))
	}
}

// withLimits adds acme_limits to a settings body (PHASE2 step 11).
func withLimits(settings map[string]any, orders, failed, accounts int) map[string]any {
	out := map[string]any{}
	maps.Copy(out, settings)
	out["acme_limits"] = map[string]int{"orders_per_account": orders, "failed_per_name": failed, "accounts_per_ip": accounts}
	return out
}

// withTrustPage adds trust_page to a settings body (v0.2.2).
func withTrustPage(settings map[string]any, on bool) map[string]any {
	out := map[string]any{}
	maps.Copy(out, settings)
	out["trust_page"] = on
	return out
}
