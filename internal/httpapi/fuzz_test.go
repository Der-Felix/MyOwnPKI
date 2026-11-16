package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// FuzzDecodeBody is the target of docs/PHASE3.md section 18.1 step 85: the
// JSON body of every REST route that takes one. The production function
// (call.decode) is called unchanged, the way the router calls it: the body
// behind http.MaxBytesReader with the 128 KiB limit.

// fuzzShape is one type a body is decoded into. The first two are the real
// request types (the issue request, a domain request: the anonymous struct
// of createDomain written out); the third has the other shapes that routes
// use: a nested map, slices of structs, a pointer to a struct, an interface,
// a time and a map of strings.
type fuzzShape struct {
	name    string
	fresh   func() any
	hasTime bool
}

type fuzzNested struct {
	Reason         string            `json:"reason"`
	InvalidityDate *time.Time        `json:"invalidity_date"`
	CAPassphrases  map[string]string `json:"ca_passphrases"`
	Items          []struct {
		Name  string              `json:"name"`
		Tags  map[string][]string `json:"tags"`
		Inner *struct {
			N *int `json:"n"`
		} `json:"inner"`
	} `json:"items"`
	Meta     map[string]any `json:"meta"`
	Anything any            `json:"anything"`
	Plain    string
}

var fuzzShapes = []fuzzShape{
	{name: "issue", fresh: func() any { return new(issueRequest) }},
	{name: "domain", fresh: func() any {
		return new(struct {
			Name string `json:"name"`
			domainSettingsJSON
		})
	}},
	{name: "nested", fresh: func() any { return new(fuzzNested) }, hasTime: true},
}

// bodyBudget is MaxBody written as a number, so a change of the constant
// shows up here.
const bodyBudget = 128 * 1024

func FuzzDecodeBody(f *testing.F) {
	seeds := []string{
		`{"ca_id":"` + strings.Repeat("a", 26) + `","preset":"server-tls","sans":{"dns":["a.example"]},"validity_days":30,"key":{"algorithm":"ecdsa-p256"}}`,
		`{"name":"homelab.lan","ca_id":"01ABC","wildcards":true,"challenge_types":["http-01"],"ip_ranges":["10.0.0.0/8"],"reason":"r"}`,
		`{"reason":"keyCompromise","invalidity_date":"2026-11-16T10:00:00+01:00","ca_passphrases":{"a":"b"},"items":[{"name":"x","tags":{"t":["1"]},"inner":{"n":3}}],"meta":{"k":[1,2.5,null,{"z":true}]},"anything":[1]}`,
		`{"valdity_days":30}`,
		`{"subject":{"common_name":"a","cn":"b"}}`,
		`{"items":[{"name":"x"},{"nam":"y"}]}`,
		`{"ca_passphrases":{"a/b~c":1}}`,
		`{"a~/b":1}`,
		`{"REASON":"x","Plain":"y","plain":"z"}`,
		`{"reason":"a","reason":"b"}`,
		`{"validity_days":1.5}`,
		`{"validity_days":1e400}`,
		`{"validity_days":"30"}`,
		`{"invalidity_date":"not a time"}`,
		`{"invalidity_date":"` + strings.Repeat("9", 40) + `"}`,
		`{"reason":"\ud800"}`,
		"{\"reason\":\"\xff\xfe\"}",
		"\xef\xbb\xbf{}",
		`null`, ` null`, `[]`, `"x"`, `1`, `true`, ``, ` `, `{`, `}`, `{}`, `{} `, "\n{}\n", `{}{}`, `{} x`, `{} {}`, `{}]`, `[{}]`,
		`{"reason":}`, `{"reason":"x",}`, `{'a':1}`, `{"a" 1}`,
		"{\"reason\":\"a\x01b\"}",
		strings.Repeat("[", 10001),
		`{"anything":` + strings.Repeat("[", 9990) + strings.Repeat("]", 9990) + `}`,
		`{"zz":` + strings.Repeat("[", 9990) + strings.Repeat("]", 9990) + `}`,
		`{"` + strings.Repeat("k", 100) + `":1}`,
		`{"items":[{"` + strings.Repeat("é", 30) + `":1}]}`,
		`{"reason":"` + strings.Repeat("a", bodyBudget) + `"}`,
		strings.Repeat(" ", bodyBudget) + `{}`,
		strings.Repeat(" ", bodyBudget+1),
	}
	for _, s := range seeds {
		for i := range fuzzShapes {
			f.Add(uint8(i), []byte(s))
		}
	}

	f.Fuzz(func(t *testing.T, which uint8, data []byte) {
		shape := fuzzShapes[int(which)%len(fuzzShapes)]
		start := time.Now()
		v := shape.fresh()
		err := decodeBytes(t, data, v)
		if d := time.Since(start); d > 2*time.Second {
			t.Fatalf("decode of %d bytes took %v", len(data), d)
		}

		if err != nil {
			checkRefusal(t, shape, data, err)
			return
		}

		// Accepted: one JSON object and nothing after it. json.Valid says
		// the whole input is exactly one value with only white space around.
		if len(data) > bodyBudget {
			t.Fatalf("accepted %d bytes, the limit is %d", len(data), bodyBudget)
		}
		if !json.Valid(data) {
			t.Fatalf("accepted input that is not one JSON value: %.80q", data)
		}
		if first := firstJSONByte(data); first != '{' {
			t.Fatalf("accepted a body that is not an object (starts with %q): %.80q", first, data)
		}

		// Round trip: what was decoded encodes to a body that decodes to
		// the same value, and encoding that again changes nothing.
		out1, merr := json.Marshal(v)
		if merr != nil {
			t.Fatalf("an accepted value does not encode: %v", merr)
		}
		v2 := shape.fresh()
		if err := decodeBytes(t, out1, v2); err != nil {
			t.Fatalf("the encoding of an accepted body is refused: %v\nbody: %.200s", err, out1)
		}
		out2, merr := json.Marshal(v2)
		if merr != nil || !bytes.Equal(out1, out2) {
			t.Fatalf("round trip changed the value:\n%.200s\n%.200s", out1, out2)
		}
		if !shape.hasTime && !reflect.DeepEqual(v, v2) {
			t.Fatalf("round trip changed the value:\n%+v\n%+v", v, v2)
		}
	})
}

// decodeBytes runs call.decode the way the router does.
func decodeBytes(t *testing.T, data []byte, v any) error {
	t.Helper()
	rec := httptest.NewRecorder()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "/x", bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	req.Body = http.MaxBytesReader(rec, req.Body, bodyBudget)
	c := &call{w: rec, r: req, limit: bodyBudget}
	return c.decode(v)
}

// firstJSONByte is the first byte that is not JSON white space (RFC 8259).
func firstJSONByte(data []byte) byte {
	for _, b := range data {
		if b != ' ' && b != '\t' && b != '\r' && b != '\n' {
			return b
		}
	}
	return 0
}

// refusalText is everything of a refusal a client reads.
func refusalText(be *bodyError) int {
	n := len(be.msg)
	for _, f := range be.fields {
		n += len(f.Field) + len(f.Message)
	}
	return n
}

func checkRefusal(t *testing.T, shape fuzzShape, data []byte, err error) {
	t.Helper()
	var be *bodyError
	if !errors.As(err, &be) {
		t.Fatalf("refusal is not a *bodyError: %T %v", err, err)
	}
	switch be.status {
	case http.StatusBadRequest:
		if len(data) > bodyBudget {
			t.Fatalf("%d bytes over the limit got %d, not 413", len(data), be.status)
		}
	case http.StatusRequestEntityTooLarge:
		if len(data) <= bodyBudget {
			t.Fatalf("%d bytes under the limit got 413", len(data))
		}
	default:
		t.Fatalf("refusal status %d", be.status)
	}
	if len(data) > bodyBudget && be.status != http.StatusRequestEntityTooLarge {
		t.Fatalf("a body over the limit was read as far as %d", be.status)
	}
	if n := refusalText(be); n > 300 {
		t.Fatalf("the refusal says %d bytes (limit 300): %.120q", n, be.fields)
	}
	for _, f := range be.fields {
		if !utf8.ValidString(f.Field) || !utf8.ValidString(f.Message) || !utf8.ValidString(be.msg) {
			t.Fatalf("the refusal holds invalid UTF-8: %q", f)
		}
	}

	// The walker, checked against the decoder's own answer.
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	derr := dec.Decode(shape.fresh())
	path, ok := unknownFieldPath(data, shape.fresh())
	name, unknown := strings.CutPrefix(errText(derr), "json: unknown field ")
	switch {
	case derr == nil:
		// Decodes alone; the only refusals left are the ones around it (data after it, or an input that is no object).
		if ok {
			t.Fatalf("unknownFieldPath names %q, but the decoder accepts the input", path)
		}
	case unknown:
		if !ok {
			t.Fatalf("the decoder refused field %s, the walker found none", name)
		}
		tokens, valid := pointerTokens(path)
		if !valid {
			t.Fatalf("%q is not a JSON Pointer (RFC 6901)", path)
		}
		if got, want := tokens[len(tokens)-1], strings.Trim(name, `"`); !equalKey(got, want) {
			t.Fatalf("the walker names %q, the decoder refused %s", path, name)
		}
		if !existsIn(t, data, tokens) {
			t.Fatalf("%q does not point into the input", path)
		}
		if !refusedByType(shape.fresh(), tokens) {
			t.Fatalf("%q is a field the type knows", path)
		}
	}
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// equalKey compares the pointer token with the name in the decoder's text:
// the decoder quotes it with strconv-style escapes, so it only compares
// short plain names exactly and skips the rest (a name with a quote or a
// control character reads differently in the text).
func equalKey(token, quoted string) bool {
	if strings.ContainsAny(quoted, `\"`) || strings.ContainsFunc(quoted, func(r rune) bool { return r < 0x20 || r == utf8.RuneError }) {
		return true
	}
	return token == quoted
}

// pointerTokens splits a JSON Pointer (RFC 6901) and unescapes it; valid is
// false for a string that is none: it must be empty or start with "/", and
// "~" is followed by 0 or 1.
func pointerTokens(p string) (tokens []string, valid bool) {
	if p == "" || p[0] != '/' || !utf8.ValidString(p) {
		return nil, false
	}
	for _, raw := range strings.Split(p[1:], "/") {
		for i := 0; i < len(raw); i++ {
			if raw[i] == '~' && (i+1 == len(raw) || (raw[i+1] != '0' && raw[i+1] != '1')) {
				return nil, false
			}
		}
		tokens = append(tokens, strings.NewReplacer("~1", "/", "~0", "~").Replace(raw))
	}
	return tokens, true
}

// existsIn follows the tokens through the input read as plain JSON.
func existsIn(t *testing.T, data []byte, tokens []string) bool {
	t.Helper()
	var doc any
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber() // 1e400 is a number here, not an error
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("the input does not read as JSON: %v", err)
	}
	for _, tok := range tokens {
		switch d := doc.(type) {
		case map[string]any:
			next, ok := d[tok]
			if !ok {
				return false
			}
			doc = next
		case []any:
			i := 0
			if tok == "" || (len(tok) > 1 && tok[0] == '0') {
				return false
			}
			for _, c := range tok {
				if c < '0' || c > '9' || i > len(d) {
					return false
				}
				i = i*10 + int(c-'0')
			}
			if i >= len(d) {
				return false
			}
			doc = d[i]
		default:
			return false
		}
	}
	return true
}

// refusedByType follows the tokens through the Go type of v and says that
// the last one is a name the type has no place for (field names compared
// without case, as encoding/json does). It is a second, short reading of the
// rules of the decoder; maps and slices lead to their element type, an
// interface or a raw message ends the walk.
func refusedByType(v any, tokens []string) bool {
	t := reflect.TypeOf(v)
	for i, tok := range tokens {
		for t.Kind() == reflect.Pointer {
			t = t.Elem()
		}
		last := i == len(tokens)-1
		switch t.Kind() {
		case reflect.Struct:
			ft, found := structField(t, tok)
			if last {
				return !found
			}
			if !found {
				return false
			}
			t = ft
		case reflect.Map:
			if last {
				return false // every key of a map is known
			}
			t = t.Elem()
		case reflect.Slice, reflect.Array:
			if last {
				return false
			}
			t = t.Elem()
		default:
			return false
		}
	}
	return false
}

func structField(t reflect.Type, key string) (reflect.Type, bool) {
	for i := range t.NumField() {
		f := t.Field(i)
		tag := f.Tag.Get("json")
		if tag == "-" {
			continue
		}
		name, _, _ := strings.Cut(tag, ",")
		if f.Anonymous && name == "" && f.Type.Kind() == reflect.Struct {
			if ft, ok := structField(f.Type, key); ok {
				return ft, true
			}
			continue
		}
		if !f.IsExported() {
			continue
		}
		if name == "" {
			name = f.Name
		}
		if strings.EqualFold(name, key) {
			return f.Type, true
		}
	}
	return nil, false
}
