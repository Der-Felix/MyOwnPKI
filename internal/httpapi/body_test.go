package httpapi

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// TestBodyMustBeAnObject: a body is one JSON object. "null" decodes into any
// struct without an error, so it has to be refused by hand (found by
// fuzzing, FuzzDecodeBody).
func TestBodyMustBeAnObject(t *testing.T) {
	t.Parallel()
	type req struct {
		Name string `json:"name"`
	}
	for _, body := range []string{"null", " null", "\n\tnull\r\n", `[]`, `"x"`, `1`, `true`} {
		var v req
		err := decodeBytes(t, []byte(body), &v)
		var be *bodyError
		if !errors.As(err, &be) || be.status != http.StatusBadRequest {
			t.Errorf("%q: got %v, want a 400", body, err)
		}
	}
	for _, body := range []string{`{}`, ` {"name":"a"} `, "\n{\"name\":null}\n"} {
		var v req
		if err := decodeBytes(t, []byte(body), &v); err != nil {
			t.Errorf("%q: %v", body, err)
		}
	}
}

// TestUnknownFieldEchoesLittle: the name of an unknown field is the client's
// own text and as long as the body; the answer repeats only its start (found
// by fuzzing, FuzzDecodeBody).
func TestUnknownFieldEchoesLittle(t *testing.T) {
	t.Parallel()
	type req struct {
		Name string `json:"name"`
		At   *struct {
			N int `json:"n"`
		} `json:"at"`
	}
	for name, body := range map[string]string{
		"top level": `{"` + strings.Repeat("k", 100_000) + `":1}`,
		"nested":    `{"at":{"` + strings.Repeat("é", 50_000) + `":1}}`,
		"after one": `{"name":"a","` + strings.Repeat("~/", 30_000) + `":[]}`,
	} {
		err := decodeBytes(t, []byte(body), new(req))
		var be *bodyError
		if !errors.As(err, &be) || be.status != http.StatusBadRequest || len(be.fields) != 1 {
			t.Fatalf("%s: got %v, want a 400 with one field", name, err)
		}
		field := be.fields[0].Field
		if n := refusalText(be); n > 300 {
			t.Errorf("%s: the refusal says %d bytes", name, n)
		}
		if !utf8.ValidString(field) || !strings.HasSuffix(field, "…") || !strings.HasPrefix(field, "/") {
			t.Errorf("%s: field %.40q is not a clipped pointer", name, field)
		}
	}
	// A short name is named in full, with its whole path.
	err := decodeBytes(t, []byte(`{"at":{"nn":1}}`), new(req))
	var be *bodyError
	if !errors.As(err, &be) || be.fields[0].Field != "/at/nn" {
		t.Errorf("short name: %v", err)
	}
}

// TestParseErrorEchoesLittle: a value that does not parse (here a time) comes
// back in the text of the decoder; the answer cuts it (found by fuzzing,
// FuzzDecodeBody).
func TestParseErrorEchoesLittle(t *testing.T) {
	t.Parallel()
	var v struct {
		At *time.Time `json:"at"`
	}
	err := decodeBytes(t, []byte(`{"at":"`+strings.Repeat("9", 100_000)+`"}`), &v)
	var be *bodyError
	if !errors.As(err, &be) || be.status != http.StatusBadRequest {
		t.Fatalf("got %v, want a 400", err)
	}
	if n := refusalText(be); n > 300 {
		t.Errorf("the refusal says %d bytes", n)
	}
	if len(be.fields) != 1 || !strings.HasPrefix(be.fields[0].Message, "parsing time") {
		t.Errorf("the answer lost its reason: %+v", be.fields)
	}
}
