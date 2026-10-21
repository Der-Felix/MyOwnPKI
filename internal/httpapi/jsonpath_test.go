package httpapi

import (
	"encoding/json"
	"testing"
	"time"
)

func TestUnknownFieldPath(t *testing.T) {
	t.Parallel()
	type inner struct {
		Name string `json:"name"`
	}
	type Embedded struct {
		Note string `json:"note"`
	}
	type outer struct {
		Embedded
		ID     string             `json:"id"`
		Inner  *inner             `json:"inner"`
		List   []inner            `json:"list"`
		Labels map[string]inner   `json:"labels"`
		Raw    json.RawMessage    `json:"raw"`
		When   time.Time          `json:"when"`
		Any    any                `json:"any"`
		Plain  string             // no tag: the Go name
		Skip   string             `json:"-"`
		Deep   map[string][]inner `json:"deep"`
	}
	for body, want := range map[string]string{
		`{"id":"x","bogus":1}`:                             "/bogus",
		`{"inner":{"name":"a","nam":"b"}}`:                 "/inner/nam",
		`{"list":[{"name":"a"},{"name":"b","x":1}]}`:       "/list/1/x",
		`{"labels":{"a/b~c":{"name":"a","y":2}}}`:          "/labels/a~1b~0c/y",
		`{"deep":{"k":[{},{"z":true}]}}`:                   "/deep/k/1/z",
		`{"raw":{"anything":1},"any":{"goes":2},"zz":0}`:   "/zz",
		`{"when":"2026-10-21T00:00:00Z","note":"n","q":1}`: "/q",
		`{"INNER":{"NAME":"a","other":1}}`:                 "/INNER/other",
		`{"Plain":"p","Skip":"s"}`:                         "/Skip",
	} {
		var v outer
		got, ok := unknownFieldPath([]byte(body), &v)
		if !ok || got != want {
			t.Errorf("%s: %q %v, want %q", body, got, ok, want)
		}
	}
	var v outer
	if got, ok := unknownFieldPath([]byte(`{"id":"x","inner":{"name":"a"}}`), &v); ok {
		t.Errorf("all fields known, got %q", got)
	}
}
