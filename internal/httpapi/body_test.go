package httpapi

import (
	"errors"
	"net/http"
	"testing"
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
