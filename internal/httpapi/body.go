package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// bodyError is a request the API can't take; it carries its answer.
type bodyError struct {
	status int
	kind   string
	msg    string
	fields []fieldError
}

func (e *bodyError) Error() string { return e.msg }

func badRequest(field, format string, args ...any) error {
	msg := fmt.Sprintf(format, args...)
	return &bodyError{status: http.StatusBadRequest, kind: "bad-request", msg: "invalid request", fields: []fieldError{{Field: field, Message: msg}}}
}

// decode reads the JSON body into v: one object, no unknown fields, nothing
// after it. Unknown fields are refused, so a typo like "valdity_days" never
// passes silently.
func (c *call) decode(v any) error {
	dec := json.NewDecoder(c.r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var tooLarge *http.MaxBytesError
		var syntax *json.SyntaxError
		var typeErr *json.UnmarshalTypeError
		switch {
		case errors.As(err, &tooLarge):
			return &bodyError{status: http.StatusRequestEntityTooLarge, kind: "too-large", msg: fmt.Sprintf("the body is larger than %d KiB", MaxBody>>10)}
		case errors.Is(err, io.EOF):
			return badRequest("", "the body is empty – a JSON object is required")
		case errors.As(err, &syntax):
			return badRequest("", "not valid JSON (at byte %d)", syntax.Offset)
		case errors.As(err, &typeErr):
			return badRequest("/"+strings.ReplaceAll(typeErr.Field, ".", "/"), "wrong type: want %s", typeErr.Type)
		case strings.HasPrefix(err.Error(), "json: unknown field "):
			name := strings.Trim(strings.TrimPrefix(err.Error(), "json: unknown field "), `"`)
			return badRequest("/"+name, "unknown field")
		}
		return badRequest("", "%v", err)
	}
	if dec.More() {
		return badRequest("", "data after the JSON object")
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return badRequest("", "data after the JSON object")
	}
	return nil
}

// reply writes v as JSON with status.
func (c *call) reply(status int, v any) error {
	c.status = status
	c.w.Header().Set("Content-Type", "application/json")
	c.w.WriteHeader(status)
	return json.NewEncoder(c.w).Encode(v)
}

// file writes a download as an attachment.
func (c *call) file(contentType, name string, data []byte) error {
	c.status = http.StatusOK
	c.w.Header().Set("Content-Type", contentType)
	c.w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	c.w.Header().Set("X-Content-Type-Options", "nosniff")
	c.w.WriteHeader(http.StatusOK)
	_, err := c.w.Write(data)
	return err
}

// fileName makes a safe download name from a CN, or falls back.
func fileName(cn, fallback string) string {
	cn = strings.ToLower(strings.ReplaceAll(cn, "*", "wildcard"))
	var b strings.Builder
	for _, r := range cn {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	if s := strings.Trim(b.String(), "._"); s != "" && len(s) <= 64 {
		return s
	}
	return fallback
}

// replyRaw writes JSON that is already encoded (WebAuthn options).
func (c *call) replyRaw(status int, data []byte) error {
	c.status = status
	c.w.Header().Set("Content-Type", "application/json")
	c.w.WriteHeader(status)
	_, err := c.w.Write(data)
	return err
}
