package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"unicode/utf8"
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

// maxEchoed is the most of the client's own text (a key, a value) that an
// answer repeats.
const maxEchoed = 200

// clipText cuts s to at most n bytes at a character boundary and marks the
// cut with an ellipsis.
func clipText(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "…"
}

// decode reads the JSON body into v: one object, no unknown fields, nothing
// after it. Unknown fields are refused, so a typo like "valdity_days" never
// passes silently.
func (c *call) decode(v any) error {
	// Read once (the body is limited by MaxBytesReader): an unknown field is
	// looked up a second time to name its full path.
	data, err := io.ReadAll(c.r.Body)
	if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
		limit := c.limit
		if limit <= 0 {
			limit = MaxBody
		}
		return &bodyError{status: http.StatusRequestEntityTooLarge, kind: "too-large", msg: fmt.Sprintf("the body is larger than %d KiB", limit>>10)}
	}
	if err != nil {
		return badRequest("", "the body can't be read")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var syntax *json.SyntaxError
		var typeErr *json.UnmarshalTypeError
		switch {
		case errors.Is(err, io.EOF):
			return badRequest("", "the body is empty – a JSON object is required")
		case errors.As(err, &syntax):
			return badRequest("", "not valid JSON (at byte %d)", syntax.Offset)
		case errors.As(err, &typeErr):
			return badRequest("/"+strings.ReplaceAll(typeErr.Field, ".", "/"), "wrong type: want %s", typeErr.Type)
		case strings.HasPrefix(err.Error(), "json: unknown field "):
			// The name is the client's own text and can be as long as the body.
			if path, ok := unknownFieldPath(data, v); ok {
				return badRequest(clipText(path, maxEchoed), "unknown field")
			}
			name := strings.Trim(strings.TrimPrefix(err.Error(), "json: unknown field "), `"`)
			return badRequest(clipText("/"+pointerToken(name), maxEchoed), "unknown field")
		}
		// The text of a value that does not parse (a time) repeats the client's own text.
		return badRequest("", "%s", clipText(err.Error(), maxEchoed))
	}
	// "null" decodes into a struct without an error and without a field, so
	// the one thing left to check is that the value is an object.
	if !bytes.HasPrefix(bytes.TrimLeft(data, " \t\r\n"), []byte("{")) {
		return badRequest("", "the body must be a JSON object")
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
