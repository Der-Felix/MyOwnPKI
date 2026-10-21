package httpapi

import (
	"bytes"
	"encoding"
	"encoding/json"
	"reflect"
	"strconv"
	"strings"
)

// unknownFieldPath finds the first field of data that the type of v has no
// place for and returns it as a JSON Pointer (RFC 6901), e.g.
// "/subject/cn". encoding/json only names the field ("cn"); a client with a
// nested typo needs the whole path. It walks the tokens in document order, as
// the decoder does, so it names the same field the decoder refused. ok is
// false when it finds none (it then can't say more than the decoder).
func unknownFieldPath(data []byte, v any) (path string, ok bool) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	path, ok, _ = walkJSON(dec, reflect.TypeOf(v), "")
	return path, ok
}

var (
	rawMessageType  = reflect.TypeFor[json.RawMessage]()
	unmarshalerType = reflect.TypeFor[json.Unmarshaler]()
	textUnmarshaler = reflect.TypeFor[encoding.TextUnmarshaler]()
)

// walkJSON reads one value from dec, checked against t. It returns the path
// of the first unknown field; err ends the walk (malformed input – the
// decoder has reported that already).
func walkJSON(dec *json.Decoder, t reflect.Type, at string) (string, bool, error) {
	for t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t == nil || t == rawMessageType || t.Kind() == reflect.Interface ||
		reflect.PointerTo(t).Implements(unmarshalerType) || reflect.PointerTo(t).Implements(textUnmarshaler) {
		return "", false, skipJSON(dec) // decoded by its own rules
	}
	tok, err := dec.Token()
	if err != nil {
		return "", false, err
	}
	switch tok {
	case json.Delim('{'):
		for dec.More() {
			keyTok, kerr := dec.Token()
			if kerr != nil {
				return "", false, kerr
			}
			key, _ := keyTok.(string)
			var ft reflect.Type
			switch t.Kind() {
			case reflect.Struct:
				f, found := jsonField(t, key)
				if !found {
					return at + "/" + pointerToken(key), true, nil
				}
				ft = f
			case reflect.Map:
				ft = t.Elem()
			default:
				ft = nil // an object where the type wants something else: the decoder says so
			}
			if p, found, werr := walkJSON(dec, ft, at+"/"+pointerToken(key)); found || werr != nil {
				return p, found, werr
			}
		}
		_, err = dec.Token() // '}'
		return "", false, err
	case json.Delim('['):
		var et reflect.Type
		if t.Kind() == reflect.Slice || t.Kind() == reflect.Array {
			et = t.Elem()
		}
		for i := 0; dec.More(); i++ {
			if p, found, werr := walkJSON(dec, et, at+"/"+strconv.Itoa(i)); found || werr != nil {
				return p, found, werr
			}
		}
		_, err = dec.Token() // ']'
		return "", false, err
	}
	return "", false, nil // a scalar
}

// skipJSON reads and drops one value.
func skipJSON(dec *json.Decoder) error {
	var raw json.RawMessage
	return dec.Decode(&raw)
}

// jsonField finds the field the decoder would fill for key: the exact name
// first, then – like encoding/json – any case. Embedded structs without a
// tag are searched as well.
func jsonField(t reflect.Type, key string) (reflect.Type, bool) {
	var fold reflect.Type
	var walk func(t reflect.Type) (reflect.Type, bool)
	walk = func(t reflect.Type) (reflect.Type, bool) {
		for i := range t.NumField() {
			f := t.Field(i)
			tag := f.Tag.Get("json")
			if tag == "-" {
				continue
			}
			name, _, _ := strings.Cut(tag, ",")
			if f.Anonymous && name == "" {
				et := f.Type
				if et.Kind() == reflect.Pointer {
					et = et.Elem()
				}
				if et.Kind() == reflect.Struct {
					if ft, ok := walk(et); ok {
						return ft, true
					}
					continue
				}
			}
			if !f.IsExported() {
				continue
			}
			if name == "" {
				name = f.Name
			}
			if name == key {
				return f.Type, true
			}
			if fold == nil && strings.EqualFold(name, key) {
				fold = f.Type
			}
		}
		return nil, false
	}
	if ft, ok := walk(t); ok {
		return ft, true
	}
	return fold, fold != nil
}

// pointerToken escapes a key for a JSON Pointer (RFC 6901 §3).
func pointerToken(key string) string {
	return strings.ReplaceAll(strings.ReplaceAll(key, "~", "~0"), "/", "~1")
}
