package auth

import (
	"crypto/subtle"
	"errors"
	"net/http"
)

// CSRF token transport: htmx sends the header (set from a <meta> tag), plain
// forms the hidden field.
const (
	CSRFHeader = "X-CSRF-Token"
	CSRFField  = "csrf_token"
)

// ErrCSRF: a state-changing request without the session's token.
var ErrCSRF = errors.New("missing or wrong CSRF token – reload the page")

// CSRF protects state-changing requests in two layers (security.md):
//
//  1. http.CrossOriginProtection refuses cross-origin requests by the
//     browser's Sec-Fetch-Site / Origin headers – this also covers the login
//     form, which has no session yet;
//  2. a request with a session must carry the session's token (header or
//     form field), compared in constant time.
//
// sessionToken returns the expected token of the request's session, or false
// when the request has none. GET, HEAD and OPTIONS pass unchecked: they must
// not change state.
func CSRF(next http.Handler, sessionToken func(*http.Request) (string, bool)) http.Handler {
	cop := http.NewCrossOriginProtection()
	check := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !safeMethod(r.Method) {
			if want, ok := sessionToken(r); ok {
				got := r.Header.Get(CSRFHeader)
				if got == "" {
					got = r.PostFormValue(CSRFField)
				}
				if want == "" || subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
					http.Error(w, ErrCSRF.Error(), http.StatusForbidden)
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
	return cop.Handler(check)
}

func safeMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions
}
