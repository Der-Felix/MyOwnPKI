package httpapi

import (
	"encoding/json"
	"errors"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/auth"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
)

// Problem types are URNs (api/openapi.yaml, schema Problem).
const problemPrefix = "urn:myownpki:problem:"

type fieldError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

type problemDoc struct {
	Type      string       `json:"type"`
	Title     string       `json:"title"`
	Status    int          `json:"status"`
	Detail    string       `json:"detail,omitempty"`
	RequestID string       `json:"request_id"`
	Errors    []fieldError `json:"errors,omitempty"`
}

// errReply is an error that already wrote its answer.
var errReply = errors.New("reply written")

// problem writes an RFC 9457 answer and returns errReply.
func (c *call) problem(status int, kind, detail string, errs []fieldError) error {
	c.status = status
	c.w.Header().Set("Content-Type", "application/problem+json")
	c.w.WriteHeader(status)
	_ = json.NewEncoder(c.w).Encode(problemDoc{
		Type: problemPrefix + kind, Title: http.StatusText(status), Status: status, Detail: detail, RequestID: c.reqID, Errors: errs,
	})
	return errReply
}

// retryAfter sets Retry-After in whole seconds, at least one.
func (c *call) retryAfter(d time.Duration) {
	c.w.Header().Set("Retry-After", strconv.Itoa(max(1, int(math.Ceil(d.Seconds())))))
}

// fail maps a service error to its answer (PHASE1 step 13 wiring notes).
// Anything unknown is a 500 with only the request ID; the details go to the
// process log.
func (c *call) fail(err error) {
	if errors.Is(err, errReply) {
		return
	}
	if agentError(c, err) {
		return
	}
	var authLocked *auth.LockedError
	var keysLocked *keys.LockedError
	var denied *ca.DeniedError
	var body *bodyError
	switch {
	case errors.As(err, &body):
		_ = c.problem(body.status, body.kind, body.Error(), body.fields)
	case errors.Is(err, auth.ErrNoSession):
		_ = c.problem(http.StatusUnauthorized, "unauthorized", auth.ErrNoSession.Error(), nil)
	case errors.Is(err, auth.ErrInvalidLogin):
		_ = c.problem(http.StatusUnauthorized, "unauthorized", auth.ErrInvalidLogin.Error(), nil)
	case errors.As(err, &authLocked):
		c.retryAfter(authLocked.RetryAfter)
		_ = c.problem(http.StatusTooManyRequests, "rate-limited", authLocked.Error(), nil)
	case errors.As(err, &keysLocked):
		c.retryAfter(keysLocked.RetryAfter)
		_ = c.problem(http.StatusTooManyRequests, "rate-limited", keysLocked.Error(), nil)
	case errors.Is(err, auth.ErrBusy):
		c.retryAfter(time.Second)
		_ = c.problem(http.StatusServiceUnavailable, "busy", auth.ErrBusy.Error(), nil)
	case errors.Is(err, keys.ErrSealed):
		_ = c.problem(http.StatusServiceUnavailable, "sealed", "the server is sealed – an instance admin must unseal it before anything can be signed", nil)
	case errors.Is(err, keys.ErrWrongSecret):
		_ = c.problem(http.StatusUnprocessableEntity, "wrong-secret", keys.ErrWrongSecret.Error(), nil)
	case errors.Is(err, keys.ErrAlreadyUnsealed):
		_ = c.problem(http.StatusConflict, "conflict", keys.ErrAlreadyUnsealed.Error(), nil)
	case errors.Is(err, ca.ErrNotFound):
		_ = c.problem(http.StatusNotFound, "not-found", "no such object, or you may not see it", nil)
	case errors.Is(err, ca.ErrNoStoredKey):
		_ = c.problem(http.StatusConflict, "conflict", ca.ErrNoStoredKey.Error(), nil)
	case errors.Is(err, ca.ErrKeyDeleted):
		_ = c.problem(http.StatusConflict, "conflict", ca.ErrKeyDeleted.Error(), nil)
	case errors.Is(err, authz.ErrStepUpRequired):
		_ = c.problem(http.StatusForbidden, "step-up-required", "confirm with a fresh code first (POST /auth/step-up)", nil)
	case errors.Is(err, authz.ErrDenied):
		_ = c.problem(http.StatusForbidden, "forbidden", deniedText(err, denied), nil)
	case errors.As(err, &denied):
		fields := make([]fieldError, 0, len(denied.Reasons))
		for _, r := range denied.Reasons {
			fields = append(fields, fieldError{Field: "", Message: r})
		}
		_ = c.problem(http.StatusUnprocessableEntity, "policy-violation", "the request violates the policy", fields)
	default:
		c.api.d.Log.Error("api error", slog.String("request_id", c.reqID), slog.String("method", c.r.Method),
			slog.String("path", c.r.URL.Path), slog.Any("error", err))
		_ = c.problem(http.StatusInternalServerError, "internal", "internal error – the server log has the details under this request ID", nil)
	}
}

// deniedText is the reason of a permission refusal, without the internals.
func deniedText(err error, denied *ca.DeniedError) string {
	var token *authz.TokenStepUpError
	if errors.As(err, &token) {
		return token.Error()
	}
	if errors.As(err, &denied) && len(denied.Reasons) > 0 {
		return denied.Reasons[0]
	}
	return "your role doesn't allow this"
}
