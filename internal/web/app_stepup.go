package web

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/auth"
	"github.com/Der-Felix/MyOwnPKI/internal/web/view"
)

const (
	pendingActionTTL     = 5 * time.Minute
	stepUpSelectorCookie = "__Secure-myownpki_step_up"
)

var errPendingAction = errors.New("the confirmation is invalid or expired; start the action again")

type actionSpec struct {
	fields  []string
	handler func(*rc)
}

type pendingAction struct {
	sessionIDHash    string
	userID           string
	credentialsEpoch int64
	createdAt        time.Time
	expiresAt        time.Time
	action           string
	path             map[string]string
	form             map[string]string
	archive          []byte
	back             string
	summary          string
}

func (p *pendingAction) clone() *pendingAction {
	if p == nil {
		return nil
	}
	out := *p
	out.path = cloneStrings(p.path)
	out.form = cloneStrings(p.form)
	out.archive = append([]byte(nil), p.archive...)
	return &out
}

func cloneStrings(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

type pendingActions struct {
	mu      sync.Mutex
	entries map[string]*pendingAction
}

func newPendingActions() *pendingActions {
	return &pendingActions{entries: map[string]*pendingAction{}}
}

func (s *pendingActions) put(entry *pendingAction) (string, error) {
	idBytes := make([]byte, 32)
	if _, err := rand.Read(idBytes); err != nil {
		return "", err
	}
	id := base64.RawURLEncoding.EncodeToString(idBytes)
	s.mu.Lock()
	defer s.mu.Unlock()
	for existingID, existing := range s.entries {
		if !entry.createdAt.Before(existing.expiresAt) {
			delete(s.entries, existingID)
		}
	}
	s.entries[id] = entry.clone()
	return id, nil
}

func (s *pendingActions) get(id string, binding auth.SessionBinding, userID string, now time.Time) (*pendingAction, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, err := s.validLocked(id, binding, userID, now)
	return entry.clone(), err
}

func (s *pendingActions) validLocked(id string, binding auth.SessionBinding, userID string, now time.Time) (*pendingAction, error) {
	entry := s.entries[id]
	if entry == nil {
		return nil, errPendingAction
	}
	if !now.Before(entry.expiresAt) {
		delete(s.entries, id)
		return nil, errPendingAction
	}
	if entry.sessionIDHash != binding.SessionIDHash || entry.userID != userID || entry.credentialsEpoch != binding.CredentialsEpoch {
		return nil, errPendingAction
	}
	return entry, nil
}

func (s *pendingActions) consume(id string, before, fresh auth.SessionBinding, userID string, now time.Time) (*pendingAction, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, err := s.validLocked(id, before, userID, now)
	if err != nil || fresh.SessionIDHash != before.SessionIDHash || fresh.CredentialsEpoch != before.CredentialsEpoch {
		return nil, errPendingAction
	}
	delete(s.entries, id)
	return entry.clone(), nil
}

func (a *app) protected(mux *http.ServeMux, pattern string, handler func(*rc), fields ...string) {
	spec := actionSpec{fields: fields, handler: handler}
	a.actions[pattern] = spec
	mux.HandleFunc(pattern, a.signedIn(func(c *rc) {
		if !c.normalizeAction(spec.fields) {
			return
		}
		handler(c)
	}))
}

func (c *rc) normalizeAction(fields []string) bool {
	allowed := make(map[string]bool, len(fields)+1)
	for _, field := range fields {
		allowed[field] = true
	}
	allowed[auth.CSRFField] = true
	normalized := make(url.Values, len(c.r.PostForm))
	for field, values := range c.r.PostForm {
		if !allowed[field] || len(values) != 1 {
			http.Error(c.w, "invalid action fields", http.StatusBadRequest)
			return false
		}
		normalized[field] = []string{values[0]}
	}
	if files := c.r.MultipartForm; files != nil {
		for field, values := range files.File {
			if c.r.Pattern != "POST /admin/import" || field != "archive" || len(values) != 1 {
				http.Error(c.w, "invalid action files", http.StatusBadRequest)
				return false
			}
		}
	}
	c.r.PostForm = normalized
	c.actionPattern = c.r.Pattern
	return true
}

func (c *rc) beginStepUp(back string) {
	if c.continuing {
		c.setFlash(view.Message{Kind: view.MessageError, Text: "The confirmation is no longer valid – start the action again."})
		c.redirect(back)
		return
	}
	if c.actionPattern == "" || safeNext(back) != back {
		c.setFlash(view.Message{Kind: view.MessageError, Text: "This action can't be continued – start it again."})
		c.redirect("/")
		return
	}
	if _, ok := c.a.actions[c.actionPattern]; !ok {
		c.setFlash(view.Message{Kind: view.MessageError, Text: "This action can't be continued – start it again."})
		c.redirect(back)
		return
	}
	now := c.a.now()
	binding := c.sess.Binding()
	entry := &pendingAction{
		sessionIDHash: binding.SessionIDHash, userID: c.sess.UserID, credentialsEpoch: binding.CredentialsEpoch,
		createdAt: now, expiresAt: now.Add(pendingActionTTL), action: c.actionPattern,
		path: map[string]string{}, form: map[string]string{}, archive: append([]byte(nil), c.actionArchive...), back: back,
	}
	for _, name := range actionPathNames(c.actionPattern) {
		entry.path[name] = c.r.PathValue(name)
	}
	for field, values := range c.r.PostForm {
		if field != auth.CSRFField && len(values) == 1 {
			entry.form[field] = values[0]
		}
	}
	entry.summary = c.a.actionSummary(c, entry)
	id, err := c.a.pending.put(entry)
	if err != nil {
		c.fail(err)
		return
	}
	setStepUpSelector(c.w, id, pendingActionTTL)
	c.redirect("/step-up")
}

func actionPathNames(pattern string) []string {
	_, path, _ := strings.Cut(pattern, " ")
	var names []string
	for _, segment := range strings.Split(path, "/") {
		if strings.HasPrefix(segment, "{") && strings.HasSuffix(segment, "}") {
			names = append(names, strings.TrimSuffix(strings.TrimPrefix(segment, "{"), "}"))
		}
	}
	return names
}

func actionPath(entry *pendingAction) string {
	_, path, _ := strings.Cut(entry.action, " ")
	for name, value := range entry.path {
		path = strings.ReplaceAll(path, "{"+name+"}", url.PathEscape(value))
	}
	return path
}

func setStepUpSelector(w http.ResponseWriter, id string, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name: stepUpSelectorCookie, Value: id, Path: "/step-up", MaxAge: int(ttl.Seconds()),
		Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
}

func clearStepUpSelector(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: stepUpSelectorCookie, Value: "", Path: "/step-up", MaxAge: -1,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
}

func (c *rc) pendingSelector() string {
	cookie, err := c.r.Cookie(stepUpSelectorCookie)
	if err != nil {
		return ""
	}
	return cookie.Value
}

func (c *rc) executePending(entry *pendingAction) bool {
	spec, ok := c.a.actions[entry.action]
	if !ok {
		http.Error(c.w, errPendingAction.Error(), http.StatusBadRequest)
		return false
	}
	path := actionPath(entry)
	r := c.r.Clone(c.r.Context())
	r.Pattern = entry.action
	r.URL = &url.URL{Path: path}
	r.RequestURI = path
	r.Header = c.r.Header.Clone()
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Body = http.NoBody
	r.ContentLength = 0
	r.MultipartForm = nil
	r.Form = make(url.Values, len(entry.form)+1)
	r.PostForm = make(url.Values, len(entry.form)+1)
	for field, value := range entry.form {
		r.Form[field] = []string{value}
		r.PostForm[field] = []string{value}
	}
	r.Form.Set(auth.CSRFField, c.sess.CSRFToken)
	r.PostForm.Set(auth.CSRFField, c.sess.CSRFToken)
	for name, value := range entry.path {
		r.SetPathValue(name, value)
	}
	c.r = r
	c.actionPattern = entry.action
	c.actionArchive = append([]byte(nil), entry.archive...)
	c.continuing = true
	spec.handler(c)
	return true
}
