package httpapi

import (
	"errors"
	"net/http"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/agents"
)

// Agents (v0.3, docs/PHASE3.md): the approval queue, join tokens, agents
// and their names. Everything the agents reported is data here.

type agentNameJSON struct {
	Name    string    `json:"name"`
	Source  string    `json:"source"`
	AddedBy string    `json:"added_by"`
	AddedAt time.Time `json:"added_at"`
}

type agentJSON struct {
	ID             string                `json:"id"`
	Hostname       string                `json:"hostname"`
	Status         string                `json:"status"`
	EnrollmentMode string                `json:"enrollment_mode"`
	OS             string                `json:"os"`
	Arch           string                `json:"arch"`
	Version        string                `json:"version"`
	CreatedAt      time.Time             `json:"created_at"`
	ApprovedAt     time.Time             `json:"approved_at"`
	ApprovedBy     string                `json:"approved_by"`
	LastSeenAt     *time.Time            `json:"last_seen_at"`
	CertificateID  *string               `json:"certificate_id"`
	Names          []agentNameJSON       `json:"names"`
	Silent         bool                  `json:"silent"`
	Deployments    []agentDeploymentJSON `json:"deployments"`
}

type agentDeploymentJSON struct {
	Name             string     `json:"name"`
	Profile          string     `json:"profile"`
	Names            []string   `json:"names"`
	Challenge        string     `json:"challenge"`
	State            string     `json:"state"`
	Serial           string     `json:"serial"`
	CertificateID    *string    `json:"certificate_id"`
	NotAfter         *time.Time `json:"not_after"`
	DeployedAt       *time.Time `json:"deployed_at"`
	Fingerprint      string     `json:"fingerprint"`
	LastError        string     `json:"last_error"`
	LastReportAt     time.Time  `json:"last_report_at"`
	RenewRequestedAt *time.Time `json:"renew_requested_at"`
	RenewRequestedBy string     `json:"renew_requested_by"`
	Removed          bool       `json:"removed"`
}

func timeOrNil(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

func toAgentJSON(a *agents.Agent) agentJSON {
	out := agentJSON{
		ID: a.ID, Hostname: a.Hostname, Status: a.Status, EnrollmentMode: a.EnrollmentMode, OS: a.OS, Arch: a.Arch,
		Version: a.Version, CreatedAt: a.CreatedAt, ApprovedAt: a.ApprovedAt, ApprovedBy: a.ApprovedBy, Names: []agentNameJSON{}, Deployments: []agentDeploymentJSON{},
	}
	if !a.LastSeenAt.IsZero() {
		out.LastSeenAt = &a.LastSeenAt
	}
	if a.CertificateID != "" {
		out.CertificateID = &a.CertificateID
	}
	for _, n := range a.Names {
		out.Names = append(out.Names, agentNameJSON{Name: n.Pattern, Source: n.Source, AddedBy: n.AddedBy, AddedAt: n.AddedAt})
	}
	for _, d := range a.Deployments {
		row := agentDeploymentJSON{Name: d.Name, Profile: d.Profile, Names: nonNil(d.Names), Challenge: d.Challenge, State: d.State,
			Serial: d.Serial, NotAfter: timeOrNil(d.NotAfter), DeployedAt: timeOrNil(d.DeployedAt), Fingerprint: d.Fingerprint,
			LastError: d.LastError, LastReportAt: d.LastReportAt, RenewRequestedAt: timeOrNil(d.RenewRequestedAt),
			RenewRequestedBy: d.RenewRequestedBy, Removed: d.Removed}
		if d.CertificateID != "" {
			row.CertificateID = &d.CertificateID
		}
		out.Deployments = append(out.Deployments, row)
	}
	return out
}

type enrollmentJSON struct {
	ID           string     `json:"id"`
	Hostname     string     `json:"hostname"`
	State        string     `json:"state"`
	CheckMethod  string     `json:"check_method"`
	CheckState   string     `json:"check_state"`
	CheckError   string     `json:"check_error"`
	TokenValid   bool       `json:"token_valid"`
	TokenProblem string     `json:"token_problem"`
	KnownAgent   bool       `json:"known_agent"`
	AgentID      *string    `json:"agent_id"`
	OS           string     `json:"os"`
	Arch         string     `json:"arch"`
	Version      string     `json:"version"`
	SourceIP     string     `json:"source_ip"`
	CreatedAt    time.Time  `json:"created_at"`
	ExpiresAt    time.Time  `json:"expires_at"`
	DecidedAt    *time.Time `json:"decided_at"`
	DecidedBy    string     `json:"decided_by"`
}

func toEnrollmentJSON(e agents.Enrollment) enrollmentJSON {
	out := enrollmentJSON{
		ID: e.ID, Hostname: e.Hostname, State: e.State, CheckMethod: e.CheckMethod, CheckState: e.CheckState, CheckError: e.CheckError,
		TokenValid: e.TokenValid, TokenProblem: e.TokenProblem, KnownAgent: e.KnownAgent, OS: e.OS, Arch: e.Arch, Version: e.Version,
		SourceIP: e.SourceIP, CreatedAt: e.CreatedAt, ExpiresAt: e.ExpiresAt, DecidedBy: e.DecidedBy,
	}
	if e.AgentID != "" {
		out.AgentID = &e.AgentID
	}
	if !e.DecidedAt.IsZero() {
		out.DecidedAt = &e.DecidedAt
	}
	return out
}

type joinTokenJSON struct {
	ID        string     `json:"id"`
	Label     string     `json:"label"`
	Names     []string   `json:"names"`
	ExpiresAt time.Time  `json:"expires_at"`
	UsedAt    *time.Time `json:"used_at"`
	UsedBy    string     `json:"used_by"`
	CreatedBy string     `json:"created_by"`
	CreatedAt time.Time  `json:"created_at"`
}

func toJoinTokenJSON(j agents.JoinToken) joinTokenJSON {
	out := joinTokenJSON{ID: j.ID, Label: j.Label, Names: j.Patterns, ExpiresAt: j.ExpiresAt, UsedBy: j.UsedBy, CreatedBy: j.CreatedBy, CreatedAt: j.CreatedAt}
	if !j.UsedAt.IsZero() {
		out.UsedAt = &j.UsedAt
	}
	return out
}

// agentsOn returns the service, or answers 404 while agents are off.
func (a *API) agentsOn(c *call) (*agents.Service, error) {
	if a.d.Agents == nil {
		return nil, c.problem(http.StatusNotFound, "not-found", "agents are off – set agent.base_url in the server's config", nil)
	}
	return a.d.Agents, nil
}

func (a *API) listAgents(c *call) error {
	s, err := a.agentsOn(c)
	if err != nil {
		return err
	}
	list, err := s.ListAgents(c.ctx(), c.who())
	if err != nil {
		return err
	}
	out := make([]agentJSON, 0, len(list))
	for i := range list {
		full, gerr := s.GetAgent(c.ctx(), c.who(), list[i].ID)
		if gerr != nil {
			return gerr
		}
		row := toAgentJSON(full)
		row.Silent = full.Silent(a.d.Clock.Now())
		out = append(out, row)
	}
	return c.reply(http.StatusOK, out)
}

func pathID(c *call, name string) string {
	id := c.r.PathValue(name)
	if !idPattern.MatchString(id) {
		return ""
	}
	return id
}

func (a *API) replyAgent(c *call, s *agents.Service, id string) error {
	ag, err := s.GetAgent(c.ctx(), c.who(), id)
	if err != nil {
		return err
	}
	out := toAgentJSON(ag)
	out.Silent = ag.Silent(a.d.Clock.Now())
	return c.reply(http.StatusOK, out)
}

func (a *API) renewAgentDeployment(c *call) error {
	s, err := a.agentsOn(c)
	if err != nil {
		return err
	}
	id := pathID(c, "agentId")
	if id == "" {
		return agents.ErrNotFound
	}
	if rerr := s.RequestRenewal(c.ctx(), c.who(), id, c.r.PathValue("deploymentName")); rerr != nil {
		return rerr
	}
	ag, err := s.GetAgent(c.ctx(), c.who(), id)
	if err != nil {
		return err
	}
	out := toAgentJSON(ag)
	out.Silent = ag.Silent(a.d.Clock.Now())
	return c.reply(http.StatusAccepted, out)
}

func (a *API) withdrawAgentDeployment(c *call) error {
	s, err := a.agentsOn(c)
	if err != nil {
		return err
	}
	id := pathID(c, "agentId")
	if id == "" {
		return agents.ErrNotFound
	}
	if werr := s.WithdrawRenewal(c.ctx(), c.who(), id, c.r.PathValue("deploymentName")); werr != nil {
		return werr
	}
	return a.replyAgent(c, s, id)
}

func (a *API) getAgent(c *call) error {
	s, err := a.agentsOn(c)
	if err != nil {
		return err
	}
	id := pathID(c, "agentId")
	if id == "" {
		return agents.ErrNotFound
	}
	return a.replyAgent(c, s, id)
}

// agentAction runs a change on one agent and answers with the agent.
func (a *API) agentAction(c *call, do func(s *agents.Service, id string) error) error {
	s, err := a.agentsOn(c)
	if err != nil {
		return err
	}
	id := pathID(c, "agentId")
	if id == "" {
		return agents.ErrNotFound
	}
	if err := do(s, id); err != nil {
		return err
	}
	return a.replyAgent(c, s, id)
}

func (a *API) disableAgent(c *call) error {
	return a.agentAction(c, func(s *agents.Service, id string) error { return s.SetDisabled(c.ctx(), c.who(), id, true) })
}

func (a *API) enableAgent(c *call) error {
	return a.agentAction(c, func(s *agents.Service, id string) error { return s.SetDisabled(c.ctx(), c.who(), id, false) })
}

func (a *API) revokeAgent(c *call) error {
	return a.agentAction(c, func(s *agents.Service, id string) error { return s.Revoke(c.ctx(), c.who(), id) })
}

func (a *API) changeAgentNames(c *call) error {
	var req struct {
		Add    []string `json:"add"`
		Remove []string `json:"remove"`
	}
	if err := c.decode(&req); err != nil {
		return err
	}
	if len(req.Add) > 50 || len(req.Remove) > 50 {
		return badRequest("/add", "at most 50 names per request")
	}
	return a.agentAction(c, func(s *agents.Service, id string) error {
		for _, n := range req.Add {
			if err := s.AddName(c.ctx(), c.who(), id, n); err != nil {
				return err
			}
		}
		for _, n := range req.Remove {
			if err := s.RemoveName(c.ctx(), c.who(), id, n); err != nil {
				return err
			}
		}
		return nil
	})
}

func (a *API) listAgentEnrollments(c *call) error {
	s, err := a.agentsOn(c)
	if err != nil {
		return err
	}
	open := true
	switch c.r.URL.Query().Get("state") {
	case "", "open":
	case "all":
		open = false
	default:
		return badRequest("/state", "open or all")
	}
	list, err := s.ListEnrollments(c.ctx(), c.who(), open)
	if err != nil {
		return err
	}
	out := make([]enrollmentJSON, 0, len(list))
	for _, e := range list {
		out = append(out, toEnrollmentJSON(e))
	}
	return c.reply(http.StatusOK, out)
}

func (a *API) decideEnrollment(c *call, approve bool) error {
	s, err := a.agentsOn(c)
	if err != nil {
		return err
	}
	id := pathID(c, "enrollmentId")
	if id == "" {
		return agents.ErrNotFound
	}
	if approve {
		err = s.Approve(c.ctx(), c.who(), id)
	} else {
		err = s.Deny(c.ctx(), c.who(), id)
	}
	if err != nil {
		return err
	}
	c.status = http.StatusNoContent
	c.w.WriteHeader(http.StatusNoContent)
	return nil
}

func (a *API) approveAgentEnrollment(c *call) error { return a.decideEnrollment(c, true) }
func (a *API) denyAgentEnrollment(c *call) error    { return a.decideEnrollment(c, false) }

func (a *API) listAgentJoinTokens(c *call) error {
	s, err := a.agentsOn(c)
	if err != nil {
		return err
	}
	list, err := s.ListJoinTokens(c.ctx(), c.who())
	if err != nil {
		return err
	}
	out := make([]joinTokenJSON, 0, len(list))
	for _, j := range list {
		out = append(out, toJoinTokenJSON(j))
	}
	return c.reply(http.StatusOK, out)
}

func (a *API) createAgentJoinToken(c *call) error {
	s, err := a.agentsOn(c)
	if err != nil {
		return err
	}
	var req struct {
		Label      string   `json:"label"`
		Names      []string `json:"names"`
		ValidHours int      `json:"valid_hours"`
	}
	if derr := c.decode(&req); derr != nil {
		return derr
	}
	if len(req.Names) == 0 {
		return badRequest("/names", "required: the names or patterns the hostname must match")
	}
	if req.ValidHours < 0 || req.ValidHours > 720 {
		return badRequest("/valid_hours", "1 to 720")
	}
	secret, jt, err := s.CreateJoinToken(c.ctx(), c.who(), req.Label, req.Names, time.Duration(req.ValidHours)*time.Hour)
	if err != nil {
		return err
	}
	c.w.Header().Set("Cache-Control", "no-store")
	return c.reply(http.StatusCreated, struct {
		joinTokenJSON
		Secret string `json:"secret"`
	}{toJoinTokenJSON(*jt), secret})
}

func (a *API) deleteAgentJoinToken(c *call) error {
	s, err := a.agentsOn(c)
	if err != nil {
		return err
	}
	id := pathID(c, "joinTokenId")
	if id == "" {
		return agents.ErrNotFound
	}
	if err := s.DeleteJoinToken(c.ctx(), c.who(), id); err != nil {
		return err
	}
	c.status = http.StatusNoContent
	c.w.WriteHeader(http.StatusNoContent)
	return nil
}

// agentError maps the service's own errors (fail has the shared ones).
func agentError(c *call, err error) bool {
	switch {
	case errors.Is(err, agents.ErrInvalid):
		_ = c.problem(http.StatusUnprocessableEntity, "policy-violation", err.Error(), nil)
	case errors.Is(err, agents.ErrConflict):
		_ = c.problem(http.StatusConflict, "conflict", err.Error(), nil)
	default:
		return false
	}
	return true
}
