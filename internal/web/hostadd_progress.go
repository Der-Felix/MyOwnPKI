package web

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/agents"
	"github.com/Der-Felix/MyOwnPKI/internal/web/view"
)

// The progress page of the Add host assistant (step 3) answers one question:
// where is this host on the way from "nothing" to "certificate deployed"? It
// stores nothing. Everything comes from the agent service: the enrollments of
// the host name, the agent, and the deployments the agent reported.

// hostStage is one row of the progress table.
type hostStage struct {
	Name   string
	State  string // plain words, from a fixed vocabulary
	Status view.Status
	Detail string // clipped, one line
	Link   string // the certificate page, once there is one
}

// hostProgress is the whole picture for one host name.
type hostProgress struct {
	Host     string
	Stages   []hostStage
	Complete bool
	// Pending is the enrollment that waits for an admin's decision, if any.
	Pending *agents.Enrollment
	// Agent is the agent of the host, if it has one that is not revoked.
	Agent *agents.Agent
}

// pickAgent chooses the agent the progress page follows: an active one first,
// else a disabled one, else a revoked one; the newest of its kind.
func pickAgent(list []agents.Agent, host string) *agents.Agent {
	rank := func(a agents.Agent) int {
		switch a.Status {
		case agents.StatusActive:
			return 0
		case agents.StatusDisabled:
			return 1
		}
		return 2
	}
	var best *agents.Agent
	for i := range list {
		a := &list[i]
		if a.Hostname != host {
			continue
		}
		if best == nil || rank(*a) < rank(*best) || rank(*a) == rank(*best) && a.ApprovedAt.After(best.ApprovedAt) {
			best = a
		}
	}
	return best
}

// latestEnrollment is the newest enrollment of the host name.
func latestEnrollment(list []agents.Enrollment, host string) *agents.Enrollment {
	var best *agents.Enrollment
	for i := range list {
		e := &list[i]
		if e.Hostname == host && (best == nil || e.CreatedAt.After(best.CreatedAt)) {
			best = e
		}
	}
	return best
}

// since describes how long ago t was, coarsely.
func since(now, t time.Time) string {
	d := now.Sub(t)
	switch {
	case t.IsZero():
		return ""
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%d minutes ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d hours ago", int(d.Hours()))
	}
	return fmt.Sprintf("%d days ago", int(d.Hours()/24))
}

// buildHostProgress turns what the service knows into the stages. ag is the
// agent with its deployments (GetAgent), nil if the host has none; enrollments
// are those of the host name. Text that came from a host or a failed check is
// clipped to one line; the page escapes it.
func buildHostProgress(now time.Time, host string, ag *agents.Agent, enrollments []agents.Enrollment) hostProgress {
	p := hostProgress{Host: host}
	enrolled := hostStage{Name: "Host enrolled"}
	online := hostStage{Name: "Agent online", State: "not yet", Status: view.StatusNeutral}
	usable := false // an agent that is admitted and not cut off
	switch {
	case ag != nil && ag.Status == agents.StatusRevoked:
		enrolled.State, enrolled.Status = "agent revoked", view.StatusCrit
		enrolled.Detail = "The agent of this host was revoked on the agent page. Enroll the host again with a new token to continue."
	case ag != nil:
		p.Agent = ag
		usable = ag.Status == agents.StatusActive
		enrolled.State, enrolled.Status = "admitted", view.StatusOK
		enrolled.Detail = "Admitted " + dateTime(ag.ApprovedAt) + " by " + clipText(ag.ApprovedBy, 60) + "."
	default:
		e := latestEnrollment(enrollments, host)
		switch {
		case e == nil:
			enrolled.State, enrolled.Status = "waiting for the host", view.StatusNeutral
			enrolled.Detail = "Nothing has arrived yet. Run the commands of the previous step on the host as root."
		case e.State == agents.StateWaitingForCheck:
			enrolled.State, enrolled.Status = "checking", view.StatusInfo
			enrolled.Detail = "The host has asked to enroll; the server is checking that it controls the name (http-01)."
		case e.State == agents.StatePending:
			enrolled.State, enrolled.Status = "waiting for your approval", view.StatusWarn
			enrolled.Detail = enrollmentDetail(*e)
			p.Pending = e
		case e.State == agents.StateDenied:
			enrolled.State, enrolled.Status = "refused", view.StatusCrit
			enrolled.Detail = "Refused" + decidedBy(*e) + ". Run setup on the host again with a new token to start over."
		case e.State == agents.StateExpired:
			enrolled.State, enrolled.Status = "expired", view.StatusWarn
			enrolled.Detail = "Nobody decided in time. Run setup on the host again."
		default: // admitted: the agent record follows within a moment
			enrolled.State, enrolled.Status = "admitted", view.StatusInfo
			enrolled.Detail = "The host is admitted; its certificate follows within about 30 seconds."
		}
	}
	if p.Agent != nil {
		switch {
		case p.Agent.Status == agents.StatusDisabled:
			online.State, online.Status = "disabled", view.StatusNeutral
			online.Detail = "The agent is disabled on its page; it is cut off at its next call."
		case p.Agent.LastSeenAt.IsZero():
			online.State, online.Status = "waiting for the first report", view.StatusInfo
			online.Detail = "The agent is admitted and has not reported yet. On the host: systemctl status myownpki-agent."
		case p.Agent.Silent(now):
			online.State, online.Status = "silent", view.StatusWarn
			online.Detail = "Last seen " + dateTime(p.Agent.LastSeenAt) + " (" + since(now, p.Agent.LastSeenAt) + "). Is the agent running?"
		default:
			online.State, online.Status = "online", view.StatusOK
			online.Detail = "Last seen " + dateTime(p.Agent.LastSeenAt) + " (" + since(now, p.Agent.LastSeenAt) + "), version " + orDash(clipText(p.Agent.Version, 40)) + "."
		}
	}
	p.Stages = []hostStage{enrolled, online}

	var deployments []agents.Deployment
	if p.Agent != nil {
		deployments = slices.DeleteFunc(slices.Clone(p.Agent.Deployments), func(d agents.Deployment) bool { return d.Removed })
	}
	allDeployed := len(deployments) > 0
	for _, d := range deployments {
		st := hostStage{Name: "Certificate for deployment " + d.Name, State: strings.ReplaceAll(d.State, "_", " "), Status: deploymentStatus(d.State)}
		switch d.State {
		case "deployed":
			st.Detail = "Serial " + orDash(d.Serial) + ", expires " + dateTime(d.NotAfter) + "."
			if d.CertificateID != "" {
				st.Link = "/certificates/" + d.CertificateID
			}
		case "failed", "rolled_back":
			allDeployed = false
			st.Detail = orDash(clipText(d.LastError, 300))
		default:
			allDeployed = false
			st.Detail = "The agent is working on it."
			if d.LastError != "" {
				st.Detail += " Last error: " + clipText(d.LastError, 300)
			}
		}
		p.Stages = append(p.Stages, st)
	}
	if len(deployments) == 0 {
		st := hostStage{Name: "First certificate", State: "not yet", Status: view.StatusNeutral, Detail: "No deployment reported yet."}
		if p.Agent != nil && usable {
			st.Detail = "The agent has not reported a deployment. Run the deployment block of the previous step on the host; it restarts the agent, which then asks for the certificate."
		}
		p.Stages = append(p.Stages, st)
	}
	p.Complete = usable && !p.Agent.Silent(now) && allDeployed
	return p
}

// enrollmentDetail says why an enrollment waits: from where, with which secret,
// and what the check said.
func enrollmentDetail(e agents.Enrollment) string {
	with := "no join token"
	switch {
	case e.KnownAgent:
		with = "a known agent key"
	case e.TokenValid:
		with = "a valid join token"
	case e.TokenProblem != "":
		with = clipText(e.TokenProblem, 120)
	}
	check := e.CheckState
	switch e.CheckState {
	case "passed":
		check = "the http-01 check passed"
	case "failed":
		check = "the http-01 check failed: " + orDash(clipText(e.CheckError, 200))
	default:
		check = "the http-01 check is " + clipText(check, 30)
	}
	return "From " + clipText(e.SourceIP, 64) + " on " + dateTime(e.CreatedAt) + " with " + with + "; " + check + ". Approve it only if you expect this host."
}

func decidedBy(e agents.Enrollment) string {
	if e.DecidedBy == "" {
		return ""
	}
	return " by " + clipText(e.DecidedBy, 60)
}
