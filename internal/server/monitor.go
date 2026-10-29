package server

import (
	"context"
	"log/slog"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/monitor"
	"github.com/Der-Felix/MyOwnPKI/internal/store"
	"github.com/Der-Felix/MyOwnPKI/internal/web"
)

// Monitoring jobs (docs/PHASE3.md §9).
const (
	jobMonitor      = "monitor"
	jobMonitorPrune = "monitor-prune"
	monitorEvery    = time.Minute
	// Resolved alerts are kept this long for the UI and the API.
	monitorKeep = 30 * 24 * time.Hour
)

var monitorWho = keys.Who{Actor: audit.Actor{Type: audit.ActorSystem, Name: "monitor"}, Principal: authz.System("monitor")}

// monitorSide evaluates the alert rules and keeps the alerts.
type monitorSide struct {
	eval  *monitor.Evaluator
	store *monitor.Store
}

// buildMonitor wires the evaluation; the configuration was validated, so
// the thresholds parse.
func (s *Server) buildMonitor() error {
	v, err := s.opt.Config.Monitor.Values()
	if err != nil {
		return err
	}
	rules := monitor.DefaultRules()
	rules.ExpiryWarn, rules.ExpiryCrit = v.ExpiryWarn, v.ExpiryCrit
	rules.CAWarn, rules.CACrit = v.CAWarn, v.CACrit
	rules.SealedAfter = v.SealedAfter
	rules.AgentSilentWarn = v.AgentSilent
	if rules.AgentSilentCrit < v.AgentSilent {
		rules.AgentSilentCrit = v.AgentSilent
	}
	rules.RepeatEvery = v.RepeatEvery
	m := &monitorSide{
		eval:  &monitor.Evaluator{Engine: s.engine, Seal: s.ring.Status, Rules: rules, Who: monitorWho},
		store: &monitor.Store{DB: s.sys.Write, Tenant: store.DefaultTenant},
	}
	if a := s.Agents(); a != nil {
		m.eval.Agents = a
	}
	s.monitor = m
	s.jobs.add(jobMonitor, monitorEvery, monitorEvery, s.evaluateAlerts)
	s.jobs.add(jobMonitorPrune, 24*time.Hour, 24*time.Hour, func(ctx context.Context) error {
		_, err := m.store.Prune(ctx, s.clk.Now().Add(-monitorKeep))
		return err
	})
	return nil
}

// evaluateAlerts runs the rules once and logs what changed.
func (s *Server) evaluateAlerts(ctx context.Context) error {
	now := s.clk.Now()
	found, err := s.monitor.eval.Evaluate(ctx, now)
	if err != nil {
		return err
	}
	ch, err := s.monitor.store.Sync(ctx, now, found)
	if err != nil {
		return err
	}
	for _, a := range ch.Opened {
		s.log.Warn("alert", slog.String("state", "opened"), slog.String("kind", a.Kind), slog.String("severity", a.Severity), slog.String("subject", a.Subject), slog.String("detail", a.Detail))
	}
	for _, a := range ch.Raised {
		s.log.Warn("alert", slog.String("state", "raised"), slog.String("kind", a.Kind), slog.String("severity", a.Severity), slog.String("subject", a.Subject), slog.String("detail", a.Detail))
	}
	for _, a := range ch.Lowered {
		s.log.Info("alert", slog.String("state", "lowered"), slog.String("kind", a.Kind), slog.String("severity", a.Severity), slog.String("subject", a.Subject))
	}
	for _, a := range ch.Resolved {
		s.log.Info("alert", slog.String("state", "resolved"), slog.String("kind", a.Kind), slog.String("subject", a.Subject))
	}
	return nil
}

// Alerts is the alert store for the UI and the API.
func (s *Server) Alerts() *monitor.Store {
	if s.monitor == nil {
		return nil
	}
	return s.monitor.store
}

// alertSource is the alert store as the UI's interface – nil (not a typed
// nil) without monitoring.
func (s *Server) alertSource() web.AlertSource {
	if s.monitor == nil {
		return nil
	}
	return s.monitor.store
}
