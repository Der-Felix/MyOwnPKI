package config

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Monitor holds the thresholds of the monitoring (docs/PHASE3.md §9.2). Like
// every key they are strings, so environment variables can set them.
type Monitor struct {
	// ExpiryDays: warning and critical days before an end-entity
	// certificate expires, "14, 3".
	ExpiryDays string `yaml:"expiry_days"`
	// CAExpiryDays: the same for CA certificates, "90, 30".
	CAExpiryDays string `yaml:"ca_expiry_days"`
	// SealedAfter: how long the server may stay sealed before it alerts.
	SealedAfter string `yaml:"sealed_after"`
	// AgentSilentAfter: how long an agent may be silent before it alerts.
	AgentSilentAfter string `yaml:"agent_silent_after"`
	// RepeatEvery: the reminder for an alert that is still open.
	RepeatEvery string `yaml:"repeat_every"`
}

// MonitorValues are the parsed thresholds.
type MonitorValues struct {
	ExpiryWarn, ExpiryCrit   time.Duration
	CAWarn, CACrit           time.Duration
	SealedAfter, AgentSilent time.Duration
	RepeatEvery              time.Duration
}

func defaultMonitor() Monitor {
	return Monitor{ExpiryDays: "14, 3", CAExpiryDays: "90, 30", SealedAfter: "10m", AgentSilentAfter: "1h", RepeatEvery: "24h"}
}

const day = 24 * time.Hour

// Values parses and checks the thresholds; the error names the key.
func (m Monitor) Values() (MonitorValues, error) {
	var v MonitorValues
	var err error
	if v.ExpiryWarn, v.ExpiryCrit, err = dayPair("monitor.expiry_days", m.ExpiryDays, 90); err != nil {
		return v, err
	}
	if v.CAWarn, v.CACrit, err = dayPair("monitor.ca_expiry_days", m.CAExpiryDays, 365); err != nil {
		return v, err
	}
	if v.SealedAfter, err = durationIn("monitor.sealed_after", m.SealedAfter, time.Minute, time.Hour); err != nil {
		return v, err
	}
	if v.AgentSilent, err = durationIn("monitor.agent_silent_after", m.AgentSilentAfter, 10*time.Minute, 24*time.Hour); err != nil {
		return v, err
	}
	if v.RepeatEvery, err = durationIn("monitor.repeat_every", m.RepeatEvery, time.Hour, 168*time.Hour); err != nil {
		return v, err
	}
	return v, nil
}

// dayPair parses "warning, critical" in days: 1 ≤ critical < warning ≤ limit.
func dayPair(key, s string, limit int) (time.Duration, time.Duration, error) {
	parts := strings.Split(s, ",")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("%s: two numbers of days, warning and critical, like \"14, 3\" – got %q", key, s)
	}
	warn, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
	crit, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err1 != nil || err2 != nil || crit < 1 || crit >= warn || warn > limit {
		return 0, 0, fmt.Errorf("%s: warning 2–%d days and critical below it, at least 1 – got %q", key, limit, s)
	}
	return time.Duration(warn) * day, time.Duration(crit) * day, nil
}

func durationIn(key, s string, lo, hi time.Duration) (time.Duration, error) {
	d, err := time.ParseDuration(strings.TrimSpace(s))
	if err != nil || d < lo || d > hi {
		return 0, fmt.Errorf("%s: a duration from %s to %s like \"%s\" – got %q", key, short(lo), short(hi), short(lo), s)
	}
	return d, nil
}

// short prints 10m instead of 10m0s.
func short(d time.Duration) string {
	s := d.String()
	s = strings.TrimSuffix(s, "0s")
	return strings.TrimSuffix(s, "0m")
}
