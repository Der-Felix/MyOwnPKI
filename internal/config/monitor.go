package config

import (
	"fmt"
	"slices"
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

	// The TLS scan (docs/PHASE3.md §10.2, v0.3.4).

	// ScanInterval: how often each endpoint is scanned, "5m" to "24h", or
	// "off" when the server must not connect anywhere.
	ScanInterval string `yaml:"scan_interval"`
	// ScanTimeout: resolve, connect and handshake of one scan together.
	ScanTimeout string `yaml:"scan_timeout"`
	// ScanPorts: the only ports an endpoint may have, "443, 8443".
	ScanPorts string `yaml:"scan_ports"`
	// ScanMaxEndpoints: how many endpoints may be entered.
	ScanMaxEndpoints string `yaml:"scan_max_endpoints"`
	// ScanUnreachableAfter: failed scans in a row before scan_unreachable opens.
	ScanUnreachableAfter string `yaml:"scan_unreachable_after"`
	// ScanMismatchAfter: how old the newest certificate for a name must be
	// before an older one still being served is an alert.
	ScanMismatchAfter string `yaml:"scan_mismatch_after"`
}

// MonitorValues are the parsed thresholds.
type MonitorValues struct {
	ExpiryWarn, ExpiryCrit   time.Duration
	CAWarn, CACrit           time.Duration
	SealedAfter, AgentSilent time.Duration
	RepeatEvery              time.Duration
}

// DefaultScanPorts are the ports where TLS starts with the first byte.
const DefaultScanPorts = "443, 465, 636, 853, 993, 995, 5061, 6514, 8443, 8883, 9443"

func defaultMonitor() Monitor {
	return Monitor{
		ExpiryDays: "14, 3", CAExpiryDays: "90, 30", SealedAfter: "10m", AgentSilentAfter: "1h", RepeatEvery: "24h",
		ScanInterval: "15m", ScanTimeout: "10s", ScanPorts: DefaultScanPorts, ScanMaxEndpoints: "100",
		ScanUnreachableAfter: "3", ScanMismatchAfter: "1h",
	}
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

// ScanValues are the parsed monitor.scan_* keys.
type ScanValues struct {
	// Interval is 0 when scanning is off.
	Interval         time.Duration
	Timeout          time.Duration
	Ports            []int
	MaxEndpoints     int
	UnreachableAfter int
	MismatchAfter    time.Duration
}

// Off reports whether scanning is switched off.
func (v ScanValues) Off() bool { return v.Interval <= 0 }

// Scan parses and checks the TLS scan keys; the error names the key.
func (m Monitor) Scan() (ScanValues, error) {
	var v ScanValues
	var err error
	if iv := strings.TrimSpace(m.ScanInterval); strings.EqualFold(iv, "off") {
		v.Interval = 0
	} else if v.Interval, err = durationIn("monitor.scan_interval", iv, 5*time.Minute, 24*time.Hour); err != nil {
		return v, fmt.Errorf("%w (or \"off\")", err)
	}
	if v.Timeout, err = durationIn("monitor.scan_timeout", m.ScanTimeout, 2*time.Second, 30*time.Second); err != nil {
		return v, err
	}
	if v.Ports, err = scanPorts("monitor.scan_ports", m.ScanPorts); err != nil {
		return v, err
	}
	if v.MaxEndpoints, err = intIn("monitor.scan_max_endpoints", m.ScanMaxEndpoints, 1, 500); err != nil {
		return v, err
	}
	if v.UnreachableAfter, err = intIn("monitor.scan_unreachable_after", m.ScanUnreachableAfter, 1, 10); err != nil {
		return v, err
	}
	if v.MismatchAfter, err = durationIn("monitor.scan_mismatch_after", m.ScanMismatchAfter, 5*time.Minute, 24*time.Hour); err != nil {
		return v, err
	}
	return v, nil
}

func intIn(key, s string, lo, hi int) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < lo || n > hi {
		return 0, fmt.Errorf("%s: a whole number from %d to %d – got %q", key, lo, hi, s)
	}
	return n, nil
}

// scanPorts parses "443, 8443": 1 to 32 different ports from 1 to 65535.
func scanPorts(key, s string) ([]int, error) {
	var out []int
	for _, part := range strings.Split(s, ",") {
		p, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil || p < 1 || p > 65535 {
			return nil, fmt.Errorf("%s: ports from 1 to 65535, comma-separated, like \"443, 8443\" – got %q", key, s)
		}
		if slices.Contains(out, p) {
			return nil, fmt.Errorf("%s: port %d is listed twice", key, p)
		}
		out = append(out, p)
	}
	if len(out) > 32 {
		return nil, fmt.Errorf("%s: at most 32 ports – got %d", key, len(out))
	}
	return out, nil
}
