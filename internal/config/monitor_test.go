package config

import (
	"strings"
	"testing"
	"time"
)

func TestMonitorDefaults(t *testing.T) {
	t.Parallel()
	v, err := Default().Monitor.Values()
	if err != nil {
		t.Fatal(err)
	}
	want := MonitorValues{
		ExpiryWarn: 14 * day, ExpiryCrit: 3 * day, CAWarn: 90 * day, CACrit: 30 * day,
		SealedAfter: 10 * time.Minute, AgentSilent: time.Hour, RepeatEvery: 24 * time.Hour,
	}
	if v != want {
		t.Errorf("defaults = %+v", v)
	}
}

func TestMonitorRejects(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		set func(*Monitor)
		key string
	}{
		{func(m *Monitor) { m.ExpiryDays = "14" }, "monitor.expiry_days"},
		{func(m *Monitor) { m.ExpiryDays = "3, 14" }, "monitor.expiry_days"},
		{func(m *Monitor) { m.ExpiryDays = "14, 0" }, "monitor.expiry_days"},
		{func(m *Monitor) { m.ExpiryDays = "120, 3" }, "monitor.expiry_days"},
		{func(m *Monitor) { m.CAExpiryDays = "400, 30" }, "monitor.ca_expiry_days"},
		{func(m *Monitor) { m.SealedAfter = "30s" }, "monitor.sealed_after"},
		{func(m *Monitor) { m.SealedAfter = "ten" }, "monitor.sealed_after"},
		{func(m *Monitor) { m.AgentSilentAfter = "48h" }, "monitor.agent_silent_after"},
		{func(m *Monitor) { m.RepeatEvery = "10m" }, "monitor.repeat_every"},
	} {
		m := defaultMonitor()
		tc.set(&m)
		if _, err := m.Values(); err == nil || !strings.HasPrefix(err.Error(), tc.key+":") {
			t.Errorf("%+v: err = %v", m, err)
		}
	}
	cfg := Default()
	cfg.Monitor.SealedAfter = "2h"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "monitor.sealed_after") {
		t.Errorf("Validate = %v", err)
	}
}
