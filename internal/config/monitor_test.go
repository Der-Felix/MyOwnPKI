package config

import (
	"strconv"
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

func TestScanDefaults(t *testing.T) {
	t.Parallel()
	v, err := Default().Monitor.Scan()
	if err != nil {
		t.Fatal(err)
	}
	if v.Interval != 15*time.Minute || v.Timeout != 10*time.Second || v.MaxEndpoints != 100 || v.UnreachableAfter != 3 || v.MismatchAfter != time.Hour || v.Off() {
		t.Errorf("defaults = %+v", v)
	}
	want := []int{443, 465, 636, 853, 993, 995, 5061, 6514, 8443, 8883, 9443}
	if len(v.Ports) != len(want) {
		t.Fatalf("ports = %v", v.Ports)
	}
	for i, p := range want {
		if v.Ports[i] != p {
			t.Errorf("ports = %v", v.Ports)
		}
	}
}

func TestScanAccepts(t *testing.T) {
	t.Parallel()
	for name, set := range map[string]func(*Monitor){
		"off":             func(m *Monitor) { m.ScanInterval = "off" },
		"OFF with spaces": func(m *Monitor) { m.ScanInterval = " OFF " },
		"the lower bounds": func(m *Monitor) {
			m.ScanInterval, m.ScanTimeout, m.ScanMaxEndpoints, m.ScanUnreachableAfter, m.ScanMismatchAfter = "5m", "2s", "1", "1", "5m"
		},
		"the upper bounds": func(m *Monitor) {
			m.ScanInterval, m.ScanTimeout, m.ScanMaxEndpoints, m.ScanUnreachableAfter, m.ScanMismatchAfter = "24h", "30s", "500", "10", "24h"
		},
		"one port":           func(m *Monitor) { m.ScanPorts = "443" },
		"ports without gaps": func(m *Monitor) { m.ScanPorts = "443,8443,65535,1" },
	} {
		m := defaultMonitor()
		set(&m)
		if _, err := m.Scan(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	m := defaultMonitor()
	m.ScanInterval = "off"
	if v, _ := m.Scan(); !v.Off() {
		t.Error("off is not off")
	}
}

func TestScanRejects(t *testing.T) {
	t.Parallel()
	manyPorts := make([]string, 33)
	for i := range manyPorts {
		manyPorts[i] = strconv.Itoa(1000 + i)
	}
	for _, tc := range []struct {
		set func(*Monitor)
		key string
	}{
		{func(m *Monitor) { m.ScanInterval = "4m" }, "monitor.scan_interval"},
		{func(m *Monitor) { m.ScanInterval = "25h" }, "monitor.scan_interval"},
		{func(m *Monitor) { m.ScanInterval = "never" }, "monitor.scan_interval"},
		{func(m *Monitor) { m.ScanInterval = "" }, "monitor.scan_interval"},
		{func(m *Monitor) { m.ScanTimeout = "1s" }, "monitor.scan_timeout"},
		{func(m *Monitor) { m.ScanTimeout = "31s" }, "monitor.scan_timeout"},
		{func(m *Monitor) { m.ScanPorts = "" }, "monitor.scan_ports"},
		{func(m *Monitor) { m.ScanPorts = "0" }, "monitor.scan_ports"},
		{func(m *Monitor) { m.ScanPorts = "65536" }, "monitor.scan_ports"},
		{func(m *Monitor) { m.ScanPorts = "443, https" }, "monitor.scan_ports"},
		{func(m *Monitor) { m.ScanPorts = "443,,8443" }, "monitor.scan_ports"},
		{func(m *Monitor) { m.ScanPorts = "443, 443" }, "monitor.scan_ports"},
		{func(m *Monitor) { m.ScanPorts = strings.Join(manyPorts, ",") }, "monitor.scan_ports"},
		{func(m *Monitor) { m.ScanMaxEndpoints = "0" }, "monitor.scan_max_endpoints"},
		{func(m *Monitor) { m.ScanMaxEndpoints = "501" }, "monitor.scan_max_endpoints"},
		{func(m *Monitor) { m.ScanMaxEndpoints = "many" }, "monitor.scan_max_endpoints"},
		{func(m *Monitor) { m.ScanUnreachableAfter = "0" }, "monitor.scan_unreachable_after"},
		{func(m *Monitor) { m.ScanUnreachableAfter = "11" }, "monitor.scan_unreachable_after"},
		{func(m *Monitor) { m.ScanMismatchAfter = "4m" }, "monitor.scan_mismatch_after"},
		{func(m *Monitor) { m.ScanMismatchAfter = "25h" }, "monitor.scan_mismatch_after"},
	} {
		m := defaultMonitor()
		tc.set(&m)
		if _, err := m.Scan(); err == nil || !strings.HasPrefix(err.Error(), tc.key+":") {
			t.Errorf("%+v: err = %v, want %s", m, err, tc.key)
		}
	}
	cfg := Default()
	cfg.Monitor.ScanPorts = "22, 22"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "monitor.scan_ports") {
		t.Errorf("Validate = %v", err)
	}
}

func TestScanFromTheEnvironment(t *testing.T) {
	t.Parallel()
	cfg := Default()
	applied, err := cfg.ApplyEnv([]string{
		"MYOWNPKI_MONITOR_SCAN_INTERVAL=off", "MYOWNPKI_MONITOR_SCAN_TIMEOUT=3s", "MYOWNPKI_MONITOR_SCAN_PORTS=443, 8443",
		"MYOWNPKI_MONITOR_SCAN_MAX_ENDPOINTS=7", "MYOWNPKI_MONITOR_SCAN_UNREACHABLE_AFTER=2", "MYOWNPKI_MONITOR_SCAN_MISMATCH_AFTER=2h",
	})
	if err != nil || len(applied) != 6 {
		t.Fatalf("applied %v: %v", applied, err)
	}
	v, err := cfg.Monitor.Scan()
	if err != nil || !v.Off() || v.Timeout != 3*time.Second || len(v.Ports) != 2 || v.MaxEndpoints != 7 || v.UnreachableAfter != 2 || v.MismatchAfter != 2*time.Hour {
		t.Errorf("%+v: %v", v, err)
	}
}
