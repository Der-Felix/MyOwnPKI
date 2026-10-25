package agent

// Windows is a compile/test target only in v0.3.0; deployment is Linux-only.
func (*Agent) deploymentLock() (func(), error) { return func() {}, nil }
