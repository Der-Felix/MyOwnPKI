package view

// CertRow is one certificate in a table (list, overview, CA details).
type CertRow struct {
	ID, CommonName, Preset, CA string
	Serial                     string
	Expires, ExpiresRel        string
	Status                     Status
	StatusText                 string
}

// ActivityRow is one audit entry in the recent-activity table.
type ActivityRow struct {
	Time, Actor, Action, Target string
	Result                      Status
	ResultText                  string
}

// Option is one entry of a select or radio group.
type Option struct {
	Value, Label string
	Selected     bool
}
