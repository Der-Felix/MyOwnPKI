package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/ca/legacy"
	"github.com/Der-Felix/MyOwnPKI/internal/store"
	"github.com/Der-Felix/MyOwnPKI/internal/store/auditdb"
)

// The legacy import over the API and the audit log (step 18).

type importCAJSON struct {
	Name          string `json:"name"`
	Kind          string `json:"kind"`
	KeyMode       string `json:"key_mode"`
	Status        string `json:"status"`
	Certificates  int    `json:"certificates"`
	Revoked       int    `json:"revoked"`
	LastCRLNumber int64  `json:"last_crl_number"`
	History       int    `json:"history"`
}

type importJobJSON struct {
	ID         string         `json:"id"`
	Status     string         `json:"status"`
	DryRun     bool           `json:"dry_run"`
	StartedAt  time.Time      `json:"started_at"`
	FinishedAt time.Time      `json:"finished_at"`
	StartedBy  string         `json:"started_by"`
	BaseURL    string         `json:"base_url"`
	LegacyURLs bool           `json:"legacy_urls"`
	CAs        []importCAJSON `json:"cas"`
	Summary    struct {
		Certificates int `json:"certificates"`
		Revoked      int `json:"revoked"`
		Keys         int `json:"keys"`
		External     int `json:"external"`
	} `json:"summary"`
	Problems []string `json:"problems"`
	Warnings []string `json:"warnings"`
}

func toImportJobJSON(j *ca.ImportJob) importJobJSON {
	out := importJobJSON{ID: j.ID, Status: j.Status, DryRun: j.DryRun, StartedAt: j.StartedAt.UTC(), FinishedAt: j.EndedAt.UTC(),
		StartedBy: j.StartedBy, CAs: []importCAJSON{}, Problems: []string{}, Warnings: []string{}}
	if r := j.Report; r != nil {
		out.BaseURL, out.LegacyURLs = r.BaseURL, r.LegacyURLs
		out.Summary.Certificates, out.Summary.Revoked, out.Summary.Keys, out.Summary.External = r.Certificates, r.Revoked, r.Keys, r.External
		out.Problems, out.Warnings = nonNil(r.Problems), nonNil(r.Warnings)
		for _, c := range r.CAs {
			out.CAs = append(out.CAs, importCAJSON{Name: c.Name, Kind: c.Kind, KeyMode: c.KeyMode, Status: c.Status,
				Certificates: c.Certificates, Revoked: c.Revoked, LastCRLNumber: c.LastCRLNumber, History: c.History})
		}
	}
	return out
}

// startLegacyImport takes the pki.sh directory as a base64 .tar.gz, runs
// the import (or the dry run) and returns the recorded job.
func (a *API) startLegacyImport(c *call) error {
	var req struct {
		Archive       string            `json:"archive"`
		BaseURL       string            `json:"base_url"`
		RootKey       string            `json:"root_key"`
		DryRun        bool              `json:"dry_run"`
		CAPassphrases map[string]string `json:"ca_passphrases"`
		KeyPassphrase string            `json:"key_passphrase"`
	}
	if err := c.decode(&req); err != nil {
		return err
	}
	if req.RootKey == "" {
		req.RootKey = "offline"
	}
	if req.RootKey != "offline" && req.RootKey != "online" {
		return badRequest("/root_key", "offline or online")
	}
	data, err := base64.StdEncoding.DecodeString(req.Archive)
	if err != nil || len(data) == 0 {
		return badRequest("/archive", "a base64 .tar.gz of the pki.sh directory")
	}
	fsys, err := legacy.FromArchive(data)
	if err != nil {
		return c.problem(http.StatusUnprocessableEntity, "policy-violation", err.Error(), nil)
	}
	pw := legacy.Passphrases{Leaf: []byte(req.KeyPassphrase), CA: func(name string) []byte { return []byte(req.CAPassphrases[name]) }}
	src, err := legacy.Read(fsys, pw)
	if err != nil {
		return c.problem(http.StatusUnprocessableEntity, "policy-violation", err.Error(), nil)
	}
	job, err := a.d.Engine.ImportLegacyJob(c.ctx(), ca.LegacyImportRequest{PKI: src, BaseURL: req.BaseURL, RootOnline: req.RootKey == "online", DryRun: req.DryRun, Who: c.who()})
	if job == nil || job.Error != "" {
		return err // not allowed, sealed, a database error: the usual answers
	}
	// Every run is a recorded job; a refused one has status failed.
	c.w.Header().Set("Location", BasePath+"/imports/"+job.ID)
	return c.reply(http.StatusCreated, toImportJobJSON(job))
}

func (a *API) getImport(c *call) error {
	id := c.r.PathValue("importId")
	if !idPattern.MatchString(id) {
		return ca.ErrNotFound
	}
	job, err := a.d.Engine.ImportJobByID(c.ctx(), c.who(), id)
	if err != nil {
		return err
	}
	return c.reply(http.StatusOK, toImportJobJSON(job))
}

// ---------------------------------------------------------------- audit

type auditEntryJSON struct {
	Seq   int64     `json:"seq"`
	Time  time.Time `json:"time"`
	Actor struct {
		Type string `json:"type"`
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"actor"`
	Action string `json:"action"`
	Target struct {
		Type string `json:"type"`
		ID   string `json:"id"`
	} `json:"target"`
	Result   string         `json:"result"`
	SourceIP string         `json:"source_ip"`
	Details  map[string]any `json:"details"`
	Hash     string         `json:"hash"`
	PrevHash string         `json:"prev_hash"`
}

// auditScope picks the log: the tenant's (operator and up, tenant-wide)
// or the instance's (instance admins).
func (a *API) auditScope(c *call, scope string) (string, error) {
	switch scope {
	case "", "tenant":
		if err := c.session.Principal.Check(authz.ReadAudit, authz.Resource{Tenant: a.d.Tenant}, a.now()); err != nil {
			return "", err
		}
		return store.TenantScope(a.d.Tenant), nil
	case "instance":
		if p := c.session.Principal; p == nil || !p.InstanceAdmin {
			return "", errors.Join(authz.ErrDenied, errors.New("the instance log is for instance admins"))
		}
		return store.InstanceScope, nil
	}
	return "", badRequest("scope", "tenant or instance")
}

func (a *API) auditDB(scope string) *auditdb.Queries {
	if scope == store.InstanceScope {
		return auditdb.New(a.d.InstanceAudit)
	}
	return auditdb.New(a.d.TenantAudit)
}

func (a *API) listAuditEntries(c *call) error {
	qv := c.r.URL.Query()
	scope, err := a.auditScope(c, qv.Get("scope"))
	if err != nil {
		return err
	}
	limit := 50
	if s := qv.Get("limit"); s != "" {
		n, perr := strconv.Atoi(s)
		if perr != nil || n < 1 || n > 100 {
			return badRequest("limit", "1 to 100")
		}
		limit = n
	}
	var before int64
	if s := qv.Get("before"); s != "" {
		n, perr := strconv.ParseInt(s, 10, 64)
		if perr != nil || n < 1 {
			return badRequest("before", "a sequence number")
		}
		before = n
	}
	timeArg := func(name string) (string, error) {
		s := qv.Get(name)
		if s == "" {
			return "", nil
		}
		t, perr := time.Parse(time.RFC3339, s)
		if perr != nil {
			return "", badRequest(name, "RFC 3339 time")
		}
		return t.UTC().Format(audit.TimeFormat), nil
	}
	since, err := timeArg("since")
	if err != nil {
		return err
	}
	until, err := timeArg("until")
	if err != nil {
		return err
	}
	result := qv.Get("result")
	if result != "" && result != "success" && result != "failure" && result != "denied" {
		return badRequest("result", "success, failure or denied")
	}
	rows, err := a.auditDB(scope).ListEntriesPage(c.ctx(), auditdb.ListEntriesPageParams{
		Before: before, Action: strings.TrimSpace(qv.Get("action")), Result: result, Since: since, Until: until, PageSize: int64(limit + 1),
	})
	if err != nil {
		return err
	}
	out := struct {
		Items      []auditEntryJSON `json:"items"`
		NextBefore *int64           `json:"next_before"`
	}{Items: []auditEntryJSON{}}
	if len(rows) > limit {
		rows = rows[:limit]
		n := rows[len(rows)-1].Seq
		out.NextBefore = &n
	}
	for _, r := range rows {
		e := auditEntryJSON{Seq: r.Seq, Action: r.Action, Result: r.Result, SourceIP: r.SourceIp, Hash: r.Hash, PrevHash: r.PrevHash, Details: map[string]any{}}
		if t, perr := time.Parse(audit.TimeFormat, r.Time); perr == nil {
			e.Time = t.UTC()
		}
		e.Actor.Type, e.Actor.ID, e.Actor.Name = r.ActorType, r.ActorID, r.ActorName
		e.Target.Type, e.Target.ID = r.TargetType, r.TargetID
		_ = json.Unmarshal([]byte(r.DetailsJson), &e.Details)
		out.Items = append(out.Items, e)
	}
	return c.reply(http.StatusOK, out)
}

func (a *API) verifyAuditChain(c *call) error {
	var req struct {
		Scope         string `json:"scope"`
		CheckpointKey string `json:"checkpoint_key"`
	}
	if c.r.ContentLength != 0 {
		if err := c.decode(&req); err != nil {
			return err
		}
	}
	scope, err := a.auditScope(c, req.Scope)
	if err != nil {
		return err
	}
	db := a.d.TenantAudit
	if scope == store.InstanceScope {
		db = a.d.InstanceAudit
	}
	r, err := audit.VerifyWith(c.ctx(), db, scope, audit.VerifyOptions{CheckpointKey: req.CheckpointKey})
	if err != nil {
		return err
	}
	out := struct {
		OK             bool    `json:"ok"`
		EntriesChecked int64   `json:"entries_checked"`
		FirstBrokenSeq *int64  `json:"first_broken_seq"`
		Reason         *string `json:"reason"`
		Head           string  `json:"head"`
		Checkpoints    int64   `json:"checkpoints"`
		CheckpointKey  string  `json:"checkpoint_key"`
	}{OK: r.Break == nil, EntriesChecked: r.Entries, Head: r.Head.String(), Checkpoints: r.Checkpoints, CheckpointKey: r.CheckpointKey}
	if r.Break != nil {
		seq, reason := r.Break.Seq, r.Break.Reason
		out.FirstBrokenSeq, out.Reason = &seq, &reason
	}
	return c.reply(http.StatusOK, out)
}
