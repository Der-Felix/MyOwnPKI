package ca

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/ids"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
)

// Import jobs (step 18): the API runs a legacy import synchronously and
// keeps its report in import_jobs, so the result can be read again.

// Import job states.
const (
	JobSucceeded = "succeeded" // imported
	JobChecked   = "checked"   // a dry run without problems
	JobFailed    = "failed"    // refused (problems) or broken
)

// ImportJob is a recorded import.
type ImportJob struct {
	ID, Kind, Status   string
	DryRun             bool
	StartedAt, EndedAt time.Time
	StartedBy          string
	Report             *LegacyImportReport
	Error              string `json:"-"` // not stored apart: Report.Problems has it
}

// ImportLegacyJob runs ImportLegacy and records the outcome. A caller who
// may not import gets the refusal and no job.
func (e *Engine) ImportLegacyJob(ctx context.Context, req LegacyImportRequest) (*ImportJob, error) {
	start := e.now()
	if err := e.authorize(req.Who, authz.ManageCA, "", start); err != nil {
		return nil, err
	}
	rep, err := e.ImportLegacy(ctx, req)
	job := &ImportJob{Kind: "legacy", DryRun: req.DryRun, StartedAt: start, EndedAt: e.now(), StartedBy: requestedBy(req.Who), Report: rep}
	var denied *DeniedError
	switch {
	case err == nil && req.DryRun:
		job.Status = JobChecked
	case err == nil:
		job.Status = JobSucceeded
	case errors.As(err, &denied):
		job.Status = JobFailed
	default:
		// A broken import (database, sealed): the caller gets the error;
		// the job records it for the report page.
		job.Status = JobFailed
		job.Error = err.Error()
		if rep != nil {
			rep.Problems = append(rep.Problems, "the import stopped: "+capText(err.Error(), 300))
		}
	}
	if rep == nil {
		job.Report = &LegacyImportReport{Warnings: []string{}, Problems: []string{job.Error}, CAs: []LegacyCAReport{}}
	}
	if job.ID, err = ids.New("imp", start, nil); err != nil {
		return nil, err
	}
	data, merr := json.Marshal(job.Report)
	if merr != nil {
		return nil, merr
	}
	if ierr := pkidb.New(e.PKI).InsertImportJob(ctx, pkidb.InsertImportJobParams{
		ID: job.ID, Kind: job.Kind, Status: job.Status, DryRun: boolInt(job.DryRun),
		StartedAt: start.Format(dbTime), FinishedAt: job.EndedAt.Format(dbTime), StartedBy: job.StartedBy, ReportJson: string(data),
	}); ierr != nil {
		return nil, ierr
	}
	if job.Error != "" && !errors.As(err, &denied) {
		return job, errors.New(job.Error)
	}
	return job, nil
}

// ImportJobByID reads a recorded job; it needs ca.manage (role only).
func (e *Engine) ImportJobByID(ctx context.Context, who keys.Who, id string) (*ImportJob, error) {
	// Without a tenant-wide role the job is "not found" (decision 64).
	if !e.canRead(who, "", e.now()) {
		return nil, ErrNotFound
	}
	if err := e.CheckManage(who, ""); err != nil {
		return nil, err
	}
	r, err := pkidb.New(e.PKI).GetImportJob(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	job := &ImportJob{ID: r.ID, Kind: r.Kind, Status: r.Status, DryRun: r.DryRun == 1, StartedAt: parseDBTime(r.StartedAt),
		EndedAt: parseDBTime(r.FinishedAt), StartedBy: r.StartedBy, Report: &LegacyImportReport{}}
	if err := json.Unmarshal([]byte(r.ReportJson), job.Report); err != nil {
		return nil, err
	}
	return job, nil
}
