-- Import jobs (ASCII only, see queries/system/tenants.sql).

-- name: InsertImportJob :exec
INSERT INTO import_jobs (id, kind, status, dry_run, started_at, finished_at, started_by, report_json)
VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetImportJob :one
SELECT * FROM import_jobs WHERE id = ?;
