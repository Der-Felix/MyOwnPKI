-- The instance row (PHASE1 step 11). ASCII only, see tenants.sql.

-- name: InsertInstance :exec
INSERT INTO instance (id, demo, initialized_at) VALUES (1, ?, ?);

-- name: GetInstance :one
SELECT demo, initialized_at FROM instance WHERE id = 1;
