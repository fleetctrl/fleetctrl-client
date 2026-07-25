package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

var migrations = []string{
	`CREATE TABLE IF NOT EXISTS winget_checks (
		winget_id TEXT PRIMARY KEY,
		last_check DATETIME NOT NULL
	);
	CREATE TABLE IF NOT EXISTS app_errors (
		release_id TEXT PRIMARY KEY,
		failures_count INTEGER DEFAULT 0,
		last_attempt DATETIME
	);`,
	`CREATE TABLE IF NOT EXISTS managed_app_states (
		release_id TEXT PRIMARY KEY,
		app_id TEXT NOT NULL,
		display_name TEXT NOT NULL,
		publisher TEXT,
		version TEXT,
		installer_type TEXT NOT NULL,
		winget_id TEXT,
		assign_type TEXT NOT NULL,
		desired_action TEXT NOT NULL,
		detected_status TEXT NOT NULL DEFAULT 'unknown',
		operation_status TEXT NOT NULL DEFAULT 'idle',
		first_seen_installed_at DATETIME,
		installed_by_client_at DATETIME,
		last_checked_at DATETIME,
		last_seen_on_server_at DATETIME NOT NULL,
		assignment_removed_at DATETIME,
		last_error TEXT,
		created_at DATETIME NOT NULL,
		updated_at DATETIME NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_managed_app_states_app_id ON managed_app_states(app_id);
	CREATE INDEX IF NOT EXISTS idx_managed_app_states_last_seen ON managed_app_states(last_seen_on_server_at);
	CREATE TABLE IF NOT EXISTS app_events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		release_id TEXT NOT NULL,
		app_id TEXT NOT NULL,
		event_type TEXT NOT NULL,
		source TEXT NOT NULL,
		message TEXT,
		details_json TEXT,
		created_at DATETIME NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_app_events_release_created ON app_events(release_id, created_at DESC);
	CREATE TABLE IF NOT EXISTS sync_runs (
		id TEXT PRIMARY KEY,
		kind TEXT NOT NULL,
		trigger TEXT NOT NULL,
		status TEXT NOT NULL,
		started_at DATETIME,
		completed_at DATETIME,
		error_message TEXT,
		details_json TEXT,
		created_at DATETIME NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_sync_runs_kind_created ON sync_runs(kind, created_at DESC);`,
}

func (r *SQLiteRepository) migrate(ctx context.Context) error {
	if _, err := r.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version INTEGER PRIMARY KEY,
		applied_at DATETIME NOT NULL
	)`); err != nil {
		return fmt.Errorf("create migrations table: %w", err)
	}
	for i, migration := range migrations {
		version := i + 1
		var exists int
		err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM schema_migrations WHERE version = ?", version).Scan(&exists)
		if err != nil {
			return fmt.Errorf("check migration %d: %w", version, err)
		}
		if exists != 0 {
			continue
		}
		if err := runMigration(ctx, r.db, version, migration); err != nil {
			return err
		}
	}
	return nil
}

func runMigration(ctx context.Context, db *sql.DB, version int, statements string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin migration %d: %w", version, err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, statements); err != nil {
		return fmt.Errorf("apply migration %d: %w", version, err)
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)", version, time.Now().UTC()); err != nil {
		return fmt.Errorf("record migration %d: %w", version, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit migration %d: %w", version, err)
	}
	return nil
}
