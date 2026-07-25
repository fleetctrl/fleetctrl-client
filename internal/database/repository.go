package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

type SQLiteRepository struct {
	db *sql.DB
}

func (r *SQLiteRepository) Close() error { return r.db.Close() }

func (r *SQLiteRepository) BeginSyncRun(ctx context.Context, run SyncRun) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO sync_runs
		(id, kind, trigger, status, started_at, completed_at, error_message, details_json, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, run.ID, run.Kind, run.Trigger, run.Status,
		run.StartedAt, run.CompletedAt, run.ErrorMessage, run.DetailsJSON, run.CreatedAt)
	return err
}

func (r *SQLiteRepository) UpdateSyncRun(ctx context.Context, run SyncRun) error {
	result, err := r.db.ExecContext(ctx, `UPDATE sync_runs SET status=?, started_at=?, completed_at=?,
		error_message=?, details_json=? WHERE id=?`, run.Status, run.StartedAt, run.CompletedAt,
		run.ErrorMessage, run.DetailsJSON, run.ID)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func scanRun(row interface{ Scan(...any) error }) (SyncRun, error) {
	var run SyncRun
	err := row.Scan(&run.ID, &run.Kind, &run.Trigger, &run.Status, &run.StartedAt,
		&run.CompletedAt, &run.ErrorMessage, &run.DetailsJSON, &run.CreatedAt)
	return run, err
}

func (r *SQLiteRepository) GetSyncRun(ctx context.Context, id string) (SyncRun, error) {
	return scanRun(r.db.QueryRowContext(ctx, `SELECT id, kind, trigger, status, started_at,
		completed_at, COALESCE(error_message,''), COALESCE(details_json,''), created_at
		FROM sync_runs WHERE id=?`, id))
}

func (r *SQLiteRepository) GetLatestSyncRuns(ctx context.Context) ([]SyncRun, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT id, kind, trigger, status, started_at,
		completed_at, COALESCE(error_message,''), COALESCE(details_json,''), created_at
		FROM sync_runs ORDER BY created_at DESC LIMIT 50`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []SyncRun
	for rows.Next() {
		run, err := scanRun(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, run)
	}
	return result, rows.Err()
}

func (r *SQLiteRepository) InterruptActiveSyncRuns(ctx context.Context, at time.Time) error {
	_, err := r.db.ExecContext(ctx, `UPDATE sync_runs SET status=?, completed_at=?,
		error_message=CASE WHEN error_message IS NULL OR error_message='' THEN 'Service restarted during synchronization' ELSE error_message END
		WHERE status IN (?, ?)`, SyncInterrupted, at, SyncQueued, SyncRunning)
	return err
}

func (r *SQLiteRepository) UpsertAssignedApps(ctx context.Context, apps []ManagedAppState, observedAt time.Time) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	seen := make(map[string]bool, len(apps))
	for _, app := range apps {
		seen[app.ReleaseID] = true
		var oldAssign, oldAction string
		err := tx.QueryRowContext(ctx, "SELECT assign_type, desired_action FROM managed_app_states WHERE release_id=?", app.ReleaseID).Scan(&oldAssign, &oldAction)
		isNew := err == sql.ErrNoRows
		if err != nil && err != sql.ErrNoRows {
			return err
		}
		wingetID := nullableString(app.WingetID)
		_, err = tx.ExecContext(ctx, `INSERT INTO managed_app_states
			(release_id, app_id, display_name, publisher, version, installer_type, winget_id,
			 assign_type, desired_action, detected_status, operation_status, last_seen_on_server_at,
			 assignment_removed_at, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)
			ON CONFLICT(release_id) DO UPDATE SET app_id=excluded.app_id, display_name=excluded.display_name,
			 publisher=excluded.publisher, version=excluded.version, installer_type=excluded.installer_type,
			 winget_id=excluded.winget_id, assign_type=excluded.assign_type,
			 desired_action=excluded.desired_action, last_seen_on_server_at=excluded.last_seen_on_server_at,
			 assignment_removed_at=NULL, updated_at=excluded.updated_at`,
			app.ReleaseID, app.AppID, app.DisplayName, nullableString(app.Publisher), nullableString(app.Version),
			app.InstallerType, wingetID, app.AssignType, app.DesiredAction, DetectionUnknown,
			OperationIdle, observedAt, observedAt, observedAt)
		if err != nil {
			return err
		}
		if isNew {
			if err := insertEvent(ctx, tx, AppEvent{ReleaseID: app.ReleaseID, AppID: app.AppID, EventType: "assigned", Source: "server", CreatedAt: observedAt}); err != nil {
				return err
			}
		} else if oldAssign != app.AssignType || oldAction != app.DesiredAction {
			if err := insertEvent(ctx, tx, AppEvent{ReleaseID: app.ReleaseID, AppID: app.AppID, EventType: "assignment_changed", Source: "server", CreatedAt: observedAt}); err != nil {
				return err
			}
		}
	}
	rows, err := tx.QueryContext(ctx, `SELECT release_id, app_id FROM managed_app_states WHERE assignment_removed_at IS NULL`)
	if err != nil {
		return err
	}
	var removed [][2]string
	for rows.Next() {
		var releaseID, appID string
		if err := rows.Scan(&releaseID, &appID); err != nil {
			rows.Close()
			return err
		}
		if !seen[releaseID] {
			removed = append(removed, [2]string{releaseID, appID})
		}
	}
	rows.Close()
	for _, item := range removed {
		if _, err := tx.ExecContext(ctx, "UPDATE managed_app_states SET assignment_removed_at=?, updated_at=? WHERE release_id=?", observedAt, observedAt, item[0]); err != nil {
			return err
		}
		if err := insertEvent(ctx, tx, AppEvent{ReleaseID: item[0], AppID: item[1], EventType: "assignment_removed", Source: "server", CreatedAt: observedAt}); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (r *SQLiteRepository) UpdateDetectionState(ctx context.Context, releaseID string, status DetectionStatus, checkedAt time.Time, detectionError string) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var old DetectionStatus
	var appID string
	if err := tx.QueryRowContext(ctx, "SELECT detected_status, app_id FROM managed_app_states WHERE release_id=?", releaseID).Scan(&old, &appID); err != nil {
		return err
	}
	firstSeenExpr := "first_seen_installed_at"
	if status == DetectionInstalled {
		firstSeenExpr = "COALESCE(first_seen_installed_at, ?)"
	}
	query := fmt.Sprintf(`UPDATE managed_app_states SET detected_status=?, last_checked_at=?,
		last_error=?, first_seen_installed_at=%s, updated_at=? WHERE release_id=?`, firstSeenExpr)
	args := []any{status, checkedAt, nullableString(detectionError)}
	if status == DetectionInstalled {
		args = append(args, checkedAt)
	}
	args = append(args, checkedAt, releaseID)
	if _, err := tx.ExecContext(ctx, query, args...); err != nil {
		return err
	}
	if old != status {
		eventType := "detection_" + string(status)
		if err := insertEvent(ctx, tx, AppEvent{ReleaseID: releaseID, AppID: appID, EventType: eventType, Source: "detection", Message: detectionError, CreatedAt: checkedAt}); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (r *SQLiteRepository) UpdateOperationState(ctx context.Context, releaseID string, status OperationStatus, operationError string) error {
	now := time.Now().UTC()
	_, err := r.db.ExecContext(ctx, `UPDATE managed_app_states SET operation_status=?, last_error=?, updated_at=? WHERE release_id=?`,
		status, nullableString(operationError), now, releaseID)
	return err
}

func (r *SQLiteRepository) MarkInstalledByClient(ctx context.Context, releaseID string, installedAt time.Time) error {
	_, err := r.db.ExecContext(ctx, `UPDATE managed_app_states SET installed_by_client_at=COALESCE(installed_by_client_at, ?),
		updated_at=? WHERE release_id=?`, installedAt, installedAt, releaseID)
	return err
}

func scanApp(row interface{ Scan(...any) error }) (ManagedAppState, error) {
	var app ManagedAppState
	var publisher, version, winget, lastError sql.NullString
	err := row.Scan(&app.ReleaseID, &app.AppID, &app.DisplayName, &publisher, &version,
		&app.InstallerType, &winget, &app.AssignType, &app.DesiredAction, &app.DetectedStatus,
		&app.OperationStatus, &app.FirstSeenInstalledAt, &app.InstalledByClientAt,
		&app.LastCheckedAt, &app.LastSeenOnServerAt, &app.AssignmentRemovedAt, &lastError,
		&app.CreatedAt, &app.UpdatedAt)
	app.Publisher, app.Version, app.WingetID, app.LastError = publisher.String, version.String, winget.String, lastError.String
	return app, err
}

func (r *SQLiteRepository) ListManagedApps(ctx context.Context) ([]ManagedAppState, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT release_id, app_id, display_name, publisher, version,
		installer_type, winget_id, assign_type, desired_action, detected_status, operation_status,
		first_seen_installed_at, installed_by_client_at, last_checked_at, last_seen_on_server_at,
		assignment_removed_at, last_error, created_at, updated_at
		FROM managed_app_states WHERE assignment_removed_at IS NULL ORDER BY display_name COLLATE NOCASE`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []ManagedAppState
	for rows.Next() {
		app, err := scanApp(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, app)
	}
	return result, rows.Err()
}

func insertEvent(ctx context.Context, q interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}, event AppEvent) error {
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now().UTC()
	}
	_, err := q.ExecContext(ctx, `INSERT INTO app_events
		(release_id, app_id, event_type, source, message, details_json, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, event.ReleaseID, event.AppID, event.EventType,
		event.Source, nullableString(event.Message), nullableString(event.DetailsJSON), event.CreatedAt)
	return err
}

func (r *SQLiteRepository) AppendAppEvent(ctx context.Context, event AppEvent) error {
	return insertEvent(ctx, r.db, event)
}

func (r *SQLiteRepository) GetAppEvents(ctx context.Context, releaseID string, limit int) ([]AppEvent, error) {
	if limit < 1 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	rows, err := r.db.QueryContext(ctx, `SELECT id, release_id, app_id, event_type, source,
		COALESCE(message,''), COALESCE(details_json,''), created_at FROM app_events
		WHERE release_id=? ORDER BY created_at DESC LIMIT ?`, releaseID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []AppEvent
	for rows.Next() {
		var event AppEvent
		if err := rows.Scan(&event.ID, &event.ReleaseID, &event.AppID, &event.EventType,
			&event.Source, &event.Message, &event.DetailsJSON, &event.CreatedAt); err != nil {
			return nil, err
		}
		result = append(result, event)
	}
	return result, rows.Err()
}

func nullableString(v string) any {
	if v == "" {
		return nil
	}
	return v
}
