package database

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	consts "KiskaLE/RustDesk-ID/internal/const"

	_ "modernc.org/sqlite"
)

var (
	dbMu        sync.RWMutex
	db          *sql.DB
	defaultRepo *SQLiteRepository
)

// Init opens the service database and applies all migrations. If the database
// cannot be opened, the original file is retained as a timestamped diagnostic
// backup before a clean database is created.
func Init() error {
	repo, err := Open(filepath.Join(consts.ProgramDataDir, "client.db"))
	if err != nil {
		return err
	}
	dbMu.Lock()
	db = repo.db
	defaultRepo = repo
	dbMu.Unlock()
	return nil
}

func Open(path string) (*SQLiteRepository, error) {
	repo, err := open(path)
	if err == nil {
		return repo, nil
	}
	if _, statErr := os.Stat(path); statErr != nil {
		return nil, fmt.Errorf("initialize database: %w", err)
	}

	backup := fmt.Sprintf("%s.corrupt-%s", path, time.Now().UTC().Format("20060102T150405Z"))
	if renameErr := os.Rename(path, backup); renameErr != nil {
		return nil, fmt.Errorf("initialize database: %w (preserving failed database: %v)", err, renameErr)
	}
	repo, retryErr := open(path)
	if retryErr != nil {
		return nil, fmt.Errorf("initialize replacement database (original retained at %s): %w", backup, retryErr)
	}
	return repo, nil
}

func open(path string) (*SQLiteRepository, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, fmt.Errorf("create database directory: %w", err)
	}
	conn, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	conn.SetMaxOpenConns(1)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err = conn.ExecContext(ctx, "PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000; PRAGMA foreign_keys=ON;"); err != nil {
		conn.Close()
		return nil, fmt.Errorf("configure database: %w", err)
	}
	repo := &SQLiteRepository{db: conn}
	if err := repo.migrate(ctx); err != nil {
		conn.Close()
		return nil, err
	}
	if err := repo.InterruptActiveSyncRuns(ctx, time.Now().UTC()); err != nil {
		conn.Close()
		return nil, fmt.Errorf("recover interrupted sync runs: %w", err)
	}
	return repo, nil
}

func DefaultRepository() *SQLiteRepository {
	dbMu.RLock()
	defer dbMu.RUnlock()
	return defaultRepo
}

func Close() error {
	dbMu.Lock()
	defer dbMu.Unlock()
	if db == nil {
		return nil
	}
	err := db.Close()
	db = nil
	defaultRepo = nil
	return err
}

func ShouldCheckWinget(wingetID string) (bool, error) {
	repo := DefaultRepository()
	if repo == nil {
		return true, nil
	}
	var lastCheck time.Time
	err := repo.db.QueryRow("SELECT last_check FROM winget_checks WHERE winget_id = ?", wingetID).Scan(&lastCheck)
	if err == sql.ErrNoRows {
		return true, nil
	}
	if err != nil {
		return true, err
	}
	return time.Since(lastCheck) >= 24*time.Hour, nil
}

func ShouldAttemptApp(releaseID string) (bool, error) {
	repo := DefaultRepository()
	if repo == nil {
		return true, nil
	}
	var failures int
	var lastAttempt time.Time
	err := repo.db.QueryRow("SELECT failures_count, last_attempt FROM app_errors WHERE release_id = ?", releaseID).Scan(&failures, &lastAttempt)
	if err == sql.ErrNoRows {
		return true, nil
	}
	if err != nil {
		return true, err
	}
	return failures < 3 || time.Since(lastAttempt) >= 24*time.Hour, nil
}

func RecordAppFailure(releaseID string) error {
	repo := DefaultRepository()
	if repo == nil {
		return nil
	}
	_, err := repo.db.Exec(`INSERT INTO app_errors (release_id, failures_count, last_attempt)
		VALUES (?, 1, ?) ON CONFLICT(release_id) DO UPDATE SET
		failures_count = failures_count + 1, last_attempt = excluded.last_attempt`, releaseID, time.Now().UTC())
	return err
}

func ResetAppFailures(releaseID string) error {
	repo := DefaultRepository()
	if repo == nil {
		return nil
	}
	_, err := repo.db.Exec("DELETE FROM app_errors WHERE release_id = ?", releaseID)
	return err
}

func UpdateWingetCheck(wingetID string) error {
	repo := DefaultRepository()
	if repo == nil {
		return nil
	}
	_, err := repo.db.Exec(`INSERT INTO winget_checks (winget_id, last_check) VALUES (?, ?)
		ON CONFLICT(winget_id) DO UPDATE SET last_check=excluded.last_check`, wingetID, time.Now().UTC())
	return err
}
