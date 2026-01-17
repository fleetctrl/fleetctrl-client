package database

import (
	consts "KiskaLE/RustDesk-ID/internal/const"
	"KiskaLE/RustDesk-ID/internal/utils"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

var db *sql.DB

// Init initializes the SQLite database with a self-healing mechanism
func Init() error {
	dbPath := filepath.Join(consts.ProgramDataDir, "client.db")
	maxAttempts := 3

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		err := tryInit(dbPath)
		if err == nil {
			utils.Infof("SQLite database initialized at %s (attempt %d)", dbPath, attempt)
			return nil
		}

		utils.Errorf("Database initialization attempt %d failed: %v", attempt, err)

		// Close connection if it was partially opened
		if db != nil {
			db.Close()
			db = nil
		}

		if attempt < maxAttempts {
			utils.Infof("Attempting to heal database by deleting: %s", dbPath)
			if err := os.Remove(dbPath); err != nil && !os.IsNotExist(err) {
				utils.Errorf("Failed to delete database file: %v", err)
			}
			time.Sleep(100 * time.Millisecond) // Small delay before retry
			continue
		}

		// Third attempt failed, panic as requested
		return fmt.Errorf("CRITICAL: SQLite database failed to initialize after %d attempts: %v", maxAttempts, err)
	}

	return nil
}

func tryInit(dbPath string) error {
	// Ensure directory exists
	if err := os.MkdirAll(consts.ProgramDataDir, 0755); err != nil {
		return fmt.Errorf("failed to create ProgramData directory: %v", err)
	}

	var err error
	db, err = sql.Open("sqlite", dbPath)
	if err != nil {
		return fmt.Errorf("failed to open database: %v", err)
	}

	// Test connection
	if err := db.Ping(); err != nil {
		return fmt.Errorf("failed to ping database: %v", err)
	}

	// Create tables
	query := `
	CREATE TABLE IF NOT EXISTS winget_checks (
		winget_id TEXT PRIMARY KEY,
		last_check DATETIME NOT NULL
	);
	CREATE TABLE IF NOT EXISTS app_errors (
		release_id TEXT PRIMARY KEY,
		failures_count INTEGER DEFAULT 0,
		last_attempt DATETIME
	);`

	if _, err := db.Exec(query); err != nil {
		return fmt.Errorf("failed to create tables: %v", err)
	}

	return nil
}

// ShouldCheckWinget returns true if the winget app should be checked for updates
func ShouldCheckWinget(wingetID string) (bool, error) {
	if db == nil {
		return true, nil // Fail open if DB is not initialized
	}

	var lastCheck time.Time
	err := db.QueryRow("SELECT last_check FROM winget_checks WHERE winget_id = ?", wingetID).Scan(&lastCheck)
	if err == sql.ErrNoRows {
		return true, nil // Never checked before
	}
	if err != nil {
		return true, err
	}

	// Only check if last check was more than 24 hours ago
	return time.Since(lastCheck) >= 24*time.Hour, nil
}

// ShouldAttemptApp returns true if the application should be attempted (install/uninstall)
func ShouldAttemptApp(releaseID string) (bool, error) {
	if db == nil {
		return true, nil
	}

	var failures int
	var lastAttempt time.Time
	err := db.QueryRow("SELECT failures_count, last_attempt FROM app_errors WHERE release_id = ?", releaseID).Scan(&failures, &lastAttempt)
	if err == sql.ErrNoRows {
		return true, nil // Never attempted before
	}
	if err != nil {
		return true, err
	}

	// If failures < 3, allow retry in every loop
	if failures < 3 {
		return true, nil
	}

	// If failures >= 3, wait 24 hours
	return time.Since(lastAttempt) >= 24*time.Hour, nil
}

// RecordAppFailure increments the failure count for a release
func RecordAppFailure(releaseID string) error {
	if db == nil {
		return nil
	}

	_, err := db.Exec(`
		INSERT INTO app_errors (release_id, failures_count, last_attempt) 
		VALUES (?, 1, ?) 
		ON CONFLICT(release_id) DO UPDATE SET 
			failures_count = failures_count + 1,
			last_attempt = excluded.last_attempt`,
		releaseID, time.Now())

	if err != nil {
		return fmt.Errorf("failed to record app failure: %v", err)
	}
	return nil
}

// ResetAppFailures resets the failure count for a release (on success)
func ResetAppFailures(releaseID string) error {
	if db == nil {
		return nil
	}

	_, err := db.Exec("DELETE FROM app_errors WHERE release_id = ?", releaseID)
	if err != nil {
		return fmt.Errorf("failed to reset app failures: %v", err)
	}
	return nil
}

// UpdateWingetCheck updates the last check time for a winget app
func UpdateWingetCheck(wingetID string) error {
	if db == nil {
		return nil
	}

	_, err := db.Exec("INSERT OR REPLACE INTO winget_checks (winget_id, last_check) VALUES (?, ?)", wingetID, time.Now())
	if err != nil {
		return fmt.Errorf("failed to update winget check time: %v", err)
	}

	return nil
}

// Close closes the database connection
func Close() error {
	if db != nil {
		return db.Close()
	}
	return nil
}
