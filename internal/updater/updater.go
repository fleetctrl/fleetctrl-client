package updater

import (
	consts "KiskaLE/RustDesk-ID/internal/const"
	"KiskaLE/RustDesk-ID/internal/utils"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
)

// UpdateInfo contains information about an available update parsed from X-Client-Update header
type UpdateInfo struct {
	Version string `json:"version"`
	ID      string `json:"id"`
	Hash    string `json:"hash"`
}

// Updater handles automatic client updates
type Updater struct {
	serverURL string
	mu        sync.Mutex
	updating  bool
}

var (
	globalUpdater     *Updater
	globalUpdaterOnce sync.Once
)

// GetUpdater returns the singleton Updater instance
func GetUpdater() *Updater {
	return globalUpdater
}

// InitUpdater initializes the global updater with the server URL
func InitUpdater(serverURL string) {
	globalUpdaterOnce.Do(func() {
		globalUpdater = &Updater{
			serverURL: serverURL,
		}
	})
}

// CheckUpdateHeader parses the X-Client-Update header from an HTTP response
// Returns nil if no update is available
func CheckUpdateHeader(resp *http.Response) *UpdateInfo {
	updateHeader := resp.Header.Get("X-Client-Update")
	if updateHeader == "" {
		return nil
	}

	var info UpdateInfo
	if err := json.Unmarshal([]byte(updateHeader), &info); err != nil {
		utils.Errorf("Failed to parse X-Client-Update header: %v", err)
		return nil
	}

	// Check if the version is actually different (simple string comparison as per docs)
	if info.Version == consts.Version {
		return nil
	}

	return &info
}

// ProcessUpdate handles the update if an update header is present in the response
// This is called from the HTTP middleware after every request
func (u *Updater) ProcessUpdate(resp *http.Response) {
	info := CheckUpdateHeader(resp)
	if info == nil {
		return
	}

	// Avoid concurrent update attempts
	u.mu.Lock()
	if u.updating {
		u.mu.Unlock()
		return
	}
	u.updating = true
	u.mu.Unlock()

	// Run update in background
	go func() {
		defer func() {
			u.mu.Lock()
			u.updating = false
			u.mu.Unlock()
		}()

		utils.Infof("New version available: %s (current: %s)", info.Version, consts.Version)

		if err := u.DownloadAndApplyUpdate(info); err != nil {
			utils.Errorf("Update failed: %v", err)
		}
	}()
}

// DownloadAndApplyUpdate downloads the new binary, verifies its hash, and applies the update
func (u *Updater) DownloadAndApplyUpdate(info *UpdateInfo) error {
	utils.Infof("Starting update to version %s...", info.Version)

	// Step 1: Download the update
	tmpPath, err := u.downloadUpdate(info)
	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}

	// Step 2: Verify hash
	if err := u.verifyHash(tmpPath, info.Hash); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("hash verification failed: %w", err)
	}

	utils.Info("Update downloaded and verified successfully")

	// Step 3: Apply update
	if err := u.applyUpdate(tmpPath, info.Version); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("apply update failed: %w", err)
	}

	return nil
}

// downloadUpdate downloads the new binary from the server
func (u *Updater) downloadUpdate(info *UpdateInfo) (string, error) {
	downloadURL := u.serverURL + "/client/download/" + info.ID

	resp, err := utils.Get(downloadURL, map[string]string{
		"Content-Type": "application/json",
	})
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle redirect (307)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Create temp file
	tmpFile, err := os.CreateTemp("", "fleetctrl-update-*.exe")
	if err != nil {
		return "", fmt.Errorf("failed to create temp file: %w", err)
	}
	defer tmpFile.Close()

	// Download the binary
	if _, err := io.Copy(tmpFile, resp.Body); err != nil {
		os.Remove(tmpFile.Name())
		return "", fmt.Errorf("failed to download: %w", err)
	}

	return tmpFile.Name(), nil
}

// verifyHash verifies the SHA256 hash of the downloaded file
func (u *Updater) verifyHash(filePath, expectedHash string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return fmt.Errorf("failed to calculate hash: %w", err)
	}

	calculatedHash := hex.EncodeToString(hasher.Sum(nil))

	// Case insensitive comparison for hex strings
	if !strings.EqualFold(calculatedHash, expectedHash) {
		return fmt.Errorf("hash mismatch: expected %s, got %s", expectedHash, calculatedHash)
	}

	utils.Infof("Hash verified: %s", calculatedHash)
	return nil
}

// applyUpdate runs the new binary with "update" command
// The new binary will use manager.UpdateService() which properly handles
// service stop/start via Windows SCM API
func (u *Updater) applyUpdate(newBinaryPath, newVersion string) error {
	utils.Infof("Launching new binary for self-update...")

	// Run the new binary with "update" command
	// This will:
	// 1. Stop the running service via SCM
	// 2. Copy itself to the target directory
	// 3. Start the service again
	cmd := exec.Command(newBinaryPath, "update")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP,
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start update process: %w", err)
	}

	utils.Infof("Update process started (PID: %d), service will restart with version %s", cmd.Process.Pid, newVersion)
	return nil
}

// IsUpdatePath returns true if the path is an update-related endpoint
// These paths should bypass update checking to avoid recursion
func IsUpdatePath(path string) bool {
	return strings.HasPrefix(path, "/client/download/")
}
