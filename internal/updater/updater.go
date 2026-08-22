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
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
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

	// Only trigger an update when the advertised version is actually newer.
	// Plain inequality would attempt downgrades, which MajorUpgrade rejects.
	if compareVersions(info.Version, consts.Version) <= 0 {
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

	installerExt := u.getInstallerExtension(info, resp.Header.Get("Content-Type"))

	// Create temp file with the final extension up-front. On Windows, renaming an
	// open file handle can fail with a sharing violation, which breaks MSI updates.
	tmpFile, err := os.CreateTemp("", "fleetctrl-update-*"+installerExt)
	if err != nil {
		return "", fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer tmpFile.Close()

	// Download the binary
	if _, err := io.Copy(tmpFile, resp.Body); err != nil {
		os.Remove(tmpPath)
		return "", fmt.Errorf("failed to download: %w", err)
	}

	if err := tmpFile.Sync(); err != nil {
		os.Remove(tmpPath)
		return "", fmt.Errorf("failed to flush downloaded file: %w", err)
	}

	if err := tmpFile.Close(); err != nil {
		os.Remove(tmpPath)
		return "", fmt.Errorf("failed to close temp file: %w", err)
	}

	return tmpPath, nil
}

func (u *Updater) getInstallerExtension(info *UpdateInfo, contentType string) string {
	contentType = strings.ToLower(strings.TrimSpace(contentType))
	updateID := strings.ToLower(strings.TrimSpace(info.ID))

	if strings.Contains(contentType, "msi") || strings.HasSuffix(updateID, ".msi") {
		return ".msi"
	}

	return ".exe"
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
	utils.Infof("Launching update process for %s...", newBinaryPath)

	if strings.HasSuffix(strings.ToLower(newBinaryPath), ".msi") {
		return u.applyMSIUpdate(newBinaryPath, newVersion)
	}

	utils.Info("Launching new binary for self-update...")
	var cmd *exec.Cmd
	cmd = exec.Command(newBinaryPath, "update")

	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP,
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start update process: %w", err)
	}

	utils.Infof("Update process started (PID: %d), version %s will be applied", cmd.Process.Pid, newVersion)
	return nil
}

func (u *Updater) applyMSIUpdate(msiPath, newVersion string) error {
	logDir := filepath.Join(consts.ProgramDataDir, "logs")
	if err := os.MkdirAll(logDir, 0755); err != nil {
		logDir = os.TempDir()
	}
	msiLog := filepath.Join(logDir, fmt.Sprintf("update-%s.log", time.Now().Format("20060102-150405")))

	utils.Infof("Applying MSI update using msiexec...")
	cmd := exec.Command("msiexec",
		"/i", msiPath,
		"/qn", "/norestart",
		fmt.Sprintf("/l*v %s", strconv.Quote(msiLog)),
	)

	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP,
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start msiexec: %w", err)
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case err := <-done:
		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				return fmt.Errorf("msiexec failed with exit code %d (log: %s): %v", exitErr.ExitCode(), msiLog, err)
			}
			return fmt.Errorf("msiexec failed (log: %s): %v", msiLog, err)
		}
		utils.Infof("MSI update to %s completed successfully (log: %s)", newVersion, msiLog)
		os.Remove(msiPath)
	case <-time.After(30 * time.Minute):
		utils.Errorf("MSI update timed out after 30 minutes (log: %s)", msiLog)
	}
	return nil
}

// compareVersions compares dotted numeric version strings.
// Returns -1 if a < b, 0 if equal (ignoring prerelease suffixes), 1 if a > b.
func compareVersions(a, b string) int {
	numericPart := func(v string) string {
		if i := strings.IndexByte(v, '-'); i >= 0 {
			return v[:i]
		}
		return v
	}
	as := strings.Split(numericPart(strings.TrimSpace(a)), ".")
	bs := strings.Split(numericPart(strings.TrimSpace(b)), ".")
	for i := 0; i < len(as) || i < len(bs); i++ {
		var av, bv int
		if i < len(as) {
			av, _ = strconv.Atoi(as[i])
		}
		if i < len(bs) {
			bv, _ = strconv.Atoi(bs[i])
		}
		if av != bv {
			if av < bv {
				return -1
			}
			return 1
		}
	}
	return 0
}

// IsUpdatePath returns true if the path is an update-related endpoint
// These paths should bypass update checking to avoid recursion
func IsUpdatePath(path string) bool {
	return strings.HasPrefix(path, "/client/download/")
}
