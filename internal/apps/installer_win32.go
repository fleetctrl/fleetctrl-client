package apps

import (
	"KiskaLE/RustDesk-ID/internal/models"
	"KiskaLE/RustDesk-ID/internal/utils"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
)

type win32Installer struct {
	ctx            context.Context
	releaseID      string
	release        *models.Win32Release
	version        string
	serverURL      string
	detectionRules []models.DetectionRule
}

func (wi *win32Installer) Install() error {
	if wi.release == nil {
		return fmt.Errorf("win32 release data is missing")
	}

	ctx := wi.ctx
	version := wi.version
	release := wi.release
	serverURL := wi.serverURL
	releaseID := wi.releaseID

	if release.InstallScript == "" {
		return fmt.Errorf("install script is missing for win32 release")
	}

	utils.Infof("Installing win32 app (version %s)...", version)

	installerPath, executionDir, cleanup, err := prepareWin32Binary(releaseID, *release, serverURL)
	if err != nil {
		return err
	}
	defer cleanup()

	// Run install script using PowerShell
	// Replace placeholder in script with actual installer path
	installScript := strings.ReplaceAll(release.InstallScript, "{{INSTALLER_PATH}}", installerPath)

	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", installScript)
	cmd.Dir = executionDir
	cmd.Stdout = log.Writer()
	cmd.Stderr = log.Writer()

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("install script failed: %v", err)
	}

	utils.Infof("Successfully installed win32 app (version %s)", version)

	return nil
}

func (wi *win32Installer) Uninstall() error {
	if wi.release == nil {
		return fmt.Errorf("win32 release data is missing")
	}

	ctx := wi.ctx
	releaseID := wi.releaseID
	release := wi.release
	version := wi.version
	serverURL := wi.serverURL

	if wi.release.UninstallScript == "" {
		return fmt.Errorf("uninstall script is missing for win32 release")
	}

	utils.Infof("Uninstalling win32 app (version %s) using script...", version)

	installerPath, executionDir, cleanup, err := prepareWin32Binary(releaseID, *release, serverURL)
	if err != nil {
		return err
	}
	defer cleanup()

	// Run uninstall script using PowerShell
	// Replace placeholder in script with actual binary path
	uninstallScript := strings.ReplaceAll(release.UninstallScript, "{{INSTALLER_PATH}}", installerPath)

	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", uninstallScript)
	cmd.Dir = executionDir
	cmd.Stdout = log.Writer()
	cmd.Stderr = log.Writer()

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("uninstall script failed: %v", err)
	}

	utils.Infof("Successfully uninstalled win32 app (version %s)", version)

	return nil
}

func (wi *win32Installer) IsInstalled() (bool, error) {
	detectionRules := wi.detectionRules

	if len(detectionRules) == 0 {
		return false, nil
	}

	// All rules must pass for the app to be considered installed
	for _, rule := range detectionRules {
		passed, err := checkDetectionRule(rule)
		if err != nil {
			log.Printf("Detection rule error (%s): %v", rule.Type, err)
			return false, err
		}
		if !passed {
			return false, nil
		}
	}

	return true, nil
}

// PrepareWin32Binary downloads and prepares a win32 binary for execution (handles ZIPs)
func prepareWin32Binary(releaseID string, release models.Win32Release, serverURL string) (string, string, func(), error) {
	tempDir := os.TempDir()
	installerPath := filepath.Join(tempDir, fmt.Sprintf("%s%s", uuid.New().String(), filepath.Ext(release.InstallerName)))
	id := releaseID

	// Download the binary
	downloadURL := fmt.Sprintf("%s/apps/download/%s", serverURL, id)
	utils.Infof("Downloading binary from: %s", downloadURL)

	resp, err := utils.Get(downloadURL, map[string]string{})
	if err != nil {
		return "", "", nil, fmt.Errorf("failed to download binary: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", "", nil, fmt.Errorf("failed to download binary: HTTP %d", resp.StatusCode)
	}

	// Create local file
	f, err := os.Create(installerPath)
	if err != nil {
		return "", "", nil, fmt.Errorf("failed to create local file: %v", err)
	}

	if _, err = utils.Copy(f, resp.Body); err != nil {
		f.Close()
		os.Remove(installerPath)
		return "", "", nil, fmt.Errorf("failed to save binary: %v", err)
	}
	f.Close()

	// Verify hash
	if release.Hash != "" {
		fileHash, err := utils.CalculateFileHash(installerPath)
		if err != nil {
			os.Remove(installerPath)
			return "", "", nil, fmt.Errorf("failed to calculate hash: %v", err)
		}
		if !strings.EqualFold(fileHash, release.Hash) {
			os.Remove(installerPath)
			return "", "", nil, fmt.Errorf("hash mismatch: expected %s, got %s", release.Hash, fileHash)
		}
		utils.Info("Hash verified successfully")
	}

	executionDir := tempDir
	var cleanupExtract func()

	// If it's a ZIP, extract it
	if strings.HasSuffix(strings.ToLower(release.InstallerName), ".zip") {
		extractDir := filepath.Join(tempDir, fmt.Sprintf("extract_%s", id))
		os.MkdirAll(extractDir, os.ModePerm)
		utils.Infof("Extracting ZIP to: %s", extractDir)
		if err := utils.Unzip(installerPath, extractDir); err != nil {
			os.Remove(installerPath)
			os.RemoveAll(extractDir)
			return "", "", nil, fmt.Errorf("failed to unzip binary: %v", err)
		}
		executionDir = extractDir
		cleanupExtract = func() { os.RemoveAll(extractDir) }
	}

	cleanupAll := func() {
		os.Remove(installerPath)
		if cleanupExtract != nil {
			cleanupExtract()
		}
	}

	return installerPath, executionDir, cleanupAll, nil
}
