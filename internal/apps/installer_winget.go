package apps

import (
	"KiskaLE/RustDesk-ID/internal/database"
	"KiskaLE/RustDesk-ID/internal/models"
	"KiskaLE/RustDesk-ID/internal/utils"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

type wingetInstaller struct {
	ctx       context.Context
	release   *models.WingetRelease
	version   string
	serverUrl string
}

func (wi *wingetInstaller) Install() error {
	if wi.release == nil {
		return fmt.Errorf("winget release data is missing")
	}

	ctx := wi.ctx
	version := wi.version
	wingetID := wi.release.WingetID

	if err := validateWingetID(wingetID); err != nil {
		return err
	}

	if err := validateWingetVersion(version); err != nil {
		return err
	}

	// Check if a higher version is already installed
	if version != "" && version != "latest" {
		installedVersion, err := GetInstalledWingetVersion(wingetID)
		if err == nil && installedVersion != "" {
			if CompareVersions(installedVersion, version) > 0 {
				utils.Infof("Higher version (%s) of %s is already installed (requested version: %s), uninstalling first...", installedVersion, wingetID, version)
				if err := wi.Uninstall(); err != nil {
					return fmt.Errorf("failed to uninstall higher version before downgrade: %v", err)
				}
			}
		}
	}

	utils.Infof("Installing winget app %s (version %s)...", wingetID, version)

	// Wait for any existing winget process to complete
	waitForWingetLock(30 * time.Minute)

	// Build winget arguments
	wingetArgs := []string{
		"install",
		"--id", wingetID,
		"--silent",
		"--force",
		"--accept-package-agreements",
		"--accept-source-agreements",
		"--disable-interactivity",
	}
	if version != "" && version != "latest" {
		wingetArgs = append(wingetArgs, "-v", version)
	}

	output, err := runWingetCommand(ctx, wingetArgs...)
	if err != nil {
		return fmt.Errorf("winget install failed: %v (output: %s)", err, strings.TrimSpace(string(output)))
	}

	utils.Infof("Successfully installed winget app %s", wingetID)

	return nil
}

func (wi *wingetInstaller) Uninstall() error {
	if wi.release == nil {
		return fmt.Errorf("winget release data is missing")
	}

	ctx := wi.ctx
	wingetID := wi.release.WingetID
	version := wi.version

	if err := validateWingetID(wingetID); err != nil {
		return err
	}

	utils.Infof("Uninstalling winget app %s (version %s)...", wingetID, version)

	// Wait for any existing winget process to complete
	waitForWingetLock(30 * time.Minute)

	output, err := runWingetCommand(
		ctx,
		"uninstall",
		"--id", wingetID,
		"--silent",
		"--force",
		"--accept-source-agreements",
		"--disable-interactivity",
	)
	if err != nil {
		return fmt.Errorf("winget uninstall failed: %v (output: %s)", err, strings.TrimSpace(string(output)))
	}

	utils.Infof("Successfully uninstalled winget app %s", wingetID)

	return nil
}

func (wi *wingetInstaller) IsInstalled() (bool, error) {
	if wi.release == nil {
		return false, fmt.Errorf("winget release data is missing")
	}

	release := wi.release
	wingetID := release.WingetID
	version := wi.version

	utils.Infof("Checking winget app %s (version %s)...", wingetID, version)

	installedVersion, err := GetInstalledWingetVersion(wingetID)
	if err == nil && installedVersion != "" {
		// If version is specified, we check it
		if version != "" && version != "latest" {
			return CompareVersions(installedVersion, version) == 0, nil
		}
		// Otherwise just being listed is enough
		return true, nil
	}

	return false, nil
}

func (wi *wingetInstaller) Update() error {
	if wi.release == nil {
		return fmt.Errorf("winget release data is missing")
	}

	ctx := wi.ctx
	wingetID := wi.release.WingetID

	if err := validateWingetID(wingetID); err != nil {
		return err
	}

	// Wait for any existing winget process to complete
	waitForWingetLock(30 * time.Minute)

	output, err := runWingetCommand(
		ctx,
		"upgrade",
		"--id", wingetID,
		"--silent",
		"--force",
		"--accept-package-agreements",
		"--accept-source-agreements",
		"--disable-interactivity",
	)
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			// 0x8a15002b is the exit code for "No applicable update found"
			if uint32(exitError.ExitCode()) == 0x8a15002b {
				utils.Info("No applicable update found")
				return nil
			}
		}
		return fmt.Errorf("winget upgrade failed: %v (output: %s)", err, strings.TrimSpace(string(output)))
	}

	return nil
}

func (wi *wingetInstaller) ShouldCheckUpdate() (bool, error) {
	if wi.release == nil {
		return false, fmt.Errorf("winget release data is missing")
	}

	if err := validateWingetID(wi.release.WingetID); err != nil {
		return false, err
	}

	return database.ShouldCheckWinget(wi.release.WingetID)
}

func (wi *wingetInstaller) MarkUpdateChecked() error {
	if wi.release == nil {
		return fmt.Errorf("winget release data is missing")
	}

	if err := validateWingetID(wi.release.WingetID); err != nil {
		return err
	}

	return database.UpdateWingetCheck(wi.release.WingetID)
}

// waitForWingetLock waits for any existing winget process to complete.
// If the process doesn't complete within the timeout, it will be killed.
func waitForWingetLock(timeout time.Duration) {
	startTime := time.Now()
	for {
		running, err := utils.IsProcessRunning("winget.exe")
		if err != nil {
			utils.Errorf("Failed to check for a running winget process: %v", err)
			return
		}
		if !running {
			return
		}

		// Check timeout
		if time.Since(startTime) >= timeout {
			utils.Info("Winget process didn't complete in time, killing it...")
			if err := utils.KillProcesses("winget.exe"); err != nil {
				utils.Errorf("Failed to kill winget: %v", err)
			}
			time.Sleep(1 * time.Second) // Wait a bit for the process to be killed
			return
		}

		utils.Info("Waiting for another winget process to complete...")
		time.Sleep(2 * time.Second)
	}
}
