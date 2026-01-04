package apps

import (
	"KiskaLE/RustDesk-ID/internal/models"
	"KiskaLE/RustDesk-ID/internal/utils"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// UninstallApp uninstalls an application based on its release type
func UninstallApp(release models.AssignedRelease, serverURL string) error {
	switch release.InstallerType {
	case "win32":
		if release.Win32 == nil {
			return utils.Errorf("win32 release data is missing")
		}
		if release.Win32.UninstallScript == "" {
			return utils.Errorf("uninstall script is missing for win32 release")
		}

		utils.Infof("Uninstalling win32 app (version %s) using script...", release.Version)

		installerPath, executionDir, cleanup, err := PrepareWin32Binary(release, serverURL, "uninstallation")
		if err != nil {
			return err
		}
		defer cleanup()

		// Run uninstall script using PowerShell
		// Replace placeholder in script with actual binary path
		uninstallScript := strings.ReplaceAll(release.Win32.UninstallScript, "{{INSTALLER_PATH}}", installerPath)

		cmd := exec.Command("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", uninstallScript)
		cmd.Dir = executionDir
		cmd.Stdout = log.Writer()
		cmd.Stderr = log.Writer()

		if err := cmd.Run(); err != nil {
			return fmt.Errorf("uninstall script failed: %v", err)
		}

		utils.Infof("Successfully uninstalled win32 app (version %s)", release.Version)
		return nil

	case "winget":
		if release.Winget == nil {
			return fmt.Errorf("winget release data is missing")
		}
		if release.Winget.WingetID == "" {
			return fmt.Errorf("winget ID is missing")
		}

		utils.Infof("Uninstalling winget app %s (version %s)...", release.Winget.WingetID, release.Version)

		// Run winget uninstall via PowerShell (winget needs to run from its folder when running as SYSTEM)
		psScript := fmt.Sprintf(`
		$wingetDir = (Get-ChildItem -Path "$env:ProgramFiles\WindowsApps\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe" | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName
		$deps = Get-ChildItem -Path "$env:ProgramFiles\WindowsApps\Microsoft.VCLibs.140.00.UWPDesktop_*_x64__8wekyb3d8bbwe", "$env:ProgramFiles\WindowsApps\Microsoft.UI.Xaml.2.*_x64__8wekyb3d8bbwe" | Sort-Object LastWriteTime -Descending
		foreach ($dep in $deps) { $env:Path = "$($dep.FullName);$env:Path" }
		Push-Location $wingetDir
		$result = .\winget.exe uninstall --id "%s" --silent --accept-source-agreements | Out-String
		Write-Host $result
		$exitCode = $LASTEXITCODE
		Pop-Location
		exit $exitCode
		`, release.Winget.WingetID)

		cmd := exec.Command("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", psScript)
		cmd.Stdout = log.Writer()
		cmd.Stderr = log.Writer()

		if err := cmd.Run(); err != nil {
			return fmt.Errorf("winget uninstall failed: %v", err)
		}

		utils.Infof("Successfully uninstalled winget app %s", release.Winget.WingetID)
		return nil

	default:
		return fmt.Errorf("unknown installer type: %s", release.InstallerType)
	}
}

// InstallApp installs an application based on its release type
func InstallApp(release models.AssignedRelease, serverURL string) error {
	switch release.InstallerType {
	case "win32":
		if release.Win32 == nil {
			return fmt.Errorf("win32 release data is missing")
		}
		if release.Win32.InstallScript == "" {
			return fmt.Errorf("install script is missing for win32 release")
		}

		utils.Infof("Installing win32 app (version %s)...", release.Version)

		installerPath, executionDir, cleanup, err := PrepareWin32Binary(release, serverURL, "installation")
		if err != nil {
			return err
		}
		defer cleanup()

		// Run install script using PowerShell
		// Replace placeholder in script with actual installer path
		installScript := strings.ReplaceAll(release.Win32.InstallScript, "{{INSTALLER_PATH}}", installerPath)

		cmd := exec.Command("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", installScript)
		cmd.Dir = executionDir
		cmd.Stdout = log.Writer()
		cmd.Stderr = log.Writer()

		if err := cmd.Run(); err != nil {
			return fmt.Errorf("install script failed: %v", err)
		}

		// check if app is installed

		utils.Infof("Successfully installed win32 app (version %s)", release.Version)
		return nil

	case "winget":
		if release.Winget == nil {
			return fmt.Errorf("winget release data is missing")
		}
		if release.Winget.WingetID == "" {
			return fmt.Errorf("winget ID is missing")
		}

		// Check if a higher version is already installed
		if release.Version != "" && release.Version != "latest" {
			installedVersion, err := GetInstalledWingetVersion(release.Winget.WingetID)
			if err == nil && installedVersion != "" {
				if CompareVersions(installedVersion, release.Version) > 0 {
					utils.Infof("Higher version (%s) of %s is already installed (requested version: %s), uninstalling first...", installedVersion, release.Winget.WingetID, release.Version)
					if err := UninstallApp(release, serverURL); err != nil {
						return fmt.Errorf("failed to uninstall higher version before downgrade: %v", err)
					}
				}
			}
		}

		utils.Infof("Installing winget app %s (version %s)...", release.Winget.WingetID, release.Version)

		// Build winget arguments
		wingetArgs := fmt.Sprintf(`--id "%s" --silent --accept-package-agreements --accept-source-agreements`, release.Winget.WingetID)
		if release.Version != "" && release.Version != "latest" {
			wingetArgs += fmt.Sprintf(` -v %s`, release.Version)
		}

		// Run winget install via PowerShell (winget needs to run from its folder when running as SYSTEM)
		psScript := fmt.Sprintf(`
		$wingetDir = (Get-ChildItem -Path "$env:ProgramFiles\WindowsApps\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe" | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName
		$deps = Get-ChildItem -Path "$env:ProgramFiles\WindowsApps\Microsoft.VCLibs.140.00.UWPDesktop_*_x64__8wekyb3d8bbwe", "$env:ProgramFiles\WindowsApps\Microsoft.UI.Xaml.2.*_x64__8wekyb3d8bbwe" | Sort-Object LastWriteTime -Descending
		foreach ($dep in $deps) { $env:Path = "$($dep.FullName);$env:Path" }
		Push-Location $wingetDir
		$result = .\winget.exe install %s | Out-String
		Write-Host $result
		$exitCode = $LASTEXITCODE
		Pop-Location
		exit $exitCode
		`, wingetArgs)

		cmd := exec.Command("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", psScript)
		cmd.Stdout = log.Writer()
		cmd.Stderr = log.Writer()

		if err := cmd.Run(); err != nil {
			return fmt.Errorf("winget install failed: %v", err)
		}

		utils.Infof("Successfully installed winget app %s", release.Winget.WingetID)
		return nil

	default:
		return fmt.Errorf("unknown installer type: %s", release.InstallerType)
	}
}

// UpgradeApp upgrades an application based on its release type
func UpgradeApp(release models.AssignedRelease) error {
	switch release.InstallerType {
	case "winget":
		if release.Winget == nil {
			return fmt.Errorf("winget release data is missing")
		}
		if release.Winget.WingetID == "" {
			return fmt.Errorf("winget ID is missing")
		}

		// Run winget upgrade via PowerShell
		psScript := fmt.Sprintf(`
		$wingetDir = (Get-ChildItem -Path "$env:ProgramFiles\WindowsApps\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe" | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName
		$deps = Get-ChildItem -Path "$env:ProgramFiles\WindowsApps\Microsoft.VCLibs.140.00.UWPDesktop_*_x64__8wekyb3d8bbwe", "$env:ProgramFiles\WindowsApps\Microsoft.UI.Xaml.2.*_x64__8wekyb3d8bbwe" | Sort-Object LastWriteTime -Descending
		foreach ($dep in $deps) { $env:Path = "$($dep.FullName);$env:Path" }
		Push-Location $wingetDir
		$result = .\winget.exe upgrade --id "%s" --silent --accept-package-agreements --accept-source-agreements | Out-String
		Write-Host $result
		$exitCode = $LASTEXITCODE
		Pop-Location
		exit $exitCode
		`, release.Winget.WingetID)

		cmd := exec.Command("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", psScript)
		cmd.Stdout = log.Writer()
		cmd.Stderr = log.Writer()

		if err := cmd.Run(); err != nil {
			if exitError, ok := err.(*exec.ExitError); ok {
				// 0x8a15002b is the exit code for "No applicable update found"
				if uint32(exitError.ExitCode()) == 0x8a15002b {
					utils.Info("No applicable update found")
					return nil
				}
			}
			return fmt.Errorf("winget upgrade failed: %v", err)
		}

		return nil

	default:
		return nil // Only winget supported for now
	}
}

// PrepareWin32Binary downloads and prepares a win32 binary for execution (handles ZIPs)
func PrepareWin32Binary(release models.AssignedRelease, serverURL string, purpose string) (string, string, func(), error) {
	if release.Win32 == nil {
		return "", "", nil, fmt.Errorf("win32 release data is missing")
	}

	tempDir := os.TempDir()
	installerPath := filepath.Join(tempDir, filepath.Base(release.Win32.InstallBinaryPath))

	// Download the binary
	downloadURL := fmt.Sprintf("%s/apps/download/%s", serverURL, release.ID)
	utils.Infof("Downloading binary for %s from: %s", purpose, downloadURL)

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
	if release.Win32.Hash != "" {
		fileHash, err := utils.CalculateFileHash(installerPath)
		if err != nil {
			os.Remove(installerPath)
			return "", "", nil, fmt.Errorf("failed to calculate hash: %v", err)
		}
		if !strings.EqualFold(fileHash, release.Win32.Hash) {
			os.Remove(installerPath)
			return "", "", nil, fmt.Errorf("hash mismatch: expected %s, got %s", release.Win32.Hash, fileHash)
		}
		utils.Info("Hash verified successfully")
	}

	executionDir := tempDir
	var cleanupExtract func()

	// If it's a ZIP, extract it
	if strings.HasSuffix(strings.ToLower(release.Win32.InstallBinaryPath), ".zip") {
		extractDir := filepath.Join(tempDir, fmt.Sprintf("extract_%s_%s", purpose, release.ID))
		os.MkdirAll(extractDir, os.ModePerm)
		utils.Infof("Extracting ZIP for %s to: %s", purpose, extractDir)
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
