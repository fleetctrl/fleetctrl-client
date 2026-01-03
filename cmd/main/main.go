package main

import (
	"KiskaLE/RustDesk-ID/internal/auth"
	consts "KiskaLE/RustDesk-ID/internal/const"
	"KiskaLE/RustDesk-ID/internal/utils"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
)

// getWingetPath finds the full path to winget.exe
// When running as SYSTEM, winget is not in PATH, so we need to find it in WindowsApps folder
func getWingetPath() (string, error) {
	programFilesPath := os.Getenv("ProgramW6432")
	if programFilesPath == "" {
		programFilesPath = "C:\\Program Files"
	}

	windowsAppsPath := filepath.Join(programFilesPath, "WindowsApps")
	pattern := filepath.Join(windowsAppsPath, "Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe", "winget.exe")

	matches, err := filepath.Glob(pattern)
	if err != nil {
		return "", fmt.Errorf("error searching for winget: %v", err)
	}

	if len(matches) == 0 {
		return "", fmt.Errorf("winget.exe not found in WindowsApps folder")
	}

	// Return the first match (should be the installed version)
	return matches[0], nil
}

type serviceHandler struct {
	ms *MainService
}

type Task struct {
	ID        string          `json:"id"`
	Status    string          `json:"status"`
	Task      string          `json:"task"`
	TaskData  json.RawMessage `json:"task_data"`
	CreatedAt time.Time       `json:"created_at"`
}

type SetPasswordTask struct {
	Password string `json:"password"`
}

type SetNetworkStringTask struct {
	NetworkString string `json:"networkString"`
}

type Win32Release struct {
	InstallBinaryPath   string `json:"install_binary_path"`
	Hash                string `json:"hash"`
	InstallScript       string `json:"install_script"`
	UninstallScript     string `json:"uninstall_script"`
	InstallBinarySize   int64  `json:"install_binary_size"`
	InstallBinaryBucket string `json:"install_binary_bucket"`
}

type WingetRelease struct {
	WingetID string `json:"winget_id"`
}

type DetectionRule struct {
	Type   string                 `json:"type"`
	Config map[string]interface{} `json:"config"`
}

type ReleaseRequirement struct {
	TimeoutSeconds int64  `json:"timeout_seconds"`
	RunAsSystem    bool   `json:"run_as_system"`
	StoragePath    string `json:"storage_path"`
	Hash           string `json:"hash"`
	Bucket         string `json:"bucket"`
	ByteSize       int64  `json:"byte_size"`
}

type AssignedRelease struct {
	ID                string               `json:"id"`
	Version           string               `json:"version"`
	AssignType        string               `json:"assign_type"`
	Action            string               `json:"action"`
	InstallerType     string               `json:"installer_type"`
	UninstallPrevious bool                 `json:"uninstall_previous"`
	Win32             *Win32Release        `json:"win32,omitempty"`
	Winget            *WingetRelease       `json:"winget,omitempty"`
	DetectionRules    []DetectionRule      `json:"detection_rules,omitempty"`
	Requirements      []ReleaseRequirement `json:"requirements,omitempty"`
}

type AssignedApp struct {
	ID          string            `json:"id"`
	DisplayName string            `json:"display_name"`
	Publisher   string            `json:"publisher"`
	AutoUpdate  bool              `json:"auto_update"`
	Releases    []AssignedRelease `json:"releases"`
}

type MainService struct {
	as        *auth.AuthService
	serverURL string
	tokens    *auth.Tokens
}

func NewMainService(as *auth.AuthService, serverURL string) *MainService {
	return &MainService{as: as, serverURL: serverURL}
}

func (ms *MainService) startRustDeskServerSync() {
	fmt.Println("Starting RustDesk sync...")
	for {
		// get rustdesk ID
		rustdeskID, err := utils.GetRustDeskID()
		if err != nil {
			log.Println(err)
			time.Sleep(15 * time.Minute)
			continue
		}
		// get PC name
		computerName, err := utils.GetComputerName()
		if err != nil {
			log.Println(err)
			time.Sleep(15 * time.Minute)
			continue
		}
		// get PC IP
		computerIP, err := utils.GetComputerIP()
		if err != nil {
			log.Println(err)
		}
		// get OS
		os, err := utils.GetComputerOS()
		if err != nil {
			log.Println(err)
		}
		// get OS version
		osVersion, err := utils.GetComputerOSVersion()
		if err != nil {
			log.Println(err)
		}

		loginUser, err := utils.GetCurrentUser()
		if err != nil {
			log.Println(err)
		}

		type Computer struct {
			Name           string `json:"name"`
			RustdeskID     string `json:"rustdesk_id"`
			IP             string `json:"ip"`
			OS             string `json:"os"`
			OSVersion      string `json:"os_version"`
			LoginUser      string `json:"login_user"`
			LastConnection string `json:"last_connection"`
		}

		computer := Computer{
			Name:           computerName,
			RustdeskID:     rustdeskID,
			IP:             computerIP,
			OS:             os,
			OSVersion:      osVersion,
			LoginUser:      loginUser,
			LastConnection: time.Now().Format(time.RFC3339),
		}

		res, err := utils.Patch(ms.serverURL+"/computer/rustdesk-sync", map[string]string{
			"name":            computer.Name,
			"rustdesk_id":     computer.RustdeskID,
			"ip":              computer.IP,
			"os":              computer.OS,
			"os_version":      computer.OSVersion,
			"login_user":      computer.LoginUser,
			"last_connection": computer.LastConnection,
		}, map[string]string{
			"Content-Type": "application/json",
		})
		if err != nil {
			log.Println(err)
			time.Sleep(15 * time.Minute)
			continue
		}

		if res.StatusCode != 200 {
			// parse body
			log.Println("Server returned status code: ", utils.ParseHttpError(res))
			time.Sleep(15 * time.Minute)
			continue
		}
		time.Sleep(5 * time.Minute)
	}
}

func (ms *MainService) startRustDeskServerTasks() {
	log.Println("Starting tasks...")
	for {
		type TaskResponse struct {
			Tasks []Task `json:"tasks"`
		}

		// get tasks
		tasksRes, err := utils.Get(ms.serverURL+"/tasks", map[string]string{
			"Content-Type": "application/json",
		})
		if err != nil {
			log.Println(err)
			time.Sleep(5 * time.Minute)
			continue
		}
		if tasksRes.StatusCode != 200 {
			// parse body
			log.Println("Server returned error: ", utils.ParseHttpError(tasksRes))
			time.Sleep(5 * time.Minute)
			continue
		}

		var data TaskResponse
		if err := json.NewDecoder(tasksRes.Body).Decode(&data); err != nil {
			log.Println(err)
			time.Sleep(5 * time.Minute)
			continue
		}
		tasks := data.Tasks

		for i := range tasks {
			task := tasks[i]
			switch task.Task {
			case "SET_PASSWD":
				// set task started
				utils.Patch(ms.serverURL+"/task/"+task.ID, map[string]string{
					"status": "IN_PROGRESS",
					"error":  "",
				}, map[string]string{
					"Content-Type": "application/json",
				})
				var d SetPasswordTask
				if err := json.Unmarshal(task.TaskData, &d); err != nil {
					log.Println(err)
				}

				// set passwor using powershell
				cmd := exec.Command("C:\\Program Files\\RustDesk\\RustDesk.exe", "--password", d.Password)
				cmd.Stdout = os.Stdout
				cmd.Stderr = os.Stderr
				err := cmd.Run()
				if err != nil {
					log.Println(err)
					utils.Patch(ms.serverURL+"/task/"+task.ID, map[string]string{
						"status": "ERROR",
						"error":  err.Error(),
					}, map[string]string{
						"Content-Type": "application/json",
					})
					break
				}
				log.Println("Password set")

				utils.Patch(ms.serverURL+"/task/"+task.ID, map[string]string{
					"status": "SUCCESS",
					"error":  "",
				}, map[string]string{
					"Content-Type": "application/json",
				})

			case "SET_NETWORK_STRING":
				// set task started
				utils.Patch(ms.serverURL+"/task/"+task.ID, map[string]string{
					"status": "IN_PROGRESS",
					"error":  "",
				}, map[string]string{
					"Content-Type": "application/json",
				})
				var d SetNetworkStringTask
				if err := json.Unmarshal(task.TaskData, &d); err != nil {
					log.Println(err)
				}
				cleanString := strings.TrimLeft(d.NetworkString, "=")
				// set network using powershell
				cmd := exec.Command("C:\\Program Files\\RustDesk\\RustDesk.exe", "--config", cleanString)
				cmd.Stdout = os.Stdout
				cmd.Stderr = os.Stderr
				err := cmd.Run()
				if err != nil {
					log.Println(err)
					utils.Patch(ms.serverURL+"/task/"+task.ID, map[string]string{
						"status": "ERROR",
						"error":  err.Error(),
					}, map[string]string{
						"Content-Type": "application/json",
					})
					break
				}
				log.Println("Network string set")

				utils.Patch(ms.serverURL+"/task/"+task.ID, map[string]string{
					"status": "SUCCESS",
					"error":  "",
				}, map[string]string{
					"Content-Type": "application/json",
				})

			}
		}

		time.Sleep(5 * time.Minute)
	}
}

func (ms *MainService) startApplicationsManagement() {
	log.Println("Starting applications management...")
	for {
		// get asigned applications
		appsResponse, err := utils.Get(ms.serverURL+"/apps/assigned", map[string]string{
			"Content-Type": "application/json",
		})
		if err != nil {
			log.Println(err)
			time.Sleep(15 * time.Minute)
			continue
		}
		if appsResponse.StatusCode != 200 {
			// parse body
			log.Println("Server returned error: ", appsResponse.StatusCode)
			time.Sleep(15 * time.Minute)
			continue
		}
		type AssignedAppsResponse struct {
			Apps []AssignedApp `json:"apps"`
		}
		var assignedAppsResponse AssignedAppsResponse
		if err := json.NewDecoder(appsResponse.Body).Decode(&assignedAppsResponse); err != nil {
			log.Println(err)
			time.Sleep(15 * time.Minute)
			continue
		}

		for _, app := range assignedAppsResponse.Apps {
			newestRelease := app.Releases[0]
			if newestRelease.AssignType == "exclude" {
				continue
			}

			switch newestRelease.Action {
			case "install":
				// check if application is installed
				installed, err := isAppInstalled(newestRelease)
				if err != nil {
					log.Println(err)
					continue
				}
				if installed {
					if newestRelease.InstallerType == "winget" && newestRelease.Winget != nil && app.AutoUpdate {
						log.Printf("Checking for updates for winget app %s...", newestRelease.Winget.WingetID)
						if err := upgradeApp(newestRelease); err != nil {
							log.Printf("Failed to upgrade winget app %s: %v", newestRelease.Winget.WingetID, err)
						}
					}
					continue
				}

				// application is not installed
				// install application
				if newestRelease.UninstallPrevious {
					// uninstall previous versions
					for _, release := range app.Releases {
						if release.Version == newestRelease.Version {
							continue
						}
						installed, err := isAppInstalled(release)
						if err != nil {
							log.Println(err)
							continue
						}
						if installed {
							log.Println("Previous version is installed, uninstalling...")
							if err := uninstallApp(release); err != nil {
								log.Printf("Failed to uninstall previous version: %v", err)
							}
							break
						}
					}
				}

				err = installApp(newestRelease, ms.serverURL)
				if err != nil {
					log.Printf("Failed to install app: %v", err)
				}

			case "uninstall":
				// check if application is unisntalled
				installed, err := isAppInstalled(newestRelease)
				if err != nil {
					log.Println(err)
					continue
				}
				if !installed {
					continue
				}

				// application is installed
				// uninstall application
				for _, release := range app.Releases {
					installed, err := isAppInstalled(release)
					if err != nil {
						log.Println(err)
						continue
					}
					if installed {
						log.Println("Previous version is installed, uninstalling...")
						if err := uninstallApp(release); err != nil {
							log.Printf("Failed to uninstall previous version: %v", err)
						}
						break
					}
				}
			}
		}

		time.Sleep(15 * time.Minute)
	}

}

// uninstallApp uninstalls an application based on its release type
func uninstallApp(release AssignedRelease) error {
	switch release.InstallerType {
	case "win32":
		if release.Win32 == nil {
			return fmt.Errorf("win32 release data is missing")
		}
		if release.Win32.UninstallScript == "" {
			return fmt.Errorf("uninstall script is missing for win32 release")
		}

		log.Printf("Uninstalling win32 app (version %s) using script...", release.Version)

		// Run uninstall script using PowerShell
		cmd := exec.Command("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", release.Win32.UninstallScript)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		if err := cmd.Run(); err != nil {
			return fmt.Errorf("uninstall script failed: %v", err)
		}

		log.Printf("Successfully uninstalled win32 app (version %s)", release.Version)
		return nil

	case "winget":
		if release.Winget == nil {
			return fmt.Errorf("winget release data is missing")
		}
		if release.Winget.WingetID == "" {
			return fmt.Errorf("winget ID is missing")
		}

		log.Printf("Uninstalling winget app %s (version %s)...", release.Winget.WingetID, release.Version)

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
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		if err := cmd.Run(); err != nil {
			return fmt.Errorf("winget uninstall failed: %v", err)
		}

		log.Printf("Successfully uninstalled winget app %s", release.Winget.WingetID)
		return nil

	default:
		return fmt.Errorf("unknown installer type: %s", release.InstallerType)
	}
}

// installApp installs an application based on its release type
func installApp(release AssignedRelease, serverURL string) error {
	switch release.InstallerType {
	case "win32":
		if release.Win32 == nil {
			return fmt.Errorf("win32 release data is missing")
		}
		if release.Win32.InstallScript == "" {
			return fmt.Errorf("install script is missing for win32 release")
		}

		log.Printf("Installing win32 app (version %s)...", release.Version)

		// Download binary from storage
		tempDir := os.TempDir()
		installerPath := filepath.Join(tempDir, filepath.Base(release.Win32.InstallBinaryPath))

		// Download the installer binary using new endpoint
		downloadURL := fmt.Sprintf("%s/apps/download/%s", serverURL, release.ID)
		log.Printf("Downloading installer from: %s", downloadURL)

		resp, err := utils.Get(downloadURL, map[string]string{})
		if err != nil {
			return fmt.Errorf("failed to download installer: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			return fmt.Errorf("failed to download installer: HTTP %d", resp.StatusCode)
		}

		// Create installer file
		installerFile, err := os.Create(installerPath)
		if err != nil {
			return fmt.Errorf("failed to create installer file: %v", err)
		}

		// Copy response body to file
		_, err = io.Copy(installerFile, resp.Body)
		installerFile.Close()
		if err != nil {
			os.Remove(installerPath)
			return fmt.Errorf("failed to write installer file: %v", err)
		}

		// Verify hash
		if release.Win32.Hash != "" {
			fileHash, err := utils.CalculateFileHash(installerPath)
			if err != nil {
				os.Remove(installerPath)
				return fmt.Errorf("failed to calculate file hash: %v", err)
			}
			if !strings.EqualFold(fileHash, release.Win32.Hash) {
				os.Remove(installerPath)
				return fmt.Errorf("hash mismatch: expected %s, got %s", release.Win32.Hash, fileHash)
			}
			log.Println("Hash verified successfully")
		}

		// Run install script using PowerShell
		// Replace placeholder in script with actual installer path
		installScript := strings.ReplaceAll(release.Win32.InstallScript, "{{INSTALLER_PATH}}", installerPath)

		cmd := exec.Command("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", installScript)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		if err := cmd.Run(); err != nil {
			os.Remove(installerPath)
			return fmt.Errorf("install script failed: %v", err)
		}

		// Cleanup installer
		os.Remove(installerPath)

		log.Printf("Successfully installed win32 app (version %s)", release.Version)
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
			installedVersion, err := getInstalledWingetVersion(release.Winget.WingetID)
			if err == nil && installedVersion != "" {
				if compareVersions(installedVersion, release.Version) > 0 {
					log.Printf("Higher version (%s) of %s is already installed (requested version: %s), uninstalling first...", installedVersion, release.Winget.WingetID, release.Version)
					if err := uninstallApp(release); err != nil {
						return fmt.Errorf("failed to uninstall higher version before downgrade: %v", err)
					}
				}
			}
		}

		log.Printf("Installing winget app %s (version %s)...", release.Winget.WingetID, release.Version)

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
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		if err := cmd.Run(); err != nil {
			return fmt.Errorf("winget install failed: %v", err)
		}

		log.Printf("Successfully installed winget app %s", release.Winget.WingetID)
		return nil

	default:
		return fmt.Errorf("unknown installer type: %s", release.InstallerType)
	}
}

// upgradeApp upgrades an application based on its release type
func upgradeApp(release AssignedRelease) error {
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
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		if err := cmd.Run(); err != nil {
			if exitError, ok := err.(*exec.ExitError); ok {
				// 0x8a15002b is the exit code for "No applicable update found"
				if uint32(exitError.ExitCode()) == 0x8a15002b {
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

// checkDetectionRule checks a single detection rule and returns whether it passes
// Config structure: { "version": "1", "operator": string, "path": string, "value": string }
// Types: "file", "registry"
// File operators: exists, version_equal, version_equal_or_higher, version_equal_or_lower, version_higher, version_lower
// Registry operators: exists, string, version_equal, version_equal_or_higher, version_equal_or_lower, version_higher, version_lower
func checkDetectionRule(rule DetectionRule) (bool, error) {
	path, _ := rule.Config["path"].(string)
	value, _ := rule.Config["value"].(string)
	operator, _ := rule.Config["operator"].(string)

	switch rule.Type {
	case "file":
		if path == "" {
			return false, fmt.Errorf("file: missing 'path' in config")
		}

		switch operator {
		case "exists":
			_, err := os.Stat(path)
			return err == nil, nil

		case "version_equal", "version_equal_or_higher", "version_equal_or_lower", "version_higher", "version_lower":
			if value == "" {
				return false, fmt.Errorf("file version check: missing 'value' in config")
			}
			// Get file version using PowerShell
			cmd := exec.Command("powershell", "-NoProfile", "-Command",
				fmt.Sprintf(`(Get-Item '%s').VersionInfo.FileVersion`, path))
			output, err := cmd.Output()
			if err != nil {
				return false, nil // File doesn't exist or has no version
			}
			fileVersion := strings.TrimSpace(string(output))
			if fileVersion == "" {
				return false, nil
			}
			cmp := compareVersions(fileVersion, value)

			switch operator {
			case "version_equal":
				return cmp == 0, nil
			case "version_equal_or_higher":
				return cmp >= 0, nil
			case "version_equal_or_lower":
				return cmp <= 0, nil
			case "version_higher":
				return cmp > 0, nil
			case "version_lower":
				return cmp < 0, nil
			}
		default:
			return false, fmt.Errorf("file: unknown operator '%s'", operator)
		}

	case "registry":
		if path == "" {
			return false, fmt.Errorf("registry: missing 'path' in config")
		}

		hive, keyPath := parseRegistryPath(path)

		switch operator {
		case "exists":
			key, err := registry.OpenKey(hive, keyPath, registry.QUERY_VALUE)
			if err == nil {
				key.Close()
				return true, nil
			}
			return false, nil

		case "string":
			// Check if registry value equals the expected string
			// Path format: HKLM\...\KeyName\ValueName
			lastBackslash := strings.LastIndex(keyPath, "\\")
			if lastBackslash == -1 {
				return false, fmt.Errorf("registry string: invalid path format, expected key\\valueName")
			}
			regKeyPath := keyPath[:lastBackslash]
			valueName := keyPath[lastBackslash+1:]

			key, err := registry.OpenKey(hive, regKeyPath, registry.QUERY_VALUE)
			if err != nil {
				return false, nil
			}
			defer key.Close()
			val, _, err := key.GetStringValue(valueName)
			if err != nil {
				return false, nil
			}
			return val == value, nil

		case "version_equal", "version_equal_or_higher", "version_equal_or_lower", "version_higher", "version_lower":
			// Compare registry value as version
			lastBackslash := strings.LastIndex(keyPath, "\\")
			if lastBackslash == -1 {
				return false, fmt.Errorf("registry version: invalid path format")
			}
			regKeyPath := keyPath[:lastBackslash]
			valueName := keyPath[lastBackslash+1:]

			key, err := registry.OpenKey(hive, regKeyPath, registry.QUERY_VALUE)
			if err != nil {
				return false, nil
			}
			defer key.Close()
			val, _, err := key.GetStringValue(valueName)
			if err != nil {
				return false, nil
			}

			cmp := compareVersions(val, value)
			switch operator {
			case "version_equal":
				return cmp == 0, nil
			case "version_equal_or_higher":
				return cmp >= 0, nil
			case "version_equal_or_lower":
				return cmp <= 0, nil
			case "version_higher":
				return cmp > 0, nil
			case "version_lower":
				return cmp < 0, nil
			}

		default:
			return false, fmt.Errorf("registry: unknown operator '%s'", operator)
		}

	default:
		return false, fmt.Errorf("unknown detection type: %s", rule.Type)
	}

	return false, nil
}

// parseRegistryPath parses a registry path into hive and key path
func parseRegistryPath(path string) (registry.Key, string) {
	path = strings.ReplaceAll(path, "/", "\\")
	if strings.HasPrefix(path, "HKLM\\") || strings.HasPrefix(path, "HKEY_LOCAL_MACHINE\\") {
		return registry.LOCAL_MACHINE, strings.TrimPrefix(strings.TrimPrefix(path, "HKLM\\"), "HKEY_LOCAL_MACHINE\\")
	}
	if strings.HasPrefix(path, "HKCU\\") || strings.HasPrefix(path, "HKEY_CURRENT_USER\\") {
		return registry.CURRENT_USER, strings.TrimPrefix(strings.TrimPrefix(path, "HKCU\\"), "HKEY_CURRENT_USER\\")
	}
	if strings.HasPrefix(path, "HKCR\\") || strings.HasPrefix(path, "HKEY_CLASSES_ROOT\\") {
		return registry.CLASSES_ROOT, strings.TrimPrefix(strings.TrimPrefix(path, "HKCR\\"), "HKEY_CLASSES_ROOT\\")
	}
	return registry.LOCAL_MACHINE, path
}

// compareVersions compares two version strings, returns -1, 0, or 1
func compareVersions(v1, v2 string) int {
	parts1 := strings.Split(v1, ".")
	parts2 := strings.Split(v2, ".")
	maxLen := max(len(parts2), len(parts1))
	for i := range maxLen {
		var n1, n2 int
		if i < len(parts1) {
			fmt.Sscanf(parts1[i], "%d", &n1)
		}
		if i < len(parts2) {
			fmt.Sscanf(parts2[i], "%d", &n2)
		}
		if n1 < n2 {
			return -1
		}
		if n1 > n2 {
			return 1
		}
	}
	return 0
}

// isAppInstalled checks if an application is installed based on detection rules
func isAppInstalled(release AssignedRelease) (bool, error) {
	// If it's a winget app, we can automatically check by ID and version
	if release.InstallerType == "winget" && release.Winget != nil && release.Winget.WingetID != "" {
		log.Printf("Checking winget app %s (version %s)...", release.Winget.WingetID, release.Version)

		installedVersion, err := getInstalledWingetVersion(release.Winget.WingetID)
		if err == nil && installedVersion != "" {
			// If version is specified, we check it
			if release.Version != "" && release.Version != "latest" {
				return compareVersions(installedVersion, release.Version) == 0, nil
			}
			// Otherwise just being listed is enough
			return true, nil
		}

		// If winget check fails and no other rules, return false
		if len(release.DetectionRules) == 0 {
			return false, nil
		}
	}

	if len(release.DetectionRules) == 0 {
		return false, nil
	}

	// All rules must pass for the app to be considered installed
	for _, rule := range release.DetectionRules {
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

// getInstalledWingetVersion returns the version of the winget app if installed, otherwise an empty string
func getInstalledWingetVersion(wingetID string) (string, error) {
	// PowerShell script to get the version of the installed winget app
	psScript := fmt.Sprintf(`
	$wingetDir = (Get-ChildItem -Path "$env:ProgramFiles\WindowsApps\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe" | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName
	if (-not $wingetDir) { exit 1 }
	$deps = Get-ChildItem -Path "$env:ProgramFiles\WindowsApps\Microsoft.VCLibs.140.00.UWPDesktop_*_x64__8wekyb3d8bbwe", "$env:ProgramFiles\WindowsApps\Microsoft.UI.Xaml.2.*_x64__8wekyb3d8bbwe" | Sort-Object LastWriteTime -Descending
	foreach ($dep in $deps) { $env:Path = "$($dep.FullName);$env:Path" }
	Push-Location $wingetDir
	$output = .\winget.exe list --id "%s" --exact --accept-source-agreements --source winget 2>$null | Out-String
	Pop-Location
	if ($output -match '%s\s+([^\s]+)') {
		Write-Host $matches[1]
	}
	`, wingetID, regexp.QuoteMeta(wingetID))

	cmd := exec.Command("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", psScript)
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

func (s *serviceHandler) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop}

	// Mark service as running and accept Stop/Shutdown
	changes <- svc.Status{
		State:   svc.Running,
		Accepts: svc.AcceptStop | svc.AcceptShutdown,
	}

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	serverURL, err := GetRegisteryValue(registry.LOCAL_MACHINE, consts.RegisteryRootKey, "server_url")
	if err != nil {
		log.Fatalln("error getting key from registry: ", err)
	}

	for {
		ok, err := utils.Ping(serverURL)
		if err == nil && ok {
			break
		}

		// wait briefly, but allow Stop/Shutdown
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				return false, 0
			case svc.Interrogate:
				changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
			}
		case <-time.After(5 * time.Second): // instead of 5 minutes; exponential backoff could be better
		}
	}

	// check if computer is enrolled

	as := auth.NewAuthService(serverURL)
	ms := NewMainService(as, serverURL)

	// check if computer is registered
	registered, err := ms.as.IsEnrolled()
	if err != nil {
		log.Fatalf("error during registration check: %v", err)
	}
	if !registered {
		log.Fatalln("This computer is not registered on the server.")
	}

	fmt.Println("Is computer registered: ", registered)
	var tokens auth.Tokens

	// load refresh token and refresh access token
	if rt, lerr := auth.LoadRefreshToken(consts.ProgramDataDir+"/tokens", "refresh_token.txt"); lerr == nil && rt != "" {
		if nt, rerr := ms.as.RefreshTokens(rt); rerr == nil {
			tokens = nt
			// uložit nový refresh token po rotaci
			if err := auth.SaveRefershToken(tokens.RefreshToken, consts.ProgramDataDir+"/tokens", "refresh_token.txt"); err != nil {
				log.Println("warning: failed to save refresh token after refresh:", err)
			}
		} else {
			log.Println("token refresh failed, trying recover:", rerr)
			if nt, rerr2 := ms.as.RecoverTokens(); rerr2 == nil {
				tokens = nt
				if err := auth.SaveRefershToken(tokens.RefreshToken, consts.ProgramDataDir+"/tokens", "refresh_token.txt"); err != nil {
					log.Println("warning: failed to save refresh token after recover:", err)
				}
			} else {
				log.Println("token recover failed:", rerr2)
			}
		}
	} else {
		log.Println("refresh token not found, attempting recover without refresh token")
		if nt, rerr := ms.as.RecoverTokens(); rerr == nil {
			tokens = nt
			if err := auth.SaveRefershToken(tokens.RefreshToken, consts.ProgramDataDir+"/tokens", "refresh_token.txt"); err != nil {
				log.Println("warning: failed to save refresh token after recover:", err)
			}
		} else {
			log.Println("token recover failed:", rerr)
		}
	}

	ms.tokens = &tokens

	// Initialize HTTP client with auth middleware (Bearer + DPoP with auto-refresh)
	auth.InitHTTPClient(ms.as, ms.tokens, func(nt auth.Tokens) {
		if err := auth.SaveRefershToken(nt.RefreshToken, consts.ProgramDataDir+"/tokens", "refresh_token.txt"); err != nil {
			log.Println("error saving refresh token after refresh:", err)
		}
	})

	go ms.startRustDeskServerSync()
	go ms.startRustDeskServerTasks()
	go ms.startApplicationsManagement()

	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				// Windows shell sometimes requests status
				changes <- svc.Status{
					State:   svc.Running,
					Accepts: svc.AcceptStop | svc.AcceptShutdown,
				}
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				return false, 0
			default:
				// ignore other commands
				log.Printf("Unknown service command: %d", c.Cmd)
			}
		case <-ticker.C:
			// do nothing
		}
	}
}

func main() {

	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "install":
			installCmd := flag.NewFlagSet("install", flag.ExitOnError)
			enrollToken := installCmd.String("token", "", "Enrollment token")
			serverURL := installCmd.String("url", "", "Server URL")

			err := installCmd.Parse(os.Args[2:])
			if err != nil {
				log.Fatal(err)
			}

			if *enrollToken == "" || *serverURL == "" {
				log.Fatalln("missing --token or --url")
			}

			err = InstallService(*enrollToken, *serverURL)
			if err != nil {
				panic(err)
			}
			return
		case "remove":
			err := RemoveService()
			if err != nil {
				panic(err)
			}
			return
		case "update":
			err := UpdateService()
			if err != nil {
				panic(err)
			}
			return
		}
	}

	// 1) open (or create) file for writing
	f, err := os.OpenFile(consts.TargetDir+`\client.log`,
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, // append to end
		0o644)                               // perms rw-r-r
	if err != nil {
		log.Fatalf("failed to open log: %v", err)
	}
	defer f.Close()

	// 2) redirect logger output
	log.SetOutput(f)

	// 3) set format (date, time, file:line)
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	if !consts.Production {
		// initialize supabase client
		// for dev only
		// check if computer is enrolled

		serverURL, err := GetRegisteryValue(registry.LOCAL_MACHINE, consts.RegisteryRootKey, "server_url")
		if err != nil {
			log.Fatalln("error getting key from registry: ", err)
		}

		as := auth.NewAuthService(serverURL)
		ms := NewMainService(as, serverURL)

		// check if computer is registered
		registered, err := ms.as.IsEnrolled()
		if err != nil {
			log.Fatalf("chyba při kontrole registrace: %v", err)
		}

		if !registered {
			log.Fatalln("This computer is not registered on the server.")
		}

		var tokens auth.Tokens

		if rt, lerr := auth.LoadRefreshToken(consts.ProgramDataDir+"/tokens", "refresh_token.txt"); lerr == nil && rt != "" {
			if nt, rerr := ms.as.RefreshTokens(rt); rerr == nil {
				tokens = nt
				if err := auth.SaveRefershToken(tokens.RefreshToken, consts.ProgramDataDir+"/tokens", "refresh_token.txt"); err != nil {
					log.Println("warning: failed to save refresh token after refresh:", err)
				}
			} else {
				log.Println("token refresh failed, trying recover:", rerr)
				if nt, rerr2 := ms.as.RecoverTokens(); rerr2 == nil {
					tokens = nt
					if err := auth.SaveRefershToken(tokens.RefreshToken, consts.ProgramDataDir+"/tokens", "refresh_token.txt"); err != nil {
						log.Println("warning: failed to save refresh token after recover:", err)
					}
				} else {
					log.Println("token recover failed:", rerr2)
				}
			}
		} else {
			log.Println("refresh token not found, attempting recover without refresh token")
			if nt, rerr := ms.as.RecoverTokens(); rerr == nil {
				tokens = nt
				if err := auth.SaveRefershToken(tokens.RefreshToken, consts.ProgramDataDir+"/tokens", "refresh_token.txt"); err != nil {
					log.Println("warning: failed to save refresh token after recover:", err)
				}
			} else {
				log.Println("token recover failed:", rerr)
			}
		}
		ms.tokens = &tokens

		// Initialize HTTP client with auth middleware (Bearer + DPoP with auto-refresh)
		auth.InitHTTPClient(ms.as, ms.tokens, func(nt auth.Tokens) {
			if err := auth.SaveRefershToken(nt.RefreshToken, consts.ProgramDataDir+"/tokens", "refresh_token.txt"); err != nil {
				log.Println("error saving refresh token after refresh:", err)
			}
		})

		go ms.startRustDeskServerSync()
		go ms.startRustDeskServerTasks()
		for {
			time.Sleep(1 * time.Hour)
		}
	}

	if err := svc.Run(consts.ServiceName, &serviceHandler{}); err != nil {
		log.Fatalf("service error: %v", err)
	}
}
