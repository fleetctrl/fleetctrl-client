package apps

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// GetWingetPath finds the full path to winget.exe
func GetWingetPath() (string, error) {
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

// GetInstalledWingetVersion returns the version of the winget app if installed, otherwise an empty string
func GetInstalledWingetVersion(wingetID string) (string, error) {
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

// CompareVersions compares two version strings, returns -1, 0, or 1
func CompareVersions(v1, v2 string) int {
	v1 = strings.ReplaceAll(v1, "-", ".")
	v2 = strings.ReplaceAll(v2, "-", ".")
	parts1 := strings.Split(v1, ".")
	parts2 := strings.Split(v2, ".")
	maxLen := max(len(parts2), len(parts1))
	for i := 0; i < maxLen; i++ {
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

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// ParseRegistryPath parses a registry path into hive and key path
func ParseRegistryPath(path string) (registry.Key, string) {
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
