package apps

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
)

var (
	wingetIDPattern      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	wingetVersionPattern = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z._-]*$`)
)

// GetWingetPath finds the full path to winget.exe
func GetWingetPath() (string, error) {
	programFilesPath := os.Getenv("ProgramW6432")
	if programFilesPath == "" {
		programFilesPath = os.Getenv("ProgramFiles")
	}
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
	if err := validateWingetID(wingetID); err != nil {
		return "", err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	output, err := runWingetCommand(ctx, "list", "--id", wingetID, "--exact", "--accept-source-agreements", "--source", "winget")
	if err != nil {
		out := strings.ToLower(string(output))
		// "not installed" is not an error for this lookup.
		if strings.Contains(out, "no installed package found") || strings.Contains(out, "no package found") {
			return "", nil
		}
		return "", fmt.Errorf("failed to query winget package %s: %v (output: %s)", wingetID, err, strings.TrimSpace(string(output)))
	}

	pattern := regexp.MustCompile(`(?mi)^` + regexp.QuoteMeta(wingetID) + `\s+([^\s]+)`)
	match := pattern.FindStringSubmatch(string(output))
	if len(match) < 2 {
		return "", nil
	}
	return strings.TrimSpace(match[1]), nil
}

func validateWingetID(wingetID string) error {
	if wingetID == "" {
		return fmt.Errorf("winget ID is missing")
	}
	if !wingetIDPattern.MatchString(wingetID) {
		return fmt.Errorf("invalid winget ID format: %q", wingetID)
	}
	return nil
}

func validateWingetVersion(version string) error {
	if version == "" || version == "latest" {
		return nil
	}
	if !wingetVersionPattern.MatchString(version) {
		return fmt.Errorf("invalid winget version format: %q", version)
	}
	return nil
}

func runWingetCommand(ctx context.Context, args ...string) ([]byte, error) {
	wingetPath, err := GetWingetPath()
	if err != nil {
		return nil, err
	}

	env, err := buildWingetEnv(wingetPath)
	if err != nil {
		return nil, err
	}

	cmd := exec.CommandContext(ctx, wingetPath, args...)
	cmd.Dir = filepath.Dir(wingetPath)
	cmd.Env = env

	return cmd.CombinedOutput()
}

func buildWingetEnv(wingetPath string) ([]string, error) {
	programFilesPath := os.Getenv("ProgramW6432")
	if programFilesPath == "" {
		programFilesPath = os.Getenv("ProgramFiles")
	}
	if programFilesPath == "" {
		programFilesPath = "C:\\Program Files"
	}

	windowsAppsPath := filepath.Join(programFilesPath, "WindowsApps")
	depPatterns := []string{
		filepath.Join(windowsAppsPath, "Microsoft.VCLibs.140.00.UWPDesktop_*_x64__8wekyb3d8bbwe"),
		filepath.Join(windowsAppsPath, "Microsoft.UI.Xaml.2.*_x64__8wekyb3d8bbwe"),
	}

	var depDirs []string
	for _, pattern := range depPatterns {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve winget dependency pattern %q: %v", pattern, err)
		}
		sort.Slice(matches, func(i, j int) bool {
			iInfo, iErr := os.Stat(matches[i])
			jInfo, jErr := os.Stat(matches[j])
			if iErr != nil || jErr != nil {
				return matches[i] > matches[j]
			}
			return iInfo.ModTime().After(jInfo.ModTime())
		})
		depDirs = append(depDirs, matches...)
	}

	wingetDir := filepath.Dir(wingetPath)
	existingPath := os.Getenv("PATH")
	pathParts := []string{wingetDir}
	pathParts = append(pathParts, depDirs...)
	if existingPath != "" {
		pathParts = append(pathParts, existingPath)
	}

	return upsertEnv(os.Environ(), "PATH", strings.Join(pathParts, ";")), nil
}

func upsertEnv(env []string, key, value string) []string {
	prefix := strings.ToUpper(key) + "="
	for i := range env {
		if strings.HasPrefix(strings.ToUpper(env[i]), prefix) {
			env[i] = key + "=" + value
			return env
		}
	}
	return append(env, key+"="+value)
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
