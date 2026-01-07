package apps

import (
	"KiskaLE/RustDesk-ID/internal/models"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// CheckDetectionRule checks a single detection rule and returns whether it passes
func CheckDetectionRule(rule models.DetectionRule) (bool, error) {
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
			cmp := CompareVersions(fileVersion, value)

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

		hive, keyPath := ParseRegistryPath(path)

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

			cmp := CompareVersions(val, value)
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

// IsAppInstalled checks if an application is installed based on detection rules
func IsAppInstalled(release models.AssignedRelease) (bool, error) {
	// If it's a winget app, we can automatically check by ID and version
	if release.InstallerType == "winget" && release.Winget != nil && release.Winget.WingetID != "" {
		log.Printf("Checking winget app %s (version %s)...", release.Winget.WingetID, release.Version)

		installedVersion, err := GetInstalledWingetVersion(release.Winget.WingetID)
		if err == nil && installedVersion != "" {
			// If version is specified, we check it
			if release.Version != "" && release.Version != "latest" {
				return CompareVersions(installedVersion, release.Version) == 0, nil
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
		passed, err := CheckDetectionRule(rule)
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
