package apps

import (
	consts "KiskaLE/RustDesk-ID/internal/const"
	"KiskaLE/RustDesk-ID/internal/models"
	"KiskaLE/RustDesk-ID/internal/utils"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/sys/windows/registry"
)

type Manager struct{}

func NewManager() *Manager {
	return &Manager{}
}

// UninstallApp uninstalls an application based on its release type
func (Manager) Uninstall(ctx context.Context, release models.AssignedRelease, serverURL string) error {
	ctx, cancel := context.WithTimeout(ctx, consts.AppInstallTimeout)
	defer cancel()

	installer, err := newInstaller(ctx, release, serverURL)
	if err != nil {
		return err
	}

	if err = installer.Uninstall(); err != nil {
		utils.Error("Error when uninstalling app: " + err.Error())
		return err
	}

	return nil
}

// InstallApp installs an application based on its release type
func (m Manager) Install(ctx context.Context, release models.AssignedRelease, serverURL string) error {
	ctx, cancel := context.WithTimeout(ctx, consts.AppInstallTimeout)
	defer cancel()

	// Check requirements before installation
	if len(release.Requirements) > 0 {
		passed, err := CheckRequirements(release, serverURL)
		if err != nil {
			return fmt.Errorf("requirement check failed: %v", err)
		}
		if !passed {
			return fmt.Errorf("requirements not met, skipping installation")
		}
	}

	// Run pre-install script if configured.
	if err := runInstallScriptForPhase(release, serverURL, "pre"); err != nil {
		return err
	}

	installer, err := newInstaller(ctx, release, serverURL)
	if err != nil {
		return err
	}

	if err = installer.Install(); err != nil {
		utils.Error("Error when installing app: " + err.Error())
		return err
	}

	// Run post-install script if configured.
	if err := runInstallScriptForPhase(release, serverURL, "post"); err != nil {
		utils.Errorf("Post-install script failed for release %s: %v. Attempting rollback uninstall...", release.ID, err)
		if uninstallErr := m.Uninstall(ctx, release, serverURL); uninstallErr != nil {
			return fmt.Errorf("post-install script failed: %v; rollback uninstall failed: %v", err, uninstallErr)
		}
		return fmt.Errorf("post-install script failed: %v; rollback uninstall succeeded", err)
	}

	return nil
}

// IsAppInstalled checks if an application is installed based on detection rules
func (Manager) IsInstalled(ctx context.Context, release models.AssignedRelease, serverURL string) (bool, error) {
	installer, err := newInstaller(ctx, release, serverURL)
	if err != nil {
		return false, err
	}

	return installer.IsInstalled()
}

func (Manager) SupportsUpgrade(ctx context.Context, release models.AssignedRelease, serverURL string) bool {
	installer, err := newInstaller(ctx, release, serverURL)
	if err != nil {
		return false
	}

	_, ok := installer.(Upgrader)
	return ok
}

func (Manager) Upgrade(ctx context.Context, release models.AssignedRelease, serverURL string) error {
	ctx, cancel := context.WithTimeout(ctx, consts.AppInstallTimeout)
	defer cancel()

	installer, err := newInstaller(ctx, release, serverURL)
	if err != nil {
		return err
	}

	upgrader, ok := installer.(Upgrader)
	if !ok {
		return fmt.Errorf("installer type %q does not support upgrade", release.InstallerType)
	}

	return upgrader.Upgrade()
}

// checkDetectionRule checks a single detection rule and returns whether it passes
func checkDetectionRule(rule models.DetectionRule) (bool, error) {
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
			// Read file version via LiteralPath and environment variable to avoid script injection.
			cmd := exec.Command("powershell", "-NoProfile", "-Command",
				`(Get-Item -LiteralPath $env:FLEETCTRL_DETECTION_PATH).VersionInfo.FileVersion`)
			cmd.Env = append(os.Environ(), "FLEETCTRL_DETECTION_PATH="+path)
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
