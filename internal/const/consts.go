package consts

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var (
	Version    = "2.2.0"
	Production = true

	// Derived from the system drive so the paths follow the Windows
	DefaultTargetDir = filepath.Join(systemVolume(), "Program Files", "fleetctrl")
	ProgramDataDir   = filepath.Join(systemVolume(), "ProgramData", "fleetctrl")
)

const (
	ServiceName        = "fleetctrl-client"
	ServiceDisplayName = "fleetctrl client"
	TargetExeName      = "client.exe"
	CompanyRegitryKey  = `SOFTWARE\fleetctrl`
	RegisteryRootKey   = `SOFTWARE\fleetctrl\client`
	DeviceIDValueName  = "DeviceID"
	MaxLogSize         = 20 * 1024 * 1024 // 20 MB
	AppInstallTimeout  = 30 * time.Minute
)

// systemVolume returns the drive Windows is installed on (e.g. "C:\"),
// falling back to C: when the environment variables are unavailable.
// Note: filepath.Clean must not be applied here - it turns "C:" into "C:."
// (a drive-relative path), which breaks filepath.Join.
func systemVolume() string {
	vol := os.Getenv("SystemDrive")
	if vol == "" {
		if sysroot := os.Getenv("SystemRoot"); sysroot != "" {
			vol = filepath.VolumeName(sysroot)
		}
	}
	if vol == "" {
		vol = `C:`
	}
	return strings.TrimSuffix(strings.TrimRight(vol, `\/`), ":") + `:\`
}

var (
	installDirOnce sync.Once
	installDir     string
)

func InstallDir() string {
	installDirOnce.Do(func() {
		exePath, err := os.Executable()
		if err != nil {
			installDir = DefaultTargetDir
			return
		}
		if resolved, err := filepath.EvalSymlinks(exePath); err == nil {
			exePath = resolved
		}
		installDir = filepath.Dir(exePath)
	})
	return installDir
}
