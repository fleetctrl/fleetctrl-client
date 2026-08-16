package apps

import (
	"KiskaLE/RustDesk-ID/internal/models"
	"context"
	"fmt"
)

type Installer interface {
	Install() error
	Uninstall() error
	IsInstalled() (bool, error)
}

type Upgrader interface {
	Upgrade() error
}

func newInstaller(ctx context.Context, release models.AssignedRelease, serverURL string) (Installer, error) {
	switch release.InstallerType {
	case "winget":
		return &wingetInstaller{ctx: ctx, release: release.Winget, version: release.Version}, nil
	case "win32":
		return &win32Installer{ctx: ctx, releaseID: release.ID, release: release.Win32, version: release.Version, serverURL: serverURL, detectionRules: release.DetectionRules}, nil
	default:
		return nil, fmt.Errorf("unknown installer type: %q", release.InstallerType)
	}
}
