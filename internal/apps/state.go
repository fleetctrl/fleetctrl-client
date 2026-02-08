package apps

import (
	"KiskaLE/RustDesk-ID/internal/utils"
	"fmt"
	"net/http"
	"strings"
)

type ReleaseInstallStateStatus string

const (
	ReleaseInstallStatePending     ReleaseInstallStateStatus = "PENDING"
	ReleaseInstallStateInstalling  ReleaseInstallStateStatus = "INSTALLING"
	ReleaseInstallStateInstalled   ReleaseInstallStateStatus = "INSTALLED"
	ReleaseInstallStateError       ReleaseInstallStateStatus = "ERROR"
	ReleaseInstallStateUninstalled ReleaseInstallStateStatus = "UNINSTALLED"
)

type releaseInstallStatePayload struct {
	Status      ReleaseInstallStateStatus `json:"status"`
	InstalledAt *int64                    `json:"installed_at,omitempty"`
	LastSeenAt  *int64                    `json:"last_seen_at,omitempty"`
}

func (s ReleaseInstallStateStatus) IsValid() bool {
	switch s {
	case ReleaseInstallStatePending,
		ReleaseInstallStateInstalling,
		ReleaseInstallStateInstalled,
		ReleaseInstallStateError,
		ReleaseInstallStateUninstalled:
		return true
	default:
		return false
	}
}

func ReportReleaseInstallState(serverURL, releaseID string, status ReleaseInstallStateStatus, installedAt, lastSeenAt *int64) error {
	if releaseID == "" {
		return fmt.Errorf("release ID is required")
	}
	if !status.IsValid() {
		return fmt.Errorf("invalid release install state status: %q", status)
	}

	url := strings.TrimRight(serverURL, "/") + "/apps/release/" + releaseID + "/state"
	payload := releaseInstallStatePayload{
		Status:      status,
		InstalledAt: installedAt,
		LastSeenAt:  lastSeenAt,
	}

	res, err := utils.Patch(url, payload, map[string]string{
		"Content-Type": "application/json",
	})
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		apiErr := utils.ParseHttpError(res)
		if apiErr == "" {
			return fmt.Errorf("state update failed with HTTP %d", res.StatusCode)
		}
		return fmt.Errorf("state update failed with HTTP %d: %s", res.StatusCode, apiErr)
	}

	return nil
}
