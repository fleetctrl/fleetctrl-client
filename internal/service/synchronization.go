package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"KiskaLE/RustDesk-ID/internal/apps"
	"KiskaLE/RustDesk-ID/internal/database"
	"KiskaLE/RustDesk-ID/internal/models"
	synccoordinator "KiskaLE/RustDesk-ID/internal/sync"
	"KiskaLE/RustDesk-ID/internal/utils"
)

type ComputerSyncResult struct {
	CompletedAt time.Time `json:"completed_at"`
}

type ApplicationSyncResult struct {
	CompletedAt  time.Time `json:"completed_at"`
	Total        int       `json:"total"`
	Installed    int       `json:"installed"`
	NotInstalled int       `json:"not_installed"`
	Errors       int       `json:"errors"`
}

func (ms *MainService) SyncComputerOnce(ctx context.Context) (ComputerSyncResult, error) {
	result := ComputerSyncResult{}
	rustdeskID, rustdeskErr := utils.GetRustDeskID()
	computerName, err := utils.GetComputerName()
	if err != nil {
		return result, fmt.Errorf("read computer name: %w", err)
	}
	computerIP, _ := utils.GetComputerIP()
	osName, _ := utils.GetComputerOS()
	osVersion, _ := utils.GetComputerOSVersion()
	loginUser, _ := utils.GetCurrentUser()
	intuneID, _ := utils.GetIntuneID()
	if rustdeskErr != nil {
		utils.Errorf("Failed to read RustDesk ID: %v", rustdeskErr)
	}
	computer := models.Computer{
		Name: computerName, RustdeskID: rustdeskID, IP: computerIP, OS: osName,
		OSVersion: osVersion, LoginUser: loginUser, IntuneID: intuneID,
		LastConnection: time.Now().UTC().Format(time.RFC3339),
	}
	body, err := json.Marshal(computer)
	if err != nil {
		return result, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, ms.serverURL+"/computer/rustdesk-sync", bytesReader(body))
	if err != nil {
		return result, err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return result, fmt.Errorf("send computer state: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return result, fmt.Errorf("server returned %s", res.Status)
	}
	result.CompletedAt = time.Now().UTC()
	return result, nil
}

func bytesReader(data []byte) *bytes.Reader { return bytes.NewReader(data) }

func (ms *MainService) fetchAssignedApps(ctx context.Context) ([]models.AssignedApp, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ms.serverURL+"/apps/assigned", nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("load assigned applications: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned %s", res.Status)
	}

	var response models.AssignedAppsResponse
	if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("decode assigned applications: %w", err)
	}

	return response.Apps, nil
}

func stateFromAssignment(app models.AssignedApp, release models.AssignedRelease) database.ManagedAppState {
	wingetID := ""

	if release.Winget != nil {
		wingetID = release.Winget.WingetID
	}

	return database.ManagedAppState{
		ReleaseID: release.ID, AppID: app.ID, DisplayName: app.DisplayName,
		Publisher: app.Publisher, Version: release.Version, InstallerType: release.InstallerType,
		WingetID: wingetID, AssignType: release.AssignType, DesiredAction: release.Action,
		DetectedStatus: database.DetectionUnknown, OperationStatus: database.OperationIdle,
	}
}

func newestAssignments(assigned []models.AssignedApp) ([]database.ManagedAppState, map[string]models.AssignedRelease) {
	states := make([]database.ManagedAppState, 0, len(assigned))
	releases := make(map[string]models.AssignedRelease)

	for _, app := range assigned {
		if len(app.Releases) == 0 {
			continue
		}
		release := app.Releases[len(app.Releases)-1]
		if release.AssignType == "exclude" {
			continue
		}
		states = append(states, stateFromAssignment(app, release))
		releases[release.ID] = release
	}

	return states, releases
}

func (ms *MainService) refreshAssignedApplicationStates(ctx context.Context, assigned []models.AssignedApp) (ApplicationSyncResult, error) {
	var result ApplicationSyncResult
	repo := database.DefaultRepository()

	if repo == nil {
		return result, fmt.Errorf("database is not initialized")
	}

	observedAt := time.Now().UTC()
	states, releases := newestAssignments(assigned)

	if err := repo.UpsertAssignedApps(ctx, states, observedAt); err != nil {
		return result, fmt.Errorf("save assignments: %w", err)
	}

	result.Total = len(states)
	for _, state := range states {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		installed, err := ms.apps.IsInstalled(ctx, releases[state.ReleaseID], ms.serverURL)
		checkedAt := time.Now().UTC()
		if err != nil {
			result.Errors++
			_ = repo.UpdateDetectionState(ctx, state.ReleaseID, database.DetectionUnknown, checkedAt, summarizeError(err))
			ms.reportReleaseInstallState(state.ReleaseID, apps.ReleaseInstallStateError, nil)
			continue
		}
		status := database.DetectionNotInstalled
		reportStatus := apps.ReleaseInstallStateUninstalled
		if installed {
			status = database.DetectionInstalled
			reportStatus = apps.ReleaseInstallStateInstalled
			result.Installed++
		} else {
			result.NotInstalled++
		}
		if err := repo.UpdateDetectionState(ctx, state.ReleaseID, status, checkedAt, ""); err != nil {
			result.Errors++
			continue
		}
		ms.reportReleaseInstallState(state.ReleaseID, reportStatus, nil)
	}

	result.CompletedAt = time.Now().UTC()

	if result.Errors > 0 {
		return result, fmt.Errorf("%d application checks failed", result.Errors)
	}

	return result, nil
}

func (ms *MainService) RefreshAssignedApplicationStates(ctx context.Context) (ApplicationSyncResult, error) {
	assigned, err := ms.fetchAssignedApps(ctx)

	if err != nil {
		return ApplicationSyncResult{}, err
	}

	return ms.refreshAssignedApplicationStates(ctx, assigned)
}

func (ms *MainService) ReconcileAssignedApplications(ctx context.Context) (ApplicationSyncResult, error) {
	assigned, err := ms.fetchAssignedApps(ctx)
	if err != nil {
		return ApplicationSyncResult{}, err
	}

	statusResult, statusErr := ms.refreshAssignedApplicationStates(ctx, assigned)

	repo := database.DefaultRepository()
	if repo == nil {
		return statusResult, fmt.Errorf("database is not initialized")
	}

	for _, app := range assigned {
		if err := ctx.Err(); err != nil {
			return statusResult, err
		}

		if len(app.Releases) == 0 {
			continue
		}

		release := app.Releases[len(app.Releases)-1]
		if release.AssignType == "exclude" {
			continue
		}

		installed, detectErr := ms.apps.IsInstalled(ctx, release, ms.serverURL)
		if detectErr != nil {
			continue
		}

		switch {
		case release.Action == "install" && !installed:
			ms.performInstall(ctx, app, release)

		case release.Action == "install" && installed && app.AutoUpdate && ms.apps.SupportsUpgrade(ctx, release, ms.serverURL):
			ms.performWingetUpgrade(ctx, app, release)

		case release.Action == "uninstall" && installed:
			ms.performUninstall(ctx, app, release)
		}
	}

	final, finalErr := ms.refreshAssignedApplicationStates(ctx, assigned)
	if statusErr != nil || finalErr != nil {
		final.Errors += statusResult.Errors
		return final, fmt.Errorf("application reconciliation completed with errors")
	}

	return final, nil
}

func (ms *MainService) performInstall(ctx context.Context, app models.AssignedApp, release models.AssignedRelease) {
	repo := database.DefaultRepository()
	allowed, err := database.ShouldAttemptApp(release.ID)

	if err != nil || !allowed {
		return
	}

	now := time.Now().UTC()
	_ = repo.UpdateOperationState(ctx, release.ID, database.OperationInstalling, "")
	_ = repo.AppendAppEvent(ctx, database.AppEvent{ReleaseID: release.ID, AppID: app.ID, EventType: "install_started", Source: "reconcile", CreatedAt: now})
	ms.reportReleaseInstallState(release.ID, apps.ReleaseInstallStateInstalling, nil)
	err = ms.apps.Install(ctx, release, ms.serverURL)

	if err != nil {
		message := summarizeError(err)
		_ = database.RecordAppFailure(release.ID)
		_ = repo.UpdateOperationState(ctx, release.ID, database.OperationError, message)
		_ = repo.AppendAppEvent(ctx, database.AppEvent{ReleaseID: release.ID, AppID: app.ID, EventType: "install_failed", Source: "reconcile", Message: message, CreatedAt: time.Now().UTC()})
		ms.reportReleaseInstallState(release.ID, apps.ReleaseInstallStateError, nil)
		return
	}

	installed, detectErr := ms.apps.IsInstalled(ctx, release, ms.serverURL)
	if detectErr != nil || !installed {
		message := "installation could not be verified"
		_ = repo.UpdateOperationState(ctx, release.ID, database.OperationError, message)
		return
	}

	completed := time.Now().UTC()
	_ = database.ResetAppFailures(release.ID)
	_ = repo.MarkInstalledByClient(ctx, release.ID, completed)
	_ = repo.UpdateOperationState(ctx, release.ID, database.OperationIdle, "")
	_ = repo.AppendAppEvent(ctx, database.AppEvent{ReleaseID: release.ID, AppID: app.ID, EventType: "install_succeeded", Source: "reconcile", CreatedAt: completed})
	ms.reportReleaseInstallState(release.ID, apps.ReleaseInstallStateInstalled, nowUnixMilliPtr())
}

func (ms *MainService) performUninstall(ctx context.Context, app models.AssignedApp, release models.AssignedRelease) {
	repo := database.DefaultRepository()
	allowed, err := database.ShouldAttemptApp(release.ID)
	if err != nil || !allowed {
		return
	}
	now := time.Now().UTC()
	_ = repo.UpdateOperationState(ctx, release.ID, database.OperationUninstalling, "")
	_ = repo.AppendAppEvent(ctx, database.AppEvent{ReleaseID: release.ID, AppID: app.ID, EventType: "uninstall_started", Source: "reconcile", CreatedAt: now})
	if err := ms.apps.Uninstall(ctx, release, ms.serverURL); err != nil {
		message := summarizeError(err)
		_ = database.RecordAppFailure(release.ID)
		_ = repo.UpdateOperationState(ctx, release.ID, database.OperationError, message)
		_ = repo.AppendAppEvent(ctx, database.AppEvent{ReleaseID: release.ID, AppID: app.ID, EventType: "uninstall_failed", Source: "reconcile", Message: message, CreatedAt: time.Now().UTC()})
		ms.reportReleaseInstallState(release.ID, apps.ReleaseInstallStateError, nil)
		return
	}
	_ = database.ResetAppFailures(release.ID)
	_ = repo.UpdateOperationState(ctx, release.ID, database.OperationIdle, "")
	_ = repo.AppendAppEvent(ctx, database.AppEvent{ReleaseID: release.ID, AppID: app.ID, EventType: "uninstall_succeeded", Source: "reconcile", CreatedAt: time.Now().UTC()})
	ms.reportReleaseInstallState(release.ID, apps.ReleaseInstallStateUninstalled, nil)
}

func (ms *MainService) performWingetUpgrade(ctx context.Context, app models.AssignedApp, release models.AssignedRelease) {
	shouldCheck, err := database.ShouldCheckWinget(release.Winget.WingetID)
	if err != nil || !shouldCheck {
		return
	}
	repo := database.DefaultRepository()
	now := time.Now().UTC()
	_ = repo.UpdateOperationState(ctx, release.ID, database.OperationUpgrading, "")
	_ = repo.AppendAppEvent(ctx, database.AppEvent{ReleaseID: release.ID, AppID: app.ID, EventType: "upgrade_started", Source: "reconcile", CreatedAt: now})
	err = ms.apps.Upgrade(ctx, release, ms.serverURL)
	_ = database.UpdateWingetCheck(release.Winget.WingetID)
	if err != nil {
		message := summarizeError(err)
		_ = repo.UpdateOperationState(ctx, release.ID, database.OperationError, message)
		_ = repo.AppendAppEvent(ctx, database.AppEvent{ReleaseID: release.ID, AppID: app.ID, EventType: "upgrade_failed", Source: "reconcile", Message: message, CreatedAt: time.Now().UTC()})
		return
	}
	_ = repo.UpdateOperationState(ctx, release.ID, database.OperationIdle, "")
	_ = repo.AppendAppEvent(ctx, database.AppEvent{ReleaseID: release.ID, AppID: app.ID, EventType: "upgrade_succeeded", Source: "reconcile", CreatedAt: time.Now().UTC()})
}

func summarizeError(err error) string {
	if err == nil {
		return ""
	}
	message := err.Error()
	if len(message) > 500 {
		return message[:500]
	}
	return message
}

func (ms *MainService) RunSync(ctx context.Context, kind database.SyncKind) (synccoordinator.Result, error) {
	switch kind {
	case database.SyncDevice:
		result, err := ms.SyncComputerOnce(ctx)
		return synccoordinator.Result{Details: result}, err
	case database.SyncAppsStatus:
		result, err := ms.RefreshAssignedApplicationStates(ctx)
		status := database.SyncSuccess
		if result.Errors > 0 {
			status = database.SyncPartial
		}
		return synccoordinator.Result{Status: status, Details: result}, err
	case database.SyncAppsReconcile:
		result, err := ms.ReconcileAssignedApplications(ctx)
		status := database.SyncSuccess
		if result.Errors > 0 {
			status = database.SyncPartial
		}
		return synccoordinator.Result{Status: status, Details: result}, err
	case database.SyncFull:
		device, deviceErr := ms.SyncComputerOnce(ctx)
		appResult, appErr := ms.RefreshAssignedApplicationStates(ctx)
		details := map[string]any{"device": device, "applications": appResult}
		if deviceErr != nil || appErr != nil {
			details["device_error"] = errorString(deviceErr)
			details["applications_error"] = errorString(appErr)
			return synccoordinator.Result{Status: database.SyncPartial, Details: details}, fmt.Errorf("one or more synchronization parts failed")
		}
		return synccoordinator.Result{Status: database.SyncSuccess, Details: details}, nil
	default:
		return synccoordinator.Result{}, synccoordinator.ErrInvalidKind
	}
}

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return summarizeError(err)
}

func (ms *MainService) StartComputerSyncLoop(ctx context.Context, coordinator *synccoordinator.Coordinator) {
	trigger := func(trigger database.SyncTrigger) {
		if _, _, err := coordinator.Trigger(database.SyncDevice, trigger); err != nil {
			utils.Errorf("Computer sync trigger failed: %v", err)
		}
	}
	trigger(database.TriggerStartup)
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			trigger(database.TriggerAutomatic)
		case <-ctx.Done():
			return
		}
	}
}

func (ms *MainService) StartApplicationSyncLoop(ctx context.Context, coordinator *synccoordinator.Coordinator) {
	trigger := func(trigger database.SyncTrigger) {
		if _, _, err := coordinator.Trigger(database.SyncAppsReconcile, trigger); err != nil {
			utils.Errorf("Application sync trigger failed: %v", err)
		}
	}
	trigger(database.TriggerStartup)
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			trigger(database.TriggerAutomatic)
		case <-ctx.Done():
			return
		}
	}
}
