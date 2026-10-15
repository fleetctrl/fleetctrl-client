package database

import (
	"context"
	"time"
)

type DetectionStatus string
type OperationStatus string
type SyncKind string
type SyncTrigger string
type SyncStatus string
type FailedOperation string

const (
	DetectionUnknown      DetectionStatus = "unknown"
	DetectionInstalled    DetectionStatus = "installed"
	DetectionNotInstalled DetectionStatus = "not_installed"

	OperationIdle         OperationStatus = "idle"
	OperationInstalling   OperationStatus = "installing"
	OperationUninstalling OperationStatus = "uninstalling"
	OperationUpgrading    OperationStatus = "upgrading"
	OperationError        OperationStatus = "error"

	SyncDevice        SyncKind = "device"
	SyncAppsStatus    SyncKind = "apps_status"
	SyncAppsReconcile SyncKind = "apps_reconcile"
	SyncFull          SyncKind = "full"

	TriggerAutomatic SyncTrigger = "automatic"
	TriggerManual    SyncTrigger = "manual"
	TriggerStartup   SyncTrigger = "startup"

	SyncQueued      SyncStatus = "queued"
	SyncRunning     SyncStatus = "running"
	SyncSuccess     SyncStatus = "success"
	SyncPartial     SyncStatus = "partial"
	SyncError       SyncStatus = "error"
	SyncInterrupted SyncStatus = "interrupted"

	FailedInstall   FailedOperation = "install"
	FailedUninstall FailedOperation = "uninstall"
	FailedUpdate    FailedOperation = "update"
)

// OperationFailure is the last failed install, uninstall or update of a release. It is kept until an
// operation succeeds, the assignment changes, or detection shows the problem no longer applies, so the
// hub keeps seeing the error between retries instead of only in the cycle in which it happened.
type OperationFailure struct {
	Operation FailedOperation
	Message   string
}

// ResolvedBy reports whether detection shows the failure no longer applies: a failed install is resolved
// once the app is installed (for example manually), and a failed uninstall or update once it is gone.
func (f OperationFailure) ResolvedBy(status DetectionStatus) bool {
	switch f.Operation {
	case FailedInstall:
		return status == DetectionInstalled
	case FailedUninstall, FailedUpdate:
		return status == DetectionNotInstalled
	default:
		return true
	}
}

type ManagedAppState struct {
	ReleaseID            string          `json:"release_id"`
	AppID                string          `json:"app_id"`
	DisplayName          string          `json:"display_name"`
	Publisher            string          `json:"publisher,omitempty"`
	Version              string          `json:"version,omitempty"`
	InstallerType        string          `json:"installer_type"`
	WingetID             string          `json:"winget_id,omitempty"`
	AssignType           string          `json:"assign_type"`
	DesiredAction        string          `json:"desired_action"`
	DetectedStatus       DetectionStatus `json:"detected_status"`
	OperationStatus      OperationStatus `json:"operation_status"`
	FirstSeenInstalledAt *time.Time      `json:"first_seen_installed_at,omitempty"`
	InstalledByClientAt  *time.Time      `json:"installed_by_client_at,omitempty"`
	LastCheckedAt        *time.Time      `json:"last_checked_at,omitempty"`
	LastSeenOnServerAt   time.Time       `json:"last_seen_on_server_at"`
	AssignmentRemovedAt  *time.Time      `json:"assignment_removed_at,omitempty"`
	LastError            string          `json:"last_error,omitempty"`
	CreatedAt            time.Time       `json:"created_at"`
	UpdatedAt            time.Time       `json:"updated_at"`
}

type AppEvent struct {
	ID          int64     `json:"id"`
	ReleaseID   string    `json:"release_id"`
	AppID       string    `json:"app_id"`
	EventType   string    `json:"event_type"`
	Source      string    `json:"source"`
	Message     string    `json:"message,omitempty"`
	DetailsJSON string    `json:"details_json,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

type SyncRun struct {
	ID           string      `json:"id"`
	Kind         SyncKind    `json:"kind"`
	Trigger      SyncTrigger `json:"trigger"`
	Status       SyncStatus  `json:"status"`
	StartedAt    *time.Time  `json:"started_at,omitempty"`
	CompletedAt  *time.Time  `json:"completed_at,omitempty"`
	ErrorMessage string      `json:"error_message,omitempty"`
	DetailsJSON  string      `json:"details_json,omitempty"`
	CreatedAt    time.Time   `json:"created_at"`
}

type Repository interface {
	BeginSyncRun(context.Context, SyncRun) error
	UpdateSyncRun(context.Context, SyncRun) error
	GetSyncRun(context.Context, string) (SyncRun, error)
	GetLatestSyncRuns(context.Context) ([]SyncRun, error)
	InterruptActiveSyncRuns(context.Context, time.Time) error
	PruneSyncRuns(context.Context) error
	PruneAppEvents(context.Context) error
	UpsertAssignedApps(context.Context, []ManagedAppState, time.Time) error
	UpdateDetectionState(context.Context, string, DetectionStatus, time.Time, string) error
	UpdateOperationState(context.Context, string, OperationStatus, string) error
	MarkInstalledByClient(context.Context, string, time.Time) error
	ListManagedApps(context.Context) ([]ManagedAppState, error)
	AppendAppEvent(context.Context, AppEvent) error
	GetAppEvents(context.Context, string, int) ([]AppEvent, error)
}
