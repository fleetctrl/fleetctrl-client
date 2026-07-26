package protocol

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"KiskaLE/RustDesk-ID/internal/database"
	synccoordinator "KiskaLE/RustDesk-ID/internal/sync"

	"github.com/stretchr/testify/require"
)

type handlerRepo struct {
	apps []database.ManagedAppState
	runs []database.SyncRun
}

func (r *handlerRepo) BeginSyncRun(context.Context, database.SyncRun) error  { return nil }
func (r *handlerRepo) UpdateSyncRun(context.Context, database.SyncRun) error { return nil }
func (r *handlerRepo) GetSyncRun(context.Context, string) (database.SyncRun, error) {
	if len(r.runs) > 0 {
		return r.runs[0], nil
	}
	return database.SyncRun{}, nil
}
func (r *handlerRepo) GetLatestSyncRuns(context.Context) ([]database.SyncRun, error) {
	return r.runs, nil
}
func (r *handlerRepo) InterruptActiveSyncRuns(context.Context, time.Time) error { return nil }
func (r *handlerRepo) UpsertAssignedApps(context.Context, []database.ManagedAppState, time.Time) error {
	return nil
}
func (r *handlerRepo) UpdateDetectionState(context.Context, string, database.DetectionStatus, time.Time, string) error {
	return nil
}
func (r *handlerRepo) UpdateOperationState(context.Context, string, database.OperationStatus, string) error {
	return nil
}
func (r *handlerRepo) MarkInstalledByClient(context.Context, string, time.Time) error { return nil }
func (r *handlerRepo) ListManagedApps(context.Context) ([]database.ManagedAppState, error) {
	return r.apps, nil
}
func (r *handlerRepo) AppendAppEvent(context.Context, database.AppEvent) error { return nil }
func (r *handlerRepo) GetAppEvents(context.Context, string, int) ([]database.AppEvent, error) {
	return nil, nil
}

func TestHandlerRejectsUnsupportedVersionAndUnsafeSyncKind(t *testing.T) {
	repo := &handlerRepo{}
	coordinator := synccoordinator.NewCoordinator(context.Background(), repo, func(context.Context, database.SyncKind) (synccoordinator.Result, error) {
		return synccoordinator.Result{}, nil
	})
	handler := &Handler{Repository: repo, Coordinator: coordinator}

	response := handler.Handle(context.Background(), Request{Version: 99, RequestID: "one", Method: "ping"})
	require.False(t, response.OK)
	require.Equal(t, UnsupportedVersion, response.Error.Code)

	params, err := json.Marshal(TriggerSyncParams{Kind: database.SyncAppsReconcile})
	require.NoError(t, err)
	response = handler.Handle(context.Background(), Request{Version: Version, RequestID: "two", Method: "trigger_sync", Params: params})
	require.False(t, response.OK)
	require.Equal(t, InvalidRequest, response.Error.Code)
}

func TestOverviewNeverExposesServerCredentialsOrPath(t *testing.T) {
	now := time.Now().UTC()
	repo := &handlerRepo{runs: []database.SyncRun{{ID: "run", Status: database.SyncSuccess, CreatedAt: now}}}
	handler := &Handler{Repository: repo, ServerURL: "https://user:secret@fleet.example.test/api/private?token=x"}
	response := handler.Handle(context.Background(), Request{Version: Version, RequestID: "one", Method: "get_overview"})
	require.True(t, response.OK)
	overview := response.Result.(Overview)
	require.Equal(t, "https://fleet.example.test", overview.ServerURL)
	require.NotNil(t, overview.LastSuccess)
}
