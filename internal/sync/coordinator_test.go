package sync

import (
	"context"
	"database/sql"
	"sync"
	"testing"
	"time"

	"KiskaLE/RustDesk-ID/internal/database"

	"github.com/stretchr/testify/require"
)

type memoryRepo struct {
	mu   sync.Mutex
	runs map[string]database.SyncRun
}

func newMemoryRepo() *memoryRepo { return &memoryRepo{runs: map[string]database.SyncRun{}} }
func (m *memoryRepo) BeginSyncRun(_ context.Context, run database.SyncRun) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.runs[run.ID] = run
	return nil
}
func (m *memoryRepo) UpdateSyncRun(_ context.Context, run database.SyncRun) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.runs[run.ID] = run
	return nil
}
func (m *memoryRepo) GetSyncRun(_ context.Context, id string) (database.SyncRun, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	run, ok := m.runs[id]
	if !ok {
		return run, sql.ErrNoRows
	}
	return run, nil
}
func (m *memoryRepo) GetLatestSyncRuns(context.Context) ([]database.SyncRun, error) { return nil, nil }
func (m *memoryRepo) InterruptActiveSyncRuns(context.Context, time.Time) error      { return nil }
func (m *memoryRepo) UpsertAssignedApps(context.Context, []database.ManagedAppState, time.Time) error {
	return nil
}
func (m *memoryRepo) UpdateDetectionState(context.Context, string, database.DetectionStatus, time.Time, string) error {
	return nil
}
func (m *memoryRepo) UpdateOperationState(context.Context, string, database.OperationStatus, string) error {
	return nil
}
func (m *memoryRepo) MarkInstalledByClient(context.Context, string, time.Time) error { return nil }
func (m *memoryRepo) ListManagedApps(context.Context) ([]database.ManagedAppState, error) {
	return nil, nil
}
func (m *memoryRepo) AppendAppEvent(context.Context, database.AppEvent) error { return nil }
func (m *memoryRepo) GetAppEvents(context.Context, string, int) ([]database.AppEvent, error) {
	return nil, nil
}

func TestCoordinatorDeduplicatesConflictingRuns(t *testing.T) {
	repo := newMemoryRepo()
	release := make(chan struct{})
	started := make(chan struct{})
	coordinator := NewCoordinator(context.Background(), repo, func(context.Context, database.SyncKind) (Result, error) {
		close(started)
		<-release
		return Result{}, nil
	})
	first, duplicate, err := coordinator.Trigger(database.SyncAppsStatus, database.TriggerManual)
	require.NoError(t, err)
	require.False(t, duplicate)
	<-started
	second, duplicate, err := coordinator.Trigger(database.SyncAppsReconcile, database.TriggerAutomatic)
	require.NoError(t, err)
	require.True(t, duplicate)
	require.Equal(t, first.ID, second.ID)
	close(release)
	require.Eventually(t, func() bool {
		run, _ := repo.GetSyncRun(context.Background(), first.ID)
		return run.Status == database.SyncSuccess
	}, time.Second, time.Millisecond)
}

func TestDeviceAndAppsMayRunTogether(t *testing.T) {
	repo := newMemoryRepo()
	release := make(chan struct{})
	started := make(chan struct{}, 2)
	coordinator := NewCoordinator(context.Background(), repo, func(context.Context, database.SyncKind) (Result, error) {
		started <- struct{}{}
		<-release
		return Result{}, nil
	})
	_, duplicate, err := coordinator.Trigger(database.SyncDevice, database.TriggerAutomatic)
	require.NoError(t, err)
	require.False(t, duplicate)
	_, duplicate, err = coordinator.Trigger(database.SyncAppsStatus, database.TriggerAutomatic)
	require.NoError(t, err)
	require.False(t, duplicate)
	<-started
	<-started
	close(release)
}
