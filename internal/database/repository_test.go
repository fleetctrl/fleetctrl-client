package database

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func newTestRepository(t *testing.T) *SQLiteRepository {
	t.Helper()
	repo, err := Open(filepath.Join(t.TempDir(), "client.db"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, repo.Close()) })
	return repo
}

func TestMigrationsApplyToEmptyAndExistingDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.db")
	repo, err := Open(path)
	require.NoError(t, err)
	require.NoError(t, repo.Close())

	repo, err = Open(path)
	require.NoError(t, err)
	defer repo.Close()

	var count int
	require.NoError(t, repo.db.QueryRow("SELECT COUNT(*) FROM schema_migrations").Scan(&count))
	require.Equal(t, len(migrations), count)
}

func TestAssignedAppsPreserveInstallAtAndRecordOnlyChanges(t *testing.T) {
	repo := newTestRepository(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	app := ManagedAppState{
		ReleaseID: "release-1", AppID: "app-1", DisplayName: "Editor",
		Publisher: "Fleet", Version: "1.2", InstallerType: "winget",
		WingetID: "Fleet.Editor", AssignType: "include", DesiredAction: "install",
	}

	require.NoError(t, repo.UpsertAssignedApps(ctx, []ManagedAppState{app}, now))
	require.NoError(t, repo.UpdateDetectionState(ctx, app.ReleaseID, DetectionInstalled, now, ""))
	require.NoError(t, repo.MarkInstalledByClient(ctx, app.ReleaseID, now))
	require.NoError(t, repo.UpsertAssignedApps(ctx, []ManagedAppState{app}, now.Add(time.Minute)))
	require.NoError(t, repo.UpdateDetectionState(ctx, app.ReleaseID, DetectionInstalled, now.Add(time.Minute), ""))

	apps, err := repo.ListManagedApps(ctx)
	require.NoError(t, err)
	require.Len(t, apps, 1)
	require.NotNil(t, apps[0].InstalledByClientAt)
	require.Equal(t, now, apps[0].InstalledByClientAt.UTC())

	events, err := repo.GetAppEvents(ctx, app.ReleaseID, 20)
	require.NoError(t, err)
	require.Len(t, events, 2) // assigned + first installed transition
}

func TestRemovedAssignmentIsSoftDeletedAndRunIsInterrupted(t *testing.T) {
	repo := newTestRepository(t)
	ctx := context.Background()
	now := time.Now().UTC()
	app := ManagedAppState{
		ReleaseID: "release-1", AppID: "app-1", DisplayName: "Editor",
		InstallerType: "win32", AssignType: "include", DesiredAction: "install",
	}
	require.NoError(t, repo.UpsertAssignedApps(ctx, []ManagedAppState{app}, now))
	require.NoError(t, repo.UpsertAssignedApps(ctx, nil, now.Add(time.Minute)))
	apps, err := repo.ListManagedApps(ctx)
	require.NoError(t, err)
	require.Empty(t, apps)

	run := SyncRun{ID: "run-1", Kind: SyncFull, Trigger: TriggerManual, Status: SyncRunning, CreatedAt: now}
	require.NoError(t, repo.BeginSyncRun(ctx, run))
	require.NoError(t, repo.InterruptActiveSyncRuns(ctx, now.Add(time.Minute)))
	got, err := repo.GetSyncRun(ctx, run.ID)
	require.NoError(t, err)
	require.Equal(t, SyncInterrupted, got.Status)
	require.NotNil(t, got.CompletedAt)
}
