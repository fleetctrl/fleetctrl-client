package main

import (
	"context"
	"fmt"
	"strings"

	"KiskaLE/RustDesk-ID/internal/database"
	ipcclient "KiskaLE/RustDesk-ID/internal/ipc/client"
	"KiskaLE/RustDesk-ID/internal/ipc/protocol"
)

type pipeClient interface {
	Call(context.Context, string, any, any) error
}

type UIBackend struct {
	ctx context.Context
	ipc pipeClient
}

func NewUIBackend() *UIBackend {
	return &UIBackend{ctx: context.Background(), ipc: ipcclient.New()}
}

func (b *UIBackend) Startup(ctx context.Context) { b.ctx = ctx }

func (b *UIBackend) GetOverview() (protocol.Overview, error) {
	var result protocol.Overview
	err := b.ipc.Call(b.ctx, "get_overview", struct{}{}, &result)
	if err != nil {
		return result, friendlyIPCError(err)
	}
	return result, nil
}

func (b *UIBackend) ListApplications() ([]database.ManagedAppState, error) {
	var result []database.ManagedAppState
	err := b.ipc.Call(b.ctx, "list_apps", struct{}{}, &result)
	if err != nil {
		return nil, friendlyIPCError(err)
	}
	return result, nil
}

func (b *UIBackend) TriggerSync(kind string) (database.SyncRun, error) {
	requested := database.SyncKind(kind)
	if requested != database.SyncFull && requested != database.SyncDevice && requested != database.SyncAppsStatus {
		return database.SyncRun{}, fmt.Errorf("Nepodporovaný typ synchronizace.")
	}
	var result database.SyncRun
	err := b.ipc.Call(b.ctx, "trigger_sync", protocol.TriggerSyncParams{Kind: requested}, &result)
	if err != nil {
		return result, friendlyIPCError(err)
	}
	return result, nil
}

func (b *UIBackend) GetSyncRun(id string) (database.SyncRun, error) {
	if strings.TrimSpace(id) == "" || len(id) > 100 {
		return database.SyncRun{}, fmt.Errorf("Neplatný identifikátor synchronizace.")
	}
	var result database.SyncRun
	err := b.ipc.Call(b.ctx, "get_sync_run", protocol.GetSyncRunParams{ID: id}, &result)
	if err != nil {
		return result, friendlyIPCError(err)
	}
	return result, nil
}

func (b *UIBackend) GetApplicationEvents(releaseID string, limit int) ([]database.AppEvent, error) {
	if strings.TrimSpace(releaseID) == "" || len(releaseID) > 200 {
		return nil, fmt.Errorf("Neplatný identifikátor aplikace.")
	}
	if limit < 1 || limit > 100 {
		limit = 20
	}
	var result []database.AppEvent
	err := b.ipc.Call(b.ctx, "get_app_events", protocol.AppEventsParams{ReleaseID: releaseID, Limit: limit}, &result)
	if err != nil {
		return nil, friendlyIPCError(err)
	}
	return result, nil
}

func friendlyIPCError(err error) error {
	message := err.Error()
	switch {
	case strings.Contains(message, string(protocol.UnsupportedVersion)):
		return fmt.Errorf("UI není kompatibilní s nainstalovanou verzí služby (%s).", protocol.UnsupportedVersion)
	case strings.Contains(message, string(protocol.DatabaseUnavailable)):
		return fmt.Errorf("Lokální data jsou dočasně nedostupná (%s).", protocol.DatabaseUnavailable)
	case strings.Contains(message, "service unavailable"):
		return fmt.Errorf("Služba FleetCtrl není dostupná (SERVICE_NOT_READY).")
	default:
		return fmt.Errorf("Požadavek se nezdařil: %s", message)
	}
}
