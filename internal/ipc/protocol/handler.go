package protocol

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"time"

	consts "KiskaLE/RustDesk-ID/internal/const"
	"KiskaLE/RustDesk-ID/internal/database"
	synccoordinator "KiskaLE/RustDesk-ID/internal/sync"
)

type Handler struct {
	Repository  database.Repository
	Coordinator *synccoordinator.Coordinator
	ServerURL   string
}

func (h *Handler) Handle(ctx context.Context, request Request) Response {
	response := Response{Version: Version, RequestID: request.RequestID}
	fail := func(code ErrorCode, message string) Response {
		response.Error = &Error{Code: code, Message: message}
		return response
	}
	if request.Version != Version {
		return fail(UnsupportedVersion, "Nekompatibilní verze rozhraní služby.")
	}
	if strings.TrimSpace(request.RequestID) == "" {
		return fail(InvalidRequest, "Chybí identifikátor požadavku.")
	}
	switch request.Method {
	case "ping":
		response.OK = true
		response.Result = Ping{ServiceVersion: consts.Version, ProtocolVersion: Version}
	case "get_overview":
		runs, err := h.Repository.GetLatestSyncRuns(ctx)
		if err != nil {
			return fail(DatabaseUnavailable, "Stav synchronizace nyní nelze načíst.")
		}
		overview := Overview{ServiceAvailable: true, ServiceVersion: consts.Version, ServerURL: publicServerURL(h.ServerURL), CheckedAt: time.Now().UTC()}
		for i := range runs {
			run := runs[i]
			if overview.LastAttempt == nil {
				overview.LastAttempt = &run
			}
			if overview.CurrentRun == nil && (run.Status == database.SyncQueued || run.Status == database.SyncRunning) {
				overview.CurrentRun = &run
			}
			if overview.LastSuccess == nil && run.Status == database.SyncSuccess {
				overview.LastSuccess = &run
			}
			if overview.LastError == nil && (run.Status == database.SyncError || run.Status == database.SyncPartial) {
				overview.LastError = &run
			}
		}
		response.OK, response.Result = true, overview
	case "list_apps":
		apps, err := h.Repository.ListManagedApps(ctx)
		if err != nil {
			return fail(DatabaseUnavailable, "Seznam aplikací nyní nelze načíst.")
		}
		response.OK, response.Result = true, apps
	case "get_app_events":
		var params AppEventsParams
		if json.Unmarshal(request.Params, &params) != nil || strings.TrimSpace(params.ReleaseID) == "" {
			return fail(InvalidRequest, "Neplatný požadavek na historii aplikace.")
		}
		events, err := h.Repository.GetAppEvents(ctx, params.ReleaseID, params.Limit)
		if err != nil {
			return fail(DatabaseUnavailable, "Historii aplikace nyní nelze načíst.")
		}
		response.OK, response.Result = true, events
	case "trigger_sync":
		var params TriggerSyncParams
		if json.Unmarshal(request.Params, &params) != nil || (params.Kind != database.SyncFull && params.Kind != database.SyncDevice && params.Kind != database.SyncAppsStatus) {
			return fail(InvalidRequest, "Tento typ synchronizace nelze ručně spustit.")
		}
		run, duplicate, err := h.Coordinator.Trigger(params.Kind, database.TriggerManual)
		if err != nil {
			return fail(InternalError, "Synchronizaci se nepodařilo zařadit.")
		}
		response.OK, response.Result = true, run
		if duplicate {
			// Returning the existing run is intentional and keeps repeated clicks idempotent.
			response.Result = run
		}
	case "get_sync_run":
		var params GetSyncRunParams
		if json.Unmarshal(request.Params, &params) != nil || strings.TrimSpace(params.ID) == "" {
			return fail(InvalidRequest, "Neplatný identifikátor synchronizace.")
		}
		run, err := h.Coordinator.GetRun(ctx, params.ID)
		if errors.Is(err, sql.ErrNoRows) {
			return fail(InvalidRequest, "Synchronizace nebyla nalezena.")
		}
		if err != nil {
			return fail(DatabaseUnavailable, "Stav synchronizace nyní nelze načíst.")
		}
		response.OK, response.Result = true, run
	default:
		return fail(InvalidRequest, "Neznámá operace.")
	}
	return response
}

func publicServerURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return ""
	}
	return parsed.Scheme + "://" + parsed.Host
}
