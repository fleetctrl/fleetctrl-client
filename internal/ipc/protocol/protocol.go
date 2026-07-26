package protocol

import (
	"encoding/json"
	"time"

	"KiskaLE/RustDesk-ID/internal/database"
)

const (
	Version    = 1
	PipeName   = `\\.\pipe\fleetctrl-client-ui-v1`
	MaxMessage = 1 << 20
	MaxClients = 8
)

type ErrorCode string

const (
	ServiceNotReady     ErrorCode = "SERVICE_NOT_READY"
	SyncAlreadyRunning  ErrorCode = "SYNC_ALREADY_RUNNING"
	InvalidRequest      ErrorCode = "INVALID_REQUEST"
	UnsupportedVersion  ErrorCode = "UNSUPPORTED_VERSION"
	DatabaseUnavailable ErrorCode = "DATABASE_UNAVAILABLE"
	ServerUnavailable   ErrorCode = "SERVER_UNAVAILABLE"
	InternalError       ErrorCode = "INTERNAL_ERROR"
)

type Request struct {
	Version   int             `json:"version"`
	RequestID string          `json:"request_id"`
	Method    string          `json:"method"`
	Params    json.RawMessage `json:"params,omitempty"`
}

type Response struct {
	Version   int    `json:"version"`
	RequestID string `json:"request_id"`
	OK        bool   `json:"ok"`
	Result    any    `json:"result,omitempty"`
	Error     *Error `json:"error,omitempty"`
}

type Error struct {
	Code    ErrorCode `json:"code"`
	Message string    `json:"message"`
}

type Ping struct {
	ServiceVersion  string `json:"service_version"`
	ProtocolVersion int    `json:"protocol_version"`
}

type Overview struct {
	ServiceAvailable bool              `json:"service_available"`
	ServiceVersion   string            `json:"service_version"`
	ServerURL        string            `json:"server_url"`
	CurrentRun       *database.SyncRun `json:"current_run,omitempty"`
	LastAttempt      *database.SyncRun `json:"last_attempt,omitempty"`
	LastSuccess      *database.SyncRun `json:"last_success,omitempty"`
	LastError        *database.SyncRun `json:"last_error,omitempty"`
	CheckedAt        time.Time         `json:"checked_at"`
}

type TriggerSyncParams struct {
	Kind database.SyncKind `json:"kind"`
}

type GetSyncRunParams struct {
	ID string `json:"id"`
}

type AppEventsParams struct {
	ReleaseID string `json:"release_id"`
	Limit     int    `json:"limit"`
}
