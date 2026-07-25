package sync

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"KiskaLE/RustDesk-ID/internal/database"

	"github.com/google/uuid"
)

var ErrInvalidKind = errors.New("unsupported synchronization kind")

type Result struct {
	Status  database.SyncStatus
	Details any
}

type Runner func(context.Context, database.SyncKind) (Result, error)

type Coordinator struct {
	ctx    context.Context
	repo   database.Repository
	runner Runner

	mu     sync.Mutex
	active map[database.SyncKind]string
}

func NewCoordinator(ctx context.Context, repo database.Repository, runner Runner) *Coordinator {
	return &Coordinator{ctx: ctx, repo: repo, runner: runner, active: make(map[database.SyncKind]string)}
}

func validKind(kind database.SyncKind) bool {
	switch kind {
	case database.SyncDevice, database.SyncAppsStatus, database.SyncAppsReconcile, database.SyncFull:
		return true
	default:
		return false
	}
}

func conflicts(a, b database.SyncKind) bool {
	if a == database.SyncFull || b == database.SyncFull {
		return true
	}
	if a == database.SyncDevice || b == database.SyncDevice {
		return a == b
	}
	return true // status and reconcile share detection/installation resources
}

// Trigger creates a queued run, or returns the existing conflicting run. The
// operation uses the service context and therefore survives UI disconnection.
func (c *Coordinator) Trigger(kind database.SyncKind, trigger database.SyncTrigger) (database.SyncRun, bool, error) {
	if !validKind(kind) {
		return database.SyncRun{}, false, ErrInvalidKind
	}
	c.mu.Lock()
	for activeKind, id := range c.active {
		if conflicts(kind, activeKind) {
			c.mu.Unlock()
			run, err := c.repo.GetSyncRun(context.Background(), id)
			return run, true, err
		}
	}
	now := time.Now().UTC()
	run := database.SyncRun{
		ID: uuid.NewString(), Kind: kind, Trigger: trigger,
		Status: database.SyncQueued, CreatedAt: now,
	}
	if err := c.repo.BeginSyncRun(context.Background(), run); err != nil {
		c.mu.Unlock()
		return database.SyncRun{}, false, fmt.Errorf("begin sync run: %w", err)
	}
	c.active[kind] = run.ID
	c.mu.Unlock()

	go c.execute(run)
	return run, false, nil
}

func (c *Coordinator) execute(run database.SyncRun) {
	defer func() {
		c.mu.Lock()
		delete(c.active, run.Kind)
		c.mu.Unlock()
	}()

	started := time.Now().UTC()
	run.Status = database.SyncRunning
	run.StartedAt = &started
	if err := c.repo.UpdateSyncRun(context.Background(), run); err != nil {
		return
	}

	result, err := c.runner(c.ctx, run.Kind)
	completed := time.Now().UTC()
	run.CompletedAt = &completed
	if result.Details != nil {
		if encoded, marshalErr := json.Marshal(result.Details); marshalErr == nil {
			run.DetailsJSON = string(encoded)
		}
	}
	if err != nil {
		run.ErrorMessage = err.Error()
		if result.Status == database.SyncPartial {
			run.Status = database.SyncPartial
		} else if errors.Is(err, context.Canceled) {
			run.Status = database.SyncInterrupted
		} else {
			run.Status = database.SyncError
		}
	} else if result.Status != "" {
		run.Status = result.Status
	} else {
		run.Status = database.SyncSuccess
	}
	_ = c.repo.UpdateSyncRun(context.Background(), run)
}

func (c *Coordinator) GetRun(ctx context.Context, id string) (database.SyncRun, error) {
	return c.repo.GetSyncRun(ctx, id)
}

func (c *Coordinator) IsRunning() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.active) != 0
}
