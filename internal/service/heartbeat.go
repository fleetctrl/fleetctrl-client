package service

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"KiskaLE/RustDesk-ID/internal/utils"
)

// Heartbeats bypass the sync coordinator so inventory and application jobs
// cannot delay presence reporting. Each attempt is bounded and cancellable.
func (ms *MainService) HeartbeatOnce(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ms.serverURL+"/computer/heartbeat", nil)
	if err != nil {
		return err
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("send heartbeat: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("heartbeat returned %s", res.Status)
	}
	return nil
}

func (ms *MainService) StartHeartbeatLoop(ctx context.Context) {
	ms.runHeartbeatLoop(ctx, time.Minute)
}

func (ms *MainService) runHeartbeatLoop(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return
		}
		if err := ms.HeartbeatOnce(ctx); err != nil && ctx.Err() == nil {
			utils.Errorf("Heartbeat failed: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
