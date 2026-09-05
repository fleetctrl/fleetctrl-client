package service

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHeartbeatRequest(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusUnauthorized, http.StatusInternalServerError} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.URL.Path != "/computer/heartbeat" {
					t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
				}
				body, _ := io.ReadAll(r.Body)
				if len(body) != 0 {
					t.Errorf("heartbeat must not send inventory: %s", body)
				}
				w.WriteHeader(status)
			}))
			defer server.Close()
			ms := &MainService{serverURL: server.URL}
			err := ms.HeartbeatOnce(context.Background())
			if (err == nil) != (status == http.StatusOK) {
				t.Fatalf("status %d: %v", status, err)
			}
		})
	}
}

func TestHeartbeatLoopRetriesAndStops(t *testing.T) {
	requests := make(chan struct{}, 10)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- struct{}{}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	ms := &MainService{serverURL: server.URL}
	go func() { defer close(done); ms.runHeartbeatLoop(ctx, 10*time.Millisecond) }()
	for range 2 {
		select {
		case <-requests:
		case <-time.After(2 * time.Second):
			t.Fatal("missing initial heartbeat or retry")
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("heartbeat loop did not stop")
	}
}

func TestHeartbeatCancellation(t *testing.T) {
	started := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	ms := &MainService{serverURL: server.URL}
	go func() { done <- ms.HeartbeatOnce(ctx) }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("request did not start")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected cancellation error")
		}
	case <-time.After(time.Second):
		t.Fatal("request ignored cancellation")
	}
}
