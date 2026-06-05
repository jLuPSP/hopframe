package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jlupsp/hopframe/pkg/detect"
	"github.com/jlupsp/hopframe/pkg/policy"
)

func TestEngineSwapAndResolve(t *testing.T) {
	e := NewEngine()
	if e.Snapshot() == nil {
		t.Fatal("snapshot nil")
	}
	if e.Snapshot().Version != 0 {
		t.Errorf("initial version = %d, want 0", e.Snapshot().Version)
	}

	mode, _ := e.Resolve(policy.EventContext{}, &detect.Verdict{}, detect.ModeMonitor)
	if mode != detect.ModeMonitor {
		t.Fatalf("default mode = %q, want monitor", mode)
	}

	snap := &Snapshot{
		Version: 5,
		Policies: []policy.Policy{
			{
				ID: "p", Name: "block-anything", Enabled: true,
				Disposition: policy.Disposition{Mode: detect.ModeBlock},
			},
		},
	}
	e.Swap(snap)
	if e.Snapshot().Version != 5 {
		t.Fatalf("version after swap = %d, want 5", e.Snapshot().Version)
	}
	mode, _ = e.Resolve(policy.EventContext{}, &detect.Verdict{}, detect.ModeMonitor)
	if mode != detect.ModeBlock {
		t.Fatalf("post-swap mode = %q, want block", mode)
	}
}

func writeTestJSON(t *testing.T, w http.ResponseWriter, v any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Fatalf("encode: %v", err)
	}
}

func TestClientFetchActiveAndHeartbeat(t *testing.T) {
	policies := []policy.Policy{
		{ID: "p1", Name: "warn", Enabled: true, Disposition: policy.Disposition{Mode: detect.ModeWarn}},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/policies/active", func(w http.ResponseWriter, _ *http.Request) {
		writeTestJSON(t, w, map[string]any{
			"policies": policies,
			"version":  int64(7),
		})
	})
	mux.HandleFunc("/v1/sensors/heartbeat", func(w http.ResponseWriter, _ *http.Request) {
		writeTestJSON(t, w, map[string]any{
			"ack":             true,
			"policy_version":  int64(7),
			"content_version": "abc123",
		})
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	c := &Client{BaseURL: ts.URL, Token: "t", SensorID: "s1"}

	ctx := context.Background()
	snap, err := c.FetchActive(ctx)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if snap.Version != 7 {
		t.Errorf("version = %d, want 7", snap.Version)
	}
	if len(snap.Policies) != 1 || snap.Policies[0].ID != "p1" {
		t.Errorf("policies = %+v", snap.Policies)
	}

	ack, err := c.Heartbeat(ctx, HeartbeatBody{SensorID: "s1", PolicyVersion: 7})
	if err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	if !ack.Ack || ack.PolicyVersion != 7 || ack.ContentVersion != "abc123" {
		t.Fatalf("ack = %+v", ack)
	}
}

func TestLoopReFetchesOnVersionMismatch(t *testing.T) {
	var version atomic.Int64
	version.Store(1)
	policies := func() []policy.Policy {
		return []policy.Policy{
			{
				ID:          "p1",
				Name:        fmt.Sprintf("v%d", version.Load()),
				Enabled:     true,
				Disposition: policy.Disposition{Mode: detect.ModeWarn},
			},
		}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/policies/active", func(w http.ResponseWriter, _ *http.Request) {
		writeTestJSON(t, w, map[string]any{
			"policies": policies(),
			"version":  version.Load(),
		})
	})
	mux.HandleFunc("/v1/sensors/heartbeat", func(w http.ResponseWriter, _ *http.Request) {
		writeTestJSON(t, w, map[string]any{
			"ack":            true,
			"policy_version": version.Load(),
		})
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	engine := NewEngine()
	c := &Client{BaseURL: ts.URL}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	swaps := make(chan *Snapshot, 4)
	go c.Loop(ctx, engine, 30*time.Millisecond, func() HeartbeatBody {
		return HeartbeatBody{SensorID: "s"}
	}, Hooks{
		OnSwap: func(s *Snapshot) { swaps <- s },
	})

	select {
	case s := <-swaps:
		if s.Version != 1 {
			t.Fatalf("first snapshot version = %d, want 1", s.Version)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no initial swap")
	}

	version.Store(2)

	select {
	case s := <-swaps:
		if s.Version != 2 {
			t.Fatalf("second snapshot version = %d, want 2", s.Version)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no refetch after version bump")
	}
}
