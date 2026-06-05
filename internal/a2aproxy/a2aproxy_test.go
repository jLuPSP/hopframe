package a2aproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/jlupsp/hopframe/internal/emitter"
	"github.com/jlupsp/hopframe/internal/pipeline"
	"github.com/jlupsp/hopframe/pkg/a2a"
	"github.com/jlupsp/hopframe/pkg/detect"
	"github.com/jlupsp/hopframe/pkg/event"
	"github.com/jlupsp/hopframe/pkg/ruleset"
)

type captureSink struct {
	mu     sync.Mutex
	events []*event.Event
}

func (c *captureSink) Deliver(_ context.Context, ev *event.Event) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, ev)
	return nil
}
func (c *captureSink) Close() error { return nil }
func (c *captureSink) snapshot() []*event.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]*event.Event, len(c.events))
	copy(out, c.events)
	return out
}

func waitForEvents(cap *captureSink, n int, timeout time.Duration) []*event.Event {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if got := cap.snapshot(); len(got) >= n {
			return got
		}
		time.Sleep(20 * time.Millisecond)
	}
	return cap.snapshot()
}

func setup(t *testing.T) (*Server, *captureSink, *httptest.Server, func()) {
	t.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/agent.json" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"name":"safe-agent","description":"plain","skills":[{"id":"x","name":"x"}]}`))
			return
		}
		body, _ := io.ReadAll(r.Body)
		env, err := a2a.ParseTask(body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		resp := a2a.TaskEnvelope{JSONRPC: a2a.JSONRPCVersion, ID: env.ID}
		resp.Result = json.RawMessage(`{"status":"ok"}`)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	rs, err := ruleset.LoadDir("../../content")
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	cap := &captureSink{}
	em := emitter.New(cap, 32)
	pipe := &pipeline.Pipeline{
		SensorID:     "a2a-test",
		Detectors:    []detect.Detector{rs},
		ModeResolver: rs.HighestMode,
	}
	srv, err := New(Options{
		Pipeline: pipe, Emitter: em,
		UpstreamURL: upstream.URL, Timeout: 5 * time.Second, FailOpen: true,
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	return srv, cap, upstream, func() {
		_ = em.Close()
		upstream.Close()
	}
}

func TestA2ATaskFlowsThrough(t *testing.T) {
	srv, cap, _, cleanup := setup(t)
	defer cleanup()

	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tasks/send","params":{"task":"benign"}}`)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	req.Header.Set("X-Hopframe-Agent-Run-Id", "run-A2A-1")
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("X-Hopframe-Agent-Run-Id") != "run-A2A-1" {
		t.Fatalf("expected run id in response header")
	}
	events := waitForEvents(cap, 2, time.Second)
	if len(events) < 2 {
		t.Fatalf("expected inbound+outbound events, got %d", len(events))
	}
	for _, ev := range events {
		if ev.Protocol != event.ProtocolA2A {
			t.Fatalf("expected a2a protocol, got %q", ev.Protocol)
		}
		if ev.AgentRunID != "run-A2A-1" {
			t.Fatalf("agent run id = %q", ev.AgentRunID)
		}
	}
}

func TestA2AAgentCardValidationPasses(t *testing.T) {
	srv, cap, _, cleanup := setup(t)
	defer cleanup()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/.well-known/agent.json", nil)
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	events := waitForEvents(cap, 1, time.Second)
	if len(events) == 0 {
		t.Fatalf("expected card event")
	}
	if events[0].Message.Method != "agent.card" {
		t.Fatalf("expected agent.card event, got %q", events[0].Message.Method)
	}
}

func TestA2AHealthz(t *testing.T) {
	srv, _, _, cleanup := setup(t)
	defer cleanup()
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
}
