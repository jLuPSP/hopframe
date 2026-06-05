package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jlupsp/hopframe/internal/emitter"
	"github.com/jlupsp/hopframe/internal/pipeline"
	"github.com/jlupsp/hopframe/pkg/detect"
	"github.com/jlupsp/hopframe/pkg/event"
	"github.com/jlupsp/hopframe/pkg/mcp"
	"github.com/jlupsp/hopframe/pkg/ruleset"
)

func startUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		env, err := mcp.Parse(body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		resp := mcp.Envelope{JSONRPC: mcp.JSONRPCVersion, ID: env.ID}
		switch env.Method {
		case mcp.MethodToolsCall:
			resp.Result = json.RawMessage(`{"content":[{"type":"text","text":"ok"}]}`)
		case mcp.MethodToolsList:
			resp.Result = json.RawMessage(`{"tools":[{"name":"echo","description":"echo back input"}]}`)
		default:
			resp.Result = json.RawMessage(`{}`)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
}

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

func setupProxy(t *testing.T, upstreamURL string) (*Server, *captureSink, *emitter.Emitter, func()) {
	t.Helper()
	rs, err := ruleset.LoadDir("../../content")
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	cap := &captureSink{}
	em := emitter.New(cap, 32)
	pipe := &pipeline.Pipeline{
		SensorID:     "proxy-test",
		Detectors:    []detect.Detector{rs},
		ModeResolver: rs.HighestMode,
	}
	srv, err := New(Options{
		Pipeline:    pipe,
		Emitter:     em,
		UpstreamURL: upstreamURL,
		BasePath:    "/mcp",
		Timeout:     5 * time.Second,
		FailOpen:    true,
	})
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}
	return srv, cap, em, func() {
		_ = em.Close()
	}
}

func waitForEvents(s *captureSink, n int, timeout time.Duration) []*event.Event {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if got := s.snapshot(); len(got) >= n {
			return got
		}
		time.Sleep(20 * time.Millisecond)
	}
	return s.snapshot()
}

func TestProxyForwardsBenign(t *testing.T) {
	upstream := startUpstream(t)
	defer upstream.Close()

	srv, cap, _, cleanup := setupProxy(t, upstream.URL)
	defer cleanup()

	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hello"}}}`)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "ok") {
		t.Fatalf("expected upstream response, got %q", rec.Body.String())
	}
	// Inbound + outbound events.
	events := waitForEvents(cap, 2, time.Second)
	if len(events) < 2 {
		t.Fatalf("expected >= 2 events, got %d", len(events))
	}
}

func TestProxyBlocksOnCredential(t *testing.T) {
	upstream := startUpstream(t)
	defer upstream.Close()

	srv, cap, _, cleanup := setupProxy(t, upstream.URL)
	defer cleanup()

	body := []byte(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"send","arguments":{"text":"AKIAIOSFODNN7EXAMPLE"}}}`)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	parsed, err := mcp.Parse(rec.Body.Bytes())
	if err != nil {
		t.Fatalf("parse: %v body=%s", err, rec.Body.String())
	}
	if parsed.Error == nil || parsed.Error.Code != mcp.ErrCodeBlockedByPolicy {
		t.Fatalf("expected blocked error, got %+v", parsed.Error)
	}
	events := waitForEvents(cap, 1, time.Second)
	if len(events) == 0 {
		t.Fatalf("expected at least one event")
	}
	if events[0].Action != event.ActionBlock {
		t.Fatalf("action = %q, want block", events[0].Action)
	}
}

func TestProxyHealthz(t *testing.T) {
	srv, _, _, cleanup := setupProxy(t, "http://upstream.invalid")
	defer cleanup()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("healthz status = %d", rec.Code)
	}
}
