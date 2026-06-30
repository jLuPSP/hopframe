package extauthz

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
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

func newServer(t *testing.T, failOpen bool) (*Server, *captureSink, func()) {
	t.Helper()
	rs, err := ruleset.LoadDir("../../content")
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	cap := &captureSink{}
	em := emitter.New(cap, 32)
	pipe := &pipeline.Pipeline{
		SensorID:     "extauthz-test",
		Detectors:    []detect.Detector{rs},
		ModeResolver: rs.HighestMode,
	}
	srv, err := New(Options{Pipeline: pipe, Emitter: em, FailOpen: failOpen})
	if err != nil {
		t.Fatalf("new extauthz: %v", err)
	}
	return srv, cap, func() { _ = em.Close() }
}

func post(srv *Server, body []byte, headers map[string]string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	srv.ServeHTTP(rec, req)
	return rec
}

func TestExtAuthzAllowsBenign(t *testing.T) {
	srv, cap, cleanup := newServer(t, true)
	defer cleanup()

	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hello"}}}`)
	rec := post(srv, body, nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get(headerDecision); got != "allow" {
		t.Fatalf("decision = %q, want allow", got)
	}
	if rec.Header().Get(headerAgentRunID) == "" {
		t.Fatalf("missing agent-run-id header on allow")
	}
	events := waitForEvents(cap, 1, time.Second)
	if len(events) == 0 || events[0].Action != event.ActionAllow {
		t.Fatalf("expected one allow event, got %+v", events)
	}
}

func TestExtAuthzDeniesOnCredential(t *testing.T) {
	srv, cap, cleanup := newServer(t, true)
	defer cleanup()

	// Same trigger the inline proxy test uses: a canonical fake AWS key in
	// the tool-call arguments resolves to a block on the inbound wire.
	body := []byte(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"send","arguments":{"text":"AKIAIOSFODNN7EXAMPLE"}}}`)
	rec := post(srv, body, nil)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if got := rec.Header().Get(headerDecision); got != "block" {
		t.Fatalf("decision = %q, want block", got)
	}
	if rec.Header().Get(headerFinding) == "" {
		t.Fatalf("expected X-Hopframe-Finding header on block")
	}
	parsed, err := mcp.Parse(rec.Body.Bytes())
	if err != nil {
		t.Fatalf("parse blocked body: %v; body=%s", err, rec.Body.String())
	}
	if parsed.Error == nil || parsed.Error.Code != mcp.ErrCodeBlockedByPolicy {
		t.Fatalf("expected blocked-by-policy error, got %+v", parsed.Error)
	}
	events := waitForEvents(cap, 1, time.Second)
	if len(events) == 0 || events[0].Action != event.ActionBlock {
		t.Fatalf("expected a block event, got %+v", events)
	}
}

func TestExtAuthzEchoesCallerAgentRunID(t *testing.T) {
	srv, _, cleanup := newServer(t, true)
	defer cleanup()

	body := []byte(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hi"}}}`)
	rec := post(srv, body, map[string]string{headerAgentRunID: "run-fixed-123"})

	if got := rec.Header().Get(headerAgentRunID); got != "run-fixed-123" {
		t.Fatalf("agent-run-id = %q, want run-fixed-123 (must propagate caller id for correlation)", got)
	}
}

func TestExtAuthzMalformedFailClosed(t *testing.T) {
	srv, _, cleanup := newServer(t, false)
	defer cleanup()

	rec := post(srv, []byte(`{not json`), nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("malformed fail-closed status = %d, want 403", rec.Code)
	}
}

func TestExtAuthzMalformedFailOpen(t *testing.T) {
	srv, _, cleanup := newServer(t, true)
	defer cleanup()

	rec := post(srv, []byte(`{not json`), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("malformed fail-open status = %d, want 200", rec.Code)
	}
}

func TestExtAuthzHealthz(t *testing.T) {
	srv, _, cleanup := newServer(t, true)
	defer cleanup()
	// Both GET and HEAD must return 200: health probes (wget --spider, k8s
	// httpGet) use one or the other, and a non-200 here reads as unhealthy.
	for _, m := range []string{http.MethodGet, http.MethodHead} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(m, "/healthz", nil)
		srv.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("healthz %s = %d, want 200", m, rec.Code)
		}
	}
}
