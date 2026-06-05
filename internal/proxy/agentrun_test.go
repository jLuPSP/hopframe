package proxy

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jlupsp/hopframe/control-plane/store"
	"github.com/jlupsp/hopframe/pkg/event"
)

func TestAgentRunIDPropagatedFromHeader(t *testing.T) {
	upstream := startUpstream(t)
	defer upstream.Close()

	srv, cap, _, cleanup := setupProxy(t, upstream.URL)
	defer cleanup()

	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hi"}}}`)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
	req.Header.Set("X-Hopframe-Agent-Run-Id", "run-from-caller")
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if got := rec.Header().Get("X-Hopframe-Agent-Run-Id"); got != "run-from-caller" {
		t.Fatalf("response header agent run id = %q, want %q", got, "run-from-caller")
	}

	events := waitForEvents(cap, 2, time.Second)
	if len(events) < 2 {
		t.Fatalf("expected 2 events (in+out), got %d", len(events))
	}
	for _, ev := range events {
		if ev.AgentRunID != "run-from-caller" {
			t.Fatalf("event agent run id = %q, want run-from-caller", ev.AgentRunID)
		}
	}
}

func TestAgentRunIDGeneratedWhenAbsent(t *testing.T) {
	upstream := startUpstream(t)
	defer upstream.Close()

	srv, cap, _, cleanup := setupProxy(t, upstream.URL)
	defer cleanup()

	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hi"}}}`)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
	srv.ServeHTTP(rec, req)

	resHeader := rec.Header().Get("X-Hopframe-Agent-Run-Id")
	if resHeader == "" || len(resHeader) < 10 {
		t.Fatalf("expected generated run id in response header, got %q", resHeader)
	}

	events := waitForEvents(cap, 2, time.Second)
	if len(events) < 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
	if events[0].AgentRunID != events[1].AgentRunID {
		t.Fatalf("inbound/outbound run ids differ: %q vs %q", events[0].AgentRunID, events[1].AgentRunID)
	}
	if events[0].AgentRunID != resHeader {
		t.Fatalf("event run id %q != response header %q", events[0].AgentRunID, resHeader)
	}
}

// Just to make the import of store/event is non-empty so the test
// file compiles cleanly even if the helpers above evolve.
var _ = store.Record{}
var _ event.Severity = event.SeverityInfo
