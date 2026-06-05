package proxy

import (
	"bytes"
	"context"
	"fmt"
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
	"github.com/jlupsp/hopframe/pkg/ruleset"
)

// startSSEUpstream is a helper that returns an httptest.Server which
// responds to POST /mcp with an SSE stream of JSON-RPC events.
func startSSEUpstream(t *testing.T, events []string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		f, _ := w.(http.Flusher)
		for _, ev := range events {
			fmt.Fprintf(w, "data: %s\n\n", ev)
			if f != nil {
				f.Flush()
			}
			time.Sleep(15 * time.Millisecond)
		}
	}))
}

type cap struct {
	mu     sync.Mutex
	events []*event.Event
}

func (c *cap) Deliver(_ context.Context, ev *event.Event) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, ev)
	return nil
}
func (c *cap) Close() error { return nil }
func (c *cap) snapshot() []*event.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]*event.Event, len(c.events))
	copy(out, c.events)
	return out
}

func newSSEServer(t *testing.T, upstreamURL string) (*Server, *cap, *emitter.Emitter, func()) {
	t.Helper()
	rs, err := ruleset.LoadDir("../../content")
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	c := &cap{}
	em := emitter.New(c, 64)
	pipe := &pipeline.Pipeline{
		SensorID:     "sse-test",
		Detectors:    []detect.Detector{rs, &detect.HeuristicClassifier{}},
		ModeResolver: rs.HighestMode,
	}
	srv, err := New(Options{
		Pipeline:    pipe,
		Emitter:     em,
		UpstreamURL: upstreamURL,
		BasePath:    "/mcp",
		Timeout:     10 * time.Second,
		FailOpen:    true,
	})
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}
	return srv, c, em, func() { _ = em.Close() }
}

func TestSSEForwardsBenignStream(t *testing.T) {
	upstream := startSSEUpstream(t, []string{
		`{"jsonrpc":"2.0","id":1,"result":{"chunk":1,"content":"hello"}}`,
		`{"jsonrpc":"2.0","id":1,"result":{"chunk":2,"content":"world"}}`,
		`{"jsonrpc":"2.0","id":1,"result":{"chunk":3,"content":"done","final":true}}`,
	})
	defer upstream.Close()

	srv, c, _, cleanup := newSSEServer(t, upstream.URL)
	defer cleanup()

	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"long_tool","arguments":{"text":"hi"}}}`)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	out := rec.Body.String()
	for _, want := range []string{`"chunk":1`, `"chunk":2`, `"chunk":3`, `"final":true`} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected stream to contain %q; full body: %q", want, out)
		}
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if len(c.snapshot()) >= 4 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := len(c.snapshot()); got < 4 {
		t.Fatalf("expected >=4 events (1 inbound + 3 outbound chunks), got %d", got)
	}
}

func TestSSEBlocksPoisonedChunk(t *testing.T) {
	// Second chunk smuggles a credential pattern.
	upstream := startSSEUpstream(t, []string{
		`{"jsonrpc":"2.0","id":1,"result":{"chunk":1,"content":"normal text"}}`,
		`{"jsonrpc":"2.0","id":1,"result":{"chunk":2,"content":"AKIAIOSFODNN7EXAMPLE"}}`,
		`{"jsonrpc":"2.0","id":1,"result":{"chunk":3,"content":"more text","final":true}}`,
	})
	defer upstream.Close()

	srv, _, _, cleanup := newSSEServer(t, upstream.URL)
	defer cleanup()

	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"long_tool","arguments":{}}}`)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
	srv.ServeHTTP(rec, req)

	out := rec.Body.String()
	if !strings.Contains(out, "hopframe-blocked") {
		t.Fatalf("expected hopframe-blocked event in stream; got %q", out)
	}
	if strings.Contains(out, "AKIAIOSFODNN7EXAMPLE") {
		t.Fatalf("poisoned chunk should NOT have been forwarded to client; got %q", out)
	}
}

// Sanity-check: passthrough for plain JSON responses still works.
func TestNonSSEPathStillWorks(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = body
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"ok":true}}`)
	}))
	defer upstream.Close()

	srv, _, _, cleanup := newSSEServer(t, upstream.URL)
	defer cleanup()

	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{}}}`)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("non-SSE path failed: status=%d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"ok":true`) {
		t.Fatalf("non-SSE body wrong: %q", rec.Body.String())
	}
}
