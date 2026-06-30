package gateway

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

// markerUpstream returns an MCP server whose tools/call result text embeds
// the given marker, so a test can prove which upstream handled a request.
func markerUpstream(t *testing.T, marker string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		env, err := mcp.Parse(body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		resp := mcp.Envelope{JSONRPC: mcp.JSONRPCVersion, ID: env.ID}
		resp.Result = json.RawMessage(`{"content":[{"type":"text","text":"upstream-` + marker + `"}]}`)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
}

func newGateway(t *testing.T, routes []Route) (*Server, func()) {
	t.Helper()
	rs, err := ruleset.LoadDir("../../content")
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	em := emitter.New(&captureSink{}, 32)
	pipe := &pipeline.Pipeline{
		SensorID:     "gateway-test",
		Detectors:    []detect.Detector{rs},
		ModeResolver: rs.HighestMode,
	}
	gw, err := New(Options{
		Pipeline: pipe,
		Emitter:  em,
		Routes:   routes,
		Timeout:  5 * time.Second,
		FailOpen: true,
	})
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	return gw, func() { _ = em.Close() }
}

func TestGatewayRoutesToCorrectUpstream(t *testing.T) {
	upA := markerUpstream(t, "A")
	defer upA.Close()
	upB := markerUpstream(t, "B")
	defer upB.Close()

	gw, cleanup := newGateway(t, []Route{
		{Name: "a", Prefix: "/mcp/a", Upstream: upA.URL},
		{Name: "b", Prefix: "/mcp/b", Upstream: upB.URL},
	})
	defer cleanup()

	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hi"}}}`)

	for _, tc := range []struct{ path, want string }{
		{"/mcp/a", "upstream-A"},
		{"/mcp/b", "upstream-B"},
		{"/mcp/a/sub/path", "upstream-A"},
	} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, tc.path, bytes.NewReader(body))
		gw.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("path %s: status = %d, body=%s", tc.path, rec.Code, rec.Body.String())
		}
		if !bytes.Contains(rec.Body.Bytes(), []byte(tc.want)) {
			t.Fatalf("path %s routed wrong: got %q, want marker %q", tc.path, rec.Body.String(), tc.want)
		}
	}
}

func TestGatewayDetectionAppliesPerRoute(t *testing.T) {
	up := markerUpstream(t, "A")
	defer up.Close()

	gw, cleanup := newGateway(t, []Route{{Name: "a", Prefix: "/mcp/a", Upstream: up.URL}})
	defer cleanup()

	// A credential in the tool-call args must still be blocked even though we
	// went through the gateway's routing layer rather than a bare proxy.
	body := []byte(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"send","arguments":{"text":"AKIAIOSFODNN7EXAMPLE"}}}`)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp/a", bytes.NewReader(body))
	gw.ServeHTTP(rec, req)

	parsed, err := mcp.Parse(rec.Body.Bytes())
	if err != nil {
		t.Fatalf("parse: %v body=%s", err, rec.Body.String())
	}
	if parsed.Error == nil || parsed.Error.Code != mcp.ErrCodeBlockedByPolicy {
		t.Fatalf("expected blocked-by-policy through gateway, got %+v", parsed.Error)
	}
}

func TestGatewayUnmatchedPath404(t *testing.T) {
	up := markerUpstream(t, "A")
	defer up.Close()
	gw, cleanup := newGateway(t, []Route{{Name: "a", Prefix: "/mcp/a", Upstream: up.URL}})
	defer cleanup()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp/unknown", bytes.NewReader([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call"}`)))
	gw.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unmatched path status = %d, want 404", rec.Code)
	}
}

func TestGatewayLongestPrefixWins(t *testing.T) {
	broad := markerUpstream(t, "BROAD")
	defer broad.Close()
	specific := markerUpstream(t, "SPECIFIC")
	defer specific.Close()

	gw, cleanup := newGateway(t, []Route{
		{Name: "broad", Prefix: "/mcp", Upstream: broad.URL},
		{Name: "specific", Prefix: "/mcp/github", Upstream: specific.URL},
	})
	defer cleanup()

	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hi"}}}`)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp/github", bytes.NewReader(body))
	gw.ServeHTTP(rec, req)
	if !bytes.Contains(rec.Body.Bytes(), []byte("upstream-SPECIFIC")) {
		t.Fatalf("longest prefix did not win: got %q", rec.Body.String())
	}
}

func TestGatewayHealthz(t *testing.T) {
	up := markerUpstream(t, "A")
	defer up.Close()
	gw, cleanup := newGateway(t, []Route{{Name: "a", Prefix: "/mcp/a", Upstream: up.URL}})
	defer cleanup()
	for _, m := range []string{http.MethodGet, http.MethodHead} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(m, "/healthz", nil)
		gw.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("healthz %s = %d, want 200", m, rec.Code)
		}
	}
}

func TestGatewayRejectsBadConfig(t *testing.T) {
	rs, err := ruleset.LoadDir("../../content")
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	em := emitter.New(&captureSink{}, 32)
	defer em.Close()
	pipe := &pipeline.Pipeline{SensorID: "x", Detectors: []detect.Detector{rs}, ModeResolver: rs.HighestMode}

	if _, err := New(Options{Pipeline: pipe, Emitter: em}); err == nil {
		t.Fatal("expected error with no routes")
	}
	if _, err := New(Options{Pipeline: pipe, Emitter: em, Routes: []Route{{Name: "x", Prefix: "/a"}}}); err == nil {
		t.Fatal("expected error with missing upstream")
	}
	if _, err := New(Options{Pipeline: pipe, Emitter: em, Routes: []Route{
		{Name: "a", Prefix: "/a", Upstream: "http://x"},
		{Name: "b", Prefix: "/a", Upstream: "http://y"},
	}}); err == nil {
		t.Fatal("expected error with duplicate prefix")
	}
}
