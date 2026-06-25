// Package integration holds cross-package, HTTP-level tests that exercise
// more than one sensor component wired together the way a deployable binary
// wires them. They live in their own package so a single test can import both
// the MCP proxy and the A2A proxy (which never import each other).
package integration

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

	"github.com/jlupsp/hopframe/internal/a2aproxy"
	"github.com/jlupsp/hopframe/internal/counterparty"
	"github.com/jlupsp/hopframe/internal/emitter"
	"github.com/jlupsp/hopframe/internal/pipeline"
	"github.com/jlupsp/hopframe/internal/proxy"
	"github.com/jlupsp/hopframe/internal/taskstate"
	"github.com/jlupsp/hopframe/pkg/detect"
	"github.com/jlupsp/hopframe/pkg/event"
	"github.com/jlupsp/hopframe/pkg/mcp"
	"github.com/jlupsp/hopframe/pkg/ruleset"
	"github.com/jlupsp/hopframe/pkg/taint"
)

const runIDHeader = "X-Hopframe-Agent-Run-Id"

// A deliberately non-credential secret: it matches no content rule, so the
// only thing that can block its egress is value lineage. This is the A1
// showpiece from the open-wire lab.
const labToken = "svc_tok_FAKE_0000_DO_NOT_USE_example_only"

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
func (c *captureSink) hasFinding(ruleID string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, ev := range c.events {
		for _, f := range ev.Findings {
			if f.RuleID == ruleID {
				return true
			}
		}
	}
	return false
}

func waitForFinding(c *captureSink, ruleID string, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if c.hasFinding(ruleID) {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return false
}

// mcpUpstream returns an MCP server whose tools/call result carries the token.
func mcpUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		env, err := mcp.Parse(body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		resp := mcp.Envelope{JSONRPC: mcp.JSONRPCVersion, ID: env.ID}
		if env.Method == mcp.MethodToolsCall {
			resp.Result = json.RawMessage(`{"content":[{"type":"text","text":"` + labToken + `"}]}`)
		} else {
			resp.Result = json.RawMessage(`{}`)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
}

// a2aUpstream is the peer drop box: it accepts anything the sensor lets through.
func a2aUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"status":"ok"}}`))
	}))
}

// TestCombinedSensorBlocksCrossProtocolLeak drives real HTTP through an MCP
// proxy and an A2A proxy that share ONE pipeline and ONE taint tracker, the
// way cmd/sensor wires the combined sensor. A token read over the MCP wire
// must be recognized and blocked when the agent forwards it over the A2A wire
// on the same agent run, even though the token matches no credential rule.
func TestCombinedSensorBlocksCrossProtocolLeak(t *testing.T) {
	rs, err := ruleset.LoadDir("../../content")
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	cap := &captureSink{}
	em := emitter.New(cap, 64)
	defer func() { _ = em.Close() }()

	// One pipeline, one taint tracker, shared by both wires. This is the point.
	tracker := taint.New(time.Hour, 128, 4096)
	pipe := &pipeline.Pipeline{
		SensorID:     "combined-test",
		Detectors:    []detect.Detector{rs},
		ModeResolver: rs.HighestMode,
		Taint:        tracker,
	}

	mcpUp := mcpUpstream(t)
	defer mcpUp.Close()
	a2aUp := a2aUpstream(t)
	defer a2aUp.Close()

	mcpSrv, err := proxy.New(proxy.Options{
		Pipeline: pipe, Emitter: em, UpstreamURL: mcpUp.URL,
		BasePath: "/mcp", Timeout: 5 * time.Second, FailOpen: true,
	})
	if err != nil {
		t.Fatalf("mcp proxy: %v", err)
	}
	a2aSrv, err := a2aproxy.New(a2aproxy.Options{
		Pipeline: pipe, Emitter: em, UpstreamURL: a2aUp.URL,
		Timeout: 5 * time.Second, FailOpen: true,
		Tasks: taskstate.New(2*time.Hour, 4096), Peers: counterparty.New(),
	})
	if err != nil {
		t.Fatalf("a2a proxy: %v", err)
	}

	// Step 1: the agent reads the token over MCP. Allowed (no credential
	// pattern), but the result is tagged against run-combined-1.
	mcpBody := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/etc/agent/service_token"}}}`)
	mrec := httptest.NewRecorder()
	mreq := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(mcpBody))
	mreq.Header.Set(runIDHeader, "run-combined-1")
	mcpSrv.ServeHTTP(mrec, mreq)
	if mrec.Code != http.StatusOK {
		t.Fatalf("mcp read status = %d, body = %s", mrec.Code, mrec.Body.String())
	}

	// Step 2: the agent forwards the token over A2A on the SAME run. The
	// other wire's sensor must recognize the bytes and block the send.
	a2aBody := []byte(`{"jsonrpc":"2.0","id":2,"method":"tasks/send","params":{"id":"handoff-1","message":{"parts":[{"type":"text","text":"register service token ` + labToken + `"}]}}}`)
	arec := httptest.NewRecorder()
	areq := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(a2aBody))
	areq.Header.Set(runIDHeader, "run-combined-1")
	a2aSrv.ServeHTTP(arec, areq)
	if arec.Code != http.StatusForbidden {
		t.Fatalf("expected A2A forward to be blocked (403), got %d: %s", arec.Code, arec.Body.String())
	}
	if !waitForFinding(cap, "taint.cross_protocol_leak", time.Second) {
		t.Fatalf("expected taint.cross_protocol_leak finding to be emitted")
	}

	// Step 3 (negative): the same token on a DIFFERENT run has no lineage and
	// must pass. Proves the block is provenance-scoped, not a content match.
	otherBody := []byte(`{"jsonrpc":"2.0","id":3,"method":"tasks/send","params":{"id":"handoff-2","message":{"parts":[{"type":"text","text":"register service token ` + labToken + `"}]}}}`)
	orec := httptest.NewRecorder()
	oreq := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(otherBody))
	oreq.Header.Set(runIDHeader, "run-combined-2")
	a2aSrv.ServeHTTP(orec, oreq)
	if orec.Code != http.StatusOK {
		t.Fatalf("token on an unrelated run must not be blocked, got %d", orec.Code)
	}
}

// TestSplitSensorsMissLeakWithoutSharedState is the control: two SEPARATE
// pipelines (the split mcp-sensor / a2a-sensor topology, each with its own
// taint tracker and no control plane) cannot catch the cross-protocol leak.
// This is exactly the gap the combined sensor and the control-plane-shared
// taint close, and documenting it as a test keeps the claim honest.
func TestSplitSensorsMissLeakWithoutSharedState(t *testing.T) {
	rs, err := ruleset.LoadDir("../../content")
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	cap := &captureSink{}
	em := emitter.New(cap, 64)
	defer func() { _ = em.Close() }()

	// Two independent trackers: the MCP sensor tags into one, the A2A sensor
	// checks against the other. No shared state, no control plane.
	mcpPipe := &pipeline.Pipeline{SensorID: "mcp-only", Detectors: []detect.Detector{rs}, ModeResolver: rs.HighestMode, Taint: taint.New(time.Hour, 128, 4096)}
	a2aPipe := &pipeline.Pipeline{SensorID: "a2a-only", Detectors: []detect.Detector{rs}, ModeResolver: rs.HighestMode, Taint: taint.New(time.Hour, 128, 4096)}

	mcpUp := mcpUpstream(t)
	defer mcpUp.Close()
	a2aUp := a2aUpstream(t)
	defer a2aUp.Close()

	mcpSrv, err := proxy.New(proxy.Options{Pipeline: mcpPipe, Emitter: em, UpstreamURL: mcpUp.URL, BasePath: "/mcp", Timeout: 5 * time.Second, FailOpen: true})
	if err != nil {
		t.Fatalf("mcp proxy: %v", err)
	}
	a2aSrv, err := a2aproxy.New(a2aproxy.Options{Pipeline: a2aPipe, Emitter: em, UpstreamURL: a2aUp.URL, Timeout: 5 * time.Second, FailOpen: true, Tasks: taskstate.New(2*time.Hour, 4096), Peers: counterparty.New()})
	if err != nil {
		t.Fatalf("a2a proxy: %v", err)
	}

	mcpBody := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/etc/agent/service_token"}}}`)
	mrec := httptest.NewRecorder()
	mreq := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(mcpBody))
	mreq.Header.Set(runIDHeader, "run-split-1")
	mcpSrv.ServeHTTP(mrec, mreq)
	if mrec.Code != http.StatusOK {
		t.Fatalf("mcp read status = %d", mrec.Code)
	}

	a2aBody := []byte(`{"jsonrpc":"2.0","id":2,"method":"tasks/send","params":{"id":"handoff-1","message":{"parts":[{"type":"text","text":"register service token ` + labToken + `"}]}}}`)
	arec := httptest.NewRecorder()
	areq := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(a2aBody))
	areq.Header.Set(runIDHeader, "run-split-1")
	a2aSrv.ServeHTTP(arec, areq)

	// The A2A sensor has no taint for this run, so the non-credential token
	// sails through. This is the documented blind spot of split, stateless
	// sensors, not a regression.
	if arec.Code == http.StatusForbidden {
		t.Fatalf("split stateless sensors should NOT catch the cross-protocol leak; got a block, the test premise is stale")
	}
}
