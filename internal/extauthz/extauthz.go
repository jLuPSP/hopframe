// Package extauthz adapts the Hopframe detection pipeline to the Envoy
// external-authorization (ext_authz) HTTP contract. Any Envoy-based
// gateway (Envoy, Istio, Gloo, Emissary, Envoy AI Gateway) can call this
// service for an allow/deny decision on an inbound MCP JSON-RPC message
// without Hopframe owning the data path: the gateway forwards the request
// here, Hopframe runs the inbound detection pipeline, and replies 200
// (allow) or 403 (deny). On allow, the response carries the resolved
// agent-run id as a header the gateway can inject into the upstream
// request; on deny, the body is a JSON-RPC blocked-by-policy envelope the
// gateway returns to the client.
//
// This is a third adapter over the same *pipeline.Pipeline that the inline
// proxy and the stdio proxy use. The brain does not move; only the
// transport does.
//
// # Capability ceiling
//
// ext_authz is request-side and decision-only. The full inbound pipeline
// runs here: regex rule packs, the heuristic classifier, the optional LLM
// judge, and quarantine ENFORCEMENT (a tools/call to an already-quarantined
// tool is blocked). But ext_authz never sees the upstream RESPONSE, so
// response-side features do NOT run on this surface:
//
//   - tools/list quarantine POPULATION (learns from the response),
//   - cross-protocol taint TAGGING (tags MCP tool results),
//   - agent-card validation, and
//   - SSE chunk rewriting.
//
// Those require ext_proc (which can see and mutate responses) or the native
// inline sensor. See docs/surface-matrix.md for the full per-surface map.
package extauthz

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/jlupsp/hopframe/internal/emitter"
	"github.com/jlupsp/hopframe/internal/pipeline"
	"github.com/jlupsp/hopframe/pkg/event"
	"github.com/jlupsp/hopframe/pkg/mcp"
)

const (
	headerAgentRunID = "X-Hopframe-Agent-Run-Id"
	headerDecision   = "X-Hopframe-Decision"
	headerFinding    = "X-Hopframe-Finding"
)

const defaultBodyMaxBytes = 1 << 20 // 1 MiB

// Options configure the ext_authz server.
type Options struct {
	Pipeline *pipeline.Pipeline
	Emitter  *emitter.Emitter
	// FailOpen decides what happens when the forwarded body cannot be read
	// or parsed, or the pipeline errors: true allows the request, false
	// denies it. Mirrors policy.fail_open on the inline sensor.
	FailOpen bool
	// DestLabel names the upstream the gateway routes to. It is used for
	// policy scoping and as the audit event's destination. Falls back to the
	// request Host header when empty.
	DestLabel string
	// BodyMaxBytes caps how much of the forwarded request body is read and
	// parsed. Zero uses a 1 MiB default.
	BodyMaxBytes int64
}

// Server implements the Envoy HTTP ext_authz contract over the pipeline.
type Server struct {
	opts    Options
	bodyMax int64
}

// New constructs the ext_authz server.
func New(opts Options) (*Server, error) {
	if opts.Pipeline == nil {
		return nil, errors.New("extauthz: pipeline is required")
	}
	if opts.Emitter == nil {
		return nil, errors.New("extauthz: emitter is required")
	}
	max := opts.BodyMaxBytes
	if max <= 0 {
		max = defaultBodyMaxBytes
	}
	return &Server{opts: opts, bodyMax: max}, nil
}

// ServeHTTP implements the ext_authz check. The gateway forwards the
// original MCP request (method, path, headers, and body) here; we reply
// 200 to allow or 403 with a JSON-RPC blocked envelope to deny. The
// upstream is never contacted from this handler, the gateway does that
// after we allow.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/healthz" && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"status":"ok"}`)
		return
	}

	// Honor the caller's agent-run id when present so cross-protocol
	// correlation survives the gateway hop; otherwise mint one.
	agentRunID := r.Header.Get(headerAgentRunID)
	if agentRunID == "" {
		agentRunID = newAgentRunID()
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, s.bodyMax))
	if err != nil {
		s.onError(w, agentRunID)
		return
	}
	defer r.Body.Close()

	env, err := mcp.Parse(body)
	if err != nil {
		// A malformed envelope is itself a signal: record it, then honor
		// the fail-open / fail-closed policy.
		s.emitMalformed(r, body, err, agentRunID)
		if s.opts.FailOpen {
			s.allow(w, agentRunID)
			return
		}
		s.deny(w, nil, agentRunID, "blocked by hopframe: invalid mcp envelope", "envelope.malformed")
		return
	}

	res, perr := s.opts.Pipeline.EvaluateMCP(
		r.Context(), env, body, event.DirectionInbound, clientSource(r), s.dest(r),
	)
	if perr != nil {
		s.onError(w, agentRunID)
		return
	}
	res.Event.AgentRunID = agentRunID
	s.opts.Emitter.Emit(res.Event)

	if res.Block {
		s.deny(w, env.ID, agentRunID, res.BlockReason, topFindingID(res.Event.Findings))
		return
	}
	s.allow(w, agentRunID)
}

// allow returns the ext_authz "OK" response. The agent-run id is returned
// as a header the gateway can be configured to inject into the upstream
// request (allowed_upstream_headers), so the run id rides through to the
// MCP server and back.
func (s *Server) allow(w http.ResponseWriter, agentRunID string) {
	h := w.Header()
	h.Set(headerDecision, "allow")
	h.Set(headerAgentRunID, agentRunID)
	w.WriteHeader(http.StatusOK)
}

// deny returns the ext_authz denial. Under the HTTP ext_authz contract a
// non-2xx status means deny, and the body + headers are returned to the
// downstream client. We return a JSON-RPC blocked-by-policy envelope so the
// MCP client gets a protocol-shaped error it can correlate by id.
//
// Note the surface difference from the inline sensor: there a block is an
// in-band JSON-RPC error carried on an HTTP 200; here it is necessarily an
// HTTP 403, because ext_authz signals the decision through the status code.
func (s *Server) deny(w http.ResponseWriter, id json.RawMessage, agentRunID, reason, findingID string) {
	blocked, _ := mcp.BlockedResponse(id, reason)
	h := w.Header()
	h.Set(headerDecision, "block")
	h.Set(headerAgentRunID, agentRunID)
	if findingID != "" {
		h.Set(headerFinding, findingID)
	}
	h.Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write(blocked)
}

// onError applies the fail-open / fail-closed policy to an internal failure
// (unreadable body, pipeline error). Fail-open allows so a Hopframe outage
// does not break the user's traffic; fail-closed denies.
func (s *Server) onError(w http.ResponseWriter, agentRunID string) {
	if s.opts.FailOpen {
		s.allow(w, agentRunID)
		return
	}
	s.deny(w, nil, agentRunID, "blocked by hopframe: internal error", "")
}

func (s *Server) dest(r *http.Request) string {
	if s.opts.DestLabel != "" {
		return s.opts.DestLabel
	}
	return r.Host
}

// clientSource picks the most specific downstream address available: the
// first hop of X-Forwarded-For when the gateway sets it, else the peer
// address of the ext_authz connection.
func clientSource(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i >= 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// topFindingID surfaces the rule that drove the block: the first high or
// critical finding, else the first finding. Mirrors the inline sensor's
// block-reason selection so the X-Hopframe-Finding header is consistent
// across surfaces.
func topFindingID(findings []event.Finding) string {
	for _, f := range findings {
		if f.Severity == event.SeverityCritical || f.Severity == event.SeverityHigh {
			return f.RuleID
		}
	}
	if len(findings) > 0 {
		return findings[0].RuleID
	}
	return ""
}

func (s *Server) emitMalformed(r *http.Request, body []byte, parseErr error, agentRunID string) {
	ev := event.New(s.opts.Pipeline.SensorID, event.ProtocolMCP, event.DirectionInbound)
	ev.EventID = "ev-malformed-" + time.Now().UTC().Format("150405.000000")
	ev.TenantID = s.opts.Pipeline.TenantID
	ev.AgentRunID = agentRunID
	ev.Source = clientSource(r)
	ev.Destination = s.dest(r)
	ev.Message = event.Message{Raw: string(body)}
	ev.Severity = event.SeverityLow
	ev.Action = event.ActionAllow
	ev.Findings = []event.Finding{{
		RuleID:      "envelope.malformed",
		Category:    "policy",
		Severity:    event.SeverityLow,
		Description: "MCP envelope failed to parse: " + parseErr.Error(),
	}}
	s.opts.Emitter.Emit(&ev)
}

// newAgentRunID mints a correlation id when the caller did not supply one.
// The "run-" prefix matches the inline sensor so operators can tell
// generator-origin ids from caller-origin ids.
func newAgentRunID() string {
	var b [10]byte
	if _, err := rand.Read(b[:]); err == nil {
		return "run-" + hex.EncodeToString(b[:])
	}
	return "run-" + time.Now().UTC().Format("20060102T150405.000000")
}
