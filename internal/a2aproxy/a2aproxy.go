// Package a2aproxy is the inline HTTP middlebox for A2A traffic.
// It mirrors internal/proxy (MCP) shape-for-shape, swapping in the
// A2A protocol parser, field extractor, and pipeline evaluator.
package a2aproxy

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/jlupsp/hopframe/internal/counterparty"
	"github.com/jlupsp/hopframe/internal/emitter"
	"github.com/jlupsp/hopframe/internal/pipeline"
	"github.com/jlupsp/hopframe/internal/taskstate"
	"github.com/jlupsp/hopframe/pkg/a2a"
	"github.com/jlupsp/hopframe/pkg/event"
)

const headerCounterparty = "X-Hopframe-Counterparty"

const headerAgentRunID = "X-Hopframe-Agent-Run-Id"

// Options configure the A2A proxy.
type Options struct {
	Pipeline    *pipeline.Pipeline
	Emitter     *emitter.Emitter
	UpstreamURL string
	Timeout     time.Duration
	FailOpen    bool
	// Tasks, when set, enables long-running + drift detection.
	Tasks *taskstate.Tracker
	// Peers, when set, enables cross-org request fingerprinting.
	Peers *counterparty.Registry
}

// Server is an http.Handler that proxies A2A traffic.
type Server struct {
	opts     Options
	upstream *url.URL
	client   *http.Client
}

// Tasks returns the underlying task tracker (or nil).
func (s *Server) Tasks() *taskstate.Tracker { return s.opts.Tasks }

// Peers returns the underlying counterparty registry (or nil).
func (s *Server) Peers() *counterparty.Registry { return s.opts.Peers }

// New constructs the A2A proxy server.
func New(opts Options) (*Server, error) {
	if opts.Pipeline == nil {
		return nil, errors.New("a2aproxy: pipeline is required")
	}
	if opts.Emitter == nil {
		return nil, errors.New("a2aproxy: emitter is required")
	}
	if opts.UpstreamURL == "" {
		return nil, errors.New("a2aproxy: upstream url is required")
	}
	u, err := url.Parse(opts.UpstreamURL)
	if err != nil {
		return nil, fmt.Errorf("a2aproxy: parse upstream %q: %w", opts.UpstreamURL, err)
	}
	if opts.Timeout == 0 {
		opts.Timeout = 30 * time.Second
	}
	return &Server{
		opts:     opts,
		upstream: u,
		client:   &http.Client{Timeout: opts.Timeout},
	}, nil
}

// ServeHTTP implements http.Handler.
//
// Two paths are recognized specially:
//
//   - GET /.well-known/agent.json, fetched from upstream, validated,
//     emitted as an event-tagged "agent.card" record. Findings can
//     block adoption.
//   - any POST, treated as an A2A task envelope; parsed, inspected,
//     forwarded, response also inspected.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet && r.URL.Path == "/healthz" {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"status":"ok"}`)
		return
	}
	if r.Method == http.MethodGet && r.URL.Path == "/.well-known/agent.json" {
		s.handleAgentCard(w, r)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.handleTask(w, r)
}

func (s *Server) handleAgentCard(w http.ResponseWriter, r *http.Request) {
	upstreamURL := *s.upstream
	upstreamURL.Path = singleJoin(s.upstream.Path, r.URL.Path)
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, upstreamURL.String(), nil)
	if err != nil {
		http.Error(w, "build upstream: "+err.Error(), http.StatusInternalServerError)
		return
	}
	resp, err := s.client.Do(req)
	if err != nil {
		http.Error(w, "upstream: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "read upstream: "+err.Error(), http.StatusBadGateway)
		return
	}

	card, parseErr := a2a.ParseCard(body)
	if parseErr != nil {
		// Card unparseable. Emit a low-severity event and pass the body
		// through unchanged so the caller can decide.
		s.emitCardError(r, body, parseErr)
		copyHeaders(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(body)
		return
	}

	validation, ev, evalErr := s.opts.Pipeline.EvaluateAgentCard(r.Context(), card, body, s.upstream.String())
	if evalErr == nil && ev != nil {
		s.opts.Emitter.Emit(ev)
	}
	// Block if the validation has hard errors or detection produced any
	// finding at high+. Otherwise pass through.
	mustBlock := false
	if validation != nil && len(validation.Errors) > 0 {
		mustBlock = true
	}
	if ev != nil && (ev.Severity == event.SeverityHigh || ev.Severity == event.SeverityCritical) {
		mustBlock = true
	}
	if mustBlock {
		http.Error(w, "agent card blocked by hopframe", http.StatusForbidden)
		return
	}
	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(body)
}

func (s *Server) handleTask(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	env, err := a2a.ParseTask(body)
	if err != nil {
		s.emitMalformedTask(r, body, err)
		if s.opts.FailOpen {
			s.forward(r.Context(), w, r, body, agentRunIDFromRequest(r), counterpartyFromRequest(r))
			return
		}
		http.Error(w, "invalid a2a envelope: "+err.Error(), http.StatusBadRequest)
		return
	}

	agentRunID := agentRunIDFromRequest(r)
	counterPartyID := counterpartyFromRequest(r)
	source := r.RemoteAddr
	dest := s.upstream.String()
	res, perr := s.opts.Pipeline.EvaluateA2A(r.Context(), env, body, event.DirectionInbound, source, dest)
	if perr != nil {
		if !s.opts.FailOpen {
			http.Error(w, "pipeline: "+perr.Error(), http.StatusInternalServerError)
			return
		}
		s.forward(r.Context(), w, r, body, agentRunID, counterPartyID)
		return
	}
	res.Event.AgentRunID = agentRunID
	res.Event.Counterparty = counterPartyID

	// Task state hook: extract task id, message fingerprint, and any
	// declared state. Drift / suspicious-transition findings are
	// merged into the event.
	s.maybeTrackTask(env, counterPartyID, res.Event)

	// Cross-protocol taint: did this task message carry data tagged
	// from an earlier MCP tool result on the same agent_run? If so,
	// the proxy raises a high-severity finding and (since it overrides
	// the action to block) the message is rejected.
	s.opts.Pipeline.CheckA2ALeak(env, agentRunID, counterPartyID, res.Event)
	if res.Event.Action == event.ActionBlock {
		res.Block = true
		if res.BlockReason == "" {
			res.BlockReason = "blocked: cross-protocol taint leak"
		}
	}

	// Counterparty hook: report this observation to the registry.
	s.maybeRecordCounterparty(counterPartyID, res.Event)

	s.opts.Emitter.Emit(res.Event)

	if res.Block {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set(headerAgentRunID, agentRunID)
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"error":"`+res.BlockReason+`"}`)
		return
	}

	s.forward(r.Context(), w, r, body, agentRunID, counterPartyID)
}

func (s *Server) forward(ctx context.Context, w http.ResponseWriter, r *http.Request, body []byte, agentRunID, counterPartyID string) {
	upstreamURL := *s.upstream
	upstreamURL.Path = singleJoin(s.upstream.Path, r.URL.Path)
	upstreamURL.RawQuery = r.URL.RawQuery

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, upstreamURL.String(), bytes.NewReader(body))
	if err != nil {
		http.Error(w, "build upstream request: "+err.Error(), http.StatusInternalServerError)
		return
	}
	copyHeaders(req.Header, r.Header)
	req.Header.Set("X-Hopframe-Sensor", "1")
	req.Header.Set(headerAgentRunID, agentRunID)
	if counterPartyID != "" {
		req.Header.Set(headerCounterparty, counterPartyID)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		http.Error(w, "upstream error: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "read upstream body: "+err.Error(), http.StatusBadGateway)
		return
	}

	if outEnv, perr := a2a.ParseTask(respBody); perr == nil {
		res, evalErr := s.opts.Pipeline.EvaluateA2A(ctx, outEnv, respBody, event.DirectionOutbound, s.upstream.String(), r.RemoteAddr)
		if evalErr == nil && res != nil {
			res.Event.AgentRunID = agentRunID
			res.Event.Counterparty = counterPartyID
			s.maybeTrackTaskOutbound(outEnv, counterPartyID, res.Event)
			s.maybeRecordCounterparty(counterPartyID, res.Event)
			s.opts.Emitter.Emit(res.Event)
			if res.Block {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set(headerAgentRunID, agentRunID)
				w.WriteHeader(http.StatusForbidden)
				_, _ = io.WriteString(w, `{"error":"`+res.BlockReason+`"}`)
				return
			}
		}
	}

	copyHeaders(w.Header(), resp.Header)
	w.Header().Set(headerAgentRunID, agentRunID)
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(respBody)
}

// maybeTrackTask updates the task state tracker on inbound task
// envelopes (tasks/send, tasks/get, tasks/cancel) and merges any
// findings the tracker raises into the event.
func (s *Server) maybeTrackTask(env *a2a.TaskEnvelope, counterPartyID string, ev *event.Event) {
	if s.opts.Tasks == nil {
		return
	}
	switch env.Method {
	case a2a.MethodTasksSend, a2a.MethodTasksSendSubscribe, a2a.MethodTasksGet, a2a.MethodTasksCancel:
	default:
		return
	}
	id, msgFP := taskIDAndFingerprint(env.Params)
	if id == "" {
		return
	}
	state := taskstate.StateUnknown
	if env.Method == a2a.MethodTasksCancel {
		state = taskstate.StateCanceled
	}
	_, findings := s.opts.Tasks.Update(id, counterPartyID, state, msgFP)
	for _, f := range findings {
		ev.Findings = append(ev.Findings, event.Finding{
			RuleID:      f.Code,
			Category:    "policy",
			Severity:    event.SeverityHigh,
			Description: f.Message,
			Field:       "params.id",
			Match:       id,
			Confidence:  0.9,
		})
		if ev.Severity == "" || severityLessThan(ev.Severity, event.SeverityHigh) {
			ev.Severity = event.SeverityHigh
		}
	}
}

// maybeTrackTaskOutbound advances the task state from a server
// response: it pulls the result.status.state field if present.
func (s *Server) maybeTrackTaskOutbound(env *a2a.TaskEnvelope, counterPartyID string, ev *event.Event) {
	if s.opts.Tasks == nil || len(env.Result) == 0 {
		return
	}
	id, state := taskIDAndStateFromResult(env.Result)
	if id == "" || state == taskstate.StateUnknown {
		return
	}
	_, findings := s.opts.Tasks.Update(id, counterPartyID, state, "")
	for _, f := range findings {
		ev.Findings = append(ev.Findings, event.Finding{
			RuleID:      f.Code,
			Category:    "policy",
			Severity:    event.SeverityHigh,
			Description: f.Message,
			Field:       "result.id",
			Match:       id,
			Confidence:  0.9,
		})
		if ev.Severity == "" || severityLessThan(ev.Severity, event.SeverityHigh) {
			ev.Severity = event.SeverityHigh
		}
	}
}

// maybeRecordCounterparty reports an observation to the counterparty
// registry and merges any threshold alarm into the event.
func (s *Server) maybeRecordCounterparty(id string, ev *event.Event) {
	if s.opts.Peers == nil || id == "" {
		return
	}
	_, alarm := s.opts.Peers.Observe(counterparty.Observation{
		Counterparty: id,
		Findings:     len(ev.Findings),
		Action:       string(ev.Action),
		Severity:     string(ev.Severity),
	})
	if alarm != nil {
		ev.Findings = append(ev.Findings, event.Finding{
			RuleID:      alarm.Code,
			Category:    "policy",
			Severity:    event.SeverityHigh,
			Description: alarm.Message,
			Field:       "counterparty",
			Match:       id,
			Confidence:  0.95,
		})
	}
}

func taskIDAndFingerprint(params json.RawMessage) (string, string) {
	if len(params) == 0 {
		return "", ""
	}
	var obj struct {
		ID      string `json:"id"`
		Message any    `json:"message"`
	}
	if err := json.Unmarshal(params, &obj); err != nil {
		return "", ""
	}
	if obj.Message == nil {
		return obj.ID, ""
	}
	body, _ := json.Marshal(obj.Message)
	sum := sha256.Sum256(body)
	return obj.ID, hex.EncodeToString(sum[:])[:16]
}

func taskIDAndStateFromResult(result json.RawMessage) (string, taskstate.State) {
	if len(result) == 0 {
		return "", taskstate.StateUnknown
	}
	var obj struct {
		ID     string `json:"id"`
		Status struct {
			State string `json:"state"`
		} `json:"status"`
	}
	if err := json.Unmarshal(result, &obj); err != nil {
		return "", taskstate.StateUnknown
	}
	return obj.ID, taskstate.State(obj.Status.State)
}

// counterpartyFromRequest derives the peer id, in priority order:
// header → upstream host as a coarse fallback. Empty string is
// returned when nothing is available, signalling "do not record".
func counterpartyFromRequest(r *http.Request) string {
	if v := r.Header.Get(headerCounterparty); v != "" {
		return v
	}
	if v := r.Header.Get("X-Forwarded-For"); v != "" {
		return v
	}
	return r.RemoteAddr
}

func severityLessThan(a, b event.Severity) bool {
	rank := map[event.Severity]int{
		event.SeverityInfo:     0,
		event.SeverityLow:      1,
		event.SeverityMedium:   2,
		event.SeverityHigh:     3,
		event.SeverityCritical: 4,
	}
	return rank[a] < rank[b]
}

func (s *Server) emitMalformedTask(r *http.Request, body []byte, parseErr error) {
	ev := event.New(s.opts.Pipeline.SensorID, event.ProtocolA2A, event.DirectionInbound)
	ev.EventID = "ev-malformed-" + time.Now().UTC().Format("150405.000000")
	ev.TenantID = s.opts.Pipeline.TenantID
	ev.AgentRunID = agentRunIDFromRequest(r)
	ev.Source = r.RemoteAddr
	ev.Destination = s.upstream.String()
	ev.Message = event.Message{Raw: string(body)}
	ev.Severity = event.SeverityLow
	ev.Findings = []event.Finding{{
		RuleID:      "envelope.malformed",
		Category:    "policy",
		Severity:    event.SeverityLow,
		Description: "A2A task envelope failed to parse: " + parseErr.Error(),
	}}
	s.opts.Emitter.Emit(&ev)
}

func (s *Server) emitCardError(r *http.Request, body []byte, parseErr error) {
	ev := event.New(s.opts.Pipeline.SensorID, event.ProtocolA2A, event.DirectionOutbound)
	ev.EventID = "ev-card-malformed-" + time.Now().UTC().Format("150405.000000")
	ev.TenantID = s.opts.Pipeline.TenantID
	ev.AgentRunID = agentRunIDFromRequest(r)
	ev.Source = s.upstream.String()
	ev.Destination = r.RemoteAddr
	ev.Message = event.Message{Method: "agent.card", Raw: string(body)}
	ev.Severity = event.SeverityLow
	ev.Findings = []event.Finding{{
		RuleID:      "card.malformed",
		Category:    "policy",
		Severity:    event.SeverityLow,
		Description: "agent card failed to parse: " + parseErr.Error(),
	}}
	s.opts.Emitter.Emit(&ev)
}

func agentRunIDFromRequest(r *http.Request) string {
	if v := r.Header.Get(headerAgentRunID); v != "" {
		return v
	}
	var b [10]byte
	if _, err := cryptorand.Read(b[:]); err == nil {
		return "run-" + hex.EncodeToString(b[:])
	}
	return "run-" + time.Now().UTC().Format("20060102T150405.000000")
}

func copyHeaders(dst, src http.Header) {
	for k, vs := range src {
		switch k {
		case "Connection", "Keep-Alive", "Proxy-Authenticate",
			"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade":
			continue
		}
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

func singleJoin(a, b string) string {
	switch {
	case a == "" || a == "/":
		return b
	case b == "" || b == "/":
		return a
	case a[len(a)-1] == '/' && b[0] == '/':
		return a + b[1:]
	case a[len(a)-1] != '/' && b[0] != '/':
		return a + "/" + b
	default:
		return a + b
	}
}
