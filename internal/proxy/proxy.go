// Package proxy is the inline HTTP middlebox that terminates MCP
// JSON-RPC traffic from a client, runs the detection pipeline, and
// forwards approved messages to the upstream MCP server.
//
// We deliberately avoid net/http/httputil.ReverseProxy: we need to
// inspect and optionally rewrite the request body before forwarding,
// and we need to intercept the response body for outbound detection.
package proxy

import (
	"bufio"
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jlupsp/hopframe/internal/emitter"
	"github.com/jlupsp/hopframe/internal/pipeline"
	"github.com/jlupsp/hopframe/pkg/event"
	"github.com/jlupsp/hopframe/pkg/mcp"
)

var (
	cryptoRandRead = cryptorand.Read
	hexEncode      = hex.EncodeToString
)

// Options configure the proxy server.
type Options struct {
	Pipeline    *pipeline.Pipeline
	Emitter     *emitter.Emitter
	UpstreamURL string
	BasePath    string
	Timeout     time.Duration
	FailOpen    bool
}

// Server is a stdlib http.Handler that proxies MCP traffic.
type Server struct {
	opts     Options
	upstream *url.URL
	client   *http.Client
}

// New constructs the proxy server. UpstreamURL must parse.
func New(opts Options) (*Server, error) {
	if opts.Pipeline == nil {
		return nil, errors.New("proxy: pipeline is required")
	}
	if opts.Emitter == nil {
		return nil, errors.New("proxy: emitter is required")
	}
	if opts.UpstreamURL == "" {
		return nil, errors.New("proxy: upstream url is required")
	}
	u, err := url.Parse(opts.UpstreamURL)
	if err != nil {
		return nil, fmt.Errorf("proxy: parse upstream %q: %w", opts.UpstreamURL, err)
	}
	if opts.Timeout == 0 {
		opts.Timeout = 30 * time.Second
	}
	if opts.BasePath == "" {
		opts.BasePath = "/mcp"
	}
	return &Server{
		opts:     opts,
		upstream: u,
		client: &http.Client{
			Timeout: opts.Timeout,
		},
	}, nil
}

// ServeHTTP implements http.Handler. The request body is read fully,
// inspected, optionally blocked, and otherwise forwarded upstream. The
// upstream response body is then inspected and returned to the client.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet && r.URL.Path == "/healthz" {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"status":"ok"}`)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	env, err := mcp.Parse(body)
	if err != nil {
		// Malformed envelope is itself a security signal, emit and
		// either fail-open or block.
		s.emitMalformed(r, body, err)
		if s.opts.FailOpen {
			s.forward(r.Context(), w, r, body, agentRunIDFromRequest(r), "")
			return
		}
		http.Error(w, "invalid mcp envelope: "+err.Error(), http.StatusBadRequest)
		return
	}

	source := r.RemoteAddr
	dest := s.upstream.String()
	agentRunID := agentRunIDFromRequest(r)
	requestMethod := env.Method
	res, perr := s.opts.Pipeline.EvaluateMCP(
		r.Context(), env, body, event.DirectionInbound, source, dest,
	)
	if perr != nil {
		if !s.opts.FailOpen {
			http.Error(w, "pipeline error: "+perr.Error(), http.StatusInternalServerError)
			return
		}
		// Fall through: forward without inspection rather than break the user.
		s.forward(r.Context(), w, r, body, agentRunID, requestMethod)
		return
	}
	res.Event.AgentRunID = agentRunID
	s.opts.Emitter.Emit(res.Event)
	if res.Block {
		blocked, _ := mcp.BlockedResponse(env.ID, res.BlockReason)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set(headerAgentRunID, agentRunID)
		w.WriteHeader(http.StatusOK) // JSON-RPC carries the error in-body
		_, _ = w.Write(blocked)
		return
	}

	s.forward(r.Context(), w, r, body, agentRunID, requestMethod)
}

func (s *Server) forward(ctx context.Context, w http.ResponseWriter, r *http.Request, body []byte, agentRunID, requestMethod string) {
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

	resp, err := s.client.Do(req)
	if err != nil {
		http.Error(w, "upstream error: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Streamable HTTP / SSE: when upstream returns text/event-stream,
	// we cannot wait for the full body, the connection stays open
	// for the duration of the stream. Switch to chunk-forwarding
	// with per-event detection.
	if isSSEResponse(resp) {
		s.forwardSSE(ctx, w, resp, agentRunID, requestMethod, r.RemoteAddr)
		return
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "read upstream body: "+err.Error(), http.StatusBadGateway)
		return
	}

	// Outbound inspection: parse the response envelope and run pipeline again.
	if outEnv, perr := mcp.Parse(respBody); perr == nil {
		// JSON-RPC responses don't carry the method, but we still need
		// to apply method-scoped rules (tools/list response, etc.).
		// Stamp the inbound method onto the response envelope so the
		// pipeline routes correctly.
		if outEnv.Method == "" {
			outEnv.Method = requestMethod
		}
		dest := s.upstream.String()
		source := r.RemoteAddr
		res, evalErr := s.opts.Pipeline.EvaluateMCP(
			ctx, outEnv, respBody, event.DirectionOutbound, dest, source,
		)
		if evalErr == nil && res != nil {
			res.Event.AgentRunID = agentRunID
			s.opts.Pipeline.TagMCPResult(outEnv, agentRunID)
			s.opts.Emitter.Emit(res.Event)
			if res.Block {
				blocked, _ := mcp.BlockedResponse(outEnv.ID, res.BlockReason)
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set(headerAgentRunID, agentRunID)
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(blocked)
				return
			}
		}
	}

	copyHeaders(w.Header(), resp.Header)
	w.Header().Set(headerAgentRunID, agentRunID)
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(respBody)
}

// isSSEResponse returns true when the upstream is using Streamable HTTP
// or plain Server-Sent Events. We treat both shapes the same: line-
// oriented `data:` events terminated by blank lines.
func isSSEResponse(resp *http.Response) bool {
	ct := resp.Header.Get("Content-Type")
	return strings.HasPrefix(ct, "text/event-stream")
}

// forwardSSE streams the upstream SSE response to the client, parsing
// each `data:` event as a JSON-RPC envelope, running detection, and
// forwarding (or dropping with a synthetic blocked-event in the
// stream when policy says so).
func (s *Server) forwardSSE(
	ctx context.Context, w http.ResponseWriter, resp *http.Response,
	agentRunID, requestMethod, clientAddr string,
) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported by sensor http server", http.StatusInternalServerError)
		return
	}
	copyHeaders(w.Header(), resp.Header)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set(headerAgentRunID, agentRunID)
	w.WriteHeader(resp.StatusCode)
	flusher.Flush()

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	var dataBuf bytes.Buffer
	flushEvent := func(rawEvent []byte) {
		dataLine := dataBuf.Bytes()
		if len(dataLine) > 0 {
			s.evaluateAndForwardSSEEvent(ctx, w, dataLine, agentRunID, requestMethod, clientAddr, rawEvent, flusher)
		} else if len(rawEvent) > 0 {
			// Pass through non-data lines (event:, id:, retry:) verbatim.
			_, _ = w.Write(rawEvent)
			flusher.Flush()
		}
		dataBuf.Reset()
	}

	var rawEvent bytes.Buffer
	for scanner.Scan() {
		line := scanner.Bytes()
		rawEvent.Write(line)
		rawEvent.WriteByte('\n')
		if len(line) == 0 {
			// Blank line terminates an event.
			rawEvent.WriteByte('\n') // preserve SSE framing on output
			flushEvent(rawEvent.Bytes())
			rawEvent.Reset()
			continue
		}
		if bytes.HasPrefix(line, []byte("data:")) {
			payload := bytes.TrimSpace(bytes.TrimPrefix(line, []byte("data:")))
			if dataBuf.Len() > 0 {
				dataBuf.WriteByte('\n')
			}
			dataBuf.Write(payload)
		}
	}
	// Final flush if the upstream closed without a trailing blank line.
	if rawEvent.Len() > 0 {
		flushEvent(rawEvent.Bytes())
	}
}

// evaluateAndForwardSSEEvent inspects one parsed SSE event payload
// (which should be a JSON-RPC envelope) and either forwards it to
// the client unchanged or replaces it with a blocked-by-policy
// envelope.
func (s *Server) evaluateAndForwardSSEEvent(
	ctx context.Context, w io.Writer, payload []byte,
	agentRunID, requestMethod, clientAddr string,
	rawEvent []byte, flusher http.Flusher,
) {
	env, perr := mcp.Parse(payload)
	if perr != nil {
		_, _ = w.Write(rawEvent)
		flusher.Flush()
		return
	}
	if env.Method == "" {
		env.Method = requestMethod
	}
	res, evalErr := s.opts.Pipeline.EvaluateMCP(
		ctx, env, payload, event.DirectionOutbound, "upstream", clientAddr,
	)
	if evalErr == nil && res != nil {
		res.Event.AgentRunID = agentRunID
		s.opts.Pipeline.TagMCPResult(env, agentRunID)
		s.opts.Emitter.Emit(res.Event)
		if res.Block {
			blocked, _ := mcp.BlockedResponse(env.ID, res.BlockReason)
			fmt.Fprintf(w, "event: hopframe-blocked\ndata: %s\n\n", blocked)
			flusher.Flush()
			return
		}
	}
	_, _ = w.Write(rawEvent)
	flusher.Flush()
}

func (s *Server) emitMalformed(r *http.Request, body []byte, parseErr error) {
	ev := event.New(s.opts.Pipeline.SensorID, event.ProtocolMCP, event.DirectionInbound)
	ev.EventID = "ev-malformed-" + time.Now().UTC().Format("150405.000000")
	ev.TenantID = s.opts.Pipeline.TenantID
	ev.Source = r.RemoteAddr
	ev.Destination = s.upstream.String()
	ev.Message = event.Message{Raw: string(body)}
	ev.Severity = event.SeverityLow
	ev.Findings = []event.Finding{{
		RuleID:      "envelope.malformed",
		Category:    "policy",
		Severity:    event.SeverityLow,
		Description: "MCP envelope failed to parse: " + parseErr.Error(),
	}}
	s.opts.Emitter.Emit(&ev)
}

func copyHeaders(dst, src http.Header) {
	for k, vs := range src {
		// Skip hop-by-hop headers.
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

// MarshalErrorResponse is a small helper used by tests.
func MarshalErrorResponse(id json.RawMessage, msg string) []byte {
	out, _ := mcp.BlockedResponse(id, msg)
	return out
}

// headerAgentRunID is the canonical header name carrying the agent
// run correlation ID. The sensor accepts inbound values from the
// caller and propagates them to the upstream + back to the client.
const headerAgentRunID = "X-Hopframe-Agent-Run-Id"

// agentRunIDFromRequest returns the existing run ID from the request
// header, or generates a new one if absent. The synthetic ID is
// prefixed "run-" so operators can spot generator-vs-caller origins.
func agentRunIDFromRequest(r *http.Request) string {
	if v := r.Header.Get(headerAgentRunID); v != "" {
		return v
	}
	var b [10]byte
	if _, err := cryptoRandRead(b[:]); err == nil {
		return "run-" + hexEncode(b[:])
	}
	return "run-" + time.Now().UTC().Format("20060102T150405.000000")
}
