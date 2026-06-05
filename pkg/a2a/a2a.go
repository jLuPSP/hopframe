// Package a2a defines lightweight types for the Agent-to-Agent
// protocol as Hopframe inspects it. Like pkg/mcp, the goal is to
// understand enough structure to extract inspectable fields and
// validate signed agent cards, we are an inspecting middlebox, not
// an A2A runtime.
//
// The wire shape used here matches the public A2A v1 spec: agent
// cards are JSON descriptors, tasks are JSON-RPC-like envelopes
// posted over HTTP with optional SSE streaming for results.
package a2a

import (
	"encoding/json"
	"errors"
	"fmt"
)

// AgentCard is the discovery descriptor that an A2A peer publishes.
// We model only the fields Hopframe inspects.
type AgentCard struct {
	Name             string         `json:"name"`
	Description      string         `json:"description,omitempty"`
	URL              string         `json:"url,omitempty"`
	Provider         *Provider      `json:"provider,omitempty"`
	Version          string         `json:"version,omitempty"`
	Capabilities     *Capabilities  `json:"capabilities,omitempty"`
	Skills           []Skill        `json:"skills,omitempty"`
	DocumentationURL string         `json:"documentationUrl,omitempty"`
	Authentication   map[string]any `json:"authentication,omitempty"`
	// Signature, when present, is the detached JWS over the canonical
	// JSON of the card with the signature field removed.
	Signature string `json:"signature,omitempty"`
}

// Provider identifies the operator behind the agent.
type Provider struct {
	Organization string `json:"organization,omitempty"`
	URL          string `json:"url,omitempty"`
}

// Capabilities describes optional A2A protocol capabilities.
type Capabilities struct {
	Streaming           bool `json:"streaming,omitempty"`
	PushNotifications   bool `json:"pushNotifications,omitempty"`
	StateTransitionHist bool `json:"stateTransitionHistory,omitempty"`
}

// Skill is a unit of capability the agent advertises.
type Skill struct {
	ID          string   `json:"id,omitempty"`
	Name        string   `json:"name,omitempty"`
	Description string   `json:"description,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	InputModes  []string `json:"inputModes,omitempty"`
	OutputModes []string `json:"outputModes,omitempty"`
}

// TaskEnvelope is the request/response wrapper for A2A task traffic.
// Method names mirror the A2A v1 spec.
type TaskEnvelope struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`
}

// Error is the JSON-RPC error object reused by A2A.
type Error struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// Methods recognized by Hopframe for routing decisions. Other
// methods are passed through unchanged.
const (
	MethodTasksSend          = "tasks/send"
	MethodTasksSendSubscribe = "tasks/sendSubscribe"
	MethodTasksGet           = "tasks/get"
	MethodTasksCancel        = "tasks/cancel"
	MethodTasksPushNotify    = "tasks/pushNotificationConfig/set"
)

// JSONRPCVersion is the A2A wire version.
const JSONRPCVersion = "2.0"

// ParseCard decodes an agent card.
func ParseCard(body []byte) (*AgentCard, error) {
	if len(body) == 0 {
		return nil, errors.New("a2a: empty card body")
	}
	var c AgentCard
	if err := json.Unmarshal(body, &c); err != nil {
		return nil, fmt.Errorf("a2a: parse card: %w", err)
	}
	if c.Name == "" {
		return nil, errors.New("a2a: card missing name")
	}
	return &c, nil
}

// ParseTask decodes a task envelope.
func ParseTask(body []byte) (*TaskEnvelope, error) {
	if len(body) == 0 {
		return nil, errors.New("a2a: empty task body")
	}
	var e TaskEnvelope
	if err := json.Unmarshal(body, &e); err != nil {
		return nil, fmt.Errorf("a2a: parse task: %w", err)
	}
	if e.JSONRPC != "" && e.JSONRPC != JSONRPCVersion {
		return nil, fmt.Errorf("a2a: unsupported jsonrpc version %q", e.JSONRPC)
	}
	return &e, nil
}
