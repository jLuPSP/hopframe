// Package mcp defines lightweight types and helpers for parsing the
// JSON-RPC 2.0 envelope used by the Model Context Protocol.
//
// We keep these intentionally minimal: we are an inspecting middlebox,
// not an MCP runtime. We need to identify the method, peek at params or
// result, and forward the bytes downstream unchanged. We never speak MCP
// on our own behalf.
package mcp

import (
	"encoding/json"
	"errors"
	"fmt"
)

// JSONRPCVersion is the version string the MCP wire protocol carries.
const JSONRPCVersion = "2.0"

// Methods enumerates the MCP methods we recognize for routing
// decisions. Other methods are passed through unchanged but still
// inspected by detection rules with empty `targets`.
const (
	MethodInitialize         = "initialize"
	MethodInitialized        = "initialized"
	MethodToolsList          = "tools/list"
	MethodToolsCall          = "tools/call"
	MethodResourcesList      = "resources/list"
	MethodResourcesRead      = "resources/read"
	MethodResourcesSubscribe = "resources/subscribe"
	MethodResourcesUnsub     = "resources/unsubscribe"
	MethodResourceTemplates  = "resources/templates/list"
	MethodPromptsList        = "prompts/list"
	MethodPromptsGet         = "prompts/get"
	MethodCompletionComplete = "completion/complete"
	MethodLoggingSetLevel    = "logging/setLevel"
	MethodRootsList          = "roots/list"
	MethodSamplingCreate     = "sampling/createMessage"
	MethodElicitationCreate  = "elicitation/create"
	// Notifications are server- or client-initiated and have no id.
	MethodNotifyCancelled       = "notifications/cancelled"
	MethodNotifyProgress        = "notifications/progress"
	MethodNotifyMessage         = "notifications/message"
	MethodNotifyResourcesUpdate = "notifications/resources/updated"
	MethodNotifyResourcesList   = "notifications/resources/list_changed"
	MethodNotifyToolsList       = "notifications/tools/list_changed"
	MethodNotifyPromptsList     = "notifications/prompts/list_changed"
	MethodNotifyRootsList       = "notifications/roots/list_changed"
)

// Envelope is the JSON-RPC 2.0 envelope used by MCP. Either Method (request
// or notification) is set, or Result/Error (response) is set.
type Envelope struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`
}

// Error is the JSON-RPC error object.
type Error struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// Standard JSON-RPC error codes plus MCP-specific extensions used by Hopframe.
const (
	ErrCodeParseError     = -32700
	ErrCodeInvalidRequest = -32600
	ErrCodeMethodNotFound = -32601
	ErrCodeInvalidParams  = -32602
	ErrCodeInternalError  = -32603

	// ErrCodeBlockedByPolicy is the code Hopframe returns when a message is
	// blocked by a sensor policy. Chosen in the MCP server-defined range.
	ErrCodeBlockedByPolicy = -32001
)

// IsRequest reports whether the envelope is a request (has Method and ID).
func (e *Envelope) IsRequest() bool {
	return e.Method != "" && len(e.ID) > 0
}

// IsNotification reports whether the envelope is a notification (Method, no ID).
func (e *Envelope) IsNotification() bool {
	return e.Method != "" && len(e.ID) == 0
}

// IsResponse reports whether the envelope is a response (no Method, has ID).
func (e *Envelope) IsResponse() bool {
	return e.Method == "" && len(e.ID) > 0
}

// Parse decodes a JSON-RPC envelope.
func Parse(data []byte) (*Envelope, error) {
	if len(data) == 0 {
		return nil, errors.New("mcp: empty body")
	}
	var env Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("mcp: parse envelope: %w", err)
	}
	if env.JSONRPC != "" && env.JSONRPC != JSONRPCVersion {
		return nil, fmt.Errorf("mcp: unsupported jsonrpc version %q", env.JSONRPC)
	}
	return &env, nil
}

// ParseBatch decodes JSON-RPC 2.0 batched calls. The wire form is a
// top-level array of envelopes. Returns the slice and an isBatch flag.
// On a single (non-array) message, returns one envelope with isBatch=false.
//
// JSON-RPC 2.0 spec section 6: "To send several Request objects at the
// same time, the Client MAY send an Array filled with Request objects."
// MCP inherits this so detection has to apply per element.
func ParseBatch(data []byte) ([]*Envelope, bool, error) {
	if len(data) == 0 {
		return nil, false, errors.New("mcp: empty body")
	}
	// Skip leading whitespace to detect batch.
	i := 0
	for i < len(data) && (data[i] == ' ' || data[i] == '\t' || data[i] == '\n' || data[i] == '\r') {
		i++
	}
	if i < len(data) && data[i] == '[' {
		var raws []json.RawMessage
		if err := json.Unmarshal(data, &raws); err != nil {
			return nil, true, fmt.Errorf("mcp: parse batch: %w", err)
		}
		envs := make([]*Envelope, 0, len(raws))
		for j, raw := range raws {
			env, err := Parse(raw)
			if err != nil {
				return envs, true, fmt.Errorf("mcp: batch[%d]: %w", j, err)
			}
			envs = append(envs, env)
		}
		return envs, true, nil
	}
	env, err := Parse(data)
	if err != nil {
		return nil, false, err
	}
	return []*Envelope{env}, false, nil
}

// IsNotificationMethod returns true for methods that do not expect a
// response (no id on the wire). Used by the proxy to know whether to
// wait for an upstream reply.
func IsNotificationMethod(method string) bool {
	if method == "" {
		return false
	}
	if len(method) >= len("notifications/") && method[:len("notifications/")] == "notifications/" {
		return true
	}
	return false
}

// ToolCallParams is the params object for tools/call.
type ToolCallParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments,omitempty"`
}

// ToolDescription is the shape returned by tools/list for each tool.
type ToolDescription struct {
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	InputSchema map[string]any `json:"inputSchema,omitempty"`
}

// ToolsListResult is the result payload of tools/list.
type ToolsListResult struct {
	Tools []ToolDescription `json:"tools"`
}

// DecodeToolCallParams parses the params field of a tools/call request.
func (e *Envelope) DecodeToolCallParams() (*ToolCallParams, error) {
	if e.Method != MethodToolsCall {
		return nil, fmt.Errorf("mcp: expected method %q, got %q", MethodToolsCall, e.Method)
	}
	if len(e.Params) == 0 {
		return nil, errors.New("mcp: tools/call missing params")
	}
	var p ToolCallParams
	if err := json.Unmarshal(e.Params, &p); err != nil {
		return nil, fmt.Errorf("mcp: decode tools/call params: %w", err)
	}
	if p.Name == "" {
		return nil, errors.New("mcp: tools/call missing name")
	}
	return &p, nil
}

// DecodeToolsListResult parses the result field of a tools/list response.
func (e *Envelope) DecodeToolsListResult() (*ToolsListResult, error) {
	if len(e.Result) == 0 {
		return nil, errors.New("mcp: empty result")
	}
	var r ToolsListResult
	if err := json.Unmarshal(e.Result, &r); err != nil {
		return nil, fmt.Errorf("mcp: decode tools/list result: %w", err)
	}
	return &r, nil
}

// BlockedResponse builds a JSON-RPC response indicating the request was
// blocked by Hopframe policy. The ID is preserved so the MCP client can
// correlate the blocked response with its outstanding request.
func BlockedResponse(id json.RawMessage, reason string) ([]byte, error) {
	if reason == "" {
		reason = "blocked by hopframe policy"
	}
	resp := Envelope{
		JSONRPC: JSONRPCVersion,
		ID:      id,
		Error: &Error{
			Code:    ErrCodeBlockedByPolicy,
			Message: reason,
		},
	}
	return json.Marshal(resp)
}
