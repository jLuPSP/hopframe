// Package event defines the structured event envelope that sensors emit
// to the Hopframe control plane.
//
// An Event captures a single observed protocol message together with the
// detection verdicts produced by the sensor pipeline. Events are designed
// to be append-only, JSON-serializable, and forward-compatible: unknown
// fields on the receiver side are tolerated.
package event

import (
	"time"
)

// Protocol identifies the wire protocol the message was observed on.
type Protocol string

const (
	ProtocolMCP Protocol = "mcp"
	ProtocolA2A Protocol = "a2a"
)

// Direction is the direction of the message relative to the sensor.
type Direction string

const (
	// DirectionInbound is a request received by the sensor from a client.
	DirectionInbound Direction = "inbound"
	// DirectionOutbound is a response returned by the upstream server.
	DirectionOutbound Direction = "outbound"
)

// Action is the policy decision applied to the message.
type Action string

const (
	ActionAllow Action = "allow"
	ActionWarn  Action = "warn"
	ActionBlock Action = "block"
)

// Severity grades the highest-severity finding on the event.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Finding is a single detection match produced by a rule or model.
type Finding struct {
	RuleID      string         `json:"rule_id"`
	Category    string         `json:"category"`
	Severity    Severity       `json:"severity"`
	Description string         `json:"description,omitempty"`
	Match       string         `json:"match,omitempty"`
	Field       string         `json:"field,omitempty"`
	Confidence  float64        `json:"confidence,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
}

// Message captures the protocol message being observed.
//
// For MCP we carry the JSON-RPC envelope fields (Method, Params, Result, Error)
// directly. The raw body is preserved verbatim for forensic replay.
type Message struct {
	ID     string         `json:"id,omitempty"`
	Method string         `json:"method,omitempty"`
	Params map[string]any `json:"params,omitempty"`
	Result map[string]any `json:"result,omitempty"`
	Error  map[string]any `json:"error,omitempty"`
	Raw    string         `json:"raw,omitempty"`
}

// Event is the unit of telemetry sent from a sensor to the control plane.
type Event struct {
	// Schema identifies the envelope version. Bumped on breaking changes.
	Schema    string    `json:"schema"`
	EventID   string    `json:"event_id"`
	Timestamp time.Time `json:"timestamp"`

	SensorID     string `json:"sensor_id"`
	TenantID     string `json:"tenant_id,omitempty"`
	AgentRunID   string `json:"agent_run_id,omitempty"`
	Counterparty string `json:"counterparty,omitempty"`

	Protocol  Protocol  `json:"protocol"`
	Direction Direction `json:"direction"`

	Source      string `json:"source,omitempty"`
	Destination string `json:"destination,omitempty"`

	Message Message `json:"message"`

	Findings []Finding `json:"findings,omitempty"`
	Action   Action    `json:"action"`
	Severity Severity  `json:"severity,omitempty"`

	// LatencyMicros is the wall-clock time the sensor spent on this message.
	LatencyMicros int64 `json:"latency_micros,omitempty"`
}

// SchemaVersion is the current event envelope version.
const SchemaVersion = "hopframe.event/v1"

// New returns an Event populated with defaults appropriate for emitting.
func New(sensorID string, proto Protocol, dir Direction) Event {
	return Event{
		Schema:    SchemaVersion,
		Timestamp: time.Now().UTC(),
		SensorID:  sensorID,
		Protocol:  proto,
		Direction: dir,
		Action:    ActionAllow,
	}
}
