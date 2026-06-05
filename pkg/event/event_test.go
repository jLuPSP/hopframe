package event

import (
	"encoding/json"
	"testing"
)

func TestNewSetsDefaults(t *testing.T) {
	ev := New("sensor-1", ProtocolMCP, DirectionInbound)
	if ev.Schema != SchemaVersion {
		t.Fatalf("schema = %q, want %q", ev.Schema, SchemaVersion)
	}
	if ev.SensorID != "sensor-1" {
		t.Fatalf("sensor id = %q", ev.SensorID)
	}
	if ev.Action != ActionAllow {
		t.Fatalf("default action = %q, want %q", ev.Action, ActionAllow)
	}
	if ev.Timestamp.IsZero() {
		t.Fatalf("timestamp not populated")
	}
}

func TestEventRoundTripsJSON(t *testing.T) {
	ev := New("s", ProtocolMCP, DirectionOutbound)
	ev.EventID = "ev-x"
	ev.Findings = []Finding{{
		RuleID:   "pi.test",
		Category: "prompt-injection",
		Severity: SeverityHigh,
	}}
	ev.Action = ActionWarn
	ev.Severity = SeverityHigh

	body, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out Event
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.EventID != "ev-x" || len(out.Findings) != 1 || out.Findings[0].RuleID != "pi.test" {
		t.Fatalf("roundtrip mismatch: %+v", out)
	}
}
