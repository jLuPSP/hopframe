package counterparty

import (
	"testing"
)

func TestObserveAggregates(t *testing.T) {
	r := New()
	r.Observe(Observation{Counterparty: "peer-a", Findings: 1, Action: "warn", Severity: "high"})
	r.Observe(Observation{Counterparty: "peer-a", Findings: 2, Action: "block", Severity: "critical"})
	r.Observe(Observation{Counterparty: "peer-b", Findings: 0, Action: "allow", Severity: "info"})

	a, ok := r.Get("peer-a")
	if !ok {
		t.Fatalf("missing peer-a")
	}
	if a.Requests != 2 || a.Findings != 3 || a.Warnings != 1 || a.Blocks != 1 {
		t.Fatalf("a stats = %+v", a)
	}
	if a.RiskScore <= 0 {
		t.Fatalf("expected positive risk score, got %v", a.RiskScore)
	}

	list := r.List(0)
	if len(list) != 2 {
		t.Fatalf("list len = %d", len(list))
	}
	if list[0].ID != "peer-a" {
		t.Fatalf("expected peer-a first, got %s", list[0].ID)
	}
}

func TestObserveCrossesThreshold(t *testing.T) {
	r := New()
	// One critical+block sits just below the threshold (9), two crosses.
	_, a1 := r.Observe(Observation{Counterparty: "peer-x", Findings: 1, Action: "block", Severity: "critical"})
	if a1 != nil {
		t.Fatalf("did not expect alarm on first obs (score below threshold), got %+v", a1)
	}
	_, a2 := r.Observe(Observation{Counterparty: "peer-x", Findings: 1, Action: "block", Severity: "critical"})
	if a2 == nil || a2.Code != "counterparty.risk_threshold" {
		t.Fatalf("expected risk threshold alarm on second obs, got %+v", a2)
	}
	// Third should NOT re-fire (already above).
	_, a3 := r.Observe(Observation{Counterparty: "peer-x", Findings: 1, Action: "block", Severity: "critical"})
	if a3 != nil {
		t.Fatalf("did not expect repeat alarm, got %+v", a3)
	}
}
