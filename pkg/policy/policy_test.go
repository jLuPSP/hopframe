package policy

import (
	"testing"

	"github.com/jlupsp/hopframe/pkg/detect"
	"github.com/jlupsp/hopframe/pkg/event"
)

func TestSpecificityOrders(t *testing.T) {
	cases := []struct {
		name string
		s    Scope
		want int
	}{
		{"org", Scope{}, 0},
		{"tenant only", Scope{TenantID: "a"}, 1},
		{"sensor only", Scope{SensorID: "s"}, 2},
		{"server only", Scope{ServerName: "x"}, 4},
		{"tenant + sensor", Scope{TenantID: "a", SensorID: "s"}, 3},
		{"server + tenant", Scope{TenantID: "a", ServerName: "x"}, 5},
		{"all three", Scope{TenantID: "a", SensorID: "s", ServerName: "x"}, 7},
	}
	for _, c := range cases {
		if got := c.s.Specificity(); got != c.want {
			t.Errorf("%s: got %d want %d", c.name, got, c.want)
		}
	}
}

func TestResolveFallsBackWithNoPolicies(t *testing.T) {
	v := &detect.Verdict{Findings: []event.Finding{{RuleID: "r1", Category: "c", Severity: event.SeverityHigh}}}
	mode, p := Resolve(nil, EventContext{TenantID: "a"}, v, detect.ModeWarn)
	if mode != detect.ModeWarn {
		t.Fatalf("got mode %q, want warn (default)", mode)
	}
	if p != nil {
		t.Fatalf("expected nil policy, got %+v", p)
	}
}

func TestResolveMostSpecificWins(t *testing.T) {
	policies := []Policy{
		{
			ID: "org", Name: "org default", Enabled: true,
			Disposition: Disposition{Mode: detect.ModeMonitor},
		},
		{
			ID: "tenantA", Name: "tenant A", Enabled: true,
			Scope:       Scope{TenantID: "A"},
			Disposition: Disposition{Mode: detect.ModeWarn},
		},
		{
			ID: "tenantA-server-foo", Name: "server foo on A", Enabled: true,
			Scope:       Scope{TenantID: "A", ServerName: "foo"},
			Disposition: Disposition{Mode: detect.ModeBlock},
		},
	}
	v := &detect.Verdict{Findings: []event.Finding{{RuleID: "r1", Category: "c", Severity: event.SeverityHigh}}}

	mode, p := Resolve(policies, EventContext{TenantID: "A", ServerName: "foo"}, v, detect.ModeMonitor)
	if mode != detect.ModeBlock {
		t.Fatalf("expected block, got %q", mode)
	}
	if p == nil || p.ID != "tenantA-server-foo" {
		t.Fatalf("expected winner tenantA-server-foo, got %+v", p)
	}

	mode, p = Resolve(policies, EventContext{TenantID: "A", ServerName: "bar"}, v, detect.ModeMonitor)
	if mode != detect.ModeWarn {
		t.Fatalf("expected warn (tenant A on bar), got %q", mode)
	}
	if p == nil || p.ID != "tenantA" {
		t.Fatalf("expected winner tenantA, got %+v", p)
	}

	mode, p = Resolve(policies, EventContext{TenantID: "B", ServerName: "anything"}, v, detect.ModeMonitor)
	if mode != detect.ModeMonitor {
		t.Fatalf("expected monitor (org default), got %q", mode)
	}
	if p == nil || p.ID != "org" {
		t.Fatalf("expected winner org, got %+v", p)
	}
}

func TestResolveSelectorFiltersByCategory(t *testing.T) {
	policies := []Policy{
		{
			ID: "block-tp", Name: "block tool poisoning", Enabled: true,
			Selector:    Selector{Categories: []string{"tool-poisoning"}},
			Disposition: Disposition{Mode: detect.ModeBlock},
		},
	}
	pi := &detect.Verdict{Findings: []event.Finding{{Category: "prompt-injection", Severity: event.SeverityHigh}}}
	tp := &detect.Verdict{Findings: []event.Finding{{Category: "tool-poisoning", Severity: event.SeverityHigh}}}

	if mode, _ := Resolve(policies, EventContext{}, pi, detect.ModeMonitor); mode != detect.ModeMonitor {
		t.Fatalf("expected monitor on prompt-injection finding, got %q", mode)
	}
	if mode, _ := Resolve(policies, EventContext{}, tp, detect.ModeMonitor); mode != detect.ModeBlock {
		t.Fatalf("expected block on tool-poisoning finding, got %q", mode)
	}
}

func TestResolveStrongerModeWinsAtSameSpecificity(t *testing.T) {
	policies := []Policy{
		{ID: "p1", Name: "warn", Enabled: true, Disposition: Disposition{Mode: detect.ModeWarn}},
		{ID: "p2", Name: "block", Enabled: true, Disposition: Disposition{Mode: detect.ModeBlock}},
	}
	v := &detect.Verdict{Findings: []event.Finding{{Severity: event.SeverityHigh}}}
	mode, _ := Resolve(policies, EventContext{}, v, detect.ModeMonitor)
	if mode != detect.ModeBlock {
		t.Fatalf("expected block (stronger mode wins at same specificity), got %q", mode)
	}
}

func TestResolveDisabledPolicyIgnored(t *testing.T) {
	policies := []Policy{
		{ID: "p1", Name: "blocked-but-disabled", Enabled: false, Disposition: Disposition{Mode: detect.ModeBlock}},
	}
	v := &detect.Verdict{Findings: []event.Finding{{Severity: event.SeverityHigh}}}
	mode, p := Resolve(policies, EventContext{}, v, detect.ModeMonitor)
	if mode != detect.ModeMonitor || p != nil {
		t.Fatalf("disabled policy should not match, got %q / %+v", mode, p)
	}
}

func TestResolveMinSeverityFilters(t *testing.T) {
	policies := []Policy{
		{
			ID: "block-high", Name: "block high+", Enabled: true,
			Selector:    Selector{MinSeverity: event.SeverityHigh},
			Disposition: Disposition{Mode: detect.ModeBlock},
		},
	}
	low := &detect.Verdict{Findings: []event.Finding{{Severity: event.SeverityLow}}}
	high := &detect.Verdict{Findings: []event.Finding{{Severity: event.SeverityHigh}}}
	if mode, _ := Resolve(policies, EventContext{}, low, detect.ModeMonitor); mode != detect.ModeMonitor {
		t.Fatalf("low severity should not match, got %q", mode)
	}
	if mode, _ := Resolve(policies, EventContext{}, high, detect.ModeMonitor); mode != detect.ModeBlock {
		t.Fatalf("high severity should match, got %q", mode)
	}
}

func TestValidateRejectsBadMode(t *testing.T) {
	bad := Policy{ID: "p", Name: "x", Disposition: Disposition{Mode: detect.Mode("nope")}}
	if err := bad.Validate(); err == nil {
		t.Fatal("expected validate to fail on unknown mode")
	}
	good := Policy{ID: "p", Name: "x", Disposition: Disposition{Mode: detect.ModeBlock}}
	if err := good.Validate(); err != nil {
		t.Fatalf("good policy should validate, got %v", err)
	}
}

func TestNewIDIsSortable(t *testing.T) {
	a := NewID()
	b := NewID()
	if a == b {
		t.Fatalf("NewID returned duplicate %q", a)
	}
	// crude: ids should have the prefix and be different lengths only
	// in extreme entropy edge cases.
	if len(a) < 20 {
		t.Fatalf("NewID looks too short: %q", a)
	}
}
