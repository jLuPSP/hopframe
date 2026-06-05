package store

import (
	"path/filepath"
	"testing"

	"github.com/jlupsp/hopframe/pkg/event"
)

func toolCallEvent(tool string, action event.Action, sev event.Severity, dir event.Direction) *event.Event {
	ev := event.New("s", event.ProtocolMCP, dir)
	ev.Action = action
	ev.Severity = sev
	ev.Message.Method = "tools/call"
	ev.Message.Params = map[string]any{"name": tool}
	return &ev
}

func TestToolRiskRanksByBlocksAndFindings(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(filepath.Join(dir, "log.ndjson"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	// Tool "alpha": 3 calls, 2 blocks. Tool "beta": 5 calls, 0 blocks.
	for i := 0; i < 3; i++ {
		ev := toolCallEvent("alpha", event.ActionAllow, event.SeverityLow, event.DirectionInbound)
		if i < 2 {
			ev.Action = event.ActionBlock
			ev.Findings = []event.Finding{{RuleID: "x", Category: "credential-exfiltration", Severity: event.SeverityHigh}}
		}
		_, _ = st.Append(ev)
	}
	for i := 0; i < 5; i++ {
		_, _ = st.Append(toolCallEvent("beta", event.ActionAllow, event.SeverityLow, event.DirectionInbound))
	}

	risks := st.ToolRisk(10)
	if len(risks) != 2 {
		t.Fatalf("got %d risks, want 2", len(risks))
	}
	if risks[0].Tool != "alpha" {
		t.Fatalf("expected alpha first, got %+v", risks)
	}
	if risks[0].Blocks != 2 {
		t.Fatalf("alpha blocks = %d", risks[0].Blocks)
	}
	if risks[0].RiskScore <= risks[1].RiskScore {
		t.Fatalf("expected alpha risk score > beta")
	}
}

func TestAgentActivityGroupsByRunID(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(filepath.Join(dir, "log.ndjson"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	runs := []struct {
		id     string
		count  int
		blocks int
	}{
		{"agent-1", 5, 1},
		{"agent-2", 2, 0},
	}
	for _, r := range runs {
		for i := 0; i < r.count; i++ {
			ev := toolCallEvent("echo", event.ActionAllow, event.SeverityLow, event.DirectionInbound)
			ev.AgentRunID = r.id
			if i < r.blocks {
				ev.Action = event.ActionBlock
				ev.Severity = event.SeverityHigh
				ev.Findings = []event.Finding{{Category: "prompt-injection"}}
			}
			_, _ = st.Append(ev)
		}
	}
	activity := st.AgentActivity(10)
	if len(activity) != 2 {
		t.Fatalf("expected 2 agents, got %d", len(activity))
	}
	got := map[string]AgentActivity{}
	for _, a := range activity {
		got[a.AgentRunID] = a
	}
	if got["agent-1"].Events != 5 || got["agent-1"].Blocks != 1 {
		t.Fatalf("agent-1 stats = %+v", got["agent-1"])
	}
	if len(got["agent-1"].Categories) != 1 || got["agent-1"].Categories[0] != "prompt-injection" {
		t.Fatalf("agent-1 categories = %+v", got["agent-1"].Categories)
	}
}

func TestCategoryCountsAggregatesAcrossEvents(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(filepath.Join(dir, "log.ndjson"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()
	ev := event.New("s", event.ProtocolMCP, event.DirectionInbound)
	ev.Findings = []event.Finding{
		{Category: "prompt-injection"},
		{Category: "prompt-injection"},
		{Category: "credential-exfiltration"},
	}
	_, _ = st.Append(&ev)
	cats := st.CategoryCounts()
	if len(cats) != 2 {
		t.Fatalf("got %d cats", len(cats))
	}
	if cats[0].Category != "prompt-injection" || cats[0].Count != 2 {
		t.Fatalf("top category = %+v", cats[0])
	}
}
