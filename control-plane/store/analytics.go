package store

import (
	"sort"

	"github.com/jlupsp/hopframe/pkg/event"
)

// ToolRisk aggregates findings keyed by the tool name observed in a
// tools/call message. Used by the UI to highlight which tools have
// the worst signal-to-noise ratio.
type ToolRisk struct {
	Tool       string  `json:"tool"`
	TotalCalls int     `json:"total_calls"`
	Findings   int     `json:"findings"`
	Warnings   int     `json:"warnings"`
	Blocks     int     `json:"blocks"`
	RiskScore  float64 `json:"risk_score"`
}

// AgentActivity summarizes traffic seen for a given agent_run_id.
type AgentActivity struct {
	AgentRunID string   `json:"agent_run_id"`
	Events     int      `json:"events"`
	Findings   int      `json:"findings"`
	Blocks     int      `json:"blocks"`
	Severity   float64  `json:"severity_score"`
	Categories []string `json:"categories"`
}

// CategoryCount is a finding count per detection category.
type CategoryCount struct {
	Category string `json:"category"`
	Count    int    `json:"count"`
}

// cacheSnapshot returns a defensive copy of the file backend's cache.
func (s *Store) cacheSnapshot() []Record {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Record, len(s.cache))
	copy(out, s.cache)
	return out
}

// ToolRisk returns a ranked summary of tools observed in tools/call
// traffic. Limit caps the result; pass 0 for all.
func (s *Store) ToolRisk(limit int) []ToolRisk { return toolRiskFromRecords(s.cacheSnapshot(), limit) }

// AgentActivity returns recent activity bucketed by agent_run_id.
func (s *Store) AgentActivity(limit int) []AgentActivity {
	return agentActivityFromRecords(s.cacheSnapshot(), limit)
}

// CategoryCounts returns finding counts grouped by category.
func (s *Store) CategoryCounts() []CategoryCount {
	return categoryCountsFromRecords(s.cacheSnapshot())
}

// toolRiskFromRecords is the backend-agnostic implementation. Both the
// file and Postgres backends pass in a record slice (cache snapshot).
func toolRiskFromRecords(records []Record, limit int) []ToolRisk {
	by := make(map[string]*ToolRisk)
	for _, rec := range records {
		ev := rec.Event
		if ev == nil || ev.Message.Method != "tools/call" {
			continue
		}
		name := toolNameFromParams(ev.Message.Params)
		if name == "" {
			continue
		}
		t := by[name]
		if t == nil {
			t = &ToolRisk{Tool: name}
			by[name] = t
		}
		if ev.Direction == event.DirectionInbound {
			t.TotalCalls++
		}
		t.Findings += len(ev.Findings)
		switch ev.Action {
		case event.ActionWarn:
			t.Warnings++
		case event.ActionBlock:
			t.Blocks++
		}
	}
	out := make([]ToolRisk, 0, len(by))
	for _, t := range by {
		t.RiskScore = riskScore(*t)
		out = append(out, *t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RiskScore > out[j].RiskScore })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func agentActivityFromRecords(records []Record, limit int) []AgentActivity {
	by := make(map[string]*AgentActivity)
	cats := make(map[string]map[string]struct{})
	sevSum := make(map[string]float64)

	for _, rec := range records {
		ev := rec.Event
		if ev == nil || ev.AgentRunID == "" {
			continue
		}
		a := by[ev.AgentRunID]
		if a == nil {
			a = &AgentActivity{AgentRunID: ev.AgentRunID}
			by[ev.AgentRunID] = a
			cats[ev.AgentRunID] = make(map[string]struct{})
		}
		a.Events++
		a.Findings += len(ev.Findings)
		if ev.Action == event.ActionBlock {
			a.Blocks++
		}
		sevSum[ev.AgentRunID] += severityWeight(ev.Severity)
		for _, f := range ev.Findings {
			if f.Category != "" {
				cats[ev.AgentRunID][f.Category] = struct{}{}
			}
		}
	}

	out := make([]AgentActivity, 0, len(by))
	for id, a := range by {
		if a.Events > 0 {
			a.Severity = sevSum[id] / float64(a.Events)
		}
		a.Categories = make([]string, 0, len(cats[id]))
		for c := range cats[id] {
			a.Categories = append(a.Categories, c)
		}
		sort.Strings(a.Categories)
		out = append(out, *a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Severity > out[j].Severity })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func categoryCountsFromRecords(records []Record) []CategoryCount {
	by := make(map[string]int)
	for _, rec := range records {
		if rec.Event == nil {
			continue
		}
		for _, f := range rec.Event.Findings {
			by[f.Category]++
		}
	}
	out := make([]CategoryCount, 0, len(by))
	for c, n := range by {
		out = append(out, CategoryCount{Category: c, Count: n})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	return out
}

func toolNameFromParams(params map[string]any) string {
	if params == nil {
		return ""
	}
	if v, ok := params["name"].(string); ok {
		return v
	}
	return ""
}

func riskScore(t ToolRisk) float64 {
	if t.TotalCalls == 0 && t.Findings == 0 {
		return 0
	}
	denom := float64(t.TotalCalls)
	if denom == 0 {
		denom = 1
	}
	return (float64(t.Blocks)*5 + float64(t.Warnings)*2 + float64(t.Findings)) / denom
}

func severityWeight(s event.Severity) float64 {
	switch s {
	case event.SeverityCritical:
		return 4
	case event.SeverityHigh:
		return 3
	case event.SeverityMedium:
		return 2
	case event.SeverityLow:
		return 1
	default:
		return 0
	}
}
