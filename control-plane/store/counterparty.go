package store

import (
	"sort"

	"github.com/jlupsp/hopframe/pkg/event"
)

// CounterpartyRisk aggregates events by their event.Counterparty
// field. Used by the UI to surface cross-org risk.
type CounterpartyRisk struct {
	Counterparty string  `json:"counterparty"`
	Events       int     `json:"events"`
	Findings     int     `json:"findings"`
	Warnings     int     `json:"warnings"`
	Blocks       int     `json:"blocks"`
	RiskScore    float64 `json:"risk_score"`
}

// CounterpartyRisks returns ranked aggregates over the cache.
func (s *Store) CounterpartyRisks(limit int) []CounterpartyRisk {
	return counterpartyRisksFromRecords(s.cacheSnapshot(), limit)
}

func counterpartyRisksFromRecords(records []Record, limit int) []CounterpartyRisk {
	by := make(map[string]*CounterpartyRisk)
	for _, rec := range records {
		ev := rec.Event
		if ev == nil || ev.Counterparty == "" {
			continue
		}
		c := by[ev.Counterparty]
		if c == nil {
			c = &CounterpartyRisk{Counterparty: ev.Counterparty}
			by[ev.Counterparty] = c
		}
		c.Events++
		c.Findings += len(ev.Findings)
		switch ev.Action {
		case event.ActionWarn:
			c.Warnings++
		case event.ActionBlock:
			c.Blocks++
		}
	}
	out := make([]CounterpartyRisk, 0, len(by))
	for _, c := range by {
		c.RiskScore = (float64(c.Blocks)*5 + float64(c.Warnings)*2 + float64(c.Findings)) /
			max1(float64(c.Events))
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RiskScore > out[j].RiskScore })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// TaskFindingSummary tracks recent findings by their task-state rule
// IDs (task.invalid_transition, task.scope_drift, task.counterparty_changed).
type TaskFindingSummary struct {
	TaskID       string `json:"task_id"`
	Counterparty string `json:"counterparty,omitempty"`
	RuleID       string `json:"rule_id"`
	Description  string `json:"description"`
	Seq          uint64 `json:"seq"`
}

// TaskConcerns scans the cache for events containing one of the
// task-state rule IDs and returns them newest-first.
func (s *Store) TaskConcerns(limit int) []TaskFindingSummary {
	return taskConcernsFromRecords(s.cacheSnapshot(), limit)
}

func taskConcernsFromRecords(records []Record, limit int) []TaskFindingSummary {
	out := make([]TaskFindingSummary, 0)
	for i := len(records) - 1; i >= 0; i-- {
		rec := records[i]
		ev := rec.Event
		if ev == nil {
			continue
		}
		for _, f := range ev.Findings {
			switch f.RuleID {
			case "task.invalid_transition", "task.scope_drift", "task.counterparty_changed":
				out = append(out, TaskFindingSummary{
					TaskID:       f.Match,
					Counterparty: ev.Counterparty,
					RuleID:       f.RuleID,
					Description:  f.Description,
					Seq:          rec.Seq,
				})
			}
		}
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out
}

func max1(v float64) float64 {
	if v < 1 {
		return 1
	}
	return v
}
