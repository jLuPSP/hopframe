// Package counterparty maintains a per-peer reputation table for A2A
// traffic. The PRD calls for "cross-org request fingerprinting:
// per-counterparty risk scores based on observed behavior across the
// deployment." This is the in-sensor primitive behind that.
//
// Identity sources, in priority order, used by the proxy:
//
//  1. X-Hopframe-Counterparty header (operator-supplied label)
//  2. agent card provider.organization observed during discovery
//  3. remote address as a coarse fallback
//
// The registry tracks aggregate counts, recent severities, and a
// rolling risk score that increases on findings/blocks and decays
// over time. It is in-process; Phase 3 will sync to the control
// plane so scores are consistent across replicas.
package counterparty

import (
	"sort"
	"sync"
	"time"
)

// Severity bucket weights used to compute the risk score increment.
const (
	weightInfo     = 0.0
	weightLow      = 0.25
	weightMedium   = 1.0
	weightHigh     = 2.5
	weightCritical = 5.0
	weightBlock    = 4.0
	decayPerHour   = 0.5
)

// Entry is the per-counterparty record.
type Entry struct {
	ID           string    `json:"id"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
	Requests     int       `json:"requests"`
	Findings     int       `json:"findings"`
	Warnings     int       `json:"warnings"`
	Blocks       int       `json:"blocks"`
	RiskScore    float64   `json:"risk_score"`
	LastSeverity string    `json:"last_severity,omitempty"`
}

// Observation is what the proxy reports per request.
type Observation struct {
	Counterparty string
	Findings     int
	Action       string // "allow" | "warn" | "block"
	Severity     string // "info"|"low"|"medium"|"high"|"critical"
}

// Registry is concurrent counterparty state.
type Registry struct {
	mu      sync.Mutex
	entries map[string]*Entry
}

// New returns an empty Registry.
func New() *Registry {
	return &Registry{entries: make(map[string]*Entry)}
}

// Observe merges a new request outcome into the registry. Returns
// the updated Entry and a finding if the score crossed an alarming
// threshold during this update.
type Alarm struct {
	Code    string
	Message string
}

// Observe merges a new observation. Returns the updated entry and
// (optionally) a single Alarm raised during this update.
func (r *Registry) Observe(o Observation) (*Entry, *Alarm) {
	if o.Counterparty == "" {
		return nil, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now().UTC()

	e, ok := r.entries[o.Counterparty]
	if !ok {
		e = &Entry{
			ID:        o.Counterparty,
			FirstSeen: now,
		}
		r.entries[o.Counterparty] = e
	}
	// Decay the existing score by elapsed time since LastSeen.
	if !e.LastSeen.IsZero() {
		hours := now.Sub(e.LastSeen).Hours()
		if hours > 0 {
			e.RiskScore *= decayFactor(hours)
		}
	}
	e.LastSeen = now
	e.Requests++
	e.Findings += o.Findings
	switch o.Action {
	case "warn":
		e.Warnings++
	case "block":
		e.Blocks++
	}
	if o.Severity != "" {
		e.LastSeverity = o.Severity
	}
	e.RiskScore += severityWeight(o.Severity) + actionWeight(o.Action)

	var alarm *Alarm
	if e.RiskScore >= 10 && (e.RiskScore-severityWeight(o.Severity)-actionWeight(o.Action) < 10) {
		alarm = &Alarm{
			Code:    "counterparty.risk_threshold",
			Message: "counterparty " + o.Counterparty + " crossed risk threshold (10)",
		}
	}
	return e, alarm
}

// List returns every counterparty sorted by descending risk score.
func (r *Registry) List(limit int) []Entry {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Entry, 0, len(r.entries))
	for _, e := range r.entries {
		out = append(out, *e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RiskScore > out[j].RiskScore })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// Get returns the entry for id if present.
func (r *Registry) Get(id string) (Entry, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.entries[id]
	if !ok {
		return Entry{}, false
	}
	return *e, true
}

// Len returns the count of tracked counterparties.
func (r *Registry) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.entries)
}

func severityWeight(s string) float64 {
	switch s {
	case "low":
		return weightLow
	case "medium":
		return weightMedium
	case "high":
		return weightHigh
	case "critical":
		return weightCritical
	default:
		return weightInfo
	}
}

func actionWeight(a string) float64 {
	if a == "block" {
		return weightBlock
	}
	return 0
}

func decayFactor(hours float64) float64 {
	// Half-life-ish: score halves every 1/decayPerHour hours.
	f := 1.0 - decayPerHour*hours
	if f < 0 {
		return 0
	}
	return f
}
