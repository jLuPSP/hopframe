// Package quarantine tracks tool names that the sensor has decided to
// auto-block on subsequent tools/call traffic. Entries are added when a
// tools/list response triggers a high-confidence finding against the
// tool description. The PRD calls for this as a Phase 1 deliverable.
//
// Quarantine state is in-process and ephemeral: restarting the sensor
// clears it. Phase 2 will sync state to the control plane so the
// quarantine is consistent across replicas.
package quarantine

import (
	"sync"
	"time"
)

// Entry records why a tool was quarantined and when it expires.
type Entry struct {
	Tool      string    `json:"tool"`
	Reason    string    `json:"reason"`
	RuleID    string    `json:"rule_id,omitempty"`
	Severity  string    `json:"severity,omitempty"`
	AddedAt   time.Time `json:"added_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Set is a concurrent quarantine table.
type Set struct {
	mu      sync.RWMutex
	ttl     time.Duration
	entries map[string]Entry
}

// New returns a Set with the given default TTL. ttl <= 0 means entries
// never expire automatically.
func New(ttl time.Duration) *Set {
	return &Set{ttl: ttl, entries: make(map[string]Entry)}
}

// Quarantine adds or refreshes an entry for tool.
func (s *Set) Quarantine(tool, reason, ruleID, severity string) Entry {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	exp := time.Time{}
	if s.ttl > 0 {
		exp = now.Add(s.ttl)
	}
	e := Entry{
		Tool:      tool,
		Reason:    reason,
		RuleID:    ruleID,
		Severity:  severity,
		AddedAt:   now,
		ExpiresAt: exp,
	}
	s.entries[tool] = e
	return e
}

// Lookup returns the entry for tool if it is currently quarantined.
func (s *Set) Lookup(tool string) (Entry, bool) {
	s.mu.RLock()
	e, ok := s.entries[tool]
	s.mu.RUnlock()
	if !ok {
		return Entry{}, false
	}
	if !e.ExpiresAt.IsZero() && time.Now().UTC().After(e.ExpiresAt) {
		s.mu.Lock()
		delete(s.entries, tool)
		s.mu.Unlock()
		return Entry{}, false
	}
	return e, true
}

// Clear removes an entry. Returns true if a record was removed.
func (s *Set) Clear(tool string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.entries[tool]
	if ok {
		delete(s.entries, tool)
	}
	return ok
}

// List returns every active entry. Expired entries are pruned in passing.
func (s *Set) List() []Entry {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	out := make([]Entry, 0, len(s.entries))
	for tool, e := range s.entries {
		if !e.ExpiresAt.IsZero() && now.After(e.ExpiresAt) {
			delete(s.entries, tool)
			continue
		}
		out = append(out, e)
	}
	return out
}

// Len returns the active entry count.
func (s *Set) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.entries)
}
