package store

import "time"

// cacheSnapshot returns a defensive copy of the Postgres backend's
// in-memory cache. Symmetric with (*Store).cacheSnapshot so the
// analytics helpers in analytics.go / counterparty.go / metrics.go
// work over either backend without modification.
func (s *PGStore) cacheSnapshot() []Record {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Record, len(s.cache))
	copy(out, s.cache)
	return out
}

func (s *PGStore) ToolRisk(limit int) []ToolRisk {
	return toolRiskFromRecords(s.cacheSnapshot(), limit)
}

func (s *PGStore) AgentActivity(limit int) []AgentActivity {
	return agentActivityFromRecords(s.cacheSnapshot(), limit)
}

func (s *PGStore) CategoryCounts() []CategoryCount {
	return categoryCountsFromRecords(s.cacheSnapshot())
}

func (s *PGStore) CounterpartyRisks(limit int) []CounterpartyRisk {
	return counterpartyRisksFromRecords(s.cacheSnapshot(), limit)
}

func (s *PGStore) TaskConcerns(limit int) []TaskFindingSummary {
	return taskConcernsFromRecords(s.cacheSnapshot(), limit)
}

func (s *PGStore) Histogram(window, bucket time.Duration) Histogram {
	return histogramFromRecords(s.cacheSnapshot(), window, bucket)
}

func (s *PGStore) Metrics(window, bucket time.Duration) Metrics {
	return metricsFromRecords(s.cacheSnapshot(), window, bucket)
}

// Compile-time assertion: *PGStore satisfies the full AnalyticsStore
// interface. If a future analytics method is added to AnalyticsStore
// without a Postgres equivalent here, the build breaks.
var _ AnalyticsStore = (*PGStore)(nil)
