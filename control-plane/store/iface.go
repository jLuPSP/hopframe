package store

import (
	"context"
	"time"

	"github.com/jlupsp/hopframe/pkg/event"
)

// EventStore is the interface every audit-chain backend satisfies.
// The control plane wires its API handlers against this interface so a
// future Postgres or ClickHouse implementation can drop in without
// touching the request path.
//
// Today the only implementation is the file-backed *Store in this
// package. A Postgres implementation lands in a follow-up; selection
// is via the DSN passed to Open: a "postgres://..." URL routes to the
// Postgres backend, anything else is treated as a file path.
//
// Conformance: each method's contract is the same one *Store
// implements today. Implementations must:
//
//   - Linearize Append. The chain is single-writer per record; two
//     concurrent Appends must produce sequential, non-overlapping seqs
//     and a valid prev/curr hash chain.
//   - Re-walk on open or on Verify. Tampering must be detectable
//     before the next Append.
//   - Honor TenantID scoping in Query. When TenantID is non-empty,
//     reads filter to records whose event.tenant_id matches exactly.
//   - Be safe for concurrent Reads alongside an Append in flight.
type EventStore interface {
	// Append commits the event to the chain and returns the
	// fully-formed Record (seq, prev_hash, hash, ingest_at).
	Append(ev *event.Event) (*Record, error)

	// Read returns up to q.Limit recent records that match the filter,
	// newest-first. Implementations may serve from cache plus on-disk
	// or DB-backed storage; callers must not assume a single source.
	Read(q Query) ([]Record, error)

	// Stats returns chain head metadata (seq, head hash, backing
	// identifier such as a file path or DSN).
	Stats() Stats

	// Verify re-walks the chain end-to-end and returns the offending
	// Record on the first mismatch. Returns nil on a clean chain.
	Verify() (*Record, error)

	// Timeline returns every cached record for the given agent_run_id
	// in ascending seq order. Used by the per-run forensic view.
	Timeline(agentRunID, tenantID string) []Record

	// Rotate enforces retention. Records older than the configured
	// window are dropped; the surviving prefix is preserved with an
	// updated chain-start anchor.
	Rotate() (kept, dropped int, err error)

	// RunRetention starts a background ticker that calls Rotate on
	// the configured interval. Stops on ctx cancellation.
	RunRetention(ctx context.Context, every time.Duration)

	// Close releases backing resources (file handles, DB connections).
	Close() error
}

// AnalyticsStore extends EventStore with the read-side aggregations
// the operator UI consumes (top tools, agent activity, category mix,
// counterparty risk, histogram, time-series metrics). These are split
// out so a backend can satisfy EventStore alone for a minimal
// "ingest + verify" deployment, and grow into AnalyticsStore when the
// UI is wired up.
type AnalyticsStore interface {
	EventStore

	ToolRisk(limit int) []ToolRisk
	AgentActivity(limit int) []AgentActivity
	CategoryCounts() []CategoryCount
	CounterpartyRisks(limit int) []CounterpartyRisk
	TaskConcerns(limit int) []TaskFindingSummary
	Histogram(window, bucket time.Duration) Histogram
	Metrics(window, bucket time.Duration) Metrics
}

// Compile-time assertion that the file-backed *Store satisfies the
// full AnalyticsStore interface. Removing a method from *Store or
// breaking a signature breaks the build, which is the point.
var _ AnalyticsStore = (*Store)(nil)
