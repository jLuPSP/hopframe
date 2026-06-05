package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/jlupsp/hopframe/pkg/event"
)

// PGStore is the Postgres-backed implementation of AnalyticsStore.
//
// Linearization: every Append takes a SELECT ... FOR UPDATE row lock on
// the singleton chain-head row, computes the new hash from the locked
// prev_hash + new event, INSERTs the event, and UPDATEs the head, all
// in one transaction. Concurrent appenders serialize on the lock, so
// the chain stays linear without serialization-failure retry loops.
//
// Cache: same in-memory cache as the file backend, populated on Append
// and on hot reads. Analytics methods read from the cache because the
// shapes (windowed metrics, sparkline buckets) are awkward to compute
// in SQL on every UI tick. Cold cache on Open: the most recent
// CacheCap records are pulled in.
//
// Compatibility: vanilla Postgres 14+. Cloud SQL, AWS RDS, Azure
// Database for PostgreSQL, Aiven, Neon, and Supabase all expose
// stock Postgres protocol, so any postgres:// or postgresql:// DSN
// pgx accepts works here. Use sslmode=require (or verify-full) in
// the DSN for any non-localhost deployment.
type PGStore struct {
	pool *pgxpool.Pool
	dsn  string

	mu        sync.RWMutex
	cache     []Record
	cacheCap  int
	retention time.Duration
}

// PGOptions configures a Postgres-backed store.
type PGOptions struct {
	// DSN is a Postgres connection string. Examples:
	//   postgres://user:pass@host:5432/dbname?sslmode=require
	//   postgresql://hopframe:secret@cloud-sql:5432/hopframe
	DSN string
	// Retention, when > 0, drops records older than this on rotation.
	Retention time.Duration
	// CacheCap is the in-memory cache size for fast UI reads. Default 1024.
	CacheCap int
}

// schemaSQL is the minimum schema PGStore expects. Idempotent so it
// runs on every Open.
//
// hopframe_events: append-only ledger. seq is the chain index;
// (prev_hash, hash) form the chain.
//
// hopframe_chain_head: singleton row holding the latest (seq, hash)
// plus chain_start (the prev_hash of the oldest surviving record,
// updated by Rotate so retention does not break Verify).
const schemaSQL = `
CREATE TABLE IF NOT EXISTS hopframe_events (
    seq BIGINT PRIMARY KEY,
    ingest_at TIMESTAMPTZ NOT NULL,
    prev_hash CHAR(64) NOT NULL,
    hash CHAR(64) NOT NULL UNIQUE,
    event JSONB NOT NULL,
    tenant_id TEXT,
    agent_run_id TEXT,
    action TEXT,
    severity TEXT,
    method TEXT
);

CREATE INDEX IF NOT EXISTS hopframe_events_ingest_at_idx ON hopframe_events (ingest_at DESC);
CREATE INDEX IF NOT EXISTS hopframe_events_tenant_idx ON hopframe_events (tenant_id) WHERE tenant_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS hopframe_events_agent_run_idx ON hopframe_events (agent_run_id) WHERE agent_run_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS hopframe_events_action_idx ON hopframe_events (action);
CREATE INDEX IF NOT EXISTS hopframe_events_severity_idx ON hopframe_events (severity);

CREATE TABLE IF NOT EXISTS hopframe_chain_head (
    id INT PRIMARY KEY DEFAULT 1,
    seq BIGINT NOT NULL DEFAULT 0,
    head_hash CHAR(64) NOT NULL DEFAULT '0000000000000000000000000000000000000000000000000000000000000000',
    chain_start CHAR(64) NOT NULL DEFAULT '0000000000000000000000000000000000000000000000000000000000000000',
    CONSTRAINT singleton CHECK (id = 1)
);

INSERT INTO hopframe_chain_head (id) VALUES (1) ON CONFLICT DO NOTHING;
`

// OpenPostgres connects to Postgres, applies the schema, and warms
// the in-memory cache.
func OpenPostgres(opts PGOptions) (*PGStore, error) {
	if opts.DSN == "" {
		return nil, errors.New("store: empty Postgres DSN")
	}
	if opts.CacheCap <= 0 {
		opts.CacheCap = 1024
	}
	cfg, err := pgxpool.ParseConfig(opts.DSN)
	if err != nil {
		return nil, fmt.Errorf("store: parse DSN: %w", err)
	}
	if cfg.MaxConns < 4 {
		cfg.MaxConns = 8
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("store: connect Postgres: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("store: ping Postgres: %w", err)
	}
	if _, err := pool.Exec(ctx, schemaSQL); err != nil {
		pool.Close()
		return nil, fmt.Errorf("store: schema: %w", err)
	}
	s := &PGStore{
		pool:      pool,
		dsn:       opts.DSN,
		cacheCap:  opts.CacheCap,
		retention: opts.Retention,
	}
	if err := s.warmCache(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("store: warm cache: %w", err)
	}
	return s, nil
}

// Close releases the connection pool.
func (s *PGStore) Close() error {
	s.pool.Close()
	return nil
}

// Append commits a new event under a row-level lock on the chain head.
// Linearizable: concurrent callers serialize on the lock, so seqs and
// hashes are produced in deterministic order.
func (s *PGStore) Append(ev *event.Event) (*Record, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, fmt.Errorf("store: begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	var headSeq int64
	var headHash string
	if err := tx.QueryRow(ctx, `SELECT seq, head_hash FROM hopframe_chain_head WHERE id = 1 FOR UPDATE`).Scan(&headSeq, &headHash); err != nil {
		return nil, fmt.Errorf("store: lock chain head: %w", err)
	}

	// Truncate to microseconds: Postgres TIMESTAMPTZ stores at usec
	// resolution, not nanosec. If we hash the nanosec-precise time at
	// insert and re-hash the usec-truncated time on Verify, the chain
	// breaks. Truncate up front so the value we hash equals the value
	// Postgres stores. The file backend keeps nanosec precision; this
	// is a Postgres-specific quirk handled in the Postgres backend.
	rec := Record{
		Seq:      uint64(headSeq) + 1,
		IngestAt: time.Now().UTC().Truncate(time.Microsecond),
		PrevHash: headHash,
		Event:    ev,
	}
	rec.Hash = computeHash(rec)

	evJSON, err := json.Marshal(ev)
	if err != nil {
		return nil, err
	}
	tenantID, agentRunID, action, severity, method := indexFields(ev)
	if _, err := tx.Exec(ctx, `
INSERT INTO hopframe_events (seq, ingest_at, prev_hash, hash, event, tenant_id, agent_run_id, action, severity, method)
VALUES ($1, $2, $3, $4, $5::jsonb, NULLIF($6,''), NULLIF($7,''), NULLIF($8,''), NULLIF($9,''), NULLIF($10,''))
`, rec.Seq, rec.IngestAt, rec.PrevHash, rec.Hash, evJSON, tenantID, agentRunID, action, severity, method); err != nil {
		return nil, fmt.Errorf("store: insert event: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE hopframe_chain_head SET seq = $1, head_hash = $2 WHERE id = 1`, rec.Seq, rec.Hash); err != nil {
		return nil, fmt.Errorf("store: update head: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("store: commit append: %w", err)
	}

	s.mu.Lock()
	s.appendCacheLocked(rec)
	s.mu.Unlock()
	return &rec, nil
}

// Stats returns chain head metadata.
func (s *PGStore) Stats() Stats {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var headSeq int64
	var headHash string
	if err := s.pool.QueryRow(ctx, `SELECT seq, head_hash FROM hopframe_chain_head WHERE id = 1`).Scan(&headSeq, &headHash); err != nil {
		return Stats{}
	}
	return Stats{Seq: uint64(headSeq), Path: s.dsn, HeadHash: headHash}
}

// Read returns up to q.Limit records matching the filter. Hot recent
// reads come from the cache; deeper queries fall through to Postgres.
func (s *PGStore) Read(q Query) ([]Record, error) {
	if q.Limit <= 0 {
		q.Limit = 50
	}
	// Fast path: cache covers the request.
	s.mu.RLock()
	cached := append([]Record(nil), s.cache...)
	s.mu.RUnlock()
	out := make([]Record, 0, q.Limit)
	for i := len(cached) - 1; i >= 0; i-- {
		if q.SinceSeq != 0 && cached[i].Seq <= q.SinceSeq {
			break
		}
		if !match(cached[i], q) {
			continue
		}
		out = append(out, cached[i])
		if len(out) >= q.Limit {
			return out, nil
		}
	}
	// Slow path: hit Postgres for records OLDER than the cache covered.
	// Without the seq < min(cache) bound, the SQL query returns the same
	// records the cache already contributed and we double-count.
	args := []any{q.Limit}
	conds := []string{}
	if len(cached) > 0 {
		// cached is in append (ASC) order, so cached[0] is the oldest.
		oldestCacheSeq := cached[0].Seq
		args = append(args, oldestCacheSeq)
		conds = append(conds, fmt.Sprintf("seq < $%d", len(args)))
	}
	if q.TenantID != "" {
		args = append(args, q.TenantID)
		conds = append(conds, fmt.Sprintf("tenant_id = $%d", len(args)))
	}
	if q.Action != "" {
		args = append(args, q.Action)
		conds = append(conds, fmt.Sprintf("action = $%d", len(args)))
	}
	if q.Severity != "" {
		args = append(args, q.Severity)
		conds = append(conds, fmt.Sprintf("severity = $%d", len(args)))
	}
	if q.Method != "" {
		args = append(args, q.Method)
		conds = append(conds, fmt.Sprintf("method = $%d", len(args)))
	}
	if q.SinceSeq != 0 {
		args = append(args, q.SinceSeq)
		conds = append(conds, fmt.Sprintf("seq > $%d", len(args)))
	}
	where := ""
	if len(conds) > 0 {
		where = "WHERE " + strings.Join(conds, " AND ")
	}
	sql := fmt.Sprintf(`SELECT seq, ingest_at, prev_hash, hash, event FROM hopframe_events %s ORDER BY seq DESC LIMIT $1`, where)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	rows, err := s.pool.Query(ctx, sql, args...)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var r Record
		var evJSON []byte
		if err := rows.Scan(&r.Seq, &r.IngestAt, &r.PrevHash, &r.Hash, &evJSON); err != nil {
			return out, err
		}
		var ev event.Event
		if err := json.Unmarshal(evJSON, &ev); err != nil {
			return out, err
		}
		r.Event = &ev
		// Application-side filters that don't have indexed columns
		// (Category, Search, MinSeverity) re-apply here.
		if !match(r, q) {
			continue
		}
		out = append(out, r)
		if len(out) >= q.Limit {
			break
		}
	}
	return out, rows.Err()
}

// Verify re-walks the entire chain and returns the first offending
// record, or nil on a clean chain.
func (s *PGStore) Verify() (*Record, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var chainStart string
	if err := s.pool.QueryRow(ctx, `SELECT chain_start FROM hopframe_chain_head WHERE id = 1`).Scan(&chainStart); err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, `SELECT seq, ingest_at, prev_hash, hash, event FROM hopframe_events ORDER BY seq ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	prev := chainStart
	for rows.Next() {
		var r Record
		var evJSON []byte
		if err := rows.Scan(&r.Seq, &r.IngestAt, &r.PrevHash, &r.Hash, &evJSON); err != nil {
			return nil, err
		}
		var ev event.Event
		if err := json.Unmarshal(evJSON, &ev); err != nil {
			return &r, err
		}
		r.Event = &ev
		if r.PrevHash != prev {
			return &r, errors.New("store: hash chain broken")
		}
		expected := computeHash(r)
		if r.Hash != expected {
			return &r, errors.New("store: record hash mismatch")
		}
		prev = r.Hash
	}
	return nil, rows.Err()
}

// Timeline returns cached records for an agent_run_id. Falls through
// to Postgres when the cache misses.
func (s *PGStore) Timeline(agentRunID, tenantID string) []Record {
	s.mu.RLock()
	out := make([]Record, 0, 16)
	for _, rec := range s.cache {
		if rec.Event == nil || rec.Event.AgentRunID != agentRunID {
			continue
		}
		if tenantID != "" && rec.Event.TenantID != tenantID {
			continue
		}
		out = append(out, rec)
	}
	s.mu.RUnlock()
	if len(out) > 0 {
		return out
	}
	// Cold path: query Postgres directly.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	args := []any{agentRunID}
	q := `SELECT seq, ingest_at, prev_hash, hash, event FROM hopframe_events WHERE agent_run_id = $1`
	if tenantID != "" {
		q += ` AND tenant_id = $2`
		args = append(args, tenantID)
	}
	q += ` ORDER BY seq ASC`
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var r Record
		var evJSON []byte
		if err := rows.Scan(&r.Seq, &r.IngestAt, &r.PrevHash, &r.Hash, &evJSON); err != nil {
			return out
		}
		var ev event.Event
		if err := json.Unmarshal(evJSON, &ev); err != nil {
			return out
		}
		r.Event = &ev
		out = append(out, r)
	}
	return out
}

// Rotate enforces retention. Records older than the configured window
// are deleted; the surviving prefix's chain start is advanced so
// Verify still passes after rotation.
func (s *PGStore) Rotate() (kept, dropped int, err error) {
	if s.retention <= 0 {
		return 0, 0, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cutoff := time.Now().UTC().Add(-s.retention)
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback(ctx)

	// Count what's about to be dropped.
	if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM hopframe_events WHERE ingest_at < $1`, cutoff).Scan(&dropped); err != nil {
		return 0, 0, err
	}
	if dropped == 0 {
		_ = tx.Commit(ctx)
		// Total kept = current count.
		_ = s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM hopframe_events`).Scan(&kept)
		return kept, 0, nil
	}

	// New chain_start is the hash of the youngest dropped record (the
	// new oldest record's prev_hash). When dropping ALL records, leave
	// chain_start at its current value.
	var newChainStart string
	row := tx.QueryRow(ctx, `SELECT hash FROM hopframe_events WHERE ingest_at < $1 ORDER BY seq DESC LIMIT 1`, cutoff)
	if err := row.Scan(&newChainStart); err != nil {
		return 0, 0, err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM hopframe_events WHERE ingest_at < $1`, cutoff); err != nil {
		return 0, 0, err
	}
	if _, err := tx.Exec(ctx, `UPDATE hopframe_chain_head SET chain_start = $1 WHERE id = 1`, newChainStart); err != nil {
		return 0, 0, err
	}
	if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM hopframe_events`).Scan(&kept); err != nil {
		return 0, 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, 0, err
	}

	// Rebuild the cache after rotation: oldest cached records may now
	// be gone, and Verify expects the in-memory view to be consistent.
	if rerr := s.warmCache(ctx); rerr != nil {
		return kept, dropped, rerr
	}
	return kept, dropped, nil
}

// RunRetention starts a ticker that calls Rotate on the configured
// interval. Stops on context cancellation.
func (s *PGStore) RunRetention(ctx context.Context, every time.Duration) {
	if every <= 0 {
		return
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_, _, _ = s.Rotate()
		}
	}
}

// warmCache loads the most recent CacheCap records into the cache.
// Called on Open and after Rotate.
func (s *PGStore) warmCache(ctx context.Context) error {
	rows, err := s.pool.Query(ctx, `SELECT seq, ingest_at, prev_hash, hash, event FROM hopframe_events ORDER BY seq DESC LIMIT $1`, s.cacheCap)
	if err != nil {
		return err
	}
	defer rows.Close()
	var fresh []Record
	for rows.Next() {
		var r Record
		var evJSON []byte
		if err := rows.Scan(&r.Seq, &r.IngestAt, &r.PrevHash, &r.Hash, &evJSON); err != nil {
			return err
		}
		var ev event.Event
		if err := json.Unmarshal(evJSON, &ev); err != nil {
			return err
		}
		r.Event = &ev
		fresh = append(fresh, r)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	// rows came in DESC; flip to ASC to match the file backend's cache order.
	s.mu.Lock()
	s.cache = make([]Record, 0, len(fresh))
	for i := len(fresh) - 1; i >= 0; i-- {
		s.cache = append(s.cache, fresh[i])
	}
	s.mu.Unlock()
	return nil
}

func (s *PGStore) appendCacheLocked(rec Record) {
	if s.cacheCap <= 0 {
		return
	}
	s.cache = append(s.cache, rec)
	if len(s.cache) > s.cacheCap {
		drop := len(s.cache) - s.cacheCap
		s.cache = s.cache[drop:]
	}
}

// indexFields extracts the columns we keep alongside the JSONB blob
// for indexed lookups. Empty strings collapse to NULL via NULLIF in
// the INSERT so partial indexes stay sparse.
func indexFields(ev *event.Event) (tenantID, agentRunID, action, severity, method string) {
	if ev == nil {
		return
	}
	tenantID = ev.TenantID
	agentRunID = ev.AgentRunID
	action = string(ev.Action)
	severity = string(ev.Severity)
	method = ev.Message.Method
	return
}

// Compile-time assertion: *PGStore satisfies the EventStore interface.
// AnalyticsStore is intentionally NOT asserted here; the analytics
// methods (ToolRisk, AgentActivity, etc.) live on the cached records
// and are added in pgstore_analytics.go.
var _ EventStore = (*PGStore)(nil)
