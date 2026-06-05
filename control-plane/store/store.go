// Package store is the control-plane append-only event log.
//
// Phase 1 uses a single-file NDJSON log with a hash chain over each
// envelope: every record carries the SHA-256 of its predecessor, so
// any tampering with the on-disk log is detectable by re-walking from
// the genesis record. ClickHouse will replace this in Phase 2 for
// scale; the API surface is designed to make that swap small.
package store

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/jlupsp/hopframe/pkg/event"
)

// Record is one entry in the log: an ingested event plus the chain link.
type Record struct {
	Seq      uint64       `json:"seq"`
	IngestAt time.Time    `json:"ingest_at"`
	PrevHash string       `json:"prev_hash"`
	Hash     string       `json:"hash"`
	Event    *event.Event `json:"event"`
}

// genesisHash is the sentinel previous-hash for the first record.
const genesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// Store is an append-only log over a single file.
type Store struct {
	mu        sync.RWMutex
	path      string
	file      *os.File
	seq       uint64
	prevHash  string
	cache     []Record // small in-memory cache for fast UI reads
	cacheCap  int
	retention time.Duration
	// chainStart is the expected prev_hash of the first record on disk.
	// Equal to genesisHash for a never-rotated log; updated by Rotate.
	chainStart string
}

// genesisFilePath returns the sidecar file storing the post-rotation
// chain start hash. Created lazily by Rotate.
func (s *Store) genesisFilePath() string { return s.path + ".genesis" }

// Open opens or creates a store at path. On open, the chain is
// re-walked to recover (seq, prevHash) and validate integrity.
func Open(path string) (*Store, error) {
	return OpenWithOptions(Options{Path: path})
}

// OpenAuto picks the right backend from a DSN string. A
// "postgres://..." or "postgresql://..." DSN routes to the Postgres
// backend; anything else is treated as a file path for the
// append-only NDJSON backend. Returns an AnalyticsStore so callers
// can wire either implementation against the same UI surface.
//
// Compatible Postgres providers: Cloud SQL, AWS RDS for PostgreSQL,
// Azure Database for PostgreSQL, Aiven, Neon, Supabase, vanilla
// self-hosted Postgres 14+. Any DSN pgx accepts works.
func OpenAuto(dsn string, opts Options) (AnalyticsStore, error) {
	if dsn == "" {
		dsn = opts.Path
	}
	if isPostgresDSN(dsn) {
		return OpenPostgres(PGOptions{
			DSN:       dsn,
			Retention: opts.Retention,
			CacheCap:  opts.CacheCap,
		})
	}
	opts.Path = dsn
	return OpenWithOptions(opts)
}

func isPostgresDSN(s string) bool {
	if len(s) < 11 {
		return false
	}
	prefix := s[:11]
	if prefix == "postgres://" {
		return true
	}
	if len(s) >= 13 && s[:13] == "postgresql://" {
		return true
	}
	return false
}

// Options configures store creation.
type Options struct {
	Path string
	// Retention, when > 0, drops records older than this on rotation.
	Retention time.Duration
	// CacheCap is the in-memory cache size for fast UI reads. Default 1024.
	CacheCap int
}

// OpenWithOptions opens or creates a store with the given configuration.
func OpenWithOptions(opts Options) (*Store, error) {
	if opts.Path == "" {
		return nil, errors.New("store: empty path")
	}
	if opts.CacheCap <= 0 {
		opts.CacheCap = 1024
	}
	f, err := os.OpenFile(opts.Path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		return nil, fmt.Errorf("store: open %s: %w", opts.Path, err)
	}
	s := &Store{
		path:       opts.Path,
		file:       f,
		prevHash:   genesisHash,
		cacheCap:   opts.CacheCap,
		retention:  opts.Retention,
		chainStart: genesisHash,
	}
	if g, err := os.ReadFile(s.genesisFilePath()); err == nil {
		if h := strings.TrimSpace(string(g)); len(h) == 64 {
			s.chainStart = h
		}
	}
	if err := s.replay(); err != nil {
		_ = f.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the underlying file.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.file.Close()
}

// Append commits a new event to the log, returning the persisted Record.
func (s *Store) Append(ev *event.Event) (*Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec := Record{
		Seq:      s.seq + 1,
		IngestAt: time.Now().UTC(),
		PrevHash: s.prevHash,
		Event:    ev,
	}
	rec.Hash = computeHash(rec)

	body, err := json.Marshal(rec)
	if err != nil {
		return nil, err
	}
	if _, err := s.file.Write(append(body, '\n')); err != nil {
		return nil, err
	}
	if err := s.file.Sync(); err != nil {
		return nil, err
	}

	s.seq = rec.Seq
	s.prevHash = rec.Hash
	s.appendCacheLocked(rec)
	return &rec, nil
}

func (s *Store) appendCacheLocked(rec Record) {
	if s.cacheCap <= 0 {
		return
	}
	s.cache = append(s.cache, rec)
	if len(s.cache) > s.cacheCap {
		drop := len(s.cache) - s.cacheCap
		s.cache = s.cache[drop:]
	}
}

// Stats returns simple counters useful for UI status panels.
type Stats struct {
	Seq      uint64 `json:"seq"`
	Path     string `json:"path"`
	HeadHash string `json:"head_hash"`
}

// Stats returns the current store stats.
func (s *Store) Stats() Stats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return Stats{Seq: s.seq, Path: s.path, HeadHash: s.prevHash}
}

// Query is a filter applied during a Read.
type Query struct {
	Limit       int
	Offset      int
	Action      string // "", "allow", "warn", "block"
	Severity    string
	MinSeverity string // pass-through filter for "min severity" UI
	Method      string
	Category    string
	Search      string // substring match in raw message
	SinceSeq    uint64
	// TenantID, when non-empty, restricts results to records whose
	// event.tenant_id matches exactly. Records without a tenant_id are
	// excluded when this filter is active. Use the empty string to read
	// across all tenants (admin scope).
	TenantID string
}

// Timeline returns every cached record for the given agent_run_id in
// ascending sequence order, the oldest event first, newest last.
// This is the read-side primitive behind forensic replay.
//
// When tenantID is non-empty, the result is further restricted to
// records whose event.tenant_id matches exactly. Pass the empty string
// to read across all tenants.
func (s *Store) Timeline(agentRunID string, tenantID string) []Record {
	s.mu.RLock()
	defer s.mu.RUnlock()
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
	return out
}

// Read returns the most recent records matching q. Records are scanned
// from the in-memory cache first, then fall through to disk.
func (s *Store) Read(q Query) ([]Record, error) {
	if q.Limit <= 0 {
		q.Limit = 50
	}
	s.mu.RLock()
	cached := append([]Record(nil), s.cache...)
	s.mu.RUnlock()

	// Walk newest-first.
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
			break
		}
	}
	return out, nil
}

func match(r Record, q Query) bool {
	if q.TenantID != "" && r.Event.TenantID != q.TenantID {
		return false
	}
	if q.Action != "" && string(r.Event.Action) != q.Action {
		return false
	}
	if q.Method != "" && r.Event.Message.Method != q.Method {
		return false
	}
	if q.Severity != "" && string(r.Event.Severity) != q.Severity {
		return false
	}
	if q.MinSeverity != "" && !meetsMinSeverity(r.Event.Severity, q.MinSeverity) {
		return false
	}
	if q.Category != "" {
		hit := false
		for _, f := range r.Event.Findings {
			if f.Category == q.Category {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}
	if q.Search != "" && !strings.Contains(r.Event.Message.Raw, q.Search) {
		return false
	}
	return true
}

func meetsMinSeverity(have event.Severity, min string) bool {
	rank := map[event.Severity]int{
		event.SeverityInfo:     0,
		event.SeverityLow:      1,
		event.SeverityMedium:   2,
		event.SeverityHigh:     3,
		event.SeverityCritical: 4,
	}
	return rank[have] >= rank[event.Severity(min)]
}

// Verify walks the on-disk log from start to current head and confirms
// every record's hash chains correctly. It returns the first record
// that breaks the chain, or nil if integrity is intact.
func (s *Store) Verify() (*Record, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if _, err := s.file.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	scanner := bufio.NewScanner(s.file)
	scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	prev := s.chainStart
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var rec Record
		if err := json.Unmarshal(line, &rec); err != nil {
			return &rec, fmt.Errorf("store: corrupt record at seq %d: %w", rec.Seq, err)
		}
		if rec.PrevHash != prev {
			r := rec
			return &r, errors.New("store: hash chain broken")
		}
		expected := computeHash(rec)
		if rec.Hash != expected {
			r := rec
			return &r, errors.New("store: record hash mismatch")
		}
		prev = rec.Hash
	}
	return nil, scanner.Err()
}

func (s *Store) replay() error {
	if _, err := s.file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	scanner := bufio.NewScanner(s.file)
	scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	prev := s.chainStart
	var seq uint64
	// Reset cache so a re-replay (e.g. after rotation) doesn't double up.
	s.cache = s.cache[:0]
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var rec Record
		if err := json.Unmarshal(line, &rec); err != nil {
			return fmt.Errorf("store: replay parse: %w", err)
		}
		s.appendCacheLocked(rec)
		prev = rec.Hash
		seq = rec.Seq
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	s.seq = seq
	s.prevHash = prev
	// Seek to end so subsequent Append continues at EOF (O_APPEND already
	// guarantees this, but explicit Seek keeps Read+Append predictable).
	if _, err := s.file.Seek(0, io.SeekEnd); err != nil {
		return err
	}
	return nil
}

// computeHash hashes (seq, ingest_at, prev_hash, event_json). It is
// reproducible across runs given identical inputs.
func computeHash(rec Record) string {
	h := sha256.New()
	fmt.Fprintf(h, "%d\n%s\n%s\n", rec.Seq, rec.IngestAt.UTC().Format(time.RFC3339Nano), rec.PrevHash)
	body, _ := json.Marshal(rec.Event)
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}
