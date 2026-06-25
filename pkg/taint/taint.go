// Package taint tracks data lineage across protocol boundaries so
// Hopframe can answer "did data from MCP tool X reach an A2A peer
// outside the allowlist?", the headline cross-protocol guarantee
// that gateways cannot give you.
//
// Taints are minted by the MCP sensor when a tools/call response
// arrives from upstream. The taint id, plus a content fingerprint
// of selected response strings, is recorded against the agent_run.
// When a subsequent A2A task envelope appears for the same agent_run
// and any of its message strings overlaps a known fingerprint, the
// A2A sensor raises a "cross-protocol taint leaked to <peer>" finding.
//
// State is in-process and per-sensor in Phase 2; Phase 3 will sync
// state via the control plane so leaks across replicas are caught.
package taint

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jlupsp/hopframe/pkg/detect"
)

// Source describes where a taint came from.
type Source struct {
	Protocol string `json:"protocol"`
	Method   string `json:"method"`
	Tool     string `json:"tool,omitempty"`
	Field    string `json:"field,omitempty"`
}

// Taint is one tagged value: source + a set of fingerprints (shingles)
// covering the value. Match succeeds when any candidate shingle
// overlaps the tagged set, standard near-duplicate detection.
type Taint struct {
	ID           string              `json:"id"`
	Source       Source              `json:"source"`
	Fingerprints map[string]struct{} `json:"-"`
	Sample       string              `json:"sample,omitempty"`
	CreatedAt    time.Time           `json:"created_at"`
}

// FingerprintList returns the taint's shingle fingerprints as a slice,
// for transport to a shared backend. Order is unspecified.
func (ta Taint) FingerprintList() []string {
	out := make([]string, 0, len(ta.Fingerprints))
	for fp := range ta.Fingerprints {
		out = append(out, fp)
	}
	return out
}

// Remote is an optional shared backend that lets a taint minted on one
// sensor be matched on another. It is what closes the cross-replica gap:
// with separate MCP and A2A sensors, or several replicas, the in-process
// tracker alone cannot recognize that data read on one process is leaving
// from another. A Remote exchanges fingerprints, never raw values, so the
// tagged data never leaves the sensor that read it. Implementations must
// be safe for concurrent use and must bound their own latency, since Match
// runs on the forward/block hot path.
type Remote interface {
	// Push registers a freshly minted taint with the shared backend.
	// Best-effort and called asynchronously; failures are non-fatal.
	Push(agentRun string, t Taint)
	// Match asks the shared backend whether any candidate fingerprint
	// overlaps a taint for agentRun. Synchronous and latency-bounded.
	Match(agentRun string, fingerprints []string) (Taint, bool)
}

// Tracker is concurrent per-agent-run taint state.
type Tracker struct {
	mu        sync.RWMutex
	byRun     map[string][]Taint
	maxPerRun int
	maxRuns   int
	ttl       time.Duration
	remote    Remote
}

// SetRemote attaches a shared backend. When set, Tag also pushes to it
// (async) and Match falls back to it on a local miss. Call once at
// startup, before traffic. Passing nil disables the remote.
func (t *Tracker) SetRemote(r Remote) {
	t.mu.Lock()
	t.remote = r
	t.mu.Unlock()
}

// New returns a tracker. maxPerRun bounds taints per agent_run, maxRuns
// caps the total run table, ttl drops idle runs.
func New(ttl time.Duration, maxPerRun, maxRuns int) *Tracker {
	if maxPerRun <= 0 {
		maxPerRun = 64
	}
	if maxRuns <= 0 {
		maxRuns = 1024
	}
	return &Tracker{
		byRun:     make(map[string][]Taint),
		maxPerRun: maxPerRun,
		maxRuns:   maxRuns,
		ttl:       ttl,
	}
}

// Tag records a new taint for agentRun. Returns the new Taint.
func (t *Tracker) Tag(agentRun string, src Source, value string) Taint {
	if agentRun == "" || strings.TrimSpace(value) == "" {
		return Taint{}
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	t.evictIfFullLocked()

	taint := Taint{
		ID:           newID(),
		Source:       src,
		Fingerprints: shingleSet(value),
		Sample:       truncate(value, 80),
		CreatedAt:    time.Now().UTC(),
	}
	taints := t.byRun[agentRun]
	taints = append(taints, taint)
	if len(taints) > t.maxPerRun {
		taints = taints[len(taints)-t.maxPerRun:]
	}
	t.byRun[agentRun] = taints
	// Mirror to the shared backend so other sensors can match it. The
	// fingerprints are immutable once minted, so reading them off-lock in
	// the goroutine is safe. Best-effort: a failed push just means the
	// cross-replica catch falls back to local-only for this taint.
	if t.remote != nil {
		go t.remote.Push(agentRun, taint)
	}
	return taint
}

// TagFingerprints records a taint from already-computed fingerprints,
// without re-shingling a value. A shared backend uses this to store taints
// it receives over the wire (fingerprints only, never the raw value).
func (t *Tracker) TagFingerprints(agentRun string, src Source, sample string, fps []string) Taint {
	if agentRun == "" || len(fps) == 0 {
		return Taint{}
	}
	set := make(map[string]struct{}, len(fps))
	for _, fp := range fps {
		set[fp] = struct{}{}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.evictIfFullLocked()
	taint := Taint{
		ID:           newID(),
		Source:       src,
		Fingerprints: set,
		Sample:       truncate(sample, 80),
		CreatedAt:    time.Now().UTC(),
	}
	taints := append(t.byRun[agentRun], taint)
	if len(taints) > t.maxPerRun {
		taints = taints[len(taints)-t.maxPerRun:]
	}
	t.byRun[agentRun] = taints
	return taint
}

// Match returns the first Taint whose shingle set overlaps the
// candidate value's shingle set. Designed to detect near-exact reuse
// of a tagged string, not paraphrase.
func (t *Tracker) Match(agentRun, value string) (Taint, bool) {
	if agentRun == "" || value == "" {
		return Taint{}, false
	}
	shingles := shingleSet(value)
	if ta, ok := t.matchLocal(agentRun, shingles); ok {
		return ta, true
	}
	// Local miss: fall back to the shared backend so a taint minted on
	// another sensor still catches this leak.
	t.mu.RLock()
	r := t.remote
	t.mu.RUnlock()
	if r != nil {
		fps := make([]string, 0, len(shingles))
		for fp := range shingles {
			fps = append(fps, fp)
		}
		return r.Match(agentRun, fps)
	}
	return Taint{}, false
}

// matchLocal checks a candidate shingle set against the in-process taints
// for agentRun only.
func (t *Tracker) matchLocal(agentRun string, shingles map[string]struct{}) (Taint, bool) {
	t.mu.RLock()
	taints := append([]Taint(nil), t.byRun[agentRun]...)
	t.mu.RUnlock()
	for _, ta := range taints {
		for fp := range shingles {
			if _, hit := ta.Fingerprints[fp]; hit {
				return ta, true
			}
		}
	}
	return Taint{}, false
}

// MatchFingerprints matches a candidate fingerprint set against agentRun's
// taints. A shared backend uses this for queries it receives over the
// wire; it never consults a remote of its own (it is the terminal store).
func (t *Tracker) MatchFingerprints(agentRun string, fps []string) (Taint, bool) {
	if agentRun == "" || len(fps) == 0 {
		return Taint{}, false
	}
	set := make(map[string]struct{}, len(fps))
	for _, fp := range fps {
		set[fp] = struct{}{}
	}
	return t.matchLocal(agentRun, set)
}

// MatchAny scans every string in values against the agent_run's taints.
func (t *Tracker) MatchAny(agentRun string, values []string) (Taint, bool) {
	for _, v := range values {
		if ta, ok := t.Match(agentRun, v); ok {
			return ta, true
		}
	}
	return Taint{}, false
}

// List returns taints for agentRun (snapshot copy).
func (t *Tracker) List(agentRun string) []Taint {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]Taint, len(t.byRun[agentRun]))
	copy(out, t.byRun[agentRun])
	return out
}

// Forget drops all taints for agentRun.
func (t *Tracker) Forget(agentRun string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	_, ok := t.byRun[agentRun]
	if ok {
		delete(t.byRun, agentRun)
	}
	return ok
}

// Stats returns the current run / taint counts.
type Stats struct {
	Runs   int `json:"runs"`
	Taints int `json:"taints"`
}

// Stats returns a snapshot.
func (t *Tracker) Stats() Stats {
	t.mu.RLock()
	defer t.mu.RUnlock()
	total := 0
	for _, ts := range t.byRun {
		total += len(ts)
	}
	return Stats{Runs: len(t.byRun), Taints: total}
}

// Sweep drops runs whose newest taint is older than ttl. Run on a
// ticker by the proxy.
func (t *Tracker) Sweep() int {
	if t.ttl <= 0 {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	cutoff := time.Now().UTC().Add(-t.ttl)
	dropped := 0
	for run, ts := range t.byRun {
		newest := ts[0].CreatedAt
		for _, ta := range ts {
			if ta.CreatedAt.After(newest) {
				newest = ta.CreatedAt
			}
		}
		if newest.Before(cutoff) {
			delete(t.byRun, run)
			dropped++
		}
	}
	return dropped
}

func (t *Tracker) evictIfFullLocked() {
	if len(t.byRun) < t.maxRuns {
		return
	}
	// Drop the run whose newest taint is oldest.
	var oldestRun string
	var oldestNewest time.Time
	first := true
	for run, ts := range t.byRun {
		if len(ts) == 0 {
			continue
		}
		newest := ts[0].CreatedAt
		for _, ta := range ts {
			if ta.CreatedAt.After(newest) {
				newest = ta.CreatedAt
			}
		}
		if first || newest.Before(oldestNewest) {
			oldestNewest = newest
			oldestRun = run
			first = false
		}
	}
	if oldestRun != "" {
		delete(t.byRun, oldestRun)
	}
}

const shingleWidth = 24

// shingleSet returns the set of SHA-256 windows of width shingleWidth
// over the canonical views of value. Used for both Tag and Match, so
// overlap means near-duplicate reuse of the same underlying bytes even
// when one side has been Unicode-obfuscated or base64-encoded.
func shingleSet(value string) map[string]struct{} {
	out := make(map[string]struct{})
	for _, view := range canonicalViews(value) {
		addShingles(out, view)
	}
	return out
}

// canonicalViews expands a value into the forms an attacker might use to
// move the same bytes while defeating exact matching: the value with
// Unicode obfuscation normalized away (NFKC + stripped zero-width /
// smuggling runes), plus any base64-encoded payloads embedded in it,
// decoded and normalized. Because both Tag and Match run over this
// expansion, a secret tagged on the MCP wire is still recognized when the
// agent base64-encodes or homoglyph-obfuscates it before forwarding over
// A2A. This mirrors the rule engine's normalize + base64-recurse pass, so
// the two halves of the engine agree on what "the same data" means.
func canonicalViews(value string) []string {
	views := []string{detect.NormalizeForDetection(value)}
	for _, decoded := range detect.ExtractBase64Candidates(value) {
		views = append(views, detect.NormalizeForDetection(decoded))
	}
	return views
}

func addShingles(out map[string]struct{}, value string) {
	b := []byte(strings.TrimSpace(value))
	if len(b) == 0 {
		return
	}
	if len(b) <= shingleWidth {
		sum := sha256.Sum256(b)
		out[hex.EncodeToString(sum[:])[:32]] = struct{}{}
		return
	}
	for i := 0; i+shingleWidth <= len(b); i++ {
		sum := sha256.Sum256(b[i : i+shingleWidth])
		out[hex.EncodeToString(sum[:])[:32]] = struct{}{}
	}
}

func newID() string {
	var b [8]byte
	now := time.Now().UnixNano()
	for i := 0; i < 8; i++ {
		b[i] = byte(now >> (i * 8))
	}
	sum := sha256.Sum256(b[:])
	return "t-" + hex.EncodeToString(sum[:])[:12]
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// keys helper used by tests.
func keys(m map[string][]Taint) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

var _ = keys
