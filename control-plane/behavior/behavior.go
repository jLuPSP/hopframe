// Package behavior is Layer 4 of the Hopframe detection pipeline:
// behavioral anomaly detection over the windowed event stream.
//
// Layers 1–3 (heuristics, classifier, LLM judge) live in the sensor
// and inspect single messages. Layer 4 lives in the control plane
// because the signal it needs, rate spikes, novel actors, cross-event
// correlation, is only visible in aggregate.
//
// The detector runs on a ticker, walks the in-memory cache slice, and
// emits synthetic events (protocol="behavior") for each anomaly it
// finds. Synthetic events are appended to the same hash-chained log,
// so they are tamper-evident and routed to the SSE hub + exporters
// like any sensor event.
package behavior

import (
	"context"
	"fmt"
	"math"
	"sort"
	"sync"
	"time"

	"github.com/jlupsp/hopframe/control-plane/store"
	"github.com/jlupsp/hopframe/pkg/event"
)

// Options configure the detector.
type Options struct {
	// Window is the look-back used by every check.
	Window time.Duration
	// Tick is how often the detector runs.
	Tick time.Duration
	// MinObservations is the floor below which we skip a check
	// (avoids firing on samples too small to be statistically meaningful).
	MinObservations int
	// SpikeFactor is the multiplier over the historical mean that a
	// rate must exceed to fire a "rate spike" finding (default 3.0).
	SpikeFactor float64
	// NoveltyHighSeverity, when true, fires a finding the first time
	// an unfamiliar counterparty produces a high+ severity event.
	NoveltyHighSeverity bool
}

// DefaultOptions returns sensible defaults.
func DefaultOptions() Options {
	return Options{
		Window:              5 * time.Minute,
		Tick:                30 * time.Second,
		MinObservations:     10,
		SpikeFactor:         3.0,
		NoveltyHighSeverity: true,
	}
}

// Sink is anything the detector can write a synthetic event to. The
// concrete implementation is store.Store, but tests use a fake.
type Sink interface {
	Append(ev *event.Event) (*store.Record, error)
}

// Broadcaster optionally fans the synthetic event out to subscribers.
// In production this is the api.Server's hub.
type Broadcaster interface {
	Broadcast(rec *store.Record)
}

// Detector ticks behavioral checks over the store cache.
type Detector struct {
	opts        Options
	store       store.EventStore
	sink        Sink
	broadcaster Broadcaster
	sensorID    string

	mu          sync.Mutex
	seenPeers   map[string]struct{}
	lastFinding map[string]time.Time
}

// New creates a Detector.
func New(s store.EventStore, sink Sink, b Broadcaster, sensorID string, opts Options) *Detector {
	if opts.Window <= 0 {
		opts.Window = 5 * time.Minute
	}
	if opts.Tick <= 0 {
		opts.Tick = 30 * time.Second
	}
	if opts.MinObservations <= 0 {
		opts.MinObservations = 10
	}
	if opts.SpikeFactor <= 1 {
		opts.SpikeFactor = 3.0
	}
	return &Detector{
		opts:        opts,
		store:       s,
		sink:        sink,
		broadcaster: b,
		sensorID:    sensorID,
		seenPeers:   make(map[string]struct{}),
		lastFinding: make(map[string]time.Time),
	}
}

// Run drives Tick on a ticker until ctx is cancelled.
func (d *Detector) Run(ctx context.Context) {
	t := time.NewTicker(d.opts.Tick)
	defer t.Stop()
	// One eager pass on startup.
	d.Tick()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			d.Tick()
		}
	}
}

// Tick runs every check once. Exposed for tests.
func (d *Detector) Tick() {
	now := time.Now().UTC()

	// We need the full cache because store.Read tops out at the
	// Limit. The Store's Snapshot helper would be cleaner, but for
	// Phase 1 we just borrow Read with a generous limit.
	recent, _ := d.store.Read(store.Query{Limit: 5000})
	if len(recent) == 0 {
		return
	}

	// Bucket by (counterparty, agent_run, tool) for spike detection,
	// and track novel peers for novelty detection.
	type bucket struct {
		count    int
		findings int
		blocks   int
		newest   time.Time
	}

	cutoff := now.Add(-d.opts.Window)
	historicalCutoff := now.Add(-d.opts.Window * 6) // wider baseline

	recentBy := make(map[string]*bucket)
	historicalBy := make(map[string]*bucket)

	pending := make([]*event.Event, 0)

	d.mu.Lock()
	for _, rec := range recent {
		ev := rec.Event
		if ev == nil {
			continue
		}
		if ev.Timestamp.Before(historicalCutoff) {
			continue
		}
		// Novelty: first time we see a peer with a high+ severity event.
		if d.opts.NoveltyHighSeverity && ev.Counterparty != "" {
			_, seen := d.seenPeers[ev.Counterparty]
			if !seen {
				d.seenPeers[ev.Counterparty] = struct{}{}
				if rank(ev.Severity) >= rank(event.SeverityHigh) {
					pending = append(pending, noveltyFinding(d.sensorID, ev.Counterparty, ev.Severity))
				}
			}
		}

		key := bucketKey(ev)
		if key == "" {
			continue
		}
		b := historicalBy[key]
		if b == nil {
			b = &bucket{}
			historicalBy[key] = b
		}
		b.count++
		b.findings += len(ev.Findings)
		if ev.Action == event.ActionBlock {
			b.blocks++
		}
		if ev.Timestamp.After(b.newest) {
			b.newest = ev.Timestamp
		}
		if !ev.Timestamp.Before(cutoff) {
			r := recentBy[key]
			if r == nil {
				r = &bucket{}
				recentBy[key] = r
			}
			r.count++
			r.findings += len(ev.Findings)
			if ev.Action == event.ActionBlock {
				r.blocks++
			}
		}
	}
	d.mu.Unlock()

	// Spike detection: recent count > SpikeFactor * (historical mean
	// over equal-sized windows).
	for key, recent := range recentBy {
		hist := historicalBy[key]
		if hist == nil || hist.count < d.opts.MinObservations {
			continue
		}
		// Mean per window across the 6-window baseline.
		baselineMean := float64(hist.count-recent.count) / 5.0
		if baselineMean <= 0 {
			continue
		}
		ratio := float64(recent.count) / baselineMean
		if ratio < d.opts.SpikeFactor {
			continue
		}
		if f := spikeFinding(d.sensorID, key, recent.count, baselineMean, ratio); f != nil {
			pending = append(pending, f)
		}
	}

	// Findings-rate anomaly: a single peer where findings/event in
	// the recent window is significantly above the historical rate.
	if peers := perPeerStats(recent, cutoff, historicalCutoff); peers != nil {
		for peer, s := range peers {
			if s.recentEvents < d.opts.MinObservations {
				continue
			}
			if s.histEvents == 0 {
				continue
			}
			recentRate := float64(s.recentFindings) / float64(s.recentEvents)
			histRate := float64(s.histFindings) / float64(s.histEvents)
			if histRate <= 0 || recentRate < histRate*d.opts.SpikeFactor {
				continue
			}
			pending = append(pending, peerRateFinding(d.sensorID, peer, recentRate, histRate))
		}
	}

	for _, ev := range pending {
		d.maybeEmit(ev)
	}
}

func (d *Detector) maybeEmit(ev *event.Event) {
	if ev == nil {
		return
	}
	// Suppress repeats of the same finding within 1 window.
	d.mu.Lock()
	key := ev.Findings[0].RuleID + "|" + ev.Findings[0].Match
	if last, ok := d.lastFinding[key]; ok && time.Since(last) < d.opts.Window {
		d.mu.Unlock()
		return
	}
	d.lastFinding[key] = time.Now().UTC()
	d.mu.Unlock()

	if d.sink == nil {
		return
	}
	rec, err := d.sink.Append(ev)
	if err == nil && d.broadcaster != nil {
		d.broadcaster.Broadcast(rec)
	}
}

type peerStats struct {
	recentEvents, recentFindings int
	histEvents, histFindings     int
}

func perPeerStats(recs []store.Record, cutoffRecent, cutoffHist time.Time) map[string]*peerStats {
	out := map[string]*peerStats{}
	for _, rec := range recs {
		ev := rec.Event
		if ev == nil || ev.Counterparty == "" {
			continue
		}
		if ev.Timestamp.Before(cutoffHist) {
			continue
		}
		s := out[ev.Counterparty]
		if s == nil {
			s = &peerStats{}
			out[ev.Counterparty] = s
		}
		s.histEvents++
		s.histFindings += len(ev.Findings)
		if !ev.Timestamp.Before(cutoffRecent) {
			s.recentEvents++
			s.recentFindings += len(ev.Findings)
		}
	}
	return out
}

func bucketKey(ev *event.Event) string {
	switch {
	case ev.Counterparty != "":
		return "peer:" + ev.Counterparty
	case ev.AgentRunID != "":
		return "run:" + ev.AgentRunID
	case ev.Message.Method != "":
		return "method:" + ev.Message.Method
	}
	return ""
}

func noveltyFinding(sensorID, peer string, sev event.Severity) *event.Event {
	ev := event.New(sensorID, "behavior", event.DirectionInbound)
	ev.Findings = []event.Finding{{
		RuleID:      "behavior.novelty_high_severity",
		Category:    "policy",
		Severity:    event.SeverityHigh,
		Description: "first event from this counterparty arrived at " + string(sev) + " severity",
		Field:       "counterparty",
		Match:       peer,
		Confidence:  0.85,
	}}
	ev.Counterparty = peer
	ev.Action = event.ActionWarn
	ev.Severity = event.SeverityHigh
	ev.Message.Method = "behavior.tick"
	return &ev
}

func spikeFinding(sensorID, key string, recent int, baseline, ratio float64) *event.Event {
	ev := event.New(sensorID, "behavior", event.DirectionInbound)
	ev.Findings = []event.Finding{{
		RuleID:      "behavior.rate_spike",
		Category:    "policy",
		Severity:    event.SeverityMedium,
		Description: fmt.Sprintf("rate spike: %d events in window (baseline %.1f, %.1fx)", recent, baseline, ratio),
		Field:       "bucket",
		Match:       key,
		Confidence:  math.Min(0.95, ratio/10),
		Metadata:    map[string]any{"recent": recent, "baseline_mean": baseline, "ratio": ratio},
	}}
	if peer, ok := splitKey(key, "peer:"); ok {
		ev.Counterparty = peer
	}
	if run, ok := splitKey(key, "run:"); ok {
		ev.AgentRunID = run
	}
	ev.Action = event.ActionWarn
	ev.Severity = event.SeverityMedium
	ev.Message.Method = "behavior.tick"
	return &ev
}

func peerRateFinding(sensorID, peer string, recentRate, histRate float64) *event.Event {
	ev := event.New(sensorID, "behavior", event.DirectionInbound)
	ev.Findings = []event.Finding{{
		RuleID:      "behavior.findings_rate_spike",
		Category:    "policy",
		Severity:    event.SeverityHigh,
		Description: fmt.Sprintf("counterparty findings rate %.2f vs historical %.2f", recentRate, histRate),
		Field:       "counterparty",
		Match:       peer,
		Confidence:  0.9,
		Metadata:    map[string]any{"recent_rate": recentRate, "historical_rate": histRate},
	}}
	ev.Counterparty = peer
	ev.Action = event.ActionWarn
	ev.Severity = event.SeverityHigh
	ev.Message.Method = "behavior.tick"
	return &ev
}

func splitKey(key, prefix string) (string, bool) {
	if len(key) > len(prefix) && key[:len(prefix)] == prefix {
		return key[len(prefix):], true
	}
	return "", false
}

func rank(s event.Severity) int {
	switch s {
	case event.SeverityCritical:
		return 4
	case event.SeverityHigh:
		return 3
	case event.SeverityMedium:
		return 2
	case event.SeverityLow:
		return 1
	}
	return 0
}

// keys returns the sorted keys of a map[string]*bucket, used by tests.
func keys(m map[string]*peerStats) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

var _ = keys
