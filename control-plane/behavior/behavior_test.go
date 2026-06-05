package behavior

import (
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/jlupsp/hopframe/control-plane/store"
	"github.com/jlupsp/hopframe/pkg/event"
)

type captureSink struct {
	mu      sync.Mutex
	events  []*event.Event
	wrapped *store.Store
}

func (c *captureSink) Append(ev *event.Event) (*store.Record, error) {
	c.mu.Lock()
	c.events = append(c.events, ev)
	c.mu.Unlock()
	return c.wrapped.Append(ev)
}
func (c *captureSink) snapshot() []*event.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]*event.Event, len(c.events))
	copy(out, c.events)
	return out
}

type captureBC struct {
	mu      sync.Mutex
	records []store.Record
}

func (c *captureBC) Broadcast(rec *store.Record) {
	c.mu.Lock()
	c.records = append(c.records, *rec)
	c.mu.Unlock()
}

func newPeer(peer string, ts time.Time, findings int, action event.Action, sev event.Severity) *event.Event {
	ev := event.New("test", event.ProtocolA2A, event.DirectionInbound)
	ev.Counterparty = peer
	ev.Action = action
	ev.Severity = sev
	ev.Timestamp = ts
	ev.Message.Method = "tasks/send"
	for i := 0; i < findings; i++ {
		ev.Findings = append(ev.Findings, event.Finding{
			RuleID:   "x",
			Severity: sev,
		})
	}
	return &ev
}

func TestNoveltyHighSeverityFires(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "log.ndjson"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	now := time.Now().UTC()
	_, _ = st.Append(newPeer("peer-newcomer", now, 1, event.ActionWarn, event.SeverityHigh))

	cap := &captureSink{wrapped: st}
	bc := &captureBC{}
	det := New(st, cap, bc, "behavior-test", DefaultOptions())
	det.Tick()

	hit := false
	for _, ev := range cap.snapshot() {
		if ev.Findings[0].RuleID == "behavior.novelty_high_severity" {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("expected novelty finding, got %d events", len(cap.snapshot()))
	}
}

func TestRateSpikeFires(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "log.ndjson"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	now := time.Now().UTC()
	opts := Options{
		Window:          time.Minute,
		Tick:            time.Hour,
		MinObservations: 5,
		SpikeFactor:     3.0,
	}

	// 6 historical buckets of 1 event each = baseline mean 1.0
	for i := 1; i <= 5; i++ {
		ts := now.Add(-time.Duration(i) * opts.Window)
		_, _ = st.Append(newPeer("peer-spiker", ts, 0, event.ActionAllow, event.SeverityInfo))
	}
	// Recent window: 10 events.
	for i := 0; i < 10; i++ {
		ts := now.Add(-time.Duration(i) * time.Second)
		_, _ = st.Append(newPeer("peer-spiker", ts, 0, event.ActionAllow, event.SeverityInfo))
	}

	cap := &captureSink{wrapped: st}
	det := New(st, cap, nil, "behavior-test", opts)
	det.Tick()

	hit := false
	for _, ev := range cap.snapshot() {
		for _, f := range ev.Findings {
			if f.RuleID == "behavior.rate_spike" && ev.Counterparty == "peer-spiker" {
				hit = true
			}
		}
	}
	if !hit {
		t.Fatalf("expected rate spike on peer-spiker; got %d findings", len(cap.snapshot()))
	}
}

func TestSuppressRepeats(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "log.ndjson"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	now := time.Now().UTC()
	_, _ = st.Append(newPeer("peer-repeat", now, 1, event.ActionWarn, event.SeverityHigh))

	cap := &captureSink{wrapped: st}
	det := New(st, cap, nil, "test", DefaultOptions())
	det.Tick()
	first := len(cap.snapshot())
	det.Tick()
	second := len(cap.snapshot())

	if second != first {
		t.Fatalf("expected duplicate finding to be suppressed: first=%d second=%d", first, second)
	}
}
