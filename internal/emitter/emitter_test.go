package emitter

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jlupsp/hopframe/pkg/event"
)

func TestStdoutSinkWritesNDJSON(t *testing.T) {
	var buf bytes.Buffer
	sink := NewWriterSink(&buf)
	ev := event.New("s", event.ProtocolMCP, event.DirectionInbound)
	ev.EventID = "ev1"
	if err := sink.Deliver(context.Background(), &ev); err != nil {
		t.Fatalf("deliver: %v", err)
	}
	out := buf.String()
	if !strings.HasSuffix(out, "\n") {
		t.Fatalf("expected newline-delimited output: %q", out)
	}
	var got event.Event
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.EventID != "ev1" {
		t.Fatalf("event id = %q", got.EventID)
	}
}

type slowSink struct {
	mu    sync.Mutex
	count int
	delay time.Duration
}

func (s *slowSink) Deliver(_ context.Context, _ *event.Event) error {
	time.Sleep(s.delay)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.count++
	return nil
}
func (s *slowSink) Close() error { return nil }

func TestEmitterDropsWhenQueueFull(t *testing.T) {
	sink := &slowSink{delay: 50 * time.Millisecond}
	em := New(sink, 1)
	defer em.Close()

	for i := 0; i < 100; i++ {
		ev := event.New("s", event.ProtocolMCP, event.DirectionInbound)
		em.Emit(&ev)
	}
	// Allow worker to drain a few.
	time.Sleep(150 * time.Millisecond)
	_, dropped := em.Stats()
	if dropped == 0 {
		t.Fatalf("expected some drops with bufferSize=1 and slow sink")
	}
}
