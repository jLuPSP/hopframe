package emitter

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/jlupsp/hopframe/pkg/event"
)

func newEvent(id string) *event.Event {
	ev := event.New("s", event.ProtocolMCP, event.DirectionInbound)
	ev.EventID = id
	return &ev
}

func TestSpoolAppendAndDrain(t *testing.T) {
	dir := t.TempDir()
	sp, err := NewSpool(filepath.Join(dir, "spool.ndjson"), 0)
	if err != nil {
		t.Fatalf("new spool: %v", err)
	}
	defer sp.Close()

	for i := 0; i < 3; i++ {
		if err := sp.Append(newEvent("e" + string(rune('a'+i)))); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}

	var seen []string
	if err := sp.Drain(func(ev *event.Event) error {
		seen = append(seen, ev.EventID)
		return nil
	}); err != nil {
		t.Fatalf("drain: %v", err)
	}
	if len(seen) != 3 {
		t.Fatalf("seen = %v", seen)
	}

	// Spool should now be empty.
	called := false
	if err := sp.Drain(func(_ *event.Event) error { called = true; return nil }); err != nil {
		t.Fatalf("second drain: %v", err)
	}
	if called {
		t.Fatalf("expected spool empty after drain")
	}
}

func TestSpoolKeepsOnError(t *testing.T) {
	dir := t.TempDir()
	sp, err := NewSpool(filepath.Join(dir, "spool.ndjson"), 0)
	if err != nil {
		t.Fatalf("new spool: %v", err)
	}
	defer sp.Close()

	for _, id := range []string{"a", "b", "c"} {
		if err := sp.Append(newEvent(id)); err != nil {
			t.Fatalf("append %s: %v", id, err)
		}
	}

	count := 0
	err = sp.Drain(func(ev *event.Event) error {
		count++
		if ev.EventID == "b" {
			return errors.New("upstream down")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	// "a" consumed; "b" failed so "b" + "c" remain.
	var remaining []string
	_ = sp.Drain(func(ev *event.Event) error {
		remaining = append(remaining, ev.EventID)
		return nil
	})
	if len(remaining) != 2 || remaining[0] != "b" || remaining[1] != "c" {
		t.Fatalf("remaining = %v, want [b c]", remaining)
	}
}

func TestSpoolEnforcesMaxSize(t *testing.T) {
	dir := t.TempDir()
	sp, err := NewSpool(filepath.Join(dir, "spool.ndjson"), 200)
	if err != nil {
		t.Fatalf("new spool: %v", err)
	}
	defer sp.Close()

	full := false
	for i := 0; i < 50; i++ {
		if err := sp.Append(newEvent("event-" + string(rune('A'+(i%26))))); err != nil {
			if errors.Is(err, ErrSpoolFull) {
				full = true
				break
			}
			t.Fatalf("append %d: %v", i, err)
		}
	}
	if !full {
		t.Fatalf("expected ErrSpoolFull")
	}
}
