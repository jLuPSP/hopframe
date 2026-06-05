package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/jlupsp/hopframe/pkg/event"
)

func TestRotateDropsOldRecords(t *testing.T) {
	dir := t.TempDir()
	st, err := OpenWithOptions(Options{
		Path:      filepath.Join(dir, "log.ndjson"),
		Retention: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	for i := 0; i < 4; i++ {
		_, _ = st.Append(newEv("old"+string(rune('a'+i)), event.ActionAllow, event.SeverityLow))
	}
	// Wait so the records age past the retention window.
	time.Sleep(150 * time.Millisecond)
	for i := 0; i < 2; i++ {
		_, _ = st.Append(newEv("new"+string(rune('a'+i)), event.ActionAllow, event.SeverityLow))
	}

	kept, dropped, err := st.Rotate()
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if kept != 2 || dropped != 4 {
		t.Fatalf("kept=%d dropped=%d", kept, dropped)
	}
	// Verify the chain on the rotated file is intact.
	if bad, err := st.Verify(); err != nil || bad != nil {
		t.Fatalf("verify after rotate: bad=%+v err=%v", bad, err)
	}
	// Read should still return the surviving records.
	all, _ := st.Read(Query{Limit: 10})
	if len(all) != 2 {
		t.Fatalf("expected 2 records after rotate, got %d", len(all))
	}
}

func TestRotateNoOpWhenRetentionDisabled(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(filepath.Join(dir, "log.ndjson"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()
	for i := 0; i < 3; i++ {
		_, _ = st.Append(newEv("e"+string(rune('a'+i)), event.ActionAllow, event.SeverityLow))
	}
	kept, dropped, err := st.Rotate()
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if kept != 0 || dropped != 0 {
		t.Fatalf("expected no-op when retention=0, got kept=%d dropped=%d", kept, dropped)
	}
}
