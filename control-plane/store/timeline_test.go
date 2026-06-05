package store

import (
	"path/filepath"
	"testing"

	"github.com/jlupsp/hopframe/pkg/event"
)

func TestTimelineFiltersByAgentRunID(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(filepath.Join(dir, "log.ndjson"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	for i, runID := range []string{"alpha", "alpha", "beta", "alpha", "beta"} {
		ev := event.New("s", event.ProtocolMCP, event.DirectionInbound)
		ev.EventID = string(rune('a' + i))
		ev.AgentRunID = runID
		_, _ = st.Append(&ev)
	}
	a := st.Timeline("alpha", "")
	b := st.Timeline("beta", "")
	z := st.Timeline("zeta", "")
	if len(a) != 3 {
		t.Fatalf("alpha timeline len = %d", len(a))
	}
	if len(b) != 2 {
		t.Fatalf("beta timeline len = %d", len(b))
	}
	if len(z) != 0 {
		t.Fatalf("zeta timeline len = %d", len(z))
	}
	// Ascending sequence order.
	for i := 1; i < len(a); i++ {
		if a[i].Seq <= a[i-1].Seq {
			t.Fatalf("timeline not ascending: %+v", a)
		}
	}
}
