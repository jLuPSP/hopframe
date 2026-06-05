package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jlupsp/hopframe/pkg/event"
)

func newEv(id string, action event.Action, sev event.Severity) *event.Event {
	ev := event.New("s", event.ProtocolMCP, event.DirectionInbound)
	ev.EventID = id
	ev.Action = action
	ev.Severity = sev
	ev.Message.Method = "tools/call"
	return &ev
}

func TestAppendAndRead(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(filepath.Join(dir, "log.ndjson"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	for i, action := range []event.Action{event.ActionAllow, event.ActionWarn, event.ActionBlock} {
		_, err := st.Append(newEv(string(rune('a'+i)), action, event.SeverityHigh))
		if err != nil {
			t.Fatalf("append: %v", err)
		}
	}

	all, err := st.Read(Query{Limit: 10})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("got %d records", len(all))
	}
	// Newest first.
	if all[0].Event.Action != event.ActionBlock {
		t.Fatalf("first action = %q", all[0].Event.Action)
	}

	blocks, err := st.Read(Query{Limit: 10, Action: "block"})
	if err != nil || len(blocks) != 1 {
		t.Fatalf("filter action=block: len=%d err=%v", len(blocks), err)
	}
}

func TestReplayRecoversChain(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "log.ndjson")
	st, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	for i := 0; i < 5; i++ {
		_, _ = st.Append(newEv(string(rune('a'+i)), event.ActionAllow, event.SeverityLow))
	}
	stats := st.Stats()
	st.Close()

	st2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer st2.Close()
	if got := st2.Stats(); got.Seq != stats.Seq || got.HeadHash != stats.HeadHash {
		t.Fatalf("stats after replay = %+v, want %+v", got, stats)
	}
}

func TestVerifyDetectsTamper(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "log.ndjson")
	st, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	for i := 0; i < 3; i++ {
		_, _ = st.Append(newEv(string(rune('a'+i)), event.ActionAllow, event.SeverityLow))
	}
	if bad, err := st.Verify(); err != nil || bad != nil {
		t.Fatalf("expected clean chain, got bad=%v err=%v", bad, err)
	}
	st.Close()

	// Corrupt the middle record.
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	corrupted := strings.Replace(string(body), `"action":"allow"`, `"action":"block"`, 1)
	if err := os.WriteFile(path, []byte(corrupted), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	st2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer st2.Close()
	bad, err := st2.Verify()
	if err == nil || bad == nil {
		t.Fatalf("expected verify to detect tamper")
	}
}

func TestQueryFilters(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(filepath.Join(dir, "log.ndjson"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	a := newEv("a", event.ActionAllow, event.SeverityLow)
	a.Findings = []event.Finding{{Category: "prompt-injection"}}
	b := newEv("b", event.ActionWarn, event.SeverityHigh)
	b.Findings = []event.Finding{{Category: "credential-exfiltration"}}
	for _, ev := range []*event.Event{a, b} {
		_, _ = st.Append(ev)
	}

	high, _ := st.Read(Query{Limit: 10, MinSeverity: "high"})
	if len(high) != 1 || high[0].Event.EventID != "b" {
		t.Fatalf("min severity filter: %+v", high)
	}
	creds, _ := st.Read(Query{Limit: 10, Category: "credential-exfiltration"})
	if len(creds) != 1 || creds[0].Event.EventID != "b" {
		t.Fatalf("category filter: %+v", creds)
	}
}
