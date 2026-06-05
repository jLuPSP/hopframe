package store

import (
	"context"
	"os"
	"testing"

	"github.com/jlupsp/hopframe/pkg/event"
)

// pgTestDSN returns the DSN for the integration-test Postgres or
// skips. Set HOPFRAME_TEST_POSTGRES to the DSN of an empty database
// the test can TRUNCATE in. CI provides this via the service
// container in .github/workflows/ci.yaml; locally:
//
//	docker run --rm -d -p 5432:5432 -e POSTGRES_PASSWORD=hop postgres:16
//	HOPFRAME_TEST_POSTGRES='postgres://postgres:hop@localhost:5432/postgres?sslmode=disable' \
//	  go test ./control-plane/store -run PG -count=1
func pgTestDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("HOPFRAME_TEST_POSTGRES")
	if dsn == "" {
		t.Skip("HOPFRAME_TEST_POSTGRES not set; skipping Postgres integration test")
	}
	return dsn
}

// resetSchema truncates the events table and resets the chain head so
// each test starts clean. Cheaper than spinning a fresh container.
func resetSchema(t *testing.T, s *PGStore) {
	t.Helper()
	ctx := context.Background()
	if _, err := s.pool.Exec(ctx, `TRUNCATE hopframe_events; UPDATE hopframe_chain_head SET seq=0, head_hash='0000000000000000000000000000000000000000000000000000000000000000', chain_start='0000000000000000000000000000000000000000000000000000000000000000'`); err != nil {
		t.Fatalf("reset schema: %v", err)
	}
	s.mu.Lock()
	s.cache = nil
	s.mu.Unlock()
}

func TestPGAppendAndStats(t *testing.T) {
	dsn := pgTestDSN(t)
	s, err := OpenPostgres(PGOptions{DSN: dsn, CacheCap: 100})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()
	resetSchema(t, s)

	for i := 0; i < 5; i++ {
		ev := event.New("test-sensor", event.ProtocolMCP, event.DirectionInbound)
		ev.Action = event.ActionAllow
		if _, err := s.Append(&ev); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	stats := s.Stats()
	if stats.Seq != 5 {
		t.Errorf("seq = %d, want 5", stats.Seq)
	}
	if stats.HeadHash == "" {
		t.Error("head hash empty after 5 appends")
	}
}

func TestPGVerifyRoundtrip(t *testing.T) {
	dsn := pgTestDSN(t)
	s, err := OpenPostgres(PGOptions{DSN: dsn, CacheCap: 100})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()
	resetSchema(t, s)

	for i := 0; i < 10; i++ {
		ev := event.New("test", event.ProtocolMCP, event.DirectionInbound)
		ev.Action = event.ActionAllow
		if _, err := s.Append(&ev); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	bad, err := s.Verify()
	if err != nil {
		t.Fatalf("verify: %v (offending=%+v)", err, bad)
	}
	if bad != nil {
		t.Fatalf("verify returned offending record: %+v", bad)
	}
}

func TestPGReadFiltersByTenant(t *testing.T) {
	dsn := pgTestDSN(t)
	s, err := OpenPostgres(PGOptions{DSN: dsn, CacheCap: 100})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()
	resetSchema(t, s)

	for _, tenant := range []string{"acme", "acme", "globex"} {
		ev := event.New("test", event.ProtocolMCP, event.DirectionInbound)
		ev.TenantID = tenant
		ev.Action = event.ActionAllow
		if _, err := s.Append(&ev); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	got, err := s.Read(Query{Limit: 100, TenantID: "acme"})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("acme tenant filter: got %d, want 2", len(got))
	}
	for _, r := range got {
		if r.Event.TenantID != "acme" {
			t.Errorf("tenant leak: got %q in acme query", r.Event.TenantID)
		}
	}
}

func TestPGSatisfiesAnalyticsStore(t *testing.T) {
	// Compile-time check: *PGStore implements the full interface.
	var _ AnalyticsStore = (*PGStore)(nil)
}
