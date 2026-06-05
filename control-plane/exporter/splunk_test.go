package exporter

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/jlupsp/hopframe/control-plane/store"
	"github.com/jlupsp/hopframe/pkg/event"
)

func TestSplunkBatchesAndAuthorizes(t *testing.T) {
	var (
		mu       sync.Mutex
		bodies   []string
		authHdrs []string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(body))
		authHdrs = append(authHdrs, r.Header.Get("Authorization"))
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sp := &Splunk{URL: srv.URL, Token: "tok-abc", Index: "main"}
	sp.batchSize = 2 // force a flush after two records
	for i := 0; i < 4; i++ {
		rec := store.Record{
			Seq:   uint64(i + 1),
			Event: &event.Event{EventID: "e", Severity: event.SeverityHigh},
		}
		if err := sp.Send(context.Background(), rec); err != nil {
			t.Fatalf("send: %v", err)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != 2 {
		t.Fatalf("expected 2 batches, got %d", len(bodies))
	}
	for _, h := range authHdrs {
		if !strings.HasPrefix(h, "Splunk ") {
			t.Fatalf("bad auth header: %q", h)
		}
	}
	// Each batch should be NDJSON containing 2 envelopes with sourcetype.
	for _, b := range bodies {
		lines := strings.Split(strings.TrimSpace(b), "\n")
		if len(lines) != 2 {
			t.Fatalf("expected 2 lines per batch, got %d in %q", len(lines), b)
		}
		var env map[string]any
		if err := json.Unmarshal([]byte(lines[0]), &env); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if env["sourcetype"] != "hopframe:event" || env["index"] != "main" {
			t.Fatalf("envelope = %+v", env)
		}
		if _, ok := env["event"]; !ok {
			t.Fatalf("envelope missing event field: %+v", env)
		}
	}
}

func TestSplunkMinSeverityFilter(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	sp := &Splunk{URL: srv.URL, Token: "tok", MinSeverity: "high"}
	sp.batchSize = 1
	low := store.Record{Event: &event.Event{Severity: event.SeverityLow}}
	high := store.Record{Event: &event.Event{Severity: event.SeverityCritical}}
	_ = sp.Send(context.Background(), low)
	_ = sp.Send(context.Background(), high)
	if hits != 1 {
		t.Fatalf("expected 1 splunk hit (high only), got %d", hits)
	}
}
