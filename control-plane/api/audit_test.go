package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/jlupsp/hopframe/control-plane/store"
	"github.com/jlupsp/hopframe/pkg/audit"
	"github.com/jlupsp/hopframe/pkg/event"
)

// auditTestStack stands up a control-plane server, a backing store on
// disk, and an http test server. It returns the *Server so audit tests
// can install a Rekor adapter directly. Cleanup is registered.
func auditTestStack(t *testing.T) (*Server, *store.Store, *httptest.Server) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "log.ndjson"))
	if err != nil {
		t.Fatalf("store open: %v", err)
	}
	srv := NewServer(st, UIHandler())
	ts := httptest.NewServer(srv.Routes())
	t.Cleanup(func() {
		ts.Close()
		st.Close()
	})
	return srv, st, ts
}

func ingestOne(t *testing.T, base string) {
	t.Helper()
	ev := event.New("test-sensor", event.ProtocolMCP, event.DirectionInbound)
	ev.Action = event.ActionAllow
	ev.Severity = event.SeverityLow
	body, _ := json.Marshal(&ev)
	req, _ := http.NewRequest(http.MethodPost, base+"/v1/events", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("ingest status %d body=%s", resp.StatusCode, b)
	}
}

// TestAnchorChainHeadEndToEnd drives the full anchor flow: ingest one
// real event so the chain has a head, post the head to a mock Rekor,
// confirm the anchor record comes back, and confirm a synthetic
// audit.rekor.anchor event landed on the chain so the witness is
// itself part of the audit trail.
func TestAnchorChainHeadEndToEnd(t *testing.T) {
	rekorHits := 0
	rekor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rekorHits++
		if r.URL.Path != "/api/v1/log/entries" || r.Method != http.MethodPost {
			t.Errorf("rekor mock: unexpected %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"abc123def456": map[string]any{
				"logIndex":       int64(42),
				"integratedTime": int64(1700000000),
				"body":           "ZHVtbXk=",
			},
		})
	}))
	defer rekor.Close()

	srv, st, ts := auditTestStack(t)
	srv.SetRekor(&audit.Rekor{Endpoint: rekor.URL})

	ingestOne(t, ts.URL)
	headBefore := st.Stats().HeadHash
	if headBefore == "" {
		t.Fatal("chain head empty after seed event")
	}

	a, err := srv.AnchorChainHead(context.Background())
	if err != nil {
		t.Fatalf("AnchorChainHead: %v", err)
	}
	if rekorHits != 1 {
		t.Errorf("expected 1 rekor hit, got %d", rekorHits)
	}
	if a.UUID != "abc123def456" {
		t.Errorf("anchor uuid = %q", a.UUID)
	}
	if a.LogIndex != 42 {
		t.Errorf("anchor log index = %d", a.LogIndex)
	}
	if a.HeadHash != headBefore {
		t.Errorf("anchor head = %q, want %q", a.HeadHash, headBefore)
	}

	// The anchor itself should be on the chain as a synthetic event.
	recs, err := st.Read(store.Query{Limit: 100})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	found := false
	for _, rec := range recs {
		for _, f := range rec.Event.Findings {
			if f.RuleID == "audit.rekor.anchor" {
				found = true
				// In-memory cache hands back the original Go types from
				// Append; LogIndex is int64. After a chain reload from
				// disk it becomes float64 via JSON, so accept both.
				switch li := f.Metadata["log_index"].(type) {
				case int64:
					if li != 42 {
						t.Errorf("anchor metadata log_index = %d, want 42", li)
					}
				case float64:
					if int64(li) != 42 {
						t.Errorf("anchor metadata log_index = %v, want 42", li)
					}
				default:
					t.Errorf("anchor metadata log_index has unexpected type %T", f.Metadata["log_index"])
				}
				if got, _ := f.Metadata["uuid"].(string); got != "abc123def456" {
					t.Errorf("anchor metadata uuid = %v, want abc123def456", f.Metadata["uuid"])
				}
			}
		}
	}
	if !found {
		t.Fatal("synthetic audit.rekor.anchor event missing from chain")
	}

	// Re-anchoring extends the chain by another synthetic event.
	seqBefore := st.Stats().Seq
	if _, err := srv.AnchorChainHead(context.Background()); err != nil {
		t.Fatalf("second AnchorChainHead: %v", err)
	}
	if got := st.Stats().Seq; got <= seqBefore {
		t.Errorf("chain seq did not advance after second anchor: before=%d after=%d", seqBefore, got)
	}
}

// TestAnchorChainHeadDisabledStillLogs confirms that running Rekor in
// disabled mode still writes a synthetic anchor event on the chain, so
// air-gapped operators can prove the wiring without an outbound call.
func TestAnchorChainHeadDisabledStillLogs(t *testing.T) {
	srv, st, ts := auditTestStack(t)
	srv.SetRekor(&audit.Rekor{Disabled: true})
	ingestOne(t, ts.URL)

	a, err := srv.AnchorChainHead(context.Background())
	if err != nil {
		t.Fatalf("AnchorChainHead disabled: %v", err)
	}
	if a.LogIndex != -1 {
		t.Errorf("disabled anchor log index = %d, want -1", a.LogIndex)
	}

	recs, _ := st.Read(store.Query{Limit: 100})
	saw := false
	for _, rec := range recs {
		for _, f := range rec.Event.Findings {
			if f.RuleID == "audit.rekor.anchor" {
				saw = true
			}
		}
	}
	if !saw {
		t.Fatal("disabled-mode anchor expected to write a synthetic chain event")
	}
}

// TestAnchorChainHeadFreshChain confirms anchoring works on a brand-
// new control plane (the chain has a genesis hash, so HeadHash is
// never literally empty). Operators bringing a control plane online
// should be able to anchor immediately.
func TestAnchorChainHeadFreshChain(t *testing.T) {
	srv, _, _ := auditTestStack(t)
	srv.SetRekor(&audit.Rekor{Disabled: true})
	a, err := srv.AnchorChainHead(context.Background())
	if err != nil {
		t.Fatalf("anchor on fresh chain: %v", err)
	}
	if a.HeadHash == "" {
		t.Fatal("fresh-chain anchor missing head hash")
	}
}

// TestAnchorChainHeadNotConfigured confirms a clear error instead of a
// nil-deref when Rekor was never installed.
func TestAnchorChainHeadNotConfigured(t *testing.T) {
	srv, _, ts := auditTestStack(t)
	ingestOne(t, ts.URL)
	if _, err := srv.AnchorChainHead(context.Background()); err == nil {
		t.Fatal("expected error when rekor is unset")
	}
}

// TestHandleAuditAnchorRequiresAdminRole confirms the HTTP endpoint
// hands back 403 to viewers and is admin-only. Without auth, it falls
// through (the existing behaviour for the open dev case).
func TestHandleAuditAnchorRequiresAdminRole(t *testing.T) {
	rekor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"u": map[string]any{"logIndex": int64(1), "integratedTime": int64(1700000000)},
		})
	}))
	defer rekor.Close()

	srv, _, ts := auditTestStack(t)
	srv.SetRekor(&audit.Rekor{Endpoint: rekor.URL})

	// Configure auth: one admin token, one viewer token. Without auth,
	// the requireRole wrapper short-circuits to allow everything; with
	// it, viewer hits 403.
	srv.SetAuthToken("admin-tok")
	srv.SetRoleTokens(map[string]Role{"viewer-tok": RoleViewer})

	ingestWith(t, ts.URL, "admin-tok", &event.Event{
		EventID:   "seed-1",
		Protocol:  event.ProtocolMCP,
		Direction: event.DirectionInbound,
		SensorID:  "test",
		Action:    event.ActionAllow,
		Severity:  event.SeverityLow,
	})

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/audit/anchor", nil)
	req.Header.Set("Authorization", "Bearer viewer-tok")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post viewer: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("viewer status = %d, want 403", resp.StatusCode)
	}

	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/v1/audit/anchor", nil)
	req.Header.Set("Authorization", "Bearer admin-tok")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post admin: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Errorf("admin status = %d body=%s", resp.StatusCode, b)
	}
}
