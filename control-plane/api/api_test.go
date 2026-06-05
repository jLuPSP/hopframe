package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jlupsp/hopframe/control-plane/store"
	"github.com/jlupsp/hopframe/pkg/event"
)

func setup(t *testing.T) (*httptest.Server, *store.Store) {
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
	return ts, st
}

func ingest(t *testing.T, base string, ev *event.Event) {
	t.Helper()
	ingestWith(t, base, "", ev)
}

func ingestWith(t *testing.T, base, token string, ev *event.Event) {
	t.Helper()
	body, _ := json.Marshal(ev)
	req, err := http.NewRequest(http.MethodPost, base+"/v1/events", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("ingest status %d body=%s", resp.StatusCode, b)
	}
}

func TestIngestAndQuery(t *testing.T) {
	ts, _ := setup(t)
	for i, action := range []event.Action{event.ActionAllow, event.ActionWarn, event.ActionBlock} {
		ev := event.New("s", event.ProtocolMCP, event.DirectionInbound)
		ev.EventID = string(rune('a' + i))
		ev.Action = action
		ev.Severity = event.SeverityHigh
		ingest(t, ts.URL, &ev)
	}

	resp, err := http.Get(ts.URL + "/v1/events?action=block")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	var got struct {
		Records []store.Record `json:"records"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.Records) != 1 || got.Records[0].Event.Action != event.ActionBlock {
		t.Fatalf("filter: %+v", got.Records)
	}
}

func TestStreamReceivesNewEvent(t *testing.T) {
	ts, _ := setup(t)

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/v1/events/stream", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("stream: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("stream status: %d", resp.StatusCode)
	}

	done := make(chan string, 1)
	go func() {
		buf := make([]byte, 4096)
		var acc strings.Builder
		for {
			n, err := resp.Body.Read(buf)
			if n > 0 {
				acc.Write(buf[:n])
				if strings.Contains(acc.String(), `"event_id":"streamed"`) {
					done <- acc.String()
					return
				}
			}
			if err != nil {
				done <- acc.String()
				return
			}
		}
	}()

	// Give the stream a moment, then ingest.
	time.Sleep(100 * time.Millisecond)
	ev := event.New("s", event.ProtocolMCP, event.DirectionInbound)
	ev.EventID = "streamed"
	ingest(t, ts.URL, &ev)

	select {
	case got := <-done:
		if !strings.Contains(got, `"event_id":"streamed"`) {
			t.Fatalf("did not see streamed event in output: %q", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for SSE event")
	}
}

func TestVerifyEndpoint(t *testing.T) {
	ts, _ := setup(t)
	for i := 0; i < 3; i++ {
		ev := event.New("s", event.ProtocolMCP, event.DirectionInbound)
		ev.EventID = "v" + string(rune('a'+i))
		ingest(t, ts.URL, &ev)
	}
	resp, err := http.Get(ts.URL + "/v1/verify")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	var got map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&got)
	if got["ok"] != true {
		t.Fatalf("expected ok=true, got %+v", got)
	}
}

func TestUIServesHTML(t *testing.T) {
	ts, _ := setup(t)
	resp, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "Hopframe") {
		t.Fatalf("UI body missing brand: %q", body[:min(200, len(body))])
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func TestPromMetricsEndpoint(t *testing.T) {
	ts, _ := setup(t)

	for i, action := range []event.Action{event.ActionAllow, event.ActionWarn, event.ActionBlock} {
		ev := event.New("s", event.ProtocolMCP, event.DirectionInbound)
		ev.EventID = "p" + string(rune('a'+i))
		ev.Action = action
		ev.Severity = event.SeverityHigh
		ingest(t, ts.URL, &ev)
	}

	resp, err := http.Get(ts.URL + "/metrics")
	if err != nil {
		t.Fatalf("get /metrics: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("content-type: %q", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	out := string(body)

	for _, want := range []string{
		"# TYPE hopframe_uptime_seconds gauge",
		"# TYPE hopframe_chain_head_seq gauge",
		"# TYPE hopframe_events_ingested_total counter",
		`hopframe_events_ingested_total{action="allow"`,
		`hopframe_events_ingested_total{action="warn"`,
		`hopframe_events_ingested_total{action="block"`,
		"# TYPE hopframe_http_requests_total counter",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("/metrics missing %q\noutput:\n%s", want, out)
		}
	}
}

func TestTenantScopedReadsBoundToToken(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "log.ndjson"))
	if err != nil {
		t.Fatalf("store open: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	srv := NewServer(st, UIHandler())
	srv.SetTenantTokens(map[string]string{
		"tokenA": "tenantA",
		"tokenB": "tenantB",
	})
	ts := httptest.NewServer(srv.Routes())
	t.Cleanup(ts.Close)

	for _, ent := range []struct {
		token  string
		tenant string
	}{
		{"tokenA", "tenantA"},
		{"tokenA", "tenantA"},
		{"tokenB", "tenantB"},
	} {
		ev := event.New("s", event.ProtocolMCP, event.DirectionInbound)
		ev.EventID = ent.tenant + "-x"
		ev.TenantID = ent.tenant
		ingestWith(t, ts.URL, ent.token, &ev)
	}

	read := func(token string) []store.Record {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, ts.URL+"/v1/events?limit=100", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("status %d body=%s", resp.StatusCode, b)
		}
		var got struct {
			Records []store.Record `json:"records"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return got.Records
	}

	a := read("tokenA")
	if len(a) != 2 {
		t.Fatalf("tokenA records = %d, want 2", len(a))
	}
	for _, r := range a {
		if r.Event.TenantID != "tenantA" {
			t.Fatalf("tokenA leaked tenant %q", r.Event.TenantID)
		}
	}

	b := read("tokenB")
	if len(b) != 1 {
		t.Fatalf("tokenB records = %d, want 1", len(b))
	}
	if b[0].Event.TenantID != "tenantB" {
		t.Fatalf("tokenB got tenant %q", b[0].Event.TenantID)
	}

	// A tenant-scoped token cannot widen its scope by passing tenant_id.
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/v1/events?limit=100&tenant_id=tenantB", nil)
	req.Header.Set("Authorization", "Bearer tokenA")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	var got struct {
		Records []store.Record `json:"records"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&got)
	for _, r := range got.Records {
		if r.Event.TenantID != "tenantA" {
			t.Fatalf("tokenA escalated to tenant %q via query param", r.Event.TenantID)
		}
	}

	// Unauthenticated request is rejected once tokens are configured.
	resp, err = http.Get(ts.URL + "/v1/events")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauth status: %d, want 401", resp.StatusCode)
	}
}

func TestAdminTokenCanScopeViaQueryParam(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "log.ndjson"))
	if err != nil {
		t.Fatalf("store open: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	srv := NewServer(st, UIHandler())
	srv.SetAuthToken("admin")
	ts := httptest.NewServer(srv.Routes())
	t.Cleanup(ts.Close)

	for _, tenant := range []string{"tenantA", "tenantB", "tenantA"} {
		ev := event.New("s", event.ProtocolMCP, event.DirectionInbound)
		ev.EventID = tenant + "-y"
		ev.TenantID = tenant
		ingestWith(t, ts.URL, "admin", &ev)
	}

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/v1/events?tenant_id=tenantB&limit=100", nil)
	req.Header.Set("Authorization", "Bearer admin")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var got struct {
		Records []store.Record `json:"records"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&got)
	if len(got.Records) != 1 || got.Records[0].Event.TenantID != "tenantB" {
		t.Fatalf("admin scoped read: %+v", got.Records)
	}
}

func TestRateLimit(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "log.ndjson"))
	if err != nil {
		t.Fatalf("store open: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	srv := NewServer(st, UIHandler())
	srv.SetRateLimit(2)
	ts := httptest.NewServer(srv.Routes())
	t.Cleanup(ts.Close)

	var got429 bool
	for i := 0; i < 25; i++ {
		resp, err := http.Get(ts.URL + "/v1/stats")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests {
			got429 = true
			break
		}
	}
	if !got429 {
		t.Fatalf("expected at least one 429 across 25 rapid requests at rps=2")
	}

	mResp, err := http.Get(ts.URL + "/metrics")
	if err != nil {
		t.Fatalf("metrics get: %v", err)
	}
	defer mResp.Body.Close()
	body, _ := io.ReadAll(mResp.Body)
	if !strings.Contains(string(body), `hopframe_rate_limited_total{path="/v1/stats"}`) {
		t.Fatalf("rate-limited counter not exposed:\n%s", body)
	}
}
