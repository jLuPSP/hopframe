package audit

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAnchorDisabledReturnsSynthetic(t *testing.T) {
	r := &Rekor{Disabled: true}
	a, err := r.Anchor(context.Background(), "abc")
	if err != nil {
		t.Fatal(err)
	}
	if a.LogIndex != -1 {
		t.Errorf("disabled log index = %d, want -1", a.LogIndex)
	}
	if a.HeadHash != "abc" {
		t.Errorf("head hash = %q, want abc", a.HeadHash)
	}
}

func TestAnchorRejectsEmptyHash(t *testing.T) {
	r := &Rekor{Disabled: true}
	if _, err := r.Anchor(context.Background(), ""); err == nil {
		t.Fatal("expected error on empty hash")
	}
}

func TestAnchorPostsAndParsesResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/log/entries" || r.Method != http.MethodPost {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"24296fb24b8ad77a": map[string]any{
				"logIndex":       int64(99342),
				"integratedTime": int64(1234567890),
				"body":           "ZHVtbXk=",
			},
		})
	}))
	defer srv.Close()

	r := &Rekor{Endpoint: srv.URL}
	a, err := r.Anchor(context.Background(), "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("anchor: %v", err)
	}
	if a.UUID != "24296fb24b8ad77a" {
		t.Errorf("uuid = %q", a.UUID)
	}
	if a.LogIndex != 99342 {
		t.Errorf("log index = %d", a.LogIndex)
	}
	if a.URL == "" || a.IntegratedAt.IsZero() {
		t.Errorf("anchor missing URL or integrated time: %+v", a)
	}
}
