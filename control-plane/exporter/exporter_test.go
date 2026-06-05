package exporter

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/jlupsp/hopframe/control-plane/store"
	"github.com/jlupsp/hopframe/pkg/event"
)

func TestWebhookSendsAndSigns(t *testing.T) {
	var (
		mu       sync.Mutex
		received [][]byte
		sigs     []string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		received = append(received, body)
		sigs = append(sigs, r.Header.Get("X-Hopframe-Signature"))
		mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	wh := &Webhook{URL: srv.URL, Secret: "topsecret"}
	rec := store.Record{Seq: 1, Event: &event.Event{EventID: "e1", Severity: event.SeverityHigh}}
	if err := wh.Send(context.Background(), rec); err != nil {
		t.Fatalf("send: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(received) != 1 {
		t.Fatalf("got %d posts", len(received))
	}
	mac := hmac.New(sha256.New, []byte("topsecret"))
	mac.Write(received[0])
	wantSig := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if sigs[0] != wantSig {
		t.Fatalf("signature mismatch:\n got=%s\nwant=%s", sigs[0], wantSig)
	}
}

func TestWebhookMinSeverityFilter(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	wh := &Webhook{URL: srv.URL, MinSeverity: "high"}
	low := store.Record{Seq: 1, Event: &event.Event{Severity: event.SeverityLow}}
	high := store.Record{Seq: 2, Event: &event.Event{Severity: event.SeverityCritical}}
	_ = wh.Send(context.Background(), low)
	_ = wh.Send(context.Background(), high)
	if hits != 1 {
		t.Fatalf("expected 1 webhook hit (high only), got %d", hits)
	}
}

func TestVerifySignatureRejectsTamper(t *testing.T) {
	body := []byte(`{"x":1}`)
	mac := hmac.New(sha256.New, []byte("k"))
	mac.Write(body)
	good := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if !VerifySignature("k", body, good) {
		t.Fatalf("expected verify ok")
	}
	if VerifySignature("k", []byte(`{"x":2}`), good) {
		t.Fatalf("expected verify reject on tampered body")
	}
	if VerifySignature("wrong", body, good) {
		t.Fatalf("expected verify reject on wrong secret")
	}
}
