// Package exporter forwards control-plane records to external systems
// (SIEM, SOAR, generic webhooks). Phase 1 ships a single HMAC-signed
// webhook target; Phase 3 adds Splunk and Datadog adapters with the
// same shape.
package exporter

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/jlupsp/hopframe/control-plane/store"
)

// Webhook posts each record to URL as JSON. If Secret is set, every
// request carries an X-Hopframe-Signature header equal to the hex
// HMAC-SHA256 of the body. Receivers verify and reject mismatches.
//
// MinSeverity, when set, scopes export to records at or above that
// severity. Useful when SIEM ingestion is metered.
type Webhook struct {
	URL         string
	Secret      string
	Timeout     time.Duration
	MinSeverity string

	client *http.Client
	once   sync.Once
}

func (w *Webhook) lazyInit() {
	w.once.Do(func() {
		t := w.Timeout
		if t <= 0 {
			t = 5 * time.Second
		}
		w.client = &http.Client{Timeout: t}
	})
}

// Send delivers a record to the webhook. Returns nil on 2xx response.
func (w *Webhook) Send(ctx context.Context, rec store.Record) error {
	w.lazyInit()
	if w.URL == "" {
		return nil
	}
	if w.MinSeverity != "" && rec.Event != nil &&
		!meetsMinSeverity(string(rec.Event.Severity), w.MinSeverity) {
		return nil
	}
	body, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Hopframe-Schema", "hopframe.record/v1")
	if w.Secret != "" {
		mac := hmac.New(sha256.New, []byte(w.Secret))
		mac.Write(body)
		req.Header.Set("X-Hopframe-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	resp, err := w.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("exporter: webhook %s responded %d", w.URL, resp.StatusCode)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

// VerifySignature checks the HMAC-SHA256 signature header on an
// incoming request body against secret. Receivers can call this to
// authenticate webhook deliveries.
func VerifySignature(secret string, body []byte, sig string) bool {
	if secret == "" {
		return false
	}
	const prefix = "sha256="
	if len(sig) <= len(prefix) || sig[:len(prefix)] != prefix {
		return false
	}
	got, err := hex.DecodeString(sig[len(prefix):])
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hmac.Equal(mac.Sum(nil), got)
}

func meetsMinSeverity(have, min string) bool {
	rank := map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
	return rank[have] >= rank[min]
}
