package exporter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/jlupsp/hopframe/control-plane/store"
)

// Splunk delivers records to Splunk via HTTP Event Collector. The
// shape Splunk expects is one JSON object per line with an outer
// "event" wrapper; we batch up to BatchSize records per POST.
//
// Splunk is the dominant on-prem SIEM in the buyer profile we care
// about (financial services, insurance, B2B SaaS with compliance) so
// this adapter is the first concrete SIEM integration the PRD calls
// for in Phase 3.
type Splunk struct {
	// URL is the HEC endpoint, e.g. https://splunk.example.com:8088/services/collector
	URL string
	// Token is the HEC token; sent as Authorization: Splunk <token>.
	Token string
	// Index is the optional Splunk index name.
	Index string
	// SourceType is the optional Splunk sourcetype. Default: "hopframe:event".
	SourceType string
	// MinSeverity, when set, scopes export to records at or above
	// that severity.
	MinSeverity string

	mu        sync.Mutex
	pending   []store.Record
	batchSize int
	flushAt   time.Time
	flushIvl  time.Duration

	client *http.Client
	once   sync.Once
}

func (s *Splunk) lazyInit() {
	s.once.Do(func() {
		if s.SourceType == "" {
			s.SourceType = "hopframe:event"
		}
		if s.batchSize <= 0 {
			s.batchSize = 32
		}
		if s.flushIvl <= 0 {
			s.flushIvl = 2 * time.Second
		}
		s.client = &http.Client{Timeout: 10 * time.Second}
	})
}

// Send buffers the record for batch delivery. When the buffer reaches
// BatchSize or FlushInterval has elapsed since the last flush, the
// batch is POSTed.
func (s *Splunk) Send(ctx context.Context, rec store.Record) error {
	s.lazyInit()
	if s.URL == "" || s.Token == "" {
		return nil
	}
	if s.MinSeverity != "" && rec.Event != nil &&
		!meetsMinSeverity(string(rec.Event.Severity), s.MinSeverity) {
		return nil
	}
	s.mu.Lock()
	s.pending = append(s.pending, rec)
	now := time.Now()
	if s.flushAt.IsZero() {
		s.flushAt = now.Add(s.flushIvl)
	}
	shouldFlush := len(s.pending) >= s.batchSize || !now.Before(s.flushAt)
	s.mu.Unlock()
	if shouldFlush {
		return s.Flush(ctx)
	}
	return nil
}

// Flush posts every buffered record in one HEC call.
func (s *Splunk) Flush(ctx context.Context) error {
	s.lazyInit()
	s.mu.Lock()
	batch := s.pending
	s.pending = nil
	s.flushAt = time.Time{}
	s.mu.Unlock()
	if len(batch) == 0 {
		return nil
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, rec := range batch {
		envelope := map[string]any{
			"sourcetype": s.SourceType,
			"event":      rec,
		}
		if s.Index != "" {
			envelope["index"] = s.Index
		}
		if rec.Event != nil && !rec.Event.Timestamp.IsZero() {
			envelope["time"] = rec.Event.Timestamp.Unix()
		}
		if err := enc.Encode(envelope); err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.URL, bytes.NewReader(buf.Bytes()))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Splunk "+s.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("splunk: hec responded %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}
