package store

import (
	"time"

	"github.com/jlupsp/hopframe/pkg/event"
)

// Metrics is a small rolling-window summary of activity over the
// store cache. Used by the UI's top stats strip.
type Metrics struct {
	WindowSeconds int   `json:"window_seconds"`
	BucketSeconds int   `json:"bucket_seconds"`
	Total         int   `json:"total"`
	Allowed       int   `json:"allowed"`
	Warned        int   `json:"warned"`
	Blocked       int   `json:"blocked"`
	Findings      int   `json:"findings"`
	UniquePeers   int   `json:"unique_peers"`
	UniqueRuns    int   `json:"unique_runs"`
	Sparkline     []int `json:"sparkline"`
}

// Histogram is a per-bucket count split by action, used by the UI's
// timeline chart to show event distribution and threat density.
type Histogram struct {
	WindowSeconds int   `json:"window_seconds"`
	BucketSeconds int   `json:"bucket_seconds"`
	Allow         []int `json:"allow"`
	Warn          []int `json:"warn"`
	Block         []int `json:"block"`
}

// Histogram returns per-bucket counts split by action over the rolling window.
func (s *Store) Histogram(window, bucket time.Duration) Histogram {
	return histogramFromRecords(s.cacheSnapshot(), window, bucket)
}

func histogramFromRecords(records []Record, window, bucket time.Duration) Histogram {
	if window <= 0 {
		window = 5 * time.Minute
	}
	if bucket <= 0 {
		bucket = 10 * time.Second
	}
	cells := int(window / bucket)
	if cells < 1 {
		cells = 1
	}
	out := Histogram{
		WindowSeconds: int(window.Seconds()),
		BucketSeconds: int(bucket.Seconds()),
		Allow:         make([]int, cells),
		Warn:          make([]int, cells),
		Block:         make([]int, cells),
	}
	now := time.Now().UTC()
	cutoff := now.Add(-window)
	for _, rec := range records {
		ev := rec.Event
		if ev == nil || ev.Timestamp.Before(cutoff) {
			continue
		}
		offset := now.Sub(ev.Timestamp)
		idx := cells - 1 - int(offset/bucket)
		if idx < 0 || idx >= cells {
			continue
		}
		switch ev.Action {
		case event.ActionAllow:
			out.Allow[idx]++
		case event.ActionWarn:
			out.Warn[idx]++
		case event.ActionBlock:
			out.Block[idx]++
		}
	}
	return out
}

// Metrics returns aggregate counts and a rolling-window sparkline.
func (s *Store) Metrics(window, bucket time.Duration) Metrics {
	return metricsFromRecords(s.cacheSnapshot(), window, bucket)
}

func metricsFromRecords(records []Record, window, bucket time.Duration) Metrics {
	if window <= 0 {
		window = 5 * time.Minute
	}
	if bucket <= 0 {
		bucket = 10 * time.Second
	}
	cells := int(window / bucket)
	if cells < 1 {
		cells = 1
	}
	out := Metrics{
		WindowSeconds: int(window.Seconds()),
		BucketSeconds: int(bucket.Seconds()),
		Sparkline:     make([]int, cells),
	}
	now := time.Now().UTC()
	cutoff := now.Add(-window)
	peers := make(map[string]struct{})
	runs := make(map[string]struct{})
	for _, rec := range records {
		ev := rec.Event
		if ev == nil || ev.Timestamp.Before(cutoff) {
			continue
		}
		out.Total++
		out.Findings += len(ev.Findings)
		switch ev.Action {
		case event.ActionAllow:
			out.Allowed++
		case event.ActionWarn:
			out.Warned++
		case event.ActionBlock:
			out.Blocked++
		}
		if ev.Counterparty != "" {
			peers[ev.Counterparty] = struct{}{}
		}
		if ev.AgentRunID != "" {
			runs[ev.AgentRunID] = struct{}{}
		}
		offset := now.Sub(ev.Timestamp)
		idx := cells - 1 - int(offset/bucket)
		if idx >= 0 && idx < cells {
			out.Sparkline[idx]++
		}
	}
	out.UniquePeers = len(peers)
	out.UniqueRuns = len(runs)
	return out
}
