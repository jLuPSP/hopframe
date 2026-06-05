// Package client is the sensor-side fetcher for policies and content
// updates from the Hopframe control plane.
//
// Sensors pull a policy snapshot at boot, then poll on a heartbeat
// interval. When the version stamp returned by the heartbeat differs
// from the last applied snapshot, the sensor refetches and atomically
// swaps in the new policy state. This lets operators ship policy
// changes without restarting sensors.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/jlupsp/hopframe/pkg/detect"
	"github.com/jlupsp/hopframe/pkg/policy"
)

// Snapshot is the immutable view of a policy state the sensor has
// applied. New snapshots replace old ones via Engine.Swap.
type Snapshot struct {
	Version  int64
	Policies []policy.Policy
}

// Engine holds the currently active policy snapshot. Reads are
// lock-free via atomic.Pointer; writes go through Swap.
type Engine struct {
	cur atomic.Pointer[Snapshot]
}

// NewEngine returns an empty engine. Callers should call Swap once
// after the first fetch to install an initial snapshot.
func NewEngine() *Engine {
	e := &Engine{}
	empty := &Snapshot{}
	e.cur.Store(empty)
	return e
}

// Snapshot returns the current snapshot. Never nil.
func (e *Engine) Snapshot() *Snapshot {
	return e.cur.Load()
}

// Swap installs a new snapshot. The previous snapshot is returned for
// the caller to inspect (e.g. for logging the version delta).
func (e *Engine) Swap(s *Snapshot) *Snapshot {
	if s == nil {
		s = &Snapshot{}
	}
	return e.cur.Swap(s)
}

// Resolve runs the policy resolver against the engine's current
// snapshot. Convenience wrapper so callers do not have to reach into
// the snapshot directly.
func (e *Engine) Resolve(ctx policy.EventContext, v *detect.Verdict, defaultMode detect.Mode) (detect.Mode, *policy.Policy) {
	snap := e.cur.Load()
	return policy.Resolve(snap.Policies, ctx, v, defaultMode)
}

// Client fetches the active policy snapshot from a control plane and
// reports sensor heartbeats back to it.
type Client struct {
	BaseURL    string
	Token      string
	HTTPClient *http.Client
	SensorID   string
	TenantID   string
}

// FetchActive performs a GET /v1/policies/active and returns the
// snapshot. Tenant-scoped tokens automatically scope the result on the
// server side, so callers do not need to filter again.
func (c *Client) FetchActive(ctx context.Context) (*Snapshot, error) {
	req, err := c.newRequest(ctx, http.MethodGet, "/v1/policies/active", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, c.errFromResp("fetch policies", resp)
	}
	var body struct {
		Policies []policy.Policy `json:"policies"`
		Version  int64           `json:"version"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("decode policies: %w", err)
	}
	return &Snapshot{Version: body.Version, Policies: body.Policies}, nil
}

// HeartbeatBody is what the sensor sends on POST /v1/sensors/heartbeat.
type HeartbeatBody struct {
	SensorID         string    `json:"sensor_id"`
	TenantID         string    `json:"tenant_id,omitempty"`
	Hostname         string    `json:"hostname,omitempty"`
	BinaryVersion    string    `json:"binary_version,omitempty"`
	PolicyVersion    int64     `json:"policy_version"`
	ContentVersion   string    `json:"content_version,omitempty"`
	StartedAt        time.Time `json:"started_at,omitempty"`
	EventsForwarded  int64     `json:"events_forwarded,omitempty"`
	FindingsObserved int64     `json:"findings_observed,omitempty"`
}

// HeartbeatAck is the control plane's response. The sensor uses
// PolicyVersion to decide whether to refetch the snapshot.
type HeartbeatAck struct {
	Ack            bool   `json:"ack"`
	PolicyVersion  int64  `json:"policy_version"`
	ContentVersion string `json:"content_version,omitempty"`
}

// Heartbeat reports current sensor state and returns the active
// policy/content versions on the control plane. The sensor compares
// these to its applied versions and refetches on mismatch.
func (c *Client) Heartbeat(ctx context.Context, hb HeartbeatBody) (*HeartbeatAck, error) {
	body, err := json.Marshal(hb)
	if err != nil {
		return nil, err
	}
	req, err := c.newRequest(ctx, http.MethodPost, "/v1/sensors/heartbeat", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, c.errFromResp("heartbeat", resp)
	}
	var ack HeartbeatAck
	if err := json.NewDecoder(resp.Body).Decode(&ack); err != nil {
		return nil, fmt.Errorf("decode ack: %w", err)
	}
	return &ack, nil
}

func (c *Client) newRequest(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
	if c.BaseURL == "" {
		return nil, errors.New("client: BaseURL required")
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, body)
	if err != nil {
		return nil, err
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	return req, nil
}

func (c *Client) do(req *http.Request) (*http.Response, error) {
	hc := c.HTTPClient
	if hc == nil {
		hc = http.DefaultClient
	}
	return hc.Do(req)
}

func (c *Client) errFromResp(op string, resp *http.Response) error {
	body, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("%s: status %d body=%s", op, resp.StatusCode, string(body))
}

// Loop runs the sensor side of the policy lifecycle. It performs an
// initial fetch, then heartbeats every interval. On a version mismatch
// it refetches and swaps in the new snapshot. The provided callbacks
// observe lifecycle events for logging and metrics.
func (c *Client) Loop(ctx context.Context, engine *Engine, interval time.Duration, hb func() HeartbeatBody, hooks Hooks) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	if engine == nil {
		return
	}
	if snap, err := c.FetchActive(ctx); err == nil {
		engine.Swap(snap)
		hooks.onSwap(snap)
	} else {
		hooks.onError("initial fetch", err)
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			body := HeartbeatBody{}
			if hb != nil {
				body = hb()
			}
			body.PolicyVersion = engine.Snapshot().Version
			ack, err := c.Heartbeat(ctx, body)
			if err != nil {
				hooks.onError("heartbeat", err)
				continue
			}
			if ack.PolicyVersion != engine.Snapshot().Version {
				snap, err := c.FetchActive(ctx)
				if err != nil {
					hooks.onError("refetch", err)
					continue
				}
				engine.Swap(snap)
				hooks.onSwap(snap)
			}
		}
	}
}

// Hooks observe sensor-side lifecycle events. All callbacks are
// optional; nil hooks are no-ops.
type Hooks struct {
	OnSwap  func(*Snapshot)
	OnError func(op string, err error)
}

func (h Hooks) onSwap(s *Snapshot) {
	if h.OnSwap != nil {
		h.OnSwap(s)
	}
}

func (h Hooks) onError(op string, err error) {
	if h.OnError != nil {
		h.OnError(op, err)
	}
}
