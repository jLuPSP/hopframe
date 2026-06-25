package client

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/jlupsp/hopframe/pkg/taint"
)

// TaintSync implements taint.Remote against the control plane, so a taint
// minted on one sensor is matchable on another (cross-replica, and across
// separate MCP/A2A sensor processes). It sends fingerprints, never the raw
// tagged value, so the data stays on the sensor that read it. Push is
// best-effort and async; Match is synchronous with a bounded timeout
// because it runs on the forward/block hot path.
type TaintSync struct {
	Client       *Client
	PushTimeout  time.Duration
	MatchTimeout time.Duration
}

var _ taint.Remote = (*TaintSync)(nil)

type taintRegisterBody struct {
	AgentRun     string       `json:"agent_run"`
	Source       taint.Source `json:"source"`
	Sample       string       `json:"sample,omitempty"`
	Fingerprints []string     `json:"fingerprints"`
}

type taintMatchBody struct {
	AgentRun     string   `json:"agent_run"`
	Fingerprints []string `json:"fingerprints"`
}

type taintMatchResp struct {
	Hit    bool         `json:"hit"`
	ID     string       `json:"id,omitempty"`
	Source taint.Source `json:"source,omitempty"`
	Sample string       `json:"sample,omitempty"`
}

// Push registers a freshly minted taint with the control plane.
func (s *TaintSync) Push(agentRun string, t taint.Taint) {
	if s == nil || s.Client == nil {
		return
	}
	body, err := json.Marshal(taintRegisterBody{
		AgentRun:     agentRun,
		Source:       t.Source,
		Sample:       t.Sample,
		Fingerprints: t.FingerprintList(),
	})
	if err != nil {
		return
	}
	to := s.PushTimeout
	if to <= 0 {
		to = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), to)
	defer cancel()
	req, err := s.Client.newRequest(ctx, http.MethodPost, "/v1/taints", bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.Client.do(req)
	if err != nil {
		return
	}
	_ = resp.Body.Close()
}

// Match asks the control plane whether any candidate fingerprint overlaps
// a taint for agentRun. Returns a partial Taint (id, source, sample) on a
// hit; failures and timeouts return false so the wire fails open to local.
func (s *TaintSync) Match(agentRun string, fingerprints []string) (taint.Taint, bool) {
	if s == nil || s.Client == nil || len(fingerprints) == 0 {
		return taint.Taint{}, false
	}
	body, err := json.Marshal(taintMatchBody{AgentRun: agentRun, Fingerprints: fingerprints})
	if err != nil {
		return taint.Taint{}, false
	}
	to := s.MatchTimeout
	if to <= 0 {
		to = 2 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), to)
	defer cancel()
	req, err := s.Client.newRequest(ctx, http.MethodPost, "/v1/taints/match", bytes.NewReader(body))
	if err != nil {
		return taint.Taint{}, false
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.Client.do(req)
	if err != nil {
		return taint.Taint{}, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return taint.Taint{}, false
	}
	var r taintMatchResp
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil || !r.Hit {
		return taint.Taint{}, false
	}
	return taint.Taint{ID: r.ID, Source: r.Source, Sample: r.Sample}, true
}
