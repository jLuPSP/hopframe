package api

import (
	"encoding/json"
	"net/http"

	"github.com/jlupsp/hopframe/pkg/taint"
)

// Shared cross-protocol taint. Sensors mint taints locally; with several
// sensors (split MCP/A2A processes, or replicas) the in-process tracker
// alone cannot recognize that data read on one process is leaving from
// another. These two endpoints let sensors share taints through the
// control plane. They exchange fingerprints only, never raw values, so
// the tagged data never leaves the sensor that read it.

type taintRegisterReq struct {
	AgentRun     string       `json:"agent_run"`
	Source       taint.Source `json:"source"`
	Sample       string       `json:"sample"`
	Fingerprints []string     `json:"fingerprints"`
}

type taintMatchReq struct {
	AgentRun     string   `json:"agent_run"`
	Fingerprints []string `json:"fingerprints"`
}

type taintMatchResp struct {
	Hit    bool         `json:"hit"`
	ID     string       `json:"id,omitempty"`
	Source taint.Source `json:"source,omitempty"`
	Sample string       `json:"sample,omitempty"`
}

// handleTaintRegister stores a sensor-minted taint (fingerprints only) so
// other sensors on this control plane can match it.
func (s *Server) handleTaintRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.taints == nil {
		http.Error(w, "taint sharing disabled", http.StatusServiceUnavailable)
		return
	}
	var req taintRegisterReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.AgentRun == "" || len(req.Fingerprints) == 0 {
		http.Error(w, "agent_run and fingerprints are required", http.StatusBadRequest)
		return
	}
	s.taints.TagFingerprints(req.AgentRun, req.Source, req.Sample, req.Fingerprints)
	w.WriteHeader(http.StatusNoContent)
}

// handleTaintMatch reports whether any candidate fingerprint overlaps a
// stored taint for the agent run. Always returns 200 with a verdict so the
// sensor's hot path has a single shape to handle.
func (s *Server) handleTaintMatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.taints == nil {
		writeTaintJSON(w, taintMatchResp{Hit: false})
		return
	}
	var req taintMatchReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	hit, ok := s.taints.MatchFingerprints(req.AgentRun, req.Fingerprints)
	if !ok {
		writeTaintJSON(w, taintMatchResp{Hit: false})
		return
	}
	writeTaintJSON(w, taintMatchResp{Hit: true, ID: hit.ID, Source: hit.Source, Sample: hit.Sample})
}

func writeTaintJSON(w http.ResponseWriter, v taintMatchResp) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
