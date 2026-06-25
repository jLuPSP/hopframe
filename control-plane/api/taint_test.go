package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/jlupsp/hopframe/pkg/taint"
)

func TestTaintRegisterAndMatch(t *testing.T) {
	ts, _ := setup(t)

	// A sensor registers a taint (fingerprints only, never the raw value).
	reg, _ := json.Marshal(taintRegisterReq{
		AgentRun:     "run-1",
		Source:       taint.Source{Protocol: "mcp", Method: "tools/call"},
		Sample:       "svc_tok_FAKE",
		Fingerprints: []string{"fp-a", "fp-b", "fp-c"},
	})
	resp, err := http.Post(ts.URL+"/v1/taints", "application/json", bytes.NewReader(reg))
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("register status = %d", resp.StatusCode)
	}

	match := func(run string, fps []string) taintMatchResp {
		body, _ := json.Marshal(taintMatchReq{AgentRun: run, Fingerprints: fps})
		r, err := http.Post(ts.URL+"/v1/taints/match", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("match: %v", err)
		}
		defer r.Body.Close()
		var out taintMatchResp
		if err := json.NewDecoder(r.Body).Decode(&out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return out
	}

	// A different sensor matches an overlapping fingerprint on the same run.
	if out := match("run-1", []string{"fp-x", "fp-b"}); !out.Hit || out.Source.Protocol != "mcp" {
		t.Fatalf("expected hit with mcp source, got %+v", out)
	}
	// No overlap, and wrong run, must both miss.
	if out := match("run-1", []string{"fp-none"}); out.Hit {
		t.Fatalf("unexpected hit on non-overlapping fingerprints")
	}
	if out := match("run-2", []string{"fp-b"}); out.Hit {
		t.Fatalf("unexpected hit across agent runs")
	}
}
