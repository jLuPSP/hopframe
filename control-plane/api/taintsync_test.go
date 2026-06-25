package api

import (
	"testing"
	"time"

	policyclient "github.com/jlupsp/hopframe/pkg/policy/client"
	"github.com/jlupsp/hopframe/pkg/taint"
)

// TestTaintSyncEndToEnd drives the real sensor-side TaintSync HTTP client
// against the live control-plane endpoints: a taint minted and pushed by
// one "sensor" is matched by another through the control plane. This is
// the cross-replica / cross-process path that the in-process tracker alone
// cannot do.
func TestTaintSyncEndToEnd(t *testing.T) {
	ts, _ := setup(t)
	remote := &policyclient.TaintSync{Client: &policyclient.Client{BaseURL: ts.URL}}

	// A sensor mints a taint locally and pushes it (fingerprints only).
	src := taint.New(time.Hour, 64, 1024)
	tt := src.Tag("run-e2e", taint.Source{Protocol: "mcp", Method: "tools/call"},
		"svc_tok_FAKE_0000_DO_NOT_USE_example_only")
	remote.Push("run-e2e", tt)

	// Another sensor, with no local taint, matches the same data via the CP.
	if _, ok := remote.Match("run-e2e", tt.FingerprintList()); !ok {
		t.Fatalf("expected end-to-end taint match through the control plane")
	}
	if _, ok := remote.Match("run-other", tt.FingerprintList()); ok {
		t.Fatalf("must not match across agent runs")
	}
}
