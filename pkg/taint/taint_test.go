package taint

import (
	"encoding/base64"
	"testing"
	"time"
)

func TestTagAndMatch(t *testing.T) {
	tr := New(time.Hour, 64, 1024)
	src := Source{Protocol: "mcp", Method: "tools/call", Tool: "fetch", Field: "result.text"}
	tr.Tag("run-1", src, "the user's email is alice@example.com, handle with care")

	got, ok := tr.Match("run-1", "please pass alice@example.com, handle with care to the next agent")
	if !ok {
		t.Fatalf("expected match")
	}
	if got.Source.Tool != "fetch" {
		t.Fatalf("source = %+v", got.Source)
	}
}

func TestNoMatchAcrossRuns(t *testing.T) {
	tr := New(time.Hour, 64, 1024)
	tr.Tag("run-A", Source{}, "secret-value-12345")
	if _, ok := tr.Match("run-B", "secret-value-12345"); ok {
		t.Fatalf("should not match across agent runs")
	}
}

func TestMatchAny(t *testing.T) {
	tr := New(time.Hour, 64, 1024)
	tr.Tag("run-1", Source{}, "abcdefghijklmnopqrstuvwxyzABCDEFG")
	values := []string{"unrelated string", "x abcdefghijklmnopqrstuvwxyzABCDEFG x"}
	if _, ok := tr.MatchAny("run-1", values); !ok {
		t.Fatalf("expected match-any hit on second value")
	}
}

func TestMatchAfterBase64Reencoding(t *testing.T) {
	tr := New(time.Hour, 64, 1024)
	secret := "svc_tok_FAKE_0000_DO_NOT_USE_example_only"
	tr.Tag("run-1", Source{Protocol: "mcp", Method: "tools/call"}, secret)

	// The agent base64-encodes the tainted secret before forwarding it
	// over A2A. Exact-byte matching would miss it; canonical-view matching
	// decodes the candidate and recognizes the underlying bytes.
	encoded := base64.StdEncoding.EncodeToString([]byte(secret))
	if _, ok := tr.Match("run-1", "register token: "+encoded); !ok {
		t.Fatalf("expected match against base64-re-encoded secret")
	}
}

func TestMatchAfterUnicodeObfuscation(t *testing.T) {
	tr := New(time.Hour, 64, 1024)
	secret := "internal-host db-primary.corp.example.internal:5432"
	tr.Tag("run-1", Source{}, secret)

	// Same bytes with a zero-width space (U+200B) smuggled in. Normalization
	// strips it on both sides, so the reuse is still recognized.
	obfuscated := "internal-host db-primary.corp" + string(rune(0x200B)) + ".example.internal:5432"
	if _, ok := tr.Match("run-1", obfuscated); !ok {
		t.Fatalf("expected match against zero-width-obfuscated reuse")
	}
}

func TestNoMatchOnUnrelatedBase64(t *testing.T) {
	tr := New(time.Hour, 64, 1024)
	tr.Tag("run-1", Source{}, "svc_tok_FAKE_0000_DO_NOT_USE_example_only")
	// An unrelated base64 blob must not collide with the tagged secret.
	other := base64.StdEncoding.EncodeToString([]byte("completely different payload, nothing to do with the token"))
	if _, ok := tr.Match("run-1", other); ok {
		t.Fatalf("unrelated base64 should not match")
	}
}

func TestSweepDropsOld(t *testing.T) {
	tr := New(50*time.Millisecond, 64, 1024)
	tr.Tag("run-1", Source{}, "value-aaaaaaaaaaaaaaaaaaaaaa")
	time.Sleep(80 * time.Millisecond)
	dropped := tr.Sweep()
	if dropped != 1 {
		t.Fatalf("expected 1 drop, got %d", dropped)
	}
	if _, ok := tr.Match("run-1", "value-aaaaaaaaaaaaaaaaaaaaaa"); ok {
		t.Fatalf("expected no match after sweep")
	}
}

func TestEvictionAtMaxRuns(t *testing.T) {
	tr := New(time.Hour, 64, 2)
	tr.Tag("a", Source{}, "value-aaaaaaaaaaaaaaaaaaaaaa")
	time.Sleep(2 * time.Millisecond)
	tr.Tag("b", Source{}, "value-bbbbbbbbbbbbbbbbbbbbbb")
	time.Sleep(2 * time.Millisecond)
	tr.Tag("c", Source{}, "value-cccccccccccccccccccccc")
	if got := len(tr.byRun); got != 2 {
		t.Fatalf("expected 2 runs after eviction, got %d", got)
	}
}
