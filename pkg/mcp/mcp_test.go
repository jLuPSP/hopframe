package mcp

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParseRequest(t *testing.T) {
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hi"}}}`)
	env, err := Parse(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !env.IsRequest() {
		t.Fatalf("expected request envelope")
	}
	if env.Method != MethodToolsCall {
		t.Fatalf("method = %q", env.Method)
	}
	p, err := env.DecodeToolCallParams()
	if err != nil {
		t.Fatalf("decode params: %v", err)
	}
	if p.Name != "echo" {
		t.Fatalf("name = %q", p.Name)
	}
	if got := p.Arguments["text"]; got != "hi" {
		t.Fatalf("arg text = %v", got)
	}
}

func TestParseResponse(t *testing.T) {
	body := []byte(`{"jsonrpc":"2.0","id":7,"result":{"tools":[{"name":"x","description":"d"}]}}`)
	env, err := Parse(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !env.IsResponse() {
		t.Fatalf("expected response envelope")
	}
	res, err := env.DecodeToolsListResult()
	if err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if len(res.Tools) != 1 || res.Tools[0].Name != "x" {
		t.Fatalf("tools = %+v", res.Tools)
	}
}

func TestParseRejectsBadVersion(t *testing.T) {
	body := []byte(`{"jsonrpc":"1.0","id":1,"method":"x"}`)
	if _, err := Parse(body); err == nil {
		t.Fatalf("expected error for jsonrpc 1.0")
	}
}

func TestBlockedResponsePreservesID(t *testing.T) {
	id := json.RawMessage(`42`)
	out, err := BlockedResponse(id, "no")
	if err != nil {
		t.Fatalf("blocked response: %v", err)
	}
	if !strings.Contains(string(out), `"id":42`) {
		t.Fatalf("missing id: %s", out)
	}
	parsed, err := Parse(out)
	if err != nil {
		t.Fatalf("re-parse: %v", err)
	}
	if parsed.Error == nil || parsed.Error.Code != ErrCodeBlockedByPolicy {
		t.Fatalf("expected blocked error, got %+v", parsed.Error)
	}
}

func TestExtractFieldsWalksMaps(t *testing.T) {
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hello world","nested":{"key":"value"}}}}`)
	env, err := Parse(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	fields := ExtractFields(env)
	want := map[string]string{
		"params.name":                 "echo",
		"params.arguments.text":       "hello world",
		"params.arguments.nested.key": "value",
	}
	got := map[string]string{}
	for _, f := range fields {
		got[f.Name] = f.Value
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("field %q = %q, want %q (all=%v)", k, got[k], v, got)
		}
	}
}

func TestParseBatchSingle(t *testing.T) {
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	envs, isBatch, err := ParseBatch(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if isBatch {
		t.Fatalf("expected single, got batch")
	}
	if len(envs) != 1 || envs[0].Method != MethodToolsList {
		t.Fatalf("envs = %+v", envs)
	}
}

func TestParseBatchMulti(t *testing.T) {
	body := []byte(`[
		{"jsonrpc":"2.0","id":1,"method":"tools/list"},
		{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"x"}},
		{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1}}
	]`)
	envs, isBatch, err := ParseBatch(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !isBatch {
		t.Fatalf("expected batch")
	}
	if len(envs) != 3 {
		t.Fatalf("got %d envelopes", len(envs))
	}
	if envs[2].Method != MethodNotifyCancelled {
		t.Fatalf("notification method = %q", envs[2].Method)
	}
	if !envs[2].IsNotification() {
		t.Fatalf("third envelope should be a notification (no id)")
	}
}

func TestIsNotificationMethod(t *testing.T) {
	cases := map[string]bool{
		"":                                 false,
		"tools/call":                       false,
		"notifications/cancelled":          true,
		"notifications/progress":           true,
		"notifications/tools/list_changed": true,
		"completion/complete":              false,
	}
	for method, want := range cases {
		if got := IsNotificationMethod(method); got != want {
			t.Errorf("IsNotificationMethod(%q) = %v, want %v", method, got, want)
		}
	}
}

func TestExtractFieldsWalksArrays(t *testing.T) {
	body := []byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"a","description":"alpha"},{"name":"b","description":"beta"}]}}`)
	env, _ := Parse(body)
	fields := ExtractFields(env)
	descriptions := []string{}
	for _, f := range fields {
		if strings.HasSuffix(f.Name, ".description") {
			descriptions = append(descriptions, f.Value)
		}
	}
	if len(descriptions) != 2 {
		t.Fatalf("expected 2 descriptions, got %v", descriptions)
	}
}
