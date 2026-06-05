package a2a

import (
	"strings"
	"testing"
)

func TestParseCard(t *testing.T) {
	body := []byte(`{
		"name": "billing-bot",
		"description": "handles invoices",
		"url": "https://agents.example/billing",
		"version": "1.0.0",
		"skills": [{"id": "invoice.fetch", "name": "fetch invoice"}]
	}`)
	c, err := ParseCard(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if c.Name != "billing-bot" || len(c.Skills) != 1 {
		t.Fatalf("parsed = %+v", c)
	}
}

func TestParseCardRejectsMissingName(t *testing.T) {
	if _, err := ParseCard([]byte(`{"description":"no name"}`)); err == nil {
		t.Fatalf("expected missing-name error")
	}
}

func TestParseTask(t *testing.T) {
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tasks/send","params":{"task":"x"}}`)
	e, err := ParseTask(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if e.Method != MethodTasksSend {
		t.Fatalf("method = %q", e.Method)
	}
}

func TestValidateCardFlagsBadURL(t *testing.T) {
	body := []byte(`{"name":"x","url":"ftp://nope","skills":[]}`)
	c, _ := ParseCard(body)
	res := ValidateCard(c, body)
	got := strings.Join(res.Warnings, " ")
	if !strings.Contains(got, "url") || !strings.Contains(got, "no skills") {
		t.Fatalf("expected url + no-skills warnings, got %v", res.Warnings)
	}
	if len(res.Errors) != 0 {
		t.Fatalf("did not expect hard errors, got %v", res.Errors)
	}
}

func TestValidateCardCanonicalStripsSignature(t *testing.T) {
	body := []byte(`{"name":"x","skills":[],"signature":"deadbeef","version":"1"}`)
	c, _ := ParseCard(body)
	res := ValidateCard(c, body)
	if !res.SignaturePresent {
		t.Fatalf("expected SignaturePresent")
	}
	canon := string(res.Canonical)
	if strings.Contains(canon, "signature") {
		t.Fatalf("canonical should not contain signature: %s", canon)
	}
	// Keys should be sorted: "name","skills","version".
	wantOrder := []string{`"name"`, `"skills"`, `"version"`}
	prev := -1
	for _, k := range wantOrder {
		i := strings.Index(canon, k)
		if i < prev {
			t.Fatalf("keys not sorted: %s", canon)
		}
		prev = i
	}
}
