package a2a

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestVerifyCardEnd2End(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	store := NewTrustStore()
	store.Add("ExampleOrg", pub)

	card := &AgentCard{
		Name:     "billing-bot",
		Version:  "1.0.0",
		Provider: &Provider{Organization: "ExampleOrg"},
		Skills:   []Skill{{ID: "x", Name: "x"}},
	}
	body, _ := json.Marshal(card)
	res := ValidateCard(card, body)
	sig := ed25519.Sign(priv, res.Canonical)
	card.Signature = base64.StdEncoding.EncodeToString(sig)

	body2, _ := json.Marshal(card)
	res2 := ValidateCard(card, body2)
	ok, err := store.VerifyCard(card, res2.Canonical)
	if err != nil || !ok {
		t.Fatalf("expected verify ok, got ok=%v err=%v", ok, err)
	}
}

func TestVerifyCardRejectsTamper(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	store := NewTrustStore()
	store.Add("ExampleOrg", pub)

	card := &AgentCard{
		Name:     "billing-bot",
		Version:  "1.0.0",
		Provider: &Provider{Organization: "ExampleOrg"},
		Skills:   []Skill{{ID: "x", Name: "x"}},
	}
	body, _ := json.Marshal(card)
	res := ValidateCard(card, body)
	sig := ed25519.Sign(priv, res.Canonical)
	card.Signature = base64.StdEncoding.EncodeToString(sig)

	// Tamper with the card after signing.
	card.Description = "now a totally different description"
	body2, _ := json.Marshal(card)
	res2 := ValidateCard(card, body2)
	ok, err := store.VerifyCard(card, res2.Canonical)
	if ok || err == nil {
		t.Fatalf("expected verify reject after tamper, got ok=%v err=%v", ok, err)
	}
}

func TestVerifyCardRejectsUnknownIssuer(t *testing.T) {
	store := NewTrustStore()
	card := &AgentCard{
		Name:      "x",
		Provider:  &Provider{Organization: "WhoEverDis"},
		Signature: base64.StdEncoding.EncodeToString(make([]byte, 64)),
	}
	body, _ := json.Marshal(card)
	res := ValidateCard(card, body)
	ok, err := store.VerifyCard(card, res.Canonical)
	if ok || err == nil {
		t.Fatalf("expected unknown-issuer reject, got ok=%v err=%v", ok, err)
	}
}
