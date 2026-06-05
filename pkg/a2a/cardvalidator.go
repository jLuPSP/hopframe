package a2a

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// CardValidationResult captures what the validator learned about a card.
type CardValidationResult struct {
	// Schema-level issues that should block adoption.
	Errors []string
	// Soft warnings: card is structurally valid but suspicious.
	Warnings []string
	// Canonical is the JSON used for signature verification (signature
	// field stripped, keys sorted recursively).
	Canonical []byte
	// SignaturePresent indicates whether the card claimed a signature.
	SignaturePresent bool
}

// ValidateCard checks structural well-formedness of an agent card and
// produces canonical bytes suitable for downstream signature
// verification. Signature verification itself is deferred: it requires
// a JWKS resolver tied to the peer's identity, which lives in the
// sensor's policy layer.
func ValidateCard(card *AgentCard, raw []byte) CardValidationResult {
	res := CardValidationResult{}
	if card == nil {
		res.Errors = append(res.Errors, "card is nil")
		return res
	}
	if strings.TrimSpace(card.Name) == "" {
		res.Errors = append(res.Errors, "name is empty")
	}
	if card.URL != "" && !strings.HasPrefix(card.URL, "https://") && !strings.HasPrefix(card.URL, "http://") {
		res.Warnings = append(res.Warnings, "url is not http(s)")
	}
	if card.Version == "" {
		res.Warnings = append(res.Warnings, "version is empty")
	}
	if len(card.Skills) == 0 {
		res.Warnings = append(res.Warnings, "no skills declared")
	}
	for i, sk := range card.Skills {
		if sk.ID == "" && sk.Name == "" {
			res.Warnings = append(res.Warnings, fmt.Sprintf("skill[%d] has neither id nor name", i))
		}
	}
	res.SignaturePresent = card.Signature != ""

	// Canonicalize: drop signature, recursively sort keys.
	if len(raw) > 0 {
		var generic map[string]any
		if err := json.Unmarshal(raw, &generic); err == nil {
			delete(generic, "signature")
			canon, err := canonicalJSON(generic)
			if err == nil {
				res.Canonical = canon
			}
		}
	}
	return res
}

// canonicalJSON serializes v with keys sorted recursively. It does
// not escape HTML and uses no indentation. This is the form a signer
// is expected to have hashed; it is the same form Hopframe will hash
// when it re-runs verification.
func canonicalJSON(v any) ([]byte, error) {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var b strings.Builder
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			kb, _ := json.Marshal(k)
			b.Write(kb)
			b.WriteByte(':')
			child, err := canonicalJSON(t[k])
			if err != nil {
				return nil, err
			}
			b.Write(child)
		}
		b.WriteByte('}')
		return []byte(b.String()), nil
	case []any:
		var b strings.Builder
		b.WriteByte('[')
		for i, child := range t {
			if i > 0 {
				b.WriteByte(',')
			}
			c, err := canonicalJSON(child)
			if err != nil {
				return nil, err
			}
			b.Write(c)
		}
		b.WriteByte(']')
		return []byte(b.String()), nil
	default:
		return json.Marshal(v)
	}
}

// ErrInvalidCard summarizes the worst issue found in a result.
func (r CardValidationResult) ErrInvalidCard() error {
	if len(r.Errors) == 0 {
		return nil
	}
	return errors.New("a2a: invalid card: " + strings.Join(r.Errors, "; "))
}
