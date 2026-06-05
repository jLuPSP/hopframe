package a2a

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// TrustStore holds Ed25519 public keys for issuers Hopframe will
// trust as signers of agent cards. The PRD calls for "signature
// verification" of agent cards as a Phase 2 deliverable; this is
// the minimum viable trust primitive behind it.
//
// Keys are keyed by an issuer string (typically the provider's
// organization or a fully qualified DNS name). Cards must declare an
// "issuer" field in their JSON for verification to apply; cards with
// no declared issuer fall through to validator soft-warnings.
type TrustStore struct {
	mu   sync.RWMutex
	keys map[string]ed25519.PublicKey
}

// NewTrustStore returns an empty trust store.
func NewTrustStore() *TrustStore {
	return &TrustStore{keys: make(map[string]ed25519.PublicKey)}
}

// Add registers a public key for an issuer.
func (t *TrustStore) Add(issuer string, key ed25519.PublicKey) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.keys[issuer] = key
}

// Get returns a public key by issuer, if present.
func (t *TrustStore) Get(issuer string) (ed25519.PublicKey, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	k, ok := t.keys[issuer]
	return k, ok
}

// Len returns the number of trusted issuers.
func (t *TrustStore) Len() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.keys)
}

// LoadDir reads every *.pem file under dir and adds the contained
// Ed25519 public key under the issuer derived from the file name
// (e.g. "billing.example.com.pem" → issuer "billing.example.com").
//
// PEM blocks must be of type "PUBLIC KEY" and the underlying key must
// be Ed25519 (32-byte SubjectPublicKeyInfo).
func (t *TrustStore) LoadDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("trust: read dir %s: %w", dir, err)
	}
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".pem" {
			continue
		}
		body, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return fmt.Errorf("trust: read %s: %w", e.Name(), err)
		}
		key, err := parseEd25519PublicKeyPEM(body)
		if err != nil {
			return fmt.Errorf("trust: parse %s: %w", e.Name(), err)
		}
		issuer := strings.TrimSuffix(e.Name(), filepath.Ext(e.Name()))
		t.Add(issuer, key)
	}
	return nil
}

// VerifyCard checks the signature on a card against the trust store.
// Returns:
//
//	ok=true when the issuer is known AND the signature verifies.
//	ok=false with a non-nil error otherwise.
//
// `canonical` is the canonical-JSON bytes returned by ValidateCard
// (signature field stripped, keys sorted recursively).
func (t *TrustStore) VerifyCard(card *AgentCard, canonical []byte) (bool, error) {
	if card == nil {
		return false, errors.New("trust: nil card")
	}
	if card.Signature == "" {
		return false, errors.New("trust: card has no signature")
	}
	issuer := cardIssuer(card)
	if issuer == "" {
		return false, errors.New("trust: card has no declared issuer")
	}
	key, ok := t.Get(issuer)
	if !ok {
		return false, fmt.Errorf("trust: unknown issuer %q", issuer)
	}
	sig, err := decodeSignature(card.Signature)
	if err != nil {
		return false, fmt.Errorf("trust: decode signature: %w", err)
	}
	if !ed25519.Verify(key, canonical, sig) {
		return false, errors.New("trust: signature does not verify")
	}
	return true, nil
}

// cardIssuer returns the declared issuer of a card. We prefer
// provider.organization; callers can declare their own format.
func cardIssuer(card *AgentCard) string {
	if card.Provider != nil && card.Provider.Organization != "" {
		return card.Provider.Organization
	}
	return ""
}

func decodeSignature(s string) ([]byte, error) {
	s = strings.TrimPrefix(s, "ed25519:")
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return nil, errors.New("not a recognized base64 encoding")
}

func parseEd25519PublicKeyPEM(body []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(body)
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	if block.Type != "PUBLIC KEY" && block.Type != "ED25519 PUBLIC KEY" {
		return nil, fmt.Errorf("unsupported PEM type %q", block.Type)
	}
	// Best-effort: accept either raw 32-byte keys (in PEM-encoded form,
	// which is uncommon) or SubjectPublicKeyInfo where the key bytes
	// are in the trailing 32 bytes.
	switch len(block.Bytes) {
	case ed25519.PublicKeySize:
		return ed25519.PublicKey(block.Bytes), nil
	default:
		if len(block.Bytes) > ed25519.PublicKeySize {
			return ed25519.PublicKey(block.Bytes[len(block.Bytes)-ed25519.PublicKeySize:]), nil
		}
	}
	return nil, errors.New("unexpected key length")
}
