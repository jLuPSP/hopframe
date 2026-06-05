package audit

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

// Signer produces and verifies Ed25519 signatures over canonical
// representations of audit records. Used to provide per-record
// signatures distinct from the chain hash, so an operator can disclose
// a single record with proof of authorship without exposing adjacent
// records on the chain.
type Signer struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

// NewSignerFromSeed deterministically builds a signer from a 32-byte
// seed. Suitable for tests and for environments where the key material
// is supplied by an external secret store. Production deployments
// should rotate keys periodically; the chain itself records each
// rotation as a synthetic event.
func NewSignerFromSeed(seed []byte) (*Signer, error) {
	if len(seed) < ed25519.SeedSize {
		return nil, fmt.Errorf("audit: seed must be %d bytes", ed25519.SeedSize)
	}
	priv := ed25519.NewKeyFromSeed(seed[:ed25519.SeedSize])
	return &Signer{priv: priv, pub: priv.Public().(ed25519.PublicKey)}, nil
}

// NewSignerFromFile loads a signer's seed from a file. The file must
// contain exactly 32 bytes (raw, not encoded). If the file does not
// exist and create=true, a fresh seed is generated and written.
func NewSignerFromFile(path string, create bool) (*Signer, error) {
	body, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) && create {
		seed := make([]byte, ed25519.SeedSize)
		if _, err := rand.Read(seed); err != nil {
			return nil, err
		}
		if err := os.WriteFile(path, seed, 0o600); err != nil {
			return nil, err
		}
		return NewSignerFromSeed(seed)
	}
	if err != nil {
		return nil, err
	}
	return NewSignerFromSeed(body)
}

// PublicKey returns the signer's verification key, hex-encoded.
func (s *Signer) PublicKey() string {
	return hex.EncodeToString(s.pub)
}

// Sign returns the base64 signature of the canonical bytes. Callers
// should pass the canonical JSON of the record they want signed.
func (s *Signer) Sign(canonical []byte) string {
	sig := ed25519.Sign(s.priv, canonical)
	return base64.StdEncoding.EncodeToString(sig)
}

// VerifyRecordSignature confirms that signature was produced by the
// holder of pubKey over canonical. pubKey is hex-encoded.
func VerifyRecordSignature(pubKeyHex string, canonical []byte, sigB64 string) error {
	pub, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return fmt.Errorf("decode pub: %w", err)
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return fmt.Errorf("decode sig: %w", err)
	}
	if !ed25519.Verify(pub, canonical, sig) {
		return errors.New("signature does not verify")
	}
	return nil
}

// CanonicalRecord returns the byte representation a verifier hashes to
// produce a per-record signature. It is the same bytes the chain hash
// uses, in compact JSON form. Two callers in agreement on the shape
// (sensor and verifier) reproduce identical bytes.
func CanonicalRecord(seq uint64, ingestAtRFC3339Nano, prevHash, eventJSON string) []byte {
	doc := map[string]any{
		"seq":       seq,
		"ingest_at": ingestAtRFC3339Nano,
		"prev_hash": prevHash,
		"event":     json.RawMessage(eventJSON),
	}
	body, _ := json.Marshal(doc)
	return body
}

// MerkleTree builds an in-memory Merkle tree over a slice of leaves.
// Leaves are SHA-256 hashes (32 bytes). The tree is balanced by
// duplicating odd leaves at each level. Suitable for export bundles up
// to ~hundreds of thousands of records; beyond that, switch to a
// streaming variant.
type MerkleTree struct {
	levels [][][]byte
}

// NewMerkleTree builds the tree from the provided leaves. Empty input
// returns a zero-leaf tree whose root is the SHA-256 of the empty
// string, suitable as a sentinel.
func NewMerkleTree(leaves [][]byte) *MerkleTree {
	if len(leaves) == 0 {
		empty := sha256.Sum256(nil)
		return &MerkleTree{levels: [][][]byte{{empty[:]}}}
	}
	current := make([][]byte, len(leaves))
	copy(current, leaves)
	t := &MerkleTree{levels: [][][]byte{current}}
	for len(current) > 1 {
		if len(current)%2 == 1 {
			current = append(current, current[len(current)-1])
		}
		next := make([][]byte, 0, len(current)/2)
		for i := 0; i < len(current); i += 2 {
			h := sha256.New()
			h.Write(current[i])
			h.Write(current[i+1])
			next = append(next, h.Sum(nil))
		}
		t.levels = append(t.levels, next)
		current = next
	}
	return t
}

// Root returns the Merkle root.
func (t *MerkleTree) Root() []byte {
	if len(t.levels) == 0 {
		return nil
	}
	return t.levels[len(t.levels)-1][0]
}

// Proof returns the audit path that proves leaf at index i is part of
// the tree under Root(). Each step is a 32-byte sibling hash; the
// "right" boolean records whether the sibling is on the right.
func (t *MerkleTree) Proof(i int) []ProofStep {
	if len(t.levels) == 0 || i < 0 {
		return nil
	}
	if i >= len(t.levels[0]) {
		return nil
	}
	var path []ProofStep
	idx := i
	for level := 0; level < len(t.levels)-1; level++ {
		nodes := t.levels[level]
		paired := nodes
		if len(paired)%2 == 1 {
			paired = append(paired, paired[len(paired)-1])
		}
		var sibling []byte
		var right bool
		if idx%2 == 0 {
			sibling = paired[idx+1]
			right = true
		} else {
			sibling = paired[idx-1]
			right = false
		}
		path = append(path, ProofStep{Sibling: sibling, RightSibling: right})
		idx /= 2
	}
	return path
}

// ProofStep is a single sibling hash on the path from a leaf to the
// Merkle root. RightSibling indicates whether the sibling is the right
// child (and therefore the leaf-side hash is on the left).
type ProofStep struct {
	Sibling      []byte
	RightSibling bool
}

// VerifyProof reconstructs the root from leaf and the audit path,
// returning true when the result matches expectedRoot.
func VerifyProof(leaf []byte, path []ProofStep, expectedRoot []byte) bool {
	cur := append([]byte{}, leaf...)
	for _, step := range path {
		h := sha256.New()
		if step.RightSibling {
			h.Write(cur)
			h.Write(step.Sibling)
		} else {
			h.Write(step.Sibling)
			h.Write(cur)
		}
		cur = h.Sum(nil)
	}
	if len(cur) != len(expectedRoot) {
		return false
	}
	for i := range cur {
		if cur[i] != expectedRoot[i] {
			return false
		}
	}
	return true
}
