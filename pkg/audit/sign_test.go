package audit

import (
	"bytes"
	"crypto/sha256"
	"path/filepath"
	"testing"
)

func TestSignerRoundTrip(t *testing.T) {
	seed := bytes.Repeat([]byte{1}, 32)
	s, err := NewSignerFromSeed(seed)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	canonical := []byte("hello world")
	sig := s.Sign(canonical)
	if err := VerifyRecordSignature(s.PublicKey(), canonical, sig); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if err := VerifyRecordSignature(s.PublicKey(), []byte("tampered"), sig); err == nil {
		t.Fatal("expected verify to fail on tampered payload")
	}
}

func TestNewSignerFromFileCreatesAndPersists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key.seed")
	s1, err := NewSignerFromFile(path, true)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	s2, err := NewSignerFromFile(path, false)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if s1.PublicKey() != s2.PublicKey() {
		t.Fatal("seed not persisted; public keys differ across loads")
	}
}

func leaf(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

func TestMerkleProofVerifies(t *testing.T) {
	leaves := [][]byte{leaf("a"), leaf("b"), leaf("c"), leaf("d"), leaf("e")}
	tree := NewMerkleTree(leaves)
	root := tree.Root()
	for i, l := range leaves {
		path := tree.Proof(i)
		if !VerifyProof(l, path, root) {
			t.Errorf("leaf %d failed proof", i)
		}
	}
	bad := leaf("z")
	if VerifyProof(bad, tree.Proof(0), root) {
		t.Error("forged leaf passed proof")
	}
}

func TestMerkleEmpty(t *testing.T) {
	tree := NewMerkleTree(nil)
	if tree.Root() == nil {
		t.Fatal("empty tree root nil")
	}
	if path := tree.Proof(0); len(path) != 0 {
		t.Fatal("empty tree should not produce a proof path")
	}
}

func TestMerkleSingleLeaf(t *testing.T) {
	leaves := [][]byte{leaf("only")}
	tree := NewMerkleTree(leaves)
	if !bytes.Equal(tree.Root(), leaves[0]) {
		t.Fatalf("single-leaf root must equal the leaf")
	}
	if path := tree.Proof(0); len(path) != 0 {
		t.Fatalf("single-leaf proof len = %d, want 0", len(path))
	}
	if !VerifyProof(leaves[0], nil, tree.Root()) {
		t.Fatal("single-leaf verify failed")
	}
}
