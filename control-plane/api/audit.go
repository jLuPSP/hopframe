package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jlupsp/hopframe/control-plane/store"
	"github.com/jlupsp/hopframe/pkg/audit"
)

// SetSigner installs an Ed25519 signer that produces per-record
// signatures and signs forensic-export bundles. With a signer, every
// record exposed via /v1/records/{seq} carries its signature alongside
// the chain hash, so a single record can be disclosed to an auditor
// with proof of authorship while the rest of the chain stays private.
func (s *Server) SetSigner(sg *audit.Signer) {
	s.signer = sg
}

// SetRekor installs a Rekor adapter the control plane uses on chain
// rotation and on demand at /v1/audit/anchor. Pass nil to disable.
func (s *Server) SetRekor(r *audit.Rekor) {
	s.rekor = r
}

// AnchorChainHead posts the current chain head to the configured Rekor
// instance and writes a synthetic audit event recording the result.
// Operators wire this to a chain-rotation hook or a periodic timer.
func (s *Server) AnchorChainHead(ctx context.Context) (*audit.RekorAnchor, error) {
	if s.rekor == nil {
		return nil, errRekorNotConfigured
	}
	stats := s.store.Stats()
	if stats.HeadHash == "" {
		return nil, errEmptyChain
	}
	a, err := s.rekor.Anchor(ctx, stats.HeadHash)
	if err != nil {
		return nil, err
	}
	s.recordAnchorEvent(a)
	return a, nil
}

func (s *Server) recordAnchorEvent(a *audit.RekorAnchor) {
	body, _ := json.Marshal(a)
	now := time.Now().UTC()
	ev := newSyntheticEvent(now, "audit.rekor.anchor", "audit_anchor",
		"chain head anchored to rekor: head="+a.HeadHash+" log_index="+strconv.FormatInt(a.LogIndex, 10),
		map[string]any{
			"head_hash":     a.HeadHash,
			"log_index":     a.LogIndex,
			"uuid":          a.UUID,
			"url":           a.URL,
			"integrated_at": a.IntegratedAt,
			"raw":           json.RawMessage(body),
		})
	if rec, err := s.store.Append(&ev); err == nil && s.hub != nil {
		s.hub.broadcast(rec)
	}
}

func (s *Server) handleAuditAnchor(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	a, err := s.AnchorChainHead(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, a)
}

// handleRecordByID exposes a single record with its per-record
// signature and a Merkle proof tying it to a snapshot of the chain.
// Path: /v1/records/{seq}.
func (s *Server) handleRecordByID(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/v1/records/")
	if rest == r.URL.Path || rest == "" {
		http.Error(w, "expected /v1/records/{seq}", http.StatusBadRequest)
		return
	}
	seq, err := strconv.ParseUint(rest, 10, 64)
	if err != nil {
		http.Error(w, "seq must be an integer", http.StatusBadRequest)
		return
	}
	recs, _ := s.store.Read(store.Query{
		Limit:    10000,
		TenantID: tenantFor(r),
	})
	var target *store.Record
	others := make([]store.Record, 0, len(recs))
	for i := range recs {
		if recs[i].Seq == seq {
			target = &recs[i]
		}
		others = append(others, recs[i])
	}
	if target == nil {
		http.Error(w, "record not found", http.StatusNotFound)
		return
	}
	canonical := canonicalRecordBytes(target)
	resp := map[string]any{
		"record":    target,
		"canonical": string(canonical),
	}
	if s.signer != nil {
		resp["signature"] = s.signer.Sign(canonical)
		resp["public_key"] = s.signer.PublicKey()
	}

	leaves := make([][]byte, 0, len(others))
	idx := -1
	for i, rec := range others {
		h := sha256.Sum256(canonicalRecordBytes(&rec))
		leaves = append(leaves, h[:])
		if rec.Seq == seq {
			idx = i
		}
	}
	if idx >= 0 {
		tree := audit.NewMerkleTree(leaves)
		proof := tree.Proof(idx)
		steps := make([]map[string]any, 0, len(proof))
		for _, st := range proof {
			steps = append(steps, map[string]any{
				"sibling":       hex.EncodeToString(st.Sibling),
				"right_sibling": st.RightSibling,
			})
		}
		resp["merkle_root"] = hex.EncodeToString(tree.Root())
		resp["merkle_proof"] = steps
		resp["merkle_window"] = len(leaves)
	}
	writeJSON(w, http.StatusOK, resp)
}

// canonicalRecordBytes is the byte form a verifier hashes to recompute
// the per-record signature or Merkle leaf. It mirrors what
// audit.CanonicalRecord produces, given the Record fields.
func canonicalRecordBytes(rec *store.Record) []byte {
	evJSON, _ := json.Marshal(rec.Event)
	return audit.CanonicalRecord(rec.Seq, rec.IngestAt.Format(time.RFC3339Nano), rec.PrevHash, string(evJSON))
}

type apiError string

func (e apiError) Error() string { return string(e) }

const (
	errRekorNotConfigured apiError = "rekor not configured"
	errEmptyChain         apiError = "chain is empty; nothing to anchor"
)
