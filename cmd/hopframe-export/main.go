// Command hopframe-export packages an evidence-grade audit bundle for
// a tenant and date range. It pulls the matching records from a
// running control plane, signs the canonical bytes of each record
// with the operator's signing key (when supplied), builds a Merkle
// root over the bundle, and writes the whole package to a directory
// alongside a manifest the receiver can verify offline.
//
// The deliverable is exactly the artifact a SOC 2 / HIPAA auditor
// expects: a self-contained directory holding the records, the chain
// proof at the moment of export, the per-record signatures (when
// signed), and a Merkle root covering the bundle. The receiver does
// not need access to the live control plane to verify; they only need
// the public key and the bundle.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jlupsp/hopframe/internal/buildinfo"
	"github.com/jlupsp/hopframe/pkg/audit"
)

// Set at link time by goreleaser.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	buildinfo.MaybePrint("hopframe-export", version, commit, date)
	base := flag.String("control-plane", "http://127.0.0.1:7090", "control plane base URL")
	token := flag.String("token", "", "bearer token for /v1/* (or set HOPFRAME_API_TOKEN)")
	tenant := flag.String("tenant", "", "tenant id to scope the export (admin tokens only)")
	since := flag.String("since", "", "RFC3339 lower bound (e.g. 2026-04-01T00:00:00Z); empty means earliest")
	until := flag.String("until", "", "RFC3339 upper bound; empty means latest")
	out := flag.String("out", "hopframe-export", "output directory")
	keyFile := flag.String("sign-key", "", "ed25519 seed file used to sign per-record canonical bytes")
	limit := flag.Int("limit", 5000, "maximum records to include")
	flag.Parse()

	if *token == "" {
		*token = os.Getenv("HOPFRAME_API_TOKEN")
	}
	if *base == "" {
		fail("--control-plane is required")
	}
	if *limit <= 0 {
		*limit = 5000
	}

	var sinceT, untilT time.Time
	var err error
	if *since != "" {
		sinceT, err = time.Parse(time.RFC3339, *since)
		if err != nil {
			fail("--since: %v", err)
		}
	}
	if *until != "" {
		untilT, err = time.Parse(time.RFC3339, *until)
		if err != nil {
			fail("--until: %v", err)
		}
	}

	var signer *audit.Signer
	if *keyFile != "" {
		signer, err = audit.NewSignerFromFile(*keyFile, true)
		if err != nil {
			fail("sign-key: %v", err)
		}
	}

	ctx := context.Background()
	records, headHash, err := fetchRecords(ctx, *base, *token, *tenant, *limit)
	if err != nil {
		fail("fetch: %v", err)
	}
	records = filterByTime(records, sinceT, untilT)
	if len(records) == 0 {
		fail("no records matched the supplied window")
	}

	if err := os.MkdirAll(*out, 0o755); err != nil {
		fail("mkdir: %v", err)
	}

	canonicalLeaves := make([][]byte, 0, len(records))
	signatures := make([]string, 0, len(records))
	for i, rec := range records {
		canonical := canonicalRecord(rec)
		path := filepath.Join(*out, fmt.Sprintf("record-%012d.json", rec.Seq))
		if err := os.WriteFile(path, canonical, 0o644); err != nil {
			fail("write record %d: %v", rec.Seq, err)
		}
		h := sha256.Sum256(canonical)
		canonicalLeaves = append(canonicalLeaves, h[:])
		if signer != nil {
			signatures = append(signatures, signer.Sign(canonical))
		} else {
			signatures = append(signatures, "")
		}
		_ = i
	}

	tree := audit.NewMerkleTree(canonicalLeaves)
	manifest := exportManifest{
		Schema:       "hopframe.export/v1",
		ExportedAt:   time.Now().UTC(),
		ControlPlane: *base,
		Tenant:       *tenant,
		ChainHead:    headHash,
		MerkleRoot:   hex.EncodeToString(tree.Root()),
		RecordCount:  len(records),
		SignerPubKey: publicKeyOrEmpty(signer),
	}
	for i, rec := range records {
		manifest.Records = append(manifest.Records, exportEntry{
			Seq:       rec.Seq,
			Hash:      rec.Hash,
			LeafHash:  hex.EncodeToString(canonicalLeaves[i]),
			IngestAt:  rec.IngestAt,
			Signature: signatures[i],
		})
	}
	manifestPath := filepath.Join(*out, "manifest.json")
	body, _ := json.MarshalIndent(manifest, "", "  ")
	if err := os.WriteFile(manifestPath, body, 0o644); err != nil {
		fail("write manifest: %v", err)
	}

	verify := []string{
		"# How to verify this export",
		"",
		"1. Confirm chain_head matches the source control plane.",
		"   Compare manifest.json:chain_head with `GET /v1/stats` head_hash.",
		"",
		"2. For any record-XXXXXXXXXXXX.json, recompute its sha256.",
		"   That hash equals manifest.json:records[].leaf_hash.",
		"",
		"3. If a signer public key is set, verify per-record signatures.",
		"   public_key = manifest.json:signer_pub_key",
		"   For record N, the signature is manifest.json:records[N].signature",
		"   over the canonical bytes of record-N.json (whole file).",
		"",
		"4. Build a Merkle tree over leaf_hash entries (in record order)",
		"   and confirm the root equals manifest.json:merkle_root.",
		"",
		"Tools: `go run github.com/jlupsp/hopframe/pkg/audit` is the",
		"reference. Any auditor with the public key and this bundle can verify",
		"without contacting the control plane.",
	}
	if err := os.WriteFile(filepath.Join(*out, "VERIFY.md"), []byte(strings.Join(verify, "\n")+"\n"), 0o644); err != nil {
		fail("write VERIFY.md: %v", err)
	}

	fmt.Printf("wrote %d records to %s\nchain_head: %s\nmerkle_root: %s\n",
		len(records), *out, manifest.ChainHead, manifest.MerkleRoot)
}

type exportManifest struct {
	Schema       string        `json:"schema"`
	ExportedAt   time.Time     `json:"exported_at"`
	ControlPlane string        `json:"control_plane"`
	Tenant       string        `json:"tenant,omitempty"`
	ChainHead    string        `json:"chain_head"`
	MerkleRoot   string        `json:"merkle_root"`
	RecordCount  int           `json:"record_count"`
	SignerPubKey string        `json:"signer_pub_key,omitempty"`
	Records      []exportEntry `json:"records"`
}

type exportEntry struct {
	Seq       uint64    `json:"seq"`
	Hash      string    `json:"hash"`
	LeafHash  string    `json:"leaf_hash"`
	IngestAt  time.Time `json:"ingest_at"`
	Signature string    `json:"signature,omitempty"`
}

type record struct {
	Seq      uint64          `json:"seq"`
	IngestAt time.Time       `json:"ingest_at"`
	PrevHash string          `json:"prev_hash"`
	Hash     string          `json:"hash"`
	Event    json.RawMessage `json:"event"`
}

func fetchRecords(ctx context.Context, base, token, tenant string, limit int) ([]record, string, error) {
	stats, err := fetchStats(ctx, base, token)
	if err != nil {
		return nil, "", err
	}
	q := url.Values{}
	q.Set("limit", fmt.Sprintf("%d", limit))
	if tenant != "" {
		q.Set("tenant_id", tenant)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/v1/events?"+q.Encode(), nil)
	if err != nil {
		return nil, "", err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, "", fmt.Errorf("status %d: %s", resp.StatusCode, body)
	}
	var body struct {
		Records []record `json:"records"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, "", err
	}
	out := make([]record, 0, len(body.Records))
	out = append(out, body.Records...)
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, stats.HeadHash, nil
}

type stats struct {
	HeadHash string `json:"head_hash"`
	Seq      uint64 `json:"seq"`
}

func fetchStats(ctx context.Context, base, token string) (stats, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/v1/stats", nil)
	if err != nil {
		return stats{}, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return stats{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return stats{}, fmt.Errorf("stats status %d", resp.StatusCode)
	}
	var s stats
	if err := json.NewDecoder(resp.Body).Decode(&s); err != nil {
		return stats{}, err
	}
	if s.HeadHash == "" {
		return stats{}, errors.New("control plane returned empty chain head")
	}
	return s, nil
}

func filterByTime(in []record, since, until time.Time) []record {
	out := make([]record, 0, len(in))
	for _, r := range in {
		if !since.IsZero() && r.IngestAt.Before(since) {
			continue
		}
		if !until.IsZero() && r.IngestAt.After(until) {
			continue
		}
		out = append(out, r)
	}
	return out
}

func canonicalRecord(r record) []byte {
	body, _ := json.Marshal(map[string]any{
		"seq":       r.Seq,
		"ingest_at": r.IngestAt.Format(time.RFC3339Nano),
		"prev_hash": r.PrevHash,
		"event":     r.Event,
	})
	return body
}

func publicKeyOrEmpty(s *audit.Signer) string {
	if s == nil {
		return ""
	}
	return s.PublicKey()
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "hopframe-export: "+format+"\n", args...)
	os.Exit(1)
}
