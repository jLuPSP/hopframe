// Package audit holds cryptographic primitives that turn the chain
// store from "claimed by Hopframe" into "independently witnessed".
//
// Rekor anchoring (this file) posts a chain head hash to a Sigstore
// transparency log on each rotation. The log is append-only and
// publicly auditable, so the timestamp and content of each anchor are
// witnessed by a third party. Operators get the witness URL plus the
// log index back; either is enough for an external auditor to confirm
// the anchor exists.
//
// The default endpoint is the public Sigstore Rekor at
// https://rekor.sigstore.dev. Operators who run a private Rekor (or
// who do not want public-log exposure) can point this at their own
// instance via SetEndpoint.
package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// RekorAnchor records a chain head being witnessed in a Rekor log.
type RekorAnchor struct {
	HeadHash     string    `json:"head_hash"`
	AnchoredAt   time.Time `json:"anchored_at"`
	LogIndex     int64     `json:"log_index"`
	UUID         string    `json:"uuid"`
	URL          string    `json:"url,omitempty"`
	IntegratedAt time.Time `json:"integrated_at,omitempty"`
}

// Rekor is the configurable adapter. Disabled by default; enable by
// setting Endpoint and calling Anchor on chain rotation.
type Rekor struct {
	Endpoint   string
	HTTPClient *http.Client
	// Disabled, when true, makes Anchor a no-op that returns a synthetic
	// "would-have-anchored" record. Useful in development and CI where
	// outbound calls to the public Rekor are inappropriate.
	Disabled bool
}

// DefaultEndpoint is the public Sigstore Rekor. Operators should
// override for private deployments.
const DefaultEndpoint = "https://rekor.sigstore.dev"

// Anchor posts a chain head to the configured Rekor instance and
// returns the anchor record. The request body is the standard hashedrekord
// "intoto" body shape, simplified: we attach the chain head as the
// pre-hashed payload, with the public-key field set to a fixed
// "hopframe-control-plane" identifier. A production deployment will
// switch to keyless signing via Fulcio.
//
// When Disabled is true, Anchor returns a synthetic anchor with
// LogIndex=-1 so callers can wire the path without making a network
// call.
func (r *Rekor) Anchor(ctx context.Context, headHash string) (*RekorAnchor, error) {
	if headHash == "" {
		return nil, errors.New("rekor: empty head hash")
	}
	if r.Disabled {
		shortPrefix := headHash
		if len(shortPrefix) > 8 {
			shortPrefix = shortPrefix[:8]
		}
		return &RekorAnchor{
			HeadHash:   headHash,
			AnchoredAt: time.Now().UTC(),
			LogIndex:   -1,
			UUID:       "disabled-" + shortPrefix,
		}, nil
	}
	endpoint := r.Endpoint
	if endpoint == "" {
		endpoint = DefaultEndpoint
	}
	body, err := buildHashedRekord(headHash)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/api/v1/log/entries", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	hc := r.HTTPClient
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("rekor post: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("rekor status %d: %s", resp.StatusCode, bodyBytes)
	}
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	uuid, logIndex, integratedAt, err := parseRekorResponse(respBody)
	if err != nil {
		return nil, err
	}
	return &RekorAnchor{
		HeadHash:     headHash,
		AnchoredAt:   time.Now().UTC(),
		LogIndex:     logIndex,
		UUID:         uuid,
		URL:          endpoint + "/api/v1/log/entries/" + uuid,
		IntegratedAt: integratedAt,
	}, nil
}

// buildHashedRekord constructs the minimum-viable rekord body. We use
// the hashedrekord type since the chain head is already a SHA-256.
// The signature field is a placeholder; a production deployment binds
// this to a Fulcio-issued key. The current implementation prioritizes
// "we anchored" semantics over "who anchored" semantics; that distinction
// is fine while the chain hash itself is the load-bearing primitive.
func buildHashedRekord(headHash string) ([]byte, error) {
	doc := map[string]any{
		"apiVersion": "0.0.1",
		"kind":       "hashedrekord",
		"spec": map[string]any{
			"data": map[string]any{
				"hash": map[string]any{
					"algorithm": "sha256",
					"value":     headHash,
				},
			},
			"signature": map[string]any{
				"format":  "x509",
				"content": "hopframe-control-plane-anchor",
				"publicKey": map[string]any{
					"content": "hopframe-control-plane-anchor",
				},
			},
		},
	}
	return json.Marshal(doc)
}

func parseRekorResponse(body []byte) (uuid string, logIndex int64, integratedAt time.Time, err error) {
	var raw map[string]json.RawMessage
	if err = json.Unmarshal(body, &raw); err != nil {
		return "", 0, time.Time{}, err
	}
	for k, v := range raw {
		uuid = k
		var entry struct {
			LogIndex     int64  `json:"logIndex"`
			IntegratedAt int64  `json:"integratedTime"`
			Body         string `json:"body"`
		}
		if err = json.Unmarshal(v, &entry); err != nil {
			return "", 0, time.Time{}, err
		}
		logIndex = entry.LogIndex
		if entry.IntegratedAt > 0 {
			integratedAt = time.Unix(entry.IntegratedAt, 0).UTC()
		}
		return uuid, logIndex, integratedAt, nil
	}
	return "", 0, time.Time{}, errors.New("rekor: empty response")
}
