package api

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// JWKS verification for OIDC id_tokens. Implements RS256 and ES256
// since those cover ~99% of IdPs in the field (Okta, Auth0, Azure AD,
// Google Workspace, Keycloak). EdDSA and HS256 are intentionally out:
// EdDSA is rare with mainstream IdPs, and HS256 requires a shared
// secret which is incompatible with the redirect-flow-only model we
// support here.
//
// Caching: the JWKS document is fetched on first need and cached for
// jwksCacheTTL. On a kid miss, the cache is invalidated and refetched
// once before failing the verify call. This handles routine key
// rotation without operator action.

const jwksCacheTTL = 1 * time.Hour

type jwksCache struct {
	mu        sync.Mutex
	keys      map[string]*jsonWebKey
	fetchedAt time.Time
}

type jsonWebKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	// RSA fields
	N string `json:"n,omitempty"`
	E string `json:"e,omitempty"`
	// EC fields
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

func (s *Server) verifyIDToken(idToken string) (map[string]any, error) {
	if s.oidc == nil {
		return nil, errors.New("oidc not configured")
	}
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("expected 3-part JWT, got %d", len(parts))
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		headerJSON, err = base64.URLEncoding.DecodeString(parts[0])
		if err != nil {
			return nil, fmt.Errorf("decode header: %w", err)
		}
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("parse header: %w", err)
	}

	signed := []byte(parts[0] + "." + parts[1])
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		sig, err = base64.URLEncoding.DecodeString(parts[2])
		if err != nil {
			return nil, fmt.Errorf("decode sig: %w", err)
		}
	}

	key, err := s.fetchJWK(header.Kid, false)
	if err != nil {
		// One refetch on miss to handle routine rotation.
		key, err = s.fetchJWK(header.Kid, true)
		if err != nil {
			return nil, err
		}
	}
	if err := verifyJWTSignature(header.Alg, key, signed, sig); err != nil {
		return nil, fmt.Errorf("signature: %w", err)
	}

	claims, err := decodeIDTokenClaims(idToken)
	if err != nil {
		return nil, err
	}
	if err := validateClaims(claims, s.oidc.cfg.Issuer, s.oidc.cfg.ClientID); err != nil {
		return nil, err
	}
	return claims, nil
}

// fetchJWK returns the JWK for a given kid, fetching the JWKS document
// if the cache is cold or the entry is missing.
func (s *Server) fetchJWK(kid string, force bool) (*jsonWebKey, error) {
	if s.oidc == nil {
		return nil, errors.New("oidc not configured")
	}
	c := &s.oidc.jwks
	c.mu.Lock()
	defer c.mu.Unlock()
	stale := time.Since(c.fetchedAt) > jwksCacheTTL
	if force || c.keys == nil || stale {
		if err := s.refreshJWKSLocked(); err != nil {
			return nil, err
		}
	}
	if k, ok := c.keys[kid]; ok {
		return k, nil
	}
	if !force && !stale {
		// Cache may be stale even if not expired (rotation between
		// fetches). One refresh attempt.
		if err := s.refreshJWKSLocked(); err != nil {
			return nil, err
		}
		if k, ok := c.keys[kid]; ok {
			return k, nil
		}
	}
	return nil, fmt.Errorf("kid %q not found in JWKS", kid)
}

func (s *Server) refreshJWKSLocked() error {
	if s.oidc.disco.JWKSURI == "" {
		return errors.New("discovery did not advertise jwks_uri")
	}
	req, err := http.NewRequest(http.MethodGet, s.oidc.disco.JWKSURI, nil)
	if err != nil {
		return err
	}
	resp, err := s.oidc.cfg.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("fetch jwks: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("jwks status %d: %s", resp.StatusCode, body)
	}
	var doc struct {
		Keys []jsonWebKey `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return fmt.Errorf("decode jwks: %w", err)
	}
	c := &s.oidc.jwks
	c.keys = make(map[string]*jsonWebKey, len(doc.Keys))
	for i := range doc.Keys {
		k := doc.Keys[i]
		if k.Kid == "" {
			continue
		}
		c.keys[k.Kid] = &k
	}
	c.fetchedAt = time.Now()
	return nil
}

func verifyJWTSignature(alg string, key *jsonWebKey, signed, sig []byte) error {
	switch alg {
	case "RS256":
		pub, err := jwkToRSA(key)
		if err != nil {
			return err
		}
		hash := sha256.Sum256(signed)
		return rsa.VerifyPKCS1v15(pub, crypto.SHA256, hash[:], sig)
	case "RS384":
		pub, err := jwkToRSA(key)
		if err != nil {
			return err
		}
		hash := sha512.Sum384(signed)
		return rsa.VerifyPKCS1v15(pub, crypto.SHA384, hash[:], sig)
	case "RS512":
		pub, err := jwkToRSA(key)
		if err != nil {
			return err
		}
		hash := sha512.Sum512(signed)
		return rsa.VerifyPKCS1v15(pub, crypto.SHA512, hash[:], sig)
	case "ES256":
		pub, err := jwkToECDSA(key, elliptic.P256())
		if err != nil {
			return err
		}
		hash := sha256.Sum256(signed)
		return verifyECDSA(pub, hash[:], sig, 32)
	case "ES384":
		pub, err := jwkToECDSA(key, elliptic.P384())
		if err != nil {
			return err
		}
		hash := sha512.Sum384(signed)
		return verifyECDSA(pub, hash[:], sig, 48)
	default:
		return fmt.Errorf("unsupported alg %q (RS256/RS384/RS512/ES256/ES384 supported)", alg)
	}
}

func jwkToRSA(k *jsonWebKey) (*rsa.PublicKey, error) {
	if k.Kty != "RSA" {
		return nil, fmt.Errorf("expected RSA jwk, got %q", k.Kty)
	}
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, fmt.Errorf("decode n: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, fmt.Errorf("decode e: %w", err)
	}
	e := 0
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}
	if e == 0 {
		return nil, errors.New("rsa exponent is zero")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}, nil
}

func jwkToECDSA(k *jsonWebKey, curve elliptic.Curve) (*ecdsa.PublicKey, error) {
	if k.Kty != "EC" {
		return nil, fmt.Errorf("expected EC jwk, got %q", k.Kty)
	}
	xBytes, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil {
		return nil, err
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(k.Y)
	if err != nil {
		return nil, err
	}
	pub := &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}
	// crypto/ecdsa.Verify returns false for off-curve or otherwise
	// invalid points, so an explicit on-curve check here would be
	// redundant. The deprecated elliptic.Curve.IsOnCurve is the only
	// other primitive in stdlib for this; we rely on Verify's own
	// validation instead.
	return pub, nil
}

// verifyECDSA accepts the JOSE-style raw r||s signature where each
// coordinate is encoded in coordSize bytes (e.g. 32 for P-256).
func verifyECDSA(pub *ecdsa.PublicKey, hash, sig []byte, coordSize int) error {
	if len(sig) != 2*coordSize {
		return fmt.Errorf("ecdsa sig length = %d, want %d", len(sig), 2*coordSize)
	}
	r := new(big.Int).SetBytes(sig[:coordSize])
	s := new(big.Int).SetBytes(sig[coordSize:])
	if !ecdsa.Verify(pub, hash, r, s) {
		return errors.New("ecdsa signature does not verify")
	}
	return nil
}

// validateClaims enforces the four claims every OIDC verifier must
// check: iss matches the configured issuer, aud contains the client
// id, exp has not passed, iat is not in the future. Failing any of
// these is a refusal-to-trust condition.
func validateClaims(claims map[string]any, expectedIssuer, expectedAudience string) error {
	now := time.Now().Unix()
	if iss, _ := claims["iss"].(string); strings.TrimRight(iss, "/") != strings.TrimRight(expectedIssuer, "/") {
		return fmt.Errorf("iss %q does not match expected %q", iss, expectedIssuer)
	}
	switch aud := claims["aud"].(type) {
	case string:
		if aud != expectedAudience {
			return fmt.Errorf("aud %q does not include client id %q", aud, expectedAudience)
		}
	case []any:
		ok := false
		for _, v := range aud {
			if s, _ := v.(string); s == expectedAudience {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("aud array does not include client id %q", expectedAudience)
		}
	default:
		return errors.New("aud claim missing or wrong type")
	}
	if exp, ok := numericClaim(claims, "exp"); ok && exp <= now {
		return fmt.Errorf("token expired (exp=%d, now=%d)", exp, now)
	} else if !ok {
		return errors.New("exp claim missing")
	}
	if iat, ok := numericClaim(claims, "iat"); ok && iat > now+300 {
		return errors.New("iat is in the future (clock skew?)")
	}
	return nil
}

func numericClaim(c map[string]any, key string) (int64, bool) {
	switch v := c[key].(type) {
	case float64:
		return int64(v), true
	case int64:
		return v, true
	case json.Number:
		n, err := v.Int64()
		if err == nil {
			return n, true
		}
	}
	return 0, false
}

// Reserved for future JWK-from-cert code paths. Keeps the import of
// crypto/x509 active without a dedicated user yet.
var _ = x509.MarshalPKIXPublicKey
