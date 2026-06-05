package api

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestVerifyIDTokenRS256(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	kid := "test-kid-1"

	jwks := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		key := jsonWebKey{
			Kty: "RSA",
			Kid: kid,
			Alg: "RS256",
			Use: "sig",
			N:   base64.RawURLEncoding.EncodeToString(priv.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(bigEndianBytes(priv.E)),
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []jsonWebKey{key}})
	})
	disc := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			_ = json.NewEncoder(w).Encode(oidcDiscovery{
				AuthorizationEndpoint: "http://localhost/auth",
				TokenEndpoint:         "http://localhost/token",
				JWKSURI:               "http://" + r.Host + "/jwks",
				Issuer:                "http://" + r.Host,
			})
			return
		}
	})

	mux := http.NewServeMux()
	mux.Handle("/.well-known/openid-configuration", disc)
	mux.Handle("/jwks", jwks)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	srv := &Server{}
	if err := srv.SetOIDC(OIDCConfig{
		Issuer:      ts.URL,
		ClientID:    "test-client",
		RedirectURL: "http://localhost/callback",
	}); err != nil {
		t.Fatal(err)
	}

	idToken := mintRS256(t, priv, kid, map[string]any{
		"iss":    ts.URL,
		"aud":    "test-client",
		"sub":    "user-123",
		"email":  "alice@example.com",
		"groups": []string{"engineers"},
		"iat":    time.Now().Unix(),
		"exp":    time.Now().Add(time.Hour).Unix(),
	})

	claims, err := srv.verifyIDToken(idToken)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims["sub"] != "user-123" {
		t.Errorf("sub = %v, want user-123", claims["sub"])
	}

	// Tamper with the payload; signature must fail.
	tampered := tamperPayload(idToken)
	if _, err := srv.verifyIDToken(tampered); err == nil {
		t.Fatal("expected verify to fail on tampered payload")
	}

	// Wrong audience.
	wrongAud := mintRS256(t, priv, kid, map[string]any{
		"iss": ts.URL, "aud": "other-client", "sub": "u",
		"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
	})
	if _, err := srv.verifyIDToken(wrongAud); err == nil {
		t.Fatal("expected verify to fail on wrong audience")
	}

	// Expired.
	expired := mintRS256(t, priv, kid, map[string]any{
		"iss": ts.URL, "aud": "test-client", "sub": "u",
		"iat": time.Now().Add(-time.Hour).Unix(),
		"exp": time.Now().Add(-time.Minute).Unix(),
	})
	if _, err := srv.verifyIDToken(expired); err == nil {
		t.Fatal("expected verify to fail on expired token")
	}
}

func TestVerifyIDTokenRefetchesOnKidMiss(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)

	currentKid := "k1"
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(oidcDiscovery{
			AuthorizationEndpoint: "http://localhost/auth",
			TokenEndpoint:         "http://localhost/token",
			JWKSURI:               "http://" + r.Host + "/jwks",
			Issuer:                "http://" + r.Host,
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		key := jsonWebKey{
			Kty: "RSA", Kid: currentKid, Alg: "RS256", Use: "sig",
			N: base64.RawURLEncoding.EncodeToString(priv.N.Bytes()),
			E: base64.RawURLEncoding.EncodeToString(bigEndianBytes(priv.E)),
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []jsonWebKey{key}})
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	srv := &Server{}
	if err := srv.SetOIDC(OIDCConfig{
		Issuer: ts.URL, ClientID: "c", RedirectURL: "http://localhost/cb",
	}); err != nil {
		t.Fatal(err)
	}

	// Prime the cache with k1.
	t1 := mintRS256(t, priv, "k1", map[string]any{
		"iss": ts.URL, "aud": "c", "sub": "u",
		"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
	})
	if _, err := srv.verifyIDToken(t1); err != nil {
		t.Fatalf("verify k1: %v", err)
	}

	// Server rotates to k2.
	currentKid = "k2"
	t2 := mintRS256(t, priv, "k2", map[string]any{
		"iss": ts.URL, "aud": "c", "sub": "u",
		"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
	})
	if _, err := srv.verifyIDToken(t2); err != nil {
		t.Fatalf("verify k2 (should refetch on kid miss): %v", err)
	}
}

// mintRS256 builds a compact JWS over the claims using the RSA key.
// The kid is set in the header. Used for tests only.
func mintRS256(t *testing.T, priv *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	header := map[string]any{"alg": "RS256", "typ": "JWT", "kid": kid}
	headerB, _ := json.Marshal(header)
	claimsB, _ := json.Marshal(claims)
	signing := base64.RawURLEncoding.EncodeToString(headerB) + "." + base64.RawURLEncoding.EncodeToString(claimsB)
	hash := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hash[:])
	if err != nil {
		t.Fatal(err)
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func tamperPayload(token string) string {
	parts := splitDot(token)
	if len(parts) != 3 {
		return token
	}
	body, _ := base64.RawURLEncoding.DecodeString(parts[1])
	body = append(body, ' ')
	parts[1] = base64.RawURLEncoding.EncodeToString(body)
	return parts[0] + "." + parts[1] + "." + parts[2]
}

func splitDot(s string) []string {
	var out []string
	last := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			out = append(out, s[last:i])
			last = i + 1
		}
	}
	out = append(out, s[last:])
	return out
}

func bigEndianBytes(n int) []byte {
	if n == 0 {
		return []byte{0}
	}
	var out []byte
	for n > 0 {
		out = append([]byte{byte(n & 0xff)}, out...)
		n >>= 8
	}
	return out
}

// suppresses an unused-import noise check; the file imports fmt but
// only via formatted errors raised by testing.T helpers.
var _ = fmt.Sprintf
