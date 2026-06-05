package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// API tokens as a first-class resource. Until now, role-bound tokens
// were declared via HOPFRAME_ROLE_TOKENS env. That works for an initial
// bootstrap but does not survive in a LaunchDarkly-shaped product
// where every config knob is API-driven and rotation is a button click.
//
// This token store sits alongside the env-bound tokens. Auth resolution
// checks both: env tokens are immutable at runtime, store tokens can be
// minted, listed, and revoked through the API. Each store token is
// persisted as (id, hash, role, tenant, name, created_by, ...). The
// secret value is shown to the caller exactly once (at mint time);
// thereafter the server only stores the hash.

// APIToken is the JSON representation operators see. The secret field
// is populated only on POST; subsequent reads return it empty.
type APIToken struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Role      Role      `json:"role"`
	TenantID  string    `json:"tenant_id,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by,omitempty"`
	LastUsed  time.Time `json:"last_used,omitempty"`
	Hash      string    `json:"-"`
	Secret    string    `json:"secret,omitempty"`
}

// TokenStore persists API tokens to disk. Hashes only; never the raw
// secret. Atomic-rewrite on each mutation. Suitable for the small
// numbers of tokens (operators + service principals) any one
// deployment maintains.
type TokenStore struct {
	mu     sync.RWMutex
	path   string
	tokens map[string]*APIToken // keyed by id
	bySalt map[string]string    // bcrypt-style: secret hash -> id
}

// OpenTokenStore loads or creates a token store at path.
func OpenTokenStore(path string) (*TokenStore, error) {
	if path == "" {
		return nil, errors.New("tokenstore: empty path")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	s := &TokenStore{
		path:   path,
		tokens: make(map[string]*APIToken),
		bySalt: make(map[string]string),
	}
	body, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if len(body) == 0 {
		return s, nil
	}
	var doc struct {
		Schema string      `json:"schema"`
		Tokens []*APIToken `json:"tokens"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("tokenstore: decode: %w", err)
	}
	for _, t := range doc.Tokens {
		s.tokens[t.ID] = t
		if t.Hash != "" {
			s.bySalt[t.Hash] = t.ID
		}
	}
	return s, nil
}

// Mint creates a new token. The secret value is returned exactly once;
// only its SHA-256 hash is persisted.
func (s *TokenStore) Mint(name string, role Role, tenantID, createdBy string) (*APIToken, error) {
	if name == "" {
		return nil, errors.New("name required")
	}
	canon := CanonicalRole(role)
	if canon == "" {
		return nil, fmt.Errorf("invalid role %q", role)
	}
	idBytes := make([]byte, 6)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, err
	}
	id := "tok_" + hex.EncodeToString(idBytes)

	secretBytes := make([]byte, 32)
	if _, err := rand.Read(secretBytes); err != nil {
		return nil, err
	}
	secret := "hf_" + base64.RawURLEncoding.EncodeToString(secretBytes)
	hash := hashToken(secret)

	t := &APIToken{
		ID:        id,
		Name:      name,
		Role:      canon,
		TenantID:  tenantID,
		CreatedAt: time.Now().UTC(),
		CreatedBy: createdBy,
		Hash:      hash,
	}
	s.mu.Lock()
	s.tokens[id] = t
	s.bySalt[hash] = id
	if err := s.persistLocked(); err != nil {
		delete(s.tokens, id)
		delete(s.bySalt, hash)
		s.mu.Unlock()
		return nil, err
	}
	s.mu.Unlock()
	out := *t
	out.Secret = secret
	out.Hash = ""
	return &out, nil
}

// Lookup returns the token for a given secret, marking it as used.
// Returns nil if no token matches. Constant-time comparison via the
// hashed lookup table; the secret never appears in plaintext on disk.
func (s *TokenStore) Lookup(secret string) *APIToken {
	if secret == "" {
		return nil
	}
	hash := hashToken(secret)
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.bySalt[hash]
	if !ok {
		return nil
	}
	t := s.tokens[id]
	if t == nil {
		return nil
	}
	t.LastUsed = time.Now().UTC()
	_ = s.persistLocked()
	out := *t
	out.Hash = ""
	return &out
}

// List returns every token, with hashes and secrets stripped.
func (s *TokenStore) List() []APIToken {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]APIToken, 0, len(s.tokens))
	for _, t := range s.tokens {
		c := *t
		c.Hash = ""
		c.Secret = ""
		out = append(out, c)
	}
	return out
}

// Revoke removes a token by id.
func (s *TokenStore) Revoke(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tokens[id]
	if !ok {
		return fmt.Errorf("token %q not found", id)
	}
	delete(s.tokens, id)
	delete(s.bySalt, t.Hash)
	return s.persistLocked()
}

func (s *TokenStore) persistLocked() error {
	out := make([]*APIToken, 0, len(s.tokens))
	for _, t := range s.tokens {
		out = append(out, t)
	}
	doc := struct {
		Schema string      `json:"schema"`
		Tokens []*APIToken `json:"tokens"`
	}{
		Schema: "hopframe.tokens/v1",
		Tokens: out,
	}
	body, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func hashToken(secret string) string {
	h := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(h[:])
}

// SetTokenStore wires the token store into the server. Auth resolution
// will additionally check this store after the env-bound paths.
func (s *Server) SetTokenStore(ts *TokenStore) {
	s.tokenStore = ts
}

// roleAndTenantForStoreToken returns the role and tenant for a
// secret looked up in the token store.
func (s *Server) roleAndTenantForStoreToken(secret string) (Role, string, bool) {
	if s.tokenStore == nil {
		return "", "", false
	}
	t := s.tokenStore.Lookup(secret)
	if t == nil {
		return "", "", false
	}
	return t.Role, t.TenantID, true
}

// /v1/tokens CRUD endpoints.

func (s *Server) handleTokensCollection(w http.ResponseWriter, r *http.Request) {
	if s.tokenStore == nil {
		http.Error(w, "token store not configured", http.StatusNotFound)
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"tokens": s.tokenStore.List()})
	case http.MethodPost:
		s.mintToken(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) mintToken(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	var body struct {
		Name     string `json:"name"`
		Role     Role   `json:"role"`
		TenantID string `json:"tenant_id,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "decode: "+err.Error(), http.StatusBadRequest)
		return
	}
	canon := CanonicalRole(body.Role)
	if canon == "" {
		http.Error(w, "invalid role", http.StatusBadRequest)
		return
	}
	// Owner-only when minting an owner token.
	caller := roleOfRequest(s, r)
	if canon == RoleOwner && caller != RoleOwner {
		http.Error(w, "only owners can mint owner tokens", http.StatusForbidden)
		return
	}
	t, err := s.tokenStore.Mint(body.Name, canon, body.TenantID, currentUsername(s, r))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusCreated, t)
}

func (s *Server) handleTokenByID(w http.ResponseWriter, r *http.Request) {
	if s.tokenStore == nil {
		http.Error(w, "token store not configured", http.StatusNotFound)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/v1/tokens/")
	if id == "" || id == r.URL.Path {
		http.Error(w, "expected /v1/tokens/{id}", http.StatusBadRequest)
		return
	}
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := s.tokenStore.Revoke(id); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"revoked": id})
}
