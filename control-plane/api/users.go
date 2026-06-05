package api

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// User is a locally-managed account that can sign in to the operator
// UI. Username is the primary key. Password is bcrypt-hashed at rest.
// Role binds to the same RBAC enum the bearer-token path uses, so a
// user-session bearer is interchangeable with an admin-issued token at
// the auth() middleware layer.
//
// User management is for the operator UI. Sensors and SDKs continue to
// use long-lived bearer tokens (HOPFRAME_API_TOKEN,
// HOPFRAME_TENANT_TOKENS, HOPFRAME_ROLE_TOKENS) since rotating their
// credentials through a UI would be operational pain.
type User struct {
	Username     string    `json:"username"`
	PasswordHash string    `json:"password_hash"`
	Role         Role      `json:"role"`
	TenantID     string    `json:"tenant_id,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	LastLogin    time.Time `json:"last_login,omitempty"`
}

// UserStore is a JSON-file-backed user directory plus an in-memory
// session map. State is small (operators, not end-users), so the
// simple-and-correct shape beats a database; an enterprise deployment
// adds OIDC SSO or SCIM provisioning instead of growing this store.
type UserStore struct {
	mu       sync.RWMutex
	path     string
	users    map[string]*User
	sessions map[string]userSession
}

type userSession struct {
	username  string
	role      Role
	tenantID  string
	expiresAt time.Time
}

// SessionTTL is the lifetime of a UI login. Twelve hours matches the
// OIDC default; long enough for a workday, short enough that a
// stolen cookie has a bounded blast radius.
const sessionTTL = 12 * time.Hour

// OpenUserStore loads or creates a user store. The file is created
// on first save; an empty file is tolerated.
func OpenUserStore(path string) (*UserStore, error) {
	if path == "" {
		return nil, errors.New("userstore: empty path")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	s := &UserStore{
		path:     path,
		users:    make(map[string]*User),
		sessions: make(map[string]userSession),
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
		Schema string  `json:"schema"`
		Users  []*User `json:"users"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("userstore: decode: %w", err)
	}
	for _, u := range doc.Users {
		s.users[strings.ToLower(u.Username)] = u
	}
	return s, nil
}

// HasAny reports whether at least one user is registered. The UI uses
// this to decide whether to enforce login: with no users registered,
// the demo tier UX (no auth) is preserved.
func (s *UserStore) HasAny() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.users) > 0
}

// Create registers a new user. Username uniqueness is case-insensitive.
// The password is hashed with bcrypt at default cost.
func (s *UserStore) Create(username, password string, role Role, tenantID string) (*User, error) {
	if username == "" || password == "" {
		return nil, errors.New("username and password required")
	}
	if len(password) < 8 {
		return nil, errors.New("password must be at least 8 characters")
	}
	if roleRank[role] == 0 && role != RoleViewer {
		return nil, fmt.Errorf("invalid role %q", role)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}
	now := time.Now().UTC()
	u := &User{
		Username:     username,
		PasswordHash: string(hash),
		Role:         role,
		TenantID:     tenantID,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := strings.ToLower(username)
	if _, exists := s.users[key]; exists {
		return nil, fmt.Errorf("user %q already exists", username)
	}
	s.users[key] = u
	if err := s.persistLocked(); err != nil {
		delete(s.users, key)
		return nil, err
	}
	return cloneUser(u), nil
}

// Authenticate returns the user record on a correct password, or nil
// + a generic error otherwise. Generic on purpose: a different message
// for "user not found" vs "wrong password" leaks whether a username
// exists.
func (s *UserStore) Authenticate(username, password string) (*User, error) {
	s.mu.RLock()
	u, ok := s.users[strings.ToLower(username)]
	s.mu.RUnlock()
	if !ok {
		// Run a comparison anyway to keep timing close to a real attempt.
		_ = bcrypt.CompareHashAndPassword([]byte("$2a$10$invalidinvalidinvalidinvalidinvalidinvalidinvalidinvalid"), []byte(password))
		return nil, errors.New("invalid credentials")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)); err != nil {
		return nil, errors.New("invalid credentials")
	}
	s.mu.Lock()
	u.LastLogin = time.Now().UTC()
	_ = s.persistLocked()
	out := cloneUser(u)
	s.mu.Unlock()
	return out, nil
}

// IssueSession mints a session token bound to the user and returns the
// token + expiry. The caller sets the cookie.
func (s *UserStore) IssueSession(u *User) (token string, expiresAt time.Time) {
	expiresAt = time.Now().Add(sessionTTL)
	token = randomSessionToken()
	s.mu.Lock()
	s.sessions[token] = userSession{
		username:  u.Username,
		role:      u.Role,
		tenantID:  u.TenantID,
		expiresAt: expiresAt,
	}
	s.mu.Unlock()
	return token, expiresAt
}

// RevokeSession drops a session token. Called from /auth/logout.
func (s *UserStore) RevokeSession(token string) {
	s.mu.Lock()
	delete(s.sessions, token)
	s.mu.Unlock()
}

// UsernameForSession returns the username bound to a session token,
// or empty if the session is unknown or expired.
func (s *UserStore) UsernameForSession(token string) string {
	if token == "" {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[token]
	if !ok {
		return ""
	}
	if time.Now().After(sess.expiresAt) {
		delete(s.sessions, token)
		return ""
	}
	return sess.username
}

// Update changes role and/or tenant on an existing user. Empty
// arguments leave the corresponding field unchanged. Cannot change
// username (delete + recreate for that).
func (s *UserStore) Update(username string, role Role, tenantID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[strings.ToLower(username)]
	if !ok {
		return fmt.Errorf("user %q not found", username)
	}
	if role != "" {
		u.Role = role
	}
	if tenantID != "" || role != "" {
		// Allow clearing tenant_id by passing role=non-empty + tenant_id="".
		// To clear, callers can pass an explicit "-" sentinel; but for now
		// any non-empty role allows tenantID to be cleared with "-".
		if tenantID == "-" {
			u.TenantID = ""
		} else if tenantID != "" {
			u.TenantID = tenantID
		}
	}
	u.UpdatedAt = time.Now().UTC()
	return s.persistLocked()
}

// Delete removes a user. Returns an error if the user does not exist.
func (s *UserStore) Delete(username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := strings.ToLower(username)
	if _, ok := s.users[key]; !ok {
		return fmt.Errorf("user %q not found", username)
	}
	delete(s.users, key)
	// Drop any active sessions for this user.
	for token, sess := range s.sessions {
		if strings.EqualFold(sess.username, username) {
			delete(s.sessions, token)
		}
	}
	return s.persistLocked()
}

// SetPassword updates a user's password to a new value. Used by
// /v1/users/{name}/password.
func (s *UserStore) SetPassword(username, password string) error {
	if len(password) < 8 {
		return errors.New("password must be at least 8 characters")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[strings.ToLower(username)]
	if !ok {
		return fmt.Errorf("user %q not found", username)
	}
	u.PasswordHash = string(hash)
	u.UpdatedAt = time.Now().UTC()
	return s.persistLocked()
}

// LookupSession returns the role and tenant for a session token, or
// the zero values if unknown / expired. Expired entries are evicted.
func (s *UserStore) LookupSession(token string) (Role, string, bool) {
	if token == "" {
		return "", "", false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[token]
	if !ok {
		return "", "", false
	}
	if time.Now().After(sess.expiresAt) {
		delete(s.sessions, token)
		return "", "", false
	}
	return sess.role, sess.tenantID, true
}

// List returns every user, scrubbed of password hashes. For the
// admin UI later.
func (s *UserStore) List() []User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]User, 0, len(s.users))
	for _, u := range s.users {
		c := *u
		c.PasswordHash = ""
		out = append(out, c)
	}
	return out
}

func (s *UserStore) persistLocked() error {
	doc := struct {
		Schema string  `json:"schema"`
		Users  []*User `json:"users"`
	}{
		Schema: "hopframe.users/v1",
	}
	for _, u := range s.users {
		doc.Users = append(doc.Users, u)
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

func cloneUser(u *User) *User {
	c := *u
	return &c
}

func randomSessionToken() string {
	var b [32]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}
