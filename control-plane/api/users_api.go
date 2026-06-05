package api

import (
	"encoding/json"
	"net/http"
	"strings"
)

// /v1/users CRUD endpoints. The UI is a thin client over these. The
// API is the product; the UI is one consumer.
//
// Permissions:
//   - List / get: admin or higher.
//   - Create: admin (when targeting a tenant they own) or owner.
//   - Update role / tenant: owner only.
//   - Update password: self, or owner for any user.
//   - Delete: owner only.

func (s *Server) handleUsersCollection(w http.ResponseWriter, r *http.Request) {
	if s.users == nil {
		http.Error(w, "user management not configured", http.StatusNotFound)
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"users": s.users.List()})
	case http.MethodPost:
		s.createUser(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     Role   `json:"role"`
		TenantID string `json:"tenant_id,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "decode: "+err.Error(), http.StatusBadRequest)
		return
	}
	if body.Username == "" || body.Password == "" || body.Role == "" {
		http.Error(w, "username, password, role required", http.StatusBadRequest)
		return
	}
	c := CanonicalRole(body.Role)
	if c == "" {
		http.Error(w, "invalid role", http.StatusBadRequest)
		return
	}
	// Owner-only when minting another owner.
	if c == RoleOwner && roleOfRequest(s, r) != RoleOwner {
		http.Error(w, "only owners can create owners", http.StatusForbidden)
		return
	}
	u, err := s.users.Create(body.Username, body.Password, c, body.TenantID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	scrubbed := *u
	scrubbed.PasswordHash = ""
	writeJSON(w, http.StatusCreated, scrubbed)
}

func (s *Server) handleUserByName(w http.ResponseWriter, r *http.Request) {
	if s.users == nil {
		http.Error(w, "user management not configured", http.StatusNotFound)
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/v1/users/")
	if rest == r.URL.Path || rest == "" {
		http.Error(w, "expected /v1/users/{username}", http.StatusBadRequest)
		return
	}
	username, suffix, _ := strings.Cut(rest, "/")
	if username == "" {
		http.Error(w, "missing username", http.StatusBadRequest)
		return
	}

	if suffix == "password" {
		s.changePassword(w, r, username)
		return
	}
	if suffix != "" {
		http.Error(w, "unknown subresource", http.StatusNotFound)
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.getUser(w, r, username)
	case http.MethodPatch, http.MethodPut:
		s.updateUser(w, r, username)
	case http.MethodDelete:
		s.deleteUser(w, r, username)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) getUser(w http.ResponseWriter, _ *http.Request, username string) {
	for _, u := range s.users.List() {
		if strings.EqualFold(u.Username, username) {
			writeJSON(w, http.StatusOK, u)
			return
		}
	}
	http.Error(w, "user not found", http.StatusNotFound)
}

func (s *Server) updateUser(w http.ResponseWriter, r *http.Request, username string) {
	if roleOfRequest(s, r) != RoleOwner {
		http.Error(w, "only owners can change another user's role or tenant", http.StatusForbidden)
		return
	}
	defer r.Body.Close()
	var body struct {
		Role     Role   `json:"role,omitempty"`
		TenantID string `json:"tenant_id,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "decode: "+err.Error(), http.StatusBadRequest)
		return
	}
	role := CanonicalRole(body.Role)
	if body.Role != "" && role == "" {
		http.Error(w, "invalid role", http.StatusBadRequest)
		return
	}
	if err := s.users.Update(username, role, body.TenantID); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.getUser(w, r, username)
}

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request, username string) {
	if roleOfRequest(s, r) != RoleOwner {
		http.Error(w, "only owners can delete users", http.StatusForbidden)
		return
	}
	if strings.EqualFold(username, currentUsername(s, r)) {
		http.Error(w, "you cannot delete your own account", http.StatusBadRequest)
		return
	}
	if err := s.users.Delete(username); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": username})
}

func (s *Server) changePassword(w http.ResponseWriter, r *http.Request, username string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	defer r.Body.Close()
	var body struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "decode: "+err.Error(), http.StatusBadRequest)
		return
	}
	role := roleOfRequest(s, r)
	caller := currentUsername(s, r)
	isSelf := strings.EqualFold(caller, username)
	if !isSelf && role != RoleOwner {
		http.Error(w, "only owners can change another user's password", http.StatusForbidden)
		return
	}
	if err := s.users.SetPassword(username, body.Password); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"username": username, "password_rotated": true})
}

// roleOfRequest looks up the caller's role from the bearer token,
// query token, or session cookie. Mirrors auth() resolution.
func roleOfRequest(s *Server, r *http.Request) Role {
	token := bearerToken(r.Header.Get("Authorization"))
	if token == "" {
		token = r.URL.Query().Get("token")
	}
	if token == "" {
		token = sessionCookie(r)
	}
	return s.roleForToken(token)
}

// currentUsername returns the username for a session-bound request, or
// "" for token-bound requests (which do not carry a user identity).
func currentUsername(s *Server, r *http.Request) string {
	if s.users == nil {
		return ""
	}
	token := bearerToken(r.Header.Get("Authorization"))
	if token == "" {
		token = r.URL.Query().Get("token")
	}
	if token == "" {
		token = sessionCookie(r)
	}
	return s.users.UsernameForSession(token)
}
