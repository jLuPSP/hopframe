package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// SessionCookieName is the HTTP cookie that carries the user's
// session token. Mirrors the bearer-token format so the auth()
// middleware can treat the cookie value as a token.
const SessionCookieName = "hopframe_session"

// SetUserStore installs the user directory + session map. When set,
// the operator UI redirects unauthenticated requests to /login and
// /v1/* requests with a session cookie are accepted in addition to
// bearer tokens.
func (s *Server) SetUserStore(us *UserStore) {
	s.users = us
}

// uiRequiresAuth reports whether the operator UI should gate access on
// a session. Any of: a configured admin token, tenant tokens,
// role-bound tokens, registered users, or OIDC. The no-auth demo
// (none of these set) keeps the UI open.
func (s *Server) uiRequiresAuth() bool {
	if s.authToken != "" || len(s.tenantTokens) > 0 || len(s.roles) > 0 || s.oidc != nil {
		return true
	}
	if s.users != nil && s.users.HasAny() {
		return true
	}
	return false
}

// roleForUserSession returns the role for a session-cookie token, or
// the empty role if unknown.
func (s *Server) roleForUserSession(token string) Role {
	if s.users == nil {
		return ""
	}
	role, _, ok := s.users.LookupSession(token)
	if !ok {
		return ""
	}
	return role
}

func sessionCookie(r *http.Request) string {
	if c, err := r.Cookie(SessionCookieName); err == nil && c.Value != "" {
		return c.Value
	}
	return ""
}

func (s *Server) handleLoginPage(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(loginHTML)
}

func (s *Server) handleLoginSubmit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.users == nil {
		http.Error(w, "user management not configured", http.StatusNotFound)
		return
	}

	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	defer r.Body.Close()
	contentType := r.Header.Get("Content-Type")
	if strings.HasPrefix(contentType, "application/x-www-form-urlencoded") {
		_ = r.ParseForm()
		creds.Username = r.FormValue("username")
		creds.Password = r.FormValue("password")
	} else {
		if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
			http.Error(w, "decode: "+err.Error(), http.StatusBadRequest)
			return
		}
	}

	user, err := s.users.Authenticate(creds.Username, creds.Password)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	token, expiresAt := s.users.IssueSession(user)
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil,
		Expires:  expiresAt,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"username":   user.Username,
		"role":       string(user.Role),
		"tenant_id":  user.TenantID,
		"expires_at": expiresAt.Format(time.RFC3339),
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if token := sessionCookie(r); token != "" && s.users != nil {
		s.users.RevokeSession(token)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
	writeJSON(w, http.StatusOK, map[string]any{"logged_out": true})
}

// handleSessionInfo returns the current caller's identity. The UI uses
// it to render the signed-in identity in the header and to decide
// whether to surface user-management surfaces.
//
// Three shapes:
//   - no-auth demo (no auth configured anywhere): role=anonymous, 200.
//   - Auth configured but the request has no recognized credentials: 401.
//   - Authenticated request: 200 with role + username (when from a user
//     session) + tenant.
func (s *Server) handleSessionInfo(w http.ResponseWriter, r *http.Request) {
	if !s.uiRequiresAuth() {
		writeJSON(w, http.StatusOK, map[string]any{
			"role":      "anonymous",
			"anonymous": true,
		})
		return
	}
	token := sessionCookie(r)
	if token == "" {
		token = bearerToken(r.Header.Get("Authorization"))
	}
	if token == "" {
		token = r.URL.Query().Get("token")
	}
	if token == "" {
		http.Error(w, "not signed in", http.StatusUnauthorized)
		return
	}
	if s.users != nil {
		if role, tenant, ok := s.users.LookupSession(token); ok {
			writeJSON(w, http.StatusOK, map[string]any{
				"username":  s.users.UsernameForSession(token),
				"role":      string(role),
				"tenant_id": tenant,
			})
			return
		}
	}
	if role := s.roleForToken(token); role != "" {
		writeJSON(w, http.StatusOK, map[string]any{
			"role":      string(role),
			"tenant_id": s.tenantTokens[token],
		})
		return
	}
	http.Error(w, "session expired", http.StatusUnauthorized)
}
