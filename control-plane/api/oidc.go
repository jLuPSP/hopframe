package api

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// OIDCConfig is the minimum set of fields required to integrate with an
// upstream OIDC IdP (Okta, Auth0, Azure AD, Google Workspace).
//
// This is a skeletal implementation: it performs the standard auth-code
// flow and maps IdP claims to roles via GroupRoleMap. It does not
// validate ID-token signatures against the IdP's JWKS, and it does not
// refresh tokens. A production deployment should layer those on top.
// Phase 2A in roadmap.md tracks the full implementation work.
type OIDCConfig struct {
	Issuer       string // e.g. https://login.example.com
	ClientID     string
	ClientSecret string
	RedirectURL  string          // public URL for /auth/callback
	Scopes       []string        // defaults to [openid, profile, email, groups]
	GroupRoleMap map[string]Role // IdP group claim -> role
	DefaultRole  Role            // role for users with no matching group
	HTTPClient   *http.Client
	// SessionTTL controls how long a session bearer token issued after
	// successful login remains valid. Defaults to 12 hours.
	SessionTTL time.Duration
}

// SetOIDC enables the OIDC login flow. When configured, /auth/login
// redirects to the IdP and /auth/callback exchanges the auth code for
// tokens, mints a session bearer token, and binds it to a role
// according to the GroupRoleMap. The session token can then be used as
// a normal bearer on /v1/* endpoints.
func (s *Server) SetOIDC(cfg OIDCConfig) error {
	if cfg.Issuer == "" || cfg.ClientID == "" || cfg.RedirectURL == "" {
		return errors.New("oidc: issuer, client_id, redirect_url required")
	}
	if cfg.SessionTTL <= 0 {
		cfg.SessionTTL = 12 * time.Hour
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"openid", "profile", "email", "groups"}
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = http.DefaultClient
	}
	disco, err := discoverOIDC(cfg.HTTPClient, cfg.Issuer)
	if err != nil {
		return fmt.Errorf("oidc discovery: %w", err)
	}
	s.oidc = &oidcState{
		cfg:      cfg,
		disco:    disco,
		states:   make(map[string]oidcPending),
		sessions: make(map[string]oidcSession),
	}
	return nil
}

type oidcState struct {
	cfg      OIDCConfig
	disco    oidcDiscovery
	mu       sync.Mutex
	states   map[string]oidcPending
	sessions map[string]oidcSession
	jwks     jwksCache
}

type oidcPending struct {
	state     string
	createdAt time.Time
}

type oidcSession struct {
	subject   string
	email     string
	role      Role
	expiresAt time.Time
}

type oidcDiscovery struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserInfoEndpoint      string `json:"userinfo_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	Issuer                string `json:"issuer"`
}

func discoverOIDC(hc *http.Client, issuer string) (oidcDiscovery, error) {
	u := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
	resp, err := hc.Get(u)
	if err != nil {
		return oidcDiscovery{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return oidcDiscovery{}, fmt.Errorf("discovery status %d: %s", resp.StatusCode, body)
	}
	var d oidcDiscovery
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		return oidcDiscovery{}, err
	}
	if d.AuthorizationEndpoint == "" || d.TokenEndpoint == "" {
		return oidcDiscovery{}, errors.New("discovery missing endpoints")
	}
	return d, nil
}

// handleOIDCLogin redirects the browser to the IdP's authorization
// endpoint with a freshly minted state parameter.
func (s *Server) handleOIDCLogin(w http.ResponseWriter, r *http.Request) {
	if s.oidc == nil {
		http.Error(w, "oidc not configured", http.StatusNotFound)
		return
	}
	state := randomToken()
	s.oidc.mu.Lock()
	s.oidc.states[state] = oidcPending{state: state, createdAt: time.Now()}
	s.oidc.mu.Unlock()

	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", s.oidc.cfg.ClientID)
	q.Set("redirect_uri", s.oidc.cfg.RedirectURL)
	q.Set("scope", strings.Join(s.oidc.cfg.Scopes, " "))
	q.Set("state", state)
	dest := s.oidc.disco.AuthorizationEndpoint + "?" + q.Encode()
	http.Redirect(w, r, dest, http.StatusFound)
}

// handleOIDCCallback exchanges the auth code for tokens, decodes the
// id_token claims, picks the role from GroupRoleMap, and mints a
// session bearer token the caller can use on /v1/* endpoints.
//
// This implementation does NOT verify the id_token signature against
// the IdP's JWKS. That is required for production. A note is emitted
// in the response body so an operator running a smoke test sees it.
func (s *Server) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	if s.oidc == nil {
		http.Error(w, "oidc not configured", http.StatusNotFound)
		return
	}
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	if code == "" || state == "" {
		http.Error(w, "missing code/state", http.StatusBadRequest)
		return
	}
	s.oidc.mu.Lock()
	_, ok := s.oidc.states[state]
	delete(s.oidc.states, state)
	s.oidc.mu.Unlock()
	if !ok {
		http.Error(w, "unknown state", http.StatusBadRequest)
		return
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", s.oidc.cfg.RedirectURL)
	form.Set("client_id", s.oidc.cfg.ClientID)
	if s.oidc.cfg.ClientSecret != "" {
		form.Set("client_secret", s.oidc.cfg.ClientSecret)
	}
	resp, err := s.oidc.cfg.HTTPClient.PostForm(s.oidc.disco.TokenEndpoint, form)
	if err != nil {
		http.Error(w, "token exchange: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		http.Error(w, fmt.Sprintf("token status %d: %s", resp.StatusCode, body), http.StatusBadGateway)
		return
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		http.Error(w, "decode token: "+err.Error(), http.StatusBadGateway)
		return
	}

	claims, err := s.verifyIDToken(tok.IDToken)
	if err != nil {
		http.Error(w, "verify id_token: "+err.Error(), http.StatusUnauthorized)
		return
	}
	role := pickRole(claims, s.oidc.cfg.GroupRoleMap, s.oidc.cfg.DefaultRole)

	session := randomToken()
	s.oidc.mu.Lock()
	s.oidc.sessions[session] = oidcSession{
		subject:   stringClaim(claims, "sub"),
		email:     stringClaim(claims, "email"),
		role:      role,
		expiresAt: time.Now().Add(s.oidc.cfg.SessionTTL),
	}
	s.oidc.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"session_token": session,
		"role":          string(role),
		"subject":       stringClaim(claims, "sub"),
		"email":         stringClaim(claims, "email"),
		"expires_at":    time.Now().Add(s.oidc.cfg.SessionTTL).Format(time.RFC3339),
	})
}

// roleForSession returns the role bound to a session bearer, or the
// empty string if the session is unknown or expired.
func (s *Server) roleForSession(token string) Role {
	if s.oidc == nil || token == "" {
		return ""
	}
	s.oidc.mu.Lock()
	defer s.oidc.mu.Unlock()
	sess, ok := s.oidc.sessions[token]
	if !ok {
		return ""
	}
	if time.Now().After(sess.expiresAt) {
		delete(s.oidc.sessions, token)
		return ""
	}
	return sess.role
}

func decodeIDTokenClaims(idToken string) (map[string]any, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) < 2 {
		return nil, errors.New("not a JWT")
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		body, err = base64.URLEncoding.DecodeString(parts[1])
		if err != nil {
			return nil, fmt.Errorf("decode payload: %w", err)
		}
	}
	var claims map[string]any
	if err := json.Unmarshal(body, &claims); err != nil {
		return nil, err
	}
	return claims, nil
}

func pickRole(claims map[string]any, groupMap map[string]Role, fallback Role) Role {
	if groups, ok := claims["groups"].([]any); ok {
		for _, g := range groups {
			if name, ok := g.(string); ok {
				if r, ok := groupMap[name]; ok {
					return r
				}
			}
		}
	}
	if fallback != "" {
		return fallback
	}
	return RoleViewer
}

func stringClaim(claims map[string]any, key string) string {
	if v, ok := claims[key].(string); ok {
		return v
	}
	return ""
}

func randomToken() string {
	var b [24]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}
