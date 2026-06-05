package api

import (
	_ "embed"
	"net/http"
	"net/url"
	"strings"
)

//go:embed ui.html
var uiHTML []byte

//go:embed audit.html
var auditHTML []byte

//go:embed policies.html
var policiesHTML []byte

//go:embed sensors.html
var sensorsHTML []byte

//go:embed records.html
var recordsHTML []byte

//go:embed login.html
var loginHTML []byte

//go:embed settings.html
var settingsHTML []byte

//go:embed rules.html
var rulesHTML []byte

//go:embed dashboard.html
var dashboardHTML []byte

// uiHandler returns an http.Handler that serves the embedded operator
// UI. Requests are gated on a session cookie when the server is
// configured with any auth (admin token, tenant tokens, role-bound
// tokens, registered users, or OIDC). The Tier-1 demo (no auth) keeps
// the UI open.
//
// Routes:
//
//	/         live event stream
//	/policies policy authoring
//	/sensors  sensor fleet inventory
//	/records  audit-record inspector
//	/audit    signed-export builder
//	/login    sign-in form (always reachable)
func (s *Server) uiHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if path == "/login" || path == "/login.html" {
			s.handleLoginPage(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")

		if s.uiRequiresAuth() && !s.requestHasValidSession(r) {
			next := url.QueryEscape(r.URL.RequestURI())
			http.Redirect(w, r, "/login?next="+next, http.StatusFound)
			return
		}

		switch path {
		case "/", "/index.html":
			_, _ = w.Write(uiHTML)
		case "/audit", "/audit.html":
			_, _ = w.Write(auditHTML)
		case "/policies", "/policies.html":
			_, _ = w.Write(policiesHTML)
		case "/sensors", "/sensors.html":
			_, _ = w.Write(sensorsHTML)
		case "/records", "/records.html":
			_, _ = w.Write(recordsHTML)
		case "/settings", "/settings.html":
			_, _ = w.Write(settingsHTML)
		case "/rules", "/rules.html":
			_, _ = w.Write(rulesHTML)
		case "/dashboard", "/dashboard.html":
			_, _ = w.Write(dashboardHTML)
		default:
			http.NotFound(w, r)
		}
	})
}

// requestHasValidSession reports whether the inbound request carries
// either a recognized session cookie, a valid query-param token, or a
// valid bearer token. Any of those is enough to bypass the /login
// redirect on UI HTML pages.
func (s *Server) requestHasValidSession(r *http.Request) bool {
	if cookie := sessionCookie(r); cookie != "" {
		if s.roleForUserSession(cookie) != "" {
			return true
		}
	}
	if q := r.URL.Query().Get("token"); q != "" {
		if s.recognizesToken(q) {
			return true
		}
	}
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		if s.recognizesToken(strings.TrimPrefix(h, "Bearer ")) {
			return true
		}
	}
	return false
}

// recognizesToken returns true when the server has a binding for the
// given bearer token: admin, tenant-scoped, role-bound, OIDC session,
// or user session.
func (s *Server) recognizesToken(token string) bool {
	if token == "" {
		return false
	}
	if s.authToken != "" && token == s.authToken {
		return true
	}
	if _, ok := s.tenantTokens[token]; ok {
		return true
	}
	if _, ok := s.roles[token]; ok {
		return true
	}
	if r := s.roleForSession(token); r != "" {
		return true
	}
	if r := s.roleForUserSession(token); r != "" {
		return true
	}
	return false
}

// UIHandler is the package-level entry kept for backward compat; it
// returns an http.Handler bound to a fresh Server with no auth state,
// suitable for the demo tier where the UI is open. Real deployments
// reach the UI through Server.Routes() which wires auth-gated UIs.
func UIHandler() http.Handler {
	return (&Server{}).uiHandler()
}
