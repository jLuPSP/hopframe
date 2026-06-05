package api

import (
	"net/http"
)

// Role names a coarse permission level. Tokens and user accounts both
// bind to a role; the auth middleware treats them identically once
// resolved. Roles map to LaunchDarkly-style names so an operator with
// product-management muscle memory does not have to learn a new model.
type Role string

const (
	// RoleViewer is read-only on /v1/* endpoints.
	RoleViewer Role = "viewer"
	// RoleEditor adds CRUD on policies within the bound tenant scope.
	// Cannot manage users or tokens; sensor management is read-only.
	RoleEditor Role = "editor"
	// RoleAdmin adds sensor management, token CRUD, and user management
	// within the tenant scope.
	RoleAdmin Role = "admin"
	// RoleOwner is cross-tenant. The legacy HOPFRAME_API_TOKEN is
	// implicitly this role. Owners can create other owners and rotate
	// the bootstrap admin.
	RoleOwner Role = "owner"

	// Deprecated aliases. Old config keeps working; new code should
	// use the canonical names above.
	RolePolicyAuthor Role = "policy_author"
	RoleTenantAdmin  Role = "tenant_admin"
	RoleSuperAdmin   Role = "super_admin"
)

// roleRank orders roles by permission strength. Higher rank includes
// every capability of every lower-ranked role. Aliases share rank with
// their canonical name so token configs from before the rename keep
// resolving.
var roleRank = map[Role]int{
	RoleViewer:       0,
	RoleEditor:       1,
	RolePolicyAuthor: 1,
	RoleAdmin:        2,
	RoleTenantAdmin:  2,
	RoleOwner:        3,
	RoleSuperAdmin:   3,
}

// canonical maps any role (including deprecated aliases) to its
// canonical form. Used so APIs and storage write the new names.
var canonical = map[Role]Role{
	RoleViewer:       RoleViewer,
	RoleEditor:       RoleEditor,
	RolePolicyAuthor: RoleEditor,
	RoleAdmin:        RoleAdmin,
	RoleTenantAdmin:  RoleAdmin,
	RoleOwner:        RoleOwner,
	RoleSuperAdmin:   RoleOwner,
}

// CanonicalRole returns the modern name for a (possibly aliased) role.
// Returns the empty string for unknown role values; callers should
// reject those.
func CanonicalRole(r Role) Role { return canonical[r] }

// KnownRoles returns the canonical role list in ascending permission
// order. Used by the UI dropdowns and validation.
func KnownRoles() []Role {
	return []Role{RoleViewer, RoleEditor, RoleAdmin, RoleOwner}
}

// SetRoleTokens binds bearer tokens to roles. This composes with
// SetTenantTokens: a token may be both tenant-scoped and role-bound.
// When a token appears here but not in tenant tokens, it has the
// declared role and cross-tenant scope (super-admin-style).
//
// To revert: pass nil or an empty map.
func (s *Server) SetRoleTokens(m map[string]Role) {
	if len(m) == 0 {
		s.roles = nil
		return
	}
	cp := make(map[string]Role, len(m))
	for k, v := range m {
		if k == "" || roleRank[v] == 0 && v != RoleViewer {
			continue
		}
		cp[k] = v
	}
	s.roles = cp
}

// requireRole wraps a handler so it only runs when the authenticated
// caller has at least the required role. When no auth is configured at
// all, the wrapper passes through (alpha-friendly default).
func (s *Server) requireRole(min Role, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.authToken == "" && len(s.tenantTokens) == 0 && len(s.roles) == 0 && (s.users == nil || !s.users.HasAny()) {
			h(w, r)
			return
		}
		token := bearerToken(r.Header.Get("Authorization"))
		if token == "" {
			token = r.URL.Query().Get("token")
		}
		if token == "" {
			token = sessionCookie(r)
		}
		role := s.roleForToken(token)
		if role == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if roleRank[role] < roleRank[min] {
			http.Error(w, "forbidden: role "+string(role)+" lacks "+string(min), http.StatusForbidden)
			return
		}
		h(w, r)
	}
}

// callerHasRole reports whether the request's caller has at least the
// given role. Used inside handlers that gate certain methods (POST,
// PATCH, DELETE) more strictly than the route-level requireRole.
func (s *Server) callerHasRole(r *http.Request, min Role) bool {
	if s.authToken == "" && len(s.tenantTokens) == 0 && len(s.roles) == 0 && (s.users == nil || !s.users.HasAny()) {
		return true
	}
	token := bearerToken(r.Header.Get("Authorization"))
	if token == "" {
		token = r.URL.Query().Get("token")
	}
	if token == "" {
		token = sessionCookie(r)
	}
	role := s.roleForToken(token)
	return role != "" && roleRank[role] >= roleRank[min]
}

// roleForToken returns the role associated with a bearer token, or the
// empty string if the token is unknown.
func (s *Server) roleForToken(token string) Role {
	if token == "" {
		return ""
	}
	if r, ok := s.roles[token]; ok {
		return r
	}
	if s.authToken != "" && token == s.authToken {
		return RoleSuperAdmin
	}
	if _, ok := s.tenantTokens[token]; ok {
		return RolePolicyAuthor
	}
	if r := s.roleForSession(token); r != "" {
		return r
	}
	if r := s.roleForUserSession(token); r != "" {
		return r
	}
	if role, _, ok := s.roleAndTenantForStoreToken(token); ok {
		return role
	}
	return ""
}
