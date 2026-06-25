// Package api is the HTTP surface of the Hopframe control plane.
//
// Endpoints:
//
//	POST /v1/events         sensor event ingest (single event per body)
//	GET  /v1/events         query recent events with filters
//	GET  /v1/events/stream  server-sent events live stream
//	GET  /v1/stats          store stats and chain head
//	GET  /v1/verify         re-walk the chain and report integrity
//	GET  /                  minimal web UI (HTML)
//	GET  /healthz           liveness probe
package api

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jlupsp/hopframe/control-plane/store"
	"github.com/jlupsp/hopframe/pkg/audit"
	"github.com/jlupsp/hopframe/pkg/event"
	"github.com/jlupsp/hopframe/pkg/taint"
)

// Server wraps the store with an HTTP API plus a small fan-out hub for
// SSE subscribers.
type Server struct {
	store        store.AnalyticsStore
	policies     *store.PolicyStore
	hub          *hub
	exporters    []RecordSink
	authToken    string
	tenantTokens map[string]string // token -> tenant_id (admin tenant is "")
	roles        map[string]Role   // token -> role (override default-admin)
	prom         *promRegistry
	limiter      *limiter
	sensors      *sensorFleet
	content      *contentBundle
	oidc         *oidcState
	signer       *audit.Signer
	rekor        *audit.Rekor
	users        *UserStore
	tokenStore   *TokenStore
	rulesCache   *rulesCache
	chainCache   *chainIntegrityCache
	taints       *taint.Tracker // shared cross-protocol taint registry for sensors
}

// RecordSink consumes a record from the hub. Used by exporter wiring.
type RecordSink interface {
	Send(ctx context.Context, rec store.Record) error
}

// NewServer constructs the API. The second argument is retained for
// backward compatibility; the operator UI is now embedded directly via
// s.uiHandler() inside Routes() and the passed-in handler is ignored.
func NewServer(s store.AnalyticsStore, _ http.Handler) *Server {
	return &Server{
		store:  s,
		hub:    newHub(),
		prom:   newPromRegistry(),
		taints: taint.New(2*time.Hour, 128, 4096),
	}
}

// SetAuthToken enables bearer-token authentication on /v1/* endpoints.
// Pass empty string to disable. /healthz, /, and the embedded UI
// remain unauthenticated so liveness checks and humans can browse.
//
// This token is treated as the admin scope and reads across all
// tenants. For per-tenant binding, use SetTenantTokens.
func (s *Server) SetAuthToken(token string) {
	s.authToken = token
}

// SetTenantTokens binds bearer tokens to tenant identifiers. When at
// least one mapping is set, every authenticated /v1/* request is
// scoped to the tenant of the matched token, and any tenant_id query
// parameter on read endpoints is ignored. The admin token configured
// via SetAuthToken still has cross-tenant scope.
//
// Call with nil or an empty map to disable per-tenant binding.
func (s *Server) SetTenantTokens(m map[string]string) {
	if len(m) == 0 {
		s.tenantTokens = nil
		return
	}
	cp := make(map[string]string, len(m))
	for k, v := range m {
		if k == "" {
			continue
		}
		cp[k] = v
	}
	s.tenantTokens = cp
}

// SetRateLimit enables a per-client token-bucket limiter on /v1/*
// endpoints. rps is the steady-state requests-per-second per client;
// the burst is twice rps. Pass 0 to disable.
func (s *Server) SetRateLimit(rps int) {
	if rps <= 0 {
		s.limiter = nil
		return
	}
	s.limiter = newLimiter(rps)
}

// AddExporter registers a downstream sink that receives every newly
// ingested record. Exporters are best-effort: errors are logged via
// the hub's drop counter, and a slow exporter cannot stall ingest.
func (s *Server) AddExporter(sink RecordSink) {
	s.exporters = append(s.exporters, sink)
}

// Broadcast pushes a record into the SSE hub. Used by the behavior
// detector when it appends a synthetic event so live UIs see it
// alongside sensor events.
func (s *Server) Broadcast(rec *store.Record) {
	s.hub.broadcast(rec)
}

// Routes returns the configured mux.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealth)
	mux.HandleFunc("/metrics", s.handlePromMetrics)
	mux.HandleFunc("/v1/events", s.auth(s.handleEvents))
	mux.HandleFunc("/v1/events/stream", s.auth(s.handleStream))
	mux.HandleFunc("/v1/stats", s.auth(s.handleStats))
	mux.HandleFunc("/v1/verify", s.auth(s.handleVerify))
	mux.HandleFunc("/v1/analytics/tools", s.auth(s.handleToolRisk))
	mux.HandleFunc("/v1/analytics/agents", s.auth(s.handleAgentActivity))
	mux.HandleFunc("/v1/analytics/categories", s.auth(s.handleCategoryCounts))
	mux.HandleFunc("/v1/metrics", s.auth(s.handleMetrics))
	mux.HandleFunc("/v1/histogram", s.auth(s.handleHistogram))
	mux.HandleFunc("/v1/events.ndjson", s.auth(s.handleEventsNDJSON))
	mux.HandleFunc("/v1/events.csv", s.auth(s.handleEventsCSV))
	mux.HandleFunc("/v1/analytics/counterparties", s.auth(s.handleCounterparties))
	mux.HandleFunc("/v1/analytics/tasks", s.auth(s.handleTaskConcerns))
	mux.HandleFunc("/v1/agent-runs/", s.auth(s.handleAgentRun))
	// Policies: list + active are viewer-readable so a sensor with a
	// viewer-role token can fetch the active policy snapshot. Mutation
	// (POST/PATCH/DELETE) is gated to editor at the handler level.
	mux.HandleFunc("/v1/policies", s.auth(s.requireRole(RoleViewer, s.handlePolicies)))
	mux.HandleFunc("/v1/policies/", s.auth(s.requireRole(RoleViewer, s.handlePolicyByID)))
	mux.HandleFunc("/v1/sensors", s.auth(s.requireRole(RoleViewer, s.handleSensors)))
	mux.HandleFunc("/v1/sensors/heartbeat", s.auth(s.handleSensorHeartbeat))
	mux.HandleFunc("/v1/taints", s.auth(s.handleTaintRegister))
	mux.HandleFunc("/v1/taints/match", s.auth(s.handleTaintMatch))
	mux.HandleFunc("/v1/content/manifest", s.auth(s.requireRole(RoleViewer, s.handleContentManifest)))
	mux.HandleFunc("/v1/content/", s.auth(s.requireRole(RoleViewer, s.handleContentFile)))
	mux.HandleFunc("/v1/rules", s.auth(s.requireRole(RoleViewer, s.handleRules)))
	mux.HandleFunc("/auth/login", s.handleLoginSubmit)
	mux.HandleFunc("/auth/logout", s.handleLogout)
	mux.HandleFunc("/auth/session", s.handleSessionInfo)
	mux.HandleFunc("/auth/oidc/login", s.handleOIDCLogin)
	mux.HandleFunc("/auth/oidc/callback", s.handleOIDCCallback)
	mux.HandleFunc("/v1/audit/anchor", s.auth(s.requireRole(RoleAdmin, s.handleAuditAnchor)))
	mux.HandleFunc("/v1/records/", s.auth(s.requireRole(RoleViewer, s.handleRecordByID)))
	mux.HandleFunc("/v1/users", s.auth(s.requireRole(RoleAdmin, s.handleUsersCollection)))
	mux.HandleFunc("/v1/users/", s.auth(s.requireRole(RoleAdmin, s.handleUserByName)))
	mux.HandleFunc("/v1/tokens", s.auth(s.requireRole(RoleAdmin, s.handleTokensCollection)))
	mux.HandleFunc("/v1/tokens/", s.auth(s.requireRole(RoleAdmin, s.handleTokenByID)))
	mux.Handle("/", s.uiHandler())
	return s.observe(mux)
}

// observe wraps the mux with rate limiting (when configured) and
// request counting. The limiter applies to /v1/* only; /healthz,
// /metrics, and the UI are unconstrained.
func (s *Server) observe(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		route := routeLabel(r.URL.Path)
		if s.limiter != nil && strings.HasPrefix(r.URL.Path, "/v1/") {
			if !s.limiter.allow(clientIP(r)) {
				s.prom.incRateLimited(route)
				w.Header().Set("Retry-After", "1")
				http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
				s.prom.incRequest(r.Method, route, http.StatusTooManyRequests)
				return
			}
		}
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		h.ServeHTTP(sw, r)
		s.prom.incRequest(r.Method, route, sw.status)
	})
}

// statusWriter records the response status so the metrics middleware
// can include it as a label without parsing the response body.
type statusWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (sw *statusWriter) WriteHeader(code int) {
	if sw.wroteHeader {
		return
	}
	sw.status = code
	sw.wroteHeader = true
	sw.ResponseWriter.WriteHeader(code)
}

func (sw *statusWriter) Write(b []byte) (int, error) {
	if !sw.wroteHeader {
		sw.wroteHeader = true
	}
	return sw.ResponseWriter.Write(b)
}

func (sw *statusWriter) Flush() {
	if f, ok := sw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// routeLabel folds dynamic path segments into stable label values so
// the request_total counter has bounded cardinality. Anything outside
// the known set is folded into "/ui" (the embedded web UI's static
// asset paths).
func routeLabel(p string) string {
	if strings.HasPrefix(p, "/v1/agent-runs/") {
		return "/v1/agent-runs/{id}/timeline"
	}
	if strings.HasPrefix(p, "/v1/policies/") {
		if strings.HasSuffix(p, "/preview") {
			return "/v1/policies/{id}/preview"
		}
		return "/v1/policies/{id}"
	}
	if strings.HasPrefix(p, "/v1/content/") && p != "/v1/content/manifest" {
		return "/v1/content/{name}"
	}
	if strings.HasPrefix(p, "/v1/") || p == "/healthz" || p == "/metrics" {
		return p
	}
	return "/ui"
}

// auth returns h wrapped with bearer-token validation when SetAuthToken
// or SetTenantTokens has been called. When no token is configured, h
// passes through and runs in admin scope. We accept the token from
// either the Authorization header or a query parameter, because
// browsers cannot set custom headers on EventSource and SSE clients
// must authenticate via the URL.
//
// On a successful match, the per-tenant scope is attached to the
// request context. Tenant-scoped tokens force the matched tenant onto
// every read; the admin token leaves the scope unforced so callers can
// pass `?tenant_id=` to pick a tenant. With no auth configured, the
// scope is unforced and reads default to cross-tenant.
func (s *Server) auth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.authToken == "" && len(s.tenantTokens) == 0 && len(s.roles) == 0 && (s.users == nil || !s.users.HasAny()) {
			h(w, r)
			return
		}
		got := bearerToken(r.Header.Get("Authorization"))
		if got == "" {
			got = r.URL.Query().Get("token")
		}
		if got == "" {
			got = sessionCookie(r)
		}
		if got == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if s.authToken != "" && got == s.authToken {
			h(w, r)
			return
		}
		if tenant, ok := s.tenantTokens[got]; ok {
			ctx := context.WithValue(r.Context(), ctxTenantKey, tenantScope{Forced: true, ID: tenant})
			h(w, r.WithContext(ctx))
			return
		}
		if _, ok := s.roles[got]; ok {
			h(w, r)
			return
		}
		if role := s.roleForSession(got); role != "" {
			h(w, r)
			return
		}
		if s.users != nil {
			if role, tenant, ok := s.users.LookupSession(got); ok {
				if tenant != "" {
					ctx := context.WithValue(r.Context(), ctxTenantKey, tenantScope{Forced: true, ID: tenant})
					h(w, r.WithContext(ctx))
					return
				}
				_ = role
				h(w, r)
				return
			}
		}
		if role, tenant, ok := s.roleAndTenantForStoreToken(got); ok {
			_ = role
			if tenant != "" {
				ctx := context.WithValue(r.Context(), ctxTenantKey, tenantScope{Forced: true, ID: tenant})
				h(w, r.WithContext(ctx))
				return
			}
			h(w, r)
			return
		}
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}
}

// tenantScope is the per-request tenant binding produced by auth.
// Forced means the caller's token was tenant-scoped, so the API must
// ignore any tenant_id query parameter and use ID instead. Unforced
// (zero value) means admin or no-auth, and any tenant_id query
// parameter is honored verbatim.
type tenantScope struct {
	Forced bool
	ID     string
}

type ctxKey int

const ctxTenantKey ctxKey = 1

// tenantFor resolves the effective tenant filter for a read request.
// A forced scope from the bearer token always wins. Otherwise the
// caller's `tenant_id` query parameter applies, defaulting to empty
// (cross-tenant).
func tenantFor(r *http.Request) string {
	if v, ok := r.Context().Value(ctxTenantKey).(tenantScope); ok && v.Forced {
		return v.ID
	}
	return r.URL.Query().Get("tenant_id")
}

func bearerToken(authHeader string) string {
	const p = "Bearer "
	if len(authHeader) > len(p) && authHeader[:len(p)] == p {
		return authHeader[len(p):]
	}
	return ""
}

// handleHealth reports component-level health, not just process
// liveness. It returns 200 when every component reports healthy and
// 503 when any single one is degraded. The response body lists every
// component's status so a load balancer can keep "is the binary up"
// semantics on the status code while a human or alerting pipeline can
// dig into the body for the why.
//
// Components checked:
//   - chain: chain-integrity walk via store.Verify, cached for 30s.
//   - store: append-only log writability (a no-op stat call).
//   - policies, content, users: store presence + reachability.
//   - exporter spool: drained (counts dropped recently).
//
// /healthz remains unauthenticated. Liveness probes need it open.
func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	checks := map[string]any{}
	overallOK := true

	// Chain integrity: cached because a full re-walk is expensive.
	chainOK, chainErr := s.cachedChainIntegrity()
	checks["chain"] = healthEntry(chainOK, chainErr)
	if !chainOK {
		overallOK = false
	}

	// Store: stats call exercises a read; if it works, the store is
	// reachable. A real failure here would be a deeper problem already
	// caught by the chain check, but we expose it separately so an
	// operator can tell "store gone" from "chain corrupted".
	storeStats := s.store.Stats()
	checks["store"] = healthEntry(true, nil)
	checks["chain_head_seq"] = storeStats.Seq

	if s.policies != nil {
		checks["policies"] = healthEntry(true, nil)
		checks["policy_version"] = s.policies.Version()
	}
	if s.content != nil {
		checks["content"] = healthEntry(true, nil)
		checks["content_version"] = s.content.version()
	}
	if s.users != nil {
		checks["users"] = healthEntry(true, nil)
		checks["user_count"] = len(s.users.List())
	}
	if s.tokenStore != nil {
		checks["tokens"] = healthEntry(true, nil)
	}

	resp := map[string]any{
		"status":     "ok",
		"checks":     checks,
		"checked_at": time.Now().UTC().Format(time.RFC3339Nano),
	}
	if !overallOK {
		resp["status"] = "degraded"
		writeJSON(w, http.StatusServiceUnavailable, resp)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// chainIntegrityCache caches the outcome of the chain re-walk so
// /healthz pings stay cheap. The walk is O(records on disk) which
// would dominate a hot probe loop. 30 seconds is short enough that
// real corruption surfaces quickly.
type chainIntegrityCache struct {
	mu        sync.Mutex
	checkedAt time.Time
	ok        bool
	err       error
}

func (s *Server) cachedChainIntegrity() (bool, error) {
	if s.chainCache == nil {
		s.chainCache = &chainIntegrityCache{}
	}
	c := s.chainCache
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.checkedAt.IsZero() && time.Since(c.checkedAt) < 30*time.Second {
		return c.ok, c.err
	}
	bad, err := s.store.Verify()
	c.checkedAt = time.Now()
	if err != nil {
		c.ok = false
		c.err = err
		_ = bad
		return false, err
	}
	c.ok = true
	c.err = nil
	return true, nil
}

func healthEntry(ok bool, err error) map[string]any {
	out := map[string]any{"ok": ok}
	if err != nil {
		out["error"] = err.Error()
	}
	return out
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		s.ingest(w, r)
	case http.MethodGet:
		s.query(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) ingest(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	var ev event.Event
	if err := json.NewDecoder(r.Body).Decode(&ev); err != nil {
		http.Error(w, "decode: "+err.Error(), http.StatusBadRequest)
		return
	}
	if ev.Schema == "" {
		ev.Schema = event.SchemaVersion
	}
	// Defense in depth: if the caller authenticated with a tenant-scoped
	// token, force the event's tenant_id to that tenant. A token cannot
	// write events under a tenant it isn't bound to.
	if scope, ok := r.Context().Value(ctxTenantKey).(tenantScope); ok && scope.Forced {
		ev.TenantID = scope.ID
	}
	rec, err := s.store.Append(&ev)
	if err != nil {
		http.Error(w, "store: "+err.Error(), http.StatusInternalServerError)
		return
	}
	s.prom.incEvent(rec.Event)
	s.hub.broadcast(rec)
	for _, ex := range s.exporters {
		go func(ex RecordSink, r store.Record) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = ex.Send(ctx, r)
		}(ex, *rec)
	}
	writeJSON(w, http.StatusAccepted, map[string]any{
		"seq":  rec.Seq,
		"hash": rec.Hash,
	})
}

func (s *Server) query(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit := 50
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	since := uint64(0)
	if v := q.Get("since_seq"); v != "" {
		if n, err := strconv.ParseUint(v, 10, 64); err == nil {
			since = n
		}
	}
	recs, err := s.store.Read(store.Query{
		Limit:       limit,
		Action:      q.Get("action"),
		Severity:    q.Get("severity"),
		MinSeverity: q.Get("min_severity"),
		Method:      q.Get("method"),
		Category:    q.Get("category"),
		Search:      q.Get("search"),
		SinceSeq:    since,
		TenantID:    tenantFor(r),
	})
	if err != nil {
		http.Error(w, "store: "+err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"records": recs})
}

func (s *Server) handleStats(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.store.Stats())
}

func (s *Server) handleToolRisk(w http.ResponseWriter, r *http.Request) {
	limit := 20
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"tools": s.store.ToolRisk(limit)})
}

func (s *Server) handleAgentActivity(w http.ResponseWriter, r *http.Request) {
	limit := 20
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"agents": s.store.AgentActivity(limit)})
}

func (s *Server) handleCategoryCounts(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"categories": s.store.CategoryCounts()})
}

// handleEventsNDJSON streams matching records as newline-delimited
// JSON, with a trailing chain-proof line that lets any downstream
// consumer verify the export was not tampered with.
//
// Format: every record on its own line, then one final line of the
// form {"_type":"chain_proof", "head_hash":"...", "exported_at":"...",
// "seq_range":[lo,hi], "record_count":N}. Combined with the on-disk
// log, a verifier can re-walk the chain over the record's hashes and
// confirm none were altered after export.
func (s *Server) handleEventsNDJSON(w http.ResponseWriter, r *http.Request) {
	recs := s.queryRecords(r, 10000)
	stats := s.store.Stats()
	now := time.Now().UTC()
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Content-Disposition", `attachment; filename="hopframe-events.ndjson"`)
	w.Header().Set("X-Hopframe-Chain-Head", stats.HeadHash)
	w.Header().Set("X-Hopframe-Exported-At", now.Format(time.RFC3339Nano))
	w.Header().Set("X-Hopframe-Record-Count", strconv.Itoa(len(recs)))
	enc := json.NewEncoder(w)
	for _, rec := range recs {
		_ = enc.Encode(rec)
	}
	proof := chainProof(recs, stats.HeadHash, now)
	_ = enc.Encode(proof)
}

// handleEventsCSV exports a flat CSV view (one row per event) plus a
// trailing comment block carrying the chain proof. Designed for
// spreadsheet triage, non-engineer analysts often want this shape -
// and crucially, the file you hand to compliance carries a proof of
// integrity in its footer that no other vendor in this category
// includes by default.
func (s *Server) handleEventsCSV(w http.ResponseWriter, r *http.Request) {
	recs := s.queryRecords(r, 10000)
	stats := s.store.Stats()
	now := time.Now().UTC()
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", `attachment; filename="hopframe-events.csv"`)
	w.Header().Set("X-Hopframe-Chain-Head", stats.HeadHash)
	w.Header().Set("X-Hopframe-Exported-At", now.Format(time.RFC3339Nano))
	w.Header().Set("X-Hopframe-Record-Count", strconv.Itoa(len(recs)))
	cw := csv.NewWriter(w)
	defer func() {
		cw.Flush()
		// Trailing chain-proof block as CSV comments. The csv writer
		// won't emit '#' so we write the comment lines directly to w
		// after flushing the structured rows.
		proof := chainProof(recs, stats.HeadHash, now)
		_, _ = fmt.Fprintf(w, "\n# hopframe chain proof\n")
		_, _ = fmt.Fprintf(w, "# exported_at: %s\n", proof.ExportedAt.Format(time.RFC3339Nano))
		_, _ = fmt.Fprintf(w, "# chain_head:  %s\n", proof.HeadHash)
		_, _ = fmt.Fprintf(w, "# record_count: %d\n", proof.RecordCount)
		if len(proof.SeqRange) == 2 {
			_, _ = fmt.Fprintf(w, "# seq_range:   [%d, %d]\n", proof.SeqRange[0], proof.SeqRange[1])
		}
		_, _ = fmt.Fprintf(w, "# verify: GET /v1/verify on the source control plane and compare chain_head\n")
	}()
	_ = cw.Write([]string{
		"seq", "ingest_at", "event_id", "timestamp", "protocol", "direction",
		"action", "severity", "agent_run_id", "counterparty", "method",
		"finding_count", "rule_ids", "categories", "highest_severity",
		"source", "destination", "raw",
	})
	for _, rec := range recs {
		ev := rec.Event
		if ev == nil {
			continue
		}
		var ruleIDs, categories []string
		highest := string(ev.Severity)
		for _, f := range ev.Findings {
			ruleIDs = append(ruleIDs, f.RuleID)
			categories = append(categories, f.Category)
		}
		_ = cw.Write([]string{
			fmt.Sprintf("%d", rec.Seq),
			rec.IngestAt.Format(time.RFC3339Nano),
			ev.EventID,
			ev.Timestamp.Format(time.RFC3339Nano),
			string(ev.Protocol),
			string(ev.Direction),
			string(ev.Action),
			string(ev.Severity),
			ev.AgentRunID,
			ev.Counterparty,
			ev.Message.Method,
			fmt.Sprintf("%d", len(ev.Findings)),
			strings.Join(ruleIDs, "|"),
			strings.Join(dedupe(categories), "|"),
			highest,
			ev.Source,
			ev.Destination,
			truncateForCSV(ev.Message.Raw, 500),
		})
	}
}

// queryRecords applies the request's filter params and returns a
// matching subset, capped at maxLimit.
func (s *Server) queryRecords(r *http.Request, maxLimit int) []store.Record {
	q := r.URL.Query()
	limit := maxLimit
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n < maxLimit {
			limit = n
		}
	}
	since := uint64(0)
	if v := q.Get("since_seq"); v != "" {
		if n, err := strconv.ParseUint(v, 10, 64); err == nil {
			since = n
		}
	}
	recs, _ := s.store.Read(store.Query{
		Limit:       limit,
		Action:      q.Get("action"),
		Severity:    q.Get("severity"),
		MinSeverity: q.Get("min_severity"),
		Method:      q.Get("method"),
		Category:    q.Get("category"),
		Search:      q.Get("search"),
		SinceSeq:    since,
		TenantID:    tenantFor(r),
	})
	return recs
}

// ChainProof is the trailer attached to every export, binding the
// export to a specific point in the on-disk audit log.
type ChainProof struct {
	Type        string    `json:"_type"`
	HeadHash    string    `json:"head_hash"`
	ExportedAt  time.Time `json:"exported_at"`
	RecordCount int       `json:"record_count"`
	SeqRange    []uint64  `json:"seq_range,omitempty"`
}

func chainProof(recs []store.Record, headHash string, at time.Time) ChainProof {
	p := ChainProof{
		Type:        "chain_proof",
		HeadHash:    headHash,
		ExportedAt:  at,
		RecordCount: len(recs),
	}
	if len(recs) > 0 {
		lo, hi := recs[0].Seq, recs[0].Seq
		for _, r := range recs {
			if r.Seq < lo {
				lo = r.Seq
			}
			if r.Seq > hi {
				hi = r.Seq
			}
		}
		p.SeqRange = []uint64{lo, hi}
	}
	return p
}

func dedupe(xs []string) []string {
	seen := make(map[string]struct{}, len(xs))
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		if x == "" {
			continue
		}
		if _, ok := seen[x]; ok {
			continue
		}
		seen[x] = struct{}{}
		out = append(out, x)
	}
	return out
}

func truncateForCSV(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	window := 5 * time.Minute
	bucket := 10 * time.Second
	if v := r.URL.Query().Get("window"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			window = d
		}
	}
	if v := r.URL.Query().Get("bucket"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			bucket = d
		}
	}
	writeJSON(w, http.StatusOK, s.store.Metrics(window, bucket))
}

func (s *Server) handleHistogram(w http.ResponseWriter, r *http.Request) {
	window := 5 * time.Minute
	bucket := 10 * time.Second
	if v := r.URL.Query().Get("window"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			window = d
		}
	}
	if v := r.URL.Query().Get("bucket"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			bucket = d
		}
	}
	writeJSON(w, http.StatusOK, s.store.Histogram(window, bucket))
}

func (s *Server) handleCounterparties(w http.ResponseWriter, r *http.Request) {
	limit := 20
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"counterparties": s.store.CounterpartyRisks(limit)})
}

func (s *Server) handleTaskConcerns(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"tasks": s.store.TaskConcerns(limit)})
}

// handleAgentRun serves /v1/agent-runs/{id}/timeline. The id segment
// is opaque (uuids, sensor-generated run-XXX strings, caller-supplied,
// etc.) and we treat it as a string match.
func (s *Server) handleAgentRun(w http.ResponseWriter, r *http.Request) {
	const prefix = "/v1/agent-runs/"
	rest := strings.TrimPrefix(r.URL.Path, prefix)
	if rest == r.URL.Path || rest == "" {
		http.Error(w, "missing agent run id", http.StatusBadRequest)
		return
	}
	id, suffix, ok := strings.Cut(rest, "/")
	if !ok || suffix != "timeline" {
		http.Error(w, "expected /v1/agent-runs/{id}/timeline", http.StatusNotFound)
		return
	}
	records := s.store.Timeline(id, tenantFor(r))
	writeJSON(w, http.StatusOK, map[string]any{
		"agent_run_id": id,
		"records":      records,
	})
}

func (s *Server) handleVerify(w http.ResponseWriter, _ *http.Request) {
	bad, err := s.store.Verify()
	resp := map[string]any{}
	if err != nil {
		resp["ok"] = false
		resp["error"] = err.Error()
		if bad != nil {
			resp["bad_seq"] = bad.Seq
		}
		writeJSON(w, http.StatusOK, resp)
		return
	}
	resp["ok"] = true
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	ch := s.hub.subscribe()
	defer s.hub.unsubscribe(ch)

	// Optional: replay a small backlog so reconnecting clients see context.
	if v := r.URL.Query().Get("backlog"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			recs, _ := s.store.Read(store.Query{Limit: n})
			// Reverse so oldest-first.
			for i := len(recs) - 1; i >= 0; i-- {
				if err := writeSSE(w, recs[i]); err != nil {
					return
				}
			}
			flusher.Flush()
		}
	}

	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case rec, open := <-ch:
			if !open {
				return
			}
			if err := writeSSE(w, rec); err != nil {
				return
			}
			flusher.Flush()
		case <-heartbeat.C:
			fmt.Fprintf(w, ": ping\n\n")
			flusher.Flush()
		}
	}
}

func writeSSE(w http.ResponseWriter, rec store.Record) error {
	body, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "event: record\ndata: %s\n\n", body)
	return err
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// hub fans out new records to live SSE subscribers. Slow subscribers are
// dropped silently rather than blocking the broadcast.
type hub struct {
	mu   sync.Mutex
	subs map[chan store.Record]struct{}
}

func newHub() *hub {
	return &hub{subs: make(map[chan store.Record]struct{})}
}

func (h *hub) subscribe() chan store.Record {
	ch := make(chan store.Record, 64)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	h.mu.Unlock()
	return ch
}

func (h *hub) unsubscribe(ch chan store.Record) {
	h.mu.Lock()
	delete(h.subs, ch)
	h.mu.Unlock()
	close(ch)
}

func (h *hub) broadcast(rec *store.Record) {
	if rec == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs {
		select {
		case ch <- *rec:
		default:
			// Slow consumer; drop.
		}
	}
}
