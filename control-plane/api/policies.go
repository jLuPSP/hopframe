package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jlupsp/hopframe/control-plane/store"
	"github.com/jlupsp/hopframe/pkg/event"
	"github.com/jlupsp/hopframe/pkg/policy"
)

// SetPolicyStore wires the control plane's policy store into the API.
// When set, the policy CRUD endpoints become available, and every
// mutation is also recorded as a synthetic event on the audit chain so
// the change is visible alongside protocol traffic.
//
// The store passed in must be opened with the matching audit listener
// (see store.OpenPolicyStoreWithAudit). This setter does not re-wire
// the listener; it only attaches the already-configured store.
func (s *Server) SetPolicyStore(ps *store.PolicyStore) {
	s.policies = ps
}

// PolicyAuditListener returns a listener that records every policy
// mutation as a synthetic event on the audit chain. Wire it into the
// PolicyStore at construction time:
//
//	listener := server.PolicyAuditListener()
//	ps, err := store.OpenPolicyStore(store.PolicyStoreOptions{
//	    Path:     "data/policies.json",
//	    Listener: listener,
//	})
//	server.SetPolicyStore(ps)
func (s *Server) PolicyAuditListener() store.PolicyListener {
	return newPolicyAuditWriter(s.store, s.hub)
}

// handlePolicies dispatches /v1/policies (POST list-create, GET list).
// The {id} routes are handled by handlePolicyByID via mux registration
// on /v1/policies/.
//
// Role gating: GET is viewer-accessible (so a sensor with a viewer
// token can read the active set). POST requires editor.
func (s *Server) handlePolicies(w http.ResponseWriter, r *http.Request) {
	if s.policies == nil {
		http.Error(w, "policy store not configured", http.StatusNotFound)
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.listPolicies(w, r)
	case http.MethodPost:
		if !s.callerHasRole(r, RoleEditor) {
			http.Error(w, "forbidden: editor role required", http.StatusForbidden)
			return
		}
		s.createPolicy(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handlePolicyByID(w http.ResponseWriter, r *http.Request) {
	if s.policies == nil {
		http.Error(w, "policy store not configured", http.StatusNotFound)
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/v1/policies/")
	if rest == r.URL.Path {
		http.Error(w, "expected /v1/policies/{id}", http.StatusBadRequest)
		return
	}
	if rest == "active" {
		s.activePolicies(w, r)
		return
	}
	id, suffix, _ := strings.Cut(rest, "/")
	if id == "" {
		http.Error(w, "missing policy id", http.StatusBadRequest)
		return
	}
	if suffix == "preview" {
		s.previewPolicy(w, r, id)
		return
	}
	if suffix != "" {
		http.Error(w, "unknown subresource", http.StatusNotFound)
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.getPolicy(w, r, id)
	case http.MethodPatch, http.MethodPut:
		if !s.callerHasRole(r, RoleEditor) {
			http.Error(w, "forbidden: editor role required", http.StatusForbidden)
			return
		}
		s.updatePolicy(w, r, id)
	case http.MethodDelete:
		if !s.callerHasRole(r, RoleEditor) {
			http.Error(w, "forbidden: editor role required", http.StatusForbidden)
			return
		}
		s.deletePolicy(w, r, id)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) listPolicies(w http.ResponseWriter, r *http.Request) {
	tenantFilter := tenantFor(r)
	all := s.policies.Snapshot()
	out := make([]policy.Policy, 0, len(all))
	for _, p := range all {
		if tenantFilter != "" && p.Scope.TenantID != tenantFilter {
			continue
		}
		out = append(out, p)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"policies": out,
		"version":  s.policies.Version(),
	})
}

func (s *Server) getPolicy(w http.ResponseWriter, r *http.Request, id string) {
	p, ok := s.policies.Get(id)
	if !ok {
		http.Error(w, "policy not found", http.StatusNotFound)
		return
	}
	if t := tenantFor(r); t != "" && p.Scope.TenantID != t {
		http.Error(w, "policy not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (s *Server) createPolicy(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	var p policy.Policy
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		http.Error(w, "decode: "+err.Error(), http.StatusBadRequest)
		return
	}
	if p.ID == "" {
		p.ID = policy.NewID()
	}
	if t := tenantFor(r); t != "" {
		p.Scope.TenantID = t
	}
	stored, err := s.policies.Put(p, actorFor(r))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.prom.incPolicyChange("create", stored.Scope.TenantID)
	writeJSON(w, http.StatusCreated, stored)
}

func (s *Server) updatePolicy(w http.ResponseWriter, r *http.Request, id string) {
	defer r.Body.Close()
	existing, ok := s.policies.Get(id)
	if !ok {
		http.Error(w, "policy not found", http.StatusNotFound)
		return
	}
	if t := tenantFor(r); t != "" && existing.Scope.TenantID != t {
		http.Error(w, "policy not found", http.StatusNotFound)
		return
	}
	var patch policy.Policy
	if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
		http.Error(w, "decode: "+err.Error(), http.StatusBadRequest)
		return
	}
	patch.ID = existing.ID
	if t := tenantFor(r); t != "" {
		patch.Scope.TenantID = t
	}
	stored, err := s.policies.Put(patch, actorFor(r))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.prom.incPolicyChange("update", stored.Scope.TenantID)
	writeJSON(w, http.StatusOK, stored)
}

func (s *Server) deletePolicy(w http.ResponseWriter, r *http.Request, id string) {
	existing, ok := s.policies.Get(id)
	if !ok {
		http.Error(w, "policy not found", http.StatusNotFound)
		return
	}
	if t := tenantFor(r); t != "" && existing.Scope.TenantID != t {
		http.Error(w, "policy not found", http.StatusNotFound)
		return
	}
	if _, _, err := s.policies.Delete(id, actorFor(r)); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.prom.incPolicyChange("delete", existing.Scope.TenantID)
	writeJSON(w, http.StatusOK, map[string]any{"deleted": id})
}

// activePolicies is the read endpoint sensors poll. It returns the
// currently active policy snapshot plus the version stamp the sensor
// uses to decide whether anything changed since its last fetch.
func (s *Server) activePolicies(w http.ResponseWriter, r *http.Request) {
	tenantFilter := tenantFor(r)
	all := s.policies.Snapshot()
	out := make([]policy.Policy, 0, len(all))
	for _, p := range all {
		if !p.Enabled {
			continue
		}
		if tenantFilter != "" && p.Scope.TenantID != "" && p.Scope.TenantID != tenantFilter {
			continue
		}
		out = append(out, p)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"policies": out,
		"version":  s.policies.Version(),
	})
}

// previewPolicy runs a candidate policy against the most recent N
// records in the cache and returns counts of would-block / would-warn /
// would-monitor under that policy. The candidate may be the saved
// version or a body-supplied override.
func (s *Server) previewPolicy(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	defer r.Body.Close()
	candidate, ok := s.policies.Get(id)
	if !ok {
		http.Error(w, "policy not found", http.StatusNotFound)
		return
	}
	if t := tenantFor(r); t != "" && candidate.Scope.TenantID != t {
		http.Error(w, "policy not found", http.StatusNotFound)
		return
	}

	var body struct {
		Override *policy.Policy `json:"override,omitempty"`
		Limit    int            `json:"limit,omitempty"`
	}
	if r.ContentLength > 0 {
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "decode: "+err.Error(), http.StatusBadRequest)
			return
		}
	}
	if body.Override != nil {
		candidate = *body.Override
		candidate.ID = id
	}
	limit := body.Limit
	if limit <= 0 || limit > 5000 {
		limit = 500
	}
	recs, _ := s.store.Read(store.Query{
		Limit:    limit,
		TenantID: tenantFor(r),
	})
	out := previewAgainstRecords(candidate, recs)
	writeJSON(w, http.StatusOK, out)
}

// previewAgainstRecords applies the candidate policy to a slice of
// recorded events and counts the dispositions that would result. It
// uses the recorded findings as the verdict, so this is a hindsight
// replay rather than a full re-execution of the detection pipeline.
func previewAgainstRecords(candidate policy.Policy, recs []store.Record) map[string]any {
	counts := map[string]int{
		"monitor": 0,
		"warn":    0,
		"block":   0,
		"none":    0,
	}
	matched := 0
	for _, rec := range recs {
		ev := rec.Event
		if ev == nil {
			continue
		}
		ctx := policy.EventContext{
			TenantID:   ev.TenantID,
			SensorID:   ev.SensorID,
			ServerName: serverNameFor(ev),
			Method:     ev.Message.Method,
		}
		if !candidate.Scope.Matches(ctx) {
			counts["none"]++
			continue
		}
		if !candidate.Selector.MatchesAny(ctx, ev.Findings) {
			counts["none"]++
			continue
		}
		matched++
		switch candidate.Disposition.Mode {
		case "block":
			counts["block"]++
		case "warn":
			counts["warn"]++
		case "monitor":
			counts["monitor"]++
		default:
			counts["none"]++
		}
	}
	return map[string]any{
		"records_considered": len(recs),
		"records_matched":    matched,
		"would_dispose":      counts,
	}
}

func serverNameFor(ev *event.Event) string {
	if ev.Destination != "" {
		return ev.Destination
	}
	return ev.Source
}

// newSyntheticEvent builds a control-plane-originated event used to
// record policy changes, anchor witnesses, and other operations on the
// audit chain. Synthetic events go through the same store.Append path
// as protocol traffic so the chain captures everything.
func newSyntheticEvent(at time.Time, ruleID, category, description string, metadata map[string]any) event.Event {
	return event.Event{
		Schema:    event.SchemaVersion,
		EventID:   ruleID + "-" + at.UTC().Format("20060102150405.000"),
		Timestamp: at.UTC(),
		SensorID:  "control-plane",
		Protocol:  event.Protocol("control"),
		Direction: event.Direction("synthetic"),
		Action:    event.ActionAllow,
		Severity:  event.SeverityInfo,
		Findings: []event.Finding{
			{
				RuleID:      ruleID,
				Category:    category,
				Severity:    event.SeverityInfo,
				Description: description,
				Metadata:    metadata,
			},
		},
	}
}

// recordPolicyChangeOnChain emits a synthetic audit-log event whenever a
// policy mutation happens. It implements PolicyListener.
type policyAuditWriter struct {
	store store.AnalyticsStore
	hub   *hub
}

func newPolicyAuditWriter(st store.AnalyticsStore, hub *hub) *policyAuditWriter {
	return &policyAuditWriter{store: st, hub: hub}
}

func (w *policyAuditWriter) OnPolicyChange(op string, p policy.Policy, actor string) {
	if w.store == nil {
		return
	}
	ev := event.Event{
		Schema:    event.SchemaVersion,
		EventID:   "policy-" + p.ID + "-v" + fmt.Sprintf("%d", p.Version),
		Timestamp: time.Now().UTC(),
		SensorID:  "control-plane",
		TenantID:  p.Scope.TenantID,
		Protocol:  event.Protocol("policy"),
		Direction: event.Direction("change"),
		Action:    event.ActionAllow,
		Severity:  event.SeverityInfo,
		Findings: []event.Finding{
			{
				RuleID:      "policy.audit." + op,
				Category:    "policy_audit",
				Severity:    event.SeverityInfo,
				Description: fmt.Sprintf("policy %q (%s) %sd by %s", p.Name, p.ID, op, displayActor(actor)),
				Metadata: map[string]any{
					"policy_id":      p.ID,
					"policy_version": p.Version,
					"actor":          displayActor(actor),
					"scope":          p.Scope,
					"disposition":    p.Disposition,
				},
			},
		},
	}
	rec, err := w.store.Append(&ev)
	if err == nil && w.hub != nil {
		w.hub.broadcast(rec)
	}
}

func displayActor(a string) string {
	if a == "" {
		return "unknown"
	}
	return a
}

// actorFor returns a stable identifier for the caller, used in audit
// events. When a tenant token authenticated, the actor is "tenant:<id>".
// When the admin token authenticated, the actor is "admin". When no
// auth is configured, the actor is "anonymous".
func actorFor(r *http.Request) string {
	if v, ok := r.Context().Value(ctxTenantKey).(tenantScope); ok && v.Forced {
		return "tenant:" + v.ID
	}
	if v := r.Header.Get("Authorization"); strings.HasPrefix(v, "Bearer ") {
		return "admin"
	}
	return "anonymous"
}

// PolicyClient is the sensor-side client for fetching policies. It is
// implemented in package policy/client; this hook lets the control
// plane expose a context for its own integration tests.
type PolicyClient interface {
	FetchActive(ctx context.Context, tenantID string) ([]policy.Policy, int64, error)
}

var _ = errors.New
