package api

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jlupsp/hopframe/pkg/event"
)

// promRegistry tracks a small set of monotonic counters and writes them
// out in Prometheus text exposition format. Hand-rolled to avoid pulling
// the prometheus/client_golang dependency tree into a service whose
// existing direct deps are gopkg.in/yaml.v3 only. The metrics shape is
// intentionally narrow: anything richer should land in a dedicated
// exporter package, not here.
type promRegistry struct {
	mu        sync.Mutex
	startedAt time.Time
	// events_ingested_total, keyed by "action|severity".
	events map[string]uint64
	// http_requests_total, keyed by "method|path|status".
	requests map[string]uint64
	// rate_limited_total, keyed by "path".
	rateLimited map[string]uint64
	// policy_changes_total, keyed by "op|tenant".
	policyChanges map[string]uint64
}

func newPromRegistry() *promRegistry {
	return &promRegistry{
		startedAt:     time.Now(),
		events:        make(map[string]uint64, 16),
		requests:      make(map[string]uint64, 32),
		rateLimited:   make(map[string]uint64, 8),
		policyChanges: make(map[string]uint64, 8),
	}
}

func (p *promRegistry) incEvent(ev *event.Event) {
	if p == nil || ev == nil {
		return
	}
	action := string(ev.Action)
	if action == "" {
		action = "unknown"
	}
	severity := string(ev.Severity)
	if severity == "" {
		severity = "unknown"
	}
	key := action + "|" + severity
	p.mu.Lock()
	p.events[key]++
	p.mu.Unlock()
}

func (p *promRegistry) incRequest(method, routePath string, status int) {
	if p == nil {
		return
	}
	key := method + "|" + routePath + "|" + fmt.Sprintf("%d", status)
	p.mu.Lock()
	p.requests[key]++
	p.mu.Unlock()
}

func (p *promRegistry) incRateLimited(routePath string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.rateLimited[routePath]++
	p.mu.Unlock()
}

func (p *promRegistry) incPolicyChange(op, tenant string) {
	if p == nil {
		return
	}
	if tenant == "" {
		tenant = "_org_"
	}
	key := op + "|" + tenant
	p.mu.Lock()
	p.policyChanges[key]++
	p.mu.Unlock()
}

// writeTo emits the registry's counters in the Prometheus text format.
// headSeq is the current chain-head sequence number, exposed as a
// gauge alongside the counters.
func (p *promRegistry) writeTo(w io.Writer, headSeq uint64) {
	p.mu.Lock()
	events := copyCounters(p.events)
	requests := copyCounters(p.requests)
	rateLimited := copyCounters(p.rateLimited)
	policyChanges := copyCounters(p.policyChanges)
	startedAt := p.startedAt
	p.mu.Unlock()

	uptime := time.Since(startedAt).Seconds()

	fmt.Fprintln(w, "# HELP hopframe_uptime_seconds Time since the control plane started.")
	fmt.Fprintln(w, "# TYPE hopframe_uptime_seconds gauge")
	fmt.Fprintf(w, "hopframe_uptime_seconds %g\n", uptime)

	fmt.Fprintln(w, "# HELP hopframe_chain_head_seq Sequence number of the most recent record in the audit log.")
	fmt.Fprintln(w, "# TYPE hopframe_chain_head_seq gauge")
	fmt.Fprintf(w, "hopframe_chain_head_seq %d\n", headSeq)

	fmt.Fprintln(w, "# HELP hopframe_events_ingested_total Number of sensor events ingested, by action and severity.")
	fmt.Fprintln(w, "# TYPE hopframe_events_ingested_total counter")
	for _, k := range sortedKeys(events) {
		action, severity := splitTwo(k)
		fmt.Fprintf(w, "hopframe_events_ingested_total{action=%q,severity=%q} %d\n",
			action, severity, events[k])
	}

	fmt.Fprintln(w, "# HELP hopframe_http_requests_total Number of HTTP requests served, by method, path, and status.")
	fmt.Fprintln(w, "# TYPE hopframe_http_requests_total counter")
	for _, k := range sortedKeys(requests) {
		parts := strings.SplitN(k, "|", 3)
		if len(parts) != 3 {
			continue
		}
		fmt.Fprintf(w, "hopframe_http_requests_total{method=%q,path=%q,status=%q} %d\n",
			parts[0], parts[1], parts[2], requests[k])
	}

	fmt.Fprintln(w, "# HELP hopframe_rate_limited_total Number of HTTP requests rejected by the rate limiter, by path.")
	fmt.Fprintln(w, "# TYPE hopframe_rate_limited_total counter")
	for _, k := range sortedKeys(rateLimited) {
		fmt.Fprintf(w, "hopframe_rate_limited_total{path=%q} %d\n", k, rateLimited[k])
	}

	fmt.Fprintln(w, "# HELP hopframe_policy_changes_total Number of policy CRUD operations, by op and tenant.")
	fmt.Fprintln(w, "# TYPE hopframe_policy_changes_total counter")
	for _, k := range sortedKeys(policyChanges) {
		op, tenant := splitTwo(k)
		fmt.Fprintf(w, "hopframe_policy_changes_total{op=%q,tenant=%q} %d\n", op, tenant, policyChanges[k])
	}
}

func (s *Server) handlePromMetrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	s.prom.writeTo(w, s.store.Stats().Seq)
}

func copyCounters(in map[string]uint64) map[string]uint64 {
	out := make(map[string]uint64, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func sortedKeys(in map[string]uint64) []string {
	keys := make([]string, 0, len(in))
	for k := range in {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func splitTwo(k string) (string, string) {
	i := strings.IndexByte(k, '|')
	if i < 0 {
		return k, ""
	}
	return k[:i], k[i+1:]
}
