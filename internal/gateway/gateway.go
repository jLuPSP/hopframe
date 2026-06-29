// Package gateway is Hopframe's native multiplexing surface: one listen
// address in front of many MCP upstreams, with the full inline detection
// pipeline on every route.
//
// It is the inline proxy (internal/proxy) with a routes table. Each route is
// a real proxy.Server bound to that route's upstream but sharing one
// *pipeline.Pipeline, so nothing is lost relative to a single inline sensor:
// response-side detection, tools/list quarantine population, cross-protocol
// taint tagging, and SSE chunk rewriting all still run. Sharing the pipeline
// also means quarantine and taint state is common across every route, which
// is what lets a tool result tagged on one upstream be recognized when the
// agent forwards it toward another.
//
// Routing is longest-prefix match on the request path. The matched prefix is
// stripped before forwarding so the upstream sees a clean path; the route's
// proxy re-joins it onto the upstream base path.
//
// This is the full-fidelity surface in the per-surface matrix
// (docs/surface-matrix.md): unlike the ext_authz attach, Hopframe owns the
// data path here, so there is no response-side blind spot.
package gateway

import (
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/jlupsp/hopframe/internal/emitter"
	"github.com/jlupsp/hopframe/internal/pipeline"
	"github.com/jlupsp/hopframe/internal/proxy"
)

// Route binds a request path prefix to an upstream MCP server.
type Route struct {
	Name     string
	Prefix   string
	Upstream string
}

// Options configure the gateway.
type Options struct {
	Pipeline *pipeline.Pipeline
	Emitter  *emitter.Emitter
	Routes   []Route
	Timeout  time.Duration
	FailOpen bool
}

type compiledRoute struct {
	name   string
	prefix string
	proxy  *proxy.Server
}

// Server multiplexes inbound MCP traffic across routes, each backed by a
// full inline proxy over the shared pipeline.
type Server struct {
	routes []compiledRoute
}

// New builds the gateway. Every route gets its own proxy.Server bound to that
// route's upstream but sharing the one pipeline + emitter.
func New(opts Options) (*Server, error) {
	if opts.Pipeline == nil {
		return nil, errors.New("gateway: pipeline is required")
	}
	if opts.Emitter == nil {
		return nil, errors.New("gateway: emitter is required")
	}
	if len(opts.Routes) == 0 {
		return nil, errors.New("gateway: at least one route is required")
	}
	compiled := make([]compiledRoute, 0, len(opts.Routes))
	seen := map[string]struct{}{}
	for _, rt := range opts.Routes {
		if rt.Prefix == "" || rt.Upstream == "" {
			return nil, fmt.Errorf("gateway: route %q needs both prefix and upstream", rt.Name)
		}
		prefix := strings.TrimRight(rt.Prefix, "/")
		if _, dup := seen[prefix]; dup {
			return nil, fmt.Errorf("gateway: duplicate route prefix %q", prefix)
		}
		seen[prefix] = struct{}{}
		p, err := proxy.New(proxy.Options{
			Pipeline:    opts.Pipeline,
			Emitter:     opts.Emitter,
			UpstreamURL: rt.Upstream,
			Timeout:     opts.Timeout,
			FailOpen:    opts.FailOpen,
		})
		if err != nil {
			return nil, fmt.Errorf("gateway: route %q: %w", rt.Name, err)
		}
		compiled = append(compiled, compiledRoute{name: rt.Name, prefix: prefix, proxy: p})
	}
	// Longest prefix first so the most specific route wins.
	sort.SliceStable(compiled, func(i, j int) bool {
		return len(compiled[i].prefix) > len(compiled[j].prefix)
	})
	return &Server{routes: compiled}, nil
}

// Routes returns the configured route names in match order. Used by the
// admin surface and for logging.
func (s *Server) Routes() []string {
	out := make([]string, len(s.routes))
	for i := range s.routes {
		out[i] = s.routes[i].name
	}
	return out
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet && r.URL.Path == "/healthz" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
		return
	}
	rt := s.match(r.URL.Path)
	if rt == nil {
		http.Error(w, "no hopframe route for path "+r.URL.Path, http.StatusNotFound)
		return
	}
	// Strip the matched prefix so the upstream sees a clean path; the route's
	// proxy re-joins the remainder onto the upstream base path.
	r2 := r.Clone(r.Context())
	r2.URL.Path = stripPrefix(r.URL.Path, rt.prefix)
	rt.proxy.ServeHTTP(w, r2)
}

func (s *Server) match(path string) *compiledRoute {
	for i := range s.routes {
		p := s.routes[i].prefix
		if path == p || strings.HasPrefix(path, p+"/") {
			return &s.routes[i]
		}
	}
	return nil
}

func stripPrefix(path, prefix string) string {
	rest := strings.TrimPrefix(path, prefix)
	if rest == "" {
		return "/"
	}
	return rest
}
