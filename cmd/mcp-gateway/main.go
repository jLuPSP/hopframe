// Command mcp-gateway runs Hopframe's native multiplexing surface: one
// listen address in front of many MCP upstreams, full inline detection on
// every route.
//
// Unlike mcp-extauthz (which rides someone else's gateway and is request-
// side only), this surface owns the data path, so it keeps full fidelity:
// response-side detection, tools/list quarantine population, cross-protocol
// taint tagging, and SSE rewriting all run, and quarantine + taint state is
// shared across every route. See docs/surface-matrix.md.
//
// Routes are supplied as a JSON array in HOPFRAME_GATEWAY_ROUTES, e.g.
//
//	[{"name":"github","prefix":"/mcp/github","upstream":"http://gh-mcp:9000"},
//	 {"name":"notion","prefix":"/mcp/notion","upstream":"http://notion-mcp:9000"}]
//
// Everything else (rules, classifier, emitter, policy, sensor id) comes from
// the shared sensor config, exactly like mcp-sensor.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"syscall"
	"time"

	"github.com/jlupsp/hopframe/internal/buildinfo"
	"github.com/jlupsp/hopframe/internal/config"
	"github.com/jlupsp/hopframe/internal/emitter"
	"github.com/jlupsp/hopframe/internal/gateway"
	"github.com/jlupsp/hopframe/internal/pipeline"
	"github.com/jlupsp/hopframe/internal/quarantine"
	"github.com/jlupsp/hopframe/pkg/detect"
	policyclient "github.com/jlupsp/hopframe/pkg/policy/client"
	"github.com/jlupsp/hopframe/pkg/ruleset"
	"github.com/jlupsp/hopframe/pkg/taint"
)

// Set at link time by goreleaser.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	buildinfo.MaybePrint("mcp-gateway", version, commit, date)
	defaultCfg := "examples/config/mcp-sensor.yaml"
	if v := os.Getenv("HOPFRAME_CONFIG"); v != "" {
		defaultCfg = v
	}
	cfgPath := flag.String("config", defaultCfg, "path to config file (or set HOPFRAME_CONFIG)")
	routesFlag := flag.String("routes", os.Getenv("HOPFRAME_GATEWAY_ROUTES"), "JSON array of {name,prefix,upstream} routes (or set HOPFRAME_GATEWAY_ROUTES)")
	flag.Parse()

	if err := run(*cfgPath, *routesFlag); err != nil {
		log.Fatalf("mcp-gateway: %v", err)
	}
}

func run(cfgPath, routesJSON string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}

	routes, err := parseRoutes(routesJSON)
	if err != nil {
		return err
	}

	rs, err := loadRules(cfg.Rules)
	if err != nil {
		return err
	}
	log.Printf("loaded %d rules from %v", rs.Len(), cfg.Rules.Dirs)

	sink, err := buildSink(cfg.Emitter)
	if err != nil {
		return err
	}
	em := emitter.New(sink, cfg.Emitter.BufferSize)
	defer func() {
		if cerr := em.Close(); cerr != nil {
			log.Printf("emitter close: %v", cerr)
		}
	}()

	// Shared state across every route: a tool result tagged on one upstream
	// is recognized when forwarded toward another.
	q := quarantine.New(24 * time.Hour)
	taintTracker := taint.New(2*time.Hour, 128, 4096)
	classifier := &detect.HeuristicClassifier{}
	policyEngine := policyclient.NewEngine()
	detectors := []detect.Detector{rs, classifier}
	if judge := detect.LLMJudgeFromEnv(os.Getenv); judge != nil {
		detectors = append(detectors, judge)
		log.Printf("mcp-gateway: Layer 3 LLM judge enabled endpoint=%s model=%q", judge.Endpoint, judge.Model)
	}
	pipe := &pipeline.Pipeline{
		SensorID:     cfg.Sensor.ID,
		TenantID:     cfg.Sensor.TenantID,
		Detectors:    detectors,
		ModeResolver: rs.HighestMode,
		PolicyEngine: policyEngine,
		Quarantine:   q,
		Taint:        taintTracker,
	}

	gw, err := gateway.New(gateway.Options{
		Pipeline: pipe,
		Emitter:  em,
		Routes:   routes,
		Timeout:  cfg.Upstream.Timeout,
		FailOpen: cfg.Policy.FailOpen,
	})
	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.Handle("/", gw)

	listen := envOr("HOPFRAME_GATEWAY_LISTEN_ADDR", cfg.Listen.Address)
	httpServer := &http.Server{
		Addr:              listen,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		log.Printf("mcp-gateway listening on %s, routes=%v", listen, gw.Routes())
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		log.Printf("shutdown signal received")
	case err := <-errCh:
		return err
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	return httpServer.Shutdown(shutdownCtx)
}

func parseRoutes(s string) ([]gateway.Route, error) {
	if s == "" {
		return nil, errors.New("no routes configured: set HOPFRAME_GATEWAY_ROUTES or -routes to a JSON array of {name,prefix,upstream}")
	}
	var routes []gateway.Route
	if err := json.Unmarshal([]byte(s), &routes); err != nil {
		return nil, fmt.Errorf("parse routes json: %w", err)
	}
	if len(routes) == 0 {
		return nil, errors.New("routes json decoded to an empty list")
	}
	return routes, nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func loadRules(rcfg config.Rules) (*ruleset.Ruleset, error) {
	merged := &ruleset.Ruleset{}
	for _, dir := range rcfg.Dirs {
		rs, err := ruleset.LoadDir(dir)
		if err != nil {
			return nil, fmt.Errorf("load rules from %s: %w", dir, err)
		}
		for _, r := range rs.Rules() {
			if slices.Contains(rcfg.DisabledRules, r.ID) {
				continue
			}
			merged.AppendRule(r)
		}
	}
	return merged, nil
}

func buildSink(ec config.Emitter) (emitter.Sink, error) {
	switch ec.Sink {
	case "stdout":
		return emitter.NewStdoutSink(), nil
	case "file":
		return emitter.NewFileSink(ec.Path)
	case "http":
		var tlsCfg *tls.Config
		if ec.TLS.CertFile != "" || ec.TLS.CAFile != "" || ec.TLS.InsecureSkipVerify {
			c, err := emitter.BuildClientTLSConfig(
				ec.TLS.CertFile, ec.TLS.KeyFile, ec.TLS.CAFile,
				ec.TLS.ServerName, ec.TLS.InsecureSkipVerify,
			)
			if err != nil {
				return nil, err
			}
			tlsCfg = c
		}
		return emitter.NewHTTPSinkWithOptions(emitter.HTTPSinkOptions{
			URL:           ec.URL,
			SpoolPath:     ec.SpoolPath,
			SpoolMaxBytes: ec.SpoolMaxBytes,
			ReplayEvery:   ec.ReplayInterval,
			BearerToken:   ec.BearerToken,
			TLSConfig:     tlsCfg,
		})
	default:
		fmt.Fprintf(os.Stderr, "unknown sink %q, defaulting to stdout\n", ec.Sink)
		return emitter.NewStdoutSink(), nil
	}
}
