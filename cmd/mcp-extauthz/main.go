// Command mcp-extauthz runs Hopframe as an Envoy external-authorization
// (ext_authz) HTTP service for MCP traffic.
//
// Unlike mcp-sensor, it does not own the data path. Any Envoy-based gateway
// (Envoy, Istio, Gloo, Emissary, Envoy AI Gateway) forwards inbound MCP
// requests here for an allow/deny decision; the gateway keeps doing the
// routing and forwarding. Hopframe contributes the four-stage inbound
// detection pipeline and the same audit events the inline sensor emits.
//
// This is the breadth surface: it attaches to the whole Envoy ecosystem
// with no per-gateway code. Its ceiling is request-side, response-dependent
// features (tools/list quarantine population, cross-protocol taint tagging,
// SSE rewrite) need ext_proc or the native inline sensor. See
// docs/index.md.
//
// Config reuses the sensor config file (rules, emitter, policy, sensor id).
// The upstream block is ignored, the gateway owns the upstream. Listen
// address comes from HOPFRAME_EXTAUTHZ_LISTEN_ADDR or the config's listen
// address; HOPFRAME_EXTAUTHZ_DEST optionally labels the routed upstream for
// policy scoping and the audit destination.
package main

import (
	"context"
	"crypto/tls"
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
	"github.com/jlupsp/hopframe/internal/extauthz"
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
	buildinfo.MaybePrint("mcp-extauthz", version, commit, date)
	defaultCfg := "examples/config/mcp-sensor.yaml"
	if v := os.Getenv("HOPFRAME_CONFIG"); v != "" {
		defaultCfg = v
	}
	cfgPath := flag.String("config", defaultCfg, "path to config file (or set HOPFRAME_CONFIG)")
	flag.Parse()

	if err := run(*cfgPath); err != nil {
		log.Fatalf("mcp-extauthz: %v", err)
	}
}

func run(cfgPath string) error {
	cfg, err := config.Load(cfgPath)
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

	// Quarantine and taint are wired for parity with the inline sensor, but
	// note the ceiling: ext_authz can ENFORCE an existing quarantine entry,
	// yet it never sees a response, so it cannot POPULATE one or tag taint.
	q := quarantine.New(24 * time.Hour)
	taintTracker := taint.New(2*time.Hour, 128, 4096)
	classifier := &detect.HeuristicClassifier{}
	policyEngine := policyclient.NewEngine()
	detectors := []detect.Detector{rs, classifier}
	if judge := detect.LLMJudgeFromEnv(os.Getenv); judge != nil {
		detectors = append(detectors, judge)
		log.Printf("mcp-extauthz: Layer 3 LLM judge enabled endpoint=%s model=%q", judge.Endpoint, judge.Model)
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

	authz, err := extauthz.New(extauthz.Options{
		Pipeline:  pipe,
		Emitter:   em,
		FailOpen:  cfg.Policy.FailOpen,
		DestLabel: os.Getenv("HOPFRAME_EXTAUTHZ_DEST"),
	})
	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.Handle("/", authz)

	listen := envOr("HOPFRAME_EXTAUTHZ_LISTEN_ADDR", cfg.Listen.Address)
	httpServer := &http.Server{
		Addr:              listen,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		log.Printf("mcp-extauthz ext_authz listening on %s (decision-only; the gateway forwards upstream)", listen)
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
