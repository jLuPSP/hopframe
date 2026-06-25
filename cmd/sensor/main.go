// Command sensor runs the MCP and A2A sensors in a single process so
// they share one detection pipeline, and therefore one taint tracker.
//
// The split mcp-sensor / a2a-sensor binaries each keep taint state in
// their own memory, so a tool result tagged on the MCP wire is invisible
// to the A2A wire (cross-protocol taint only works once both sensors
// share state). Running both proxies here, over one *pipeline.Pipeline,
// closes that gap in a single deployable: an MCP tool result tagged on
// the way to the agent is recognized when the agent forwards it to an
// A2A peer, and the forward is blocked.
//
// It listens on two addresses (MCP and A2A) and forwards each to its own
// upstream. Everything else, rules, classifier, emitter, quarantine,
// task-state, counterparty, taint, is shared.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"syscall"
	"time"

	"github.com/jlupsp/hopframe/internal/a2aproxy"
	"github.com/jlupsp/hopframe/internal/buildinfo"
	"github.com/jlupsp/hopframe/internal/config"
	"github.com/jlupsp/hopframe/internal/counterparty"
	"github.com/jlupsp/hopframe/internal/emitter"
	"github.com/jlupsp/hopframe/internal/pipeline"
	"github.com/jlupsp/hopframe/internal/proxy"
	"github.com/jlupsp/hopframe/internal/quarantine"
	"github.com/jlupsp/hopframe/internal/taskstate"
	"github.com/jlupsp/hopframe/pkg/a2a"
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
	buildinfo.MaybePrint("sensor", version, commit, date)
	defaultCfg := "examples/config/sensor.yaml"
	if v := os.Getenv("HOPFRAME_CONFIG"); v != "" {
		defaultCfg = v
	}
	cfgPath := flag.String("config", defaultCfg, "shared sensor config (rules, emitter, policy)")
	trustDir := flag.String("trust-dir", "", "directory of *.pem Ed25519 public keys for agent-card verification")
	flag.Parse()
	if v := os.Getenv("HOPFRAME_TRUST_DIR"); v != "" {
		*trustDir = v
	}
	if err := run(*cfgPath, *trustDir); err != nil {
		log.Fatalf("sensor: %v", err)
	}
}

func run(cfgPath, trustDir string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}

	// MCP listen/upstream default to the config's single pair; A2A comes
	// from its own env vars (a combined sensor has two wires).
	mcpListen := envOr("HOPFRAME_MCP_LISTEN_ADDR", cfg.Listen.Address)
	mcpUpstream := envOr("HOPFRAME_MCP_UPSTREAM_URL", cfg.Upstream.URL)
	a2aListen := envOr("HOPFRAME_A2A_LISTEN_ADDR", ":7081")
	a2aUpstream := os.Getenv("HOPFRAME_A2A_UPSTREAM_URL")
	if mcpUpstream == "" || a2aUpstream == "" {
		return errors.New("sensor: HOPFRAME_MCP_UPSTREAM_URL and HOPFRAME_A2A_UPSTREAM_URL are both required")
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

	// One set of shared state seen by both wires. This is the whole point.
	q := quarantine.New(24 * time.Hour)
	tasks := taskstate.New(2*time.Hour, 4096)
	peers := counterparty.New()
	taintTracker := taint.New(2*time.Hour, 128, 4096)
	// One process already shares taint across both wires. When a control
	// plane is configured, also share it across replicas of this sensor.
	if base := os.Getenv("HOPFRAME_CONTROL_PLANE_URL"); base != "" {
		taintTracker.SetRemote(&policyclient.TaintSync{Client: &policyclient.Client{
			BaseURL:  base,
			Token:    os.Getenv("HOPFRAME_API_TOKEN"),
			SensorID: cfg.Sensor.ID,
			TenantID: cfg.Sensor.TenantID,
		}})
		log.Printf("sensor: cross-replica taint sharing via %s", base)
	}
	classifier := &detect.HeuristicClassifier{}
	detectors := []detect.Detector{rs, classifier}
	if judge := detect.LLMJudgeFromEnv(os.Getenv); judge != nil {
		detectors = append(detectors, judge)
		log.Printf("sensor: Layer 3 LLM judge enabled endpoint=%s model=%q", judge.Endpoint, judge.Model)
	}

	var trust *a2a.TrustStore
	if trustDir != "" {
		trust = a2a.NewTrustStore()
		if err := trust.LoadDir(trustDir); err != nil {
			return fmt.Errorf("trust: %w", err)
		}
		log.Printf("loaded %d trusted issuer keys from %s", trust.Len(), trustDir)
	}

	pipe := &pipeline.Pipeline{
		SensorID:     cfg.Sensor.ID,
		TenantID:     cfg.Sensor.TenantID,
		Detectors:    detectors,
		ModeResolver: rs.HighestMode,
		Quarantine:   q,
		Trust:        trust,
		Taint:        taintTracker,
	}

	mcpSrv, err := proxy.New(proxy.Options{
		Pipeline:    pipe,
		Emitter:     em,
		UpstreamURL: mcpUpstream,
		BasePath:    cfg.Listen.BasePath,
		Timeout:     cfg.Upstream.Timeout,
		FailOpen:    cfg.Policy.FailOpen,
	})
	if err != nil {
		return err
	}

	a2aSrv, err := a2aproxy.New(a2aproxy.Options{
		Pipeline:       pipe,
		Emitter:        em,
		UpstreamURL:    a2aUpstream,
		Timeout:        cfg.Upstream.Timeout,
		FailOpen:       cfg.Policy.FailOpen,
		Tasks:          tasks,
		Peers:          peers,
		BlockTaskDrift: cfg.Policy.BlockTaskDrift,
	})
	if err != nil {
		return err
	}

	mcpMux := http.NewServeMux()
	mcpMux.Handle("/", mcpSrv)
	a2aMux := http.NewServeMux()
	a2aMux.Handle("/", a2aSrv)

	mcpServer := &http.Server{Addr: mcpListen, Handler: mcpMux, ReadHeaderTimeout: 5 * time.Second}
	a2aServer := &http.Server{Addr: a2aListen, Handler: a2aMux, ReadHeaderTimeout: 5 * time.Second}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	errCh := make(chan error, 2)
	go func() {
		log.Printf("sensor: MCP wire listening on %s, forwarding to %s", mcpListen, mcpUpstream)
		if err := mcpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()
	go func() {
		log.Printf("sensor: A2A wire listening on %s, forwarding to %s", a2aListen, a2aUpstream)
		if err := a2aServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
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
	_ = mcpServer.Shutdown(shutdownCtx)
	return a2aServer.Shutdown(shutdownCtx)
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

func jsonEncode(w io.Writer, v any) error {
	return json.NewEncoder(w).Encode(v)
}

var _ = jsonEncode

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
