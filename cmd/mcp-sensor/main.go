// Command mcp-sensor is the inline Hopframe sensor for MCP traffic.
//
// It accepts JSON-RPC over HTTP from MCP clients, runs the detection
// pipeline, optionally blocks the message, and forwards approved
// traffic to the configured upstream MCP server. Detection events are
// streamed to the configured emitter sink.
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

	"github.com/jlupsp/hopframe/internal/buildinfo"
	"github.com/jlupsp/hopframe/internal/config"
	"github.com/jlupsp/hopframe/internal/emitter"
	"github.com/jlupsp/hopframe/internal/pipeline"
	"github.com/jlupsp/hopframe/internal/proxy"
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
	buildinfo.MaybePrint("mcp-sensor", version, commit, date)
	defaultCfg := "examples/config/mcp-sensor.yaml"
	if v := os.Getenv("HOPFRAME_CONFIG"); v != "" {
		defaultCfg = v
	}
	cfgPath := flag.String("config", defaultCfg, "path to sensor config file (or set HOPFRAME_CONFIG)")
	flag.Parse()

	if err := run(*cfgPath); err != nil {
		log.Fatalf("mcp-sensor: %v", err)
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

	q := quarantine.New(24 * time.Hour)
	taintTracker := taint.New(2*time.Hour, 128, 4096)
	classifier := &detect.HeuristicClassifier{}
	policyEngine := policyclient.NewEngine()
	detectors := []detect.Detector{rs, classifier}
	if judge := detect.LLMJudgeFromEnv(os.Getenv); judge != nil {
		detectors = append(detectors, judge)
		log.Printf("mcp-sensor: Layer 3 LLM judge enabled endpoint=%s model=%q", judge.Endpoint, judge.Model)
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

	srv, err := proxy.New(proxy.Options{
		Pipeline:    pipe,
		Emitter:     em,
		UpstreamURL: cfg.Upstream.URL,
		BasePath:    cfg.Listen.BasePath,
		Timeout:     cfg.Upstream.Timeout,
		FailOpen:    cfg.Policy.FailOpen,
	})
	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/admin/quarantine", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			_ = jsonEncode(w, map[string]any{"entries": q.List()})
		case http.MethodDelete:
			tool := r.URL.Query().Get("tool")
			if tool == "" {
				http.Error(w, "missing tool query param", http.StatusBadRequest)
				return
			}
			ok := q.Clear(tool)
			_ = jsonEncode(w, map[string]any{"cleared": ok})
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.Handle("/", srv)

	httpServer := &http.Server{
		Addr:              cfg.Listen.Address,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if base := os.Getenv("HOPFRAME_CONTROL_PLANE_URL"); base != "" {
		token := os.Getenv("HOPFRAME_API_TOKEN")
		pc := &policyclient.Client{
			BaseURL:  base,
			Token:    token,
			SensorID: cfg.Sensor.ID,
			TenantID: cfg.Sensor.TenantID,
		}
		taintTracker.SetRemote(&policyclient.TaintSync{Client: pc})
		log.Printf("mcp-sensor: cross-protocol taint sharing via %s", base)
		startedAt := time.Now().UTC()
		hostname, _ := os.Hostname()
		hbBuilder := func() policyclient.HeartbeatBody {
			return policyclient.HeartbeatBody{
				SensorID:      cfg.Sensor.ID,
				TenantID:      cfg.Sensor.TenantID,
				Hostname:      hostname,
				BinaryVersion: "0.2.0",
				StartedAt:     startedAt,
			}
		}
		hooks := policyclient.Hooks{
			OnSwap: func(s *policyclient.Snapshot) {
				log.Printf("policy snapshot v=%d (%d policies) applied", s.Version, len(s.Policies))
			},
			OnError: func(op string, err error) {
				log.Printf("policy %s: %v", op, err)
			},
		}
		go pc.Loop(ctx, policyEngine, 30*time.Second, hbBuilder, hooks)
		log.Printf("mcp-sensor: policy + heartbeat loop running against %s", base)
	}

	errCh := make(chan error, 1)
	go func() {
		log.Printf("mcp-sensor listening on %s, forwarding to %s", cfg.Listen.Address, cfg.Upstream.URL)
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
