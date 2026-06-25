// Command a2a-sensor is the inline Hopframe sensor for Agent-to-Agent
// traffic. It mirrors mcp-sensor: HTTP proxy → detection pipeline →
// emitter → control plane. Adds an agent-card validation hook on
// /.well-known/agent.json so card spoofing is caught at discovery.
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
	buildinfo.MaybePrint("a2a-sensor", version, commit, date)
	defaultCfg := "examples/config/a2a-sensor.yaml"
	if v := os.Getenv("HOPFRAME_CONFIG"); v != "" {
		defaultCfg = v
	}
	cfgPath := flag.String("config", defaultCfg, "path to sensor config (or set HOPFRAME_CONFIG)")
	trustDir := flag.String("trust-dir", "", "directory of *.pem Ed25519 public keys for agent-card verification")
	flag.Parse()

	if v := os.Getenv("HOPFRAME_TRUST_DIR"); v != "" {
		*trustDir = v
	}

	if err := run(*cfgPath, *trustDir); err != nil {
		log.Fatalf("a2a-sensor: %v", err)
	}
}

func run(cfgPath, trustDir string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}

	rs, err := loadRules(cfg.Rules)
	if err != nil {
		return err
	}
	log.Printf("loaded %d rules from %v", rs.Len(), cfg.Rules.Dirs)

	var trust *a2a.TrustStore
	if trustDir != "" {
		trust = a2a.NewTrustStore()
		if err := trust.LoadDir(trustDir); err != nil {
			return fmt.Errorf("trust: %w", err)
		}
		log.Printf("loaded %d trusted issuer keys from %s", trust.Len(), trustDir)
	}

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
	tasks := taskstate.New(2*time.Hour, 4096)
	peers := counterparty.New()
	taintTracker := taint.New(2*time.Hour, 128, 4096)
	// Cross-protocol taint across separate sensor processes: when a control
	// plane is configured, share taints through it so a result tagged by the
	// MCP sensor is matchable here on the A2A wire.
	if base := os.Getenv("HOPFRAME_CONTROL_PLANE_URL"); base != "" {
		taintTracker.SetRemote(&policyclient.TaintSync{Client: &policyclient.Client{
			BaseURL:  base,
			Token:    os.Getenv("HOPFRAME_API_TOKEN"),
			SensorID: cfg.Sensor.ID,
			TenantID: cfg.Sensor.TenantID,
		}})
		log.Printf("a2a-sensor: cross-protocol taint sharing via %s", base)
	}
	classifier := &detect.HeuristicClassifier{}
	detectors := []detect.Detector{rs, classifier}
	if judge := detect.LLMJudgeFromEnv(os.Getenv); judge != nil {
		detectors = append(detectors, judge)
		log.Printf("a2a-sensor: Layer 3 LLM judge enabled endpoint=%s model=%q", judge.Endpoint, judge.Model)
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

	srv, err := a2aproxy.New(a2aproxy.Options{
		Pipeline:    pipe,
		Emitter:     em,
		UpstreamURL: cfg.Upstream.URL,
		Timeout:     cfg.Upstream.Timeout,
		FailOpen:    cfg.Policy.FailOpen,
		Tasks:       tasks,
		Peers:       peers,
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
	mux.HandleFunc("/admin/tasks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = jsonEncode(w, map[string]any{
			"tasks":        tasks.List(),
			"long_running": tasks.CheckLongRunning(),
		})
	})
	mux.HandleFunc("/admin/counterparties", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = jsonEncode(w, map[string]any{"counterparties": peers.List(0)})
	})
	mux.Handle("/", srv)

	httpServer := &http.Server{
		Addr:              cfg.Listen.Address,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		log.Printf("a2a-sensor listening on %s, forwarding to %s", cfg.Listen.Address, cfg.Upstream.URL)
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

func jsonEncode(w io.Writer, v any) error {
	return json.NewEncoder(w).Encode(v)
}
