// Command mcp-stdio-sensor wraps a stdio MCP server with Hopframe
// detection. The dominant production shape of MCP today is stdio:
// clients like Claude Desktop, Cursor, Continue, VS Code, claude-code
// spawn MCP servers as subprocesses and speak JSON-RPC over the
// child's stdin/stdout pipes. Without this binary, that traffic is
// invisible to Hopframe.
//
// Usage:
//
//	mcp-stdio-sensor --config sensor.yaml -- python -m mcp_server_filesystem /tmp
//
// The arguments after `--` are the upstream command + args. The
// sensor itself becomes a stdio MCP server from the client's point
// of view: configure your MCP client (Claude Desktop config, etc.)
// to launch `mcp-stdio-sensor -- <real-command>` instead of the real
// command directly. The sensor inspects every JSON-RPC line in both
// directions, applies the detection pipeline, and emits events to
// the configured sink. Blocked messages are short-circuited with a
// JSON-RPC error and never reach the upstream.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"slices"
	"syscall"
	"time"

	"github.com/jlupsp/hopframe/internal/buildinfo"
	"github.com/jlupsp/hopframe/internal/config"
	"github.com/jlupsp/hopframe/internal/emitter"
	"github.com/jlupsp/hopframe/internal/pipeline"
	"github.com/jlupsp/hopframe/internal/quarantine"
	"github.com/jlupsp/hopframe/internal/stdioproxy"
	"github.com/jlupsp/hopframe/pkg/detect"
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
	buildinfo.MaybePrint("mcp-stdio-sensor", version, commit, date)
	defaultCfg := "examples/config/mcp-sensor.yaml"
	if v := os.Getenv("HOPFRAME_CONFIG"); v != "" {
		defaultCfg = v
	}
	cfgPath := flag.String("config", defaultCfg, "sensor config (or HOPFRAME_CONFIG)")
	flag.Parse()

	cmdArgs := flag.Args()
	if len(cmdArgs) == 0 {
		fmt.Fprintln(os.Stderr, "usage: mcp-stdio-sensor [--config FILE] -- COMMAND [ARG...]")
		os.Exit(2)
	}

	if err := run(*cfgPath, cmdArgs[0], cmdArgs[1:]); err != nil {
		log.Fatalf("mcp-stdio-sensor: %v", err)
	}
}

func run(cfgPath, command string, args []string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}

	rs, err := loadRules(cfg.Rules)
	if err != nil {
		return err
	}
	// Log to stderr so we don't pollute stdout (which is the JSON-RPC channel).
	log.SetOutput(os.Stderr)
	log.Printf("loaded %d rules from %v", rs.Len(), cfg.Rules.Dirs)
	log.Printf("wrapping upstream: %s %v", command, args)

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
	pipe := &pipeline.Pipeline{
		SensorID:     cfg.Sensor.ID,
		TenantID:     cfg.Sensor.TenantID,
		Detectors:    []detect.Detector{rs, classifier},
		ModeResolver: rs.HighestMode,
		Quarantine:   q,
		Taint:        taintTracker,
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	return stdioproxy.Run(ctx, stdioproxy.Options{
		Pipeline: pipe,
		Emitter:  em,
		Command:  command,
		Args:     args,
		FailOpen: cfg.Policy.FailOpen,
	})
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
		// In the stdio sensor, stdout is the JSON-RPC channel to the
		// MCP client. NEVER write events there. Force file or http.
		return nil, fmt.Errorf("stdio sensor refuses sink=stdout, use file or http")
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
		return nil, fmt.Errorf("unknown sink %q (must be file or http for stdio sensor)", ec.Sink)
	}
}

// Unused import keeper for json (in case future detection lookups need it).
var _ = json.RawMessage{}
var _ = io.Discard
