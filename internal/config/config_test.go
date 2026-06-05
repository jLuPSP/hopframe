package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadAppliesDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cfg.yaml")
	body := []byte(`
sensor:
  id: ""
upstream:
  url: http://example
`)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Sensor.ID != "mcp-sensor-local" {
		t.Fatalf("sensor id = %q", cfg.Sensor.ID)
	}
	if cfg.Listen.Address == "" {
		t.Fatalf("listen address should default")
	}
	if cfg.Listen.BasePath != "/mcp" {
		t.Fatalf("base path = %q", cfg.Listen.BasePath)
	}
	if cfg.Emitter.Sink != "stdout" {
		t.Fatalf("sink = %q", cfg.Emitter.Sink)
	}
	if cfg.Emitter.BufferSize <= 0 {
		t.Fatalf("buffer size = %d", cfg.Emitter.BufferSize)
	}
}

func TestLoadRejectsMissingUpstream(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cfg.yaml")
	if err := os.WriteFile(path, []byte("sensor: {id: x}"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Fatalf("expected error for missing upstream.url")
	}
}

func TestEnvOverridesWin(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cfg.yaml")
	body := []byte(`
sensor:
  id: from-file
upstream:
  url: http://from-file
`)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	t.Setenv("HOPFRAME_SENSOR_ID", "from-env")
	t.Setenv("HOPFRAME_UPSTREAM_URL", "http://from-env")
	t.Setenv("HOPFRAME_LISTEN_ADDR", ":9999")
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Sensor.ID != "from-env" {
		t.Fatalf("sensor id = %q", cfg.Sensor.ID)
	}
	if cfg.Upstream.URL != "http://from-env" {
		t.Fatalf("upstream url = %q", cfg.Upstream.URL)
	}
	if cfg.Listen.Address != ":9999" {
		t.Fatalf("listen address = %q", cfg.Listen.Address)
	}
}

func TestLoadRejectsBadSink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cfg.yaml")
	body := []byte(`
upstream:
  url: http://example
emitter:
  sink: typo
`)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Fatalf("expected error for unknown sink")
	}
}
