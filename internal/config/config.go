// Package config defines the on-disk configuration for the MCP and A2A
// sensors. Configuration is YAML; sensible defaults are applied on Load.
package config

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the top-level sensor configuration.
type Config struct {
	Sensor   Sensor   `yaml:"sensor"`
	Upstream Upstream `yaml:"upstream"`
	Listen   Listen   `yaml:"listen"`
	Rules    Rules    `yaml:"rules"`
	Emitter  Emitter  `yaml:"emitter"`
	Policy   Policy   `yaml:"policy"`
}

// Sensor identifies the running sensor.
type Sensor struct {
	ID       string `yaml:"id"`
	TenantID string `yaml:"tenant_id"`
}

// Upstream is the MCP server we forward to.
type Upstream struct {
	URL     string        `yaml:"url"`
	Timeout time.Duration `yaml:"timeout"`
}

// Listen is where the sensor accepts inbound traffic.
type Listen struct {
	Address  string `yaml:"address"`
	BasePath string `yaml:"base_path"`
}

// Rules controls rule loading.
type Rules struct {
	// Dirs is a list of directories to load rules from. Defaults to "content".
	Dirs []string `yaml:"dirs"`
	// DisabledRules is a list of rule IDs to skip even if loaded.
	DisabledRules []string `yaml:"disabled_rules"`
}

// Emitter controls where events go.
type Emitter struct {
	// Sink is one of: stdout, file, http.
	Sink string `yaml:"sink"`
	// Path is used by the file sink.
	Path string `yaml:"path"`
	// URL is used by the http sink.
	URL string `yaml:"url"`
	// BufferSize bounds the in-memory queue.
	BufferSize int `yaml:"buffer_size"`
	// SpoolPath, when set on the http sink, enables durable on-disk
	// buffering for events that fail to deliver immediately.
	SpoolPath string `yaml:"spool_path"`
	// SpoolMaxBytes caps the spool file size. Default 64 MiB.
	SpoolMaxBytes int64 `yaml:"spool_max_bytes"`
	// ReplayInterval controls how often the spool is drained back to
	// the upstream sink. Default 5s.
	ReplayInterval time.Duration `yaml:"replay_interval"`
	// BearerToken authenticates the sensor against the control plane.
	// Loaded from HOPFRAME_API_TOKEN at runtime when set.
	BearerToken string `yaml:"bearer_token"`
	// TLS, when populated, enables mutual TLS to the control plane.
	TLS TLS `yaml:"tls"`
}

// TLS configures mutual TLS for sensor → control-plane traffic.
type TLS struct {
	// CertFile is the sensor's client certificate (PEM).
	CertFile string `yaml:"cert_file"`
	// KeyFile is the sensor's private key (PEM).
	KeyFile string `yaml:"key_file"`
	// CAFile is the trust anchor used to verify the control plane's
	// certificate. Empty means use the system trust store.
	CAFile string `yaml:"ca_file"`
	// ServerName overrides the SNI name used for verification. Useful
	// when the control plane URL is reached via an IP or DNS alias.
	ServerName string `yaml:"server_name"`
	// InsecureSkipVerify disables verification. Set only for local dev.
	InsecureSkipVerify bool `yaml:"insecure_skip_verify"`
}

// Policy controls how the sensor reacts when a detector fires.
type Policy struct {
	// FailOpen, when true, forwards the request even if the pipeline errored.
	FailOpen bool `yaml:"fail_open"`
	// DefaultMode is the floor mode applied when a rule has none. Rarely used.
	DefaultMode string `yaml:"default_mode"`
	// BlockTaskDrift, when true, makes A2A task-drift findings (state skip,
	// invalid transition, counterparty mismatch) block the response rather
	// than only flag it. Default false: drift is detected and reported, but
	// blocking it is an opt-in policy because instant/trivial tasks can
	// legitimately look like a state skip.
	BlockTaskDrift bool `yaml:"block_task_drift"`
}

// Defaults returns a Config populated with safe defaults.
func Defaults() Config {
	return Config{
		Sensor: Sensor{
			ID: "mcp-sensor-local",
		},
		Upstream: Upstream{
			Timeout: 30 * time.Second,
		},
		Listen: Listen{
			Address:  ":7080",
			BasePath: "/mcp",
		},
		Rules: Rules{
			Dirs: []string{"content"},
		},
		Emitter: Emitter{
			Sink:       "stdout",
			BufferSize: 1024,
		},
		Policy: Policy{
			FailOpen: true,
		},
	}
}

// Load reads, parses, and validates a YAML config file.
// Environment variables prefixed with HOPFRAME_ override file values.
func Load(path string) (Config, error) {
	cfg := Defaults()
	body, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("config: read %s: %w", path, err)
	}
	if err := yaml.Unmarshal(body, &cfg); err != nil {
		return cfg, fmt.Errorf("config: parse %s: %w", path, err)
	}
	cfg.applyEnvOverrides()
	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func (c *Config) applyEnvOverrides() {
	if v := os.Getenv("HOPFRAME_SENSOR_ID"); v != "" {
		c.Sensor.ID = v
	}
	if v := os.Getenv("HOPFRAME_TENANT_ID"); v != "" {
		c.Sensor.TenantID = v
	}
	if v := os.Getenv("HOPFRAME_UPSTREAM_URL"); v != "" {
		c.Upstream.URL = v
	}
	if v := os.Getenv("HOPFRAME_LISTEN_ADDR"); v != "" {
		c.Listen.Address = v
	}
	if v := os.Getenv("HOPFRAME_EMITTER_SINK"); v != "" {
		c.Emitter.Sink = v
	}
	if v := os.Getenv("HOPFRAME_EMITTER_URL"); v != "" {
		c.Emitter.URL = v
	}
	if v := os.Getenv("HOPFRAME_EMITTER_PATH"); v != "" {
		c.Emitter.Path = v
	}
	if v := os.Getenv("HOPFRAME_API_TOKEN"); v != "" {
		c.Emitter.BearerToken = v
	}
}

func (c *Config) applyDefaults() {
	if c.Sensor.ID == "" {
		c.Sensor.ID = "mcp-sensor-local"
	}
	if c.Upstream.Timeout == 0 {
		c.Upstream.Timeout = 30 * time.Second
	}
	if c.Listen.Address == "" {
		c.Listen.Address = ":7080"
	}
	if c.Listen.BasePath == "" {
		c.Listen.BasePath = "/mcp"
	} else if !strings.HasPrefix(c.Listen.BasePath, "/") {
		c.Listen.BasePath = "/" + c.Listen.BasePath
	}
	if len(c.Rules.Dirs) == 0 {
		c.Rules.Dirs = []string{"content"}
	}
	if c.Emitter.Sink == "" {
		c.Emitter.Sink = "stdout"
	}
	if c.Emitter.BufferSize <= 0 {
		c.Emitter.BufferSize = 1024
	}
}

func (c *Config) validate() error {
	if c.Upstream.URL == "" {
		return errors.New("config: upstream.url is required")
	}
	switch c.Emitter.Sink {
	case "stdout":
	case "file":
		if c.Emitter.Path == "" {
			return errors.New("config: emitter.path required for file sink")
		}
	case "http":
		if c.Emitter.URL == "" {
			return errors.New("config: emitter.url required for http sink")
		}
	default:
		return fmt.Errorf("config: unknown emitter.sink %q", c.Emitter.Sink)
	}
	return nil
}
