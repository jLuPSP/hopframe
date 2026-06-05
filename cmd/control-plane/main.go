// Command control-plane is the Hopframe ingest + query service.
//
// Phase 1 ships a single-process server backed by a hash-chained
// append-only file log. Sensors POST events to /v1/events; operators
// open the embedded UI on / for a live stream and can verify the
// chain at /v1/verify. Phase 2 swaps the file store for ClickHouse.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/jlupsp/hopframe/control-plane/api"
	"github.com/jlupsp/hopframe/control-plane/behavior"
	"github.com/jlupsp/hopframe/control-plane/exporter"
	"github.com/jlupsp/hopframe/control-plane/store"
	"github.com/jlupsp/hopframe/internal/buildinfo"
	"github.com/jlupsp/hopframe/pkg/audit"
)

// Set at link time by goreleaser.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	buildinfo.MaybePrint("control-plane", version, commit, date)
	addr := flag.String("addr", ":7090", "listen address (or set HOPFRAME_CONTROL_PLANE_ADDR)")
	logPath := flag.String("log", "data/events.ndjson", "path to append-only event log (or set HOPFRAME_CONTROL_PLANE_LOG); ignored when HOPFRAME_STORE_DSN is set")
	storeDSN := flag.String("store-dsn", "", "Postgres DSN for the audit chain (e.g. postgres://user:pass@host:5432/db?sslmode=require); or set HOPFRAME_STORE_DSN. Falls back to the file backend when empty.")
	retention := flag.Duration("retention", 90*24*time.Hour, "drop records older than this on rotation; 0 disables")
	rotateEvery := flag.Duration("rotate-every", 1*time.Hour, "how often to run retention rotation")
	tlsCert := flag.String("tls-cert", "", "path to server TLS cert (PEM)")
	tlsKey := flag.String("tls-key", "", "path to server TLS key (PEM)")
	tlsClientCA := flag.String("tls-client-ca", "", "path to client CA bundle for mutual TLS (optional)")
	flag.Parse()

	if v := os.Getenv("HOPFRAME_CONTROL_PLANE_ADDR"); v != "" {
		*addr = v
	}
	if v := os.Getenv("HOPFRAME_CONTROL_PLANE_LOG"); v != "" {
		*logPath = v
	}
	if v := os.Getenv("HOPFRAME_STORE_DSN"); v != "" {
		*storeDSN = v
	}
	if v := os.Getenv("HOPFRAME_CONTROL_PLANE_RETENTION"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			*retention = d
		}
	}

	// Pick a backend. A DSN starting with postgres:// or postgresql://
	// routes to the Postgres backend (compatible with Cloud SQL,
	// AWS RDS, Azure Database for PostgreSQL, Aiven, Neon, Supabase,
	// or self-hosted). Anything else is treated as a file path for
	// the append-only NDJSON backend.
	dsn := *storeDSN
	if dsn == "" {
		dsn = *logPath
		if err := os.MkdirAll(dirOf(*logPath), 0o755); err != nil {
			log.Fatalf("control-plane: mkdir log dir: %v", err)
		}
	}
	st, err := store.OpenAuto(dsn, store.Options{
		Path:      *logPath,
		Retention: *retention,
	})
	if err != nil {
		log.Fatalf("control-plane: open store: %v", err)
	}
	if *storeDSN != "" {
		log.Printf("control-plane: store backend=postgres")
	} else {
		log.Printf("control-plane: store backend=file path=%s", *logPath)
	}
	defer func() {
		if err := st.Close(); err != nil {
			log.Printf("control-plane: store close: %v", err)
		}
	}()

	server := api.NewServer(st, api.UIHandler())
	if tok := os.Getenv("HOPFRAME_API_TOKEN"); tok != "" {
		server.SetAuthToken(tok)
		log.Printf("control-plane: bearer-token auth enabled on /v1/*")
	}
	if raw := os.Getenv("HOPFRAME_TENANT_TOKENS"); raw != "" {
		m, err := parseTenantTokens(raw)
		if err != nil {
			log.Fatalf("control-plane: HOPFRAME_TENANT_TOKENS: %v", err)
		}
		server.SetTenantTokens(m)
		log.Printf("control-plane: per-tenant bearer-token scoping enabled (%d tenants)", len(m))
	}
	if v := os.Getenv("HOPFRAME_RATE_LIMIT_RPS"); v != "" {
		if rps, err := strconv.Atoi(v); err == nil && rps > 0 {
			server.SetRateLimit(rps)
			log.Printf("control-plane: rate limit enabled rps=%d on /v1/*", rps)
		} else {
			log.Printf("control-plane: ignoring HOPFRAME_RATE_LIMIT_RPS=%q (must be positive integer)", v)
		}
	}
	if raw := os.Getenv("HOPFRAME_ROLE_TOKENS"); raw != "" {
		m, err := parseRoleTokens(raw)
		if err != nil {
			log.Fatalf("control-plane: HOPFRAME_ROLE_TOKENS: %v", err)
		}
		server.SetRoleTokens(m)
		log.Printf("control-plane: %d role-bound tokens configured", len(m))
	}
	if path := os.Getenv("HOPFRAME_POLICY_PATH"); path != "" {
		ps, err := store.OpenPolicyStore(store.PolicyStoreOptions{
			Path:     path,
			Listener: server.PolicyAuditListener(),
		})
		if err != nil {
			log.Fatalf("control-plane: open policy store: %v", err)
		}
		server.SetPolicyStore(ps)
		log.Printf("control-plane: policy store at %s (version=%d)", path, ps.Version())
	}
	if path := os.Getenv("HOPFRAME_USERS_PATH"); path != "" {
		us, err := api.OpenUserStore(path)
		if err != nil {
			log.Fatalf("control-plane: open user store: %v", err)
		}
		server.SetUserStore(us)
		log.Printf("control-plane: user store at %s (%d users)", path, len(us.List()))

		if raw := os.Getenv("HOPFRAME_BOOTSTRAP_ADMIN"); raw != "" && len(us.List()) == 0 {
			i := indexByte(raw, ':')
			if i < 0 {
				log.Fatalf("control-plane: HOPFRAME_BOOTSTRAP_ADMIN must be username:password")
			}
			username := trimSpace(raw[:i])
			password := raw[i+1:]
			if _, err := us.Create(username, password, api.RoleOwner, ""); err != nil {
				log.Fatalf("control-plane: bootstrap admin: %v", err)
			}
			log.Printf("control-plane: bootstrap owner %q created", username)
		}
	}
	if path := os.Getenv("HOPFRAME_TOKENS_PATH"); path != "" {
		ts, err := api.OpenTokenStore(path)
		if err != nil {
			log.Fatalf("control-plane: open token store: %v", err)
		}
		server.SetTokenStore(ts)
		log.Printf("control-plane: token store at %s (%d tokens)", path, len(ts.List()))
	}
	if root := os.Getenv("HOPFRAME_CONTENT_ROOT"); root != "" {
		if err := server.SetContentRoot(root); err != nil {
			log.Fatalf("control-plane: content root: %v", err)
		}
		log.Printf("control-plane: OTA content delivery from %s", root)
	}
	if os.Getenv("HOPFRAME_SENSOR_FLEET") != "" {
		server.SetSensorFleetEnabled(true)
		log.Printf("control-plane: sensor fleet inventory enabled")
	}
	if path := os.Getenv("HOPFRAME_SIGNING_KEY"); path != "" {
		signer, err := audit.NewSignerFromFile(path, true)
		if err != nil {
			log.Fatalf("control-plane: signing key %s: %v", path, err)
		}
		server.SetSigner(signer)
		log.Printf("control-plane: per-record signer enabled (pub=%s...)", signer.PublicKey()[:16])
	}
	if endpoint := os.Getenv("HOPFRAME_REKOR_URL"); endpoint != "" {
		disabled := os.Getenv("HOPFRAME_REKOR_DISABLED") != ""
		server.SetRekor(&audit.Rekor{Endpoint: endpoint, Disabled: disabled})
		log.Printf("control-plane: rekor anchoring url=%s disabled=%v", endpoint, disabled)
	}
	if issuer := os.Getenv("HOPFRAME_OIDC_ISSUER"); issuer != "" {
		err := server.SetOIDC(api.OIDCConfig{
			Issuer:       issuer,
			ClientID:     os.Getenv("HOPFRAME_OIDC_CLIENT_ID"),
			ClientSecret: os.Getenv("HOPFRAME_OIDC_CLIENT_SECRET"),
			RedirectURL:  os.Getenv("HOPFRAME_OIDC_REDIRECT_URL"),
			DefaultRole:  api.Role(os.Getenv("HOPFRAME_OIDC_DEFAULT_ROLE")),
		})
		if err != nil {
			log.Fatalf("control-plane: oidc: %v", err)
		}
		log.Printf("control-plane: oidc enabled issuer=%s", issuer)
	}

	if url := os.Getenv("HOPFRAME_WEBHOOK_URL"); url != "" {
		wh := &exporter.Webhook{
			URL:         url,
			Secret:      os.Getenv("HOPFRAME_WEBHOOK_SECRET"),
			MinSeverity: os.Getenv("HOPFRAME_WEBHOOK_MIN_SEVERITY"),
		}
		server.AddExporter(wh)
		log.Printf("control-plane: webhook exporter enabled url=%s min_severity=%q", url, wh.MinSeverity)
	}
	if url := os.Getenv("HOPFRAME_SPLUNK_URL"); url != "" {
		sp := &exporter.Splunk{
			URL:         url,
			Token:       os.Getenv("HOPFRAME_SPLUNK_TOKEN"),
			Index:       os.Getenv("HOPFRAME_SPLUNK_INDEX"),
			MinSeverity: os.Getenv("HOPFRAME_SPLUNK_MIN_SEVERITY"),
		}
		server.AddExporter(sp)
		log.Printf("control-plane: splunk HEC exporter enabled url=%s index=%q", url, sp.Index)
	}

	httpServer := &http.Server{
		Addr:              *addr,
		Handler:           server.Routes(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	if *tlsCert != "" && *tlsKey != "" {
		cfg, err := buildServerTLSConfig(*tlsClientCA)
		if err != nil {
			log.Fatalf("control-plane: tls: %v", err)
		}
		httpServer.TLSConfig = cfg
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	go st.RunRetention(ctx, *rotateEvery)

	det := behavior.New(st, st, server, "control-plane", behavior.DefaultOptions())
	go det.Run(ctx)

	errCh := make(chan error, 1)
	go func() {
		scheme := "http"
		if *tlsCert != "" && *tlsKey != "" {
			scheme = "https"
		}
		log.Printf("control-plane listening on %s://%s, log=%s, retention=%s", scheme, *addr, *logPath, *retention)
		var err error
		if *tlsCert != "" && *tlsKey != "" {
			err = httpServer.ListenAndServeTLS(*tlsCert, *tlsKey)
		} else {
			err = httpServer.ListenAndServe()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		log.Printf("shutdown signal received")
	case err := <-errCh:
		log.Fatalf("control-plane: %v", err)
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		log.Printf("control-plane: shutdown: %v", err)
	}
}

// buildServerTLSConfig constructs a *tls.Config for the control-plane
// HTTPS listener. When clientCAFile is set, mutual TLS is enforced -
// any sensor connection without a valid client cert is rejected.
func buildServerTLSConfig(clientCAFile string) (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if clientCAFile != "" {
		body, err := os.ReadFile(clientCAFile)
		if err != nil {
			return nil, fmt.Errorf("read client ca: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(body) {
			return nil, errors.New("client ca file has no usable certs")
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return cfg, nil
}

func dirOf(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[:i]
		}
	}
	return "."
}

// parseTenantTokens parses HOPFRAME_TENANT_TOKENS in the form
// "token1:tenantA,token2:tenantB". Whitespace around commas and colons
// is tolerated. Returns an error on a malformed entry rather than
// silently dropping a token, since a misconfigured tenant binding is
// a security failure mode.
func parseTenantTokens(raw string) (map[string]string, error) {
	out := make(map[string]string)
	for _, entry := range splitTrim(raw, ',') {
		if entry == "" {
			continue
		}
		i := indexByte(entry, ':')
		if i < 0 {
			return nil, fmt.Errorf("entry %q must be in the form token:tenant_id", entry)
		}
		token := trimSpace(entry[:i])
		tenant := trimSpace(entry[i+1:])
		if token == "" {
			return nil, fmt.Errorf("entry %q has empty token", entry)
		}
		if _, dup := out[token]; dup {
			return nil, fmt.Errorf("duplicate token %q", token)
		}
		out[token] = tenant
	}
	if len(out) == 0 {
		return nil, errors.New("no tenant tokens parsed")
	}
	return out, nil
}

// parseRoleTokens parses HOPFRAME_ROLE_TOKENS in the form
// "token1:role1,token2:role2". Canonical role names are
// viewer/editor/admin/owner. The legacy aliases policy_author,
// tenant_admin, super_admin (from before the LaunchDarkly-style
// rename) are accepted and normalized to their canonical form on
// the way in so existing operator configs keep working.
func parseRoleTokens(raw string) (map[string]api.Role, error) {
	out := make(map[string]api.Role)
	for _, entry := range splitTrim(raw, ',') {
		if entry == "" {
			continue
		}
		i := indexByte(entry, ':')
		if i < 0 {
			return nil, fmt.Errorf("entry %q must be in the form token:role", entry)
		}
		token := trimSpace(entry[:i])
		role := api.Role(trimSpace(entry[i+1:]))
		canonical := api.CanonicalRole(role)
		if canonical == "" {
			return nil, fmt.Errorf("unknown role %q (use viewer, editor, admin, owner)", role)
		}
		out[token] = canonical
	}
	if len(out) == 0 {
		return nil, errors.New("no role tokens parsed")
	}
	return out, nil
}

func splitTrim(s string, sep byte) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == sep {
			out = append(out, trimSpace(s[start:i]))
			start = i + 1
		}
	}
	out = append(out, trimSpace(s[start:]))
	return out
}

func trimSpace(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	return s
}

func indexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}
