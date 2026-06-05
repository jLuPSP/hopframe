// Command dumb-proxy is a deliberately uninspected reverse proxy used
// in the blind-spot demo. It approximates what a generic MCP gateway
// gives you: route + auth + logging, but no protocol-aware threat
// detection. Sending poisoned content through it and through Hopframe
// side-by-side is the cleanest way to show what Hopframe adds.
package main

import (
	"flag"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/jlupsp/hopframe/internal/buildinfo"
)

// Set at link time by goreleaser.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	buildinfo.MaybePrint("dumb-proxy", version, commit, date)
	addr := flag.String("addr", ":7180", "listen address")
	upstream := flag.String("upstream", "http://127.0.0.1:8088", "upstream URL")
	flag.Parse()

	u, err := url.Parse(*upstream)
	if err != nil {
		log.Fatalf("dumb-proxy: parse upstream: %v", err)
	}
	rev := httputil.NewSingleHostReverseProxy(u)
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"status":"ok"}`)
	})
	mux.Handle("/", rev)
	srv := &http.Server{Addr: *addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	log.Printf("dumb-proxy listening on %s, forwarding to %s (NO inspection)", *addr, *upstream)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("dumb-proxy: %v", err)
	}
}
