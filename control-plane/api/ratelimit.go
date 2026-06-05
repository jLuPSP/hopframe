package api

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// limiter is a per-client token-bucket rate limiter. Each unique client
// (identified by IP address) gets its own bucket. Buckets are evicted
// after evictAfter of inactivity to keep memory bounded under churn.
//
// The implementation is intentionally small. Operators who need tiered
// limits, distributed counting, or richer keying should put hopframe
// behind their existing API gateway.
type limiter struct {
	mu          sync.Mutex
	rps         int
	burst       int
	evictAfter  time.Duration
	lastSweepAt time.Time
	buckets     map[string]*bucket
}

type bucket struct {
	tokens   float64
	lastFill time.Time
	lastUsed time.Time
}

func newLimiter(rps int) *limiter {
	if rps < 1 {
		rps = 1
	}
	return &limiter{
		rps:         rps,
		burst:       rps * 2,
		evictAfter:  10 * time.Minute,
		lastSweepAt: time.Now(),
		buckets:     make(map[string]*bucket),
	}
}

// allow returns true if the client is allowed to proceed. It returns
// false when the bucket is empty.
func (l *limiter) allow(key string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()

	if now.Sub(l.lastSweepAt) > l.evictAfter {
		for k, b := range l.buckets {
			if now.Sub(b.lastUsed) > l.evictAfter {
				delete(l.buckets, k)
			}
		}
		l.lastSweepAt = now
	}

	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: float64(l.burst), lastFill: now}
		l.buckets[key] = b
	}
	elapsed := now.Sub(b.lastFill).Seconds()
	b.tokens += elapsed * float64(l.rps)
	if b.tokens > float64(l.burst) {
		b.tokens = float64(l.burst)
	}
	b.lastFill = now
	b.lastUsed = now

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// clientIP returns the client's IP for rate-limiting bucket lookup. It
// trusts X-Forwarded-For when the immediate peer is loopback or RFC1918,
// since that's the typical k8s ingress / sidecar setup. Otherwise it
// uses the direct peer address.
//
// If you front the control plane with a reverse proxy on a public
// network, terminate the X-Forwarded-For header at that proxy so the
// upstream can't spoof its identity.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if !isPrivatePeer(host) {
		return host
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// X-Forwarded-For: client, proxy1, proxy2 - take the first hop.
		for i := 0; i < len(xff); i++ {
			if xff[i] == ',' {
				return trimSpace(xff[:i])
			}
		}
		return trimSpace(xff)
	}
	return host
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

func isPrivatePeer(host string) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() {
		return true
	}
	for _, cidr := range privateCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

var privateCIDRs = func() []*net.IPNet {
	out := make([]*net.IPNet, 0, 4)
	for _, raw := range []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"fc00::/7",
	} {
		_, n, err := net.ParseCIDR(raw)
		if err != nil {
			continue
		}
		out = append(out, n)
	}
	return out
}()
