// Package emitter delivers structured events to the configured sink:
// stdout (default), an append-only file, or an HTTP control-plane endpoint.
//
// Emitters are non-blocking from the caller's perspective: events are
// enqueued on a bounded channel and a background worker drains it. On
// outage the worker buffers up to BufferSize events; further events are
// dropped with a counter incremented (sensor must never block forwarding).
package emitter

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jlupsp/hopframe/pkg/event"
)

// Sink is the wire-side delivery primitive.
type Sink interface {
	Deliver(ctx context.Context, ev *event.Event) error
	Close() error
}

// Emitter buffers events and pushes them to a Sink from a worker goroutine.
type Emitter struct {
	sink      Sink
	queue     chan *event.Event
	dropped   atomic.Uint64
	delivered atomic.Uint64

	wg     sync.WaitGroup
	cancel context.CancelFunc
}

// New creates an Emitter wrapping the given Sink with a bounded queue.
func New(sink Sink, bufferSize int) *Emitter {
	if bufferSize <= 0 {
		bufferSize = 1024
	}
	ctx, cancel := context.WithCancel(context.Background())
	e := &Emitter{
		sink:   sink,
		queue:  make(chan *event.Event, bufferSize),
		cancel: cancel,
	}
	e.wg.Add(1)
	go e.run(ctx)
	return e
}

// Emit enqueues an event. If the queue is full the event is dropped and
// the dropped counter is incremented.
func (e *Emitter) Emit(ev *event.Event) {
	select {
	case e.queue <- ev:
	default:
		e.dropped.Add(1)
	}
}

// Stats returns delivery counters.
func (e *Emitter) Stats() (delivered, dropped uint64) {
	return e.delivered.Load(), e.dropped.Load()
}

// Close drains the queue and closes the sink.
func (e *Emitter) Close() error {
	e.cancel()
	close(e.queue)
	e.wg.Wait()
	return e.sink.Close()
}

func (e *Emitter) run(ctx context.Context) {
	defer e.wg.Done()
	for ev := range e.queue {
		if ev == nil {
			continue
		}
		// Each delivery has its own short timeout so the worker can
		// drain even when the sink is slow.
		dctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		if err := e.sink.Deliver(dctx, ev); err != nil {
			e.dropped.Add(1)
		} else {
			e.delivered.Add(1)
		}
		cancel()
	}
}

// StdoutSink writes one JSON object per line to stdout. Useful for
// local development and pipelines that consume newline-delimited JSON.
type StdoutSink struct {
	mu sync.Mutex
	w  io.Writer
}

// NewStdoutSink returns a sink that writes to os.Stdout.
func NewStdoutSink() *StdoutSink { return &StdoutSink{w: os.Stdout} }

// NewWriterSink returns a sink that writes to an arbitrary io.Writer.
// Used by tests.
func NewWriterSink(w io.Writer) *StdoutSink { return &StdoutSink{w: w} }

// Deliver implements Sink.
func (s *StdoutSink) Deliver(_ context.Context, ev *event.Event) error {
	body, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.w.Write(append(body, '\n')); err != nil {
		return err
	}
	return nil
}

// Close implements Sink.
func (s *StdoutSink) Close() error { return nil }

// FileSink appends NDJSON to a file, rotating is left to external tooling.
type FileSink struct {
	mu   sync.Mutex
	file *os.File
}

// NewFileSink opens path for append-write.
func NewFileSink(path string) (*FileSink, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("emitter: open %s: %w", path, err)
	}
	return &FileSink{file: f}, nil
}

// Deliver implements Sink.
func (s *FileSink) Deliver(_ context.Context, ev *event.Event) error {
	body, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.file.Write(append(body, '\n')); err != nil {
		return err
	}
	return nil
}

// Close implements Sink.
func (s *FileSink) Close() error { return s.file.Close() }

// HTTPSink POSTs each event as JSON to a control-plane endpoint.
//
// On delivery failure the event is appended to an optional Spool. A
// background goroutine periodically attempts to drain the spool back
// to the upstream endpoint. This gives the sensor at-least-once
// semantics across short control-plane outages without unbounded
// memory growth.
type HTTPSink struct {
	url    string
	client *http.Client
	token  string

	spool       *Spool
	stopReplay  chan struct{}
	replayWG    sync.WaitGroup
	replayEvery time.Duration
}

// HTTPSinkOptions configures the HTTPSink.
type HTTPSinkOptions struct {
	URL string
	// SpoolPath, when non-empty, enables durable replay buffering.
	SpoolPath string
	// SpoolMaxBytes caps the on-disk spool. Default 64 MiB.
	SpoolMaxBytes int64
	// ReplayEvery controls how often the replay loop ticks. Default 5s.
	ReplayEvery time.Duration
	// Timeout on each request. Default 5s.
	Timeout time.Duration
	// BearerToken, when non-empty, is sent as Authorization: Bearer <token>.
	BearerToken string
	// TLSConfig, when non-nil, is used for the HTTPS transport.
	// Constructed by callers via BuildClientTLSConfig.
	TLSConfig *tls.Config
}

// BuildClientTLSConfig assembles a *tls.Config for the sensor side
// of mutual TLS. Pass empty strings to fall back to system trust /
// no client cert.
func BuildClientTLSConfig(certFile, keyFile, caFile, serverName string, insecure bool) (*tls.Config, error) {
	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ServerName:         serverName,
		InsecureSkipVerify: insecure,
	}
	if certFile != "" && keyFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("emitter: load client cert: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	if caFile != "" {
		body, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("emitter: read ca: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(body) {
			return nil, fmt.Errorf("emitter: ca file %s has no usable certs", caFile)
		}
		cfg.RootCAs = pool
	}
	return cfg, nil
}

// NewHTTPSink returns a sink that POSTs events to url with no spool.
// For durable buffering, use NewHTTPSinkWithOptions.
func NewHTTPSink(url string) *HTTPSink {
	s, _ := NewHTTPSinkWithOptions(HTTPSinkOptions{URL: url})
	return s
}

// NewHTTPSinkWithOptions builds an HTTPSink with optional spool and
// configurable timing. Returns an error only if SpoolPath is set and
// cannot be opened.
func NewHTTPSinkWithOptions(opts HTTPSinkOptions) (*HTTPSink, error) {
	if opts.Timeout <= 0 {
		opts.Timeout = 5 * time.Second
	}
	if opts.ReplayEvery <= 0 {
		opts.ReplayEvery = 5 * time.Second
	}
	client := &http.Client{Timeout: opts.Timeout}
	if opts.TLSConfig != nil {
		t := http.DefaultTransport.(*http.Transport).Clone()
		t.TLSClientConfig = opts.TLSConfig
		client.Transport = t
	}
	s := &HTTPSink{
		url:         opts.URL,
		client:      client,
		token:       opts.BearerToken,
		stopReplay:  make(chan struct{}),
		replayEvery: opts.ReplayEvery,
	}
	if opts.SpoolPath != "" {
		sp, err := NewSpool(opts.SpoolPath, opts.SpoolMaxBytes)
		if err != nil {
			return nil, err
		}
		s.spool = sp
		s.replayWG.Add(1)
		go s.runReplay()
	}
	return s, nil
}

// Deliver implements Sink. On failure with a spool configured, the
// event is buffered for a later attempt and Deliver returns nil so the
// caller's delivery counter is not penalized. On failure without a
// spool, the error propagates.
func (s *HTTPSink) Deliver(ctx context.Context, ev *event.Event) error {
	if err := s.post(ctx, ev); err != nil {
		if s.spool == nil {
			return err
		}
		if appendErr := s.spool.Append(ev); appendErr != nil {
			return fmt.Errorf("emitter: deliver=%v, spool=%v", err, appendErr)
		}
		return nil
	}
	return nil
}

func (s *HTTPSink) post(ctx context.Context, ev *event.Event) error {
	body, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Hopframe-Schema", event.SchemaVersion)
	if s.token != "" {
		req.Header.Set("Authorization", "Bearer "+s.token)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("emitter: control plane responded %d", resp.StatusCode)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

func (s *HTTPSink) runReplay() {
	defer s.replayWG.Done()
	tick := time.NewTicker(s.replayEvery)
	defer tick.Stop()
	for {
		select {
		case <-s.stopReplay:
			return
		case <-tick.C:
			_ = s.spool.Drain(func(ev *event.Event) error {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				return s.post(ctx, ev)
			})
		}
	}
}

// Close implements Sink.
func (s *HTTPSink) Close() error {
	if s.spool != nil {
		close(s.stopReplay)
		s.replayWG.Wait()
		return s.spool.Close()
	}
	return nil
}
