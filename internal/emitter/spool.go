package emitter

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/jlupsp/hopframe/pkg/event"
)

// Spool is a bounded, durable, append-only NDJSON file used by sinks to
// hold events during a control-plane outage. It is intentionally simple:
// one writer, one reader, no sharding. Phase 2 may swap this for a
// segmented log if hot paths need higher throughput.
type Spool struct {
	mu      sync.Mutex
	path    string
	maxSize int64
	file    *os.File
}

// NewSpool opens or creates a spool file at path. maxSize is the cap in
// bytes; once exceeded, Append returns ErrSpoolFull and callers drop.
func NewSpool(path string, maxSize int64) (*Spool, error) {
	if path == "" {
		return nil, errors.New("spool: empty path")
	}
	if maxSize <= 0 {
		maxSize = 64 * 1024 * 1024
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, fmt.Errorf("spool: open %s: %w", path, err)
	}
	return &Spool{path: path, maxSize: maxSize, file: f}, nil
}

// ErrSpoolFull is returned when a write would exceed maxSize.
var ErrSpoolFull = errors.New("spool: full")

// Append writes one event to the spool as a single NDJSON line.
func (s *Spool) Append(ev *event.Event) error {
	body, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.file.Stat()
	if err != nil {
		return err
	}
	if st.Size()+int64(len(body))+1 > s.maxSize {
		return ErrSpoolFull
	}
	if _, err := s.file.Write(append(body, '\n')); err != nil {
		return err
	}
	return nil
}

// Drain reads every event currently in the spool and yields them to fn
// in arrival order. If fn returns nil, the event is consumed; if fn
// returns an error, the remaining events are kept for a later attempt.
//
// Drain rewrites the spool file with the unprocessed remainder. It is
// safe to call concurrently with Append; a mutex serializes both.
func (s *Spool) Drain(fn func(*event.Event) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := s.file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	scanner := bufio.NewScanner(s.file)
	scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)

	var keep [][]byte
	stopped := false
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		if stopped {
			keep = append(keep, append([]byte(nil), line...))
			continue
		}
		var ev event.Event
		if err := json.Unmarshal(line, &ev); err != nil {
			// Corrupt line, drop it.
			continue
		}
		if err := fn(&ev); err != nil {
			// Sink unhealthy; keep this and everything after.
			stopped = true
			keep = append(keep, append([]byte(nil), line...))
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}

	if err := s.file.Truncate(0); err != nil {
		return err
	}
	if _, err := s.file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	for _, line := range keep {
		if _, err := s.file.Write(append(line, '\n')); err != nil {
			return err
		}
	}
	return nil
}

// Close flushes and closes the underlying file.
func (s *Spool) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.file.Close()
}

// Path returns the spool file path.
func (s *Spool) Path() string { return s.path }
