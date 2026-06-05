package store

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"
)

// Rotate rewrites the on-disk log, dropping any record whose IngestAt
// is older than the configured retention. The hash chain is preserved
// for the surviving records: each record keeps its original seq, prev,
// and hash. The genesis pointer of the surviving log is updated to the
// hash of the predecessor record we kept (or genesisHash if we kept
// from the start).
//
// Rotation is a stop-the-world operation: we hold the write mutex for
// the duration. For the file sizes Phase 1 targets this is acceptable;
// Phase 2 will swap to ClickHouse where retention is a SQL DELETE.
func (s *Store) Rotate() (kept, dropped int, err error) {
	if s.retention <= 0 {
		return 0, 0, nil
	}
	cutoff := time.Now().UTC().Add(-s.retention)

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := s.file.Seek(0, io.SeekStart); err != nil {
		return 0, 0, err
	}
	scanner := bufio.NewScanner(s.file)
	scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)

	tmpPath := s.path + ".rotate"
	tmp, err := os.Create(tmpPath)
	if err != nil {
		return 0, 0, fmt.Errorf("store: create rotate tmp: %w", err)
	}
	closed := false
	defer func() {
		if !closed {
			_ = tmp.Close()
		}
	}()

	// newChainStart is the prev_hash of the first record we keep. After
	// rotation, this becomes the verified-genesis of the rotated log.
	newChainStart := s.chainStart
	wroteFirst := false

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var rec Record
		if err := json.Unmarshal(line, &rec); err != nil {
			// Skip corrupt records during rotation rather than aborting.
			dropped++
			continue
		}
		if rec.IngestAt.Before(cutoff) {
			dropped++
			continue
		}
		if !wroteFirst {
			newChainStart = rec.PrevHash
			wroteFirst = true
		}
		if _, err := tmp.Write(append(append([]byte{}, line...), '\n')); err != nil {
			return kept, dropped, err
		}
		kept++
	}
	if err := scanner.Err(); err != nil {
		return kept, dropped, err
	}
	if err := tmp.Sync(); err != nil {
		return kept, dropped, err
	}
	if err := tmp.Close(); err != nil {
		return kept, dropped, err
	}
	closed = true

	// Swap files atomically.
	if err := s.file.Close(); err != nil {
		return kept, dropped, err
	}
	if err := os.Rename(tmpPath, s.path); err != nil {
		return kept, dropped, err
	}
	// Persist the new chain genesis. Written after the rename so the
	// log and the genesis pointer are committed together (genesis lags
	// the log by at most one fsync, which Verify tolerates).
	if err := os.WriteFile(s.genesisFilePath(), []byte(newChainStart), 0o644); err != nil {
		return kept, dropped, err
	}
	s.chainStart = newChainStart

	f, err := os.OpenFile(s.path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		return kept, dropped, err
	}
	s.file = f
	// Replay to refresh seq, prevHash, cache.
	if err := s.replay(); err != nil {
		return kept, dropped, err
	}
	return kept, dropped, nil
}

// RunRetention drives Rotate on an interval until ctx is cancelled.
// Intended to be run in a goroutine by the control-plane main loop.
func (s *Store) RunRetention(ctx context.Context, every time.Duration) {
	if s.retention <= 0 || every <= 0 {
		return
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_, _, _ = s.Rotate()
		}
	}
}
