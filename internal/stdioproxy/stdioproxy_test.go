package stdioproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jlupsp/hopframe/internal/emitter"
	"github.com/jlupsp/hopframe/internal/pipeline"
	"github.com/jlupsp/hopframe/pkg/detect"
	"github.com/jlupsp/hopframe/pkg/event"
	"github.com/jlupsp/hopframe/pkg/ruleset"
)

// We test the stdio proxy by spawning the stub-stdio-mcp-server we
// ship alongside it. The build of that binary lives at
// ../../cmd/stub-stdio-mcp-server. To avoid coupling the test to a
// pre-built binary, we use `go run` which compiles + runs the stub
// in a single invocation.

type captureSink struct {
	mu     sync.Mutex
	events []*event.Event
}

func (c *captureSink) Deliver(_ context.Context, ev *event.Event) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, ev)
	return nil
}
func (c *captureSink) Close() error { return nil }
func (c *captureSink) snapshot() []*event.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]*event.Event, len(c.events))
	copy(out, c.events)
	return out
}

func setup(t *testing.T) (*pipeline.Pipeline, *captureSink, *emitter.Emitter) {
	t.Helper()
	rs, err := ruleset.LoadDir("../../content")
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	cap := &captureSink{}
	em := emitter.New(cap, 32)
	pipe := &pipeline.Pipeline{
		SensorID:     "stdio-test",
		Detectors:    []detect.Detector{rs, &detect.HeuristicClassifier{}},
		ModeResolver: rs.HighestMode,
	}
	return pipe, cap, em
}

func waitFor(cap *captureSink, n int, timeout time.Duration) []*event.Event {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if got := cap.snapshot(); len(got) >= n {
			return got
		}
		time.Sleep(20 * time.Millisecond)
	}
	return cap.snapshot()
}

// stubArgs returns a `go run` invocation of the stub stdio server.
// We use go run so the test doesn't depend on a pre-built binary.
func stubArgs(extra ...string) (string, []string) {
	stubMain, _ := filepath.Abs(filepath.Join("..", "..", "cmd", "stub-stdio-mcp-server"))
	args := []string{"run", stubMain}
	args = append(args, extra...)
	return "go", args
}

func TestStdioBenignRoundTrip(t *testing.T) {
	pipe, cap, em := setup(t)
	defer em.Close()

	clientIn := bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hi"}}}` + "\n")
	clientOut := &lockedBuffer{}

	cmd, args := stubArgs()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	go func() {
		_ = Run(ctx, Options{
			Pipeline: pipe, Emitter: em,
			Command: cmd, Args: args,
			ClientIn: clientIn, ClientOut: clientOut,
			ChildStderr: io.Discard,
			FailOpen:    true,
		})
	}()

	// Wait for a response on clientOut.
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(clientOut.String(), `"result"`) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	resp := clientOut.String()
	if !strings.Contains(resp, `"id":1`) {
		t.Fatalf("expected response with id=1, got %q", resp)
	}
	if !strings.Contains(resp, `"result"`) {
		t.Fatalf("expected result field, got %q", resp)
	}

	events := waitFor(cap, 2, 5*time.Second)
	if len(events) < 2 {
		t.Fatalf("expected >=2 events (in+out), got %d", len(events))
	}
}

func TestStdioBlocksCredentialExfil(t *testing.T) {
	pipe, _, em := setup(t)
	defer em.Close()

	body := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"text":"my key is AKIAIOSFODNN7EXAMPLE"}}}` + "\n"
	clientIn := bytes.NewBufferString(body)
	clientOut := &lockedBuffer{}

	cmd, args := stubArgs()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	go func() {
		_ = Run(ctx, Options{
			Pipeline: pipe, Emitter: em,
			Command: cmd, Args: args,
			ClientIn: clientIn, ClientOut: clientOut,
			ChildStderr: io.Discard,
			FailOpen:    true,
		})
	}()

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(clientOut.String(), `"error"`) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	resp := clientOut.String()
	var env struct {
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	// Take just the first line to ignore any trailing data.
	first := strings.SplitN(strings.TrimSpace(resp), "\n", 2)[0]
	if err := json.Unmarshal([]byte(first), &env); err != nil {
		t.Fatalf("decode response: %v\nbody: %q", err, resp)
	}
	if env.Error == nil || env.Error.Code != -32001 {
		t.Fatalf("expected blocked-by-policy (-32001), got %+v from %q", env.Error, resp)
	}
}

// lockedBuffer is an io.Writer + Stringer with a mutex for concurrent
// reads-while-writing.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}
func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// Skip the test if go isn't on PATH (unlikely in dev, possible in CI).
func init() {
	if _, err := exec.LookPath("go"); err != nil {
		// Tests in this file require go-toolchain; if missing,
		// they'll naturally fail with an exec error.
		_ = err
	}
}
