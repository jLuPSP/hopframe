// Package stdioproxy implements the stdio transport for Hopframe.
//
// The dominant production shape of MCP today is stdio: clients like
// Claude Desktop, Cursor, Continue, VS Code, and claude-code spawn
// MCP servers as subprocesses and speak JSON-RPC over the child's
// stdin/stdout pipes. Until Hopframe handles this transport, the
// majority of agent traffic in the wild is invisible to it.
//
// stdioproxy is itself a stdio MCP server from the client's
// perspective. It launches the real upstream as a child process and
// pipes JSON-RPC between the client (its own stdin/stdout) and the
// child. Every message in either direction is parsed, evaluated by
// the pipeline, and emitted as an event. Blocked messages are
// short-circuited with a JSON-RPC error and never reach the child.
//
// Wire format assumed: newline-delimited JSON-RPC 2.0. The
// Content-Length-framed variant from the older MCP spec is not
// supported in v1.
package stdioproxy

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/jlupsp/hopframe/internal/emitter"
	"github.com/jlupsp/hopframe/internal/pipeline"
	"github.com/jlupsp/hopframe/pkg/event"
	"github.com/jlupsp/hopframe/pkg/mcp"
)

// Options configure the stdio proxy.
type Options struct {
	Pipeline *pipeline.Pipeline
	Emitter  *emitter.Emitter
	// Command is the upstream MCP server, e.g. "python".
	Command string
	// Args are the arguments to Command.
	Args []string
	// Env is the environment to pass to the child. Empty inherits os.Environ.
	Env []string
	// FailOpen, when true, forwards malformed messages instead of dropping.
	FailOpen bool
	// ClientIn / ClientOut default to os.Stdin / os.Stdout. Tests override.
	ClientIn  io.Reader
	ClientOut io.Writer
	// ChildStderr, when set, receives the child's stderr stream. Defaults
	// to os.Stderr so the operator sees upstream errors.
	ChildStderr io.Writer
}

// Run launches the upstream child and proxies messages until either
// stdin closes (client disconnects) or the child exits. Blocks until
// the session ends.
func Run(ctx context.Context, opts Options) error {
	if err := validate(opts); err != nil {
		return err
	}
	if opts.ClientIn == nil {
		opts.ClientIn = os.Stdin
	}
	if opts.ClientOut == nil {
		opts.ClientOut = os.Stdout
	}
	if opts.ChildStderr == nil {
		opts.ChildStderr = os.Stderr
	}

	cmd := exec.CommandContext(ctx, opts.Command, opts.Args...)
	if len(opts.Env) > 0 {
		cmd.Env = opts.Env
	} else {
		cmd.Env = os.Environ()
	}
	childIn, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("stdio: child stdin: %w", err)
	}
	childOut, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdio: child stdout: %w", err)
	}
	cmd.Stderr = opts.ChildStderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("stdio: start child: %w", err)
	}

	// Generate one synthetic agent run id per session. stdio sessions
	// don't carry a run id over the wire, the client doesn't expose
	// one, so we mint one per child process.
	runID := newRunID()

	// Mutex around the client out pipe: both directions can write to
	// it (block responses on inbound, normal forwards on outbound).
	var outMu sync.Mutex
	writeClient := func(line []byte) error {
		outMu.Lock()
		defer outMu.Unlock()
		if _, err := opts.ClientOut.Write(line); err != nil {
			return err
		}
		if len(line) == 0 || line[len(line)-1] != '\n' {
			_, err := opts.ClientOut.Write([]byte{'\n'})
			return err
		}
		return nil
	}

	// Inbound goroutine: client → pipeline → child.
	inboundDone := make(chan struct{})
	go func() {
		defer close(inboundDone)
		scanner := bufio.NewScanner(opts.ClientIn)
		scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
		for scanner.Scan() {
			line := append([]byte{}, scanner.Bytes()...)
			if len(bytesTrimSpace(line)) == 0 {
				continue
			}
			handled := evaluateAndForward(ctx, opts, line, event.DirectionInbound, runID, writeClient, childIn)
			if !handled {
				// Forwarding error to upstream, child is gone. Stop reading client.
				return
			}
		}
		// Client EOF, close child stdin so the child can exit.
		_ = childIn.Close()
	}()

	// Outbound goroutine: child → pipeline → client.
	outboundDone := make(chan struct{})
	go func() {
		defer close(outboundDone)
		scanner := bufio.NewScanner(childOut)
		scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
		for scanner.Scan() {
			line := append([]byte{}, scanner.Bytes()...)
			if len(bytesTrimSpace(line)) == 0 {
				continue
			}
			evaluateAndForwardOutbound(ctx, opts, line, runID, writeClient)
		}
	}()

	// Wait for the child to exit OR ctx cancellation.
	waitErr := make(chan error, 1)
	go func() { waitErr <- cmd.Wait() }()

	select {
	case <-ctx.Done():
		_ = cmd.Process.Signal(os.Interrupt)
		<-waitErr
	case err := <-waitErr:
		// Wait for goroutines to finish draining.
		<-inboundDone
		<-outboundDone
		if err != nil {
			return fmt.Errorf("stdio: child exited: %w", err)
		}
	}
	return nil
}

// evaluateAndForward parses an inbound line, runs the pipeline, and
// either forwards to the child or short-circuits with a block
// response. Returns false on hard write error (forwarding broke).
func evaluateAndForward(
	ctx context.Context, opts Options, line []byte,
	dir event.Direction, runID string,
	writeClient func([]byte) error,
	childIn io.Writer,
) bool {
	env, err := mcp.Parse(line)
	if err != nil {
		emitMalformed(opts, line, err, runID, dir)
		if opts.FailOpen {
			_, ferr := childIn.Write(append(line, '\n'))
			return ferr == nil
		}
		// Refuse, write a generic JSON-RPC parse-error back to the client.
		errResp, _ := mcp.BlockedResponse(nil, "invalid mcp envelope: "+err.Error())
		_ = writeClient(errResp)
		return true
	}

	res, perr := opts.Pipeline.EvaluateMCP(
		ctx, env, line, dir, "client", "child:"+opts.Command,
	)
	if perr != nil {
		if opts.FailOpen {
			_, ferr := childIn.Write(append(line, '\n'))
			return ferr == nil
		}
		errResp, _ := mcp.BlockedResponse(env.ID, "pipeline error: "+perr.Error())
		_ = writeClient(errResp)
		return true
	}
	res.Event.AgentRunID = runID
	opts.Emitter.Emit(res.Event)

	if res.Block {
		blocked, _ := mcp.BlockedResponse(env.ID, res.BlockReason)
		_ = writeClient(blocked)
		return true
	}
	if _, err := childIn.Write(append(line, '\n')); err != nil {
		return false
	}
	return true
}

// evaluateAndForwardOutbound is the response-side variant. Responses
// don't carry a method on the wire; we'd need to remember the
// inbound method by id to apply method-scoped rules. For v1 we run
// generic detection against the response body.
func evaluateAndForwardOutbound(
	ctx context.Context, opts Options, line []byte, runID string,
	writeClient func([]byte) error,
) {
	env, err := mcp.Parse(line)
	if err != nil {
		emitMalformed(opts, line, err, runID, event.DirectionOutbound)
		_ = writeClient(line)
		return
	}
	res, perr := opts.Pipeline.EvaluateMCP(
		ctx, env, line, event.DirectionOutbound, "child:"+opts.Command, "client",
	)
	if perr != nil {
		_ = writeClient(line)
		return
	}
	res.Event.AgentRunID = runID
	if opts.Pipeline.Taint != nil {
		opts.Pipeline.TagMCPResult(env, runID)
	}
	opts.Emitter.Emit(res.Event)
	if res.Block {
		blocked, _ := mcp.BlockedResponse(env.ID, res.BlockReason)
		_ = writeClient(blocked)
		return
	}
	_ = writeClient(line)
}

func emitMalformed(opts Options, body []byte, parseErr error, runID string, dir event.Direction) {
	if opts.Pipeline == nil || opts.Emitter == nil {
		return
	}
	ev := event.New(opts.Pipeline.SensorID, event.ProtocolMCP, dir)
	ev.EventID = "ev-malformed-" + time.Now().UTC().Format("150405.000000")
	ev.TenantID = opts.Pipeline.TenantID
	ev.AgentRunID = runID
	ev.Source = "client"
	ev.Destination = "child:" + opts.Command
	ev.Message = event.Message{Raw: string(body)}
	ev.Severity = event.SeverityLow
	ev.Findings = []event.Finding{{
		RuleID:      "envelope.malformed",
		Category:    "policy",
		Severity:    event.SeverityLow,
		Description: "MCP envelope failed to parse: " + parseErr.Error(),
	}}
	opts.Emitter.Emit(&ev)
}

func validate(opts Options) error {
	if opts.Pipeline == nil {
		return errors.New("stdioproxy: pipeline is required")
	}
	if opts.Emitter == nil {
		return errors.New("stdioproxy: emitter is required")
	}
	if opts.Command == "" {
		return errors.New("stdioproxy: command is required")
	}
	return nil
}

func newRunID() string {
	var b [10]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "run-stdio-" + time.Now().UTC().Format("150405.000000")
	}
	return "run-stdio-" + hex.EncodeToString(b[:])
}

func bytesTrimSpace(b []byte) []byte {
	for len(b) > 0 && (b[0] == ' ' || b[0] == '\t' || b[0] == '\r' || b[0] == '\n') {
		b = b[1:]
	}
	for len(b) > 0 && (b[len(b)-1] == ' ' || b[len(b)-1] == '\t' || b[len(b)-1] == '\r' || b[len(b)-1] == '\n') {
		b = b[:len(b)-1]
	}
	return b
}
