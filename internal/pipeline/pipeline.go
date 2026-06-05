// Package pipeline orchestrates the per-message detection flow:
// parse the protocol envelope, extract inspectable fields, run all
// configured detectors, derive a policy decision, and produce an
// event.Event ready for emission.
//
// The pipeline does not own networking or the sink; the proxy and
// emitter packages do. This keeps the pipeline trivially testable and
// reusable across protocols.
package pipeline

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/jlupsp/hopframe/internal/quarantine"
	"github.com/jlupsp/hopframe/pkg/a2a"
	"github.com/jlupsp/hopframe/pkg/detect"
	"github.com/jlupsp/hopframe/pkg/event"
	"github.com/jlupsp/hopframe/pkg/mcp"
	"github.com/jlupsp/hopframe/pkg/policy"
	policyclient "github.com/jlupsp/hopframe/pkg/policy/client"
	"github.com/jlupsp/hopframe/pkg/taint"
)

// Pipeline composes a chain of detectors with policy resolution.
type Pipeline struct {
	SensorID  string
	TenantID  string
	Detectors []detect.Detector
	// ModeResolver converts the verdict into the rule-default mode
	// based on the rules that produced findings. Typically wired to
	// ruleset.Ruleset.HighestMode. The result becomes the fallback for
	// the policy engine.
	ModeResolver func(*detect.Verdict) detect.Mode
	// PolicyEngine, when set, is consulted after ModeResolver. If any
	// active policy matches the event scope and verdict, its
	// disposition wins over the rule default. Without an engine, the
	// rule default is the final mode.
	PolicyEngine *policyclient.Engine
	// Quarantine, when set, auto-blocks tools/call to tools previously
	// flagged via tools/list, and adds entries when a tools/list
	// response triggers a critical/high finding on a tool description.
	Quarantine *quarantine.Set
	// Trust, when set, verifies signatures on agent cards observed
	// during EvaluateAgentCard. Cards from issuers not in the trust
	// store get a low-severity "unverified" finding.
	Trust *a2a.TrustStore
	// Taint, when set, enables cross-protocol data lineage: MCP
	// tool-call results are tagged, and A2A task messages from the
	// same agent_run are checked for reuse of tagged data. This is
	// the unique-in-category capability the gateways cannot offer.
	Taint *taint.Tracker
	// TaintAllowedPeers is the optional allowlist of A2A counterparties
	// permitted to receive tainted data. Empty means "alert on any
	// counterparty"; populate to express "data may flow to peer X
	// but never to peer Y."
	TaintAllowedPeers map[string]struct{}
}

// resolveMode picks the final mode for a verdict. Without a policy
// engine, this is whatever the rule default produced. With an engine,
// any matching policy's disposition wins over the rule default.
func (p *Pipeline) resolveMode(v *detect.Verdict, ctx policy.EventContext) (detect.Mode, *policy.Policy) {
	def := detect.ModeMonitor
	if p.ModeResolver != nil {
		def = p.ModeResolver(v)
	}
	if p.PolicyEngine == nil {
		return def, nil
	}
	return p.PolicyEngine.Resolve(ctx, v, def)
}

// scopeServer picks the operator-facing server name for the policy
// context. For inbound traffic (request flowing into the upstream),
// that is the destination. For outbound traffic (response from the
// upstream), that is the source.
func scopeServer(dir event.Direction, source, dest string) string {
	if dir == event.DirectionInbound {
		if dest != "" {
			return dest
		}
		return source
	}
	if source != "" {
		return source
	}
	return dest
}

// MCPResult carries the pipeline outcome for an MCP message.
type MCPResult struct {
	Event  *event.Event
	Action event.Action
	// Block, when true, instructs the proxy to short-circuit with a
	// blocked-by-policy response.
	Block bool
	// BlockReason is the user-visible message used when Block is true.
	BlockReason string
}

// EvaluateMCP runs the pipeline against a single MCP envelope. Raw is
// the original message bytes preserved for forensic replay.
func (p *Pipeline) EvaluateMCP(
	ctx context.Context,
	env *mcp.Envelope,
	raw []byte,
	dir event.Direction,
	source, dest string,
) (*MCPResult, error) {
	start := time.Now()

	in := &detect.Input{
		Protocol:  event.ProtocolMCP,
		Direction: dir,
		Method:    env.Method,
		Fields:    mcp.ExtractFields(env),
		Raw:       raw,
	}

	verdict := &detect.Verdict{}
	for _, d := range p.Detectors {
		if err := d.Detect(ctx, in, verdict); err != nil {
			return nil, err
		}
	}

	// Tools/call to a quarantined tool short-circuits regardless of
	// payload content. We surface this as a synthetic finding so the
	// reason is visible in the event.
	preBlocked := false
	if p.Quarantine != nil && env.Method == mcp.MethodToolsCall && dir == event.DirectionInbound {
		if name := callTargetName(env); name != "" {
			if e, ok := p.Quarantine.Lookup(name); ok {
				verdict.Add(event.Finding{
					RuleID:      "quarantine.tool",
					Category:    "tool-poisoning",
					Severity:    event.SeverityHigh,
					Description: "tool is quarantined: " + e.Reason,
					Field:       "params.name",
					Match:       name,
					Confidence:  1.0,
					Metadata:    map[string]any{"quarantine_rule": e.RuleID},
				})
				preBlocked = true
			}
		}
	}

	mode, matched := p.resolveMode(verdict, policy.EventContext{
		TenantID:   p.TenantID,
		SensorID:   p.SensorID,
		ServerName: scopeServer(dir, source, dest),
		Method:     env.Method,
	})

	action := event.ActionAllow
	switch mode {
	case detect.ModeWarn:
		action = event.ActionWarn
	case detect.ModeBlock:
		action = event.ActionBlock
	}
	if preBlocked {
		action = event.ActionBlock
	}

	// Tools/list response: any high/critical finding on a tool entry
	// adds that tool to the quarantine.
	if p.Quarantine != nil && env.Method == mcp.MethodToolsList && dir == event.DirectionOutbound {
		quarantineFromToolsList(p.Quarantine, env, verdict.Findings)
	}

	ev := event.New(p.SensorID, event.ProtocolMCP, dir)
	ev.EventID = newEventID()
	ev.TenantID = p.TenantID
	ev.Source = source
	ev.Destination = dest
	ev.Message = mcp.MessageFromEnvelope(env, raw)
	ev.Findings = verdict.Findings
	ev.Action = action
	ev.Severity = detect.HighestSeverity(verdict.Findings)
	ev.LatencyMicros = time.Since(start).Microseconds()
	annotateMatchedPolicy(&ev, matched)

	res := &MCPResult{Event: &ev, Action: action}
	if action == event.ActionBlock {
		res.Block = true
		res.BlockReason = blockReason(verdict.Findings)
	}
	return res, nil
}

// annotateMatchedPolicy stamps the matched policy id onto the event so
// the audit log records which policy disposed the traffic. The event
// already carries the rule findings; this adds the policy layer above
// them.
func annotateMatchedPolicy(ev *event.Event, p *policy.Policy) {
	if p == nil {
		return
	}
	ev.Findings = append(ev.Findings, event.Finding{
		RuleID:      "policy.match",
		Category:    "policy_audit",
		Severity:    event.SeverityInfo,
		Description: "matched policy " + p.ID + " v" + itoa(p.Version) + " (" + string(p.Disposition.Mode) + ")",
		Metadata: map[string]any{
			"policy_id":      p.ID,
			"policy_version": p.Version,
			"policy_mode":    string(p.Disposition.Mode),
			"policy_scope":   p.Scope,
		},
	})
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

func blockReason(findings []event.Finding) string {
	for _, f := range findings {
		if f.Severity == event.SeverityCritical || f.Severity == event.SeverityHigh {
			if f.Description != "" {
				return "blocked by hopframe: " + f.RuleID + " (" + f.Description + ")"
			}
			return "blocked by hopframe: " + f.RuleID
		}
	}
	return "blocked by hopframe policy"
}

// A2AResult mirrors MCPResult for A2A traffic.
type A2AResult struct {
	Event       *event.Event
	Action      event.Action
	Block       bool
	BlockReason string
}

// EvaluateA2A runs the detection pipeline against an A2A task envelope.
// Phase 2 sensors call this from the inline proxy.
func (p *Pipeline) EvaluateA2A(
	ctx context.Context,
	env *a2a.TaskEnvelope,
	raw []byte,
	dir event.Direction,
	source, dest string,
) (*A2AResult, error) {
	start := time.Now()

	in := &detect.Input{
		Protocol:  event.ProtocolA2A,
		Direction: dir,
		Method:    env.Method,
		Fields:    a2a.ExtractTaskFields(env),
		Raw:       raw,
	}

	verdict := &detect.Verdict{}
	for _, d := range p.Detectors {
		if err := d.Detect(ctx, in, verdict); err != nil {
			return nil, err
		}
	}

	mode, matched := p.resolveMode(verdict, policy.EventContext{
		TenantID:   p.TenantID,
		SensorID:   p.SensorID,
		ServerName: scopeServer(dir, source, dest),
		Method:     env.Method,
	})
	action := event.ActionAllow
	switch mode {
	case detect.ModeWarn:
		action = event.ActionWarn
	case detect.ModeBlock:
		action = event.ActionBlock
	}

	ev := event.New(p.SensorID, event.ProtocolA2A, dir)
	ev.EventID = newEventID()
	ev.TenantID = p.TenantID
	ev.Source = source
	ev.Destination = dest
	ev.Message = a2a.MessageFromTaskEnvelope(env, raw)
	ev.Findings = verdict.Findings
	ev.Action = action
	ev.Severity = detect.HighestSeverity(verdict.Findings)
	ev.LatencyMicros = time.Since(start).Microseconds()
	annotateMatchedPolicy(&ev, matched)

	res := &A2AResult{Event: &ev, Action: action}
	if action == event.ActionBlock {
		res.Block = true
		res.BlockReason = blockReason(verdict.Findings)
	}
	return res, nil
}

// EvaluateAgentCard runs detection against a discovered A2A agent
// card (typically at /.well-known/agent.json). Returns findings
// alongside structural validation results.
func (p *Pipeline) EvaluateAgentCard(
	ctx context.Context,
	card *a2a.AgentCard,
	raw []byte,
	source string,
) (*a2a.CardValidationResult, *event.Event, error) {
	start := time.Now()

	validation := a2a.ValidateCard(card, raw)

	in := &detect.Input{
		Protocol:  event.ProtocolA2A,
		Direction: event.DirectionOutbound,
		Method:    "agent.card",
		Fields:    a2a.ExtractCardFields(card),
		Raw:       raw,
	}
	verdict := &detect.Verdict{}
	for _, d := range p.Detectors {
		if err := d.Detect(ctx, in, verdict); err != nil {
			return &validation, nil, err
		}
	}

	ev := event.New(p.SensorID, event.ProtocolA2A, event.DirectionOutbound)
	ev.EventID = newEventID()
	ev.TenantID = p.TenantID
	ev.Source = source
	ev.Message = event.Message{
		Method: "agent.card",
		Raw:    string(raw),
	}
	ev.Findings = verdict.Findings

	// Signature verification, when a trust store is configured.
	if p.Trust != nil && validation.SignaturePresent {
		if ok, verr := p.Trust.VerifyCard(card, validation.Canonical); !ok {
			msg := "card signature did not verify"
			if verr != nil {
				msg = verr.Error()
			}
			ev.Findings = append(ev.Findings, event.Finding{
				RuleID:      "card.signature_invalid",
				Category:    "tool-poisoning",
				Severity:    event.SeverityHigh,
				Description: msg,
				Field:       "card.signature",
				Confidence:  1.0,
			})
		} else {
			ev.Findings = append(ev.Findings, event.Finding{
				RuleID:      "card.signature_verified",
				Category:    "policy",
				Severity:    event.SeverityInfo,
				Description: "card signature verified against trust store",
				Field:       "card.signature",
				Confidence:  1.0,
			})
		}
	} else if p.Trust != nil && !validation.SignaturePresent {
		ev.Findings = append(ev.Findings, event.Finding{
			RuleID:      "card.signature_missing",
			Category:    "policy",
			Severity:    event.SeverityLow,
			Description: "card declared no signature; provenance is unverified",
			Field:       "card.signature",
			Confidence:  1.0,
		})
	}

	ev.Severity = detect.HighestSeverity(ev.Findings)
	if len(validation.Errors) > 0 {
		ev.Action = event.ActionBlock
	} else if hasFinding(ev.Findings, "card.signature_invalid") {
		ev.Action = event.ActionBlock
	} else {
		ev.Action = event.ActionAllow
	}
	ev.LatencyMicros = time.Since(start).Microseconds()
	return &validation, &ev, nil
}

func hasFinding(findings []event.Finding, ruleID string) bool {
	for _, f := range findings {
		if f.RuleID == ruleID {
			return true
		}
	}
	return false
}

// TagMCPResult tags every leaf string in the response of a tools/call
// against the agent_run's taint set. Called by the proxy after the
// outbound pipeline pass succeeds. The PRD describes this as
// "data flows from an MCP tool result into an A2A task message", we
// stamp the data here so the A2A side can recognize it later.
func (p *Pipeline) TagMCPResult(env *mcp.Envelope, agentRun string) []taint.Taint {
	if p.Taint == nil || agentRun == "" || env.Method != mcp.MethodToolsCall {
		return nil
	}
	fields := mcp.ExtractFields(env)
	out := make([]taint.Taint, 0, len(fields))
	tool := ""
	if p, err := env.DecodeToolCallParams(); err == nil {
		tool = p.Name
	}
	for _, f := range fields {
		if !isResultField(f.Name) {
			continue
		}
		t := p.Taint.Tag(agentRun, taint.Source{
			Protocol: "mcp",
			Method:   mcp.MethodToolsCall,
			Tool:     tool,
			Field:    f.Name,
		}, f.Value)
		out = append(out, t)
	}
	return out
}

// CheckA2ALeak inspects an A2A task envelope for any leaf string that
// matches a previously-tagged MCP tool result on the same agent_run.
// When a hit is found AND the counterparty is not on the allowlist,
// a finding is appended to the verdict and (when configured) the
// envelope is marked for blocking.
func (p *Pipeline) CheckA2ALeak(env *a2a.TaskEnvelope, agentRun, counterparty string, ev *event.Event) {
	if p.Taint == nil || agentRun == "" {
		return
	}
	if _, allowed := p.TaintAllowedPeers[counterparty]; allowed {
		return
	}
	values := taintCandidateStrings(env)
	if len(values) == 0 {
		return
	}
	hit, ok := p.Taint.MatchAny(agentRun, values)
	if !ok {
		return
	}
	desc := "tainted data from " + hit.Source.Protocol + ":" + hit.Source.Method
	if hit.Source.Tool != "" {
		desc += "(" + hit.Source.Tool + ")"
	}
	desc += " reached A2A counterparty"
	if counterparty != "" {
		desc += " " + counterparty
	}
	ev.Findings = append(ev.Findings, event.Finding{
		RuleID:      "taint.cross_protocol_leak",
		Category:    "policy",
		Severity:    event.SeverityHigh,
		Description: desc,
		Field:       hit.Source.Field,
		Match:       hit.Sample,
		Confidence:  0.95,
		Metadata: map[string]any{
			"taint_id":     hit.ID,
			"source":       hit.Source,
			"counterparty": counterparty,
		},
	})
	ev.Action = event.ActionBlock
	ev.Severity = event.SeverityHigh
}

func isResultField(name string) bool {
	const prefix = "result"
	return len(name) >= len(prefix) && name[:len(prefix)] == prefix
}

func taintCandidateStrings(env *a2a.TaskEnvelope) []string {
	if env == nil {
		return nil
	}
	fields := a2a.ExtractTaskFields(env)
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		// Trim trivial values; taint matching is meaningful only on
		// substantive payloads.
		if len(f.Value) < 16 {
			continue
		}
		out = append(out, f.Value)
	}
	return out
}

// callTargetName extracts params.name from a tools/call envelope.
func callTargetName(env *mcp.Envelope) string {
	p, err := env.DecodeToolCallParams()
	if err != nil {
		return ""
	}
	return p.Name
}

// quarantineFromToolsList walks findings, maps each finding's field
// path back to the tool index, and records that tool name as
// quarantined for any high/critical finding.
func quarantineFromToolsList(set *quarantine.Set, env *mcp.Envelope, findings []event.Finding) {
	if len(findings) == 0 {
		return
	}
	res, err := env.DecodeToolsListResult()
	if err != nil || len(res.Tools) == 0 {
		return
	}
	for _, f := range findings {
		if f.Severity != event.SeverityHigh && f.Severity != event.SeverityCritical {
			continue
		}
		idx := toolIndexFromField(f.Field)
		if idx < 0 || idx >= len(res.Tools) {
			continue
		}
		tool := res.Tools[idx].Name
		if tool == "" {
			continue
		}
		set.Quarantine(tool, f.Description, f.RuleID, string(f.Severity))
	}
}

// toolIndexFromField parses "result.tools.<i>...." and returns <i>.
// Returns -1 if the field name isn't on a tools entry.
func toolIndexFromField(field string) int {
	const prefix = "result.tools."
	if len(field) <= len(prefix) || field[:len(prefix)] != prefix {
		return -1
	}
	rest := field[len(prefix):]
	end := 0
	for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
		end++
	}
	if end == 0 {
		return -1
	}
	idx := 0
	for i := 0; i < end; i++ {
		idx = idx*10 + int(rest[i]-'0')
	}
	return idx
}

func newEventID() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Random failure is exceptional. Fall back to a timestamp tag.
		return "ev-" + time.Now().UTC().Format("20060102T150405.000000")
	}
	return "ev-" + hex.EncodeToString(b[:])
}
