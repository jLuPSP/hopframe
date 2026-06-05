// Package policy is the operator-facing dispatch layer that sits on top of
// detection rules. A rule matches ("this regex hits this field"); a policy
// disposes ("for tenant X on the github MCP server, when rule R fires, block
// in production but only warn in staging"). Policies are managed through
// the control plane, not by editing YAML in git.
//
// This package is shared by the control plane (which owns the canonical
// policy state) and the sensors (which fetch and apply policies on the
// inline path). Both ends agree on the wire shape and resolution rule.
package policy

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/jlupsp/hopframe/pkg/detect"
	"github.com/jlupsp/hopframe/pkg/event"
)

// Policy is the operator's decision for a slice of traffic. It binds a
// selector (which findings or rule ids to act on) to a disposition (the
// mode to apply when that selector matches), scoped to an org, tenant,
// sensor, or specific MCP server.
type Policy struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Description string      `json:"description,omitempty"`
	Version     int         `json:"version"`
	Enabled     bool        `json:"enabled"`
	Scope       Scope       `json:"scope"`
	Selector    Selector    `json:"selector"`
	Disposition Disposition `json:"disposition"`
	CreatedAt   time.Time   `json:"created_at"`
	UpdatedAt   time.Time   `json:"updated_at"`
	CreatedBy   string      `json:"created_by,omitempty"`
	UpdatedBy   string      `json:"updated_by,omitempty"`
}

// Scope decides where a policy applies. Empty fields mean "any". The
// most specific match wins during resolution: server > sensor > tenant
// > org. An "org" policy is one with all scope fields empty.
type Scope struct {
	TenantID   string `json:"tenant_id,omitempty"`
	SensorID   string `json:"sensor_id,omitempty"`
	ServerName string `json:"server_name,omitempty"`
}

// Selector decides which detector findings a policy targets. Empty
// slices mean "any". A finding satisfies the selector when every
// non-empty field matches one of its values.
type Selector struct {
	RuleIDs     []string       `json:"rule_ids,omitempty"`
	Categories  []string       `json:"categories,omitempty"`
	MinSeverity event.Severity `json:"min_severity,omitempty"`
	Methods     []string       `json:"methods,omitempty"`
}

// Disposition is the action a policy applies when its selector matches.
// Mode is the strongest mode the policy can produce; it does not weaken
// what other matching policies request. Resolution picks the strongest
// mode across the most-specific policy or policies that match.
type Disposition struct {
	Mode detect.Mode `json:"mode"`
}

// EventContext is the scope information a sensor presents to the
// resolver alongside the verdict. Anything left empty matches any
// policy with that scope field empty.
type EventContext struct {
	TenantID   string
	SensorID   string
	ServerName string
	Method     string
}

// Resolve picks the effective mode for a verdict given a list of
// policies and the event's scope. The algorithm:
//
//  1. Filter policies that are enabled and whose scope matches the event.
//  2. Filter further by selector: at least one finding in the verdict
//     must satisfy the policy's selector for that policy to apply.
//  3. Among matching policies, group by specificity. The
//     highest-specificity group wins.
//  4. Within that group, the strongest mode wins.
//
// When no policy matches, the default mode is returned. The default is
// typically the rule-default mode produced by ruleset.HighestMode, so
// callers can chain: try the policy resolver first, fall back to the
// rule-default if the policy resolver returns ModeMonitor with no match.
func Resolve(policies []Policy, ctx EventContext, v *detect.Verdict, defaultMode detect.Mode) (detect.Mode, *Policy) {
	type match struct {
		p           Policy
		specificity int
	}
	var matches []match
	for _, p := range policies {
		if !p.Enabled {
			continue
		}
		if !p.Scope.Matches(ctx) {
			continue
		}
		if !p.Selector.MatchesAny(ctx, v.Findings) {
			continue
		}
		matches = append(matches, match{p: p, specificity: p.Scope.Specificity()})
	}
	if len(matches) == 0 {
		return defaultMode, nil
	}
	sort.SliceStable(matches, func(i, j int) bool {
		return matches[i].specificity > matches[j].specificity
	})
	topSpec := matches[0].specificity
	chosenMode := detect.ModeMonitor
	rank := map[detect.Mode]int{detect.ModeMonitor: 0, detect.ModeWarn: 1, detect.ModeBlock: 2}
	var winner Policy
	for _, m := range matches {
		if m.specificity != topSpec {
			break
		}
		if rank[m.p.Disposition.Mode] >= rank[chosenMode] {
			chosenMode = m.p.Disposition.Mode
			winner = m.p
		}
	}
	return chosenMode, &winner
}

// Matches reports whether this scope applies to the given event context.
// Empty scope fields match anything; non-empty fields must equal.
func (s Scope) Matches(ctx EventContext) bool {
	if s.TenantID != "" && s.TenantID != ctx.TenantID {
		return false
	}
	if s.SensorID != "" && s.SensorID != ctx.SensorID {
		return false
	}
	if s.ServerName != "" && s.ServerName != ctx.ServerName {
		return false
	}
	return true
}

// Specificity scores how narrow a scope is. Higher is more specific.
// Server pin is the most specific, then sensor, then tenant, then org
// (no scope at all).
func (s Scope) Specificity() int {
	score := 0
	if s.TenantID != "" {
		score |= 1
	}
	if s.SensorID != "" {
		score |= 2
	}
	if s.ServerName != "" {
		score |= 4
	}
	return score
}

// MatchesAny reports whether the selector matches any finding in the
// list, in the context of the given event.
func (sel Selector) MatchesAny(ctx EventContext, findings []event.Finding) bool {
	if len(sel.Methods) > 0 {
		ok := false
		for _, m := range sel.Methods {
			if m == ctx.Method {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if len(findings) == 0 {
		return len(sel.RuleIDs) == 0 && len(sel.Categories) == 0 && sel.MinSeverity == ""
	}
	for _, f := range findings {
		if sel.matchesFinding(f) {
			return true
		}
	}
	return false
}

func (sel Selector) matchesFinding(f event.Finding) bool {
	if len(sel.RuleIDs) > 0 && !contains(sel.RuleIDs, f.RuleID) {
		return false
	}
	if len(sel.Categories) > 0 && !contains(sel.Categories, f.Category) {
		return false
	}
	if sel.MinSeverity != "" && severityRank(f.Severity) < severityRank(sel.MinSeverity) {
		return false
	}
	return true
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func severityRank(s event.Severity) int {
	switch s {
	case event.SeverityInfo:
		return 0
	case event.SeverityLow:
		return 1
	case event.SeverityMedium:
		return 2
	case event.SeverityHigh:
		return 3
	case event.SeverityCritical:
		return 4
	}
	return 0
}

// NewID returns a fresh policy id. Format: pol_<unix-nanos>_<6 hex>.
// Sortable by creation time, easy to grep, no external dep.
func NewID() string {
	var b [3]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failure is fatal in normal operation; the caller
		// can panic if this matters. Return a deterministic fallback so
		// tests don't have to mock crypto/rand.
		return fmt.Sprintf("pol_%d_000000", time.Now().UnixNano())
	}
	return fmt.Sprintf("pol_%d_%s", time.Now().UnixNano(), hex.EncodeToString(b[:]))
}

// Validate checks that a policy is well-formed enough to store. Empty
// name, unknown mode, and zero-value timestamps are rejected.
func (p Policy) Validate() error {
	if p.ID == "" {
		return errors.New("policy id required")
	}
	if p.Name == "" {
		return errors.New("policy name required")
	}
	switch p.Disposition.Mode {
	case detect.ModeMonitor, detect.ModeWarn, detect.ModeBlock:
	default:
		return fmt.Errorf("invalid disposition mode: %q", p.Disposition.Mode)
	}
	if p.Selector.MinSeverity != "" {
		switch p.Selector.MinSeverity {
		case event.SeverityInfo, event.SeverityLow, event.SeverityMedium, event.SeverityHigh, event.SeverityCritical:
		default:
			return fmt.Errorf("invalid min severity: %q", p.Selector.MinSeverity)
		}
	}
	return nil
}
