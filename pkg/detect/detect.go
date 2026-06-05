// Package detect defines detection categories, verdicts, and the
// detector interface implemented by rule packs and pluggable models.
package detect

import (
	"context"

	"github.com/jlupsp/hopframe/pkg/event"
)

// Category names align with the directory layout under content/.
const (
	CategoryPromptInjection        = "prompt-injection"
	CategoryToolPoisoning          = "tool-poisoning"
	CategoryCredentialExfiltration = "credential-exfiltration"
	CategoryPIILeakage             = "pii-leakage"
	CategoryPolicy                 = "policy"
)

// Categories returns the canonical category list. Used for validation and
// UI grouping.
func Categories() []string {
	return []string{
		CategoryPromptInjection,
		CategoryToolPoisoning,
		CategoryCredentialExfiltration,
		CategoryPIILeakage,
		CategoryPolicy,
	}
}

// Mode is how a finding influences policy.
type Mode string

const (
	ModeMonitor Mode = "monitor"
	ModeWarn    Mode = "warn"
	ModeBlock   Mode = "block"
)

// Input is the unit a detector inspects: a single protocol message in
// structured form, with the side that produced it.
type Input struct {
	Protocol  event.Protocol
	Direction event.Direction
	Method    string
	// Fields enumerates inspectable string fields keyed by a stable name
	// (for example "params.arguments.query" or "result.tools[0].description").
	// Detectors choose which fields to scan.
	Fields []Field
	// Raw is the unparsed message body. Used for byte-level checks.
	Raw []byte
}

// Field is an inspectable string drawn from the protocol message.
type Field struct {
	Name  string
	Value string
}

// Verdict is the outcome of a detector on a single Input.
type Verdict struct {
	Findings []event.Finding
}

// Add appends a finding to the verdict.
func (v *Verdict) Add(f event.Finding) {
	v.Findings = append(v.Findings, f)
}

// Detector inspects an Input and contributes findings to a Verdict.
//
// Detectors must be safe for concurrent use; the pipeline calls them
// from many goroutines. Detectors should not mutate the Input.
type Detector interface {
	Name() string
	Detect(ctx context.Context, in *Input, v *Verdict) error
}

// HighestSeverity returns the maximum severity present in the findings.
// It returns event.SeverityInfo when there are no findings.
func HighestSeverity(findings []event.Finding) event.Severity {
	rank := map[event.Severity]int{
		event.SeverityInfo:     0,
		event.SeverityLow:      1,
		event.SeverityMedium:   2,
		event.SeverityHigh:     3,
		event.SeverityCritical: 4,
	}
	highest := event.SeverityInfo
	for _, f := range findings {
		if rank[f.Severity] > rank[highest] {
			highest = f.Severity
		}
	}
	return highest
}
