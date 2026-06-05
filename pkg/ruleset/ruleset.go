// Package ruleset implements the Layer 1 (heuristics) detector for
// Hopframe: a set of regex-based rules loaded from YAML, evaluated
// against fields extracted from a protocol message.
//
// A Ruleset is a Detector and is the workhorse of Phase 1 detection.
// Layer 2 (small classifier) and Layer 3 (LLM judge) are pluggable
// detectors composed alongside it by the pipeline.
package ruleset

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/jlupsp/hopframe/pkg/detect"
	"github.com/jlupsp/hopframe/pkg/event"
)

// Rule is a single regex-based detection rule.
type Rule struct {
	ID          string         `yaml:"id"`
	Category    string         `yaml:"category"`
	Severity    event.Severity `yaml:"severity"`
	Description string         `yaml:"description"`
	Mode        detect.Mode    `yaml:"mode"`

	// Targets restricts the rule to messages with these methods. Empty
	// means any method.
	Targets []string `yaml:"targets,omitempty"`
	// Directions restricts the rule to inbound or outbound messages.
	// Empty means both.
	Directions []event.Direction `yaml:"directions,omitempty"`
	// FieldGlobs is a list of shell-style globs over field names. Empty
	// means scan every field.
	FieldGlobs []string `yaml:"fields,omitempty"`

	// Patterns is the list of regex patterns; ANY match is a finding.
	Patterns []string `yaml:"patterns"`

	// CaseSensitive defaults to false (we use (?i) by default).
	CaseSensitive bool `yaml:"case_sensitive,omitempty"`

	// Confidence is the calibrated confidence we attach to a finding.
	// Range [0, 1]. Defaults to 0.9 when zero. Lower for fuzzy patterns;
	// higher for exact-format matches like cryptographic key formats.
	Confidence float64 `yaml:"confidence,omitempty"`

	compiled    []*regexp.Regexp
	contentHash string // sha256 of canonical fields, set at compile
}

// ContentHash returns the SHA-256 fingerprint of this rule's
// authoritative fields (id, severity, mode, patterns, etc.) computed at
// compile time. Findings cite this hash in their metadata so a verifier
// can re-run the rule on the same input and confirm the same finding.
func (r *Rule) ContentHash() string { return r.contentHash }

// Pack is a YAML-loaded collection of rules under one category.
type Pack struct {
	Category string `yaml:"category"`
	Rules    []Rule `yaml:"rules"`
}

// Ruleset is a compiled, queryable bundle of rules.
type Ruleset struct {
	rules []Rule
}

// Name implements detect.Detector.
func (r *Ruleset) Name() string { return "heuristics" }

// Rules returns the compiled rules. Useful for diagnostics.
func (r *Ruleset) Rules() []Rule { return r.rules }

// Len returns the rule count.
func (r *Ruleset) Len() int { return len(r.rules) }

// AppendRule adds an already-compiled Rule to the Ruleset. Used to
// merge multiple LoadDir results or filter by disabled-id.
func (r *Ruleset) AppendRule(rule Rule) { r.rules = append(r.rules, rule) }

// LoadDir loads every *.yaml and *.yml file under root recursively into a
// single Ruleset. The on-disk layout is content/<category>/<pack>.yaml.
func LoadDir(root string) (*Ruleset, error) {
	var rs Ruleset
	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}
		body, readErr := os.ReadFile(path)
		if readErr != nil {
			return fmt.Errorf("ruleset: read %s: %w", path, readErr)
		}
		pack, parseErr := parsePack(body)
		if parseErr != nil {
			return fmt.Errorf("ruleset: parse %s: %w", path, parseErr)
		}
		for _, rule := range pack.Rules {
			if rule.Category == "" {
				rule.Category = pack.Category
			}
			if err := rule.compile(); err != nil {
				return fmt.Errorf("ruleset: compile %s/%s: %w", path, rule.ID, err)
			}
			rs.rules = append(rs.rules, rule)
		}
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}
	return &rs, nil
}

// LoadBytes parses one or more YAML pack documents from a byte slice.
// Multi-document YAML is supported.
func LoadBytes(body []byte) (*Ruleset, error) {
	var rs Ruleset
	dec := yaml.NewDecoder(strings.NewReader(string(body)))
	for {
		var pack Pack
		if err := dec.Decode(&pack); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}
		for _, rule := range pack.Rules {
			if rule.Category == "" {
				rule.Category = pack.Category
			}
			if err := rule.compile(); err != nil {
				return nil, fmt.Errorf("ruleset: compile %s: %w", rule.ID, err)
			}
			rs.rules = append(rs.rules, rule)
		}
	}
	return &rs, nil
}

func parsePack(body []byte) (Pack, error) {
	var p Pack
	if err := yaml.Unmarshal(body, &p); err != nil {
		return p, err
	}
	return p, nil
}

func (r *Rule) compile() error {
	if r.ID == "" {
		return errors.New("rule missing id")
	}
	if len(r.Patterns) == 0 {
		return errors.New("rule has no patterns")
	}
	if r.Severity == "" {
		r.Severity = event.SeverityMedium
	}
	if r.Mode == "" {
		r.Mode = detect.ModeMonitor
	}
	prefix := "(?i)"
	if r.CaseSensitive {
		prefix = ""
	}
	r.compiled = make([]*regexp.Regexp, 0, len(r.Patterns))
	for i, p := range r.Patterns {
		re, err := regexp.Compile(prefix + p)
		if err != nil {
			return fmt.Errorf("pattern[%d] %q: %w", i, p, err)
		}
		r.compiled = append(r.compiled, re)
	}
	r.contentHash = computeRuleHash(r)
	return nil
}

// computeRuleHash returns the SHA-256 of the rule's authoritative
// fields in canonical form. The hash is stable across runs and across
// Go versions: it depends only on the rule's declared content. Pattern
// order and target/direction order are preserved as-declared, since
// match precedence depends on order.
func computeRuleHash(r *Rule) string {
	h := sha256.New()
	fmt.Fprintln(h, "id:", r.ID)
	fmt.Fprintln(h, "category:", r.Category)
	fmt.Fprintln(h, "severity:", r.Severity)
	fmt.Fprintln(h, "mode:", r.Mode)
	fmt.Fprintln(h, "case_sensitive:", r.CaseSensitive)
	fmt.Fprintln(h, "confidence:", r.Confidence)
	for _, t := range r.Targets {
		fmt.Fprintln(h, "target:", t)
	}
	for _, d := range r.Directions {
		fmt.Fprintln(h, "direction:", d)
	}
	for _, fg := range r.FieldGlobs {
		fmt.Fprintln(h, "field:", fg)
	}
	for _, p := range r.Patterns {
		fmt.Fprintln(h, "pattern:", p)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Detect implements detect.Detector by evaluating every rule against
// every selected field and producing findings.
//
// Each field is normalized (NFKC + invisible-rune strip) before regex
// matching, so attacks using zero-width characters or homoglyphs
// cannot trivially bypass detection. Embedded base64 payloads are
// also decoded and re-scanned, catching attacks that wrap content
// in base64 to slip past plain regex.
func (r *Ruleset) Detect(_ context.Context, in *detect.Input, v *detect.Verdict) error {
	for _, rule := range r.rules {
		if !rule.applicable(in) {
			continue
		}
		for _, f := range in.Fields {
			if !rule.matchesField(f.Name) {
				continue
			}
			r.evalRuleAgainstField(&rule, f.Name, f.Value, "", v)
			// Recurse into base64-decoded payloads. Bounded; see
			// detect.ExtractBase64Candidates for the heuristics.
			for _, decoded := range detect.ExtractBase64Candidates(f.Value) {
				r.evalRuleAgainstField(&rule, f.Name, decoded, "base64", v)
			}
		}
	}
	return nil
}

// evalRuleAgainstField runs one rule's patterns against one value
// (after normalization) and adds a finding on first match. encoding
// is "" for plaintext or "base64" when the value came from decoding.
func (r *Ruleset) evalRuleAgainstField(rule *Rule, fieldName, value, encoding string, v *detect.Verdict) {
	normalized := detect.NormalizeForDetection(value)
	confidence := rule.Confidence
	if confidence == 0 {
		confidence = 0.9
	}
	for _, re := range rule.compiled {
		if loc := re.FindStringIndex(normalized); loc != nil {
			match := normalized[loc[0]:loc[1]]
			meta := map[string]any{
				"mode":              string(rule.Mode),
				"rule_content_hash": rule.contentHash,
			}
			if encoding != "" {
				meta["encoding"] = encoding
				meta["note"] = "match found after " + encoding + " decode"
			}
			if normalized != value {
				meta["normalized"] = true
			}
			v.Add(event.Finding{
				RuleID:      rule.ID,
				Category:    rule.Category,
				Severity:    rule.Severity,
				Description: rule.Description,
				Match:       truncate(match, 200),
				Field:       fieldName,
				Confidence:  confidence,
				Metadata:    meta,
			})
			return // one finding per rule per field
		}
	}
}

func (r *Rule) applicable(in *detect.Input) bool {
	if len(r.Targets) > 0 {
		hit := false
		for _, t := range r.Targets {
			if t == in.Method {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}
	if len(r.Directions) > 0 {
		hit := false
		for _, d := range r.Directions {
			if d == in.Direction {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}
	return true
}

func (r *Rule) matchesField(name string) bool {
	if len(r.FieldGlobs) == 0 {
		return true
	}
	for _, glob := range r.FieldGlobs {
		if globMatch(glob, name) {
			return true
		}
	}
	return false
}

// globMatch is a small wildcard matcher supporting "*" segments.
// It is path-style: "params.*.text" matches "params.foo.text" but not
// "params.foo.bar.text". Use "**" to match across segments.
func globMatch(pattern, name string) bool {
	if pattern == "**" {
		return true
	}
	if !strings.Contains(pattern, "*") {
		return pattern == name
	}
	// Treat ** as cross-segment, * as within-segment.
	pp := splitGlob(pattern)
	np := strings.Split(name, ".")
	return matchSegments(pp, np)
}

type globSegment struct {
	literal string
	star    bool
	dstar   bool
}

func splitGlob(pattern string) []globSegment {
	parts := strings.Split(pattern, ".")
	out := make([]globSegment, 0, len(parts))
	for _, p := range parts {
		switch p {
		case "*":
			out = append(out, globSegment{star: true})
		case "**":
			out = append(out, globSegment{dstar: true})
		default:
			out = append(out, globSegment{literal: p})
		}
	}
	return out
}

func matchSegments(pp []globSegment, np []string) bool {
	switch {
	case len(pp) == 0:
		return len(np) == 0
	case pp[0].dstar:
		// Match zero or more name segments.
		for i := 0; i <= len(np); i++ {
			if matchSegments(pp[1:], np[i:]) {
				return true
			}
		}
		return false
	case len(np) == 0:
		return false
	case pp[0].star:
		return matchSegments(pp[1:], np[1:])
	case pp[0].literal == np[0]:
		return matchSegments(pp[1:], np[1:])
	default:
		return false
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// HighestMode returns the strongest mode among the rules that produced
// findings in v. Used by the pipeline to decide allow/warn/block.
func (r *Ruleset) HighestMode(v *detect.Verdict) detect.Mode {
	idx := make(map[string]detect.Mode, len(r.rules))
	for _, rule := range r.rules {
		idx[rule.ID] = rule.Mode
	}
	highest := detect.ModeMonitor
	rank := map[detect.Mode]int{detect.ModeMonitor: 0, detect.ModeWarn: 1, detect.ModeBlock: 2}
	for _, f := range v.Findings {
		if m, ok := idx[f.RuleID]; ok && rank[m] > rank[highest] {
			highest = m
		}
	}
	return highest
}
