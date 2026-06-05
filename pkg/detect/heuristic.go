package detect

import (
	"context"
	"strings"
	"unicode"

	"github.com/jlupsp/hopframe/pkg/event"
)

// HeuristicClassifier is Layer 2 of the detection pipeline: a small,
// dependency-free, feature-density scorer for prompt-injection-shaped
// content. It is deliberately not an ML model, but unlike the
// regex pack, it generalizes across paraphrase by counting *features*
// rather than matching specific phrases.
//
// Features (each contributes to a [0,1] score, summed and normalized):
//
//   - role markers: <system>, [system], "as the assistant", etc.
//   - override imperatives: "ignore", "disregard", "forget", "override"
//   - new-role declarations: "you are now …", "from now on you are …"
//   - exfiltration imperatives: "send … to https://", "post … to"
//   - imperative-verb density: high ratio of imperative verbs
//
// When the aggregate exceeds a threshold, a single finding is added
// to the verdict. The classifier is cheap (~5µs/string in benchmarks)
// and runs alongside the ruleset detector in the pipeline.
type HeuristicClassifier struct {
	// Threshold is the score (0..1) above which a finding is emitted.
	// Default 0.45.
	Threshold float64
	// MinLength skips strings shorter than this. Default 24.
	MinLength int
	// Mode controls the policy mode embedded on emitted findings.
	// Default "warn".
	Mode Mode
}

// Name implements Detector.
func (h *HeuristicClassifier) Name() string { return "heuristic-classifier" }

// Detect scans every field on the input and contributes findings.
func (h *HeuristicClassifier) Detect(_ context.Context, in *Input, v *Verdict) error {
	threshold := h.Threshold
	if threshold <= 0 {
		threshold = 0.45
	}
	minLen := h.MinLength
	if minLen <= 0 {
		minLen = 24
	}
	mode := h.Mode
	if mode == "" {
		mode = ModeWarn
	}

	for _, f := range in.Fields {
		if len(f.Value) < minLen {
			continue
		}
		score, contributors := scoreField(f.Value)
		if score < threshold {
			continue
		}
		v.Add(event.Finding{
			RuleID:      "heuristic.injection_density",
			Category:    CategoryPromptInjection,
			Severity:    severityFromScore(score),
			Description: "feature-density classifier flagged injection-shaped content",
			Match:       truncate(f.Value, 160),
			Field:       f.Name,
			Confidence:  score,
			Metadata: map[string]any{
				"score":        score,
				"contributors": contributors,
				"mode":         string(mode),
			},
		})
	}
	return nil
}

// scoreField computes the aggregate score and returns a list of
// feature names that contributed materially (score >= 0.15 each).
func scoreField(value string) (float64, []string) {
	lower := strings.ToLower(value)
	tokens := tokenize(lower)
	tokenCount := len(tokens)
	if tokenCount == 0 {
		return 0, nil
	}

	scores := map[string]float64{
		"role_marker":           scoreRoleMarker(value, lower),
		"override_imperative":   scoreOverrideImperative(lower, tokens, tokenCount),
		"new_role":              scoreNewRole(lower),
		"exfil_imperative":      scoreExfilImperative(lower),
		"extraction_imperative": scoreExtractionImperative(lower, tokens),
		"imperative_density":    scoreImperativeDensity(tokens, tokenCount),
		"length_anomaly":        scoreLengthAnomaly(value),
	}

	// Aggregate via noisy-OR: P(malicious) = 1 - prod(1 - score_i).
	// Behaves well under sparse signals: a single strong feature is
	// enough to fire, multiple weak features accumulate.
	prod := 1.0
	for _, s := range scores {
		prod *= 1 - s
	}
	final := 1 - prod
	if final > 1 {
		final = 1
	}

	contribs := make([]string, 0, len(scores))
	for k, s := range scores {
		if s >= 0.15 {
			contribs = append(contribs, k)
		}
	}
	return final, contribs
}

func scoreRoleMarker(raw, lower string) float64 {
	score := 0.0
	markers := []string{
		"<system>", "<admin>", "<developer>", "<root>",
		"<assistant>", "<user>", "<tool>",
		"[system]", "[admin]", "[developer]",
		"[[system]]", "[[admin]]", "[[assistant]]",
	}
	for _, m := range markers {
		if strings.Contains(lower, m) {
			score = 0.95
			break
		}
	}
	if score == 0 {
		// Light heuristic: phrases like "as the assistant" / "as system" /
		// "I am the assistant" near the start of a string.
		probes := []string{"as the assistant", "as the system", "i am the assistant", "i am the system"}
		for _, p := range probes {
			if strings.Contains(lower, p) {
				score = 0.55
				break
			}
		}
	}
	// Bonus when a role marker appears alongside a control verb.
	if score > 0 {
		for _, c := range []string{"ignore", "override", "now", "must", "always", "never"} {
			if strings.Contains(lower, c) {
				score = clamp01(score + 0.05)
				break
			}
		}
	}
	_ = raw
	return score
}

func scoreOverrideImperative(lower string, tokens []string, n int) float64 {
	hits := 0
	overrides := []string{"ignore", "disregard", "forget", "override", "bypass", "circumvent"}
	contextNouns := []string{
		"previous", "prior", "above", "earlier", "preceding", "old",
		"instructions", "instruction", "rules", "rule", "directives",
		"prompts", "prompt", "messages", "message", "everything",
		"whatever", "anything", "context",
		// Safety / guardrails framing, present in many bypass attempts.
		"safety", "guardrails", "guardrail", "filters", "filter",
		"restrictions", "restriction", "policies", "policy",
	}
	for _, ov := range overrides {
		for _, cn := range contextNouns {
			if hasNearby(tokens, ov, cn, 8) {
				hits++
				break // count each override verb once
			}
		}
	}
	if hits == 0 {
		return 0
	}
	score := float64(hits) * 0.35
	// Density bonus: the same verbs concentrated in a short string.
	if n < 30 && hits >= 1 {
		score += 0.2
	}
	if strings.Contains(lower, "system prompt") || strings.Contains(lower, "initial prompt") || strings.Contains(lower, "hidden prompt") {
		score += 0.25
	}
	return clamp01(score)
}

func scoreNewRole(lower string) float64 {
	probes := []string{
		"you are now ", "you are no longer ", "from now on you ", "starting now you ",
		"act as ", "behave like ", "pretend to be ", "role: ", "switch role to ",
		// Role-play declaration framing, common in jailbreak prompts.
		"role-play exercise", "role-play as", "roleplay as", "roleplay exercise",
		"role play exercise", "role play as",
		// "you are an/a" + restriction-removal qualifier.
		"you are an unbounded ", "you are an unrestricted ",
		"you are a different ", "you are a new ",
	}
	for _, p := range probes {
		if strings.Contains(lower, p) {
			return 0.7
		}
	}
	// Authority-laundering: "no longer apply" + "starting now" or
	// "authorised by your developer/admin" declare the prior policy
	// void without naming an explicit override verb.
	if (strings.Contains(lower, "no longer apply") || strings.Contains(lower, "no longer applies")) &&
		(strings.Contains(lower, "starting now") || strings.Contains(lower, "from now on") || strings.Contains(lower, "going forward")) {
		return 0.75
	}
	if strings.Contains(lower, "authorised by your") || strings.Contains(lower, "authorized by your") {
		if strings.Contains(lower, "developer") || strings.Contains(lower, "admin") || strings.Contains(lower, "system") {
			return 0.7
		}
	}
	return 0
}

func scoreExfilImperative(lower string) float64 {
	probes := []string{
		"send the ", "send all ", "post the ", "post all ",
		"upload the ", "upload all ", "share the ", "exfiltrate ",
		"leak the ", "leak all ", "transmit the ", "fetch https://",
	}
	hits := 0
	for _, p := range probes {
		if strings.Contains(lower, p) {
			hits++
		}
	}
	if hits == 0 {
		return 0
	}
	hasURL := strings.Contains(lower, "http://") || strings.Contains(lower, "https://")
	hasSensitiveNoun := strings.Contains(lower, "context") ||
		strings.Contains(lower, "messages") ||
		strings.Contains(lower, "history") ||
		strings.Contains(lower, "secret") ||
		strings.Contains(lower, "conversation") ||
		strings.Contains(lower, "credentials") ||
		strings.Contains(lower, "token")
	// Generic "send the X" alone is benign English. Require the verb
	// alongside a destination URL OR a sensitive object noun.
	if !hasURL && !hasSensitiveNoun {
		return 0
	}
	score := 0.45 * float64(hits)
	if hasURL {
		score += 0.25
	}
	if hasSensitiveNoun {
		score += 0.20
	}
	return clamp01(score)
}

// scoreExtractionImperative scores attempts to make the model output
// its own configuration (system prompt, initial instructions, hidden
// rules). Pattern: extraction verb near a "system/initial/hidden +
// prompt/message/instructions" pair.
func scoreExtractionImperative(lower string, tokens []string) float64 {
	verbs := []string{"reveal", "print", "show", "output", "return", "repeat", "leak", "expose", "dump", "disclose"}
	verbHit := false
	for _, v := range verbs {
		for _, t := range tokens {
			if t == v {
				verbHit = true
				break
			}
		}
		if verbHit {
			break
		}
	}
	if !verbHit {
		return 0
	}
	qualifiers := []string{"system", "initial", "hidden", "original", "secret", "internal"}
	objects := []string{
		"prompt", "message", "instructions", "rules", "rule",
		"directive", "directives", "configuration", "config",
		"told", "said", "given", "configured",
	}
	hasQual, hasObj := false, false
	for _, q := range qualifiers {
		if strings.Contains(lower, q) {
			hasQual = true
			break
		}
	}
	for _, o := range objects {
		if strings.Contains(lower, o) {
			hasObj = true
			break
		}
	}
	// Strong path: explicit qualifier + named object.
	if hasQual && hasObj {
		if strings.Contains(lower, "verbatim") || strings.Contains(lower, "exact") || strings.Contains(lower, "in full") {
			return 0.85
		}
		return 0.65
	}
	// Softer path: extraction verb + "everything|anything" near a
	// "told|said|given|configured" object catches phrasings like
	// "reveal everything you were told before this message arrived"
	// that lack an explicit system/initial qualifier.
	for _, anything := range []string{"everything you were", "anything you were", "what you were"} {
		if strings.Contains(lower, anything) {
			return 0.6
		}
	}
	return 0
}

// scoreImperativeDensity counts strong control verbs over total tokens.
// Requires at least two distinct imperatives, a single benign use of
// "ignore" or "send" should not fire on its own. Real attacks tend
// to chain multiple control verbs.
func scoreImperativeDensity(tokens []string, n int) float64 {
	if n < 8 {
		return 0
	}
	imperatives := map[string]struct{}{
		"ignore": {}, "disregard": {}, "forget": {},
		"override": {}, "bypass": {}, "circumvent": {},
		"reveal": {}, "show": {}, "print": {}, "output": {}, "return": {}, "repeat": {},
		"send": {}, "post": {}, "upload": {}, "exfiltrate": {}, "leak": {}, "transmit": {},
		"act": {}, "pretend": {}, "behave": {}, "roleplay": {},
	}
	seen := make(map[string]struct{})
	hits := 0
	for _, tok := range tokens {
		if _, ok := imperatives[tok]; ok {
			hits++
			seen[tok] = struct{}{}
		}
	}
	if len(seen) < 2 {
		return 0
	}
	density := float64(hits) / float64(n)
	switch {
	case density >= 0.10:
		return 0.8
	case density >= 0.06:
		return 0.6
	case density >= 0.03:
		return 0.4
	case density >= 0.015:
		return 0.2
	default:
		return 0.05
	}
}

// scoreLengthAnomaly flags very long fields (often used to bury an
// instruction inside an otherwise normal payload). Mild signal only.
func scoreLengthAnomaly(value string) float64 {
	switch {
	case len(value) > 4000:
		return 0.4
	case len(value) > 1500:
		return 0.2
	}
	return 0
}

// hasNearby reports whether tokens a and b appear within `window`
// positions of each other in the slice.
func hasNearby(tokens []string, a, b string, window int) bool {
	idx := make([]int, 0, 4)
	for i, t := range tokens {
		if t == a {
			idx = append(idx, i)
		}
	}
	if len(idx) == 0 {
		return false
	}
	for i, t := range tokens {
		if t != b {
			continue
		}
		for _, j := range idx {
			d := i - j
			if d < 0 {
				d = -d
			}
			if d <= window {
				return true
			}
		}
	}
	return false
}

func tokenize(s string) []string {
	out := make([]string, 0, 32)
	var b strings.Builder
	flush := func() {
		if b.Len() > 0 {
			out = append(out, b.String())
			b.Reset()
		}
	}
	for _, r := range s {
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			b.WriteRune(r)
		default:
			flush()
		}
	}
	flush()
	return out
}

func severityFromScore(score float64) event.Severity {
	switch {
	case score >= 0.85:
		return event.SeverityCritical
	case score >= 0.65:
		return event.SeverityHigh
	case score >= 0.5:
		return event.SeverityMedium
	}
	return event.SeverityLow
}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
