package detect

import (
	"encoding/base64"
	"strings"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

// NormalizeForDetection prepares a field value for regex evaluation.
// Many attacks use Unicode tricks (zero-width characters, homoglyphs,
// fullwidth lookalikes, RTL/LTR markers) to slip past regex. We
// produce a normalized string in a consistent form so detection
// catches the underlying intent regardless of cosmetic obfuscation.
//
// Steps applied, in order:
//
//  1. NFKC compatibility decomposition + canonical composition.
//     Collapses fullwidth/halfwidth variants, ligatures, mathematical
//     alphanumerics, etc. to their plain-ASCII equivalents.
//  2. Strip zero-width and bidirectional control characters.
//  3. Strip Unicode tag block (U+E0000–U+E007F), used by some
//     prompt-injection smuggling techniques to encode hidden text.
//
// We intentionally do NOT lowercase here, the case_sensitive flag
// on rules controls that. Normalization runs even on case_sensitive
// rules because the goal is structural sameness, not casing.
func NormalizeForDetection(s string) string {
	if s == "" {
		return s
	}
	// NFKC normalization.
	out := norm.NFKC.String(s)
	// Strip invisible / smuggling code points.
	out = stripInvisible(out)
	return out
}

func stripInvisible(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if isInvisibleSmugglingRune(r) {
			continue
		}
		// Strip any other format/control rune that has no visible
		// representation. This is conservative: we keep newline,
		// tab, and other whitespace, they're meaningful in our
		// tokenization downstream.
		if unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Cs, r) {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func isInvisibleSmugglingRune(r rune) bool {
	switch {
	// Zero-width characters
	case r == 0x200B, r == 0x200C, r == 0x200D, r == 0xFEFF:
		return true
	// Bidirectional / directional formatting marks
	case r >= 0x200E && r <= 0x200F:
		return true
	case r >= 0x202A && r <= 0x202E:
		return true
	case r >= 0x2066 && r <= 0x2069:
		return true
	// Tag block, used to smuggle hidden instructions
	case r >= 0xE0000 && r <= 0xE007F:
		return true
	// Variation selectors (often used to bypass naive matching)
	case r >= 0xFE00 && r <= 0xFE0F:
		return true
	case r >= 0xE0100 && r <= 0xE01EF:
		return true
	}
	return false
}

// ExtractBase64Candidates scans s for substrings that look like
// base64-encoded payloads, attempts to decode each, and returns
// the decoded strings (UTF-8 only, length-bounded).
//
// Used by the base64-recursion pass in the rule engine: many
// exfiltration attempts encode payloads in base64, then ask the
// model to call a tool with the encoded value. Running rules
// against the decoded plaintext catches attacks the encoded form
// would slip past.
//
// This is deliberately conservative: short strings are skipped to
// avoid false positives on UUIDs or hashes; the candidate must
// look base64-shaped (length divisible by 4 with optional padding).
func ExtractBase64Candidates(s string) []string {
	const minLen = 24
	const maxLen = 16 * 1024
	out := make([]string, 0)
	// Walk runs of base64-alphabet characters.
	start := -1
	for i, r := range s {
		if isBase64Rune(r) {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 {
			candidate := s[start:i]
			if decoded, ok := tryDecodeBase64(candidate, minLen, maxLen); ok {
				out = append(out, decoded)
			}
			start = -1
		}
	}
	if start >= 0 {
		candidate := s[start:]
		if decoded, ok := tryDecodeBase64(candidate, minLen, maxLen); ok {
			out = append(out, decoded)
		}
	}
	return out
}

func isBase64Rune(r rune) bool {
	switch {
	case r >= 'A' && r <= 'Z':
		return true
	case r >= 'a' && r <= 'z':
		return true
	case r >= '0' && r <= '9':
		return true
	case r == '+', r == '/', r == '-', r == '_', r == '=':
		return true
	}
	return false
}

func tryDecodeBase64(candidate string, minLen, maxLen int) (string, bool) {
	if len(candidate) < minLen || len(candidate) > maxLen {
		return "", false
	}
	// Strip trailing equals signs for the URL-safe variant.
	for _, dec := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	} {
		if b, err := dec.DecodeString(candidate); err == nil {
			s := string(b)
			if isMostlyPrintable(s) {
				return s, true
			}
		}
	}
	return "", false
}

func isMostlyPrintable(s string) bool {
	if len(s) == 0 {
		return false
	}
	printable := 0
	for _, r := range s {
		if unicode.IsPrint(r) || r == '\n' || r == '\t' || r == '\r' {
			printable++
		}
	}
	// Require >=80% printable to consider it text.
	return printable*5 >= len(s)*4
}
