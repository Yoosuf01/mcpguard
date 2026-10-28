package guard

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

// Finding is one suspicious signal in a piece of text.
type Finding struct {
	Kind   string // "injection_marker" | "hidden_unicode"
	Detail string
}

// Heuristic markers of instruction-like text inside data that should be inert
// (tool outputs, tool descriptions, server instructions). These are a cheap
// first line; the Python plugin SDK can add a classifier model later.
var injectionMarkers = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bignore\s+(?:all\s+)?(?:the\s+)?(?:previous|prior|above|earlier|safety)\s+(?:instructions|rules|prompts?)`),
	regexp.MustCompile(`(?i)\bdisregard\s+(?:all\s+)?(?:previous|prior|your|the)\s+\w*\s*(?:instructions|rules|guidelines)`),
	regexp.MustCompile(`(?i)\b(?:important|urgent|critical)\s+(?:override|system\s+notice|instruction)`),
	regexp.MustCompile(`(?i)\byou\s+are\s+now\s+(?:a|an|in)\b`),
	regexp.MustCompile(`(?i)\b(?:new|updated|real)\s+system\s+prompt\b`),
	regexp.MustCompile(`(?i)<\s*/?\s*(?:system|im_start|im_end|assistant)\s*>|<\|im_(?:start|end)\|>`),
	regexp.MustCompile(`(?i)\bdo\s+not\s+(?:tell|inform|mention\s+(?:this\s+)?to)\s+the\s+user\b`),
	regexp.MustCompile(`(?i)\b(?:call|invoke|use|run)\s+the\s+[\w.\-]+\s+tool\b.*\b(?:immediately|silently|without\s+(?:asking|confirmation))`),
	regexp.MustCompile(`(?i)\b(?:send|post|upload|exfiltrate|forward)\b[^.\n]{0,80}\b(?:to|at)\s+https?://`),
	regexp.MustCompile(`(?i)\b(?:export|print|reveal|leak)\s+(?:the\s+)?(?:connection\s+string|api\s+keys?|credentials|secrets?|env(?:ironment)?\s+variables)`),
}

// ScanInjection returns heuristic prompt-injection markers in s.
func ScanInjection(s string) []Finding {
	var out []Finding
	for _, re := range injectionMarkers {
		if m := re.FindString(s); m != "" {
			out = append(out, Finding{Kind: "injection_marker", Detail: truncate(m, 80)})
		}
	}
	return out
}

// ScanHiddenUnicode detects invisible / direction-override / tag characters
// commonly used to hide instructions from human reviewers.
func ScanHiddenUnicode(s string) []Finding {
	var out []Finding
	seen := map[string]bool{}
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		i += size
		var kind string
		switch {
		case r >= 0xE0000 && r <= 0xE007F:
			kind = "unicode_tag_chars"
		case r >= 0x200B && r <= 0x200F, r >= 0x2060 && r <= 0x2064, r == 0xFEFF:
			kind = "zero_width_chars"
		case r >= 0x202A && r <= 0x202E, r >= 0x2066 && r <= 0x2069:
			kind = "bidi_override_chars"
		}
		if kind != "" && !seen[kind] {
			seen[kind] = true
			out = append(out, Finding{Kind: "hidden_unicode", Detail: kind})
		}
	}
	return out
}

// ScanAll runs every text scanner.
func ScanAll(s string) []Finding {
	return append(ScanInjection(s), ScanHiddenUnicode(s)...)
}

func FindingStrings(fs []Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.Kind+":"+f.Detail)
	}
	return out
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
