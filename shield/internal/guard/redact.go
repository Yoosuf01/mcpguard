// Package guard holds the content-level defenses: secret/PII redaction,
// prompt-injection and hidden-unicode scanning, and discovery hardening
// (server instructions + tool definition pinning).
package guard

import (
	"regexp"
	"sort"
	"strings"
)

type detector struct {
	name  string
	re    *regexp.Regexp
	valid func(string) bool // optional post-check (e.g. Luhn)
}

// Secret-class detectors are also used to block credential exfiltration in
// tool arguments when policy says so.
var secretKinds = map[string]bool{
	"aws_access_key": true, "github_token": true, "private_key": true,
	"jwt": true, "openai_key": true, "anthropic_key": true, "slack_token": true, "generic_api_key": true,
}

var allDetectors = []detector{
	{name: "private_key", re: regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----`)},
	{name: "jwt", re: regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`)},
	{name: "aws_access_key", re: regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)},
	{name: "github_token", re: regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b`)},
	{name: "anthropic_key", re: regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_-]{20,}\b`)},
	{name: "openai_key", re: regexp.MustCompile(`\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b`)},
	{name: "slack_token", re: regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9-]{10,}\b`)},
	{name: "generic_api_key", re: regexp.MustCompile(`(?i)\b(?:api[_-]?key|secret|password|passwd|token)\s*[:=]\s*["']?[A-Za-z0-9_\-./+=]{12,}`)},
	{name: "credit_card", re: regexp.MustCompile(`\b(?:\d[ -]?){12,18}\d\b`), valid: luhn},
	{name: "ssn", re: regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)},
	{name: "email", re: regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`)},
	{name: "phone", re: regexp.MustCompile(`(?:\+\d{1,3}[ -]?)?\(?\d{3}\)?[ -]\d{3}[ -]\d{4}\b`)},
}

// Redactor masks configured data classes inside arbitrary JSON values.
type Redactor struct{ dets []detector }

// NewRedactor builds a redactor for the given kinds. Unknown kinds are ignored
// (and reported by the policy loader).
func NewRedactor(kinds []string) *Redactor {
	want := map[string]bool{}
	for _, k := range kinds {
		want[k] = true
	}
	r := &Redactor{}
	for _, d := range allDetectors {
		if want[d.name] {
			r.dets = append(r.dets, d)
		}
	}
	return r
}

func KnownKind(k string) bool {
	for _, d := range allDetectors {
		if d.name == k {
			return true
		}
	}
	return false
}

func IsSecretKind(k string) bool { return secretKinds[k] }

// RedactString returns the masked string and a count per kind.
func (r *Redactor) RedactString(s string, counts map[string]int) string {
	for _, d := range r.dets {
		s = d.re.ReplaceAllStringFunc(s, func(m string) string {
			if d.valid != nil && !d.valid(m) {
				return m
			}
			counts[d.name]++
			return "[REDACTED:" + d.name + "]"
		})
	}
	return s
}

// RedactValue walks decoded JSON (maps, slices, strings) and masks in place.
func (r *Redactor) RedactValue(v any, counts map[string]int) any {
	switch t := v.(type) {
	case string:
		return r.RedactString(t, counts)
	case map[string]any:
		for k, vv := range t {
			t[k] = r.RedactValue(vv, counts)
		}
		return t
	case []any:
		for i, vv := range t {
			t[i] = r.RedactValue(vv, counts)
		}
		return t
	default:
		return v
	}
}

// Detect reports which kinds appear in v without modifying it.
func (r *Redactor) Detect(v any) []string {
	counts := map[string]int{}
	walkStrings(v, func(s string) { _ = r.RedactString(s, counts) })
	return sortedKeys(counts)
}

func luhn(s string) bool {
	var digits []int
	for _, c := range s {
		if c >= '0' && c <= '9' {
			digits = append(digits, int(c-'0'))
		}
	}
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	sum, alt := 0, false
	for i := len(digits) - 1; i >= 0; i-- {
		d := digits[i]
		if alt {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}
	return sum%10 == 0
}

func walkStrings(v any, fn func(string)) {
	switch t := v.(type) {
	case string:
		fn(t)
	case map[string]any:
		for k, vv := range t {
			fn(k)
			walkStrings(vv, fn)
		}
	case []any:
		for _, vv := range t {
			walkStrings(vv, fn)
		}
	}
}

// CollectStrings flattens every string (keys and values) in a JSON value.
func CollectStrings(v any) []string {
	var out []string
	walkStrings(v, func(s string) { out = append(out, s) })
	return out
}

func sortedKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Summarize renders counts like "email=2,ssn=1".
func Summarize(counts map[string]int) string {
	keys := sortedKeys(counts)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+itoa(counts[k]))
	}
	return strings.Join(parts, ",")
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	n := len(b)
	for i > 0 {
		n--
		b[n] = byte('0' + i%10)
		i /= 10
	}
	return string(b[n:])
}
