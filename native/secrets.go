package main

// Sensitive data handling (§39, §173). Conservative patterns; detected values
// are NEVER exposed in reports or sent to LM Studio — only location and a
// redaction note.

import (
	"regexp"
	"strings"
)

type SecretHit struct {
	File string `json:"file"`
	Line int    `json:"line"`
	Kind string `json:"kind"` // category, never the value
	Hash string `json:"hash"` // short fingerprint for dedup only
}

var secretPatterns = []struct {
	kind    string
	pattern *regexp.Regexp
}{
	{"AWS access key ID", regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)},
	{"Google API key", regexp.MustCompile(`\bAIza[0-9A-Za-z\-_]{35}\b`)},
	{"GitHub token", regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,255}\b`)},
	{"Slack token", regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9\-]{10,}\b`)},
	{"Stripe key", regexp.MustCompile(`\b(sk|pk|rk)_(live|test)_[A-Za-z0-9]{20,}\b`)},
	{"OpenAI-style key", regexp.MustCompile(`\bsk-[A-Za-z0-9\-_]{20,}\b`)},
	{"Private key block", regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)},
	{"JWT", regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b`)},
	{"Bearer token literal", regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9\-._~+/]{20,}`)},
	{"Password-like assignment", regexp.MustCompile(`(?i)\b(pass(word)?|secret|api[_-]?key|access[_-]?token|auth[_-]?token)\b\s*[:=]\s*["'][^"'\s]{8,}["']`)},
}

// DetectSecrets scans source text conservatively. Values are hashed for
// deduplication and never returned.
func DetectSecrets(file string, src string) []SecretHit {
	var hits []SecretHit
	seen := map[string]bool{}
	for _, sp := range secretPatterns {
		for _, loc := range sp.pattern.FindAllStringIndex(src, 50) {
			line := lineOfOffset([]byte(src), loc[0])
			key := sp.kind + "@" + file + ":" + itoa(line)
			if seen[key] {
				continue
			}
			seen[key] = true
			hits = append(hits, SecretHit{
				File: file,
				Line: line,
				Kind: sp.kind,
				Hash: sha256Bytes([]byte(src[loc[0]:min(loc[1], loc[0]+64)]))[:12],
			})
		}
	}
	return hits
}

// RedactSecrets removes secret-like substrings from text before it is sent to
// LM Studio (§173). Applied to every excerpt leaving the deterministic
// scanner.
func RedactSecrets(text string) string {
	for _, sp := range secretPatterns {
		text = sp.pattern.ReplaceAllStringFunc(text, func(m string) string {
			if sp.kind == "Password-like assignment" {
				// keep "key:" part, redact value
				idx := strings.IndexAny(m, ":=")
				if idx > 0 {
					return m[:idx+1] + " [REDACTED]"
				}
			}
			return "[REDACTED]"
		})
	}
	return text
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var b [20]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		b[pos] = '-'
	}
	return string(b[pos:])
}
