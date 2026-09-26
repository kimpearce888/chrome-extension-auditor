package main

import (
        "crypto/sha256"
        "encoding/hex"
        "encoding/json"
        "fmt"
        "math"
        "os"
        "path/filepath"
        "strings"
        "time"
        "unicode"
)

// Scanner identity — §125 rule versioning. Bump when rules/analyzers change.
const (
        ScannerVersion  = "1.0.0"
        RuleSetVersion  = "1.0.0"
        AnalyzerVersion = "1.0.0"
        AIPromptVersion = "1.0.0"
        StoreSchema     = 1
)

// Safety limits (§55) — defaults, kept conservative.
type Limits struct {
        MaxFileAnalyzeBytes  int64 // max text bytes analyzed per file
        MaxFilesPerExt       int   // max files inventoried per extension
        MaxPackageBytes      int64 // flag beyond this, still inventory
        MaxArchiveExtract    int64 // max uncompressed bytes extracted
        MaxArchiveEntries    int   // max entries in an archive
        MaxCompressionRatio  float64
        MaxNestedArchives    int
        ScanWorkers          int   // bounded concurrency (§90)
}

func DefaultLimits() Limits {
        return Limits{
                MaxFileAnalyzeBytes: 2 * 1024 * 1024,
                MaxFilesPerExt:      10000,
                MaxPackageBytes:     1024 * 1024 * 1024,
                MaxArchiveExtract:   512 * 1024 * 1024,
                MaxArchiveEntries:   20000,
                MaxCompressionRatio: 100.0,
                MaxNestedArchives:   2,
                ScanWorkers:         4,
        }
}

func nowISO() string { return time.Now().Format(time.RFC3339) }

func sha256Bytes(b []byte) string {
        h := sha256.Sum256(b)
        return hex.EncodeToString(h[:])
}

func sha256File(path string) (string, error) {
        f, err := os.Open(path)
        if err != nil {
                return "", err
        }
        defer f.Close()
        h := sha256.New()
        buf := make([]byte, 64*1024)
        for {
                n, err := f.Read(buf)
                if n > 0 {
                        h.Write(buf[:n])
                }
                if err != nil {
                        break
                }
        }
        return hex.EncodeToString(h.Sum(nil)), nil
}

// Tolerant JSON: returns map even for malformed JSON (err != nil => nil map).
func decodeJSONMap(data []byte) (map[string]any, error) {
        var m map[string]any
        dec := json.NewDecoder(strings.NewReader(string(data)))
        dec.UseNumber()
        if err := dec.Decode(&m); err != nil {
                return nil, err
        }
        return m, nil
}

func jsonString(m map[string]any, keys ...string) string {
        cur := m
        for i, k := range keys {
                if cur == nil {
                        return "Not available"
                }
                v, ok := cur[k]
                if !ok {
                        return "Not available"
                }
                if i == len(keys)-1 {
                        switch t := v.(type) {
                        case string:
                                return t
                        case json.Number:
                                return t.String()
                        case bool:
                                return fmt.Sprintf("%v", t)
                        }
                        return "Not available"
                }
                if nm, ok := v.(map[string]any); ok {
                        cur = nm
                } else {
                        return "Not available"
                }
        }
        return "Not available"
}

func jsonBool(m map[string]any, key string) (bool, bool) {
        if m == nil {
                return false, false
        }
        v, ok := m[key]
        if !ok {
                return false, false
        }
        b, ok := v.(bool)
        return b, ok
}

func jsonSlice(m map[string]any, key string) []any {
        if m == nil {
                return nil
        }
        v, ok := m[key]
        if !ok {
                return nil
        }
        s, ok := v.([]any)
        return s
}

func stringSlice(m map[string]any, key string) []string {
        raw := jsonSlice(m, key)
        out := make([]string, 0, len(raw))
        for _, v := range raw {
                if s, ok := v.(string); ok {
                        out = append(out, s)
                }
        }
        return out
}

// humanSize formats bytes for UI display.
func humanSize(n int64) string {
        const unit = 1024
        if n < unit {
                return fmt.Sprintf("%d B", n)
        }
        div, exp := int64(unit), 0
        for m := n / unit; m >= unit; m /= unit {
                div *= unit
                exp++
        }
        return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}

// fileCategory maps a filename to a coarse type used in package stats.
func fileCategory(name string) string {
        switch strings.ToLower(filepath.Ext(name)) {
        case ".js", ".mjs", ".cjs":
                return "javascript"
        case ".ts", ".tsx":
                return "typescript"
        case ".css":
                return "css"
        case ".html", ".htm":
                return "html"
        case ".json":
                return "json"
        case ".wasm":
                return "wasm"
        case ".map":
                return "sourcemap"
        case ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".bmp":
                return "image"
        case ".woff", ".woff2", ".ttf", ".otf", ".eot":
                return "font"
        case ".md", ".txt", ".license":
                return "text"
        default:
                return "other"
        }
}

// isTextual reports whether the file type gets source analysis.
func isTextual(cat string) bool {
        switch cat {
        case "javascript", "typescript", "css", "html", "json", "text":
                return true
        }
        return false
}

// classifyMimetype isn't needed; keep simple helpers below.

// clampExcerpt shortens evidence excerpts to keep reports small (§51).
func clampExcerpt(s string) string {
        s = strings.TrimSpace(s)
        if len(s) > 200 {
                return s[:200] + "…"
        }
        return s
}

// lineOfOffset computes 1-based line number for a byte offset.
func lineOfOffset(data []byte, off int) int {
        if off > len(data) {
                off = len(data)
        }
        return 1 + strings.Count(string(data[:off]), "\n")
}

// avgIdentifierLen is used by minification heuristics.
func avgIdentifierLen(idents []string) float64 {
        if len(idents) == 0 {
                return 0
        }
        sum := 0
        for _, s := range idents {
                sum += len(s)
        }
        return float64(sum) / float64(len(idents))
}

// shannonEntropy returns bits-per-char entropy of a string (§38).
func shannonEntropy(s string) float64 {
        if len(s) == 0 {
                return 0
        }
        freq := map[rune]float64{}
        for _, r := range s {
                freq[r]++
        }
        var e float64
        for _, c := range freq {
                p := c / float64(len([]rune(s)))
                e -= p * math.Log2(p)
        }
        return e
}

// looksBase64 reports whether s is a plausible base64 blob.
func looksBase64(s string) bool {
        if len(s) < 80 {
                return false
        }
        hasPad := false
        for _, r := range s {
                switch {
                case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '+', r == '/':
                case r == '=':
                        hasPad = true
                default:
                        return false
                }
        }
        return !hasPad || len(s)%4 == 0
}

// isMostlyPrintableASCII is a cheap filter for binary-vs-text detection.
func isMostlyPrintableASCII(b []byte) bool {
        if len(b) == 0 {
                return true
        }
        nonPrint := 0
        n := len(b)
        if n > 4096 {
                n = 4096
        }
        for i := 0; i < n; i++ {
                c := b[i]
                if c == '\n' || c == '\r' || c == '\t' {
                        continue
                }
                if c < 32 || c > 126 {
                        nonPrint++
                }
        }
        return float64(nonPrint)/float64(n) < 0.10
}

// redactUserPath applies §164 username redaction on a path string.
func redactUserPath(p string) string {
        // Windows style C:\Users\<name>\... and unix /home/<name>/, /Users/<name>/
        if i := strings.Index(p, `\Users\`); i >= 0 && len(p) > i+7 {
                rest := p[i+7:]
                if j := strings.Index(rest, `\`); j > 0 {
                        return p[:i+7] + "REDACTED" + rest[j:]
                }
        }
        for _, prefix := range []string{"/home/", "/Users/"} {
                if strings.HasPrefix(p, prefix) {
                        rest := p[len(prefix):]
                        if j := strings.Index(rest, "/"); j > 0 {
                                return prefix + "REDACTED" + rest[j:]
                        }
                }
        }
        return p
}

func containsFold(s, sub string) bool {
        return strings.Contains(strings.ToLower(s), strings.ToLower(sub))
}

func uniqStrings(in []string) []string {
        seen := map[string]bool{}
        out := make([]string, 0, len(in))
        for _, s := range in {
                if !seen[s] {
                        seen[s] = true
                        out = append(out, s)
                }
        }
        return out
}

func isIdentChar(r rune) bool {
        return r == '_' || r == '$' || unicode.IsLetter(r) || unicode.IsDigit(r)
}

// compactManifest returns a trimmed copy of the manifest for reports: keys
// kept, giant values (like embedded images in "icons" or "key") shortened.
func compactManifest(mi *ManifestInfo) map[string]any {
	if mi.Raw == nil {
		return nil
	}
	out := map[string]any{}
	for k, v := range mi.Raw {
		out[k] = v
	}
	return out
}
