package main

// Readability (§37), obfuscation heuristics (§38), dependency detection
// (§33–34) and cross-extension conflicts (§45–46). Minification is normal and
// never labeled a security problem (§36).

import (
        "fmt"
        "os"
        "path/filepath"
        "regexp"
        "sort"
        "strings"
)

// BuildReadability produces the readability report (§37).
func BuildReadability(files []FileInfo, results []*FileAnalysisResult, mode string) ReadabilityReport {
        rr := ReadabilityReport{Level: "High"}
        if mode == "quick" {
                rr.AuditImpact = "Quick scan: source-level readability analysis not run."
                return rr
        }
        var indicators []string
        minifiedScore := 0
        totalJS := 0
        bundled := false
        obfScore := 0

        for _, r := range results {
                if r.Analysis == nil {
                        continue
                }
                if r.Category != "javascript" && r.Category != "typescript" {
                        continue
                }
                totalJS++
                m := r.Analysis.Metrics
                // minification heuristics
                if m.AvgLineLen > 300 || (m.Bytes > 4096 && m.Lines < m.Bytes/500) {
                        minifiedScore++
                }
                if m.IdentCount > 1000 && m.AvgIdentLen < 2.2 {
                        minifiedScore++
                        bundled = true
                }
                if r.Analysis.APIs["__webpack_require__"] > 0 || strings.Contains(r.File, "bundle") || strings.Contains(r.File, "chunk") {
                        bundled = true
                }
                // obfuscation heuristics (§38) — deliberately conservative thresholds:
                // each signal alone is weak; the score needs two or more.
                if m.HexIdents >= 3 {
                        obfScore += 2
                        indicators = append(indicators, fmt.Sprintf("%s: %d hex-style identifiers (_0x…)", r.File, m.HexIdents))
                }
                if m.Base64Blobs >= 1 && r.Analysis.APIs["atob"] > 0 {
                        obfScore += 2
                        indicators = append(indicators, fmt.Sprintf("%s: %d large base64 blobs decoded via atob()", r.File, m.Base64Blobs))
                }
                if m.AvgStringEntropy > 5.2 && m.LongStrings > 8 {
                        obfScore++
                        indicators = append(indicators, fmt.Sprintf("%s: high average string entropy (%.2f)", r.File, m.AvgStringEntropy))
                }
                if m.BackslashX >= 2 {
                        obfScore++
                        indicators = append(indicators, fmt.Sprintf("%s: %d \\x-escaped strings", r.File, m.BackslashX))
                }
                if r.Analysis.APIs["String.fromCharCode"] > 0 && m.LongStrings > 4 {
                        obfScore++
                        indicators = append(indicators, fmt.Sprintf("%s: String.fromCharCode decoding with long strings", r.File))
                }
        }

        sourcemaps := 0
        for _, f := range files {
                if f.Type == "sourcemap" || f.HasSourceMap {
                        sourcemaps++
                }
        }

        if totalJS > 0 {
                ratio := float64(minifiedScore) / float64(totalJS)
                if ratio > 0.5 && sourcemaps == 0 {
                        rr.Minified = true
                        rr.Level = "Low"
                        indicators = append(indicators, "heavily minified output without source maps")
                } else if ratio > 0.25 || (sourcemaps == 0 && bundled) {
                        rr.Level = "Medium"
                }
        }
        rr.Bundled = bundled
        rr.Obfuscated = obfScore >= 2
        rr.Indicators = uniqStrings(indicators)
        if len(rr.Indicators) == 0 {
                rr.Indicators = []string{"no strong readability obstacles detected"}
        }
        switch rr.Level {
        case "Low":
                rr.AuditImpact = "This affects static audit confidence; manual review may be needed."
        case "Medium":
                rr.AuditImpact = "Some files are difficult to inspect; audit confidence is moderately affected."
        default:
                rr.AuditImpact = "Source appears reasonably inspectable."
        }
        return rr
}

// ---- Dependency detection (§33) ----

// DetectDependencies identifies packaged libraries via local signatures
// (§33, §99). Offline only; results carry confidence levels.
func DetectDependencies(files []FileInfo, results []*FileAnalysisResult, pkgPath string) []Dependency {
        var deps []Dependency
        type hit struct {
                files []string
        }
        libHits := map[string]*hit{}

        // Signature scan over file contents (read bounded sizes)
        for _, f := range files {
                if !isTextual(f.Type) || f.Size > 4*1024*1024 {
                        continue
                }
                data, err := readFileLimited(joinPath(pkgPath, f.Path), 512*1024)
                if err != nil {
                        continue
                }
                src := string(data)
                for _, sig := range DepSignatures() {
                        nameMatch := false
                        for _, s := range sig.Signatures {
                                if strings.Contains(src, s) {
                                        nameMatch = true
                                        break
                                }
                        }
                        fileHint := false
                        base := strings.ToLower(fileNameOf(f.Path))
                        for _, h := range sig.FileHints {
                                if base == strings.ToLower(h) {
                                        fileHint = true
                                        break
                                }
                        }
                        if !nameMatch && !fileHint {
                                continue
                        }
                        h := libHits[sig.Library]
                        if h == nil {
                                h = &hit{}
                                libHits[sig.Library] = h
                        }
                        h.files = append(h.files, f.Path)
                }
        }

        for lib, h := range libHits {
                dep := Dependency{
                        Name:       lib,
                        Version:    "Not available",
                        Confidence: "medium",
                        Files:      uniqStrings(h.files),
                }
                if len(dep.Files) > 1 {
                        dep.Confidence = "high"
                }
                // version attempt from first matching file
                if len(h.files) > 0 {
                        data, err := readFileLimited(joinPath(pkgPath, h.files[0]), 256*1024)
                        if err == nil {
                                for _, sig := range DepSignatures() {
                                        if sig.Library == lib && sig.VersionRegex != "" {
                                                if re, err := regexp.Compile(sig.VersionRegex); err == nil {
                                                        if m := re.FindStringSubmatch(string(data)); len(m) > 1 {
                                                                dep.Version = m[1]
                                                                break
                                                        }
                                                }
                                        }
                                }
                        }
                }
                for _, sig := range DepSignatures() {
                        if sig.Library == lib {
                                dep.License = sig.License
                        }
                }
                deps = append(deps, dep)
        }
        sort.Slice(deps, func(i, j int) bool { return deps[i].Name < deps[j].Name })
        return deps
}

type depDuplicate struct {
        Name   string
        Copies int
}

// readFileLimited reads at most limit bytes.
func readFileLimited(path string, limit int64) ([]byte, error) {
        f, err := os.Open(path)
        if err != nil {
                return nil, err
        }
        defer f.Close()
        if limit <= 0 {
                limit = 512 * 1024
        }
        buf := make([]byte, limit)
        n, err := f.Read(buf)
        if err != nil && n == 0 {
                return nil, err
        }
        return buf[:n], nil
}



func joinPath(parts ...string) string { return filepath.Join(parts...) }
func fileNameOf(p string) string      { return filepath.Base(filepath.FromSlash(p)) }
func dirNameOf(p string) string      { return filepath.Dir(filepath.FromSlash(p)) }

// DetectDuplicateDependencies reports libraries bundled multiple times (§34).
func DetectDuplicateDependencies(deps []Dependency) []depDuplicate {
        var out []depDuplicate
        // duplicates = same library detected in multiple distinct files that look
        // like separate copies (same basename patterns in different dirs)
        fileCount := map[string]map[string]bool{} // lib -> set of basenames
        for _, d := range deps {
                if fileCount[d.Name] == nil {
                        fileCount[d.Name] = map[string]bool{}
                }
                for _, f := range d.Files {
                        base := fileNameOf(f)
                        dir := dirNameOf(f)
                        fileCount[d.Name][base+"@"+dir] = true
                }
        }
        for lib, set := range fileCount {
                if len(set) > 1 {
                        out = append(out, depDuplicate{Name: lib, Copies: len(set)})
                }
        }
        return out
}

// ---- Conflict / overlap analysis (§45–46) ----

var purposeCategories = []struct {
        name  string
        match []string
}{
        {"Ad blocking", []string{"adblock", "ad block", "adguard", "ublock", "blocker", "ad"}},
        {"Password management", []string{"password", "vault", "keeper", "lastpass", "bitwarden", "1password"}},
        {"VPN / proxy", []string{"vpn", "proxy"}},
        {"Translation", []string{"translate", "translation"}},
        {"Screenshot", []string{"screenshot", "capture", "screen record"}},
        {"Video downloading", []string{"video download", "downloader"}},
        {"Shopping", []string{"coupon", "shopping", "price", "deal"}},
        {"Privacy", []string{"privacy", "tracker", "anti-tracking", "dnt"}},
        {"Tab management", []string{"tab manager", "session", "tab group"}},
        {"Developer tools", []string{"devtools", "developer", "json", "regex", "web debug"}},
}

// guessPurposes infers likely functional categories from name/description.
func guessPurposes(er *ExtensionReport) []string {
        blob := strings.ToLower(er.Name + " " + er.Description)
        var out []string
        for _, pc := range purposeCategories {
                for _, m := range pc.match {
                        if strings.Contains(blob, m) {
                                out = append(out, pc.name)
                                break
                        }
                }
        }
        if len(out) == 0 {
                return nil
        }
        return out
}

// conflictTags returns overlap tags relative to the installed set (§45).
func conflictTags(er *ExtensionReport, all []ExtensionReport) []string {
        var tags []string
        myPurpose := guessPurposes(er)
        if len(myPurpose) > 0 {
                for _, other := range all {
                        if other.ID == er.ID {
                                continue
                        }
                        for _, p := range myPurpose {
                                for _, op := range guessPurposes(&other) {
                                        if p == op {
                                                tags = append(tags, "Possible functional overlap ("+p+")")
                                        }
                                }
                        }
                }
        }
        // broad content-script overlap
        if AnalyzeHostPermissionsQuick(er).AllSites {
                for _, other := range all {
                        if other.ID == er.ID {
                                continue
                        }
                        if AnalyzeHostPermissionsQuick(&other).AllSites && len(other.ContentScripts) > 0 && len(er.ContentScripts) > 0 {
                                tags = append(tags, "Broad content-script scope alongside "+other.Name)
                        }
                }
        }
        return uniqStrings(tags)
}
