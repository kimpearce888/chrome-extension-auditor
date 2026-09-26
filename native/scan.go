package main

// Scan orchestration (§153: the 21-step pipeline). Per-extension isolation
// (§89), bounded concurrency (§90), cancellation (§88/§161), incremental
// analysis via the file-hash cache (§92), and honest coverage tracking (§109).

import (
        "context"
        crand "crypto/rand"
        "fmt"
        "os"
        "path/filepath"
        "regexp"
        "sort"
        "strings"
        "sync"
        "sync/atomic"
        "time"
)

type ScanOptions struct {
        Mode              string // quick | standard | deep
        ChromeUserData    string
        ChromeVersion     string
        ExtensionFilter   []string
        ManagementInventory []map[string]any
        LM                LMStudioSettings
        ProfileOverride   []string
}

type Scanner struct {
        Store    *Store
        Limits   Limits
        validator *PathValidator
        cancel    atomic.Bool
        cancelCtx context.Context
        mu        sync.Mutex
        currentScanID string
}

func NewScanner(store *Store) *Scanner {
        return &Scanner{
                Store:    store,
                Limits:   DefaultLimits(),
                validator: NewPathValidator(),
        }
}

func (s *Scanner) RequestCancel() { s.cancel.Store(true) }

func (s *Scanner) cancelled() bool { return s.cancel.Load() }

// ProgressFn receives scan progress events (§88).
type ProgressFn func(stage string, current, total int, message string)

// ScanAll — top-level scan across every discovered profile/extension.
func (s *Scanner) ScanAll(opts ScanOptions, progress ProgressFn) (*ScanResult, *ProtocolError) {
        s.cancel.Store(false)
        s.cancelCtx = context.Background()

        mode := normalizeMode(opts.Mode)
        scanID := newScanID()
        s.currentScanID = scanID
        currentScanIDref = scanID // published for single-extension flows
        scan := Scan{
                ID:              scanID,
                StartedAt:       nowISO(),
                Mode:            mode,
                Status:          "SCAN_OK",
                ChromeVersion:   strOr2(opts.ChromeVersion, "Not available"),
                OSVersion:       osVersion(),
                ScannerVersion:  ScannerVersion,
                RuleSetVersion:  ruleSet.RuleSetVersion,
                AnalyzerVersion: AnalyzerVersion,
        }

        progress("profiles", 0, 0, "Discovering Chrome profiles...")
        profiles := DiscoverProfiles(opts.ChromeUserData)
        for _, p := range profiles {
                s.validator.AddRoot(p.Dir)
        }
        progress("profiles", len(profiles), len(profiles), fmt.Sprintf("Found %d profiles.", len(profiles)))

        if s.cancelled() {
                scan.Status = "SCAN_PARTIAL"
                scan.FinishedAt = nowISO()
                return &ScanResult{Scan: scan, Profiles: profiles}, nil
        }

        progress("extensions", 0, 0, "Discovering extensions...")
        byID := DiscoverExtensions(profiles, opts.ManagementInventory)
        total := len(byID)
        progress("extensions", total, total, fmt.Sprintf("Found %d extensions.", total))

        // previous snapshot ids for removed/new detection
        prevScan := s.Store.LatestFinishedScan(scanID)
        var prevExtensions map[string]bool
        if prevScan != nil {
                prevExtensions = map[string]bool{}
                for id := range s.Store.Data.Snapshots {
                        if s.Store.Data.Snapshots[id].ScanID == prevScan.ID {
                                prevExtensions[id] = true
                        }
                }
        }

        result := &ScanResult{Scan: scan, Profiles: profiles}
        analyzed := 0
        var errsMu sync.Mutex
        var extensions []ExtensionReport
        var sem = make(chan struct{}, s.Limits.ScanWorkers)
        var extMu sync.Mutex
        var idx int32
        var failed int32

        for id, de := range byID {
                if s.cancelled() {
                        scan.Status = "SCAN_PARTIAL"
                        break
                }
                if len(opts.ExtensionFilter) > 0 && !containsString(opts.ExtensionFilter, id) {
                        continue
                }
                sem <- struct{}{}
                go func(id string, de *DiscoveredExtension) {
                        defer func() { <-sem }()
                        if r := recover(); r != nil {
                                errsMu.Lock()
                                scan.Errors = append(scan.Errors, fmt.Sprintf("extension %s: recovered from analysis error: %v", id, r))
                                errsMu.Unlock()
                                atomic.AddInt32(&failed, 1)
                                return
                        }
                        if s.cancelled() {
                                return
                        }
                        report, err := s.ScanExtension(de, mode, opts, progress, int(atomic.AddInt32(&idx, 1)), total)
                        extMu.Lock()
                        if err != nil {
                                errsMu.Lock()
                                scan.Errors = append(scan.Errors, fmt.Sprintf("extension %s: %s", id, err.Message))
                                errsMu.Unlock()
                                atomic.AddInt32(&failed, 1)
                                if report != nil {
                                        extensions = append(extensions, *report)
                                }
                        } else if report != nil {
                                extensions = append(extensions, *report)
                        }
                        extMu.Unlock()
                }(id, de)
        }
        for i := 0; i < cap(sem); i++ {
                sem <- struct{}{}
        }
        analyzed = len(extensions)

        // removed / new detection (§148–149)
        if prevExtensions != nil {
                current := map[string]bool{}
                for _, e := range extensions {
                        current[e.ID] = true
                }
                for id := range prevExtensions {
                        if !current[id] {
                                result.RemovedSinceLast = append(result.RemovedSinceLast, id)
                        }
                }
                for id := range current {
                        if !prevExtensions[id] {
                                result.NewSinceLast = append(result.NewSinceLast, id)
                        }
                }
        }

        // aggregate stats
        scan.ExtensionsFound = total
        scan.ProfilesScanned = len(profiles)
        scan.Stats = ScanStats{
                ExtensionsAnalyzed: analyzed,
                ExtensionsFailed:   int(failed),
                FindingsByCategory: map[string]int{},
                FindingsBySeverity: map[string]int{},
        }
        var coverageSum float64
        for i := range extensions {
                e := &extensions[i]
                for _, f := range e.Findings {
                        scan.Stats.FindingsByCategory[f.Category]++
                        scan.Stats.FindingsBySeverity[f.Severity]++
                }
                coverageSum += e.Analysis.Coverage
                if e.OverallStatus != "Healthy" && e.OverallStatus != "Analysis Incomplete" {
                        scan.Stats.ExtensionsNeedingReview++
                }
                if e.Analysis.Coverage < 95 {
                        scan.Stats.IncompleteAnalysis++
                }
        }
        if len(extensions) > 0 {
                scan.Stats.AverageCoverage = coverageSum / float64(len(extensions))
        }
        if int(failed) > 0 {
                if scan.Status == "SCAN_OK" {
                        scan.Status = "SCAN_PARTIAL"
                }
        }
        scan.FinishedAt = nowISO()
        result.Extensions = extensions
        result.Scan = scan

        // conflict / duplicate-function analysis across extensions (§45–46)
        if mode != "quick" && len(extensions) > 1 {
                for i := range result.Extensions {
                        result.Extensions[i].Tags = append(result.Extensions[i].Tags, conflictTags(&result.Extensions[i], extensions)...)
                        result.Extensions[i].Tags = uniqStrings(result.Extensions[i].Tags)
                }
        }

        // persist scan + snapshots
        s.Store.RecordScan(result)
        return result, nil
}

func normalizeMode(m string) string {
        switch m {
        case "quick", "standard", "deep":
                return m
        case "":
                return "standard"
        }
        return "standard"
}

func newScanID() string {
        return "scan-" + strings.ReplaceAll(strings.ReplaceAll(nowISO(), ":", ""), "-", "")[:15] + "-" + randSuffix()
}

func randSuffix() string {
        b := make([]byte, 6)
        if _, err := crand.Read(b); err != nil {
                for i := range b {
                        b[i] = byte(time.Now().UnixNano() >> (i * 8))
                }
        }
        const hex = "0123456789abcdef"
        out := make([]byte, len(b))
        for i, v := range b {
                out[i] = hex[v&0xf]
        }
        return string(out)
}

func strOr2(s, def string) string {
        if strings.TrimSpace(s) != "" {
                return s
        }
        return def
}

func containsString(list []string, s string) bool {
        for _, x := range list {
                if x == s {
                        return true
                }
        }
        return false
}

func osVersion() string {
        if v := os.Getenv("OS"); v != "" {
                return v
        }
        return "Not available"
}

// ScanExtension runs the §153 pipeline for one extension. Never panics the
// whole scan (§89).
func (s *Scanner) ScanExtension(de *DiscoveredExtension, mode string, opts ScanOptions, progress ProgressFn, idx, total int) (*ExtensionReport, *ProtocolError) {
        primary := primaryInstallation(de)
        report := &ExtensionReport{
                ID: de.ID,
        }
        if primary == nil {
                report.Analysis = AnalysisState{Status: "SCAN_FAILED", Coverage: 0, CoverageNotes: []string{"No installation with a package path was found."}}
                normalizeSlices(report)
                return report, &ProtocolError{Code: "SCAN_FAILED", Message: "no scannable package path for " + de.ID}
        }
        if progress != nil {
                progress("scanning", idx, total, fmt.Sprintf("Scanning %s...", de.ID))
        }
        pkgPath, perr := s.validator.ValidateDiscovered(primary.Path)
        if perr != nil {
                pe, ok := perr.(*ProtocolError)
                if !ok {
                        pe = &ProtocolError{Code: "ACCESS_DENIED", Message: perr.Error()}
                }
                report.Analysis = AnalysisState{Status: "ACCESS_DENIED", Coverage: 0, CoverageNotes: []string{"Package path rejected: " + pe.Message}}
                normalizeSlices(report)
                return report, pe
        }
        if fi, err := os.Stat(pkgPath); err != nil || !fi.IsDir() {
                report.Analysis = AnalysisState{Status: "PROFILE_UNAVAILABLE", Coverage: 0, CoverageNotes: []string{"Package directory not accessible."}}
                normalizeSlices(report)
                return report, &ProtocolError{Code: "PROFILE_UNAVAILABLE", Message: "cannot read package dir " + pkgPath}
        }

        status := "SCAN_OK"
        coverageNotes := []string{}

        // Steps 4–5: validate package, parse manifest
        mi := ParseManifest(pkgPath)
        if !mi.Valid {
                report.Analysis = AnalysisState{Status: "MANIFEST_INVALID", Coverage: 0, CoverageNotes: []string{mi.ParseError}}
                report.Findings = append(report.Findings, MakeFinding("COMPAT-005", "medium", "high",
                        []Evidence{{Note: mi.ParseError}}, "manifest.json"))
                fillBasicsFromInstall(report, de, primary)
                finalize(report)
                return report, nil
        }

        fillBasicsFromManifest(report, de, primary, mi)

        // Steps 6–7: inventory files, hash (incremental §92)
        files, pkg, fileAnalyses, covNotes := s.InventoryAndAnalyzeFiles(pkgPath, mode, de.ID)
        report.Files = files
        report.Package = pkg
        coverageNotes = append(coverageNotes, covNotes...)

        // Aggregate per-file analyses
        agg := aggregateAnalyses(fileAnalyses)
        report.APIs = buildAPIUsage(agg)
        report.Background = buildBackground(mi, agg)
        report.ContentScripts = buildContentScripts(mi)

        // Steps 8–9: permissions + host analysis
        report.Permissions = AnalyzePermissions(mi, agg)
        hostAnalysis := AnalyzeHostPermissions(mi)
        report.HostPermissions = hostAnalysis.Patterns

        // Network inventory (§22–23)
        if mode != "quick" {
                report.Network = buildNetworkInventory(report, mi, agg, pkgPath)
        }

        // Secrets (§39) — standard+
        var secretHits []SecretHit
        if mode != "quick" {
                for _, fa := range fileAnalyses {
                        secretHits = append(secretHits, fa.Secrets...)
                }
        }

        // Dependencies, readability, obfuscation
        if mode != "quick" {
                report.Dependencies = DetectDependencies(files, fileAnalyses, pkgPath)
        }
        report.Readability = BuildReadability(files, fileAnalyses, mode)

        // Findings from every analyzer
        report.Findings = s.BuildFindings(report, mi, agg, hostAnalysis, secretHits, mode, opts)
        SortFindings(report.Findings)

        // coverage computation (§109)
        analyzable := 0
        analyzedOK := 0
        for _, f := range fileAnalyses {
                if f.Analyzed {
                        analyzable++
                        analyzedOK++
                } else if f.Considered {
                        analyzable++
                }
        }
        coverage := 100.0
        if analyzable > 0 {
                coverage = float64(analyzedOK) / float64(analyzable) * 100
        }
        if pkg.FilesSkipped > 0 {
                coverageNotes = append(coverageNotes, fmt.Sprintf("%d files skipped due to size/count limits.", pkg.FilesSkipped))
        }
        if status == "SCAN_OK" && coverage < 100 {
                status = "SCAN_PARTIAL"
        }
        report.Analysis = AnalysisState{
                Status:        status,
                Coverage:      round1(coverage),
                CoverageNotes: coverageNotes,
        }
        if coverage < 100 && coverage > 0 {
                report.Findings = append(report.Findings, MakeFinding("SCAN-001", "", "high",
                        []Evidence{{Note: strings.Join(coverageNotes, "; ")}}, "package"))
        }

        // Snapshot comparison (§63, §130) — standard & deep include diff
        if mode != "quick" {
                snapshot := BuildSnapshot(report, s.currentScanID)
                prev := s.Store.PreviousSnapshot(de.ID, snapshot.ScanID)
                if prev != nil {
                        changes := DiffSnapshots(prev, &snapshot)
                        if len(changes) > 0 {
                                report.Findings = append(report.Findings, findingsFromDiff(changes)...)
                                SortFindings(report.Findings)
                        }
                }
                s.Store.PutSnapshot(s.currentScanID, snapshot)
        }

        // AI interpretation (§68–71) — deep only
        if mode == "deep" {
                ai := s.RunAIInterpretation(report, opts.LM)
                if ai != nil {
                        report.AI = ai
                }
        }

        finalize(report)
        return report, nil
}

func finalize(report *ExtensionReport) {
        normalizeSlices(report)
        report.Health, report.OverallStatus = BuildHealth(report.Findings, report.Analysis.Coverage)
        report.Tags = BuildTags(report)
}

// normalizeSlices guarantees iterable JSON fields ([] / {} instead of null)
// on every return path, including scan failures.
func normalizeSlices(report *ExtensionReport) {
        if report.Installations == nil {
                report.Installations = []ExtensionInstallation{}
        }
        if report.Permissions == nil {
                report.Permissions = []PermissionInfo{}
        }
        if report.HostPermissions == nil {
                report.HostPermissions = []HostPatternInfo{}
        }
        if report.ContentScripts == nil {
                report.ContentScripts = []ContentScriptInfo{}
        }
        if report.APIs == nil {
                report.APIs = []APIUsage{}
        }
        if report.Network == nil {
                report.Network = []NetworkEndpoint{}
        }
        if report.Dependencies == nil {
                report.Dependencies = []Dependency{}
        }
        if report.Files == nil {
                report.Files = []FileInfo{}
        }
        if report.Findings == nil {
                report.Findings = []Finding{}
        }
        if report.Tags == nil {
                report.Tags = []string{}
        }
        if report.Health == nil {
                report.Health = map[string]string{}
        }
        if report.Analysis.CoverageNotes == nil {
                report.Analysis.CoverageNotes = []string{}
        }
}

func fillBasicsFromInstall(report *ExtensionReport, de *DiscoveredExtension, inst *ExtensionInstallation) {
        report.Name = "Not available"
        report.Version = inst.Version
        report.Installations = flattenInstalls(de)
}

func fillBasicsFromManifest(report *ExtensionReport, de *DiscoveredExtension, primary *ExtensionInstallation, mi *ManifestInfo) {
        report.Name = mi.Name
        report.Version = orDefault(mi.VersionString, primary.Version)
        report.Description = orDefault(jsonString(mi.Raw, "description"), "Not available")
        report.ShortName = orDefault(jsonString(mi.Raw, "short_name"), "")
        report.HomepageURL = orDefault(jsonString(mi.Raw, "homepage_url"), "Not available")
        report.UpdateURL = orDefault(jsonString(mi.Raw, "update_url"), "Not available")
        if mi.Version == 2 {
                // MV2 often lacks homepage; update_url present for webstore
        }
        if oui, ok := mi.Raw["options_ui"].(map[string]any); ok {
                if p, ok := oui["page"].(string); ok {
                        report.OptionsURL = p
                }
        } else if p, ok := mi.Raw["options_page"].(string); ok {
                report.OptionsURL = p
        } else {
                report.OptionsURL = "Not available"
        }
        report.ManifestVersion = mi.Version
        report.Type = extType(mi)
        report.UnknownManifestFields = mi.UnknownFields
        report.ManifestRaw = compactManifest(mi)
        report.Installations = flattenInstalls(de)
}

func orDefault(s, def string) string {
        if s == "" || s == "Not available" {
                return def
        }
        return s
}

func extType(mi *ManifestInfo) string {
        if mi.Version == -1 {
                return "Not available"
        }
        if _, hasApp := mi.Raw["app"]; hasApp {
                return "Chrome App (deprecated platform)"
        }
        if _, hasTheme := mi.Raw["theme"]; hasTheme {
                return "Theme"
        }
        return "Extension"
}

func flattenInstalls(de *DiscoveredExtension) []ExtensionInstallation {
        out := make([]ExtensionInstallation, 0, len(de.Installations))
        for _, i := range de.Installations {
                out = append(out, i)
        }
        return out
}

func primaryInstallation(de *DiscoveredExtension) *ExtensionInstallation {
        var best *ExtensionInstallation
        for i := range de.Installations {
                inst := &de.Installations[i]
                if inst.Path == "" {
                        continue
                }
                if best == nil {
                        best = inst
                        continue
                }
                if inst.Enabled && !best.Enabled {
                        best = inst
                }
        }
        return best
}

func round1(f float64) float64 {
        return float64(int(f*10+0.5)) / 10
}

// ---- per-file walk with hashing + cached analysis ----

type FileAnalysisResult struct {
        File      string
        Category  string
        Analyzed  bool
        Considered bool
        Analysis  *FileAnalysis
        Secrets   []SecretHit
        HTMLURLs  []CodeSite
        RawURLs   []CodeSite
}

// InventoryAndAnalyzeFiles walks the package, hashes files (§13) and runs or
// reuses per-file analysis (§92).
func (s *Scanner) InventoryAndAnalyzeFiles(pkgPath, mode, extID string) ([]FileInfo, PackageStats, []*FileAnalysisResult, []string) {
        var files []FileInfo
        var results []*FileAnalysisResult
        pkg := PackageStats{ByType: map[string]int{}, SizeByType: map[string]int64{}}
        var notes []string
        fileCount := 0

        _ = filepath.WalkDir(pkgPath, func(path string, d os.DirEntry, err error) error {
                if err != nil {
                        return nil // tolerate unreadable entries (§56)
                }
                if d.IsDir() {
                        return nil
                }
                fileCount++
                if fileCount > s.Limits.MaxFilesPerExt {
                        pkg.FilesSkipped++
                        return nil
                }
                rel, _ := filepath.Rel(pkgPath, path)
                rel = filepath.ToSlash(rel)
                fi, err := d.Info()
                if err != nil {
                        return nil
                }
                cat := fileCategory(rel)
                hash, _ := sha256File(path)
                info := FileInfo{
                        Path:         rel,
                        Type:         cat,
                        Size:         fi.Size(),
                        SHA256:       hash,
                }
                pkg.ByType[cat]++
                pkg.SizeByType[cat] += fi.Size()
                pkg.TotalSize += fi.Size()
                if fi.Size() > pkg.LargestFileSize {
                        pkg.LargestFile, pkg.LargestFileSize = rel, fi.Size()
                }
                switch cat {
                case "javascript", "typescript":
                        if fi.Size() > pkg.LargestJSSize {
                                pkg.LargestJS, pkg.LargestJSSize = rel, fi.Size()
                        }
                case "css":
                        if fi.Size() > pkg.LargestCSSSize {
                                pkg.LargestCSS, pkg.LargestCSSSize = rel, fi.Size()
                        }
                case "sourcemap":
                        pkg.SourceMaps++
                }
                files = append(files, info)

                if mode == "quick" || !isTextual(cat) {
                        return nil
                }

                // incremental: reuse cached per-file analysis when hash matches (§92)
                if cached, ok := s.Store.GetFileCache(hash); ok && cached.AnalysisVersion == AnalyzerVersion {
                        results = append(results, &FileAnalysisResult{
                                File: rel, Category: cat, Analyzed: true, Considered: true,
                                Analysis: &cached.Analysis,
                        })
                        info.Minified = cached.Analysis.Metrics.AvgLineLen > 300
                        return nil
                }

                data, err := os.ReadFile(path)
                if err != nil {
                        return nil
                }
                if !isMostlyPrintableASCII(data) {
                        return nil
                }
                res := &FileAnalysisResult{File: rel, Category: cat, Considered: true}
                if int64(len(data)) > s.Limits.MaxFileAnalyzeBytes {
                        notes = append(notes, fmt.Sprintf("%s exceeded the analysis size limit (%s).", rel, humanSize(int64(len(data)))))
                        res.Analyzed = false
                        results = append(results, res)
                        return nil
                }
                src := string(data)
                switch cat {
                case "javascript", "typescript":
                        fa := AnalyzeJS(rel, src)
                        res.Analysis = fa
                        res.Secrets = DetectSecrets(rel, src)
                        info.Minified = fa.Metrics.AvgLineLen > 300
                        info.HasSourceMap = strings.Contains(src, "sourceMappingURL=")
                case "html":
                        res.HTMLURLs = extractHTMLURLs(rel, src)
                        res.RawURLs = rawCodeSites(rel, src)
                case "css", "json", "text":
                        res.RawURLs = rawCodeSites(rel, src)
                        if cat == "json" {
                                // sourceMappingURL in minified json is uncommon; skip
                        }
                }
                if res.Analysis != nil {
                        res.Analyzed = true
                        s.Store.PutFileCache(hash, *res.Analysis)
                } else if len(res.HTMLURLs) > 0 || len(res.RawURLs) > 0 {
                        res.Analyzed = true
                } else {
                        // the file was read and processed; an empty result is a
                        // complete analysis, not a failure (§109 honest coverage).
                        res.Analyzed = true
                        res.Analysis = &FileAnalysis{
                                APIs: map[string]int{}, APIEvidence: map[string][]string{},
                                Metrics: FileMetrics{Bytes: len(src), Lines: strings.Count(src, "\n") + 1},
                        }
                }
                results = append(results, res)
                return nil
        })

        pkg.TotalFiles = len(files)
        if pkg.TotalFiles == 0 {
                notes = append(notes, "No files found in the package directory.")
        }
        return files, pkg, results, notes
}

func rawCodeSites(rel, src string) []CodeSite {
        var out []CodeSite
        for _, u := range ExtractRawURLs(src) {
                out = append(out, CodeSite{File: rel, Line: lineOfOffset([]byte(src), strings.Index(src, u)), Kind: "literal", Arg: u})
        }
        return out
}

func mustCompile(expr string) *regexp.Regexp {
        return regexp.MustCompile(expr)
}

var htmlAttrRe = mustCompile(`(?i)(?:src|href|action|data-src)\s*=\s*["']([^"']+)["']`)

func extractHTMLURLs(rel, src string) []CodeSite {
        var out []CodeSite
        for _, m := range htmlAttrRe.FindAllStringSubmatch(src, -1) {
                if looksLikeURL(m[1]) {
                        out = append(out, CodeSite{File: rel, Line: lineOfOffset([]byte(src), strings.Index(src, m[0])), Kind: "html", Arg: m[1]})
                }
        }
        return out
}

// aggregateAnalyses merges per-file analyses.
type AggFiles struct {
        byFile map[string]*FileAnalysis
        order  []string
}

func aggregateAnalyses(results []*FileAnalysisResult) map[string]*FileAnalysis {
        agg := map[string]*FileAnalysis{}
        for _, r := range results {
                if r.Analysis == nil {
                        continue
                }
                if existing, ok := agg[r.File]; ok {
                        mergeAnalysis(existing, r.Analysis)
                } else {
                        cp := *r.Analysis
                        agg[r.File] = &cp
                }
        }
        return agg
}

func mergeAnalysis(dst, src *FileAnalysis) {
        for k, v := range src.APIs {
                dst.APIs[k] += v
        }
        for k, v := range src.APIEvidence {
                dst.APIEvidence[k] = append(dst.APIEvidence[k], v...)
        }
        dst.Timers = append(dst.Timers, src.Timers...)
        dst.StringCodeExec = append(dst.StringCodeExec, src.StringCodeExec...)
        dst.DomInjections = append(dst.DomInjections, src.DomInjections...)
        dst.Observers = append(dst.Observers, src.Observers...)
        dst.NetworkCalls = append(dst.NetworkCalls, src.NetworkCalls...)
        dst.DynamicURLs = append(dst.DynamicURLs, src.DynamicURLs...)
        dst.MessageHandlers = append(dst.MessageHandlers, src.MessageHandlers...)
        dst.ExternalHandlers = append(dst.ExternalHandlers, src.ExternalHandlers...)
        dst.PostMessage = append(dst.PostMessage, src.PostMessage...)
        dst.NativeMsg = append(dst.NativeMsg, src.NativeMsg...)
        dst.DynamicAccess = append(dst.DynamicAccess, src.DynamicAccess...)
        dst.ScriptInsert = append(dst.ScriptInsert, src.ScriptInsert...)
        dst.EventListeners += src.EventListeners
        dst.DocQueries += src.DocQueries
        dst.StorageCalls += src.StorageCalls
        dst.ClipboardCalls += src.ClipboardCalls
        dst.URLStrings = append(dst.URLStrings, src.URLStrings...)
}

func buildAPIUsage(agg map[string]*FileAnalysis) []APIUsage {
        apiFiles := aggAllAPIs(agg)
        var out []APIUsage
        for api, files := range apiFiles {
                calls, evidence := 0, []string{}
                for _, f := range files {
                        calls += agg[f].APIs[api]
                        if ev := agg[f].APIEvidence[api]; len(ev) > 0 {
                                evidence = append(evidence, ev[0])
                        }
                }
                out = append(out, APIUsage{API: api, Calls: calls, Files: files, Evidence: evidence})
        }
        sort.Slice(out, func(i, j int) bool { return out[i].Calls > out[j].Calls })
        return out
}

func aggAllAPIs(agg map[string]*FileAnalysis) map[string][]string {
        m := map[string][]string{}
        for f, fa := range agg {
                for api := range fa.APIs {
                        m[api] = append(m[api], f)
                }
        }
        for api, files := range m {
                sort.Strings(files)
                m[api] = uniqStrings(files)
        }
        return m
}
