package main

// Finding construction (§48–§51) with rule metadata, severity/confidence
// discipline, health aggregation (§47) and tags (§122).

import (
	"fmt"
	"sort"
	"strings"
)

func (f *Finding) loc() string { return f.Location }

// MakeFinding builds a finding from a rule template, allowing contextual
// severity/confidence overrides (§49: severity depends on capability,
// evidence, reachability, breadth, context, confidence).
func MakeFinding(ruleID string, sev string, conf string, evidence []Evidence, location string, ctxNotes ...string) Finding {
	r := GetRule(ruleID)
	if sev == "" {
		sev = r.DefaultSeverity
	}
	if conf == "" {
		conf = r.DefaultConfidence
	}
	f := Finding{
		RuleID:         ruleID,
		Category:       r.Category,
		Severity:       sev,
		Confidence:     conf,
		Title:          r.Title,
		Summary:        r.Summary,
		Evidence:       evidence,
		WhyItMatters:   r.WhyItMatters,
		Location:       location,
		Recommendation: r.Recommendation,
	}
	if len(ctxNotes) > 0 && ctxNotes[0] != "" {
		f.Summary = r.Summary + " " + ctxNotes[0]
	}
	return f
}

func evFile(file string, line int, note string) Evidence {
	return Evidence{File: file, Line: line, Note: note}
}

// CountSeverity returns map for stats.
func CountSeverity(findings []Finding) map[string]int {
	m := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
	for _, f := range findings {
		m[f.Severity]++
	}
	return m
}

func CountCategory(findings []Finding) map[string]int {
	m := map[string]int{}
	for _, f := range findings {
		m[f.Category]++
	}
	return m
}

// healthCategories (§47).
var healthCategories = []string{"Security", "Privacy", "Performance", "Compatibility", "Code Quality", "Permissions", "Network", "Package", "Maintenance"}

func categoryFor(health string) string {
	switch strings.ToLower(health) {
	case "security":
		return "Security"
	case "privacy":
		return "Privacy"
	case "performance":
		return "Performance"
	case "compatibility":
		return "Compatibility"
	case "code quality":
		return "Code Quality"
	case "permissions":
		return "Permissions"
	case "network":
		return "Network"
	case "package":
		return "Package"
	case "maintenance":
		return "Maintenance"
	}
	return "Code Quality"
}

// BuildHealth computes per-category statuses (§47) without a single score.
func BuildHealth(findings []Finding, coverage float64) (map[string]string, string) {
	health := map[string]string{}
	for _, h := range healthCategories {
		health[h] = "Healthy"
	}
	needsReview := false
	significant := false
	for _, f := range findings {
		cat := categoryFor(f.Category)
		switch f.Severity {
		case "critical", "high":
			if health[cat] != "Significant Concerns" {
				health[cat] = "Significant Concerns"
			}
			significant = true
		case "medium":
			if health[cat] == "Healthy" {
				health[cat] = "Needs Review"
			}
			needsReview = true
		}
	}
	overall := "Healthy"
	if needsReview {
		overall = "Needs Review"
	}
	if significant {
		overall = "Significant Concerns"
	}
	if coverage < 95.0 {
		overall = "Analysis Incomplete"
	}
	return health, overall
}

// BuildTags derives descriptive, non-verdict tags (§122).
func BuildTags(er *ExtensionReport) []string {
	var tags []string
	add := func(t string) { tags = append(tags, t) }

	ha := AnalyzeHostPermissionsQuick(er)
	if ha.AllSites {
		add("Broad host access")
	}
	for _, p := range er.Permissions {
		if p.Risk == "high" && p.Source == "required" {
			add("High privilege")
			break
		}
	}
	if len(er.Background.NativeMsgSites) > 0 || er.Background.HasNative {
		add("Native messaging")
	}
	if er.Package.TotalSize > 10*1024*1024 {
		add("Large package")
	}
	for _, cs := range er.ContentScripts {
		if cs.ScriptCount > 0 && totalScriptSize(er, cs) > 512*1024 {
			add("Large content script")
			break
		}
	}
	if er.Readability.Obfuscated {
		add("Obfuscation indicators")
	}
	if er.Readability.Minified {
		add("Minified")
	}
	if len(er.Installations) > 1 {
		add("Multiple profiles")
	}
	for _, inst := range er.Installations {
		if inst.InstallType == "developer" {
			add("Developer installed")
			break
		}
	}
	for _, inst := range er.Installations {
		if inst.InstalledByPolicy {
			add("Policy installed")
			break
		}
	}
	thirdParty := false
	for _, n := range er.Network {
		if n.Classification == "analytics" || n.Classification == "advertising" {
			thirdParty = true
			break
		}
	}
	if thirdParty {
		add("Third-party network")
	}
	for _, t := range er.Background.Timers {
		if t.Interval && t.DelayMS >= 0 && t.DelayMS < 1000 {
			add("Potential polling")
			break
		}
	}
	domHeavy := false
	for _, f := range er.Findings {
		if f.RuleID == "PERF-002" {
			domHeavy = true
			break
		}
	}
	if domHeavy {
		add("Potential DOM-heavy behavior")
	}
	return uniqStrings(tags)
}

// AnalyzeHostPermissionsQuick recomputes host breadth for tag derivation.
func AnalyzeHostPermissionsQuick(er *ExtensionReport) HostAnalysis {
	var patterns []string
	for _, h := range er.HostPermissions {
		patterns = append(patterns, h.Pattern)
	}
	ha := HostAnalysis{PatternCount: len(patterns)}
	for _, p := range patterns {
		if p == "<all_urls>" || strings.Contains(p, "*/*") && strings.HasPrefix(p, "*") {
			ha.AllSites = true
		}
	}
	return ha
}

func totalScriptSize(er *ExtensionReport, cs ContentScriptInfo) int64 {
	var total int64
	for _, s := range cs.ScriptFiles {
		for _, f := range er.Files {
			if f.Path == s {
				total += f.Size
			}
		}
	}
	return total
}

// SortFindings orders by severity then confidence.
func SortFindings(fs []Finding) {
	rankS := map[string]int{"critical": 5, "high": 4, "medium": 3, "low": 2, "informational": 1}
	rankC := map[string]int{"high": 3, "medium": 2, "low": 1}
	sort.SliceStable(fs, func(i, j int) bool {
		if rankS[fs[i].Severity] != rankS[fs[j].Severity] {
			return rankS[fs[i].Severity] > rankS[fs[j].Severity]
		}
		if rankC[fs[i].Confidence] != rankC[fs[j].Confidence] {
			return rankC[fs[i].Confidence] > rankC[fs[j].Confidence]
		}
		return fs[i].RuleID < fs[j].RuleID
	})
}

// findingLocation formats a stable location string.
func findingLocation(file string, line int) string {
	if file == "" {
		return "package"
	}
	if line > 0 {
		return fmt.Sprintf("%s:%d", file, line)
	}
	return file
}
