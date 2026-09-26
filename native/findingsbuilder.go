package main

// BuildFindings maps analyzer output to rule-based findings with contextual
// severity/confidence (§49). Every finding carries evidence (§51).

import (
        "fmt"
        "strings"
)

// BuildFindings is the consolidated deterministic rule evaluation.
func (s *Scanner) BuildFindings(er *ExtensionReport, mi *ManifestInfo, agg map[string]*FileAnalysis, ha HostAnalysis, secrets []SecretHit, mode string, opts ScanOptions) []Finding {
        var findings []Finding

        // ---- Permission findings ----
        for _, p := range er.Permissions {
                if p.Risk == "high" && p.Source == "required" {
                        sev := "low"
                        // context escalation (§16): powerful permission + broad hosts
                        if ha.AllSites {
                                sev = "medium"
                        }
                        findings = append(findings, MakeFinding("PERM-001", sev, "high",
                                []Evidence{{Field: "permissions: " + p.Name, Note: p.WhyItMatters}},
                                "manifest.json"))
                }
                if p.Source == "optional" && p.Risk == "high" {
                        findings = append(findings, MakeFinding("PERM-003", "", "",
                                []Evidence{{Field: "optional_permissions: " + p.Name}},
                                "manifest.json"))
                }
                if p.ObservedUse == "not observed" && mode != "quick" {
                        findings = append(findings, MakeFinding("PERM-002", "", "medium",
                                []Evidence{{Field: "permissions: " + p.Name, Note: "No matching API usage found in static analysis."}},
                                "manifest.json"))
                }
        }

        // ---- Host findings ----
        if ha.AllSites {
                sev := "medium"
                if HasHighImpactPermission(er.Permissions) {
                        sev = "high"
                }
                var ev []Evidence
                for _, hp := range ha.Patterns {
                        if hp.Breadth == "all urls" {
                                ev = append(ev, Evidence{Field: "host_permissions: " + hp.Pattern})
                        }
                }
                findings = append(findings, MakeFinding("HOST-001", sev, "high", ev, "manifest.json"))
        }
        if ha.FileAccess {
                findings = append(findings, MakeFinding("HOST-002", "", "",
                        []Evidence{{Field: "host pattern with file:// scheme"}},
                        "manifest.json"))
        }
        if ha.PlainHTTP {
                var ev []Evidence
                for _, hp := range ha.Patterns {
                        if hp.Scheme == "http" {
                                ev = append(ev, Evidence{Field: hp.Pattern})
                        }
                }
                findings = append(findings, MakeFinding("HOST-003", "", "", ev, "manifest.json"))
        }
        sensitive := []Evidence{}
        for _, hp := range ha.Patterns {
                if hp.Sensitive {
                        sensitive = append(sensitive, Evidence{Field: hp.Pattern})
                }
        }
        if len(sensitive) > 0 {
                findings = append(findings, MakeFinding("HOST-004", "", "medium", sensitive, "manifest.json"))
        }

        // ---- Content script findings ----
        for _, cs := range er.ContentScripts {
                if cs.Broad && cs.RunAt == "document_start" {
                        findings = append(findings, MakeFinding("CS-001", "medium", "high",
                                []Evidence{{Field: "content_scripts.matches includes all URLs", Note: "run_at: document_start"}},
                                "manifest.json"))
                }
                if cs.AllFrames {
                        findings = append(findings, MakeFinding("CS-002", "", "",
                                []Evidence{{Field: "all_frames: true", Note: strings.Join(cs.ScriptFiles, ", ")}},
                                "manifest.json"))
                }
        }
        // Large content scripts (§20 / PERF-005)
        for _, cs := range er.ContentScripts {
                size := int64(0)
                for _, sf := range cs.ScriptFiles {
                        for _, f := range er.Files {
                                if f.Path == sf {
                                        size += f.Size
                                }
                        }
                }
                if size > 512*1024 {
                        findings = append(findings, MakeFinding("PERF-005", "", "high",
                                []Evidence{{File: strings.Join(cs.ScriptFiles, ", "), Note: fmt.Sprintf("Content scripts total %s", humanSize(size))}},
                                "manifest.json"))
                }
        }

        // ---- Background / native messaging (§29) ----
        for _, nm := range er.Background.NativeMsgSites {
                findings = append(findings, MakeFinding("SEC-001", "", "",
                        []Evidence{{File: nm.File, Line: nm.Line, Note: nm.Kind}},
                        findingLocation(nm.File, nm.Line)))
                break // one finding per extension, evidence lists first site
        }
        if len(er.Background.NativeMsgSites) > 1 {
                findings[len(findings)-1].Evidence = append(findings[len(findings)-1].Evidence,
                        Evidence{Note: fmt.Sprintf("%d call sites total", len(er.Background.NativeMsgSites))})
        }

        // ---- Security pattern findings (standard+) ----
        if mode != "quick" {
                // dynamic code execution (§25)
                stringExec := []Evidence{}
                for f, fa := range agg {
                        for _, se := range fa.StringCodeExec {
                                stringExec = append(stringExec, Evidence{File: se.File, Line: se.Line, Note: se.Kind, Excerpt: clampExcerpt(se.Arg)})
                                if len(stringExec) >= 5 {
                                        break
                                }
                        }
                        _ = f
                        if len(stringExec) >= 5 {
                                break
                        }
                }
                if len(stringExec) > 0 {
                        findings = append(findings, MakeFinding("SEC-002", "", "medium", stringExec, findingLocation(stringExec[0].File, stringExec[0].Line)))
                }

                // DOM injection (§26)
                inj := []Evidence{}
                for f, fa := range agg {
                        for _, di := range fa.DomInjections {
                                inj = append(inj, Evidence{File: di.File, Line: di.Line, Note: di.Kind})
                                if len(inj) >= 5 {
                                        break
                                }
                        }
                        _ = f
                        if len(inj) >= 5 {
                                break
                        }
                }
                if len(inj) > 0 {
                        findings = append(findings, MakeFinding("SEC-003", "", "low", inj, findingLocation(inj[0].File, inj[0].Line)))
                }

                // remote code references (§24)
                remote := []Evidence{}
                for _, n := range er.Network {
                        if n.Classification == "CDN" || n.Classification == "unknown" || n.Classification == "third-party" {
                                if isLikelyCodeResource(n.URL) {
                                        remote = append(remote, Evidence{File: n.SourceFile, Line: n.Line, Pattern: clampExcerpt(n.URL)})
                                        if len(remote) >= 4 {
                                                break
                                        }
                                }
                        }
                }
                if len(remote) > 0 {
                        findings = append(findings, MakeFinding("SEC-004", "", "medium", remote, findingLocation(remote[0].File, remote[0].Line)))
                }

                // external handlers (§27–28)
                ext := []Evidence{}
                for f, fa := range agg {
                        for _, h := range fa.ExternalHandlers {
                                ext = append(ext, Evidence{File: h.File, Line: h.Line, Note: h.Kind})
                        }
                        _ = f
                }
                if ec := mi.ExternallyConnectable; ec != nil {
                        origins := stringSlice(ec, "matches")
                        ids := stringSlice(ec, "ids")
                        ext = append(ext, Evidence{Field: "externally_connectable", Note: fmt.Sprintf("matches: %v; ids: %v", origins, ids)})
                }
                if len(ext) > 0 {
                        findings = append(findings, MakeFinding("SEC-005", "", "medium", ext, "manifest.json / source"))
                }

                // secrets (§39)
                if len(secrets) > 0 {
                        ev := []Evidence{}
                        for i, sh := range secrets {
                                if i >= 5 {
                                        ev = append(ev, Evidence{Note: fmt.Sprintf("%d more redacted detections", len(secrets)-5)})
                                        break
                                }
                                ev = append(ev, Evidence{File: sh.File, Line: sh.Line, Note: sh.Kind + " — value redacted"})
                        }
                        findings = append(findings, MakeFinding("SEC-006", "", "medium", ev, findingLocation(secrets[0].File, secrets[0].Line)))
                }

                // web accessible resources (§31)
                if war := mi.WebAccessible; war != nil {
                        jsExposed := 0
                        totalRes := 0
                        for _, r := range war {
                                if rm, ok := r.(map[string]any); ok {
                                        for _, res := range stringSlice(rm, "resources") {
                                                totalRes++
                                                if strings.HasSuffix(res, ".js") {
                                                        jsExposed++
                                                }
                                        }
                                        if m := stringSlice(rm, "matches"); len(m) > 0 && m[0] == "<all_urls>" {
                                                // noted
                                        }
                                } else if s, ok := r.(string); ok {
                                        totalRes++
                                        if strings.HasSuffix(s, ".js") {
                                                jsExposed++
                                        }
                                }
                        }
                        if jsExposed > 0 {
                                findings = append(findings, MakeFinding("SEC-007", "", "high",
                                        []Evidence{{Field: "web_accessible_resources", Note: fmt.Sprintf("%d of %d exposed resources are scripts", jsExposed, totalRes)}},
                                        "manifest.json"))
                        }
                }

                // CSP (§32)
                if mi.CSP != nil {
                        for scope, v := range mi.CSP {
                                if s, ok := v.(string); ok {
                                        if strings.Contains(s, "unsafe-inline") || strings.Contains(s, "unsafe-eval") ||
                                                strings.Contains(s, "http:") || strings.Contains(s, "*") {
                                                findings = append(findings, MakeFinding("SEC-008", "", "high",
                                                        []Evidence{{Field: "content_security_policy." + scope, Pattern: clampExcerpt(s)}},
                                                        "manifest.json"))
                                        }
                                }
                        }
                } else if mi.CSPString != "" && (strings.Contains(mi.CSPString, "unsafe") || strings.Contains(mi.CSPString, "http:")) {
                        findings = append(findings, MakeFinding("SEC-008", "", "high",
                                []Evidence{{Field: "content_security_policy", Pattern: clampExcerpt(mi.CSPString)}},
                                "manifest.json"))
                }
        }

        // ---- Privacy findings (§41) ----
        privacySensitivePerms := []string{"history", "tabs", "cookies", "webRequest", "webNavigation", "clipboardRead", "geolocation", "identity", "identity.email", "topSites", "browsingData", "pageCapture", "desktopCapture", "tabCapture"}
        have := map[string]bool{}
        for _, p := range er.Permissions {
                have[p.Name] = true
        }
        var privEv []Evidence
        for _, sp := range privacySensitivePerms {
                if have[sp] {
                        privEv = append(privEv, Evidence{Field: "permissions: " + sp})
                }
        }
        if len(privEv) > 0 {
                findings = append(findings, MakeFinding("PRIV-001", "", "high", privEv, "manifest.json"))
        }
        if have["cookies"] {
                findings = append(findings, MakeFinding("PRIV-002", "", "high",
                        []Evidence{{Field: "permissions: cookies"}}, "manifest.json"))
        }
        if have["clipboardRead"] || have["clipboardWrite"] {
                findings = append(findings, MakeFinding("PRIV-004", "", "high",
                        []Evidence{{Field: "permissions: clipboard"}}, "manifest.json"))
        }
        if ha.AllSites && len(er.ContentScripts) > 0 {
                findings = append(findings, MakeFinding("PRIV-005", "medium", "high",
                        []Evidence{{Field: "broad host access + content scripts"}}, "manifest.json"))
        }
        if mode != "quick" {
                trackEv := []Evidence{}
                for _, n := range er.Network {
                        if n.Classification == "analytics" || n.Classification == "advertising" || n.Classification == "crash reporting" {
                                trackEv = append(trackEv, Evidence{File: n.SourceFile, Line: n.Line, Pattern: n.Host, Note: n.Classification})
                        }
                }
                if len(trackEv) > 0 {
                        findings = append(findings, MakeFinding("PRIV-003", "", "medium", trackEv, findingLocation(trackEv[0].File, trackEv[0].Line)))
                }
        }

        // ---- Performance findings (§42) ----
        if mode != "quick" {
                smallTimers := []Evidence{}
                for f, fa := range agg {
                        for _, t := range fa.Timers {
                                if t.DelayMS >= 0 && t.DelayMS < 250 {
                                        smallTimers = append(smallTimers, Evidence{File: t.File, Line: t.Line, Note: fmt.Sprintf("%s with %g ms delay", t.Kind, t.DelayMS)})
                                }
                        }
                        _ = f
                        if len(smallTimers) >= 5 {
                                break
                        }
                }
                if len(smallTimers) > 0 {
                        findings = append(findings, MakeFinding("PERF-001", "", "medium", smallTimers, findingLocation(smallTimers[0].File, smallTimers[0].Line)))
                }
                obs := []Evidence{}
                for f, fa := range agg {
                        for _, o := range fa.Observers {
                                if o.Subtree || o.ChildList || o.Attributes {
                                        obs = append(obs, Evidence{File: o.File, Line: o.Line, Note: fmt.Sprintf("MutationObserver (subtree=%v, childList=%v, attributes=%v)", o.Subtree, o.ChildList, o.Attributes)})
                                }
                        }
                        _ = f
                        if len(obs) >= 3 {
                                break
                        }
                }
                if len(obs) > 0 {
                        findings = append(findings, MakeFinding("PERF-002", "", "medium", obs, findingLocation(obs[0].File, obs[0].Line)))
                }
                if er.Background.HasPolling {
                        findings = append(findings, MakeFinding("PERF-003", "", "low",
                                []Evidence{{Note: "interval timers under 5s detected in background code"}}, "background"))
                }
                domHeavy := []Evidence{}
                for f, fa := range agg {
                        if fa.DocQueries >= 10 {
                                domHeavy = append(domHeavy, Evidence{File: f, Note: fmt.Sprintf("%d document-wide DOM queries", fa.DocQueries)})
                        }
                }
                if len(domHeavy) > 0 {
                        findings = append(findings, MakeFinding("PERF-004", "", "low", domHeavy, findingLocation(domHeavy[0].File, 0)))
                }
                // dynamic network destinations (NET-002)
                dyn := []Evidence{}
                for f, fa := range agg {
                        for _, d := range fa.DynamicURLs {
                                dyn = append(dyn, Evidence{File: d.File, Line: d.Line, Note: d.Kind})
                        }
                        _ = f
                        if len(dyn) >= 4 {
                                break
                        }
                }
                if len(dyn) > 0 {
                        findings = append(findings, MakeFinding("NET-002", "", "medium", dyn, findingLocation(dyn[0].File, dyn[0].Line)))
                }
                // raw IP endpoints (NET-003)
                ipEv := []Evidence{}
                for _, n := range er.Network {
                        if n.Classification == "IP address" {
                                ipEv = append(ipEv, Evidence{File: n.SourceFile, Line: n.Line, Pattern: n.Host})
                        }
                }
                if len(ipEv) > 0 {
                        findings = append(findings, MakeFinding("NET-003", "", "medium", ipEv, findingLocation(ipEv[0].File, ipEv[0].Line)))
                }
        }

        // third-party network (NET-001)
        tp := []Evidence{}
        for _, n := range er.Network {
                if n.Classification == "third-party" || n.Classification == "analytics" || n.Classification == "advertising" {
                        tp = append(tp, Evidence{File: n.SourceFile, Line: n.Line, Pattern: n.Host})
                        if len(tp) >= 6 {
                                break
                        }
                }
        }
        if len(tp) > 0 {
                findings = append(findings, MakeFinding("NET-001", "", "medium", tp, findingLocation(tp[0].File, tp[0].Line)))
        }

        // ---- Package findings ----
        if er.Package.FilesSkipped > 0 {
                findings = append(findings, MakeFinding("PKG-002", "", "high",
                        []Evidence{{Note: fmt.Sprintf("%d files exceeded limits", er.Package.FilesSkipped)}}, "package"))
        }
        dupDeps := DetectDuplicateDependencies(er.Dependencies)
        if len(dupDeps) > 0 {
                ev := []Evidence{}
                for _, d := range dupDeps {
                        ev = append(ev, Evidence{Note: fmt.Sprintf("%s appears in %d copies", d.Name, d.Copies)})
                }
                findings = append(findings, MakeFinding("PKG-001", "", "medium", ev, "package"))
        }

        // ---- Readability / obfuscation (§37–38) ----
        if er.Readability.Level == "Low" {
                findings = append(findings, MakeFinding("CODE-001", "", "high",
                        []Evidence{{Note: strings.Join(er.Readability.Indicators, "; ")}}, "package"))
        }
        if er.Readability.Obfuscated {
                findings = append(findings, MakeFinding("CODE-002", "", "medium",
                        []Evidence{{Note: strings.Join(er.Readability.Indicators, "; ")}}, "package"))
        }

        // ---- Compatibility findings (§61, §14) ----
        if mi.Version == 2 {
                findings = append(findings, MakeFinding("COMPAT-001", "high", "high",
                        []Evidence{{Field: "manifest_version: 2"}}, "manifest.json"))
        }
        if mi.Version == 1 {
                findings = append(findings, MakeFinding("COMPAT-001", "critical", "high",
                        []Evidence{{Field: "manifest_version: 1"}}, "manifest.json"))
        }
        if er.Background.Type == "background page" || er.Background.Type == "legacy scripts" {
                findings = append(findings, MakeFinding("COMPAT-002", "", "high",
                        []Evidence{{Field: "background (MV2-style)"}}, "manifest.json"))
        }
        // deprecated APIs
        depAPIs := []Evidence{}
        for _, api := range er.APIs {
                if dep, ok := LookupAPIDeprecation(api.API); ok {
                        depAPIs = append(depAPIs, Evidence{File: strings.Join(api.Files, ", "), Note: fmt.Sprintf("%s — %s (use %s)", api.API, dep.Status, dep.Replacement)})
                }
        }
        if len(depAPIs) > 0 {
                findings = append(findings, MakeFinding("COMPAT-003", "", "medium", depAPIs, findingLocation(depAPIs[0].File, 0)))
        }
        // obsolete fields
        if len(mi.UnknownFields) > 0 {
                findings = append(findings, MakeFinding("COMPAT-004", "", "high",
                        []Evidence{{Field: "unknown fields: " + strings.Join(mi.UnknownFields, ", ")}}, "manifest.json"))
        }
        for field, note := range obsoleteManifestFields {
                if _, ok := mi.Raw[field]; ok {
                        findings = append(findings, MakeFinding("COMPAT-004", "", "high",
                                []Evidence{{Field: field, Note: note}}, "manifest.json"))
                }
        }
        if len(mi.MissingRefs) > 0 {
                ev := []Evidence{}
                for _, r := range mi.MissingRefs {
                        ev = append(ev, Evidence{Field: r, Note: "referenced but not present in package"})
                }
                findings = append(findings, MakeFinding("COMPAT-006", "", "high", ev, "manifest.json"))
        }

        // ---- Maintenance (§62, §107) ----
        developer := false
        for _, inst := range er.Installations {
                if inst.InstallType == "developer" {
                        developer = true
                }
        }
        if developer {
                findings = append(findings, MakeFinding("MAINT-002", "", "high",
                        []Evidence{{Note: "Loaded unpacked or from outside the Chrome Web Store"}}, "installation"))
        }
        findings = append(findings, MakeFinding("MAINT-001", "", "high",
                []Evidence{{Note: "No reliable local signal of maintenance status"}}, "Not available"))

        // ---- Large package (PERF-006) — contextual only ----
        if er.Package.TotalSize > 20*1024*1024 {
                findings = append(findings, MakeFinding("PERF-006", "informational", "high",
                        []Evidence{{Note: fmt.Sprintf("Package size %s", humanSize(er.Package.TotalSize))}}, "package"))
        }

        // ---- Coverage note (§109) is appended in scan.go after coverage is computed ----

        return findings
}

// isLikelyCodeResource checks whether a URL plausibly loads code (§24).
func isLikelyCodeResource(u string) bool {
        l := strings.ToLower(u)
        for _, ext := range []string{".js", ".mjs", ".css", ".wasm"} {
                if strings.Contains(l, ext) {
                        return true
                }
        }
        for _, frag := range []string{"api.js", "sdk.js", "script", "embed"} {
                if strings.Contains(l, frag) {
                        return true
                }
        }
        return false
}
