package main

// Analyzers: background/service worker (§21), content scripts (§19–20),
// network inventory (§22–23), and the consolidated findings builder that maps
// analyzer output to rule-based findings.

import (
	"fmt"
	"sort"
	"strings"
)

// buildBackground summarizes the background/service-worker architecture.
func buildBackground(mi *ManifestInfo, agg map[string]*FileAnalysis) BackgroundInfo {
	bi := BackgroundInfo{Type: "none"}
	bg := mi.Background
	if bg != nil {
		if sw, ok := bg["service_worker"].(string); ok {
			bi.Type = "service worker"
			bi.WorkerFile = sw
		} else if _, ok := bg["page"].(string); ok {
			bi.Type = "background page"
			bi.Scripts = stringSlice(bg, "scripts")
			if pers, ok := jsonBool(bg, "persistent"); ok {
				if pers {
					bi.Persistent = "true"
				} else {
					bi.Persistent = "false"
				}
			}
		} else if len(stringSlice(bg, "scripts")) > 0 {
			bi.Type = "legacy scripts"
			bi.Scripts = stringSlice(bg, "scripts")
		}
	}
	// aggregate background-file behaviors
	for f, fa := range agg {
		if bi.WorkerFile != "" && !strings.HasPrefix(f, bi.WorkerFile) && !isBackgroundish(f) {
			continue
		}
		if len(fa.NativeMsg) > 0 {
			bi.HasNative = true
			bi.NativeMsgSites = append(bi.NativeMsgSites, fa.NativeMsg...)
		}
		bi.Timers = append(bi.Timers, fa.Timers...)
		for _, t := range fa.Timers {
			if t.Interval && t.DelayMS >= 0 && t.DelayMS < 5000 {
				bi.HasPolling = true
			}
		}
		for api := range fa.APIs {
			if strings.HasPrefix(api, "chrome.alarms") {
				bi.HasAlarms = true
			}
			if strings.HasPrefix(api, "chrome.") && strings.Contains(api, ".addListener") {
				bi.HasListeners++
			}
		}
		if len(fa.MessageHandlers) > 0 {
			bi.HasListeners += len(fa.MessageHandlers)
		}
	}
	return bi
}

func isBackgroundish(f string) bool {
	lf := strings.ToLower(f)
	return strings.Contains(lf, "background") || strings.Contains(lf, "sw") || strings.Contains(lf, "service") || strings.Contains(lf, "worker")
}

// buildContentScripts summarizes content-script declarations (§19).
func buildContentScripts(mi *ManifestInfo) []ContentScriptInfo {
	var out []ContentScriptInfo
	for _, cs := range mi.ContentScripts {
		matches := stringSlice(cs, "matches")
		globs := stringSlice(cs, "include_globs")
		exMatches := stringSlice(cs, "exclude_matches")
		exGlobs := stringSlice(cs, "exclude_globs")
		runAt := strOr2(anyToString(cs["run_at"]), "document_idle")
		allFrames := false
		if b, ok := jsonBool(cs, "all_frames"); ok {
			allFrames = b
		}
		mab := false
		if b, ok := jsonBool(cs, "match_about_blank"); ok {
			mab = b
		}
		world := strOr2(anyToString(cs["world"]), "Not available")
		js := stringSlice(cs, "js")
		css := stringSlice(cs, "css")
		broad := false
		for _, m := range matches {
			if m == "<all_urls>" || strings.Contains(m, "*/*") {
				broad = true
			}
		}
		out = append(out, ContentScriptInfo{
			Matches: matches, IncludeGlobs: globs, ExcludeMatch: exMatches, ExcludeGlobs: exGlobs,
			RunAt: runAt, AllFrames: allFrames, MatchAboutBlank: mab, World: world,
			ScriptFiles: js, CssFiles: css, ScriptCount: len(js), Broad: broad,
		})
	}
	return out
}

// buildNetworkInventory creates the destination list (§22–23).
func buildNetworkInventory(er *ExtensionReport, mi *ManifestInfo, agg map[string]*FileAnalysis, pkgPath string) []NetworkEndpoint {
	firstParty := ""
	if er.HomepageURL != "Not available" && er.HomepageURL != "" {
		firstParty = urlHostPort(er.HomepageURL)
	}
	var endpoints []NetworkEndpoint
	seen := map[string]bool{}

	addEndpoint := func(host, url, protocol, file string, line int, method string) {
		if host == "" || host == "Not available" {
			return
		}
		key := host + "|" + file + "|" + fmt.Sprint(line)
		if seen[key] {
			return
		}
		seen[key] = true
		class := classifyHost(host, firstParty)
		if class == "unknown" && firstParty != "" && host != firstParty {
			class = "third-party"
		}
		endpoints = append(endpoints, NetworkEndpoint{
			Host: host, URL: clampExcerpt(url), Protocol: protocol,
			SourceFile: file, Line: line, Classification: class, Method: method,
		})
	}

	for _, fa := range agg {
		for _, nc := range fa.NetworkCalls {
			if nc.URL != "" {
				addEndpoint(urlHostPort(nc.URL), nc.URL, schemeOf(nc.URL), nc.File, nc.Line, nc.Method)
			}
		}
		for _, us := range fa.URLStrings {
			addEndpoint(urlHostPort(us.Arg), us.Arg, schemeOf(us.Arg), us.File, us.Line, "literal")
		}
	}
	// manifest URLs
	for _, m := range mi.HostPermissions {
		_ = m // host permissions are capabilities, not network destinations
	}
	if mi.Raw != nil {
		for _, field := range []string{"homepage_url", "update_url"} {
			if v := jsonString(mi.Raw, field); v != "Not available" && looksLikeURL(v) {
				addEndpoint(urlHostPort(v), v, schemeOf(v), "manifest.json", 0, "manifest")
			}
		}
	}
	sort.Slice(endpoints, func(i, j int) bool {
		if endpoints[i].Classification != endpoints[j].Classification {
			return endpoints[i].Classification < endpoints[j].Classification
		}
		return endpoints[i].Host < endpoints[j].Host
	})
	return endpoints
}

func schemeOf(u string) string {
	switch {
	case strings.HasPrefix(u, "https://"):
		return "HTTPS"
	case strings.HasPrefix(u, "http://"):
		return "HTTP"
	case strings.HasPrefix(u, "wss://"):
		return "WSS"
	case strings.HasPrefix(u, "ws://"):
		return "WS"
	}
	return "Not available"
}
