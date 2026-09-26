package main

// Permission intelligence (§15–§18): risk context, observed usage vs declared
// permissions, optional permission states, and honest "unable to determine"
// handling. Danger classification never comes from the list alone —
// combinations and context are considered (§16).

import (
        "fmt"
        "sort"
        "strings"
)

// permissionUsageAPIs maps permission names to API usage that indicates the
// capability is exercised.
var permissionUsageAPIs = map[string][]string{
        "cookies":      {"chrome.cookies.get", "chrome.cookies.getAll", "chrome.cookies.set", "chrome.cookies.remove"},
        "history":      {"chrome.history.search", "chrome.history.getVisits", "chrome.history.addUrl", "chrome.history.deleteUrl"},
        "bookmarks":    {"chrome.bookmarks.getTree", "chrome.bookmarks.create", "chrome.bookmarks.getRecent", "chrome.bookmarks.search"},
        "tabs":         {"chrome.tabs.query", "chrome.tabs.create", "chrome.tabs.sendMessage", "chrome.tabs.update", "chrome.tabs.get", "chrome.tabs.onUpdated", "chrome.tabs.onActivated"},
        "storage":      {"chrome.storage.local.get", "chrome.storage.local.set", "chrome.storage.sync.get", "chrome.storage.sync.set", "chrome.storage.session.get", "chrome.storage.session.set"},
        "alarms":       {"chrome.alarms.create", "chrome.alarms.onAlarm", "chrome.alarms.clear", "chrome.alarms.get"},
        "idle":         {"chrome.idle.queryState", "chrome.idle.onStateChanged"},
        "contextMenus": {"chrome.contextMenus.create", "chrome.contextMenus.onClicked"},
        "notifications": {"chrome.notifications.create", "chrome.notifications.onClicked"},
        "downloads":    {"chrome.downloads.download", "chrome.downloads.search", "chrome.downloads.onChanged", "chrome.downloads.open"},
        "webRequest":   {"chrome.webRequest.onBeforeRequest", "chrome.webRequest.onBeforeSendHeaders", "chrome.webRequest.onCompleted", "chrome.webRequest.addListener"},
        "webNavigation": {"chrome.webNavigation.onCompleted", "chrome.webNavigation.onBeforeNavigate", "chrome.webNavigation.onDOMContentLoaded"},
        "management":   {"chrome.management.getAll", "chrome.management.get", "chrome.management.setEnabled"},
        "proxy":        {"chrome.proxy.settings"},
        "privacy":      {"chrome.privacy.services", "chrome.privacy.network", "chrome.privacy.websites"},
        "identity":     {"chrome.identity.getAuthToken", "chrome.identity.getProfileUserInfo", "chrome.identity.launchWebAuthFlow"},
        "identity.email": {"chrome.identity.getProfileUserInfo"},
        "nativeMessaging": {"chrome.runtime.connectNative", "chrome.runtime.sendNativeMessage"},
        "scripting":    {"chrome.scripting.executeScript", "chrome.scripting.insertCSS", "chrome.scripting.removeCSS"},
        "declarativeNetRequest": {"chrome.declarativeNetRequest.updateDynamicRules", "chrome.declarativeNetRequest.getDynamicRules", "chrome.declarativeNetRequest.updateSessionRules", "chrome.declarativeNetRequest.getStaticRules"},
        "declarativeNetRequestWithHostAccess": {"chrome.declarativeNetRequest.updateDynamicRules", "chrome.declarativeNetRequest.updateSessionRules"},
        "geolocation":  {"navigator.geolocation.getCurrentPosition", "navigator.geolocation.watchPosition"},
        "clipboardRead":  {"navigator.clipboard.readText", "document.execCommand"},
        "clipboardWrite": {"navigator.clipboard.writeText", "document.execCommand"},
        "topSites":     {"chrome.topSites.get"},
        "sessions":     {"chrome.sessions.getRecentlyClosed", "chrome.sessions.restore"},
        "browsingData": {"chrome.browsingData.remove"},
        "desktopCapture": {"chrome.desktopCapture.chooseDesktopMedia"},
        "tabCapture":   {"chrome.tabCapture.capture"},
        "pageCapture":  {"chrome.pageCapture.saveAsMHTML"},
        "favicon":      {"chrome favicon", "chrome.action.setIcon"},
        "dns":          {"chrome.dns.resolve"},
        "tts":          {"chrome.tts.speak"},
        "system.cpu":   {"chrome.system.cpu.getInfo"},
        "system.memory": {"chrome.system.memory.getInfo"},
        "system.storage": {"chrome.system.storage.getInfo"},
        "system.display": {"chrome.system.display.getInfo"},
        "gcm":          {"chrome.gcm.register", "chrome.gcm.onMessage"},
        "background":   {"chrome.extension.getBackgroundPage"},
        "usb":          {"chrome.usb.getDevices", "chrome.usb.openDevice"},
        "serial":       {"chrome.serial.getDevices", "chrome.serial.connect"},
        "bluetooth":    {"chrome.bluetooth.getDevices", "chrome.bluetooth.getAdapterState"},
        "offscreen":    {"chrome.offscreen.createDocument"},
        "sidePanel":    {"chrome.sidePanel.setOptions", "chrome.sidePanel.open"},
        "userScripts":  {"chrome.userScripts.register"},
}

// clipboard via execCommand("paste")
func clipboardUsed(fa *FileAnalysis) bool {
        if fa.ClipboardCalls > 0 {
                return true
        }
        for api := range fa.APIs {
                if strings.HasPrefix(api, "navigator.clipboard") {
                        return true
                }
        }
        return false
}

// AnalyzePermissions builds the permission report with context (§16).
func AnalyzePermissions(mi *ManifestInfo, aggregated map[string]*FileAnalysis) []PermissionInfo {
        var out []PermissionInfo

        observed := func(perm string) (string, []string) {
                usageAPIs, known := permissionUsageAPIs[perm]
                var evidence []string
                if known {
                        for _, api := range usageAPIs {
                                for _, f := range aggregatedFiles(aggregated) {
                                        fa := aggregated[f]
                                        if n := fa.APIs[api]; n > 0 {
                                                if ev := fa.APIEvidence[api]; len(ev) > 0 {
                                                        evidence = append(evidence, ev[0])
                                                } else {
                                                        evidence = append(evidence, f+":?")
                                                }
                                                break
                                        }
                                }
                        }
                }
                // special cases
                switch perm {
                case "clipboardRead", "clipboardWrite":
                        for _, f := range aggregatedFiles(aggregated) {
                                if clipboardUsed(aggregated[f]) {
                                        evidence = append(evidence, f)
                                        break
                                }
                        }
                case "nativeMessaging":
                        for _, f := range aggregatedFiles(aggregated) {
                                fa := aggregated[f]
                                if len(fa.NativeMsg) > 0 {
                                        evidence = append(evidence, fmt.Sprintf("%s:%d", fa.NativeMsg[0].File, fa.NativeMsg[0].Line))
                                        break
                                }
                        }
                }
                if len(evidence) > 0 {
                        return "detected", evidence
                }
                if known {
                        return "not observed", nil
                }
                return "unable to determine", nil
        }

        addPerm := func(name, source string) {
                pi := PermissionInfo{Name: name, Source: source, GrantedState: "Not available"}
                if source == "required" {
                        pi.GrantedState = "required at install"
                }
                meta, ok := LookupPermission(name)
                if ok {
                        pi.Risk = meta.Risk
                        pi.Description = meta.Description
                        pi.RiskContext = riskContextLabel(meta.Risk)
                        pi.WhyItMatters = meta.WhyItMatters
                } else {
                        pi.Risk = "unknown"
                        pi.RiskContext = "Unknown permission"
                        pi.Description = "Not in the local permission knowledge base."
                        pi.WhyItMatters = "Unable to determine statically."
                }
                usage, ev := observed(name)
                pi.ObservedUse = usage
                pi.Evidence = ev
                out = append(out, pi)
        }

        for _, p := range mi.Permissions {
                addPerm(p, "required")
        }
        for _, p := range mi.OptionalPermissions {
                addPerm(p, "optional")
                if meta, ok := LookupPermission(p); ok && meta.Risk == "high" {
                        // PERM-003 handled by findings builder
                        _ = meta
                }
        }
        sort.Slice(out, func(i, j int) bool {
                ri, rj := riskRank(out[i].Risk), riskRank(out[j].Risk)
                if ri != rj {
                        return ri > rj
                }
                return out[i].Name < out[j].Name
        })
        return out
}

// aggregatedFiles returns the aggregated map's files in stable order.
func aggregatedFiles(aggregated map[string]*FileAnalysis) []string {
        files := make([]string, 0, len(aggregated))
        for f := range aggregated {
                files = append(files, f)
        }
        sort.Strings(files)
        return files
}

func riskContextLabel(risk string) string {
        switch risk {
        case "high":
                return "High-impact capability"
        case "moderate":
                return "Moderate capability"
        case "low":
                return "Low-impact capability"
        }
        return "Unknown capability"
}

func riskRank(risk string) int {
        switch risk {
        case "high":
                return 3
        case "moderate":
                return 2
        case "low":
                return 1
        }
        return 0
}

// HasHighImpactPermission reports whether any required permission is high risk.
func HasHighImpactPermission(perms []PermissionInfo) bool {
        for _, p := range perms {
                if p.Risk == "high" && p.Source == "required" {
                        return true
                }
        }
        return false
}

// ---- Host pattern analysis (§17) ----

type HostAnalysis struct {
        Patterns []HostPatternInfo
        AllSites bool
        FileAccess bool
        Localhost bool
        PlainHTTP bool
        PatternCount int
}

// ParseHostPattern interprets one Chrome match pattern.
func ParseHostPattern(pattern string) HostPatternInfo {
        hp := HostPatternInfo{Pattern: pattern, Scheme: "Not available", Host: "Not available", Breadth: "other"}
        s := pattern
        // scheme
        if i := strings.Index(s, "://"); i > 0 {
                hp.Scheme = s[:i]
                s = s[i+3:]
        } else if s == "<all_urls>" {
                hp.Scheme = "any"
                hp.Host = "any"
                hp.Breadth = "all urls"
                return hp
        }
        // host/path split
        if i := strings.Index(s, "/"); i >= 0 {
                hp.Host = s[:i]
                s = s[i:]
        } else {
                hp.Host = s
                s = "/"
        }
        host := hp.Host
        switch {
        case host == "*":
                hp.Breadth = "wildcard host"
        case strings.HasPrefix(host, "*."):
                hp.Breadth = "wildcard subdomain"
        case host == "":
                hp.Breadth = "other"
        default:
                hp.Breadth = "specific host"
        }
        if hp.Scheme == "any" && (host == "*" || host == "") {
                hp.Breadth = "all urls"
        }
        if hp.Scheme == "file" {
                hp.Breadth = "local file"
        }
        lh := strings.ToLower(host)
        if strings.Contains(lh, "localhost") || strings.HasPrefix(lh, "127.") {
                hp.Breadth = "localhost"
        }
        return hp
}

// AnalyzeHostPermissions processes all host patterns from manifest
// (permissions + host_permissions + content_scripts matches).
func AnalyzeHostPermissions(mi *ManifestInfo) HostAnalysis {
        ha := HostAnalysis{}
        var patterns []string
        patterns = append(patterns, mi.HostPermissions...)
        for _, p := range mi.Permissions {
                if looksLikeHostPattern(p) {
                        patterns = append(patterns, p)
                }
        }
        for _, cs := range mi.ContentScripts {
                for _, m := range stringSlice(cs, "matches") {
                        patterns = append(patterns, m)
                }
        }
        // "optional_host_permissions"
        if mi.Raw != nil {
                patterns = append(patterns, stringSlice(mi.Raw, "optional_host_permissions")...)
        }
        patterns = uniqStrings(patterns)
        ha.PatternCount = len(patterns)

        for _, p := range patterns {
                hp := ParseHostPattern(p)
                if p == "<all_urls>" || strings.EqualFold(p, "*://*/*") || strings.EqualFold(p, "http://*/*,https://*/*") {
                        ha.AllSites = true
                        hp.Breadth = "all urls"
                        hp.Notes = "The extension can potentially interact with pages matching this pattern across all websites."
                }
                if hp.Scheme == "file" || strings.HasPrefix(p, "file://") {
                        ha.FileAccess = true
                }
                if hp.Breadth == "localhost" {
                        ha.Localhost = true
                }
                if hp.Scheme == "http" {
                        ha.PlainHTTP = true
                }
                if sensitiveDomain(hp.Host) {
                        hp.Sensitive = true
                }
                ha.Patterns = append(ha.Patterns, hp)
        }
        sort.Slice(ha.Patterns, func(i, j int) bool {
                return breadthRank(ha.Patterns[i].Breadth) > breadthRank(ha.Patterns[j].Breadth)
        })
        return ha
}

func breadthRank(b string) int {
        switch b {
        case "all urls":
                return 5
        case "wildcard host":
                return 4
        case "wildcard subdomain":
                return 3
        case "local file":
                return 3
        case "localhost":
                return 1
        case "specific host":
                return 2
        }
        return 0
}

// looksLikeHostPattern distinguishes patterns from API permission names.
func looksLikeHostPattern(p string) bool {
        if p == "<all_urls>" {
                return true
        }
        if strings.Contains(p, "://") || strings.Contains(p, "/*") {
                return true
        }
        // "https://example.com/*" always has ://; file:///* too.
        return false
}

var sensitiveHostHints = []string{
        "accounts.google.com", "mail.google.com", "gmail.com", "paypal.com",
        "stripe.com", "login.microsoftonline.com", "outlook.com", "live.com",
        "onlinebanking", "bankof", ".bank.", "chase.com", "wellsfargo.com",
        "citibank.com", "hsbc.com", "americanexpress.com", "discover.com",
        "coinbase.com", "binance.com", "login", "signin", "account",
}

func sensitiveDomain(host string) bool {
        lh := strings.ToLower(host)
        for _, h := range sensitiveHostHints {
                if strings.Contains(lh, strings.TrimPrefix(h, ".")) {
                        return true
                }
        }
        return false
}
