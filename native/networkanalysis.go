package main

// Network destination inventory and classification (§22, §23). Destinations
// are extracted from JS strings/tokens, HTML attributes, CSS and manifest
// fields. Third-party is not automatically malicious.

import (
	"net"
	"regexp"
	"strings"
)

var knownClassifications = []struct {
	match []string
	class string
}{
	{[]string{"google-analytics.com", "analytics.google.com", "segment.io", "segment.com", "cdn.segment.com", "mixpanel.com", "amplitude.com", "hotjar.com", "matomo", "plausible.io", "posthog.com", "statsig.com", "heapanalytics.com", "newrelic.com", "nr-data.net"}, "analytics"},
	{[]string{"doubleclick.net", "googlesyndication.com", "googleadservices.com", "adsystem.com", "adservice.google.com", "taboola.com", "outbrain.com", "criteo.com", "adnxs.com", "adform.net", "smartadserver.com", "pubmatic.com", "rubiconproject.com", "openx.net", "moatads.com", "amazon-adsystem.com"}, "advertising"},
	{[]string{"sentry.io", "bugsnag.com", "rollbar.com", "crashlytics.com", "backtrace.io"}, "crash reporting"},
	{[]string{"cdnjs.cloudflare.com", "jsdelivr.net", "unpkg.com", "ajax.googleapis.com", "storage.googleapis.com", "fonts.googleapis.com", "fonts.gstatic.com", "gstatic.com", "cdn.jsdelivr.net", "akamaihd.net", "cloudflare.com", "fastly.net", "kstatic.com"}, "CDN"},
	{[]string{"accounts.google.com", "login.microsoftonline.com", "auth0.com", "okta.com", "login.live.com", "signin.aws.amazon.com"}, "authentication"},
	{[]string{"stripe.com", "js.stripe.com", "paypal.com", "braintreegateway.com", "checkout.com"}, "payment"},
	{[]string{"chrome.google.com", "chromium.org", "developer.chrome.com", "clients2.google.com", "update.googleapis.com", "edgedl.me.gvt1.com"}, "Chrome infrastructure"},
}

// classifyHost assigns a best-effort classification to a host.
func classifyHost(host, firstPartyDomain string) string {
	lh := strings.ToLower(host)
	if lh == "localhost" || lh == "127.0.0.1" || lh == "::1" || lh == "[::1]" || strings.HasPrefix(lh, "127.") || strings.HasPrefix(lh, "localhost:") {
		return "localhost"
	}
	if ip := net.ParseIP(trimPort(lh)); ip != nil {
		return "IP address"
	}
	for _, kc := range knownClassifications {
		for _, m := range kc.match {
			if strings.Contains(lh, m) {
				return kc.class
			}
		}
	}
	if firstPartyDomain != "" {
		fp := strings.ToLower(trimWWW(firstPartyDomain))
		if fp != "" && strings.Contains(lh, fp) {
			return "first-party"
		}
	}
	if looksInternalHost(lh) {
		return "internal"
	}
	return "unknown"
}

func trimPort(h string) string {
	if i := strings.LastIndex(h, ":"); i > strings.LastIndex(h, "]") && i >= 0 {
		// avoid stripping IPv6 colons — only strip ":port" when host has a dot
		if strings.Contains(h[:i], ".") {
			return h[:i]
		}
	}
	return h
}

func trimWWW(h string) string {
	return strings.TrimPrefix(strings.TrimPrefix(h, "http://"), "https://")
}

func looksInternalHost(h string) bool {
	for _, suffix := range []string{".local", ".internal", ".lan", ".corp", ".home"} {
		if strings.HasSuffix(h, suffix) {
			return true
		}
	}
	return strings.HasSuffix(h, ".localdomain")
}

var urlRe = regexp.MustCompile(`(?i)\b(?:https?|wss?)://[^\s"'<>()\[\]{}\\]+`)

// ExtractRawURLs finds URL substrings in any text (fallback for HTML/CSS/JSON).
func ExtractRawURLs(text string) []string {
	m := urlRe.FindAllString(text, -1)
	out := make([]string, 0, len(m))
	for _, u := range m {
		u = strings.TrimRight(u, ".,;:`\"'")
		if len(u) > 8 {
			out = append(out, u)
		}
	}
	return out
}

// urlHostPort extracts host from a URL string (lenient, no net/url needed for
// malformed input).
func urlHostPort(u string) string {
	u = strings.TrimPrefix(strings.TrimPrefix(u, "wss://"), "ws://")
	u = strings.TrimPrefix(strings.TrimPrefix(u, "https://"), "http://")
	if i := strings.IndexAny(u, "/?#"); i >= 0 {
		u = u[:i]
	}
	if i := strings.Index(u, "@"); i >= 0 {
		u = u[i+1:]
	}
	return u
}

var ipRe = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b`)

// urlIsIP reports whether the URL's host is an IP literal.
func urlIsIP(u string) bool {
	h := urlHostPort(u)
	return ipRe.MatchString(h)
}
