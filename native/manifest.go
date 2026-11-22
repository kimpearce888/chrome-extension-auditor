package main

// Manifest analysis (§14). Tolerant of malformed manifests: parse failures are
// reported as findings, never crashes (§56).

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

type ManifestInfo struct {
	Raw                   map[string]any
	Valid                 bool
	ParseError            string
	Version               int
	Name                  string
	VersionString         string
	Permissions           []string
	OptionalPermissions   []string
	HostPermissions       []string
	ContentScripts        []map[string]any
	Background            map[string]any
	Action                map[string]any
	CSP                   map[string]any
	CSPString             string
	WebAccessible         []any
	ExternallyConnectable map[string]any
	DeclarativeNetRequest map[string]any
	Sandbox               map[string]any
	UnknownFields         []string
	MissingRefs           []string

	// UnresolvedMessages lists __MSG_*__ keys with no entry in the extension's
	// _locales messages file (reported, never invented — §9).
	UnresolvedMessages []string

	// resolved is a deep copy of Raw with whole-string __MSG_key__ placeholders
	// replaced by their localized text. Raw stays untouched.
	resolved map[string]any
}

// resolvedString reads a field from the i18n-resolved manifest copy.
func (mi *ManifestInfo) resolvedString(key string) string {
	if mi.resolved != nil {
		return jsonString(mi.resolved, key)
	}
	return ""
}

// Key must end in an alphanumeric so the closing "__" is never swallowed
// into the capture group (greedy [A-Za-z0-9_]+ matched "app_name__").
var msgPlaceholderRe = regexp.MustCompile(`^__MSG_([A-Za-z0-9]+(?:_[A-Za-z0-9]+)*)__(\([^)]*\))?$`)
var localeNameRe = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// loadLocaleMessages reads _locales/<locale>/messages.json, Chrome's store for
// __MSG_*__ manifest placeholders. Preference order: the manifest's
// default_locale, then en / en_US / en_GB, then any available locale.
// Returns nil when no messages file can be read (nothing is invented).
func loadLocaleMessages(dir, defaultLocale string) map[string]string {
	localesDir := filepath.Join(dir, "_locales")
	candidates := []string{}
	if defaultLocale != "" && defaultLocale != "Not available" {
		candidates = append(candidates, defaultLocale)
	}
	candidates = append(candidates, "en", "en_US", "en_GB")
	if entries, err := os.ReadDir(localesDir); err == nil {
		names := []string{}
		for _, e := range entries {
			if e.IsDir() {
				names = append(names, e.Name())
			}
		}
		sort.Strings(names)
		candidates = append(candidates, names...)
	}
	for _, loc := range candidates {
		if !localeNameRe.MatchString(loc) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(localesDir, loc, "messages.json"))
		if err != nil {
			continue
		}
		var raw map[string]any
		if json.Unmarshal(data, &raw) != nil {
			continue
		}
		msgs := make(map[string]string, len(raw))
		for k, v := range raw {
			switch m := v.(type) {
			case map[string]any:
				if s, ok := m["message"].(string); ok {
					msgs[k] = s
				}
			case string:
				msgs[k] = m
			}
		}
		if len(msgs) > 0 {
			return msgs
		}
	}
	return nil
}

// resolveManifestPlaceholders deep-copies raw and replaces every whole-string
// __MSG_key__ placeholder with its localized message. Keys without a message
// entry are kept as-is and reported in the returned list.
func resolveManifestPlaceholders(raw map[string]any, msgs map[string]string) (map[string]any, []string) {
	unresolved := map[string]bool{}
	// Some extensions name placeholder keys in a different case than the
	// message file (e.g. __MSG_APP_NAME__ vs "app_name"); fall back to a
	// case-insensitive lookup before giving up.
	lowerMsgs := make(map[string]string, len(msgs))
	for k, v := range msgs {
		if _, exists := lowerMsgs[strings.ToLower(k)]; !exists {
			lowerMsgs[strings.ToLower(k)] = v
		}
	}
	var walk func(v any) any
	walk = func(v any) any {
		switch t := v.(type) {
		case string:
			if m := msgPlaceholderRe.FindStringSubmatch(t); m != nil {
				s, ok := msgs[m[1]]
				if !ok {
					s, ok = lowerMsgs[strings.ToLower(m[1])]
				}
				if ok {
					return s
				}
				unresolved[m[1]] = true
				return t
			}
			return v
		case map[string]any:
			out := make(map[string]any, len(t))
			for k, val := range t {
				out[k] = walk(val)
			}
			return out
		case []any:
			out := make([]any, len(t))
			for i, val := range t {
				out[i] = walk(val)
			}
			return out
		default:
			return v
		}
	}
	resolved, ok := walk(raw).(map[string]any)
	if !ok {
		resolved = raw
	}
	keys := make([]string, 0, len(unresolved))
	for k := range unresolved {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return resolved, keys
}

// knownManifestFields — used to detect unknown/obsolete fields (COMPAT-004).
var knownManifestFields = map[string]bool{
	"manifest_version": true, "name": true, "short_name": true, "version": true,
	"default_locale": true, "description": true, "icons": true,
	"action": true, "browser_action": true, "page_action": true,
	"background": true, "content_scripts": true, "content_security_policy": true,
	"options_page": true, "options_ui": true, "permissions": true,
	"optional_permissions": true, "host_permissions": true,
	"devtools_page": true, "web_accessible_resources": true,
	"externally_connectable": true, "commands": true, "minimum_chrome_version": true,
	"oauth2": true, "offline_enabled": true, "incognito": true,
	"update_url": true, "key": true, "sandbox": true, "app": true,
	"declarative_net_request": true, "declarativeNetRequest": true,
	"chrome_settings_overrides": true, "chrome_url_overrides": true,
	"storage": true, "tts_engine": true, "input_components": true,
	"file_browser_handlers": true, "file_handlers": true,
	"nacl_modules": true, "platforms": true, "requirements": true,
	"conversion_headers": true, "import": true, "export": true,
	"differential_fingerprint": true, "side_panel": true, "user_scripts": true,
	"webview": true, "kiosk": true, "kiosk_enabled": true, "bluetooth": true,
	"usb_printers": true, "notebook": true, "cross_origin_embedders_policy": true,
	"cross_origin_opener_policy": true, "use_dynamic_url": true,
	"homepage_url": true, "author": true, "browser_specific_settings": true,
}

// obsoleteManifestFields — fields meaningful only for old platforms.
var obsoleteManifestFields = map[string]string{
	"nacl_modules":          "NaCl (Native Client) was removed from Chrome.",
	"input_components":      "Legacy input API; removed.",
	"app":                   "Chrome Apps platform is deprecated.",
	"kiosk":                 "Chrome App kiosk mode; platform deprecated.",
	"kiosk_enabled":         "Chrome App kiosk mode; platform deprecated.",
	"file_browser_handlers": "ChromeOS-only legacy app API.",
	"offline_enabled":       "Legacy app field; ignored for extensions.",
}

// ParseManifest reads and summarizes manifest.json from a package dir.
func ParseManifest(dir string) *ManifestInfo {
	mi := &ManifestInfo{Version: -1}
	data, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		if os.IsNotExist(err) {
			mi.ParseError = "manifest.json not found"
		} else {
			mi.ParseError = "manifest.json unreadable: " + err.Error()
		}
		return mi
	}
	raw, err := decodeJSONMap(data)
	if err != nil {
		mi.ParseError = "manifest.json is not valid JSON: " + err.Error()
		return mi
	}
	mi.Raw = raw
	mi.Valid = true
	if msgs := loadLocaleMessages(dir, jsonString(raw, "default_locale")); msgs != nil {
		resolved, unresolved := resolveManifestPlaceholders(raw, msgs)
		mi.resolved = resolved
		mi.UnresolvedMessages = unresolved
	} else {
		mi.resolved = raw
	}

	if v := toFloat(raw["manifest_version"]); v > 0 {
		mi.Version = int(v)
	}
	mi.Name = jsonString(mi.resolved, "name")
	mi.VersionString = jsonString(raw, "version")
	mi.Permissions = stringSlice(raw, "permissions")
	mi.OptionalPermissions = stringSlice(raw, "optional_permissions")
	mi.HostPermissions = stringSlice(raw, "host_permissions")

	if cs, ok := raw["content_scripts"].([]any); ok {
		for _, c := range cs {
			if cm, ok := c.(map[string]any); ok {
				mi.ContentScripts = append(mi.ContentScripts, cm)
			}
		}
	}
	if bg, ok := raw["background"].(map[string]any); ok {
		mi.Background = bg
	}
	if a, ok := raw["action"].(map[string]any); ok {
		mi.Action = a
	}
	if csp, ok := raw["content_security_policy"].(map[string]any); ok {
		mi.CSP = csp
	} else if s, ok := raw["content_security_policy"].(string); ok {
		mi.CSPString = s
	}
	if war, ok := raw["web_accessible_resources"].([]any); ok {
		mi.WebAccessible = war
	}
	if ec, ok := raw["externally_connectable"].(map[string]any); ok {
		mi.ExternallyConnectable = ec
	}
	if dnr, ok := raw["declarative_net_request"].(map[string]any); ok {
		mi.DeclarativeNetRequest = dnr
	}
	if sb, ok := raw["sandbox"].(map[string]any); ok {
		mi.Sandbox = sb
	}

	for k := range raw {
		if !knownManifestFields[k] {
			mi.UnknownFields = append(mi.UnknownFields, k)
		}
	}

	// Referenced-file existence check (COMPAT-006) — quick, cheap, honest.
	mi.MissingRefs = findMissingRefs(dir, raw)
	return mi
}

// findMissingRefs verifies that scripts/pages referenced by the manifest exist.
func findMissingRefs(dir string, raw map[string]any) []string {
	var missing []string
	check := func(rel string) {
		if rel == "" {
			return
		}
		clean, err := safeJoin(dir, rel)
		if err != nil {
			return
		}
		if _, err := os.Stat(clean); err != nil {
			missing = append(missing, rel)
		}
	}
	if bg, ok := raw["background"].(map[string]any); ok {
		if sw, ok := bg["service_worker"].(string); ok {
			check(sw)
		}
		if scripts, ok := bg["scripts"].([]any); ok {
			for _, s := range scripts {
				if str, ok := s.(string); ok {
					check(str)
				}
			}
		}
		if p, ok := bg["page"].(string); ok {
			check(p)
		}
	}
	if cs, ok := raw["content_scripts"].([]any); ok {
		for _, c := range cs {
			cm, ok := c.(map[string]any)
			if !ok {
				continue
			}
			for _, s := range stringSlice(cm, "js") {
				check(s)
			}
			for _, s := range stringSlice(cm, "css") {
				check(s)
			}
		}
	}
	if a, ok := raw["action"].(map[string]any); ok {
		if p, ok := a["default_popup"].(string); ok {
			check(p)
		}
	}
	if p, ok := raw["options_page"].(string); ok {
		check(p)
	}
	if oui, ok := raw["options_ui"].(map[string]any); ok {
		if p, ok := oui["page"].(string); ok {
			check(p)
		}
	}
	if sp, ok := raw["side_panel"].(map[string]any); ok {
		if p, ok := sp["default_path"].(string); ok {
			check(p)
		}
	}
	return missing
}
