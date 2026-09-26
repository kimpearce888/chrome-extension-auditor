package main

// Manifest analysis (§14). Tolerant of malformed manifests: parse failures are
// reported as findings, never crashes (§56).

import (
	"os"
	"path/filepath"
)

type ManifestInfo struct {
	Raw              map[string]any
	Valid            bool
	ParseError       string
	Version          int
	Name             string
	VersionString    string
	Permissions      []string
	OptionalPermissions []string
	HostPermissions  []string
	ContentScripts   []map[string]any
	Background       map[string]any
	Action           map[string]any
	CSP              map[string]any
	CSPString        string
	WebAccessible    []any
	ExternallyConnectable map[string]any
	DeclarativeNetRequest  map[string]any
	Sandbox          map[string]any
	UnknownFields    []string
	MissingRefs      []string
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
	"nacl_modules":      "NaCl (Native Client) was removed from Chrome.",
	"input_components":  "Legacy input API; removed.",
	"app":               "Chrome Apps platform is deprecated.",
	"kiosk":             "Chrome App kiosk mode; platform deprecated.",
	"kiosk_enabled":     "Chrome App kiosk mode; platform deprecated.",
	"file_browser_handlers": "ChromeOS-only legacy app API.",
	"offline_enabled":   "Legacy app field; ignored for extensions.",
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

	if v := toFloat(raw["manifest_version"]); v > 0 {
		mi.Version = int(v)
	}
	mi.Name = jsonString(raw, "name")
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
