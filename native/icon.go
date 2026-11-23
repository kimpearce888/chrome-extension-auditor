package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
)

// readIconDataURL reads the extension's own icon from its package and returns
// it as a base64 data URL. The dashboard may NOT load chrome-extension://
// resources of other extensions (they would have to be declared in that
// extension's web_accessible_resources, which we cannot control) — so the
// scanner ships the icon with the report instead. Missing/unreadable icons
// yield "" and the UI falls back to an initial-letter avatar (§9 - honest).
func readIconDataURL(dir string, raw map[string]any) string {
	rel := manifestIconPath(raw)
	if rel == "" {
		return ""
	}
	clean, err := safeJoin(dir, rel)
	if err != nil {
		return ""
	}
	fi, err := os.Stat(clean)
	if err != nil || fi.IsDir() {
		return ""
	}
	const maxIcon = 300 << 10 // keep reports small; real icons are <50KB
	if fi.Size() > maxIcon {
		return ""
	}
	data, err := os.ReadFile(clean)
	if err != nil {
		return ""
	}
	mime := mimeByExt(clean)
	if mime == "" {
		return ""
	}
	return "data:" + mime + ";base64," + base64.StdEncoding.EncodeToString(data)
}

// manifestIconPath picks the icon file from the manifest: "icons" first
// (preferring 48/32px, then any size), then action/browser_action default_icon.
func manifestIconPath(raw map[string]any) string {
	pick := func(m any) string {
		if s, ok := m.(string); ok { // default_icon may be a plain path
			return s
		}
		mm, ok := m.(map[string]any)
		if !ok {
			return ""
		}
		for _, size := range []string{"48", "32", "128", "64", "16"} {
			if p, ok := mm[size].(string); ok && p != "" {
				return p
			}
		}
		for _, p := range mm {
			if s, ok := p.(string); ok && s != "" {
				return s
			}
		}
		return ""
	}
	if p := pick(raw["icons"]); p != "" {
		return p
	}
	for _, key := range []string{"action", "browser_action"} {
		if a, ok := raw[key].(map[string]any); ok {
			if p := pick(a["default_icon"]); p != "" {
				return p
			}
		}
	}
	return ""
}

func mimeByExt(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".png":
		return "image/png"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".webp":
		return "image/webp"
	case ".gif":
		return "image/gif"
	default:
		return ""
	}
}
