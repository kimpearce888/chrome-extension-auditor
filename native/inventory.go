package main

// Extension inventory (§9, §11): discovers every extension Chrome exposes via
// its per-profile preference stores, merges the same extension installed in
// multiple profiles, and optionally merges authoritative metadata supplied by
// the auditor extension itself (chrome.management data for the profile it
// runs in).

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type DiscoveredExtension struct {
	ID            string
	Installations []ExtensionInstallation
}

// DiscoverExtensions walks all profiles and returns extensions keyed by ID.
// mgmtInventory (may be nil) is chrome.management.getAll() output from the
// auditor extension for the profile it is running in; each entry has
// id/name/version/enabled/installType/type etc.
func DiscoverExtensions(profiles []Profile, mgmtInventory []map[string]any) map[string]*DiscoveredExtension {
	byID := map[string]*DiscoveredExtension{}

	getOrCreate := func(id string) *DiscoveredExtension {
		if e, ok := byID[id]; ok {
			return e
		}
		e := &DiscoveredExtension{ID: id}
		byID[id] = e
		return e
	}

	for _, prof := range profiles {
		if !prof.Available {
			continue
		}
		settings := map[string]any{}
		for _, prefName := range []string{"Preferences", "Secure Preferences"} {
			prefs := readPrefJSON(filepath.Join(prof.Dir, prefName))
			if prefs == nil {
				continue
			}
			exts := prefs
			for _, k := range []string{"extensions", "settings"} {
				if m, ok := exts[k].(map[string]any); ok {
					exts = m
				} else {
					exts = nil
					break
				}
			}
			if exts == nil {
				continue
			}
			for id, v := range exts {
				if sm, ok := v.(map[string]any); ok {
					settings[id] = sm
				}
			}
		}
		for id, raw := range settings {
			sm, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			e := getOrCreate(id)
			// Skip our own auditor extension? No — include it; §138 self-audit
			// runs separately, and showing ourselves is honest.
			inst := parseInstallation(id, prof, sm)
			// merge with any management-API info for this profile
			if mgmt := findMgmt(mgmtInventory, id, prof.ID); mgmt != nil {
				mergeMgmtIntoInstall(&inst, mgmt)
			}
			if inst.Path == "" {
				continue // nothing scannable about this entry
			}
			e.Installations = append(e.Installations, inst)
		}

		// management inventory may contain entries not on disk (shouldn't
		// normally happen) — add them so the inventory stays complete.
		for _, mgmt := range mgmtInventory {
			id, _ := mgmt["id"].(string)
			if id == "" {
				continue
			}
			if _, ok := settings[id]; ok {
				continue
			}
			e := getOrCreate(id)
			inst := ExtensionInstallation{
				ProfileID:      prof.ID,
				ProfileName:    prof.Name,
				Enabled:        toBool(mgmt["enabled"]),
				InstallType:    strOr(mgmt["installType"], "Not available"),
				Version:        strOr(mgmt["version"], "Not available"),
				CachedName:     strOr(mgmt["name"], ""),
				Path:           "",
				DisabledReason: "Not available",
				Location:       "From Chrome management API",
			}
			e.Installations = append(e.Installations, inst)
		}
	}

	// Deduplicate installations (same profile listed twice via Preferences +
	// Secure Preferences).
	for _, e := range byID {
		seen := map[string]bool{}
		var dedup []ExtensionInstallation
		for _, inst := range e.Installations {
			key := inst.ProfileID + "|" + inst.Path + "|" + inst.Version
			if seen[key] {
				continue
			}
			seen[key] = true
			dedup = append(dedup, inst)
		}
		sort.Slice(dedup, func(i, j int) bool { return dedup[i].ProfileID < dedup[j].ProfileID })
		e.Installations = dedup
	}

	// Record which resolved package folders actually exist on disk. Preferences
	// entries outlive their folders (uninstall, disable-then-clean, moved
	// profiles), so callers must not assume Path implies a scannable package.
	for _, e := range byID {
		for i := range e.Installations {
			if e.Installations[i].Path != "" {
				if fi, err := os.Stat(e.Installations[i].Path); err == nil && fi.IsDir() {
					e.Installations[i].PathOnDisk = true
				}
			}
		}
	}
	return byID
}

// classifyInstall derives an honest location description and install type for
// one settings entry. The on-disk path shape is the primary signal because it
// is stable across Chrome versions; the preferences "location" code (whose
// meaning has shifted between Chrome releases) breaks ties for downloaded
// packages: under <profile>/Extensions with a component code it is a Chrome
// built-in, otherwise a Web Store install. Absolute paths outside the profile
// are unpacked developer installs.
func classifyInstall(path, userDataDir, profileID string, loc float64) (string, string, bool) {
	locInt := int(loc)
	componentCode := locInt == 5 || locInt == 6 || locInt == 9 || locInt == 10
	if path != "" {
		clean := filepath.Clean(path)
		inProfilePkg := strings.HasPrefix(clean, filepath.Join(userDataDir, profileID, "Extensions")+string(filepath.Separator))
		switch {
		case inProfilePkg && componentCode:
			return "Component (part of Chrome)", "component", false
		case inProfilePkg && locInt == 8:
			return "Managed by policy", "policy", true
		case inProfilePkg:
			return "Installed from Chrome Web Store", "web_store", false
		case strings.Contains(clean, "/google/chrome/resources/"), componentCode:
			return "Component (part of Chrome)", "component", false
		case locInt == 8:
			return "Managed by policy", "policy", true
		default:
			return "Unpacked (developer mode)", "developer", false
		}
	}
	desc, itype, policy := locationName(loc)
	if desc == "Not available" {
		return "Unknown (no package path in preferences)", "unknown", false
	}
	return desc, itype, policy
}

// parseInstallation reads one settings entry from Chrome preferences.
func parseInstallation(id string, prof Profile, sm map[string]any) ExtensionInstallation {
	userDataDir := filepath.Dir(prof.Dir)
	inst := ExtensionInstallation{
		ProfileID:      prof.ID,
		ProfileName:    prof.Name,
		DisabledReason: "Not available",
		InstallType:    "Not available",
		Version:        "Not available",
		Location:       "Not available",
	}

	if st, ok := sm["state"]; ok {
		s := anyToString(st)
		inst.Enabled = s == "1"
	} else {
		inst.Enabled = false
	}

	if reasons, ok := sm["disable_reasons"].([]any); ok && len(reasons) > 0 {
		inst.DisabledReason = disabledReasonName(reasons)
	}

	loc := toFloat(sm["location"])
	if p, ok := sm["path"].(string); ok && p != "" {
		inst.Path = resolveExtensionPath(userDataDir, prof.ID, loc, p)
	}

	desc, itype, policy := classifyInstall(inst.Path, userDataDir, prof.ID, loc)
	inst.Location = desc
	inst.InstallType = itype
	inst.InstalledByPolicy = policy

	// Chrome caches a copy of the manifest in preferences for many entries;
	// its name is an honest fallback when no folder can be read.
	if manifest, ok := sm["manifest"].(map[string]any); ok {
		if v := jsonString(manifest, "version"); v != "Not available" {
			inst.Version = v
		}
		if n := jsonString(manifest, "name"); n != "" && n != "Not available" {
			inst.CachedName = n
		}
	}
	return inst
}

// resolveExtensionPath maps a "path" value from Chrome preferences to an
// absolute on-disk folder. Absolute paths (developer/unpacked installs) are
// used as-is. Relative paths - the normal form for Web Store and sideloaded
// extensions, e.g. "<id>/<version>" - are relative to a per-kind directory
// inside the profile:
//   - normal / store / sideloaded:  <profile>/Extensions/<path>
//   - themes:                       <profile>/Themes/<path>
//   - component (location 4, 9):    <profile>/Component Extensions/<path>
//
// Older layouts stored packages directly under the User Data root. The first
// candidate that exists on disk wins; when none exist, the standard layout
// for the entry's location type is returned so a report can still be produced
// (the caller records PathOnDisk=false and says so in the UI).
func resolveExtensionPath(userDataDir, profileID string, loc float64, p string) string {
	if filepath.IsAbs(p) {
		return filepath.Clean(p)
	}
	var bases []string
	switch int(loc) {
	case 4, 9: // component / external component (Chrome's own pieces)
		bases = []string{"Component Extensions", "Extensions"}
	default:
		bases = []string{"Extensions", "Themes", "Component Extensions"}
	}
	candidates := make([]string, 0, len(bases)+1)
	for _, b := range bases {
		candidates = append(candidates, filepath.Join(userDataDir, profileID, b, p))
	}
	candidates = append(candidates, filepath.Join(userDataDir, p)) // legacy layout
	for _, c := range candidates {
		if fi, err := os.Stat(c); err == nil && fi.IsDir() {
			return filepath.Clean(c)
		}
	}
	return filepath.Clean(filepath.Join(userDataDir, profileID, bases[0], p))
}

// mergeMgmtIntoInstall overlays authoritative management-API values.
func mergeMgmtIntoInstall(inst *ExtensionInstallation, mgmt map[string]any) {
	if v, ok := mgmt["enabled"].(bool); ok {
		inst.Enabled = v
	}
	if v, ok := mgmt["installType"].(string); ok && v != "" {
		inst.InstallType = v
		if v == "development" {
			inst.Location = "Unpacked (developer mode)"
		}
	}
	if v, ok := mgmt["version"].(string); ok && v != "" {
		inst.Version = v
	}
	if v, ok := mgmt["name"].(string); ok && v != "" && inst.CachedName == "" {
		inst.CachedName = v
	}
	if v, ok := mgmt["disabledReason"].(string); ok && v != "" {
		inst.DisabledReason = v
	}
	if b, ok := mgmt["mayDisable"].(bool); ok {
		_ = b
	}
}

func findMgmt(inv []map[string]any, id, profileID string) map[string]any {
	// The management API only sees the profile the auditor runs in; we accept
	// its data once per id (the UI tags which profile it came from elsewhere).
	_ = profileID
	for _, m := range inv {
		if mid, _ := m["id"].(string); mid == id {
			return m
		}
	}
	return nil
}

func toBool(v any) bool {
	b, _ := v.(bool)
	return b
}

// anyToString renders pref scalars (string, json.Number, bool) as text.
func anyToString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case bool:
		if t {
			return "true"
		}
		return "false"
	default:
		return ""
	}
}

func strOr(v any, def string) string {
	if s, ok := v.(string); ok && s != "" {
		return s
	}
	return def
}

// countProfileExtensions counts the unique extension IDs recorded for one
// profile across Preferences and Secure Preferences. Used to fill in
// Profile.ExtensionCount, which discoverProfiles surfaces to the UI.
func countProfileExtensions(prof Profile) int {
	if !prof.Available {
		return 0
	}
	seen := map[string]bool{}
	for _, prefName := range []string{"Preferences", "Secure Preferences"} {
		prefs := readPrefJSON(filepath.Join(prof.Dir, prefName))
		if prefs == nil {
			continue
		}
		exts := prefs
		for _, k := range []string{"extensions", "settings"} {
			m, ok := exts[k].(map[string]any)
			if !ok {
				exts = nil
				break
			}
			exts = m
		}
		if exts == nil {
			continue
		}
		for id := range exts {
			seen[id] = true
		}
	}
	return len(seen)
}

// hasManifest reports whether dir contains a manifest.json (unpacked extension).
func hasManifest(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, "manifest.json"))
	return err == nil
}
