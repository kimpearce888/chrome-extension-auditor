package main

// Extension inventory (§9, §11): discovers every extension Chrome exposes via
// its per-profile preference stores, merges the same extension installed in
// multiple profiles, and optionally merges authoritative metadata supplied by
// the auditor extension itself (chrome.management data for the profile it
// runs in).

import (
        "path/filepath"
        "sort"
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
        return byID
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

        if loc := toFloat(sm["location"]); loc >= 0 {
                desc, itype, policy := locationName(loc)
                inst.Location = desc
                inst.InstallType = itype
                inst.InstalledByPolicy = policy
        }

        if p, ok := sm["path"].(string); ok && p != "" {
                if filepath.IsAbs(p) {
                        inst.Path = filepath.Clean(p)
                } else {
                        inst.Path = filepath.Join(userDataDir, p)
                }
        }

        if manifest, ok := sm["manifest"].(map[string]any); ok {
                if v := jsonString(manifest, "version"); v != "Not available" {
                        inst.Version = v
                }
        }
        return inst
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
