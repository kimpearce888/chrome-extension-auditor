package main

// Chrome profile discovery (§10). Never assumes only "Default" exists.
// Cross-platform with an override (env/option) so the same code runs in tests
// and on Linux during development.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// chromeUserDataDirs returns candidate Chrome "User Data" directories.
func chromeUserDataDirs(override string) []string {
	if override != "" {
		return []string{override}
	}
	var dirs []string
	if runtime.GOOS == "windows" {
		if la := os.Getenv("LOCALAPPDATA"); la != "" {
			dirs = append(dirs, filepath.Join(la, "Google", "Chrome", "User Data"))
		}
	} else if runtime.GOOS == "darwin" {
		if h, err := os.UserHomeDir(); err == nil {
			dirs = append(dirs, filepath.Join(h, "Library", "Application Support", "Google", "Chrome"))
		}
	} else {
		if h, err := os.UserHomeDir(); err == nil {
			dirs = append(dirs, filepath.Join(h, ".config", "google-chrome"))
		}
	}
	if env := os.Getenv("CEA_CHROME_USER_DATA"); env != "" {
		dirs = append([]string{env}, dirs...)
	}
	return dirs
}

// profileNames reads display names from "Local State" (info_cache).
func profileNames(userDataDir string) map[string]string {
	names := map[string]string{}
	data, err := os.ReadFile(filepath.Join(userDataDir, "Local State"))
	if err != nil {
		return names
	}
	var ls struct {
		Profile struct {
			InfoCache map[string]struct {
				Name string `json:"name"`
			} `json:"info_cache"`
		} `json:"profile"`
	}
	if json.Unmarshal(data, &ls) == nil {
		for dir, info := range ls.Profile.InfoCache {
			if info.Name != "" {
				names[dir] = info.Name
			}
		}
	}
	return names
}

// DiscoverProfiles finds all profiles containing extension data.
func DiscoverProfiles(override string) []Profile {
	var out []Profile
	for _, ud := range chromeUserDataDirs(override) {
		if fi, err := os.Stat(ud); err != nil || !fi.IsDir() {
			continue
		}
		names := profileNames(ud)
		entries, err := os.ReadDir(ud)
		if err != nil {
			out = append(out, Profile{ID: "user-data", Dir: ud, Available: false, Error: "read error"})
			continue
		}
		for _, e := range entries {
			if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
				continue
			}
			pdir := filepath.Join(ud, e.Name())
			hasPrefs := fileExists(filepath.Join(pdir, "Preferences")) ||
				fileExists(filepath.Join(pdir, "Secure Preferences"))
			if !hasPrefs {
				continue
			}
			name := names[e.Name()]
			if name == "" {
				name = e.Name()
			}
			p := Profile{
				ID:        e.Name(),
				Name:      name,
				Dir:       pdir,
				Available: true,
			}
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ID == "Default" {
			return true
		}
		if out[j].ID == "Default" {
			return false
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}

// readPrefJSON loads a Preferences file tolerantly.
func readPrefJSON(path string) map[string]any {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	m, err := decodeJSONMap(data)
	if err != nil {
		return nil
	}
	return m
}

// locationName maps Chrome's internal location codes to honest descriptions.
func locationName(loc float64) (desc string, installType string, byPolicy bool) {
	switch int(loc) {
	case 0:
		return "Internal (installed from Chrome Web Store)", "normal", false
	case 1:
		return "External (preferences file)", "sideloaded", false
	case 2:
		return "External (Windows registry)", "sideloaded", false
	case 3:
		return "Unpacked (developer mode)", "developer", false
	case 4:
		return "Component (part of Chrome)", "other", true
	case 5:
		return "External (downloaded via preferences)", "sideloaded", false
	case 6:
		return "External (policy download)", "policy", true
	case 7:
		return "Command line", "other", false
	case 8:
		return "External (policy)", "policy", true
	case 9:
		return "External component", "other", true
	default:
		return "Not available", "Not available", false
	}
}

// disabledReasonName maps Chrome disable-reason codes where known.
func disabledReasonName(reasons []any) string {
	if len(reasons) == 0 {
		return "Not available"
	}
	var parts []string
	for _, r := range reasons {
		switch int(toFloat(r)) {
		case 0:
			parts = append(parts, "Disabled by user")
		case 1:
			parts = append(parts, "Permissions increase not acknowledged")
		case 2:
			parts = append(parts, "Install not acknowledged")
		case 3:
			parts = append(parts, "Disabled by blacklist / unsafe")
		case 4:
			parts = append(parts, "Disabled by parental controls")
		case 5:
			parts = append(parts, "Unsupported API/maintenance")
		case 6:
			parts = append(parts, "Disabled by policy")
		case 7:
			parts = append(parts, "Reload required")
		case 11:
			parts = append(parts, "Disabled for unsupported manifest version")
		case 12:
			parts = append(parts, "Disabled for incognito correctness")
		case 15:
			parts = append(parts, "Update from new website not acknowledged")
		default:
			parts = append(parts, "Not available")
		}
	}
	return strings.Join(parts, ", ")
}

func toFloat(v any) float64 {
	switch t := v.(type) {
	case float64:
		return t
	case json.Number:
		f, _ := t.Float64()
		return f
	}
	return -1
}
