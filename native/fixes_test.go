package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writePrefsFile(t *testing.T, profileDir string, settings map[string]any) {
	t.Helper()
	os.MkdirAll(profileDir, 0o755)
	b, _ := json.Marshal(map[string]any{"extensions": map[string]any{"settings": settings}})
	if err := os.WriteFile(filepath.Join(profileDir, "Preferences"), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func mkProfile(root string) Profile {
	pd := filepath.Join(root, "Default")
	return Profile{ID: "Default", Name: "Default", Dir: pd, Available: true}
}

// Bug 1: __MSG_*__ placeholders must be resolved from _locales before display.
func TestI18nManifestResolution(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "manifest.json"), `{"manifest_version":3,"name":"__MSG_app_name__","description":"__MSG_app_desc__","version":"2.0"}`)
	os.MkdirAll(filepath.Join(dir, "_locales", "en"), 0o755)
	write(t, filepath.Join(dir, "_locales", "en", "messages.json"), `{"app_name":{"message":"Full Page Screenshot & PDF"},"app_desc":{"message":"Capture pages."}}`)
	mi := ParseManifest(dir)
	if !mi.Valid {
		t.Fatalf("parse failed: %+v", mi.ParseError)
	}
	if mi.Name != "Full Page Screenshot & PDF" {
		t.Fatalf("name not resolved: %q", mi.Name)
	}
	if d := mi.resolvedString("description"); d != "Capture pages." {
		t.Fatalf("description not resolved: %q", d)
	}
}

// Bug 2a: component extensions live under Component Extensions/, not Extensions/.
func TestComponentExtensionLayoutAndPathOnDisk(t *testing.T) {
	root := t.TempDir()
	pd := filepath.Join(root, "Default")
	settings := map[string]any{
		"aaaa1111bbbb2222cccc3333dddd4444": map[string]any{
			"location": 1, "state": 1,
			"path": "aaaa1111bbbb2222cccc3333dddd4444/1.0",
		},
		"eeee5555ffff6666gggg7777hhhh8888": map[string]any{
			"location": 4, "state": 1,
			"path": "eeee5555ffff6666gggg7777hhhh8888/2.0",
		},
	}
	writePrefsFile(t, pd, settings)
	for _, base := range []string{"Extensions/aaaa1111bbbb2222cccc3333dddd4444/1.0", "Component Extensions/eeee5555ffff6666gggg7777hhhh8888/2.0"} {
		d := filepath.Join(pd, base)
		os.MkdirAll(d, 0o755)
		write(t, filepath.Join(d, "manifest.json"), `{"manifest_version":3,"name":"X","version":"1.0"}`)
	}
	found := DiscoverExtensions([]Profile{mkProfile(root)}, nil)
	if len(found) != 2 {
		t.Fatalf("expected 2 extensions, got %d", len(found))
	}
	comp := found["eeee5555ffff6666gggg7777hhhh8888"]
	if comp == nil || len(comp.Installations) != 1 {
		t.Fatalf("component extension not discovered: %+v", comp)
	}
	inst := comp.Installations[0]
	if !strings.Contains(inst.Path, "Component Extensions") {
		t.Fatalf("component path resolved to wrong base: %q", inst.Path)
	}
	if !inst.PathOnDisk {
		t.Fatal("PathOnDisk false for existing folder")
	}
	norm := found["aaaa1111bbbb2222cccc3333dddd4444"]
	if norm == nil || !norm.Installations[0].PathOnDisk {
		t.Fatalf("normal extension wrong: %+v", norm)
	}
}

// Bug 2b: preferences entries whose folder is gone must be reported honestly,
// never as fake zero-coverage audits.
func TestLeftoverPrefsEntryIsNotOnDisk(t *testing.T) {
	root := t.TempDir()
	pd := filepath.Join(root, "Default")
	settings := map[string]any{
		"ghost000000000000000000000000000": map[string]any{
			"location": 1, "state": 1,
			"path":     "ghost000000000000000000000000000/9.9",
			"manifest": map[string]any{"name": "Ghost Extension", "version": "9.9"},
		},
	}
	writePrefsFile(t, pd, settings) // folder intentionally NOT created
	found := DiscoverExtensions([]Profile{mkProfile(root)}, nil)
	de := found["ghost000000000000000000000000000"]
	if de == nil {
		t.Fatal("leftover entry not discovered")
	}
	if de.Installations[0].PathOnDisk {
		t.Fatal("PathOnDisk true for missing folder")
	}
	if de.Installations[0].CachedName != "Ghost Extension" {
		t.Fatalf("cached name not picked up: %q", de.Installations[0].CachedName)
	}
	rep, _ := NewScanner(nil).ScanExtension(de, "quick", ScanOptions{}, nil, 0, 1)
	if rep.Analysis.Status != "NOT_ON_DISK" {
		t.Fatalf("status = %q, want NOT_ON_DISK", rep.Analysis.Status)
	}
	if rep.OverallStatus != "Not Analyzed" {
		t.Fatalf("overall = %q, want Not Analyzed", rep.OverallStatus)
	}
	if rep.Name != "Ghost Extension" {
		t.Fatalf("name = %q, want cached name", rep.Name)
	}
}
