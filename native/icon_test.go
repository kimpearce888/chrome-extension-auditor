package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 1x1 transparent PNG.
const tinyPNGB64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="

func TestReadIconDataURL(t *testing.T) {
	dir := t.TempDir()
	png, err := base64.StdEncoding.DecodeString(tinyPNGB64)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "icon.png"), png, 0o644); err != nil {
		t.Fatal(err)
	}

	// Prefers the 48px entry; a missing smaller entry must not break it.
	raw := map[string]any{"icons": map[string]any{"16": "missing.png", "48": "icon.png"}}
	if got := readIconDataURL(dir, raw); !strings.HasPrefix(got, "data:image/png;base64,") {
		t.Fatalf("expected png data URL, got %q", got)
	}

	// No icon declared -> empty string (UI falls back to an initial).
	if got := readIconDataURL(dir, map[string]any{}); got != "" {
		t.Fatalf("expected empty for missing icons, got %q", got)
	}

	// Path traversal must not escape the package dir.
	evil := map[string]any{"icons": map[string]any{"48": "../../etc/passwd"}}
	if got := readIconDataURL(dir, evil); got != "" {
		t.Fatalf("expected traversal to be rejected, got %q", got)
	}

	// action.default_icon (string form) works too.
	raw2 := map[string]any{"action": map[string]any{"default_icon": "icon.png"}}
	if got := readIconDataURL(dir, raw2); !strings.HasPrefix(got, "data:image/png;base64,") {
		t.Fatalf("expected data URL from action.default_icon, got %q", got)
	}
}
