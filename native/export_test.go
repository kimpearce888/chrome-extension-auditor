package main

// Export smoke tests (§65-67): all four formats must produce non-empty local files.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func exportFixtureResult(t *testing.T) *ScanResult {
	rep := fixtureScan(t, "05-permission-heavy")
	return &ScanResult{
		Scan: Scan{
			ID: "exp", StartedAt: nowISO(), FinishedAt: nowISO(), Mode: "standard",
			Status: "SCAN_OK", ProfilesScanned: 1, ExtensionsFound: 1,
			ChromeVersion: "120.0", OSVersion: "Windows", ScannerVersion: ScannerVersion,
			RuleSetVersion: ruleSet.RuleSetVersion, AnalyzerVersion: AnalyzerVersion,
		},
		Profiles:   []Profile{{ID: "Default", Name: "Person 1", Dir: "/x", Available: true}},
		Extensions: []ExtensionReport{*rep},
	}
}

func TestExportJSON(t *testing.T) {
	dir := t.TempDir()
	res := exportFixtureResult(t)
	p := filepath.Join(dir, "r.json")
	if err := exportJSON(p, res, "full"); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(p)
	if len(data) < 1000 || !strings.Contains(string(data), "Permission Heavy") {
		t.Fatalf("json export too small/wrong: %d bytes", len(data))
	}
}

func TestExportCSV(t *testing.T) {
	dir := t.TempDir()
	res := exportFixtureResult(t)
	p := filepath.Join(dir, "r.csv")
	if err := exportCSV(p, res, "findings"); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(p)
	if !strings.Contains(string(data), "Permission Heavy") || !strings.Contains(string(data), "PERM-001") {
		t.Fatalf("csv export missing content")
	}
	if err := exportCSV(filepath.Join(dir, "i.csv"), res, "inventory"); err != nil {
		t.Fatal(err)
	}
}

func TestExportHTMLSelfContained(t *testing.T) {
	dir := t.TempDir()
	res := exportFixtureResult(t)
	p := filepath.Join(dir, "r.html")
	if err := exportHTML(p, res, "full"); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(p)
	s := string(data)
	for _, banned := range []string{"http://cdn", "https://fonts", "https://", "src=\"http"} {
		if strings.Contains(s, banned) && !strings.Contains(s, "127.0.0.1") {
			t.Fatalf("HTML report references remote resources: %s", banned)
		}
	}
	if !strings.Contains(s, "<!DOCTYPE html>") || !strings.Contains(s, "Permission Heavy") {
		t.Fatal("html export malformed")
	}
}

func TestExportPDF(t *testing.T) {
	dir := t.TempDir()
	res := exportFixtureResult(t)
	p := filepath.Join(dir, "r.pdf")
	if err := exportPDF(p, res, "full"); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(p)
	if len(data) < 500 || string(data[:5]) != "%PDF-" {
		t.Fatalf("pdf export invalid: %d bytes, header %q", len(data), string(data[:5]))
	}
	if !strings.Contains(string(data), "%%EOF") {
		t.Fatal("pdf missing EOF marker")
	}
}

func TestRedaction(t *testing.T) {
	res := exportFixtureResult(t)
	res.Profiles[0].Dir = `C:\Users\alice\AppData\Local\Google\Chrome\User Data\Default`
	res.Extensions[0].Installations[0].Path = `C:\Users\alice\Extensions\abc`
	res.Extensions[0].Installations[0].ProfileName = "Alice"
	red := ApplyRedaction(res, DefaultRedaction())
	if strings.Contains(red.Extensions[0].Installations[0].Path, "alice") {
		t.Fatal("username not redacted")
	}
	if strings.Contains(red.Profiles[0].Dir, "alice") {
		t.Fatal("profile path username not redacted")
	}
	if red.Extensions[0].Installations[0].ProfileName == "Alice" {
		t.Fatal("profile name not redacted")
	}
}
