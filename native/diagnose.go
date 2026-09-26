package main

// Diagnostics (§135), self-audit (§138, §101, §139, §140) and CLI scan-dir
// mode used by tests and Diagnose.bat.

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// RunDiagnostics prints the §135 checklist.
func RunDiagnostics() {
	fmt.Println("Local Chrome Extension Auditor — Diagnostics")
	fmt.Println(strings.Repeat("-", 52))
	fmt.Printf("Scanner version:  %s (rules %s, analyzers %s)\n", ScannerVersion, ruleSet.RuleSetVersion, AnalyzerVersion)
	fmt.Printf("OS:               %s / %s\n", runtime.GOOS, runtime.GOARCH)

	userData := chromeUserDataDirs("")
	chromeOK := false
	var ud string
	for _, d := range userData {
		if fi, err := os.Stat(d); err == nil && fi.IsDir() {
			chromeOK = true
			ud = d
			break
		}
	}
	passFail("Chrome detected", chromeOK)
	_ = ud

	profiles := DiscoverProfiles("")
	passFail("Chrome profiles detected", len(profiles) > 0)
	for _, p := range profiles {
		fmt.Printf("    profile: %s (%s)\n", p.Name, p.ID)
	}

	byID := DiscoverExtensions(profiles, nil)
	passFail("Extension inventory", true)
	fmt.Printf("    extensions discovered: %d\n", len(byID))

	// native host registration (Windows registry via file presence fallback)
	hostManifest := nativeHostManifestPath()
	registered := fileExists(hostManifest)
	if runtime.GOOS != "windows" {
		fmt.Println("Native host registration: SKIPPED (non-Windows diagnostic run)")
	} else {
		passFail("Native host manifest present", registered)
	}
	passFail("Scanner executable", true)

	store, err := OpenStore()
	passFail("Database", err == nil)
	if err == nil {
		scans := store.ListScans()
		last := "Not available"
		if len(scans) > 0 {
			last = scans[len(scans)-1].FinishedAt
		}
		fmt.Printf("    last scan: %s\n", last)
		fmt.Printf("    known extensions: %d\n", len(store.Data.Extensions))
		fmt.Printf("    data dir: %s\n", DataDir())
	}

	client := NewLMClient(DefaultLMStudio())
	st := client.Status()
	passFail("LM Studio", st.Reachable)
	if st.Reachable {
		fmt.Printf("    models: %s\n", strings.Join(st.Models, ", "))
		passFail("Model", len(st.Models) > 0)
	} else {
		fmt.Printf("    (%s) — static audit remains fully available\n", st.Error)
	}
	fmt.Println()
	fmt.Println("Diagnostics complete. All checks ran locally; nothing was sent anywhere.")
}

func passFail(name string, ok bool) {
	status := "PASS"
	if !ok {
		status = "FAIL"
	}
	fmt.Printf("%-32s %s\n", name+":", status)
}

func nativeHostManifestPath() string {
	if runtime.GOOS == "windows" {
		if la := os.Getenv("LOCALAPPDATA"); la != "" {
			return filepath.Join(la, "Google", "Chrome", "User Data", "NativeMessagingHosts", "com.local.extensionauditor.scanner.json")
		}
	}
	return ""
}

// RunSelfAudit audits the auditor's own extension + native source (§138).
func RunSelfAudit(path string) {
	fmt.Println("Self-audit of the Local Chrome Extension Auditor")
	fmt.Println(strings.Repeat("-", 52))
	issues := 0

	// 1. scan the given directory (extension dist) for network references
	var foundURLs []string
	var remote []string
	var localhost []string
	_ = filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		cat := fileCategory(p)
		if !isTextual(cat) {
			return nil
		}
		if fi, ferr := d.Info(); ferr == nil && fi.Size() > 4*1024*1024 {
			return nil
		}
		data, rerr := os.ReadFile(p)
		if rerr != nil {
			return nil
		}
		src := string(data)
		for _, u := range ExtractRawURLs(src) {
			foundURLs = append(foundURLs, u+"  ["+filepath.Base(p)+"]")
			host := urlHostPort(u)
			if isLocalhostHost(host) {
				localhost = append(localhost, u)
			} else {
				remote = append(remote, u+"  ["+filepath.Base(p)+"]")
			}
		}
		// sourcemap/eval-style checks on JS
		if cat == "javascript" || cat == "typescript" {
			fa := AnalyzeJS(filepath.Base(p), src)
			for _, se := range fa.StringCodeExec {
				fmt.Printf("[ISSUE] dynamic code execution in own code: %s:%d %s\n", se.File, se.Line, se.Kind)
				issues++
			}
		}
		return nil
	})

	fmt.Printf("URL references found: %d\n", len(foundURLs))
	fmt.Printf("  localhost-only:      %d\n", len(localhost))
	for _, u := range uniqStrings(localhost) {
		fmt.Printf("    %s\n", u)
	}
	fmt.Printf("  non-local:           %d\n", len(remote))
	for _, u := range uniqStrings(remote) {
		fmt.Printf("    %s\n", u)
		issues++
	}

	// 2. telemetry/analytics keyword scan (§140)
	keywords := []string{"telemetry", "analytics", "sentry", "segment", "firebase", "supabase", "doubleclick", "googletagmanager"}
	hits := 0
	_ = filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if !isTextual(fileCategory(p)) {
			return nil
		}
		data, rerr := os.ReadFile(p)
		if rerr != nil {
			return nil
		}
		src := strings.ToLower(string(data))
		for _, kw := range keywords {
			if strings.Contains(src, kw) {
				fmt.Printf("[REVIEW] keyword '%s' appears in %s (verify context)\n", kw, filepath.Base(p))
				hits++
			}
		}
		return nil
	})

	if issues == 0 {
		fmt.Println()
		fmt.Println("Self-audit result: PASS — no non-local network references and no dynamic code execution detected.")
	} else {
		fmt.Println()
		fmt.Printf("Self-audit result: ATTENTION — %d issue(s), %d keyword review(s) above.\n", issues, hits)
		os.Exit(1)
	}
}

func isLocalhostHost(h string) bool {
	lh := strings.ToLower(h)
	return lh == "localhost" || strings.HasPrefix(lh, "127.") || strings.HasPrefix(lh, "127.0.0.1") || lh == "[::1]" || lh == "::1"
}

// RunDirScan scans a directory of extension packages (tests, fixtures).
func RunDirScan(dir, chromeUserData, mode, outJSON string) {
	store, err := OpenStore()
	if err != nil {
		fmt.Println("store error:", err)
		os.Exit(1)
	}
	sc := NewScanner(store)

	entries, err := os.ReadDir(dir)
	if err != nil {
		fmt.Println("cannot read dir:", err)
		os.Exit(1)
	}
	var reports []ExtensionReport
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pkg := filepath.Join(dir, e.Name())
		if !fileExists(filepath.Join(pkg, "manifest.json")) {
			continue
		}
		de := &DiscoveredExtension{ID: e.Name()}
		de.Installations = []ExtensionInstallation{{
			ProfileID: "dir", ProfileName: "Directory scan", Enabled: true,
			InstallType: "developer", Version: "Not available", Path: pkg,
		}}
		report, perr := sc.ScanExtension(de, mode, ScanOptions{Mode: mode, ChromeUserData: chromeUserData}, nil, 1, 1)
		if report != nil {
			if perr != nil {
				fmt.Printf("  %s: %s (partial)\n", e.Name(), perr.Message)
			} else {
				fmt.Printf("  %s: %d findings, coverage %.0f%%\n", e.Name(), len(report.Findings), report.Analysis.Coverage)
			}
			reports = append(reports, *report)
		}
	}
	result := ScanResult{
		Scan: Scan{
			ID: newScanID(), StartedAt: nowISO(), FinishedAt: nowISO(), Mode: mode,
			Status: "SCAN_OK", ScannerVersion: ScannerVersion, RuleSetVersion: ruleSet.RuleSetVersion,
			AnalyzerVersion: AnalyzerVersion, OSVersion: osVersion(),
			ExtensionsFound: len(reports),
		},
		Extensions: reports,
	}
	store.RecordScan(&result)
	fmt.Printf("\nScanned %d extension package(s). Results stored locally.\n", len(reports))
	if outJSON != "" {
		if err := os.WriteFile(outJSON, []byte(marshalPretty(result)), 0o600); err != nil {
			fmt.Println("write error:", err)
			os.Exit(1)
		}
		fmt.Println("JSON written to", outJSON)
	}
}
