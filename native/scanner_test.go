package main

// Tests (§136): lexer, manifest, host patterns, path security, archive
// security, secrets, protocol validation, snapshots, network classification,
// LM Studio behavior and end-to-end fixture scans (§137: real output only).

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---- Lexer tests ----

func TestLexerIgnoresPatternsInStringsAndComments(t *testing.T) {
	src := `// eval("in comment")
var s = "setTimeout('evil')";
/* fetch("https://comment.example.com") */
var re = /eval\(.*\)/;
real();`
	fa := AnalyzeJS("t.js", src)
	if len(fa.StringCodeExec) != 0 {
		t.Fatalf("expected no string-code exec from comments/strings, got %v", fa.StringCodeExec)
	}
	if got := fa.URLStrings; len(got) != 0 {
		t.Fatalf("expected no URL strings from comments/strings, got %v", got)
	}
	// regex literal must not break tokenization: real() still detected via APIs absence is fine
}

func TestLexerDetectsRealCalls(t *testing.T) {
	src := "eval(userInput);\nnew Function('a', 'b');\nsetTimeout(\"do()\", 100);\nsetInterval(tick, 10);\nfetch(\"https://api.example.com/v1\");\n"
	fa := AnalyzeJS("t.js", src)
	if len(fa.StringCodeExec) != 3 {
		t.Fatalf("expected 3 string-code exec sites, got %d: %v", len(fa.StringCodeExec), fa.StringCodeExec)
	}
	if len(fa.Timers) != 2 {
		t.Fatalf("expected 2 timers, got %d", len(fa.Timers))
	}
	if len(fa.NetworkCalls) != 1 || fa.NetworkCalls[0].URL != "https://api.example.com/v1" {
		t.Fatalf("network call not detected: %+v", fa.NetworkCalls)
	}
	small := false
	for _, tm := range fa.Timers {
		if tm.DelayMS == 10 {
			small = true
		}
	}
	if !small {
		t.Fatal("10ms interval delay not captured")
	}
}

func TestLexerMutationObserverAndInjection(t *testing.T) {
	src := `const o = new MutationObserver(cb);
o.observe(document.body, {childList: true, subtree: true});
el.innerHTML = userInput;
document.write(data);
el.insertAdjacentHTML("beforeend", html);`
	fa := AnalyzeJS("t.js", src)
	if len(fa.Observers) < 2 {
		t.Fatalf("observer not detected: %+v", fa.Observers)
	}
	obsConfigured := false
	for _, o := range fa.Observers {
		if o.Subtree && o.ChildList {
			obsConfigured = true
		}
	}
	if !obsConfigured {
		t.Fatalf("observe() config flags not parsed: %+v", fa.Observers)
	}
	if len(fa.DomInjections) != 3 {
		t.Fatalf("expected 3 DOM injection sites, got %d: %+v", len(fa.DomInjections), fa.DomInjections)
	}
}

func TestLexerDynamicAccess(t *testing.T) {
	src := "chrome[ns][fn]();\nwindow[\"chrome\"].tabs.query({});"
	fa := AnalyzeJS("t.js", src)
	if len(fa.DynamicAccess) != 1 {
		t.Fatalf("dynamic access not detected: %+v", fa.DynamicAccess)
	}
}

func TestLexerXHRVerbDetection(t *testing.T) {
	src := `const x = new XMLHttpRequest();
x.open("GET", "https://data.example.com/feed");
cache.open();`
	fa := AnalyzeJS("t.js", src)
	found := false
	for _, n := range fa.NetworkCalls {
		if n.Method == "XHR" && n.URL == "https://data.example.com/feed" {
			found = true
		}
	}
	if !found {
		t.Fatalf("XHR URL not detected: %+v", fa.NetworkCalls)
	}
}

func TestLexerTemplateDynamic(t *testing.T) {
	src := "fetch(`https://${host}/api`);\nfetch(url);"
	fa := AnalyzeJS("t.js", src)
	if len(fa.DynamicURLs) != 2 {
		t.Fatalf("dynamic URLs not detected: %+v", fa.DynamicURLs)
	}
}

// ---- Manifest tests ----

func TestManifestValid(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "manifest.json"), `{"manifest_version":3,"name":"T","version":"1.0","permissions":["storage"],"background":{"service_worker":"bg.js"}}`)
	write(t, filepath.Join(dir, "bg.js"), "chrome.runtime.onInstalled.addListener(()=>{});\n")
	mi := ParseManifest(dir)
	if !mi.Valid || mi.Version != 3 || mi.Name != "T" {
		t.Fatalf("bad parse: %+v", mi)
	}
	if len(mi.MissingRefs) != 0 {
		t.Fatalf("unexpected missing refs: %v", mi.MissingRefs)
	}
}

func TestManifestInvalid(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "manifest.json"), `{ nope`)
	mi := ParseManifest(dir)
	if mi.Valid {
		t.Fatal("invalid JSON accepted")
	}
	if mi.ParseError == "" {
		t.Fatal("no parse error recorded")
	}
}

func TestManifestMissing(t *testing.T) {
	mi := ParseManifest(t.TempDir())
	if mi.Valid || !strings.Contains(mi.ParseError, "not found") {
		t.Fatalf("missing manifest not reported: %+v", mi)
	}
}

func TestManifestUnknownFieldsAndMV2(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "manifest.json"), `{"manifest_version":2,"name":"T","version":"1","bogus_field":1,"nacl_modules":[]}`)
	mi := ParseManifest(dir)
	if mi.Version != 2 {
		t.Fatal("MV2 not detected")
	}
	foundUnknown, foundObsolete := false, false
	for _, f := range mi.UnknownFields {
		if f == "bogus_field" {
			foundUnknown = true
		}
	}
	for k := range mi.Raw {
		if k == "nacl_modules" {
			foundObsolete = true
		}
	}
	if !foundUnknown || !foundObsolete {
		t.Fatalf("unknown/obsolete fields not flagged: %v", mi.UnknownFields)
	}
}

// ---- Host pattern tests ----

func TestHostPatternParsing(t *testing.T) {
	hp := ParseHostPattern("<all_urls>")
	if hp.Breadth != "all urls" {
		t.Fatalf("all_urls breadth: %s", hp.Breadth)
	}
	hp = ParseHostPattern("https://*.example.com/*")
	if hp.Breadth != "wildcard subdomain" || hp.Scheme != "https" {
		t.Fatalf("wildcard parse: %+v", hp)
	}
	hp = ParseHostPattern("file:///*")
	if !strings.Contains(hp.Breadth, "local file") && hp.Scheme != "file" {
		t.Fatalf("file scheme parse: %+v", hp)
	}
}

func TestHostAnalysisAllSites(t *testing.T) {
	mi := &ManifestInfo{Raw: map[string]any{
		"host_permissions": []any{"<all_urls>"},
		"permissions":      []any{"storage"},
	}}
	mi.HostPermissions = stringSlice(mi.Raw, "host_permissions")
	mi.Permissions = stringSlice(mi.Raw, "permissions")
	ha := AnalyzeHostPermissions(mi)
	if !ha.AllSites || ha.PatternCount != 1 {
		t.Fatalf("all sites not detected: %+v", ha)
	}
}

// ---- Path security tests (§103) ----

func TestPathValidatorRejectsTraversal(t *testing.T) {
	pv := NewPathValidator()
	if _, err := pv.Validate(`C:\Users\x\..\..\windows\temp`); err == nil {
		t.Fatal("traversal accepted")
	}
	if _, err := pv.Validate(`/home/user/../etc/passwd`); err == nil {
		t.Fatal("unix traversal accepted")
	}
}

func TestPathValidatorRejectsUNC(t *testing.T) {
	pv := NewPathValidator()
	if _, err := pv.Validate(`\\server\share\ext`); err == nil {
		t.Fatal("UNC accepted")
	}
}

func TestPathValidatorRejectsOutsideRoots(t *testing.T) {
	pv := NewPathValidator()
	root := t.TempDir()
	pv.AddRoot(root)
	if _, err := pv.Validate(filepath.Join(root, "sub")); err != nil {
		t.Fatalf("valid path rejected: %v", err)
	}
	if _, err := pv.Validate(filepath.Join(root, "..", "elsewhere")); err == nil {
		t.Fatal("escape via .. accepted (should be rejected before root check)")
	}
}

func TestSafeJoin(t *testing.T) {
	if _, err := safeJoin("/tmp/x", "../evil.txt"); err == nil {
		t.Fatal("traversal accepted")
	}
	if _, err := safeJoin("/tmp/x", "/abs.txt"); err == nil {
		t.Fatal("absolute accepted")
	}
	if _, err := safeJoin("/tmp/x", `C:\evil.txt`); err == nil {
		t.Fatal("drive path accepted")
	}
	p, err := safeJoin("/tmp/x", "ok/deep/file.js")
	if err != nil || !strings.HasPrefix(p, "/tmp/x") {
		t.Fatalf("valid join rejected: %s %v", p, err)
	}
}

// ---- Archive security tests (§104) ----

func makeZip(t *testing.T, entries map[string]string) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestArchiveRejectsTraversal(t *testing.T) {
	data := makeZip(t, map[string]string{"../evil.txt": "boom"})
	dir := t.TempDir()
	limits := DefaultLimits()
	err := extractZipBytes(data, dir, limits, 0)
	if err == nil {
		t.Fatal("traversal entry accepted")
	}
	if fileExists(filepath.Join(dir, "..", "evil.txt")) {
		t.Fatal("file escaped extraction dir")
	}
}

func TestArchiveRejectsZipBomb(t *testing.T) {
	// create an entry with huge declared uncompressed size and high ratio
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.CreateHeader(&zip.FileHeader{
		Name:           "bomb.txt",
		Method:         zip.Deflate,
		CompressedSize64: 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	big := make([]byte, 64*1024*1024) // 64MB of zeros from 1KB-ish compressed
	if _, err := w.Write(big); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	limits := DefaultLimits()
	limits.MaxArchiveExtract = 32 * 1024 * 1024 // 32MB cap
	if err := extractZipBytes(buf.Bytes(), dir, limits, 0); err == nil {
		t.Fatal("zip bomb accepted")
	}
}

func TestCRX3HeaderStrip(t *testing.T) {
	zipBytes := makeZip(t, map[string]string{"manifest.json": `{"manifest_version":3}`})
	crx := &bytes.Buffer{}
	crx.WriteString("Cr24")
	crx.Write([]byte{3, 0, 0, 0})
	var hdr [4]byte
	hdr[0] = byte(8) // fake 8-byte header
	crx.Write(hdr[:])
	crx.WriteString("abcdefgh") // header blob
	crx.Write(zipBytes)
	stripped, err := stripCRXHeader(crx.Bytes())
	if err != nil {
		t.Fatalf("CRX3 strip failed: %v", err)
	}
	if !bytes.HasPrefix(stripped, []byte("PK")) {
		t.Fatal("stripped payload is not a zip")
	}
}

func TestSafeExtractArchiveAcceptsNormalZip(t *testing.T) {
	data := makeZip(t, map[string]string{
		"manifest.json":  `{"manifest_version":3,"name":"Z","version":"1"}`,
		"background.js":  "console.log(1);",
	})
	tmp := filepath.Join(t.TempDir(), "test.zip")
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		t.Fatal(err)
	}
	dir, err := SafeExtractArchive(tmp, DefaultLimits())
	if err != nil {
		t.Fatalf("normal zip rejected: %v", err)
	}
	defer os.RemoveAll(dir)
	if !fileExists(filepath.Join(dir, "manifest.json")) {
		t.Fatal("extracted manifest missing")
	}
}

// ---- Secret tests (§39) ----

func TestSecretDetectionAndRedaction(t *testing.T) {
	src := `const KEY = "AKIAIOSFODNN7EXAMPLE";
const token = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";
password: "supersecret123";`
	hits := DetectSecrets("f.js", src)
	if len(hits) < 2 {
		t.Fatalf("secrets not detected: %+v", hits)
	}
	for _, h := range hits {
		if strings.Contains(h.Kind, "EXAMPLE") || strings.Contains(h.Kind, "ghp") && len(h.Kind) > 40 {
			// kind must be a category, not the value
			t.Fatalf("kind leaks value: %s", h.Kind)
		}
	}
	red := RedactSecrets(src)
	if strings.Contains(red, "AKIAIOSFODNN7EXAMPLE") || strings.Contains(red, "supersecret123") {
		t.Fatalf("redaction failed: %s", red)
	}
}

// ---- Protocol tests (§155–156) ----

func TestProtocolValidation(t *testing.T) {
	if _, err := validateRequest([]byte(`{"requestId":"1","action":"scanAll"}`)); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}
	if _, err := validateRequest([]byte(`{"requestId":"1","action":"execute"}`)); err == nil {
		t.Fatal("unknown action accepted")
	}
	if _, err := validateRequest([]byte(`{"action":"scanAll"}`)); err == nil {
		t.Fatal("missing requestId accepted")
	}
	if _, err := validateRequest([]byte(`not json`)); err == nil {
		t.Fatal("malformed JSON accepted")
	}
}

// ---- Snapshot diff tests (§130) ----

func TestSnapshotDiff(t *testing.T) {
	oldS := &Snapshot{Version: "2.4.1", Permissions: []string{"storage"}, Hosts: []string{"https://a.com/*"}, NetworkHosts: []string{"a.com"}, PackageSize: 1000, FileHashes: map[string]string{"f": "h1"}, FindingIDs: []string{"PERM-001"}}
	newS := &Snapshot{Version: "2.5.0", Permissions: []string{"storage", "tabs"}, Hosts: []string{"https://a.com/*", "https://b.com/*"}, NetworkHosts: []string{"a.com", "analytics.new.com"}, PackageSize: 1000 + 3800000, FileHashes: map[string]string{"f": "h1", "g": "h2"}, FindingIDs: []string{"PERM-001", "HOST-001"}}
	changes := DiffSnapshots(oldS, newS)
	kinds := map[string]bool{}
	for _, c := range changes {
		kinds[c.Kind] = true
	}
	for _, want := range []string{"versionChanged", "permissionAdded", "hostAdded", "domainAdded", "packageGrew", "fileChanged", "findingAppeared"} {
		if !kinds[want] {
			t.Fatalf("missing change kind %s in %+v", want, changes)
		}
	}
}

// ---- Network classification tests (§23) ----

func TestClassifyHost(t *testing.T) {
	if c := classifyHost("www.google-analytics.com", ""); c != "analytics" {
		t.Fatalf("analytics: %s", c)
	}
	if c := classifyHost("localhost", ""); c != "localhost" {
		t.Fatalf("localhost: %s", c)
	}
	if c := classifyHost("8.8.8.8", ""); c != "IP address" {
		t.Fatalf("IP: %s", c)
	}
	if c := classifyHost("api.myownsite.com", "myownsite.com"); c != "first-party" {
		t.Fatalf("first-party: %s", c)
	}
	if c := classifyHost("cdn.jsdelivr.net", ""); c != "CDN" {
		t.Fatalf("CDN: %s", c)
	}
}

// ---- Store tests (§64, §159, §160) ----

func TestStoreRoundtripAndDelete(t *testing.T) {
	t.Setenv("CEA_DATA_DIR", filepath.Join(t.TempDir(), "data"))
	store, err := OpenStore()
	if err != nil {
		t.Fatal(err)
	}
	res := &ScanResult{Scan: Scan{ID: "s1", StartedAt: nowISO(), FinishedAt: nowISO(), Status: "SCAN_OK"},
		Extensions: []ExtensionReport{{ID: "abc", Name: "Test", Version: "1", Analysis: AnalysisState{Status: "SCAN_OK", Coverage: 100}}}}
	store.RecordScan(res)
	if got := store.ListScans(); len(got) != 1 {
		t.Fatalf("scan not stored: %+v", got)
	}
	if _, ok := store.GetExtension("abc"); !ok {
		t.Fatal("extension not stored")
	}
	if err := store.DeleteAllHistory(); err != nil {
		t.Fatal(err)
	}
	if got := store.ListScans(); len(got) != 0 {
		t.Fatalf("history not deleted: %+v", got)
	}
}

// ---- LM Studio tests (§136) ----

func TestLMStudioUnavailable(t *testing.T) {
	client := NewLMClient(LMStudioSettings{BaseURL: "http://127.0.0.1:1", TimeoutSec: 1})
	st := client.Status()
	if st.Reachable {
		t.Fatal("unreachable server considered reachable")
	}
}

func testLMClient(t *testing.T, handler http.HandlerFunc) *LMClient {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return NewLMClient(LMStudioSettings{BaseURL: srv.URL, Model: "test-model", TimeoutSec: 5})
}

func TestLMStudioModelDiscovery(t *testing.T) {
	client := testLMClient(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/v1/models") {
			w.Write([]byte(`{"data":[{"id":"model-a"},{"id":"model-b"}]}`))
			return
		}
		w.WriteHeader(500)
	})
	st := client.Status()
	if !st.Reachable || len(st.Models) != 2 || st.Models[0] != "model-a" {
		t.Fatalf("model discovery failed: %+v", st)
	}
}

func TestLMStudioValidResponse(t *testing.T) {
	client := testLMClient(t, func(w http.ResponseWriter, r *http.Request) {
		resp := `{"choices":[{"message":{"content":"{\"summary\":\"ok\",\"keyConcerns\":[\"broad host access\"],\"positiveFindings\":[\"no dynamic code\"],\"uncertainties\":[],\"plainEnglishExplanation\":\"This extension can read all sites.\",\"questionsForUser\":[]}"}}]}`
		w.Write([]byte(resp))
	})
	sc := &Scanner{Store: &Store{Data: freshStore()}}
	er := &ExtensionReport{ID: "x", Name: "T", Version: "1", Findings: []Finding{{RuleID: "HOST-001", Category: "permissions", Severity: "medium", Confidence: "high", Title: "Broad host access"}}}
	ai := sc.askLM(client, er, "explain")
	if ai == nil || ai.Status != "ok" || ai.Summary != "ok" {
		t.Fatalf("valid AI response not parsed: %+v", ai)
	}
}

func TestLMStudioMalformedThenFallback(t *testing.T) {
	client := testLMClient(t, func(w http.ResponseWriter, r *http.Request) {
		resp := `{"choices":[{"message":{"content":"this is not json at all"}}]}`
		w.Write([]byte(resp))
	})
	sc := &Scanner{Store: &Store{Data: freshStore()}}
	er := &ExtensionReport{ID: "x", Name: "T", Version: "1"}
	ai := sc.askLM(client, er, "explain")
	if ai == nil || ai.Status != "AI_ANALYSIS_FAILED" {
		t.Fatalf("fallback expected, got %+v", ai)
	}
}

func TestLMStudioTimeout(t *testing.T) {
	client := testLMClient(t, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second) // slower than the client timeout
	})
	client.Timeout = 100_000_000 // 100ms
	client.http.Timeout = client.Timeout
	sc := &Scanner{Store: &Store{Data: freshStore()}}
	ai := sc.askLM(client, &ExtensionReport{ID: "x"}, "q")
	if ai == nil || ai.Status != "LM_STUDIO_UNAVAILABLE" {
		t.Fatalf("timeout handling: %+v", ai)
	}
}

func TestAIParseFencedJSON(t *testing.T) {
	raw := "```json\n{\"summary\":\"s\",\"keyConcerns\":[],\"positiveFindings\":[],\"uncertainties\":[],\"plainEnglishExplanation\":\"p\",\"questionsForUser\":[]}\n```"
	ai, err := parseAIJSON(raw)
	if err != nil || ai.Summary != "s" {
		t.Fatalf("fenced JSON not parsed: %v %+v", err, ai)
	}
}

// ---- Evidence payload redaction (§173) ----

func TestEvidencePayloadRedactsSecrets(t *testing.T) {
	er := &ExtensionReport{
		ID: "x", Name: "T", Version: "1", Description: "",
		Findings: []Finding{{RuleID: "SEC-006", Title: "Secret", Severity: "medium", Confidence: "medium",
			Summary: "Found AKIAIOSFODNN7EXAMPLE in source"}},
	}
	payload := BuildEvidencePayload(er)
	if strings.Contains(payload, "AKIAIOSFODNN7EXAMPLE") {
		t.Fatal("secret leaked into LM Studio payload")
	}
}

// ---- End-to-end fixture scans (§137: real scanner output only) ----

func fixtureScan(t *testing.T, name string) *ExtensionReport {
	t.Helper()
	fixRoot, err := filepath.Abs(filepath.Join("..", "fixtures"))
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(fixRoot, name)
	if !fileExists(filepath.Join(dir, "manifest.json")) {
		t.Skipf("fixture %s missing", name)
	}
	t.Setenv("CEA_DATA_DIR", filepath.Join(t.TempDir(), "data"))
	store, _ := OpenStore()
	sc := NewScanner(store)
	de := &DiscoveredExtension{ID: name}
	de.Installations = []ExtensionInstallation{{ProfileID: "test", ProfileName: "Test", Enabled: true, InstallType: "developer", Path: dir}}
	rep, perr := sc.ScanExtension(de, "standard", ScanOptions{Mode: "standard"}, nil, 1, 1)
	if rep == nil {
		t.Fatalf("scan failed: %v", perr)
	}
	return rep
}

func hasFinding(t *testing.T, rep *ExtensionReport, ruleID string) bool {
	t.Helper()
	for _, f := range rep.Findings {
		if f.RuleID == ruleID {
			return true
		}
	}
	return false
}

func TestFixtureContentHeavy(t *testing.T) {
	rep := fixtureScan(t, "04-content-heavy")
	if !hasFinding(t, rep, "CS-001") {
		t.Fatal("CS-001 (content scripts on all sites at document_start) not detected")
	}
	if !hasFinding(t, rep, "CS-002") {
		t.Fatal("CS-002 (all_frames) not detected")
	}
	if !hasFinding(t, rep, "HOST-001") {
		t.Fatal("HOST-001 (broad host access) not detected")
	}
}

func TestFixturePermissionHeavy(t *testing.T) {
	rep := fixtureScan(t, "05-permission-heavy")
	if !hasFinding(t, rep, "PERM-001") {
		t.Fatal("PERM-001 not detected")
	}
	if !hasFinding(t, rep, "PERM-003") {
		t.Fatal("PERM-003 (powerful optional perms) not detected")
	}
	if !hasFinding(t, rep, "PRIV-001") {
		t.Fatal("PRIV-001 not detected")
	}
	if !hasFinding(t, rep, "HOST-002") {
		t.Fatal("HOST-002 (file access) not detected")
	}
	if !hasFinding(t, rep, "HOST-003") {
		t.Fatal("HOST-003 (plain http) not detected")
	}
	// unused permissions: none of these APIs are used in the fixture
	if !hasFinding(t, rep, "PERM-002") {
		t.Fatal("PERM-002 (potentially unused) not detected")
	}
}

func TestFixtureNetworkHeavy(t *testing.T) {
	rep := fixtureScan(t, "06-network-heavy")
	hosts := map[string]string{}
	for _, n := range rep.Network {
		hosts[n.Host] = n.Classification
	}
	if _, ok := hosts["api.example.com"]; !ok {
		t.Fatalf("api host missing: %+v", rep.Network)
	}
	if _, ok := hosts["analytics.example.net"]; !ok {
		t.Fatalf("analytics host missing: %+v", rep.Network)
	}
	if !hasFinding(t, rep, "NET-002") {
		t.Fatal("NET-002 (dynamic destinations) not detected")
	}
	// XHR + WebSocket + sendBeacon + EventSource all detected
	methods := map[string]bool{}
	for _, n := range rep.Network {
		methods[n.Method] = true
	}
	for _, m := range []string{"fetch", "XHR", "WebSocket", "sendBeacon", "EventSource"} {
		if !methods[m] {
			t.Fatalf("method %s not detected: %+v", m, rep.Network)
		}
	}
}

func TestFixtureTimerHeavy(t *testing.T) {
	rep := fixtureScan(t, "07-timer-heavy")
	if !hasFinding(t, rep, "PERF-001") {
		t.Fatal("PERF-001 (small interval timers) not detected")
	}
	if !hasFinding(t, rep, "SEC-002") {
		t.Fatal("SEC-002 (setTimeout with string) not detected")
	}
	if rep.Background.HasPolling != true {
		t.Fatal("background polling not flagged")
	}
}

func TestFixtureObserverHeavy(t *testing.T) {
	rep := fixtureScan(t, "08-observer-heavy")
	if !hasFinding(t, rep, "PERF-002") {
		t.Fatal("PERF-002 (broad MutationObserver) not detected")
	}
	if !hasFinding(t, rep, "PERF-004") {
		t.Fatal("PERF-004 (repeated DOM queries) not detected")
	}
}

func TestFixtureNativeMessaging(t *testing.T) {
	rep := fixtureScan(t, "09-native-messaging")
	if !hasFinding(t, rep, "SEC-001") {
		t.Fatal("SEC-001 (native messaging) not detected")
	}
	if !hasFinding(t, rep, "SEC-005") {
		t.Fatal("SEC-005 (external handlers) not detected")
	}
}

func TestFixtureMalformedManifest(t *testing.T) {
	rep := fixtureScan(t, "10-malformed-manifest")
	if rep.Analysis.Status != "MANIFEST_INVALID" {
		t.Fatalf("status: %s", rep.Analysis.Status)
	}
	if !hasFinding(t, rep, "COMPAT-005") {
		t.Fatal("COMPAT-005 (malformed manifest) not detected")
	}
}

func TestFixtureMissingFiles(t *testing.T) {
	rep := fixtureScan(t, "11-missing-files")
	if !hasFinding(t, rep, "COMPAT-006") {
		t.Fatal("COMPAT-006 (missing referenced files) not detected")
	}
}

func TestFixtureObfuscated(t *testing.T) {
	rep := fixtureScan(t, "12-obfuscated")
	if !rep.Readability.Obfuscated {
		t.Fatalf("obfuscation not detected: %+v", rep.Readability)
	}
	if !hasFinding(t, rep, "CODE-002") {
		t.Fatal("CODE-002 not detected")
	}
	if !hasFinding(t, rep, "SEC-002") {
		t.Fatal("eval in obfuscated fixture not detected")
	}
}

func TestFixtureLargePackage(t *testing.T) {
	rep := fixtureScan(t, "13-large-package")
	if !hasFinding(t, rep, "SEC-007") {
		t.Fatal("SEC-007 (web accessible scripts) not detected")
	}
	if rep.Package.TotalSize < 500000 {
		t.Fatalf("package size not computed: %d", rep.Package.TotalSize)
	}
}

func TestFixtureLegacyMV2(t *testing.T) {
	rep := fixtureScan(t, "14-legacy-mv2")
	if !hasFinding(t, rep, "COMPAT-001") {
		t.Fatal("COMPAT-001 (MV2) not detected")
	}
	if !hasFinding(t, rep, "COMPAT-002") {
		t.Fatal("COMPAT-002 (legacy background) not detected")
	}
	if !hasFinding(t, rep, "COMPAT-003") {
		t.Fatal("COMPAT-003 (deprecated APIs) not detected")
	}
	if !hasFinding(t, rep, "SEC-008") {
		t.Fatal("SEC-008 (relaxed CSP) not detected")
	}
}

func TestFixtureSimpleIsClean(t *testing.T) {
	rep := fixtureScan(t, "01-simple")
	for _, f := range rep.Findings {
		// only informational maintenance findings expected
		if f.Severity != "informational" && f.RuleID != "MAINT-001" && f.RuleID != "MAINT-002" {
			t.Fatalf("unexpected finding on clean fixture: %+v", f)
		}
	}
	if rep.OverallStatus != "Healthy" {
		t.Fatalf("clean fixture not healthy: %s (%+v)", rep.OverallStatus, rep.Findings)
	}
}

func TestFixtureMinifiedReadability(t *testing.T) {
	rep := fixtureScan(t, "03-minified")
	if rep.Readability.Level != "Low" && rep.Readability.Minified != true {
		t.Fatalf("minified fixture readability: %+v", rep.Readability)
	}
	if !hasFinding(t, rep, "CODE-001") {
		t.Fatal("CODE-001 (low readability) not detected")
	}
}

// ---- helpers ----

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

var _ = fmt.Sprintf
var _ = json.Marshal
