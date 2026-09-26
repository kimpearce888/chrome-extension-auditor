package main

// Report export (§65–§67, §124, §164): JSON, CSV, self-contained HTML and a
// local text-based PDF. All generation is local; reports honor redaction
// options; secrets are always redacted.

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type RedactionOptions struct {
	RedactUsernames   bool `json:"redactUsernames"`
	RedactPaths       bool `json:"redactPaths"`
	RedactSecrets     bool `json:"redactSecrets"` // always effectively true
	RedactProfileNames bool `json:"redactProfileNames"`
}

func DefaultRedaction() RedactionOptions {
	return RedactionOptions{RedactUsernames: true, RedactPaths: true, RedactSecrets: true, RedactProfileNames: true}
}

// ApplyRedaction sanitizes a scan result copy per §164.
func ApplyRedaction(res *ScanResult, ro RedactionOptions) *ScanResult {
	cp := *res
	profiles := make([]Profile, len(res.Profiles))
	for i, p := range res.Profiles {
		if ro.RedactProfileNames {
			p.Name = "Profile " + p.ID
		}
		if ro.RedactPaths {
			p.Dir = redactUserPath(p.Dir)
		}
		profiles[i] = p
	}
	cp.Profiles = profiles

	exts := make([]ExtensionReport, len(res.Extensions))
	for i := range res.Extensions {
		e := res.Extensions[i]
		insts := make([]ExtensionInstallation, len(e.Installations))
		for j, inst := range e.Installations {
			if ro.RedactPaths && inst.Path != "" {
				inst.Path = redactUserPath(inst.Path)
			}
			if ro.RedactProfileNames {
				inst.ProfileName = "Profile " + inst.ProfileID
			}
			insts[j] = inst
		}
		e.Installations = insts
		exts[i] = e
	}
	cp.Extensions = exts
	return &cp
}

// exportReport handles the exportReport action.
func (h *Host) exportReport(opts map[string]any) (map[string]any, *ProtocolError) {
	format := strings.ToLower(optString(opts, "format"))
	switch format {
	case "json", "csv", "html", "pdf":
	default:
		return nil, &ProtocolError{Code: "SCAN_FAILED", Message: "unsupported format: " + format + " (use json|csv|html|pdf)"}
	}
	scanID := optString(opts, "scanId")
	scope := optString(opts, "scope") // full | extension | findings | inventory
	extID := optString(opts, "extensionId")

	res := h.store.GetScanResult(scanID)
	if res == nil {
		res = h.store.GetScanResult(h.store.Data.LastScanID)
	}
	if res == nil {
		return nil, &ProtocolError{Code: "SCAN_FAILED", Message: "no scan available to export"}
	}
	if scope == "extension" {
		if extID == "" {
			return nil, &ProtocolError{Code: "SCAN_FAILED", Message: "extensionId required for extension scope"}
		}
		var kept []ExtensionReport
		for _, e := range res.Extensions {
			if e.ID == extID {
				kept = append(kept, e)
			}
		}
		res.Extensions = kept
	}

	ro := DefaultRedaction()
	if v, ok := opts["redactUsernames"].(bool); ok {
		ro.RedactUsernames = v
	}
	if v, ok := opts["redactPaths"].(bool); ok {
		ro.RedactPaths = v
	}
	if v, ok := opts["redactProfileNames"].(bool); ok {
		ro.RedactProfileNames = v
	}
	redacted := ApplyRedaction(res, ro)

	if err := os.MkdirAll(ReportsDir(), 0o700); err != nil {
		return nil, &ProtocolError{Code: "SCAN_FAILED", Message: "cannot create reports dir"}
	}
	stamp := time.Now().Format("20060102-150405")
	var filename string
	switch scope {
	case "findings":
		filename = fmt.Sprintf("findings-%s.%s", stamp, format)
	case "inventory":
		filename = fmt.Sprintf("inventory-%s.%s", stamp, format)
	case "extension":
		filename = fmt.Sprintf("extension-%s-%s.%s", sanitizeFile(extID), stamp, format)
	default:
		filename = fmt.Sprintf("report-%s.%s", stamp, format)
	}
	full := filepath.Join(ReportsDir(), filename)

	var err error
	switch format {
	case "json":
		err = exportJSON(full, redacted, scope)
	case "csv":
		err = exportCSV(full, redacted, scope)
	case "html":
		err = exportHTML(full, redacted, scope)
	case "pdf":
		err = exportPDF(full, redacted, scope)
	}
	if err != nil {
		return nil, &ProtocolError{Code: "SCAN_FAILED", Message: "export failed: " + err.Error()}
	}
	return map[string]any{"path": full, "format": format, "scope": scope}, nil
}

func sanitizeFile(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "extension"
	}
	return b.String()
}

func exportJSON(path string, res *ScanResult, scope string) error {
	var payload any = res
	switch scope {
	case "findings":
		payload = findingsOnly(res)
	case "inventory":
		payload = inventoryOnly(res)
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func findingsOnly(res *ScanResult) map[string]any {
	out := map[string]any{"scan": res.Scan}
	var all []map[string]any
	for _, e := range res.Extensions {
		for _, f := range e.Findings {
			all = append(all, map[string]any{
				"extension": e.Name, "extensionId": e.ID, "version": e.Version,
				"finding": f,
			})
		}
	}
	out["findings"] = all
	return out
}

func inventoryOnly(res *ScanResult) []map[string]any {
	var out []map[string]any
	for _, e := range res.Extensions {
		out = append(out, map[string]any{
			"id": e.ID, "name": e.Name, "version": e.Version, "enabled": firstEnabled(e),
			"installType": firstInstallType(e), "profiles": installProfileNames(e),
			"permissions": len(e.Permissions), "hosts": len(e.HostPermissions),
			"packageSize": e.Package.TotalSize, "findings": len(e.Findings),
			"overallStatus": e.OverallStatus, "coverage": e.Analysis.Coverage,
		})
	}
	return out
}

func firstEnabled(e ExtensionReport) string {
	for _, i := range e.Installations {
		if i.Enabled {
			return "enabled"
		}
	}
	if len(e.Installations) > 0 {
		return "disabled"
	}
	return "Not available"
}

func firstInstallType(e ExtensionReport) string {
	if len(e.Installations) > 0 {
		return e.Installations[0].InstallType
	}
	return "Not available"
}

func installProfileNames(e ExtensionReport) []string {
	var out []string
	for _, i := range e.Installations {
		out = append(out, i.ProfileName)
	}
	return out
}

func exportCSV(path string, res *ScanResult, scope string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()

	if scope == "inventory" {
		w.Write([]string{"Extension ID", "Name", "Version", "State", "Install type", "Profiles", "Permissions", "Host patterns", "Package size", "Findings", "Overall status", "Coverage %"})
		for _, e := range res.Extensions {
			w.Write([]string{
				e.ID, e.Name, e.Version, firstEnabled(e), firstInstallType(e),
				strings.Join(installProfileNames(e), "; "),
				fmt.Sprint(len(e.Permissions)), fmt.Sprint(len(e.HostPermissions)),
				fmt.Sprint(e.Package.TotalSize), fmt.Sprint(len(e.Findings)),
				e.OverallStatus, fmt.Sprintf("%.0f", e.Analysis.Coverage),
			})
		}
		return nil
	}

	w.Write([]string{"Extension", "Extension ID", "Version", "Finding ID", "Rule", "Category", "Severity", "Confidence", "Title", "Summary", "Location", "Evidence"})
	for _, e := range res.Extensions {
		for _, f := range e.Findings {
			var ev []string
			for _, x := range f.Evidence {
				ev = append(ev, evidenceString(x))
			}
			w.Write([]string{
				e.Name, e.ID, e.Version, f.ID, f.RuleID, f.Category, f.Severity, f.Confidence,
				f.Title, f.Summary, f.Location, strings.Join(ev, " | "),
			})
		}
	}
	return nil
}

func evidenceString(e Evidence) string {
	parts := []string{}
	if e.File != "" {
		parts = append(parts, "file: "+e.File+fmt.Sprintf(":%d", e.Line))
	}
	if e.Field != "" {
		parts = append(parts, "field: "+e.Field)
	}
	if e.Pattern != "" {
		parts = append(parts, "pattern: "+e.Pattern)
	}
	if e.Note != "" {
		parts = append(parts, e.Note)
	}
	if e.Excerpt != "" {
		parts = append(parts, "excerpt: "+e.Excerpt)
	}
	return strings.Join(parts, ", ")
}

func exportHTML(path string, res *ScanResult, scope string) error {
	var b strings.Builder
	b.WriteString(`<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Local Chrome Extension Auditor — Report</title><style>
body{font-family:Segoe UI,Arial,sans-serif;margin:0;background:#f5f6f8;color:#1c2430}
header{background:#1c2430;color:#fff;padding:18px 28px}
header h1{margin:0;font-size:20px}
main{padding:24px 28px;max-width:1100px;margin:0 auto}
table{border-collapse:collapse;width:100%;background:#fff;font-size:13px;margin:12px 0 24px}
th,td{border:1px solid #d7dbe0;padding:6px 10px;text-align:left;vertical-align:top}
th{background:#eef1f4}
.sev-critical,.sev-high{color:#b3261e;font-weight:600}
.sev-medium{color:#9a6700;font-weight:600}
.sev-low{color:#57606a}
.sev-informational{color:#6e7781}
details{margin:4px 0}
summary{cursor:pointer}
.badge{display:inline-block;padding:2px 8px;border-radius:10px;background:#e6ebf0;font-size:12px;margin-right:4px}
h2{border-bottom:2px solid #d7dbe0;padding-bottom:6px;margin-top:32px}
.meta{color:#57606a;font-size:12px}
</style></head><body><header><h1>Local Chrome Extension Auditor — Local Report</h1><div class="meta">Generated locally; no data has left this computer.</div></header><main>`)

	scan := res.Scan
	b.WriteString(fmt.Sprintf("<h2>Scan</h2><table><tr><th>Started</th><td>%s</td></tr><tr><th>Finished</th><td>%s</td></tr><tr><th>Mode</th><td>%s</td></tr><tr><th>Status</th><td>%s</td></tr><tr><th>Profiles scanned</th><td>%d</td></tr><tr><th>Extensions found</th><td>%d</td></tr><tr><th>Chrome</th><td>%s</td></tr><tr><th>OS</th><td>%s</td></tr><tr><th>Scanner</th><td>%s (rules %s, analyzers %s)</td></tr><tr><th>Model used</th><td>%s</td></tr></table>",
		scan.StartedAt, scan.FinishedAt, scan.Mode, scan.Status, scan.ProfilesScanned, scan.ExtensionsFound,
		scan.ChromeVersion, scan.OSVersion, scan.ScannerVersion, scan.RuleSetVersion, scan.AnalyzerVersion, orDefault(scan.ModelUsed, "Not used")))

	b.WriteString("<h2>Inventory</h2><table><tr><th>Extension</th><th>Version</th><th>Profiles</th><th>State</th><th>Permissions</th><th>Hosts</th><th>Package</th><th>Findings</th><th>Status</th><th>Coverage</th></tr>")
	for _, e := range res.Extensions {
		b.WriteString(fmt.Sprintf("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%d</td><td>%d</td><td>%s</td><td>%d</td><td>%s</td><td>%.0f%%</td></tr>",
			htmlEsc(e.Name), htmlEsc(e.Version), htmlEsc(strings.Join(installProfileNames(e), ", ")), firstEnabled(e),
			len(e.Permissions), len(e.HostPermissions), humanSize(e.Package.TotalSize), len(e.Findings),
			e.OverallStatus, e.Analysis.Coverage))
	}
	b.WriteString("</table>")

	b.WriteString("<h2>Findings</h2>")
	for _, e := range res.Extensions {
		if len(e.Findings) == 0 {
			continue
		}
		b.WriteString(fmt.Sprintf("<h3>%s <span class='meta'>v%s (%s)</span></h3>", htmlEsc(e.Name), htmlEsc(e.Version), e.ID))
		for _, f := range e.Findings {
			b.WriteString(fmt.Sprintf("<div class='badge sev-%s'>%s / %s confidence</div>", f.Severity, f.Severity, f.Confidence))
			b.WriteString(fmt.Sprintf("<p><strong>%s</strong> — %s</p>", htmlEsc(f.Title), htmlEsc(f.Summary)))
			b.WriteString("<details><summary>Evidence</summary><ul>")
			for _, ev := range f.Evidence {
				b.WriteString("<li>" + htmlEsc(evidenceString(ev)) + "</li>")
			}
			b.WriteString("</ul></details>")
			b.WriteString(fmt.Sprintf("<p class='meta'>Why it matters: %s</p><p class='meta'>Recommendation: %s</p>", htmlEsc(f.WhyItMatters), htmlEsc(f.Recommendation)))
		}
	}
	b.WriteString("<p class='meta'>This report was produced by static local analysis. It does not prove absence or presence of malicious behavior; it documents observed evidence.</p>")
	b.WriteString("</main></body></html>")
	return os.WriteFile(path, []byte(b.String()), 0o600)
}

func htmlEsc(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, `"`, "&#34;")
	return s
}

// ---- minimal local PDF writer (§67) ----

func exportPDF(path string, res *ScanResult, scope string) error {
	var lines []string
	scan := res.Scan
	lines = append(lines, "Local Chrome Extension Auditor - Local Report", "")
	lines = append(lines, fmt.Sprintf("Scan: %s to %s", scan.StartedAt, scan.FinishedAt))
	lines = append(lines, fmt.Sprintf("Mode: %s   Status: %s", scan.Mode, scan.Status))
	lines = append(lines, fmt.Sprintf("Profiles: %d   Extensions: %d", scan.ProfilesScanned, scan.ExtensionsFound))
	lines = append(lines, fmt.Sprintf("Chrome: %s   OS: %s", scan.ChromeVersion, scan.OSVersion))
	lines = append(lines, fmt.Sprintf("Scanner: %s (rules %s, analyzers %s)", scan.ScannerVersion, scan.RuleSetVersion, scan.AnalyzerVersion))
	lines = append(lines, "")
	lines = append(lines, "INVENTORY")
	for _, e := range res.Extensions {
		lines = append(lines, fmt.Sprintf("- %s v%s [%s] perms=%d hosts=%d pkg=%s findings=%d status=%s coverage=%.0f%%",
			e.Name, e.Version, e.ID, len(e.Permissions), len(e.HostPermissions),
			humanSize(e.Package.TotalSize), len(e.Findings), e.OverallStatus, e.Analysis.Coverage))
	}
	lines = append(lines, "", "FINDINGS")
	for _, e := range res.Extensions {
		for _, f := range e.Findings {
			lines = append(lines, fmt.Sprintf("[%s/%s] %s (%s v%s)", f.Severity, f.Confidence, f.Title, e.Name, e.Version))
			lines = append(lines, "  "+f.Summary)
			for _, ev := range f.Evidence {
				lines = append(lines, "    evidence: "+truncate(evidenceString(ev), 110))
			}
			lines = append(lines, "")
		}
	}
	lines = append(lines, "This report documents observed static evidence only.")
	return writeTextPDF(path, lines)
}

// writeTextPDF produces a simple paginated PDF with the 14 built-in Helvetica
// fonts — zero external dependencies, fully local (§67).
func writeTextPDF(path string, lines []string) error {
	const (
		pageW   = 612.0
		pageH   = 792.0
		marginX = 54.0
		marginY = 54.0
		leading = 14.0
		fontSz  = 10.0
		maxW    = pageW - 2*marginX
	)
	perPage := 48 // (pageH - 2*marginY) / leading ≈ 48.86 lines/page
	wrapped := []string{}
	for _, l := range lines {
		wrapped = append(wrapped, wrapPlain(l, 95)...)
	}
	pages := 1 + len(wrapped)*int(leading)/int(pageH-2*marginY)
	if pages < 1 {
		pages = 1
	}
	// paginate
	var pageLines [][]string
	cur := []string{}
	for _, l := range wrapped {
		if len(cur) >= perPage {
			pageLines = append(pageLines, cur)
			cur = []string{}
		}
		cur = append(cur, l)
	}
	pageLines = append(pageLines, cur)

	var objs []string
	obj := func(s string) int {
		objs = append(objs, s)
		return len(objs)
	}
	_ = pages

	fontObj := obj("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
	var pageObjIDs []int
	var contentObjIDs []int
	for _, pl := range pageLines {
		var b strings.Builder
		for i, l := range pl {
			y := pageH - marginY - float64(i+1)*leading
			b.WriteString(fmt.Sprintf("BT /F1 %g %.0f %.0f Td (%s) Tj ET\n", fontSz, marginX, y, pdfEscape(l)))
		}
		contentObjIDs = append(contentObjIDs, obj(fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", len(b.String()), b.String())))
	}
	pagesObjID := len(objs) + len(pageLines) + 2 // placeholder computed below

	for i := range pageLines {
		pageObjIDs = append(pageObjIDs, obj(fmt.Sprintf("<< /Type /Page /Parent %d 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 %d 0 R >> >> /Contents %d 0 R >>", pagesObjID, fontObj, contentObjIDs[i])))
	}
	kids := []string{}
	for _, id := range pageObjIDs {
		kids = append(kids, fmt.Sprintf("%d 0 R", id))
	}
	pagesObjID = obj(fmt.Sprintf("<< /Type /Pages /Kids [%s] /Count %d >>", strings.Join(kids, " "), len(pageObjIDs)))
	catObj := obj(fmt.Sprintf("<< /Type /Catalog /Pages %d 0 R >>", pagesObjID))

	var out strings.Builder
	out.WriteString("%PDF-1.4\n")
	offsets := []int{0}
	for i, o := range objs {
		offsets = append(offsets, len(out.String()))
		out.WriteString(fmt.Sprintf("%d 0 obj\n%s\nendobj\n", i+1, o))
	}
	xref := len(out.String())
	out.WriteString(fmt.Sprintf("xref\n0 %d\n", len(objs)+1))
	out.WriteString("0000000000 65535 f \n")
	for i := 1; i <= len(objs); i++ {
		out.WriteString(fmt.Sprintf("%010d 00000 n \n", offsets[i]))
	}
	out.WriteString(fmt.Sprintf("trailer\n<< /Size %d /Root %d 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objs)+1, catObj, xref))
	return os.WriteFile(path, []byte(out.String()), 0o600)
}

func wrapPlain(s string, width int) []string {
	if len(s) <= width {
		return []string{s}
	}
	var out []string
	for len(s) > width {
		cut := width
		if i := strings.LastIndex(s[:width], " "); i > width/2 {
			cut = i
		}
		out = append(out, strings.TrimSpace(s[:cut]))
		s = strings.TrimSpace(s[cut:])
	}
	if len(s) > 0 {
		out = append(out, s)
	}
	return out
}

func pdfEscape(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "(", "\\(")
	s = strings.ReplaceAll(s, ")", "\\)")
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	// keep to Latin-1-ish
	var b strings.Builder
	for _, r := range s {
		if r < 256 {
			b.WriteRune(r)
		} else {
			b.WriteByte('?')
		}
	}
	return b.String()
}

var _ = sort.Strings
