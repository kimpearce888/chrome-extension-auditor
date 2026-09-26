package main

// Command dispatch (§156). Only whitelisted actions run (protocol.go).
// Handlers validate every input; the host never executes anything.

import (
        "encoding/json"
        "fmt"
        "os"
        "path/filepath"
        "strings"
)

func (h *Host) dispatch(req *NativeRequest) NativeResponse {
        switch req.Action {
        case "getStatus":
                return okResponse(req.RequestID, h.statusPayload())

        case "discoverProfiles":
                override := optString(req.Options, "chromeUserData")
                profiles := DiscoverProfiles(override)
                for i := range profiles {
                        profiles[i].ExtensionCount = 0
                }
                return okResponse(req.RequestID, map[string]any{"profiles": profiles})

        case "discoverExtensions":
                override := optString(req.Options, "chromeUserData")
                profiles := DiscoverProfiles(override)
                byID := DiscoverExtensions(profiles, nil)
                var list []map[string]any
                for id, de := range byID {
                        item := map[string]any{
                                "id":             id,
                                "installations":  de.Installations,
                        }
                        if primary := primaryInstallation(de); primary != nil {
                                item["name"] = extNameFromInstall(de, primary)
                                item["version"] = primary.Version
                        }
                        list = append(list, item)
                }
                return okResponse(req.RequestID, map[string]any{"profiles": profiles, "extensions": list})

        case "scanExtension":
                extID := optString(req.Options, "extensionId")
                if extID == "" {
                        return errResponse(req.RequestID, &ProtocolError{Code: "SCAN_FAILED", Message: "missing extensionId"})
                }
                override := optString(req.Options, "chromeUserData")
                profiles := DiscoverProfiles(override)
                byID := DiscoverExtensions(profiles, mgmtList(req.Options))
                de, ok := byID[extID]
                if !ok {
                        return errResponse(req.RequestID, &ProtocolError{Code: "SCAN_FAILED", Message: "extension not found: " + extID})
                }
                h.scanner.cancel.Store(false)
                report, perr := h.scanner.ScanExtension(de, optString(req.Options, "mode"), h.scanOptions(req.Options), nil, 1, 1)
                if report != nil {
                        report.ID = extID
                        h.store.RecordScan(&ScanResult{Scan: Scan{
                                ID: currentScanIDref, StartedAt: nowISO(), FinishedAt: nowISO(), Mode: "single",
                                Status: "SCAN_OK", ScannerVersion: ScannerVersion, RuleSetVersion: ruleSet.RuleSetVersion,
                        }, Extensions: []ExtensionReport{*report}})
                        if perr != nil {
                                return okResponse(req.RequestID, map[string]any{"report": report, "warning": perr.Message})
                        }
                        return okResponse(req.RequestID, map[string]any{"report": report})
                }
                return errResponse(req.RequestID, perr)

        case "scanAll":
                opts := h.scanOptions(req.Options)
                h.scanner.cancel.Store(false)
                result, perr := h.scanner.ScanAll(opts, func(stage string, current, total int, message string) {
                        h.writeEvent(req.RequestID, "progress", ProgressEvent{Type: "progress", Stage: stage, Current: current, Total: total, Message: message})
                })
                if perr != nil {
                        return errResponse(req.RequestID, perr)
                }
                // Trim heavy fields for the aggregate response; details come via
                // getScanExtension (1MB native messaging limit).
                trimmed := *result
                for i := range trimmed.Extensions {
                        e := &trimmed.Extensions[i]
                        e.ManifestRaw = nil
                        if len(e.Files) > 200 {
                                e.Files = e.Files[:200]
                        }
                }
                return okResponse(req.RequestID, trimmed)

        case "cancelScan":
                h.scanner.RequestCancel()
                return okResponse(req.RequestID, map[string]any{"cancelled": true})

        case "getScan":
                scanID := optString(req.Options, "scanId")
                if scanID == "" {
                        scanID = h.store.Data.LastScanID
                }
                res := h.store.GetScanResult(scanID)
                if res == nil {
                        return errResponse(req.RequestID, &ProtocolError{Code: "SCAN_FAILED", Message: "scan not found"})
                }
                for i := range res.Extensions {
                        res.Extensions[i].ManifestRaw = nil
                }
                return okResponse(req.RequestID, res)

        case "getScanExtension":
                extID := optString(req.Options, "extensionId")
                scanID := optString(req.Options, "scanId")
                var report *ExtensionReport
                if scanID != "" {
                        if res := h.store.GetScanResult(scanID); res != nil {
                                for i := range res.Extensions {
                                        if res.Extensions[i].ID == extID {
                                                report = &res.Extensions[i]
                                                break
                                        }
                                }
                        }
                } else if e, ok := h.store.GetExtension(extID); ok {
                        report = e
                }
                if report == nil {
                        return errResponse(req.RequestID, &ProtocolError{Code: "SCAN_FAILED", Message: "extension report not found"})
                }
                return okResponse(req.RequestID, map[string]any{"report": report})

        case "getSourceFile":
                extID := optString(req.Options, "extensionId")
                file := optString(req.Options, "file")
                if extID == "" || file == "" {
                        return errResponse(req.RequestID, &ProtocolError{Code: "ACCESS_DENIED", Message: "missing extensionId or file"})
                }
                report, ok := h.store.GetExtension(extID)
                if !ok {
                        return errResponse(req.RequestID, &ProtocolError{Code: "SCAN_FAILED", Message: "extension not scanned yet"})
                }
                base := h.scanner.validator
                var pkgRoot string
                for _, inst := range report.Installations {
                        if inst.Path != "" {
                                pkgRoot = inst.Path
                                break
                        }
                }
                if pkgRoot == "" {
                        return errResponse(req.RequestID, &ProtocolError{Code: "ACCESS_DENIED", Message: "no package path known"})
                }
                // File must be one of the inventoried files (§103: validated paths).
                known := false
                for _, f := range report.Files {
                        if f.Path == file {
                                known = true
                                break
                        }
                }
                if !known {
                        return errResponse(req.RequestID, &ProtocolError{Code: "ACCESS_DENIED", Message: "file not part of the scanned inventory"})
                }
                // The inventory membership check above is the security gate; the
                // joined path still gets sanity validation (traversal/UNC/absolute).
                full, err := base.ValidateDiscovered(filepath.Join(pkgRoot, file))
                if err != nil {
                        return errResponse(req.RequestID, &ProtocolError{Code: "ACCESS_DENIED", Message: "path rejected"})
                }
                data, rerr := os.ReadFile(full)
                if rerr != nil {
                        return errResponse(req.RequestID, &ProtocolError{Code: "FILE_CHANGED_DURING_SCAN", Message: "file unreadable"})
                }
                if len(data) > 2*1024*1024 {
                        data = data[:2*1024*1024]
                        return okResponse(req.RequestID, map[string]any{"content": string(data), "truncated": true})
                }
                return okResponse(req.RequestID, map[string]any{"content": string(data), "truncated": false})

        case "compareScans":
                scanA := optString(req.Options, "scanA")
                scanB := optString(req.Options, "scanB")
                if scanA == "" || scanB == "" {
                        // default: the two most recent stored scans (§129)
                        scans := h.store.ListScans()
                        if len(scans) >= 2 {
                                scanA = scans[len(scans)-2].ID
                                scanB = scans[len(scans)-1].ID
                        } else if scanB == "" && len(scans) == 1 {
                                scanB = scans[0].ID
                        }
                }
                resA := h.store.GetScanResult(scanA)
                resB := h.store.GetScanResult(scanB)
                if resA == nil || resB == nil {
                        return errResponse(req.RequestID, &ProtocolError{Code: "SCAN_FAILED", Message: "two stored scans are required for comparison"})
                }
                diff := CompareScanResults(resA, resB)
                // Prefer the recorded per-scan snapshot history — it captures the
                // exact state at each scan time (§130), not just the latest state.
                snapsA := h.store.SnapshotsForScan(scanA)
                snapsB := h.store.SnapshotsForScan(scanB)
                if len(snapsA) > 0 || len(snapsB) > 0 {
                        diff = compareSnapshotSets(scanA, snapsA, scanB, snapsB, h.store)
                }
                return okResponse(req.RequestID, diff)

        case "exportReport":
                result, perr := h.exportReport(req.Options)
                if perr != nil {
                        return errResponse(req.RequestID, perr)
                }
                return okResponse(req.RequestID, result)

        case "deleteHistory":
                if err := h.store.DeleteAllHistory(); err != nil {
                        return errResponse(req.RequestID, &ProtocolError{Code: "SCAN_FAILED", Message: err.Error()})
                }
                return okResponse(req.RequestID, map[string]any{"deleted": true})

        case "getLMStudioStatus", "testLMStudio":
                settings := lmSettingsFromOptions(req.Options)
                client := NewLMClient(settings)
                return okResponse(req.RequestID, client.Status())

        case "askAuditor":
                extID := optString(req.Options, "extensionId")
                question := optString(req.Options, "question")
                report, ok := h.store.GetExtension(extID)
                if !ok {
                        return errResponse(req.RequestID, &ProtocolError{Code: "SCAN_FAILED", Message: "extension not scanned yet"})
                }
                ai, perr := h.scanner.AskAuditor(report, question, lmSettingsFromOptions(req.Options))
                if perr != nil {
                        return errResponse(req.RequestID, perr)
                }
                return okResponse(req.RequestID, ai)

        case "scanArchive":
                path := optString(req.Options, "path")
                if path == "" {
                        return errResponse(req.RequestID, &ProtocolError{Code: "ACCESS_DENIED", Message: "missing path"})
                }
                // Explicitly user-selected archive: must exist, be CRX/ZIP, size-capped.
                fi, err := os.Stat(path)
                if err != nil || fi.IsDir() {
                        return errResponse(req.RequestID, &ProtocolError{Code: "ACCESS_DENIED", Message: "archive not found"})
                }
                if fi.Size() > h.scanner.Limits.MaxPackageBytes {
                        return errResponse(req.RequestID, &ProtocolError{Code: "ARCHIVE_TOO_LARGE", Message: "archive exceeds size limit"})
                }
                tmpDir, aerr := SafeExtractArchive(path, h.scanner.Limits)
                if aerr != nil {
                        if pe, ok := aerr.(*ProtocolError); ok {
                                return errResponse(req.RequestID, pe)
                        }
                        return errResponse(req.RequestID, &ProtocolError{Code: "SCAN_FAILED", Message: aerr.Error()})
                }
                defer os.RemoveAll(tmpDir)
                de := &DiscoveredExtension{ID: "archive-" + filepath.Base(path)}
                de.Installations = []ExtensionInstallation{{
                        ProfileID: "archive", ProfileName: "Archive", Enabled: true,
                        InstallType: "Not available", Version: "Not available", Path: tmpDir,
                }}
                report, perr := h.scanner.ScanExtension(de, "standard", h.scanOptions(req.Options), nil, 1, 1)
                if report != nil && perr == nil {
                        return okResponse(req.RequestID, map[string]any{"report": report})
                }
                if perr != nil {
                        return errResponse(req.RequestID, perr)
                }
                return errResponse(req.RequestID, &ProtocolError{Code: "SCAN_FAILED", Message: "archive analysis failed"})
        }
        return errResponse(req.RequestID, &ProtocolError{Code: "ACCESS_DENIED", Message: "unhandled action"})
}

func (h *Host) statusPayload() map[string]any {
        scans := h.store.ListScans()
        last := "Not available"
        var lastScan *Scan
        if len(scans) > 0 {
                lastScan = &scans[len(scans)-1]
                last = lastScan.FinishedAt
        }
        extCount := len(h.store.Data.Extensions)
        stale := 0
        for _, sc := range scans {
                if sc.FinishedAt == "" {
                        stale++
                }
        }
        return map[string]any{
                "scannerVersion":   ScannerVersion,
                "ruleSetVersion":   ruleSet.RuleSetVersion,
                "analyzerVersion":  AnalyzerVersion,
                "os":               osVersion(),
                "dataDir":          DataDir(),
                "extensionsKnown":  extCount,
                "scanCount":        len(scans),
                "lastScan":         last,
                "interruptedScans": stale,
                "localOnly":        true,
        }
}

func (h *Host) scanOptions(opts map[string]any) ScanOptions {
        so := ScanOptions{
                Mode:           optString(opts, "mode"),
                ChromeUserData: optString(opts, "chromeUserData"),
                ChromeVersion:  optString(opts, "chromeVersion"),
                LM:             lmSettingsFromOptions(opts),
        }
        so.ManagementInventory = mgmtList(opts)
        if ids, ok := opts["extensionIds"].([]any); ok {
                for _, v := range ids {
                        if s, ok := v.(string); ok {
                                so.ExtensionFilter = append(so.ExtensionFilter, s)
                        }
                }
        }
        return so
}

func lmSettingsFromOptions(opts map[string]any) LMStudioSettings {
        s := DefaultLMStudio()
        if opts == nil {
                return s
        }
        if v := optString(opts, "lmBaseUrl"); v != "" {
                s.BaseURL = v
        }
        if v := optString(opts, "lmModel"); v != "" {
                s.Model = v
        }
        if v, ok := opts["lmTemperature"].(float64); ok {
                s.Temperature = v
        }
        if v, ok := opts["lmMaxTokens"].(float64); ok {
                s.MaxTokens = int(v)
        }
        if v, ok := opts["lmTimeoutSec"].(float64); ok && v > 0 {
                s.TimeoutSec = int(v)
        }
        return s
}

func optString(opts map[string]any, key string) string {
        if opts == nil {
                return ""
        }
        if s, ok := opts[key].(string); ok {
                return s
        }
        return ""
}

func mgmtList(opts map[string]any) []map[string]any {
        if opts == nil {
                return nil
        }
        raw, ok := opts["managementInventory"].([]any)
        if !ok {
                return nil
        }
        var out []map[string]any
        for _, v := range raw {
                if m, ok := v.(map[string]any); ok {
                        out = append(out, m)
                }
        }
        return out
}

func extNameFromInstall(de *DiscoveredExtension, inst *ExtensionInstallation) string {
        if mi := ParseManifest(inst.Path); mi != nil && mi.Valid && mi.Name != "Not available" {
                return mi.Name
        }
        return "Not available"
}

// CompareScanResults diffs two scans (§129–130).
func CompareScanResults(a, b *ScanResult) map[string]any {
        out := map[string]any{
                "scanA": a.Scan.ID,
                "scanB": b.Scan.ID,
        }
        mapA := map[string]*ExtensionReport{}
        for i := range a.Extensions {
                mapA[a.Extensions[i].ID] = &a.Extensions[i]
        }
        mapB := map[string]*ExtensionReport{}
        for i := range b.Extensions {
                mapB[b.Extensions[i].ID] = &b.Extensions[i]
        }
        extDiffs := []map[string]any{}
        for id, ea := range mapA {
                eb, ok := mapB[id]
                if !ok {
                        extDiffs = append(extDiffs, map[string]any{"extensionId": id, "change": "removed"})
                        continue
                }
                snapA := BuildSnapshot(ea, a.Scan.ID)
                snapB := BuildSnapshot(eb, b.Scan.ID)
                changes := DiffSnapshots(&snapA, &snapB)
                if len(changes) > 0 {
                        extDiffs = append(extDiffs, map[string]any{
                                "extensionId": id, "name": ea.Name, "change": "changed", "changes": changes,
                        })
                }
        }
        for id, eb := range mapB {
                if _, ok := mapA[id]; !ok {
                        extDiffs = append(extDiffs, map[string]any{"extensionId": id, "name": eb.Name, "change": "new"})
                }
        }
        out["extensions"] = extDiffs
        return out
}

// marshalPretty is a small helper for CLI output.
func marshalPretty(v any) string {
        data, err := json.MarshalIndent(v, "", "  ")
        if err != nil {
                return fmt.Sprint(v)
        }
        return string(data)
}

var _ = strings.TrimSpace


// compareSnapshotSets diffs two scans using their recorded snapshots (§130).
func compareSnapshotSets(scanA string, snapsA map[string]Snapshot, scanB string, snapsB map[string]Snapshot, store *Store) map[string]any {
        extDiffs := []map[string]any{}
        for id, sa := range snapsA {
                sb, ok := snapsB[id]
                if !ok {
                        extDiffs = append(extDiffs, map[string]any{"extensionId": id, "change": "removed"})
                        continue
                }
                changes := DiffSnapshots(&sa, &sb)
                if len(changes) > 0 {
                        name := id
                        if e, ok := store.GetExtension(id); ok && e.Name != "" {
                                name = e.Name
                        }
                        extDiffs = append(extDiffs, map[string]any{
                                "extensionId": id, "name": name, "change": "changed", "changes": changes,
                        })
                }
        }
        for id := range snapsB {
                if _, ok := snapsA[id]; !ok {
                        name := id
                        if e, ok := store.GetExtension(id); ok && e.Name != "" {
                                name = e.Name
                        }
                        extDiffs = append(extDiffs, map[string]any{"extensionId": id, "name": name, "change": "new"})
                }
        }
        return map[string]any{"scanA": scanA, "scanB": scanB, "extensions": extDiffs}
}
