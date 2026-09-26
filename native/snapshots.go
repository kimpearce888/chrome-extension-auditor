package main

// Snapshot comparison (§63, §130) — one of the product's strongest features.
// Snapshots record what was observed so the next scan can diff honestly.

import (
        "fmt"
        "sort"
)

// BuildSnapshot captures the comparable state of an extension report.
func BuildSnapshot(er *ExtensionReport, scanID string) Snapshot {
        snap := Snapshot{
                ExtensionID:    er.ID,
                TakenAt:        nowISO(),
                Version:        er.Version,
                ContentScripts: len(er.ContentScripts),
                BackgroundType: er.Background.Type,
                PackageSize:    er.Package.TotalSize,
                FileCount:      er.Package.TotalFiles,
                FileHashes:     map[string]string{},
        }
        snap.ScanID = scanID
        for _, p := range er.Permissions {
                if p.Source == "required" {
                        snap.Permissions = append(snap.Permissions, p.Name)
                } else {
                        snap.OptionalPerms = append(snap.OptionalPerms, p.Name)
                }
        }
        for _, h := range er.HostPermissions {
                snap.Hosts = append(snap.Hosts, h.Pattern)
        }
        for _, a := range er.APIs {
                snap.APIs = append(snap.APIs, a.API)
        }
        for _, n := range er.Network {
                snap.NetworkHosts = append(snap.NetworkHosts, n.Host)
        }
        for _, f := range er.Files {
                snap.FileHashes[f.Path] = f.SHA256
        }
        for _, f := range er.Findings {
                snap.FindingIDs = append(snap.FindingIDs, f.RuleID)
        }
        sort.Strings(snap.Permissions)
        sort.Strings(snap.Hosts)
        sort.Strings(snap.APIs)
        sort.Strings(snap.NetworkHosts)
        return snap
}

// currentScanID is tracked by the store while a scan is running.
var currentScanIDref string

func currentScanID() string { return currentScanIDref }

// DiffSnapshots computes the change list between two snapshots (§130).
func DiffSnapshots(old, new *Snapshot) []DiffChange {
        var changes []DiffChange
        if old == nil || new == nil {
                return changes
        }
        if old.Version != new.Version {
                changes = append(changes, DiffChange{Kind: "versionChanged", Detail: "Extension version changed", Old: old.Version, New: new.Version})
        }
        oldPerms := setOf(old.Permissions)
        newPerms := setOf(new.Permissions)
        for p := range newPerms {
                if !oldPerms[p] {
                        changes = append(changes, DiffChange{Kind: "permissionAdded", Detail: "New permission: " + p, New: p})
                }
        }
        for p := range oldPerms {
                if !newPerms[p] {
                        changes = append(changes, DiffChange{Kind: "permissionRemoved", Detail: "Permission removed: " + p, Old: p})
                }
        }
        oldOpt := setOf(old.OptionalPerms)
        newOpt := setOf(new.OptionalPerms)
        for p := range newOpt {
                if !oldOpt[p] {
                        changes = append(changes, DiffChange{Kind: "permissionAdded", Detail: "New optional permission: " + p, New: p})
                }
        }
        oldHosts := setOf(old.Hosts)
        newHosts := setOf(new.Hosts)
        for h := range newHosts {
                if !oldHosts[h] {
                        changes = append(changes, DiffChange{Kind: "hostAdded", Detail: "New host permission: " + h, New: h})
                }
        }
        for h := range oldHosts {
                if !newHosts[h] {
                        changes = append(changes, DiffChange{Kind: "hostRemoved", Detail: "Host permission removed: " + h, Old: h})
                }
        }
        oldAPIs := setOf(old.APIs)
        newAPIs := setOf(new.APIs)
        for a := range newAPIs {
                if !oldAPIs[a] {
                        changes = append(changes, DiffChange{Kind: "apiAdded", Detail: "New API usage: " + a, New: a})
                }
        }
        oldNet := setOf(old.NetworkHosts)
        newNet := setOf(new.NetworkHosts)
        for n := range newNet {
                if !oldNet[n] {
                        changes = append(changes, DiffChange{Kind: "domainAdded", Detail: "New network destination: " + n, New: n})
                }
        }
        for n := range oldNet {
                if !newNet[n] {
                        changes = append(changes, DiffChange{Kind: "domainRemoved", Detail: "Network destination no longer referenced: " + n, Old: n})
                }
        }
        if old.PackageSize != new.PackageSize {
                kind := "packageGrew"
                if new.PackageSize < old.PackageSize {
                        kind = "packageShrank"
                }
                changes = append(changes, DiffChange{Kind: kind,
                        Detail: fmt.Sprintf("Package size: %s → %s", humanSize(old.PackageSize), humanSize(new.PackageSize)),
                        Old: fmt.Sprint(old.PackageSize), New: fmt.Sprint(new.PackageSize)})
        }
        if old.FileCount != new.FileCount {
                changes = append(changes, DiffChange{Kind: "fileAdded", Detail: fmt.Sprintf("File count: %d → %d", old.FileCount, new.FileCount)})
        }
        added, removed, changed := 0, 0, 0
        for p, h := range new.FileHashes {
                if oh, ok := old.FileHashes[p]; ok {
                        if oh != h {
                                changed++
                        }
                } else {
                        added++
                }
        }
        for p := range old.FileHashes {
                if _, ok := new.FileHashes[p]; !ok {
                        removed++
                }
        }
        if added > 0 || removed > 0 || changed > 0 {
                changes = append(changes, DiffChange{Kind: "fileChanged",
                        Detail: fmt.Sprintf("Files: %d added, %d removed, %d changed since previous scan", added, removed, changed)})
        }
        if old.ContentScripts != new.ContentScripts {
                changes = append(changes, DiffChange{Kind: "newContentScript",
                        Detail: fmt.Sprintf("Content script declarations: %d → %d", old.ContentScripts, new.ContentScripts)})
        }
        if old.BackgroundType != new.BackgroundType {
                changes = append(changes, DiffChange{Kind: "newBackgroundScript",
                        Detail: fmt.Sprintf("Background architecture: %s → %s", old.BackgroundType, new.BackgroundType)})
        }
        oldFindings := setOf(old.FindingIDs)
        newFindings := setOf(new.FindingIDs)
        for f := range newFindings {
                if !oldFindings[f] {
                        changes = append(changes, DiffChange{Kind: "findingAppeared", Detail: "New finding type: " + f, New: f})
                }
        }
        for f := range oldFindings {
                if !newFindings[f] {
                        changes = append(changes, DiffChange{Kind: "findingResolved", Detail: "Finding no longer present: " + f, Old: f})
                }
        }
        return changes
}

func setOf(list []string) map[string]bool {
        m := map[string]bool{}
        for _, s := range list {
                m[s] = true
        }
        return m
}

// findingsFromDiff surfaces important changes as informational findings so
// they appear in the findings stream with evidence.
func findingsFromDiff(changes []DiffChange) []Finding {
        var out []Finding
        for _, ch := range changes {
                switch ch.Kind {
                case "permissionAdded":
                        out = append(out, MakeFinding("PERM-001", "medium", "high",
                                []Evidence{{Note: ch.Detail}}, "snapshot diff"))
                case "hostAdded":
                        out = append(out, MakeFinding("HOST-001", "medium", "high",
                                []Evidence{{Note: ch.Detail}}, "snapshot diff"))
                case "domainAdded":
                        out = append(out, MakeFinding("NET-001", "informational", "high",
                                []Evidence{{Note: ch.Detail}}, "snapshot diff"))
                case "versionChanged", "packageGrew", "fileChanged":
                        out = append(out, Finding{
                                RuleID:       "DIFF-INFO",
                                Category:     "maintenance",
                                Severity:     "informational",
                                Confidence:   "high",
                                Title:        "Changed since previous scan",
                                Summary:      ch.Detail,
                                Evidence:     []Evidence{{Note: ch.Detail, Excerpt: ch.Old + " → " + ch.New}},
                                WhyItMatters: "Changes since the last audit may introduce new behavior worth reviewing.",
                                Location:     "snapshot diff",
                                Recommendation: "Review the diff tab for details.",
                        })
                case "findingAppeared":
                        out = append(out, Finding{
                                RuleID:       "DIFF-NEW",
                                Category:     "code quality",
                                Severity:     "informational",
                                Confidence:   "high",
                                Title:        "New finding type since previous scan",
                                Summary:      ch.Detail,
                                Evidence:     []Evidence{{Note: ch.Detail}},
                                WhyItMatters: "A category of finding appeared that was not present previously.",
                                Location:     "snapshot diff",
                                Recommendation: "Open the finding for evidence.",
                        })
                }
        }
        return out
}
