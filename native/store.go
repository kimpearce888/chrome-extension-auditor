package main

// Local structured storage (§64, §159): versioned JSON store with atomic
// writes, schema versioning, backups, bounded caches, and full history
// deletion. The scanner never stores complete source files — only hashes,
// findings and references.

import (
        "encoding/json"
        "fmt"
        "os"
        "path/filepath"
        "runtime"
        "sort"
        "sync"
        "time"
)

// DataDir returns the application data directory (per-user).
func DataDir() string {
        if v := os.Getenv("CEA_DATA_DIR"); v != "" {
                return v
        }
        if runtime.GOOS == "windows" {
                if la := os.Getenv("LOCALAPPDATA"); la != "" {
                        return filepath.Join(la, "LocalExtensionAuditor")
                }
        }
        home, err := os.UserHomeDir()
        if err != nil {
                return "."
        }
        return filepath.Join(home, ".local", "share", "LocalExtensionAuditor")
}



func ReportsDir() string { return filepath.Join(DataDir(), "reports") }
func LogsDir() string   { return filepath.Join(DataDir(), "logs") }

type Store struct {
        mu   sync.Mutex
        path string
        Data *StoreData
}

// OpenStore loads (or initializes) the store with backup + migration.
func OpenStore() (*Store, error) {
        dir := DataDir()
        if err := os.MkdirAll(dir, 0o700); err != nil {
                return nil, err
        }
        path := filepath.Join(dir, "store.json")
        s := &Store{path: path, Data: freshStore()}
        data, err := os.ReadFile(path)
        if err != nil {
                if !os.IsNotExist(err) {
                        // try backup
                        if b, berr := os.ReadFile(path + ".bak"); berr == nil {
                                data = b
                        } else {
                                return nil, fmt.Errorf("store unreadable: %w", err)
                        }
                } else {
                        if err := s.save(); err != nil {
                                return nil, err
                        }
                        return s, nil
                }
        }
        if err := json.Unmarshal(data, s.Data); err != nil {
                // corrupted: keep a copy for forensics, start fresh
                _ = os.Rename(path, path+".corrupt-"+time.Now().Format("20060102150405"))
                s.Data = freshStore()
                if err := s.save(); err != nil {
                        return nil, err
                }
                return s, nil
        }
        if s.Data.SchemaVersion < StoreSchema {
                // migrations (future versions chain here)
                s.Data.SchemaVersion = StoreSchema
        }
        if s.Data.FileCache == nil {
                s.Data.FileCache = map[string]FileCacheEntry{}
        }
        if s.Data.AICache == nil {
                s.Data.AICache = map[string]AICacheEntry{}
        }
        if s.Data.Snapshots == nil {
                s.Data.Snapshots = map[string]Snapshot{}
        }
        if s.Data.SnapshotHistory == nil {
                s.Data.SnapshotHistory = map[string]map[string]Snapshot{}
        }
        if s.Data.Extensions == nil {
                s.Data.Extensions = map[string]ExtensionReport{}
        }
        return s, nil
}

func freshStore() *StoreData {
        return &StoreData{
                SchemaVersion:   StoreSchema,
                Scans:           []Scan{},
                Extensions:      map[string]ExtensionReport{},
                Snapshots:       map[string]Snapshot{},
                SnapshotHistory: map[string]map[string]Snapshot{},
                FileCache:       map[string]FileCacheEntry{},
                AICache:         map[string]AICacheEntry{},
        }
}

// save writes atomically: temp file + rename, keeping a .bak (§159).
func (s *Store) save() error {
        data, err := json.MarshalIndent(s.Data, "", " ")
        if err != nil {
                return err
        }
        tmp := s.path + ".tmp"
        if err := os.WriteFile(tmp, data, 0o600); err != nil {
                return err
        }
        if _, err := os.Stat(s.path); err == nil {
                _ = os.Rename(s.path, s.path+".bak")
        }
        return os.Rename(tmp, s.path)
}

func (s *Store) Save() error {
        s.mu.Lock()
        defer s.mu.Unlock()
        return s.save()
}

// GetFileCache returns a cached per-file analysis (§92).
func (s *Store) GetFileCache(hash string) (FileCacheEntry, bool) {
        s.mu.Lock()
        defer s.mu.Unlock()
        e, ok := s.Data.FileCache[hash]
        return e, ok
}

// PutFileCache stores a per-file analysis, pruning the cache when large.
func (s *Store) PutFileCache(hash string, fa FileAnalysis) {
        s.mu.Lock()
        defer s.mu.Unlock()
        s.Data.FileCache[hash] = FileCacheEntry{
                AnalysisVersion: AnalyzerVersion,
                LastSeen:        nowISO(),
                Analysis:        fa,
        }
        if len(s.Data.FileCache) > 50000 {
                s.pruneFileCache()
        }
}

// pruneFileCache removes least-recently-seen entries (§91 bounded caches).
func (s *Store) pruneFileCache() {
        type kv struct {
                k    string
                seen string
        }
        var entries []kv
        for k, v := range s.Data.FileCache {
                entries = append(entries, kv{k, v.LastSeen})
        }
        sort.Slice(entries, func(i, j int) bool { return entries[i].seen < entries[j].seen })
        remove := len(entries) - 30000
        for i := 0; i < remove; i++ {
                delete(s.Data.FileCache, entries[i].k)
        }
}

// RecordScan persists scan + extension states + sets current scan id.
func (s *Store) RecordScan(result *ScanResult) {
        s.mu.Lock()
        defer s.mu.Unlock()
        currentScanIDref = result.Scan.ID
        s.Data.Scans = append(s.Data.Scans, result.Scan)
        if len(s.Data.Scans) > 100 {
                s.Data.Scans = s.Data.Scans[len(s.Data.Scans)-100:]
        }
        for i := range result.Extensions {
                e := result.Extensions[i]
                // keep AI analysis + trim file lists? keep for detail view
                s.Data.Extensions[e.ID] = e
        }
        s.Data.LastScanID = result.Scan.ID
        _ = s.save()
}

// PutSnapshot stores the latest snapshot for an extension and records it in
// the bounded per-scan history (used by compareScans, §130).
func (s *Store) PutSnapshot(scanID string, snap Snapshot) {
        s.mu.Lock()
        defer s.mu.Unlock()
        snap.ScanID = scanID
        s.Data.Snapshots[snap.ExtensionID] = snap
        if scanID != "" {
                if s.Data.SnapshotHistory[scanID] == nil {
                        s.Data.SnapshotHistory[scanID] = map[string]Snapshot{}
                }
                s.Data.SnapshotHistory[scanID][snap.ExtensionID] = snap
                // bound history to the most recent 20 scans
                if len(s.Data.SnapshotHistory) > 20 {
                        for i := 0; i < len(s.Data.Scans) && len(s.Data.SnapshotHistory) > 20; i++ {
                                old := s.Data.Scans[i].ID
                                delete(s.Data.SnapshotHistory, old)
                        }
                }
        }
        _ = s.save()
}

// SnapshotsForScan returns the per-extension snapshots recorded for one scan.
func (s *Store) SnapshotsForScan(scanID string) map[string]Snapshot {
        s.mu.Lock()
        defer s.mu.Unlock()
        out := map[string]Snapshot{}
        for id, snap := range s.Data.SnapshotHistory[scanID] {
                out[id] = snap
        }
        return out
}

// PreviousSnapshot returns the most recent snapshot for an extension that
// comes from a scan older than excludeScanID.
func (s *Store) PreviousSnapshot(extID, excludeScanID string) *Snapshot {
        s.mu.Lock()
        defer s.mu.Unlock()
        snap, ok := s.Data.Snapshots[extID]
        if !ok || snap.ScanID == excludeScanID || snap.ScanID == "" {
                return nil
        }
        cp := snap
        return &cp
}

// LatestFinishedScan returns the newest finished scan excluding excludeID.
func (s *Store) LatestFinishedScan(excludeID string) *Scan {
        s.mu.Lock()
        defer s.mu.Unlock()
        for i := len(s.Data.Scans) - 1; i >= 0; i-- {
                sc := s.Data.Scans[i]
                if sc.ID != excludeID && sc.Status != "SCAN_FAILED" {
                        cp := sc
                        return &cp
                }
        }
        return nil
}

// ListScans returns stored scan summaries.
func (s *Store) ListScans() []Scan {
        s.mu.Lock()
        defer s.mu.Unlock()
        out := make([]Scan, len(s.Data.Scans))
        copy(out, s.Data.Scans)
        return out
}

// GetScanResult reconstructs the last-known extension reports for a scan.
func (s *Store) GetScanResult(scanID string) *ScanResult {
        s.mu.Lock()
        defer s.mu.Unlock()
        var scan *Scan
        for i := range s.Data.Scans {
                if s.Data.Scans[i].ID == scanID {
                        cp := s.Data.Scans[i]
                        scan = &cp
                        break
                }
        }
        if scan == nil {
                return nil
        }
        res := &ScanResult{Scan: *scan}
        for id, e := range s.Data.Extensions {
                if id == e.ID {
                        res.Extensions = append(res.Extensions, e)
                }
        }
        sort.Slice(res.Extensions, func(i, j int) bool {
                if res.Extensions[i].OverallStatus != res.Extensions[j].OverallStatus {
                        return statusRank(res.Extensions[i].OverallStatus) > statusRank(res.Extensions[j].OverallStatus)
                }
                return res.Extensions[i].Name < res.Extensions[j].Name
        })
        return res
}

func statusRank(s string) int {
        switch s {
        case "Significant Concerns":
                return 3
        case "Needs Review":
                return 2
        case "Analysis Incomplete":
                return 1
        }
        return 0
}

// GetExtension returns the latest stored report for one extension.
func (s *Store) GetExtension(extID string) (*ExtensionReport, bool) {
        s.mu.Lock()
        defer s.mu.Unlock()
        e, ok := s.Data.Extensions[extID]
        if !ok {
                return nil, false
        }
        return &e, true
}

// DeleteAllHistory removes every scan, snapshot and cache (§64).
func (s *Store) DeleteAllHistory() error {
        s.mu.Lock()
        defer s.mu.Unlock()
        s.Data = freshStore()
        return s.save()
}

// MarkInterruptedScans flags stale running scans (§160 crash recovery).
func (s *Store) MarkInterruptedScans() {
        s.mu.Lock()
        defer s.mu.Unlock()
        changed := false
        for i := range s.Data.Scans {
                if s.Data.Scans[i].FinishedAt == "" {
                        s.Data.Scans[i].Status = "SCAN_INTERRUPTED"
                        s.Data.Scans[i].FinishedAt = nowISO()
                        changed = true
                }
        }
        if changed {
                _ = s.save()
        }
}

// ---- AI cache (§113) ----

func (s *Store) AICacheGet(key string) (AICacheEntry, bool) {
        s.mu.Lock()
        defer s.mu.Unlock()
        e, ok := s.Data.AICache[key]
        return e, ok
}

func (s *Store) AICachePut(key string, e AICacheEntry) {
        s.mu.Lock()
        defer s.mu.Unlock()
        s.Data.AICache[key] = e
        if len(s.Data.AICache) > 2000 {
                // simple bound
                for k := range s.Data.AICache {
                        delete(s.Data.AICache, k)
                        if len(s.Data.AICache) <= 1500 {
                                break
                        }
                }
        }
        _ = s.save()
}
