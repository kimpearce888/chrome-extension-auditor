package main

// Data model per spec §154 (clean data model) and §165 (JSON schemas).
// Missing information is represented explicitly as "Not available" strings,
// never invented.

// ---- Chrome profiles ----

type Profile struct {
        ID             string `json:"id"`
        Name           string `json:"name"`
        Dir            string `json:"dir"`
        Available      bool   `json:"available"`
        Error          string `json:"error,omitempty"`
        ExtensionCount int    `json:"extensionCount"`
}

// ---- Extensions ----

type ExtensionInstallation struct {
        ProfileID         string `json:"profileId"`
        ProfileName       string `json:"profileName"`
        Enabled           bool   `json:"enabled"`
        DisabledReason    string `json:"disabledReason"`
        InstallType       string `json:"installType"`
        Version           string `json:"version"`
        Path              string `json:"path"`
        InstalledByPolicy bool   `json:"installedByPolicy"`
        Location          string `json:"location"`
}

type PermissionInfo struct {
        Name         string   `json:"name"`
        Source       string   `json:"source"` // "required" | "optional"
        Risk         string   `json:"risk"`   // "low" | "moderate" | "high" | "unknown"
        RiskContext  string   `json:"riskContext"`
        Description  string   `json:"description"`
        WhyItMatters string   `json:"whyItMatters,omitempty"`
        ObservedUse  string   `json:"observedUse"` // "detected" | "not observed" | "unable to determine"
        Evidence     []string `json:"evidence"`    // file:line refs
        GrantedState string   `json:"grantedState"`// "required at install" | "optional" | "not granted" | "Not available"
}

type HostPatternInfo struct {
        Pattern     string   `json:"pattern"`
        Scheme      string   `json:"scheme"`
        Host        string   `json:"host"`
        Breadth     string   `json:"breadth"` // "all urls" | "wildcard subdomain" | "specific host" | "local file" | "localhost" | "other"
        Notes       string   `json:"notes,omitempty"`
        Sensitive   bool     `json:"sensitive"`
        Evidence    []string `json:"evidence,omitempty"`
}

type ContentScriptInfo struct {
        Matches       []string `json:"matches"`
        IncludeGlobs  []string `json:"includeGlobs,omitempty"`
        ExcludeMatch  []string `json:"excludeMatches,omitempty"`
        ExcludeGlobs  []string `json:"excludeGlobs,omitempty"`
        RunAt         string   `json:"runAt"`
        AllFrames     bool     `json:"allFrames"`
        MatchAboutBlank bool   `json:"matchAboutBlank"`
        World         string   `json:"world"`
        ScriptFiles   []string `json:"scriptFiles"`
        CssFiles      []string `json:"cssFiles"`
        ScriptCount   int      `json:"scriptCount"`
        Broad         bool     `json:"broad"`
}

type BackgroundInfo struct {
        Type           string      `json:"type"` // "service worker" | "background page" | "legacy scripts" | "none" | "Not available"
        Scripts        []string    `json:"scripts,omitempty"`
        Persistent     string      `json:"persistent,omitempty"`
        WorkerFile     string      `json:"workerFile,omitempty"`
        HasListeners   int         `json:"hasListeners"`
        HasAlarms      bool        `json:"hasAlarms"`
        HasPolling     bool        `json:"hasPolling"`
        HasNative      bool        `json:"hasNative"`
        NativeMsgSites []CodeSite  `json:"nativeMsgSites,omitempty"`
        Timers         []TimerSite `json:"timers,omitempty"`
}

type APIUsage struct {
        API      string   `json:"api"`
        Calls    int      `json:"calls"`
        Files    []string `json:"files"`
        Evidence []string `json:"evidence"`
}

type NetworkEndpoint struct {
        Host           string `json:"host"`
        URL            string `json:"url,omitempty"`
        Protocol       string `json:"protocol"`
        SourceFile     string `json:"sourceFile"`
        Line           int    `json:"line"`
        Classification string `json:"classification"`
        Method         string `json:"method,omitempty"` // fetch | XHR | WebSocket | EventSource | sendBeacon | literal | html | manifest
}

type Dependency struct {
        Name       string   `json:"name"`
        Version    string   `json:"version"`
        Confidence string   `json:"confidence"`
        Files      []string `json:"files"`
        License    string   `json:"license,omitempty"`
}

type FileInfo struct {
        Path            string `json:"path"`
        Type            string `json:"type"`
        Size            int64  `json:"size"`
        SHA256          string `json:"sha256"`
        Minified        bool   `json:"minified"`
        HasSourceMap    bool   `json:"hasSourceMap"`
        LikelyGenerated bool   `json:"likelyGenerated"`
}

type PackageStats struct {
        TotalFiles      int            `json:"totalFiles"`
        TotalSize       int64          `json:"totalSize"`
        ByType          map[string]int `json:"byType"`
        SizeByType      map[string]int64 `json:"sizeByType"`
        LargestFile     string         `json:"largestFile"`
        LargestFileSize int64          `json:"largestFileSize"`
        LargestJS       string         `json:"largestJs"`
        LargestJSSize   int64          `json:"largestJsSize"`
        LargestCSS      string         `json:"largestCss"`
        LargestCSSSize  int64          `json:"largestCssSize"`
        SourceMaps      int            `json:"sourceMaps"`
        FilesSkipped    int            `json:"filesSkipped"`
}

type ReadabilityReport struct {
        Level        string   `json:"level"` // "High" | "Medium" | "Low"
        Minified     bool     `json:"minified"`
        Bundled      bool     `json:"bundled"`
        Obfuscated   bool     `json:"obfuscated"`
        Indicators   []string `json:"indicators"`
        AuditImpact  string   `json:"auditImpact"`
}

// ---- Findings ----

type Evidence struct {
        File     string `json:"file,omitempty"`
        Line     int    `json:"line,omitempty"`
        Field    string `json:"field,omitempty"`
        Pattern  string `json:"pattern,omitempty"`
        Excerpt  string `json:"excerpt,omitempty"`
        Manifest string `json:"manifest,omitempty"`
        Note     string `json:"note,omitempty"`
}

type Finding struct {
        ID             string     `json:"id"`
        RuleID         string     `json:"ruleId"`
        Category       string     `json:"category"` // security|privacy|performance|compatibility|permissions|network|package|code quality|maintenance
        Severity       string     `json:"severity"` // critical|high|medium|low|informational
        Confidence     string     `json:"confidence"` // high|medium|low
        Title          string     `json:"title"`
        Summary        string     `json:"summary"`
        Evidence       []Evidence `json:"evidence"`
        WhyItMatters   string     `json:"whyItMatters"`
        Location       string     `json:"location"`
        Recommendation string     `json:"recommendation"`
}

// ---- Scan lifecycle ----

type ScanStats struct {
        ExtensionsAnalyzed int            `json:"extensionsAnalyzed"`
        ExtensionsFailed   int            `json:"extensionsFailed"`
        FindingsByCategory map[string]int `json:"findingsByCategory"`
        FindingsBySeverity map[string]int `json:"findingsBySeverity"`
        ExtensionsNeedingReview int       `json:"extensionsNeedingReview"`
        IncompleteAnalysis int          `json:"incompleteAnalysis"`
        AverageCoverage   float64       `json:"averageCoverage"`
}

type Scan struct {
        ID              string     `json:"id"`
        StartedAt       string     `json:"startedAt"`
        FinishedAt      string     `json:"finishedAt"`
        Mode            string     `json:"mode"` // quick|standard|deep
        Status          string     `json:"status"` // SCAN_OK|SCAN_PARTIAL|SCAN_FAILED|SCAN_INTERRUPTED
        ProfilesScanned int        `json:"profilesScanned"`
        ExtensionsFound int        `json:"extensionsFound"`
        ChromeVersion   string     `json:"chromeVersion"`
        OSVersion       string     `json:"osVersion"`
        ScannerVersion  string     `json:"scannerVersion"`
        RuleSetVersion  string     `json:"ruleSetVersion"`
        AnalyzerVersion string     `json:"analyzerVersion"`
        ModelUsed       string     `json:"modelUsed,omitempty"`
        Stats           ScanStats  `json:"stats"`
        Errors          []string   `json:"errors,omitempty"`
}

type AnalysisState struct {
        Status        string   `json:"status"`  // SCAN_OK|SCAN_PARTIAL|SCAN_FAILED|MANIFEST_INVALID|...
        Coverage      float64  `json:"coverage"`
        CoverageNotes []string `json:"coverageNotes"`
        Errors        []string `json:"errors,omitempty"`
}

// ---- Full extension audit report ----

type ExtensionReport struct {
        ID              string                  `json:"id"`
        Name            string                  `json:"name"`
        ShortName       string                  `json:"shortName,omitempty"`
        Description     string                  `json:"description"`
        Version         string                  `json:"version"`
        Type            string                  `json:"type"`
        HomepageURL     string                  `json:"homepageUrl"`
        UpdateURL       string                  `json:"updateUrl"`
        OptionsURL      string                  `json:"optionsUrl"`
        Installations   []ExtensionInstallation `json:"installations"`
        ManifestVersion int                     `json:"manifestVersion"`
        Permissions     []PermissionInfo        `json:"permissions"`
        HostPermissions []HostPatternInfo       `json:"hostPermissions"`
        ContentScripts  []ContentScriptInfo     `json:"contentScripts"`
        Background      BackgroundInfo          `json:"background"`
        APIs            []APIUsage              `json:"apis"`
        Network         []NetworkEndpoint       `json:"network"`
        Dependencies    []Dependency            `json:"dependencies"`
        Files           []FileInfo              `json:"files"`
        Package         PackageStats            `json:"package"`
        Readability     ReadabilityReport       `json:"readability"`
        Findings        []Finding               `json:"findings"`
        Tags            []string                `json:"tags"`
        Health          map[string]string       `json:"health"` // category -> status
        OverallStatus   string                  `json:"overallStatus"`
        Analysis        AnalysisState           `json:"analysis"`
        AI              *AIAnalysis              `json:"ai,omitempty"`
        ManifestRaw     map[string]any          `json:"manifestRaw,omitempty"`
        UnknownManifestFields []string          `json:"unknownManifestFields,omitempty"`
}

// ---- Snapshots & diffs (§63, §130) ----

type Snapshot struct {
        ExtensionID    string   `json:"extensionId"`
        ScanID         string   `json:"scanId"`
        TakenAt        string   `json:"takenAt"`
        Version        string   `json:"version"`
        Permissions    []string `json:"permissions"`
        OptionalPerms  []string `json:"optionalPerms"`
        Hosts          []string `json:"hosts"`
        APIs           []string `json:"apis"`
        NetworkHosts   []string `json:"networkHosts"`
        FileHashes     map[string]string `json:"fileHashes"`
        PackageSize    int64    `json:"packageSize"`
        FileCount      int      `json:"fileCount"`
        ContentScripts int      `json:"contentScripts"`
        BackgroundType string   `json:"backgroundType"`
        FindingIDs     []string `json:"findingIds"`
}

type DiffChange struct {
        Kind     string `json:"kind"`   // versionChanged|permissionAdded|permissionRemoved|hostAdded|hostRemoved|apiAdded|domainAdded|packageGrew|packageShrank|fileAdded|fileRemoved|fileChanged|newContentScript|newBackgroundScript|findingAppeared|findingResolved|manifestChanged
        Detail   string `json:"detail"`
        Old      string `json:"old,omitempty"`
        New      string `json:"new,omitempty"`
}

type ScanDiff struct {
        ScanA         string                 `json:"scanA"`
        ScanB         string                 `json:"scanB"`
        ExtensionID   string                 `json:"extensionId"`
        ExtensionName string                 `json:"extensionName"`
        Changes       []DiffChange           `json:"changes"`
        NewExtensions []string               `json:"newExtensions,omitempty"`
        RemovedExtensions []string           `json:"removedExtensions,omitempty"`
}

// ---- AI analysis (§71, §165) ----

type AIAnalysis struct {
        Summary                string   `json:"summary"`
        KeyConcerns            []string `json:"keyConcerns"`
        PositiveFindings       []string `json:"positiveFindings"`
        Uncertainties          []string `json:"uncertainties"`
        PlainEnglishExplanation string  `json:"plainEnglishExplanation"`
        QuestionsForUser       []string `json:"questionsForUser"`
        Model                  string   `json:"model"`
        PromptVersion          string   `json:"promptVersion"`
        GeneratedAt            string   `json:"generatedAt"`
        Status                 string   `json:"status"` // ok|AI_ANALYSIS_FAILED|LM_STUDIO_UNAVAILABLE
}

// ---- LM Studio settings ----

type LMStudioSettings struct {
        BaseURL     string  `json:"baseUrl"`
        Model       string  `json:"model"`
        Temperature float64 `json:"temperature"`
        MaxTokens   int     `json:"maxTokens"`
        TimeoutSec  int     `json:"timeoutSec"`
}

func DefaultLMStudio() LMStudioSettings {
        return LMStudioSettings{
                BaseURL:     "http://127.0.0.1:1234",
                Model:       "",
                Temperature: 0.2,
                MaxTokens:   2048,
                TimeoutSec:  180,
        }
}

// ---- Top-level scan result (what the UI consumes) ----

type ScanResult struct {
        Scan        Scan               `json:"scan"`
        Profiles    []Profile          `json:"profiles"`
        Extensions  []ExtensionReport  `json:"extensions"`
        RemovedSinceLast []string      `json:"removedSinceLast,omitempty"`
        NewSinceLast     []string      `json:"newSinceLast,omitempty"`
}

// ---- Store (§64) ----

type StoreData struct {
        SchemaVersion int                     `json:"schemaVersion"`
        Scans         []Scan                  `json:"scans"`
        Extensions    map[string]ExtensionReport `json:"extensions"`
        Snapshots     map[string]Snapshot     `json:"snapshots"`
        SnapshotHistory map[string]map[string]Snapshot `json:"snapshotHistory"` // scanID -> extID -> snapshot (bounded)
        FileCache     map[string]FileCacheEntry `json:"fileCache"`
        AICache       map[string]AICacheEntry `json:"aiCache"`
        LastScanID    string                  `json:"lastScanId"`
}

type FileCacheEntry struct {
        AnalysisVersion string          `json:"analysisVersion"`
        LastSeen        string          `json:"lastSeen"`
        Analysis        FileAnalysis    `json:"analysis"`
}

type AICacheEntry struct {
        Model         string     `json:"model"`
        PromptVersion string     `json:"promptVersion"`
        CreatedAt     string     `json:"createdAt"`
        Response      AIAnalysis `json:"response"`
}
