/**
 * Shared data types mirroring the native scanner's model (/). * "Not available" is an explicit, honest value — fields are never invented (§9).
 */

export interface Profile {
  id: string;
  name: string;
  dir: string;
  available: boolean;
  error?: string;
  extensionCount: number;
}

export interface ExtensionInstallation {
  profileId: string;
  profileName: string;
  enabled: boolean;
  disabledReason: string;
  installType: string;
  version: string;
  path: string;
  installedByPolicy: boolean;
  location: string;
}

export interface PermissionInfo {
  name: string;
  source: string;
  risk: string;
  riskContext: string;
  description: string;
  whyItMatters?: string;
  observedUse: string;
  evidence: string[];
  grantedState: string;
}

export interface HostPatternInfo {
  pattern: string;
  scheme: string;
  host: string;
  breadth: string;
  notes?: string;
  sensitive: boolean;
}

export interface ContentScriptInfo {
  matches: string[];
  includeGlobs?: string[];
  excludeMatches?: string[];
  excludeGlobs?: string[];
  runAt: string;
  allFrames: boolean;
  matchAboutBlank: boolean;
  world: string;
  scriptFiles: string[];
  cssFiles: string[];
  scriptCount: number;
  broad: boolean;
}

export interface BackgroundInfo {
  type: string;
  scripts?: string[];
  persistent?: string;
  workerFile?: string;
  hasListeners: number;
  hasAlarms: boolean;
  hasPolling: boolean;
  hasNative: boolean;
  nativeMsgSites?: Array<{ file: string; line: number; kind: string }>;
  timers?: Array<{ file: string; line: number; kind: string; delayMs: number; interval: boolean }>;
}

export interface APIUsage {
  api: string;
  calls: number;
  files: string[];
  evidence: string[];
}

export interface NetworkEndpoint {
  host: string;
  url?: string;
  protocol: string;
  sourceFile: string;
  line: number;
  classification: string;
  method?: string;
}

export interface Dependency {
  name: string;
  version: string;
  confidence: string;
  files: string[];
  license?: string;
}

export interface FileInfo {
  path: string;
  type: string;
  size: number;
  sha256: string;
  minified: boolean;
  hasSourceMap: boolean;
}

export interface PackageStats {
  totalFiles: number;
  totalSize: number;
  byType: Record<string, number>;
  sizeByType: Record<string, number>;
  largestFile: string;
  largestFileSize: number;
  largestJs: string;
  largestJsSize: number;
  largestCss: string;
  largestCssSize: number;
  sourceMaps: number;
  filesSkipped: number;
}

export interface ReadabilityReport {
  level: string;
  minified: boolean;
  bundled: boolean;
  obfuscated: boolean;
  indicators: string[];
  auditImpact: string;
}

export interface Evidence {
  file?: string;
  line?: number;
  field?: string;
  pattern?: string;
  excerpt?: string;
  note?: string;
}

export interface Finding {
  id: string;
  ruleId: string;
  category: string;
  severity: string;
  confidence: string;
  title: string;
  summary: string;
  evidence: Evidence[];
  whyItMatters: string;
  location: string;
  recommendation: string;
}

export interface AnalysisState {
  status: string;
  coverage: number;
  coverageNotes: string[];
  errors?: string[];
}

export interface AIAnalysis {
  summary?: string;
  keyConcerns?: string[];
  positiveFindings?: string[];
  uncertainties?: string[];
  plainEnglishExplanation?: string;
  questionsForUser?: string[];
  model?: string;
  promptVersion?: string;
  generatedAt?: string;
  status?: string;
}

export interface ExtensionReport {
  id: string;
  name: string;
  shortName?: string;
  description: string;
  version: string;
  type: string;
  homepageUrl: string;
  updateUrl: string;
  optionsUrl: string;
  installations: ExtensionInstallation[];
  manifestVersion: number;
  permissions: PermissionInfo[];
  hostPermissions: HostPatternInfo[];
  contentScripts: ContentScriptInfo[];
  background: BackgroundInfo;
  apis: APIUsage[];
  network: NetworkEndpoint[];
  dependencies: Dependency[];
  files: FileInfo[];
  package: PackageStats;
  readability: ReadabilityReport;
  findings: Finding[];
  tags: string[];
  health: Record<string, string>;
  overallStatus: string;
  analysis: AnalysisState;
  ai?: AIAnalysis;
  unknownManifestFields?: string[];
}

export interface ScanStats {
  extensionsAnalyzed: number;
  extensionsFailed: number;
  findingsByCategory: Record<string, number>;
  findingsBySeverity: Record<string, number>;
  extensionsNeedingReview: number;
  incompleteAnalysis: number;
  averageCoverage: number;
}

export interface Scan {
  id: string;
  startedAt: string;
  finishedAt: string;
  mode: string;
  status: string;
  profilesScanned: number;
  extensionsFound: number;
  chromeVersion: string;
  osVersion: string;
  scannerVersion: string;
  ruleSetVersion: string;
  analyzerVersion: string;
  modelUsed?: string;
  stats: ScanStats;
  errors?: string[];
}

export interface ScanResult {
  scan: Scan;
  profiles: Profile[];
  extensions: ExtensionReport[];
  removedSinceLast?: string[];
  newSinceLast?: string[];
}

export interface DiffChange {
  kind: string;
  detail: string;
  old?: string;
  new?: string;
}

export interface LMSettings {
  baseUrl: string;
  model: string;
  temperature: number;
  maxTokens: number;
  timeoutSec: number;
}

export interface LMStatus {
  reachable: boolean;
  models: string[];
  error?: string;
}

export const DEFAULT_LM: LMSettings = {
  baseUrl: 'http://127.0.0.1:1234',
  model: '',
  temperature: 0.2,
  maxTokens: 2048,
  timeoutSec: 180,
};

export type ReviewStatus = 'unreviewed' | 'reviewed' | 'needs-investigation' | 'accepted-risk' | 'ignored';

/** User annotations live in extension storage; never synced anywhere (§127-128). */
export interface UserAnnotation {
  reviewStatus: ReviewStatus;
  notes: string;
  ignoredFindings: Record<string, boolean>; // ruleId -> ignored
}

export interface AppSettings {
  theme: 'light' | 'dark' | 'system';
  scanMode: 'quick' | 'standard' | 'deep';
  lm: LMSettings;
  scheduledScans: 'off' | 'daily' | 'weekly';
  notifications: boolean;
  redactUsernames: boolean;
  redactPaths: boolean;
  redactProfileNames: boolean;
}

export const DEFAULT_SETTINGS: AppSettings = {
  theme: 'system',
  scanMode: 'standard',
  lm: DEFAULT_LM,
  scheduledScans: 'off',
  notifications: false,
  redactUsernames: true,
  redactPaths: true,
  redactProfileNames: true,
};

export function humanSize(n: number): string {
  if (n < 1024) return `${n} B`;
  const units = ['KB', 'MB', 'GB'];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(1)} ${units[i]}`;
}

export function fmtDate(iso: string): string {
  if (!iso || iso === 'Not available') return 'Not available';
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

export const CATEGORY_ORDER = [
  'security', 'privacy', 'permissions', 'network', 'performance',
  'compatibility', 'package', 'code quality', 'maintenance',
] as const;

export function categoryLabel(cat: string): string {
  return cat.charAt(0).toUpperCase() + cat.slice(1);
}

export const NA = 'Not available';
