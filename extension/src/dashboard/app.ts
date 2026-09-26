/**
 * Dashboard application: hash-routed SPA over the native host's data. * No network access — everything is local (§100, §168).
 */
import { nativeHost } from '../core/native';
import {
  DEFAULT_SETTINGS, type AppSettings, type ScanResult, type ExtensionReport,
  type UserAnnotation, type ReviewStatus, fmtDate,
} from '../core/types';
import { renderOverview } from './views/overview';
import { renderExtensions } from './views/list';
import { renderDetail } from './views/detail';
import { renderCompare } from './views/compare';
import { renderHistory } from './views/history';
import { renderSettings } from './views/settings';
import { renderPrivacy } from './views/privacy';

export const state = {
  scan: null as ScanResult | null,
  settings: { ...DEFAULT_SETTINGS } as AppSettings,
  annotations: {} as Record<string, UserAnnotation>,
  scanning: false,
};

export const $ = (sel: string, root: ParentNode = document): HTMLElement =>
  root.querySelector(sel) as HTMLElement;

export function el(tag: string, attrs: Record<string, string | boolean> = {}, ...children: (Node | string | null | undefined)[]): HTMLElement {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === true) node.setAttribute(k, '');
    else if (v !== false && v != null) node.setAttribute(k, String(v));
  }
  for (const c of children) {
    if (c == null) continue;
    node.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return node;
}

export function esc(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');}

// ---------- persistence ----------

export async function loadState(): Promise<void> {
  const data = await chrome.storage.local.get(['settings', 'lastScanResult', 'annotations']);
  if (data.settings) state.settings = { ...DEFAULT_SETTINGS, ...data.settings, lm: { ...DEFAULT_SETTINGS.lm, ...(data.settings.lm || {}) } };
  if (data.lastScanResult) state.scan = normalizeScan(data.lastScanResult);
  if (data.annotations) state.annotations = data.annotations;
}

/** Defensive: guarantee iterable arrays on every extension report so no
 * view can crash on `.map()` of a null field, whatever produced the data. */
export function normalizeScan(s: any): ScanResult {
  if (!s || !Array.isArray(s.extensions)) return s;
  const arrays = ['installations', 'permissions', 'hostPermissions', 'contentScripts',
    'apis', 'network', 'dependencies', 'files', 'findings', 'tags', 'unknownManifestFields'];
  for (const e of s.extensions) {
    for (const k of arrays) if (!Array.isArray(e[k])) e[k] = [];
    if (!e.health || typeof e.health !== 'object') e.health = {};
    if (!e.analysis) e.analysis = { status: 'Not available', coverage: 0, coverageNotes: [] } as any;
    else if (!Array.isArray(e.analysis.coverageNotes)) e.analysis.coverageNotes = [];
  }
  return s;
}

async function persist(): Promise<void> {
  await chrome.storage.local.set({
    settings: state.settings,
    annotations: state.annotations,
  });
}

export function getAnnotation(extId: string): UserAnnotation {
  return state.annotations[extId] || { reviewStatus: 'unreviewed', notes: '', ignoredFindings: {} };
}

export async function setReviewStatus(extId: string, status: ReviewStatus): Promise<void> {
  const a = getAnnotation(extId);
  a.reviewStatus = status;
  state.annotations[extId] = a;
  await persist();
}

export async function setNotes(extId: string, notes: string): Promise<void> {
  const a = getAnnotation(extId);
  a.notes = notes;
  state.annotations[extId] = a;
  await persist();
}

export async function toggleIgnoredFinding(extId: string, ruleId: string): Promise<void> {
  const a = getAnnotation(extId);
  if (a.ignoredFindings[ruleId]) delete a.ignoredFindings[ruleId];
  else a.ignoredFindings[ruleId] = true;
  state.annotations[extId] = a;
  await persist();
}

export function restoreFinding(extId: string, ruleId: string): void {
  const a = getAnnotation(extId);
  delete a.ignoredFindings[ruleId];
  state.annotations[extId] = a;
  persist();
}

// ---------- native host requests with LM settings (§111) ----------

export function lmOptions(): Record<string, unknown> {
  const lm = state.settings.lm;
  return {
    lmBaseUrl: lm.baseUrl,
    lmModel: lm.model,
    lmTemperature: lm.temperature,
    lmMaxTokens: lm.maxTokens,
    lmTimeoutSec: lm.timeoutSec,
  };
}

export function chromeVersion(): string {
  const m = navigator.userAgent.match(/Chrome\/(\d+(?:\.\d+)*)/);
  return m ? m[1] : 'Not available';
}

async function managementInventory(): Promise<unknown[]> {
  return new Promise((resolve) => {
    try {
      chrome.management.getAll((all) => {
        resolve(all.map((e) => ({
          id: e.id, name: e.name, version: e.version, enabled: e.enabled,
          installType: e.installType, type: e.type, description: e.description,
          mayDisable: e.mayDisable, disabledReason: e.disabledReason,
        })));
      });
    } catch {
      resolve([]);
    }
  });
}

// ---------- scanning (§87 modes, §88 progress, §161 cancel) ----------

export async function startScan(mode?: string): Promise<void> {
  if (state.scanning) return;
  state.scanning = true;
  const useMode = mode || state.settings.scanMode;
  const banner = $('#scanBanner');
  banner.hidden = false;
  setProgress('Contacting local scanner…', 0);
  try {
    const inv = await managementInventory();
    const result = await nativeHost.request<ScanResult>('scanAll', {
      mode: useMode,
      chromeVersion: chromeVersion(),
      managementInventory: inv,
      ...lmOptions(),
    }, (ev, payload) => {
      if (ev === 'progress' && payload) {
        setProgress(payload.message || payload.stage, payload.total ? payload.current / payload.total : 0);
      }
    });
    state.scan = normalizeScan(result);
    await chrome.storage.local.set({ lastScanResult: result, lastScanId: result?.scan?.id });
    setProgress('Scan completed', 1);
  } catch (e: any) {
    setProgress(`Scan failed: ${String(e && e.message ? e.message : e)}`, 0);
  } finally {
    state.scanning = false;
    setTimeout(() => { banner.hidden = true; }, 1800);
    route();
  }
}

function setProgress(text: string, fraction: number): void {
  $('#scanProgressText').textContent = text;
  ($('#scanBarFill') as HTMLElement).style.width = `${Math.round(Math.min(1, Math.max(0, fraction)) * 100)}%`;
}

// ---------- router ----------

const routes: Record<string, (params: string[]) => Promise<HTMLElement | void> | HTMLElement | void> = {
  overview: () => renderOverview(),
  extensions: () => renderExtensions(),
  ext: (params) => renderDetail(params[0], params[1]),
  compare: () => renderCompare(),
  history: () => renderHistory(),
  settings: () => renderSettings(),
  privacy: () => renderPrivacy(),
};

export function route(): void {
  const hash = location.hash.replace(/^#\//, '') || 'overview';
  const [view, ...params] = hash.split('/');
  const main = $('#main');
  main.innerHTML = '';
  document.querySelectorAll('.tab').forEach((t) => {
    t.classList.toggle('active', (t as HTMLElement).dataset.view === view || (view.startsWith('ext') && (t as HTMLElement).dataset.view === 'extensions'));
  });
  const fn = routes[view] || routes.overview;
  Promise.resolve(fn(params)).then((node) => {
    if (node) {
      main.innerHTML = '';
      main.append(node);
    }
  }).catch((e) => {
    main.innerHTML = '';
    main.append(el('div', { class: 'empty' },
      el('div', { class: 'big' }, '⚠'),
      el('div', {}, `View failed to load: ${String(e)}`)));
  });
  updateFooter();
}

function updateFooter(): void {
  const meta = $('#footerMeta');
  if (state.scan) {
    const s = state.scan.scan;
    meta.textContent = `Last scan ${fmtDate(s.finishedAt)} · mode ${s.mode} · scanner ${s.scannerVersion} (rules ${s.ruleSetVersion})`;
  } else {
    meta.textContent = 'No scan yet.';
  }
}

// ---------- boot ----------

window.addEventListener('hashchange', route);

document.addEventListener('DOMContentLoaded', async () => {
  await loadState();
  $('#btnScan').addEventListener('click', () => startScan());
  $('#btnCancelScan').addEventListener('click', async () => {
    await nativeHost.cancelScan();
    setProgress('Cancelling… (saving partial results)', 0);
  });
  $('#globalSearch').addEventListener('input', (e) => {
    const q = (e.target as HTMLInputElement).value.trim();
    if (q && location.hash.replace(/^#\//, '').split('/')[0] !== 'extensions') {
      location.hash = '#/extensions';
    }
    window.dispatchEvent(new CustomEvent('cea:search', { detail: q }));
  });
  // keyboard: "/" focuses search (§144)
  document.addEventListener('keydown', (e) => {
    if (e.key === '/' && !/INPUT|TEXTAREA|SELECT/.test((e.target as HTMLElement).tagName)) {
      e.preventDefault();
      ($('#globalSearch') as HTMLInputElement).focus();
    }
  });
  route();
});
