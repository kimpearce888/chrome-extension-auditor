/**
 * Background service worker: the bridge between UI pages and the native host.
 * Keeps one native connection alive, routes scan progress to any open
 * dashboard, and manages the optional scan schedule (§146) and local
 * notifications (§147-148). It makes NO network requests of its own.
 */

import { nativeHost } from './core/native';

const ALARM_SCHEDULE = 'cea-scheduled-scan';

interface ScanRequestMessage {
  kind: 'scan';
  mode: string;
  chromeVersion: string;
  lm?: Record<string, unknown>;
}

// management inventory snapshot for the current profile (§9: Chrome-exposed
// metadata is authoritative for the profile the auditor runs in).
let managementCache: any[] | null = null;

async function refreshManagementInventory(): Promise<any[]> {
  return new Promise((resolve) => {
    try {
      chrome.management.getAll((all: any[]) => {
        managementCache = all.map((e) => ({
          id: e.id,
          name: e.name,
          version: e.version,
          enabled: e.enabled,
          installType: e.installType,
          type: e.type,
          description: e.description,
          mayDisable: e.mayDisable,
          disabledReason: e.disabledReason,
        }));
        resolve(managementCache!);
      });
    } catch {
      resolve([]);
    }
  });
}

async function getLMOptions(): Promise<Record<string, unknown>> {
  const { settings } = await chrome.storage.local.get('settings');
  if (!settings || !settings.lm) return {};
  return {
    lmBaseUrl: settings.lm.baseUrl,
    lmModel: settings.lm.model,
    lmTemperature: settings.lm.temperature,
    lmMaxTokens: settings.lm.maxTokens,
    lmTimeoutSec: settings.lm.timeoutSec,
  };
}

async function runScan(mode: string, senderTabId?: number): Promise<void> {
  const inv = await refreshManagementInventory();
  const lm = await getLMOptions();
  const options: Record<string, unknown> = {
    mode,
    chromeVersion: getChromeVersion(),
    managementInventory: inv,
    ...lm,
  };
  try {
    const result = await nativeHost.request<any>('scanAll', options, (ev, payload) => {
      if (ev === 'progress') {
        broadcast({ kind: 'scanProgress', progress: payload });
      }
    });
    broadcast({ kind: 'scanComplete', result });
    maybeNotifyChanges(result);
    // store last scan id for popup
    if (result && result.scan && result.scan.id) {
      await chrome.storage.local.set({ lastScanId: result.scan.id });
    }
  } catch (e: any) {
    broadcast({ kind: 'scanError', error: String(e && e.message ? e.message : e) });
  }
}

function getChromeVersion(): string {
  const m = navigator.userAgent.match(/Chrome\/(\d+(?:\.\d+)*)/);
  return m ? m[1] : 'Not available';
}

function broadcast(msg: unknown): void {
  chrome.runtime.sendMessage(msg).catch(() => {
    /* no listener — dashboard closed; fine */
  });
}

/** Optional local notifications for new/removed extensions (§147-148). */
async function maybeNotifyChanges(result: any): Promise<void> {
  try {
    const { settings } = await chrome.storage.local.get('settings');
    if (!settings || !settings.notifications) return;
    const granted = await new Promise<boolean>((res) => {
      try {
        chrome.notifications.getPermissionLevel?.((lvl: string) => res(lvl === 'granted'));
      } catch {
        res(false);
      }
    });
    if (!granted) return;
    const newOnes: string[] = (result.newSinceLast || []).filter((id: string) => id !== AUDITOR_ID());
    const removed: string[] = result.removedSinceLast || [];
    if (newOnes.length > 0) {
      const names = newOnes
        .map((id) => (result.extensions || []).find((e: any) => e.id === id)?.name || id)
        .slice(0, 3);
      chrome.notifications.create({
        type: 'basic',
        iconUrl: chrome.runtime.getURL('icons/icon128.png'),
        title: 'Chrome extension changes detected',
        message: `New extension(s) since previous scan: ${names.join(', ')}`,
      });
    } else if (removed.length > 0) {
      chrome.notifications.create({
        type: 'basic',
        iconUrl: chrome.runtime.getURL('icons/icon128.png'),
        title: 'Chrome extension changes detected',
        message: `${removed.length} extension(s) removed since previous scan.`,
      });
    }
  } catch {
    /* notifications are optional; never break the scan */
  }
}

function AUDITOR_ID(): string {
  return chrome.runtime.id;
}

chrome.runtime.onMessage.addListener((msg: ScanRequestMessage | { kind: string }, _sender, sendResponse) => {
  if (!msg || typeof msg !== 'object') return;
  switch (msg.kind) {
    case 'scan':
      runScan((msg as ScanRequestMessage).mode);
      sendResponse({ accepted: true });
      return true;
    case 'cancelScan':
      nativeHost.cancelScan().then(() => sendResponse({ cancelled: true }));
      return true;
    case 'getManagementInventory':
      (async () => {
        const inv = managementCache ?? (await refreshManagementInventory());
        sendResponse({ inventory: inv });
      })();
      return true;
    default:
      return;
  }
});

// Scheduled scans (§146) — local alarms only.
async function setupSchedule(): Promise<void> {
  const { settings } = await chrome.storage.local.get('settings');
  const sched = settings?.scheduledScans || 'off';
  chrome.alarms.clear(ALARM_SCHEDULE, () => {
    if (sched === 'daily') {
      chrome.alarms.create(ALARM_SCHEDULE, { periodInMinutes: 60 * 24 });
    } else if (sched === 'weekly') {
      chrome.alarms.create(ALARM_SCHEDULE, { periodInMinutes: 60 * 24 * 7 });
    }
  });
}

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === ALARM_SCHEDULE) {
    (async () => {
      const { settings } = await chrome.storage.local.get('settings').catch(() => ({ settings: null }));
      runScan((settings as any)?.scanMode || 'standard');
    })();
  }
});

chrome.runtime.onInstalled.addListener(() => {
  setupSchedule();
  refreshManagementInventory();
});

chrome.runtime.onStartup.addListener(() => {
  setupSchedule();
  refreshManagementInventory();
  nativeHost.connect();
});
