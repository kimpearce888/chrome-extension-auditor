/** Popup (§7): the compact summary the user sees first. */
import { nativeHost } from '../core/native';
import { fmtDate, type ScanResult } from '../core/types';

const $ = (id: string) => document.getElementById(id)!;

async function loadStatus(): Promise<void> {
  // last stored scan result (from dashboard broadcasts / storage)
  const { lastScanResult } = await chrome.storage.local.get('lastScanResult');
  render(lastScanResult as ScanResult | undefined);

  const statusLine = $('statusLine');
  try {
    const st = await nativeHost.request<any>('getStatus', {});
    const host = 'Native scanner: connected';
    const lmRaw = await nativeHost.request<any>('getLMStudioStatus', {});
    const lm = lmRaw && lmRaw.reachable
      ? ` · LM Studio: local (${(lmRaw.models || []).length} models)`
      : ' · LM Studio: unavailable (static audit still works)';
    statusLine.textContent = host + lm;
    statusLine.className = 'meta';
  } catch (e) {
    statusLine.textContent =
      'Native scanner not connected. Run Install.bat from the package, then reload this extension.';
    statusLine.className = 'meta err';
  }
}

function render(result: ScanResult | undefined): void {
  if (!result || !result.scan) {
    $('lastScan').textContent = 'Not available';
    return;
  }
  const s = result.scan;
  $('extCount').textContent = String(s.extensionsFound);
  $('profCount').textContent = String(s.profilesScanned);
  const byCat = s.stats.findingsByCategory || {};
  $('secFindings').textContent = String(byCat['security'] || 0);
  $('perfFindings').textContent = String(byCat['performance'] || 0);
  $('privFindings').textContent = String(byCat['privacy'] || 0);
  $('compatFindings').textContent = String(byCat['compatibility'] || 0);
  $('lastScan').textContent = fmtDate(s.finishedAt);
}

$('openDashboard').addEventListener('click', () => {
  chrome.tabs.create({ url: chrome.runtime.getURL('dashboard.html') });
  window.close();
});

$('quickScan').addEventListener('click', async () => {
  const btn = $('quickScan') as HTMLButtonElement;
  btn.disabled = true;
  btn.textContent = 'Scanning…';
  chrome.runtime.sendMessage({ kind: 'scan', mode: 'quick' });
  setTimeout(() => window.close(), 1500);
});

loadStatus();
