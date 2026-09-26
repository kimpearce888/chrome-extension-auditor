/** Settings (§111–113, §146–147, §164): LM Studio, scan mode, schedules,
 * notifications, redaction, data deletion. */
import { el, state, startScan, lmOptions } from '../app';
import { nativeHost } from '../../core/native';
import { DEFAULT_SETTINGS, type LMStatus } from '../../core/types';

export async function renderSettings(): Promise<HTMLElement> {
  const page = el('div', {});
  page.append(el('h1', { style: 'font-size:18px;margin-top:0' }, 'Settings'));
  const s = state.settings;

  const save = async (mutate: () => void) => {
    mutate();
    await chrome.storage.local.set({ settings: state.settings });
  };

  // ---- scan defaults ----
  const scanCard = el('div', { class: 'card' }, el('h2', {}, 'Scanning'));
  const modeSel = el('select', { 'aria-label': 'Default scan mode' },
    ...([['quick', 'Quick — inventory + manifest + permissions'], ['standard', 'Standard — + source, network, performance, dependencies'], ['deep', 'Deep — + AI interpretation and snapshot comparison']] as Array<[string, string]>)
      .map(([v, l]) => {
        const o = el('option', { value: v }, l) as HTMLOptionElement;
        if (s.scanMode === v) o.selected = true;
        return o;
      })) as HTMLSelectElement;
  modeSel.addEventListener('change', () => save(() => { s.scanMode = modeSel.value as any; }));
  scanCard.append(labelled('Default scan mode', modeSel));

  const schedSel = el('select', { 'aria-label': 'Scheduled scans' },
    ...([['off', 'Manual only'], ['daily', 'Daily'], ['weekly', 'Weekly']] as Array<[string, string]>)
      .map(([v, l]) => {
        const o = el('option', { value: v }, l) as HTMLOptionElement;
        if (s.scheduledScans === v) o.selected = true;
        return o;
      })) as HTMLSelectElement;
  schedSel.addEventListener('change', () => save(() => { s.scheduledScans = schedSel.value as any; }));
  scanCard.append(labelled('Scheduled scans (, local only)', schedSel));

  const notifCb = checkbox('Local notifications for extension changes', s.notifications);
  notifCb.addEventListener('change', async () => {
    await save(() => { s.notifications = notifCb.checked; });
    if (notifCb.checked) {
      try { await chrome.permissions.request({ permissions: ['notifications'] }); } catch { /* optional */ }
    }
  });
  scanCard.append(notifCb.parentElement!);
  page.append(scanCard);

  // ---- LM Studio (§111) ----
  const lmCard = el('div', { class: 'card section-gap' }, el('h2', {}, 'LM Studio (local AI)'));
  lmCard.append(el('div', { class: 'sub' },
    'Optional. The deterministic audit works fully without it. All requests go to your local OpenAI-compatible endpoint only.'));

  const urlInput = el('input', { type: 'text', value: s.lm.baseUrl, style: inputStyle }) as HTMLInputElement;
  urlInput.addEventListener('change', () => save(() => { s.lm.baseUrl = urlInput.value.trim() || DEFAULT_LM().baseUrl; }));
  lmCard.append(labelled('Server', urlInput));

  const modelRow = el('div', { class: 'row' });
  const modelSel = el('select', { 'aria-label': 'Model', style: inputStyle }) as HTMLSelectElement;
  modelSel.append(el('option', { value: '' }, s.lm.model ? s.lm.model + ' (selected)' : 'Automatic — first discovered model'));
  modelSel.addEventListener('change', () => save(() => { s.lm.model = modelSel.value; }));
  const testBtn = el('button', { class: 'btn' }, 'Test Connection');
  const testOut = el('span', { class: 'muted', style: 'font-size:11.5px' }, '');
  testBtn.addEventListener('click', async () => {
    testOut.textContent = 'Testing…';
    try {
      const st = await nativeHost.request<LMStatus>('testLMStudio', lmOptions());
      if (st && st.reachable) {
        testOut.textContent = `Reachable — ${st.models?.length || 0} model(s) discovered.`;
        modelSel.innerHTML = '';
        modelSel.append(el('option', { value: '' }, 'Automatic — first discovered model'));
        for (const m of st.models || []) {
          const o = el('option', { value: m }, m) as HTMLOptionElement;
          if (s.lm.model === m) o.selected = true;
          modelSel.append(o);
        }
      } else {
        testOut.textContent = `Unreachable: ${st?.error || 'unknown error'} — static audit remains available.`;
      }
    } catch (e: any) {
      testOut.textContent = `Unreachable: ${e.message}`;
    }
  });
  modelRow.append(modelSel, testBtn, testOut);
  lmCard.append(labelled('Model (discovered from your local server)', modelRow));

  const tempInput = el('input', { type: 'range', min: '0', max: '1', step: '0.1', value: String(s.lm.temperature) }) as HTMLInputElement;
  const tempLabel = el('span', { class: 'muted' }, `Temperature: ${s.lm.temperature}`);
  tempInput.addEventListener('input', () => { tempLabel.textContent = `Temperature: ${tempInput.value}`; });
  tempInput.addEventListener('change', () => save(() => { s.lm.temperature = Number(tempInput.value); }));
  lmCard.append(labelled('', el('div', { class: 'row' }, tempInput, tempLabel)));

  const tokInput = el('input', { type: 'number', min: '256', max: '32768', step: '256', value: String(s.lm.maxTokens), style: inputStyle }) as HTMLInputElement;
  tokInput.addEventListener('change', () => save(() => { s.lm.maxTokens = Number(tokInput.value) || 2048; }));
  lmCard.append(labelled('Max tokens', tokInput));
  page.append(lmCard);

  // ---- report redaction (§164) ----
  const redCard = el('div', { class: 'card section-gap' }, el('h2', {}, 'Report redaction'));
  redCard.append(el('div', { class: 'sub' }, 'Defaults minimize personal information in exported reports. Secrets are always redacted.'));
  for (const [key, label] of [
    ['redactUsernames', 'Redact local usernames in paths'],
    ['redactPaths', 'Redact full filesystem paths'],
    ['redactProfileNames', 'Redact profile names'],
  ] as Array<[keyof typeof s, string]>) {
    const cb = checkbox(label, s[key] as boolean);
    cb.addEventListener('change', () => save(() => { (s as any)[key] = cb.checked; }));
    redCard.append(cb.parentElement!);
  }
  page.append(redCard);

  // ---- appearance ----
  const themeCard = el('div', { class: 'card section-gap' }, el('h2', {}, 'Appearance'));
  const themeSel = el('select', { 'aria-label': 'Theme' },
    ...([['system', 'Follow system'], ['light', 'Light'], ['dark', 'Dark']] as Array<[string, string]>)
      .map(([v, l]) => {
        const o = el('option', { value: v }, l) as HTMLOptionElement;
        if (s.theme === v) o.selected = true;
        return o;
      })) as HTMLSelectElement;
  themeSel.addEventListener('change', () => save(() => { s.theme = themeSel.value as any; }));
  themeCard.append(labelled('Theme', themeSel));
  page.append(themeCard);

  // ---- data control (§64) ----
  const dataCard = el('div', { class: 'card section-gap' }, el('h2', {}, 'Local data'));
  const delBtn = el('button', { class: 'btn danger' }, 'Delete all audit history');
  delBtn.addEventListener('click', async () => {
    if (!confirm('Delete all locally stored scans, snapshots and caches? Your notes and review statuses in the UI are kept until you clear extension storage.')) return;
    try {
      await nativeHost.request('deleteHistory', {});
      await chrome.storage.local.remove(['lastScanResult', 'lastScanId']);
      state.scan = null;
      alert('Audit history deleted.');
      location.hash = '#/overview';
    } catch (e: any) {
      alert(`Could not delete: ${e.message}`);
    }
  });
  dataCard.append(el('div', { class: 'sub' }, 'Everything is stored locally. Deleting history never touches your extensions or browser data.'), delBtn);
  page.append(dataCard);

  return page;
}

function DEFAULT_LM() {
  return DEFAULT_SETTINGS.lm;
}

const inputStyle = 'padding:6px 9px;border-radius:8px;border:1px solid var(--border);background:var(--bg);color:var(--text)';

function labelled(text: string, control: HTMLElement): HTMLElement {
  const wrap = el('div', { style: 'margin-bottom:12px' });
  if (text) wrap.append(el('div', { class: 'muted', style: 'font-size:12px;margin-bottom:4px' }, text));
  const c = el('div', {}, control);
  wrap.append(c);
  return wrap;
}

function checkbox(text: string, checked: boolean): HTMLInputElement {
  const cb = el('input', { type: 'checkbox' }) as HTMLInputElement;
  cb.checked = checked;
  const label = el('label', { class: 'row', style: 'cursor:pointer;margin-bottom:8px' }, cb, document.createTextNode(' ' + text));
  cb.parentElement!.append();
  return cb;
}
