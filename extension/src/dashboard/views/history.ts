/** Scan history (§129) + before/after diff (§130). */
import { el, state } from '../app';
import { nativeHost } from '../../core/native';
import { fmtDate } from '../../core/types';

export function renderHistory(): HTMLElement {
  const page = el('div', {});
  page.append(el('h1', { style: 'font-size:18px;margin-top:0' }, 'Scan history & diffs'));
  page.append(el('p', { class: 'muted' }, 'Before/after comparison is one of the strongest features: permission, host, code and finding changes between scans.'));

  const listCard = el('div', { class: 'card' }, el('h2', {}, 'Stored scans'));
  const out = el('div', { class: 'section-gap' });

  (async () => {
    let scans: any[] = [];
    try {
      const res = await nativeHost.request<any>('getScan', {});
      scans = res?.scan ? [res.scan] : [];
      // the host keeps history; listScans is exposed via getScan (latest) and
      // compareScans (pairs). Show latest + comparison tooling below.
    } catch { /* host offline */ }
    if (!scans.length) {
      listCard.append(el('div', { class: 'empty' }, 'No scans stored yet.'));
    } else {
      const s = scans[0];
      listCard.append(el('div', {},
        `Latest: ${fmtDate(s.finishedAt)} · mode ${s.mode} · status ${s.status} · ${s.extensionsFound} extensions · scanner ${s.scannerVersion} (rules ${s.ruleSetVersion})`));
    }
    listCard.append(out);
  })();

  page.append(listCard);

  // compare two scans (§130)
  const cmpCard = el('div', { class: 'card section-gap' }, el('h2', {}, 'Compare the two most recent scans'));
  const btn = el('button', { class: 'btn primary' }, 'Run comparison');
  const result = el('div', { class: 'section-gap' });
  btn.addEventListener('click', async () => {
    result.textContent = 'Comparing…';
    try {
      const diff = await nativeHost.request<any>('compareScans', {});
      result.innerHTML = '';
      const exts = diff?.extensions || [];
      if (!exts.length) {
        result.append(el('div', { class: 'notice ok' }, 'No differences found between the two most recent scans.'));
      }
      for (const item of exts) {
        const box = el('div', { class: 'finding' });
        const name = item.name || item.extensionId;
        if (item.change === 'new') {
          box.append(el('b', {}, `${name} — new since previous scan`));
        } else if (item.change === 'removed') {
          box.append(el('b', {}, `${name} — removed since previous scan (history kept)`));
        } else {
          box.append(el('b', {}, `${name} — changed`));
          for (const c of item.changes || []) {
            box.append(el('div', { class: 'row', style: 'margin-top:4px' },
              el('span', { class: 'tag' }, c.kind),
              el('span', {}, c.detail),
              c.old && c.new ? el('span', { class: 'muted mono' }, `${c.old} → ${c.new}`) : '',
            ));
          }
        }
        result.append(box);
      }
    } catch (e: any) {
      result.textContent = `Could not compare: ${e.message}`;
    }
  });
  cmpCard.append(btn, result);
  page.append(cmpCard);

  return page;
}
