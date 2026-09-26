/** Side-by-side comparison (§85, §123) + profile comparison (§86). No winners. */
import { el, state } from '../app';
import { humanSize, type ExtensionReport } from '../../core/types';

export function renderCompare(): HTMLElement {
  const page = el('div', {});
  const exts = state.scan?.extensions || [];
  if (exts.length < 2) {
    page.append(el('div', { class: 'empty' },
      el('div', { class: 'big' }, 'Need at least two scanned extensions'),
      el('div', { class: 'hint' }, 'Comparison shows documented differences only — no ranking.')));
    return page;
  }

  page.append(el('h1', { style: 'font-size:18px;margin-top:0' }, 'Compare extensions'));
  page.append(el('p', { class: 'muted' }, 'Select two or more extensions to see documented differences side by side. This view does not generate a winner.'));

  const container = el('div', { class: 'card' });
  const selected = new Set<string>();

  const list = el('div', { class: 'grid cols-2', style: 'margin-bottom:14px' });
  for (const e of exts) {
    const row = el('label', { class: 'row', style: 'cursor:pointer' });
    const cb = el('input', { type: 'checkbox' }) as HTMLInputElement;
    cb.addEventListener('change', () => {
      if (cb.checked) selected.add(e.id);
      else selected.delete(e.id);
      renderMatrix();
    });
    row.append(cb, document.createTextNode(` ${e.name} (v${e.version})`));
    list.append(row);
  }
  container.append(list);
  const matrixHost = el('div', {});
  container.append(matrixHost);
  page.append(container);

  // profile comparison (§86)
  const profiles = state.scan?.profiles || [];
  if (profiles.length >= 2) {
    const profCard = el('div', { class: 'card section-gap' },
      el('h2', {}, 'Profile comparison'));
    const table = el('table', { class: 'data' });
    const head = el('tr', {}, el('th', {}, 'Extension'));
    for (const p of profiles) head.append(el('th', {}, p.name));
    table.append(el('thead', {}, head));
    const tb = el('tbody');
    for (const e of exts) {
      const tr = el('tr', {}, el('td', {}, el('code', {}, `${e.name}`)));
      for (const p of profiles) {
        const inst = e.installations.find((i) => i.profileId === p.id);
        if (!inst) {
          tr.append(el('td', {}, el('span', { class: 'muted' }, 'not installed')));
        } else {
          const bits = [inst.version !== e.version ? `v${inst.version} (differs)` : `v${inst.version}`];
          bits.push(inst.enabled ? 'enabled' : `disabled (${inst.disabledReason})`);
          if (inst.installType && inst.installType !== 'Not available') bits.push(inst.installType);
          tr.append(el('td', {}, bits.join(' · ')));
        }
      }
      tb.append(tr);
    }
    table.append(tb);
    profCard.append(table);
    page.append(profCard);
  }

  function renderMatrix(): void {
    matrixHost.innerHTML = '';
    const chosen = exts.filter((e) => selected.has(e.id));
    if (chosen.length < 2) {
      matrixHost.append(el('div', { class: 'empty' }, 'Select at least two extensions above.'));
      return;
    }
    const rows: Array<[string, (e: ExtensionReport) => string]> = [
      ['Version', (e) => e.version],
      ['Manifest', (e) => String(e.manifestVersion)],
      ['Permissions (required)', (e) => String(e.permissions.filter((p) => p.source === 'required').length)],
      ['Permissions (optional)', (e) => String(e.permissions.filter((p) => p.source === 'optional').length)],
      ['Host patterns', (e) => String(e.hostPermissions.length)],
      ['All-sites access', (e) => e.hostPermissions.some((h) => h.breadth === 'all urls') ? 'Yes' : 'No'],
      ['Content scripts', (e) => e.contentScripts.length ? `Yes (${e.contentScripts.length})` : 'No'],
      ['Background', (e) => e.background.type],
      ['Native messaging', (e) => e.background.hasNative ? 'Yes' : 'No'],
      ['Package size', (e) => humanSize(e.package.totalSize)],
      ['Files', (e) => String(e.package.totalFiles)],
      ['Minified', (e) => e.readability.minified ? 'Yes' : 'No'],
      ['Obfuscation indicators', (e) => e.readability.obfuscated ? 'Yes' : 'No'],
      ['Network destinations', (e) => String(e.network.length)],
      ['Third-party domains', (e) => String(e.network.filter((n) => n.classification === 'third-party' || n.classification === 'analytics' || n.classification === 'advertising').length)],
      ['Findings', (e) => String(e.findings.length)],
      ['Security findings', (e) => String(e.findings.filter((f) => f.category === 'security').length)],
      ['Coverage', (e) => `${e.analysis.coverage.toFixed(0)}%`],
      ['Overall status', (e) => e.overallStatus],
    ];
    const table = el('table', { class: 'data' });
    const head = el('tr', {}, el('th', {}, ''));
    for (const e of chosen) head.append(el('th', {}, `${e.name} v${e.version}`));
    table.append(el('thead', {}, head));
    const tb = el('tbody');
    for (const [label, fn] of rows) {
      const tr = el('tr', {}, el('th', { scope: 'row' }, label));
      for (const e of chosen) tr.append(el('td', {}, fn(e)));
      tb.append(tr);
    }
    table.append(tb);
    matrixHost.append(table);
  }
  renderMatrix();
  return page;
}
