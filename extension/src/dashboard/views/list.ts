/** Extension inventory list (§9, §120): cards, search (§121), filters (§83), sort (§84), tags (§122). */
import { el, state } from '../app';
import { humanSize, type ExtensionReport } from '../../core/types';
import { extIcon, statusChip, tagList } from './components';

type Filter = 'all' | 'needs-review' | 'security' | 'privacy' | 'performance' | 'compatibility' | 'permissions' | 'network' | 'high' | 'medium' | 'low';
type SortKey = 'name' | 'findings' | 'severity' | 'size' | 'permissions' | 'hosts' | 'lastScanned' | 'version';

let currentFilter: Filter = 'all';
let currentSort: SortKey = 'severity';
let searchQuery = '';

window.addEventListener('cea:search', (e) => {
  searchQuery = (e as CustomEvent).detail || '';
  rerenderList();
});

function rerenderList(): void {
  const host = document.getElementById('extListHost');
  if (host) {
    host.innerHTML = '';
    host.append(listBody());
  }
}

export function renderExtensions(): HTMLElement {
  const page = el('div', {});
  if (!state.scan) {
    page.append(el('div', { class: 'empty' },
      el('div', { class: 'big' }, 'No scan yet'),
      el('div', { class: 'hint' }, 'Run your first scan from the Overview page.')));
    return page;
  }
  const exts = state.scan.extensions || [];

  // ---- toolbar: filters + sort (§83–84) ----
  const filters: Array<[Filter, string]> = [
    ['all', 'All'], ['needs-review', 'Needs Review'], ['security', 'Security'], ['privacy', 'Privacy'],
    ['performance', 'Performance'], ['compatibility', 'Compatibility'], ['permissions', 'Permissions'],
    ['network', 'Network'], ['high', 'High severity'], ['medium', 'Medium severity'], ['low', 'Low severity'],
  ];
  const chips = el('div', { class: 'filter-chips', role: 'group', 'aria-label': 'Filter extensions' });
  for (const [f, label] of filters) {
    const chip = el('button', { class: `fchip${currentFilter === f ? ' active' : ''}` }, label);
    chip.addEventListener('click', () => { currentFilter = f; rerenderList(); });
    chips.append(chip);
  }

  const sortSel = el('select', { 'aria-label': 'Sort extensions' },
    ...([
      ['severity', 'Sort: severity signals'], ['findings', 'Sort: finding count'], ['name', 'Sort: name'],
      ['size', 'Sort: package size'], ['permissions', 'Sort: permission count'],
      ['hosts', 'Sort: host patterns'], ['version', 'Sort: version'],
    ] as Array<[SortKey, string]>).map(([v, l]) => {
      const o = el('option', { value: v }, l) as HTMLOptionElement;
      if (v === currentSort) o.selected = true;
      return o;
    }));
  sortSel.addEventListener('change', () => { currentSort = (sortSel as HTMLSelectElement).value as SortKey; rerenderList(); });

  page.append(el('div', { class: 'toolbar' }, chips, el('span', { class: 'spacer' }), sortSel));

  const host = el('div', { id: 'extListHost' });
  page.append(host);
  // render after insertion so rerenderList can find it
  setTimeout(() => rerenderList(), 0);
  return page;
}

function listBody(): HTMLElement {
  const exts = (state.scan?.extensions || []).slice();

  const filtered = exts.filter((e) => {
    if (currentFilter !== 'all') {
      const cats = e.findings.map((f) => f.category);
      switch (currentFilter) {
        case 'needs-review':
          if (e.overallStatus === 'Healthy') return false;
          break;
        case 'high': case 'medium': case 'low':
          if (!e.findings.some((f) => f.severity === currentFilter)) return false;
          break;
        default:
          if (!cats.includes(currentFilter)) return false;
      }
    }
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      const hay = [
        e.name, e.id, e.description, e.version,
        ...e.permissions.map((p) => p.name),
        ...e.hostPermissions.map((h) => h.pattern),
        ...e.network.map((n) => n.host),
        ...e.findings.map((f) => `${f.title} ${f.summary}`),
        ...e.files.slice(0, 200).map((f) => f.path),
        ...e.installations.map((i) => i.profileName),
      ].join(' ').toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });

  // Sorting is a user-controlled presentation function (§84) — no "best/worst" ranking.
  const sevRank: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, informational: 1 };
  filtered.sort((a, b) => {
    switch (currentSort) {
      case 'name': return a.name.localeCompare(b.name);
      case 'findings': return b.findings.length - a.findings.length;
      case 'size': return b.package.totalSize - a.package.totalSize;
      case 'permissions': return b.permissions.length - a.permissions.length;
      case 'hosts': return b.hostPermissions.length - a.hostPermissions.length;
      case 'version': return a.version.localeCompare(b.version);
      case 'severity': {
        const maxSev = (e: ExtensionReport) => Math.max(0, ...e.findings.map((f) => sevRank[f.severity] || 0));
        const d = maxSev(b) - maxSev(a);
        return d !== 0 ? d : b.findings.length - a.findings.length;
      }
      default: return 0;
    }
  });

  const wrap = el('div', { class: 'grid' });
  if (!filtered.length) {
    wrap.append(el('div', { class: 'empty' }, 'No extensions match the current filters.'));
    return wrap;
  }
  for (const e of filtered) wrap.append(extCard(e));
  return wrap;
}

/** Extension card (§120): concise indicators, click opens the audit. */
function extCard(e: ExtensionReport): HTMLElement {
  const byCat = (cat: string) => e.findings.filter((f) => f.category === cat).length;
  const card = el('div', {
    class: 'card ext-card',
    role: 'link', tabindex: '0',
    'aria-label': `Open audit for ${e.name}`,
  });
  card.append(extIcon(e));
  const main = el('div', { class: 'ext-card-main' });
  const title = el('div', { class: 'ext-card-title' },
    el('b', {}, e.name),
    el('span', { class: 'ver' }, `v${e.version}`),
    statusChip(e.overallStatus));
  main.append(title);
  const enabled = e.installations[0]?.enabled;
  main.append(el('div', { class: 'ext-meta' },
    `${e.installations.map((i) => i.profileName).join(', ') || 'Not available'} · ` +
    `${enabled === undefined ? 'state Not available' : enabled ? 'Enabled' : 'Disabled'} · ` +
    `${e.package.totalFiles} files · ${humanSize(e.package.totalSize)}`));
  main.append(el('div', { class: 'ext-meta mono' }, e.id));
  main.append(el('div', { class: 'ext-counts' },
    spanB(`Security: ${byCat('security')}`),
    spanB(`Privacy: ${byCat('privacy')}`),
    spanB(`Performance: ${byCat('performance')}`),
    spanB(`Compatibility: ${byCat('compatibility')}`),
    spanB(`Permissions: ${e.permissions.length}`),
    spanB(`Hosts: ${e.hostPermissions.length}`),
    spanB(`Coverage: ${e.analysis.coverage.toFixed(0)}%`),
  ));
  main.append(el('div', { style: 'margin-top:6px' }, tagList(e.tags)));
  card.append(main);

  const open = () => { location.hash = `#/ext/${encodeURIComponent(e.id)}`; };
  card.addEventListener('click', open);
  card.addEventListener('keydown', (ev) => { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); open(); } });
  return card;
}

function spanB(text: string): HTMLElement {
  const s = el('span', {}, '');
  const [label, value] = text.split(': ');
  s.append(document.createTextNode(`${label}: `), el('b', {}, value));
  return s;
}
