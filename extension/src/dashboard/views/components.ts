/** Shared UI components: finding cards with expandable evidence (§51), chips, cards. */
import { el, getAnnotation, toggleIgnoredFinding } from '../app';
import type { ExtensionReport, Finding, Profile } from '../../core/types';

export function statusChip(status: string): HTMLElement {
  const cls = status === 'Healthy' ? 'ok' : status === 'Needs Review' ? 'warn'
    : status === 'Significant Concerns' ? 'bad' : 'info';
  return el('span', { class: `chip ${cls}` }, status);
}

export function sevChip(sev: string): HTMLElement {
  return el('span', { class: `chip sev-${sev}` }, sev);
}

export function confChip(conf: string): HTMLElement {
  return el('span', { class: 'chip info' }, `confidence: ${conf}`);
}

export function tagList(tags: string[]): HTMLElement {
  return el('span', {}, ...tags.map((t) => el('span', { class: 'tag' }, t)));
}

export function evidenceList(f: Finding): HTMLElement {
  const ul = el('ul', { class: 'evidence-list' });
  for (const ev of f.evidence || []) {
    const parts: string[] = [];
    if (ev.field) parts.push(ev.field);
    if (ev.file) parts.push(`${ev.file}${ev.line ? ':' + ev.line : ''}`);
    if (ev.pattern) parts.push(`pattern: ${ev.pattern}`);
    if (ev.excerpt) parts.push(`excerpt: ${ev.excerpt}`);
    if (ev.note) parts.push(ev.note);
    ul.append(el('li', {}, parts.join(' · ') || '—'));
  }
  return ul;
}

/** Render one finding card, §51: evidence expandable, actions per §126. */
export function findingCard(f: Finding, ext?: ExtensionReport, opts: { onRerender?: () => void } = {}): HTMLElement {
  const card = el('div', { class: 'finding' });
  const head = el('div', { class: 'finding-head' },
    sevChip(f.severity),
    el('b', {}, f.title),
    confChip(f.confidence),
    el('span', { class: 'tag' }, f.category),
  );
  card.append(head);
  card.append(el('p', { class: 'summary' }, f.summary));
  const details = el('details', {},
    el('summary', {}, 'Evidence'));
  details.append(evidenceList(f));
  card.append(details);
  card.append(el('div', { class: 'why' }, f.whyItMatters));
  card.append(el('div', { class: 'rec' }, f.recommendation));

  if (ext) {
    const actions = el('div', { class: 'finding-actions' });
    const ann = getAnnotation(ext.id);
    const ignored = !!ann.ignoredFindings[f.ruleId];
    const btnIgnore = el('button', { class: 'btn small', title: 'Hide this finding locally; evidence is kept' },
      ignored ? 'Restore this finding' : 'Ignore this finding');
    btnIgnore.addEventListener('click', async () => {
      await toggleIgnoredFinding(ext.id, f.ruleId);
      opts.onRerender?.();
    });
    actions.append(btnIgnore);
    card.append(actions);
  }
  return card;
}

export function findingsSection(findings: Finding[], ext?: ExtensionReport): HTMLElement {
  const wrap = el('div', {});
  if (!findings.length) {
    wrap.append(el('div', { class: 'empty' }, 'No findings in this view.'));
    return wrap;
  }
  const rerender = () => {
    wrap.innerHTML = '';
    buildFiltered(wrap, findings, ext);
  };
  buildFiltered(wrap, findings, ext);
  (wrap as any)._rerender = rerender;
  return wrap;
}

function buildFiltered(wrap: HTMLElement, findings: Finding[], ext?: ExtensionReport): void {
  const ann = ext ? getAnnotation(ext.id) : null;
  const visible = ann ? findings.filter((f) => !ann.ignoredFindings[f.ruleId]) : findings;
  const ignoredCount = findings.length - visible.length;
  if (ignoredCount > 0) {
    wrap.append(el('div', { class: 'muted', style: 'font-size:11.5px' },
      `${ignoredCount} finding(s) ignored locally — restore them from the finding cards.`));
  }
  for (const f of visible) {
    wrap.append(findingCard(f, ext, { onRerender: () => (wrap as any)._rerender?.() }));
  }
}

export function kv(pairs: Array<[string, Node | string]>): HTMLElement {
  const dl = el('dl', { class: 'kv' });
  for (const [k, v] of pairs) {
    dl.append(el('dt', {}, k));
    const dd = el('dd', {});
    dd.append(typeof v === 'string' ? document.createTextNode(v) : v);
    dl.append(dd);
  }
  return dl;
}

export function profileChips(profiles: Profile[]): HTMLElement {
  return el('div', { class: 'row' }, ...profiles.map((p) =>
    el('span', { class: 'chip info', title: p.dir }, `${p.name} (${p.extensionCount})`)));
}

export function extIcon(ext: ExtensionReport): HTMLElement {
  const img = el('img', { class: 'ext-icon', alt: '' }) as HTMLImageElement;
  img.src = `chrome-extension://${ext.id}/icon.png`;
  img.onerror = () => {
    img.replaceWith(el('div', { class: 'ext-icon', style: 'display:flex;align-items:center;justify-content:center;font-weight:700' },
      (ext.name || '?').slice(0, 1).toUpperCase()));
  };
  return img;
}
