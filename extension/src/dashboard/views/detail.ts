/** Extension detail page (§74): 13 tabs + Ask the Auditor panel (§72). */
import { el, state, lmOptions, setReviewStatus, setNotes, getAnnotation } from '../app';
import { nativeHost } from '../../core/native';
import {
  fmtDate, humanSize, type AIAnalysis, type ExtensionReport, type ReviewStatus,
} from '../../core/types';
import { evidenceList, extIcon, findingCard, kv, sevChip, statusChip, tagList } from './components';
import { sourceViewerSection } from './source';

const TABS = [
  'overview', 'security', 'privacy', 'performance', 'permissions', 'host-access',
  'source', 'network', 'files', 'dependencies', 'compatibility', 'history', 'ai',
] as const;
type Tab = (typeof TABS)[number];

export function renderDetail(extId: string, tabParam?: string): HTMLElement {
  const page = el('div', {});
  const ext = (state.scan?.extensions || []).find((e) => e.id === decodeURIComponent(extId));
  if (!ext) {
    page.append(el('div', { class: 'empty' },
      el('div', { class: 'big' }, 'Extension not found'),
      el('div', { class: 'hint' }, 'It may have been removed. Run a new scan.')));
    return page;
  }
  const tab = (TABS as readonly string[]).includes(tabParam || '') ? (tabParam as Tab) : 'overview';

  // ---- header (§75) ----
  const header = el('div', { class: 'card detail-header' });
  header.append(extIcon(ext));
  const title = el('div', { class: 'detail-title' });
  title.append(el('h1', {}, `${ext.name} `, el('span', { class: 'muted', style: 'font-size:13px' }, `v${ext.version}`)));
  title.append(el('div', { class: 'sub' },
    `${ext.id} · manifest v${ext.manifestVersion === -1 ? 'Not available' : ext.manifestVersion} · ${ext.type}`));
  title.append(el('div', { class: 'row', style: 'margin-top:6px' }, statusChip(ext.overallStatus),
    el('span', { class: 'chip info' }, `coverage ${ext.analysis.coverage.toFixed(0)}%`),
    el('span', { class: 'chip info' }, `${ext.findings.length} findings`)));
  title.append(el('div', { style: 'margin-top:6px' }, tagList(ext.tags)));
  // review status (§127)
  const ann = getAnnotation(ext.id);
  const reviewSel = el('select', { 'aria-label': 'Review status' },
    ...([['unreviewed', 'Not reviewed'], ['reviewed', 'Reviewed'], ['needs-investigation', 'Needs investigation'], ['accepted-risk', 'Accepted risk'], ['ignored', 'Ignored']] as Array<[ReviewStatus, string]>)
      .map(([v, l]) => {
        const o = el('option', { value: v }, l) as HTMLOptionElement;
        if (ann.reviewStatus === v) o.selected = true;
        return o;
      })) as HTMLSelectElement;
  reviewSel.addEventListener('change', () => setReviewStatus(ext.id, reviewSel.value as ReviewStatus));
  title.append(el('div', { class: 'row', style: 'margin-top:8px' }, el('span', { class: 'muted' }, 'Your review:'), reviewSel));
  header.append(title);
  page.append(header);

  // ---- tabs ----
  const tabs = el('div', { class: 'dtabs', role: 'tablist' });
  for (const t of TABS) {
    const a = el('a', { class: `dtab${t === tab ? ' active' : ''}`, href: `#/ext/${encodeURIComponent(ext.id)}/${t}`, role: 'tab' },
      tabLabel(t));
    tabs.append(a);
  }
  page.append(tabs);

  const body = el('div', {});
  page.append(body);
  buildTab(body, ext, tab);
  return page;
}

function tabLabel(t: Tab): string {
  const labels: Record<Tab, string> = {
    'overview': 'Overview', 'security': 'Security', 'privacy': 'Privacy', 'performance': 'Performance',
    'permissions': 'Permissions', 'host-access': 'Host Access', 'source': 'Source', 'network': 'Network',
    'files': 'Files', 'dependencies': 'Dependencies', 'compatibility': 'Compatibility', 'history': 'History',
    'ai': 'AI Explanation',
  };
  return labels[t];
}

function buildTab(body: HTMLElement, ext: ExtensionReport, tab: Tab): void {
  body.innerHTML = '';
  body.append(tabContent(ext, tab));
}

function tabContent(ext: ExtensionReport, tab: Tab): HTMLElement {
  const f = (cat: string) => ext.findings.filter((x) => x.category === cat);

  switch (tab) {
    case 'overview':
      return overviewTab(ext);
    case 'security':
      return findingsTab(ext, f('security'), 'Security findings');
    case 'privacy':
      return findingsTab(ext, f('privacy'), 'Privacy findings');
    case 'performance':
      return performanceTab(ext);
    case 'permissions':
      return permissionsTab(ext);
    case 'host-access':
      return hostAccessTab(ext);
    case 'source':
      return sourceViewerSection(ext);
    case 'network':
      return networkTab(ext);
    case 'files':
      return filesTab(ext);
    case 'dependencies':
      return dependenciesTab(ext);
    case 'compatibility':
      return findingsTab(ext, f('compatibility'), 'Compatibility findings');
    case 'history':
      return historyTab(ext);
    case 'ai':
      return aiTab(ext);
  }
}

// ---- Overview tab (§75) ----
function overviewTab(ext: ExtensionReport): HTMLElement {
  const wrap = el('div', { class: 'grid cols-2' });
  const info = el('div', { class: 'card' }, el('h2', {}, 'Overview'));
  const inst = ext.installations[0];
  info.append(kv([
    ['Name', ext.name],
    ['Version', ext.version],
    ['ID', ext.id],
    ['Profiles', ext.installations.map((i) => `${i.profileName}${i.enabled ? '' : ' (disabled)'}`).join(', ') || 'Not available'],
    ['Publisher / author', 'Not available' /* §9: only when Chrome exposes it */],
    ['Homepage', ext.homepageUrl !== 'Not available' ? link(ext.homepageUrl) : 'Not available'],
    ['Install type', ext.installations.map((i) => i.installType).join(', ') || 'Not available'],
    ['Enabled', inst ? (inst.enabled ? 'Enabled' : `Disabled — ${inst.disabledReason}`) : 'Not available'],
    ['Installed by policy', inst?.installedByPolicy ? 'Yes' : 'No / Not available'],
    ['Package size', `${humanSize(ext.package.totalSize)} (${ext.package.totalFiles} files)`],
    ['Last scan', fmtDate(state.scan?.scan.finishedAt || '')],
  ]));
  wrap.append(info);

  const analysis = el('div', { class: 'card' }, el('h2', {}, 'Analysis status'));
  analysis.append(kv([
    ['Status', ext.analysis.status],
    ['Coverage', `${ext.analysis.coverage.toFixed(0)}%`],
    ['Notes', ext.analysis.coverageNotes.join(' · ') || 'complete'],
    ['AI interpretation', ext.ai ? (ext.ai.status === 'ok' ? `Available (model ${ext.ai.model || 'unknown'})` : ext.ai.status || 'unknown') : 'Not available (deep scan required)'],
  ]));
  analysis.append(el('h3', {}, 'Health by category'));
  for (const [cat, st] of Object.entries(ext.health || {})) {
    analysis.append(el('div', { class: 'row', style: 'margin-bottom:4px' },
      el('span', { style: 'width:120px' }, cat), statusChip(st)));
  }
  wrap.append(analysis);

  // user notes (§128)
  const notesCard = el('div', { class: 'card section-gap', style: 'grid-column: 1 / -1' },
    el('h2', {}, 'Your notes (local only,)'));
  const ann = getAnnotation(ext.id);
  const ta = el('textarea', { style: 'width:100%;min-height:60px', placeholder: 'e.g. I use this extension for work. Reviewed after version update.' }) as HTMLTextAreaElement;
  ta.value = ann.notes;
  const saveBtn = el('button', { class: 'btn small', style: 'margin-top:6px' }, 'Save note');
  saveBtn.addEventListener('click', async () => {
    await setNotes(ext.id, ta.value);
    saveBtn.textContent = 'Saved';
    setTimeout(() => (saveBtn.textContent = 'Save note'), 1200);
  });
  notesCard.append(ta, saveBtn);
  wrap.append(notesCard);
  return wrap;
}

// ---- findings tabs ----
function findingsTab(ext: ExtensionReport, findings: any[], title: string): HTMLElement {
  const wrap = el('div', { class: 'card' }, el('h2', {}, title));
  if (!findings.length) {
    wrap.append(el('div', { class: 'empty' }, 'No findings in this category.'));
    return wrap;
  }
  for (const x of findings) wrap.append(findingCard(x, ext));
  return wrap;
}

// ---- Performance tab (§77) ----
function performanceTab(ext: ExtensionReport): HTMLElement {
  const wrap = el('div', { class: 'grid cols-2' });
  const perf = el('div', { class: 'card' }, el('h2', {}, 'Performance profile'));
  const timers = ext.background.timers || [];
  const smallTimers = timers.filter((t) => t.delayMs >= 0 && t.delayMs < 1000).length;
  perf.append(kv([
    ['Package size', humanSize(ext.package.totalSize)],
    ['JS size', humanSize(ext.package.sizeByType?.javascript || 0)],
    ['CSS size', humanSize(ext.package.sizeByType?.css || 0)],
    ['Largest JS', `${ext.package.largestJs} (${humanSize(ext.package.largestJsSize)})`],
    ['Content scripts', String(ext.contentScripts.length)],
    ['Background', ext.background.type],
    ['Timer call sites', `${timers.length} (${smallTimers} under 1s)`],
    ['Background polling', ext.background.hasPolling ? 'Potential polling pattern detected' : 'Not observed'],
    ['Direct runtime measurement', 'Direct runtime resource measurement unavailable in this Chrome configuration. Static resource-risk analysis is being used instead.'],
  ]));
  wrap.append(perf);
  wrap.append(findingsTab(ext, ext.findings.filter((f) => f.category === 'performance'), 'Performance findings'));
  return wrap;
}

// ---- Permissions tab (§78) ----
function permissionsTab(ext: ExtensionReport): HTMLElement {
  const wrap = el('div', { class: 'card' }, el('h2', {}, 'Permissions'));
  wrap.append(el('div', { class: 'sub' },
    'Risk context comes from capability, not from a scary-sounding name. Observed usage reflects static detection only.'));
  const table = el('table', { class: 'data' });
  table.append(el('thead', {}, el('tr', {},
    el('th', {}, 'Permission'), el('th', {}, 'Risk context'), el('th', {}, 'Observed usage'), el('th', {}, 'Evidence'))));
  const tbody = el('tbody');
  for (const p of ext.permissions) {
    tbody.append(el('tr', {},
      el('td', {}, el('code', {}, p.name), el('span', { class: 'muted' }, ` (${p.source})`)),
      el('td', {}, `${p.riskContext}${p.source === 'optional' ? ' — optional, can be granted later' : ''}`),
      el('td', {}, p.observedUse),
      el('td', {}, p.evidence && p.evidence.length ? p.evidence.slice(0, 3).join(', ') : '—'),
    ));
  }
  table.append(tbody);
  wrap.append(table);
  wrap.append(el('div', { class: 'section-gap' },
    ...ext.findings.filter((f) => f.category === 'permissions').map((f) => findingCard(f, ext))));
  return wrap;
}

// ---- Host access tab (§17) ----
function hostAccessTab(ext: ExtensionReport): HTMLElement {
  const wrap = el('div', { class: 'card' }, el('h2', {}, 'Host access'));
  wrap.append(el('div', { class: 'sub' },
    'Patterns describe what the extension could interact with. Breadth is a scope statement, not a verdict.'));
  const table = el('table', { class: 'data' });
  table.append(el('thead', {}, el('tr', {},
    el('th', {}, 'Pattern'), el('th', {}, 'Scheme'), el('th', {}, 'Host'), el('th', {}, 'Breadth'))));
  const tb = el('tbody');
  for (const h of ext.hostPermissions) {
    tb.append(el('tr', {},
      el('td', {}, el('code', {}, h.pattern), h.sensitive ? el('span', { class: 'chip warn', style: 'margin-left:6px' }, 'sensitive domain') : ''),
      el('td', {}, h.scheme),
      el('td', {}, h.host),
      el('td', {}, h.breadth + (h.notes ? ` — ${h.notes}` : '')),
    ));
  }
  table.append(tb);
  wrap.append(table);
  return wrap;
}

// ---- Network tab (§80) ----
function networkTab(ext: ExtensionReport): HTMLElement {
  const wrap = el('div', { class: 'card' }, el('h2', {}, 'Network destinations'));
  wrap.append(el('div', { class: 'sub' },
    'Statically referenced destinations. Third-party is a classification, not an accusation.'));
  if (!ext.network.length) {
    wrap.append(el('div', { class: 'empty' }, 'No network destinations referenced in static analysis.'));
    return wrap;
  }
  const table = el('table', { class: 'data' });
  table.append(el('thead', {}, el('tr', {},
    el('th', {}, 'Domain'), el('th', {}, 'Source'), el('th', {}, 'Line'), el('th', {}, 'Protocol'), el('th', {}, 'Type'))));
  const tb = el('tbody');
  for (const n of ext.network) {
    tb.append(el('tr', {},
      el('td', {}, el('code', {}, n.host)),
      el('td', {}, n.sourceFile || ''),
      el('td', {}, String(n.line || '—')),
      el('td', {}, n.protocol),
      el('td', {}, `${n.method || ''} · ${n.classification}`),
    ));
  }
  table.append(tb);
  wrap.append(table);
  wrap.append(el('div', { class: 'section-gap' },
    ...ext.findings.filter((f) => f.category === 'network').map((f) => findingCard(f, ext))));
  return wrap;
}

// ---- Files tab (§79) ----
function filesTab(ext: ExtensionReport): HTMLElement {
  const wrap = el('div', { class: 'card' }, el('h2', {}, 'Files'));
  wrap.append(kv([
    ['Total files', String(ext.package.totalFiles)],
    ['Total size', humanSize(ext.package.totalSize)],
    ['Largest file', `${ext.package.largestFile} (${humanSize(ext.package.largestFileSize)})`],
    ['Source maps', String(ext.package.sourceMaps)],
    ['Files skipped by limits', String(ext.package.filesSkipped)],
  ]));
  const table = el('table', { class: 'data' });
  table.append(el('thead', {}, el('tr', {},
    el('th', {}, 'Path'), el('th', {}, 'Type'), el('th', {}, 'Size'), el('th', {}, 'SHA-256 (first 12)'), el('th', {}, 'Flags'))));
  const tb = el('tbody');
  for (const file of [...ext.files].sort((a, b) => b.size - a.size).slice(0, 300)) {
    const tr = el('tr', { style: 'cursor:pointer', tabindex: '0' });
    tr.append(
      el('td', {}, el('code', {}, file.path)),
      el('td', {}, file.type),
      el('td', {}, humanSize(file.size)),
      el('td', {}, el('span', { class: 'mono' }, file.sha256.slice(0, 12))),
      el('td', {}, [file.minified ? 'minified' : '', file.hasSourceMap ? 'source map' : ''].filter(Boolean).join(', ') || '—'),
    );
    tr.addEventListener('click', () => { location.hash = `#/ext/${encodeURIComponent(ext.id)}/source?file=${encodeURIComponent(file.path)}`; });
    tb.append(tr);
  }
  table.append(tb);
  wrap.append(table);
  if (ext.files.length > 300) {
    wrap.append(el('div', { class: 'muted', style: 'font-size:11.5px' }, `Showing 300 of ${ext.files.length} files (largest first).`));
  }
  return wrap;
}

// ---- Dependencies tab (§33) ----
function dependenciesTab(ext: ExtensionReport): HTMLElement {
  const wrap = el('div', { class: 'card' }, el('h2', {}, 'Detected libraries'));
  wrap.append(el('div', { class: 'sub' }, 'Identified offline via a local signature database; confidence levels apply.'));
  if (!ext.dependencies.length) {
    wrap.append(el('div', { class: 'empty' }, 'No known libraries detected.'));
    return wrap;
  }
  const table = el('table', { class: 'data' });
  table.append(el('thead', {}, el('tr', {},
    el('th', {}, 'Library'), el('th', {}, 'Version'), el('th', {}, 'Confidence'), el('th', {}, 'Files'))));
  const tb = el('tbody');
  for (const d of ext.dependencies) {
    tb.append(el('tr', {},
      el('td', {}, d.name + (d.license ? ` (${d.license})` : '')),
      el('td', {}, d.version),
      el('td', {}, d.confidence),
      el('td', {}, d.files.join(', ')),
    ));
  }
  table.append(tb);
  wrap.append(table);
  return wrap;
}

// ---- History tab (§63, §129-130) ----
function historyTab(ext: ExtensionReport): HTMLElement {
  const wrap = el('div', { class: 'card' }, el('h2', {}, 'History & changes'));
  const btn = el('button', { class: 'btn' }, 'Compare with previous scan');
  const out = el('div', { class: 'section-gap' });
  btn.addEventListener('click', async () => {
    out.textContent = 'Comparing…';
    try {
      const diff = await nativeHost.request<any>('compareScans', { extensionId: ext.id });
      out.innerHTML = '';
      renderDiffInto(out, diff, ext);
    } catch (e: any) {
      out.textContent = `Could not compare: ${e.message}`;
    }
  });
  wrap.append(btn, out);
  wrap.append(el('div', { class: 'sub' }, 'Snapshot comparison requires at least two scans (standard or deep mode).'));
  return wrap;
}

const DIFF_KIND_LABELS: Record<string, string> = {
  versionChanged: 'Version changed',
  permissionAdded: 'Permission added',
  permissionRemoved: 'Permission removed',
  hostAdded: 'Host pattern added',
  hostRemoved: 'Host pattern removed',
  apiAdded: 'New API usage',
  domainAdded: 'New network destination',
  domainRemoved: 'Network destination removed',
  fileAdded: 'Files added',
  fileChanged: 'Files changed',
  packageGrew: 'Package grew',
  packageShrank: 'Package shrank',
  newContentScript: 'New content script',
  newBackgroundScript: 'New background script',
  findingAppeared: 'New finding',
  findingResolved: 'Finding resolved',
};

function renderDiffInto(out: HTMLElement, diff: any, ext?: ExtensionReport): void {
  const exts = diff?.extensions || [];
  const mine = ext ? exts.find((x: any) => x.extensionId === ext.id) : null;
  const list = mine ? [mine] : exts;
  if (!list.length) {
    out.append(el('div', { class: 'empty' }, 'No stored previous scan to compare against yet.'));
    return;
  }
  for (const item of list) {
    if (item.change === 'new') {
      out.append(el('div', { class: 'notice ok' }, 'This extension is new since the previous scan.'));
      continue;
    }
    if (item.change === 'removed') {
      out.append(el('div', { class: 'notice' }, 'This extension was present in the previous scan but is gone now.'));
      continue;
    }
    const changes: any[] = item.changes || [];
    if (!changes.length) {
      out.append(el('div', { class: 'notice ok' }, 'No changes since the previous scan.'));
      continue;
    }
    for (const c of changes) {
      out.append(el('div', { class: 'row', style: 'margin-bottom:4px' },
        el('span', { class: 'tag' }, DIFF_KIND_LABELS[c.kind] || c.kind),
        el('span', {}, c.detail),
        c.old && c.new ? el('span', { class: 'muted mono' }, `${c.old} → ${c.new}`) : '',
      ));
    }
  }
}

// ---- AI tab (§72, §150–152) ----
function aiTab(ext: ExtensionReport): HTMLElement {
  const wrap = el('div', { class: 'card' }, el('h2', {}, 'AI Explanation & Ask the Auditor'));
  wrap.append(el('div', { class: 'sub' },
    'Answers come only from the collected local evidence. The AI cannot invent permissions, domains or code.'));

  if (ext.ai && ext.ai.status === 'ok') {
    wrap.append(renderAI(ext.ai));
  } else if (ext.ai) {
    wrap.append(el('div', { class: 'notice' },
      `AI interpretation unavailable (${ext.ai.status}). Static audit remains fully available.`));
  } else {
    wrap.append(el('div', { class: 'notice' },
      'No AI interpretation yet. Run a Deep Scan, or ask a question below if LM Studio is running.'));
  }

  // Ask panel
  const log = el('div', { class: 'ask-log section-gap' });
  const suggestions = el('div', { class: 'suggest-q' });
  for (const q of [
    'Why does this extension need its most powerful permission?',
    'Why does it have access to all websites?',
    'What looks expensive here?',
    'What files are hardest to understand?',
    'What should I investigate manually?',
  ]) {
    const b = el('button', { class: 'btn small' }, q);
    b.addEventListener('click', () => ask(q));
    suggestions.append(b);
  }
  const input = el('input', { type: 'text', placeholder: 'Ask about this extension…', 'aria-label': 'Ask the auditor a question', style: 'flex:1' }) as HTMLInputElement;
  const send = el('button', { class: 'btn primary' }, 'Ask');
  send.addEventListener('click', () => ask(input.value));
  input.addEventListener('keydown', (e) => { if (e.key === 'Enter') ask(input.value); });

  async function ask(q: string): Promise<void> {
    if (!q.trim()) return;
    log.append(el('div', { class: 'ask-msg user' }, q));
    input.value = '';
    const thinking = el('div', { class: 'ask-msg ai muted' }, 'Thinking (local model)…');
    log.append(thinking);
    try {
      const ai = await nativeHost.request<AIAnalysis>('askAuditor', { extensionId: ext.id, question: q, ...lmOptions() });
      thinking.remove();
      log.append(renderAI(ai, true));
    } catch (e: any) {
      thinking.remove();
      log.append(el('div', { class: 'ask-msg ai' }, `Could not answer: ${e.message}`));
    }
  }

  wrap.append(log, suggestions, el('div', { class: 'ask-input' }, input, send));
  return wrap;
}

function renderAI(ai: AIAnalysis, isAnswer = false): HTMLElement {
  const box = el('div', { class: 'ask-msg ai' });
  if (isAnswer && ai.plainEnglishExplanation) {
    box.append(el('div', {}, ai.plainEnglishExplanation));
  } else if (ai.summary) {
    box.append(el('div', {}, ai.summary));
  }
  const sections: Array<[string, string[] | undefined]> = [
    ['Key concerns', ai.keyConcerns],
    ['Positive findings', ai.positiveFindings],
    ['Uncertainties', ai.uncertainties],
    ['Questions you might consider', ai.questionsForUser],
  ];
  for (const [label, arr] of sections) {
    if (arr && arr.length) {
      const ul = el('ul', { style: 'margin:6px 0; padding-left:18px' });
      for (const item of arr) ul.append(el('li', {}, item));
      box.append(el('div', { style: 'margin-top:6px' }, el('b', {}, label)), ul);
    }
  }
  if (!isAnswer && ai.plainEnglishExplanation) {
    box.append(el('div', { style: 'margin-top:6px' }, el('b', {}, 'Plain English')), el('div', {}, ai.plainEnglishExplanation));
  }
  box.append(el('div', { class: 'ai-meta' },
    `model: ${ai.model || 'unknown'} · prompt v${ai.promptVersion || '?'} · generated ${fmtDate(ai.generatedAt || '')}`));
  return box;
}

function link(url: string): HTMLElement {
  const a = el('a', { href: '#', title: url }, url);
  a.addEventListener('click', (e) => { e.preventDefault(); chrome.tabs.create({ url }); });
  return a;
}
