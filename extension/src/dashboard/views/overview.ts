/** Overview dashboard (§7–8) + first-run onboarding (§169) + limitation disclosure (§117). */
import { el, state, startScan, lmOptions } from '../app';
import { nativeHost } from '../../core/native';
import { fmtDate, humanSize, type ExtensionReport } from '../../core/types';
import { statusChip, kv } from './components';

export function renderOverview(): HTMLElement {
  const page = el('div', {});

  if (!state.scan) {
    page.append(onboarding());
    return page;
  }

  const s = state.scan.scan;
  const exts = state.scan.extensions || [];

  // ---- KPI row (§7) ----
  const byCat = s.stats.findingsByCategory || {};
  const kpis = el('div', { class: 'grid cols-4' },
    kpi(String(s.extensionsFound), 'Extensions found'),
    kpi(String(s.profilesScanned), 'Profiles scanned'),
    kpi(String(exts.filter((e) => e.overallStatus !== 'Healthy').length), 'Extensions requiring attention'),
    kpi(`${s.stats.averageCoverage.toFixed(0)}%`, 'Average analysis coverage'),
    kpi(String(byCat['security'] || 0), 'Security findings'),
    kpi(String(byCat['privacy'] || 0), 'Privacy findings'),
    kpi(String(byCat['performance'] || 0), 'Performance findings'),
    kpi(String(byCat['compatibility'] || 0), 'Compatibility findings'),
  );

  const scanCard = el('div', { class: 'card' },
    el('h2', {}, 'Scan summary'),
    el('div', { class: 'sub' }, `Completed ${fmtDate(s.finishedAt)} · mode: ${s.mode} · status: ${s.status}`),
    kpis,
    el('div', { class: 'row section-gap' },
      el('button', { class: 'btn primary', id: 'ovRescan' }, 'Scan Again'),
      el('button', { class: 'btn', id: 'ovQuick' }, 'Quick Scan'),
      el('button', { class: 'btn', id: 'ovStandard' }, 'Standard Scan'),
      el('button', { class: 'btn', id: 'ovDeep' }, 'Deep Scan (AI)'),
      statusChip(overallOf(exts)),
    ),
  );
  scanCard.querySelector('#ovRescan')!.addEventListener('click', () => startScan());
  scanCard.querySelector('#ovQuick')!.addEventListener('click', () => startScan('quick'));
  scanCard.querySelector('#ovStandard')!.addEventListener('click', () => startScan('standard'));
  scanCard.querySelector('#ovDeep')!.addEventListener('click', () => startScan('deep'));
  page.append(scanCard);

  // ---- Health summary (§47) ----
  const cats = ['Security', 'Privacy', 'Performance', 'Compatibility', 'Code Quality', 'Permissions', 'Network', 'Package', 'Maintenance'];
  const agg: Record<string, { bad: number; review: number }> = {};
  for (const c of cats) agg[c] = { bad: 0, review: 0 };
  for (const e of exts) {
    for (const c of cats) {
      const st = e.health?.[c];
      if (st === 'Significant Concerns') agg[c].bad++;
      else if (st === 'Needs Review') agg[c].review++;
    }
  }
  const healthCard = el('div', { class: 'card section-gap' },
    el('h2', {}, 'Health summary'),
    el('div', { class: 'sub' }, 'Category statuses, never a single score. Click Extensions to see the evidence behind every status.'),
    ...cats.map((c) => el('div', { class: 'row', style: 'margin-bottom:4px' },
      el('span', { style: 'width:120px' }, c),
      statusChip(agg[c].bad > 0 ? 'Significant Concerns' : agg[c].review > 0 ? 'Needs Review' : 'Healthy'),
      el('span', { class: 'muted', style: 'font-size:11.5px' },
        agg[c].bad > 0 ? `${agg[c].bad} extension(s) with significant concerns`
          : agg[c].review > 0 ? `${agg[c].review} needing review`
          : 'no category-level concerns recorded'))));
  page.append(healthCard);

  // ---- profiles (§10) ----
  if (state.scan.profiles?.length) {
    page.append(el('div', { class: 'card section-gap' },
      el('h2', {}, 'Chrome profiles discovered'),
      el('div', { class: 'sub' }, 'All profiles are scanned — not just Default.'),
      ...state.scan.profiles.map((p) => el('div', { class: 'row', style: 'margin-bottom:4px' },
        el('span', { style: 'width:120px' }, p.name),
        el('span', { class: 'muted mono' }, p.id),
        el('span', { class: 'muted' }, `${p.extensionCount} extensions`)))));
  }

  // ---- changes since last scan (§148-149) ----
  const newOnes = state.scan.newSinceLast || [];
  const removed = state.scan.removedSinceLast || [];
  if (newOnes.length || removed.length) {
    const card = el('div', { class: 'card section-gap' },
      el('h2', {}, 'Changes since previous scan'));
    for (const id of newOnes) {
      const e = exts.find((x) => x.id === id);
      card.append(el('div', {}, `New extension: ${e ? e.name : id} (${id})`));
    }
    for (const id of removed) {
      card.append(el('div', {}, `Removed since previous scan: ${id} — history kept for comparison`));
    }
    page.append(card);
  }

  // ---- what this tool can / cannot know (§117) ----
  page.append(el('div', { class: 'notice section-gap' },
    el('b', {}, 'What this audit can and cannot determine. '),
    document.createTextNode(
      'It can observe installed metadata, permissions, host patterns, package contents, source patterns, referenced domains and static indicators. ' +
      'It cannot prove malicious intent, measure real per-extension CPU/RAM in every situation, discover zero-days, or see server-side behavior. ' +
      'Findings are evidence for your own review — not verdicts.')));

  return page;
}

function kpi(value: string, label: string): HTMLElement {
  return el('div', { class: 'card kpi' }, el('b', {}, value), el('span', {}, label));
}

function overallOf(exts: ExtensionReport[]): string {
  if (exts.some((e) => e.overallStatus === 'Significant Concerns')) return 'Significant Concerns';
  if (exts.some((e) => e.overallStatus === 'Needs Review')) return 'Needs Review';
  if (exts.some((e) => e.overallStatus === 'Analysis Incomplete')) return 'Analysis Incomplete';
  return 'Healthy';
}

/** First-run experience (§169). */
function onboarding(): HTMLElement {
  const page = el('div', {});
  page.append(el('h1', { style: 'font-size:20px;margin-top:0' }, 'Welcome to Local Chrome Extension Auditor'));
  page.append(el('p', { class: 'muted' },
    'This tool inspects every Chrome extension installed in your Chrome profiles and produces a fully local audit. ' +
    'No account, no cloud, no telemetry. The AI (optional) runs in your own LM Studio.'));

  const steps = el('div', { class: 'onboarding-steps' });
  const mkStep = (n: number, title: string, statusEl: HTMLElement) => {
    const step = el('div', { class: 'onb-step pending' },
      el('div', { class: 'n' }, String(n)),
      el('div', { style: 'flex:1' }, el('b', {}, title), statusEl));
    return step;
  };

  const s1 = el('div', { class: 'muted', style: 'font-size:12px' }, 'checking…');
  const s2 = el('div', { class: 'muted', style: 'font-size:12px' }, 'checking…');
  const s3 = el('div', { class: 'muted', style: 'font-size:12px' }, 'checking…');
  steps.append(mkStep(1, 'Detect Chrome profiles', s1));
  steps.append(mkStep(2, 'Connect to local scanner', s2));
  steps.append(mkStep(3, 'Check LM Studio (optional)', s3));

  const goBtn = el('button', { class: 'btn primary', style: 'margin-top:6px' }, 'Run first scan');
  goBtn.addEventListener('click', () => startScan('standard'));
  steps.append(el('div', { class: 'onb-step' },
    el('div', { class: 'n' }, '4'),
    el('div', { style: 'flex:1' }, el('b', {}, 'Run first scan'), goBtn)));

  page.append(el('div', { class: 'card' }, steps));

  // live checks
  (async () => {
    try {
      const res = await nativeHost.request<any>('discoverProfiles', {});
      const profiles = res?.profiles || [];
      s1.textContent = profiles.length
        ? `Found ${profiles.length} profile(s): ${profiles.map((p: any) => p.name).join(', ')}`
        : 'No Chrome profiles found — is Chrome installed?';
    } catch (e) {
      s1.textContent = 'Failed: native scanner not reachable.';
    }
    try {
      const st = await nativeHost.request<any>('getStatus', {});
      s2.textContent = st?.scannerVersion
        ? `Connected. Scanner ${st.scannerVersion} (rules ${st.ruleSetVersion}).`
        : 'Failed.';
    } catch (e) {
      s2.textContent = 'Failed: run Install.bat from the package and reload the extension.';
    }
    try {
      const st = await nativeHost.request<any>('getLMStudioStatus', lmOptions());
      s3.textContent = st?.reachable
        ? `Reachable — ${st.models?.length || 0} model(s) available.`
        : 'Not reachable — the deterministic audit works without it.';
    } catch (e) {
      s3.textContent = 'Not reachable — the deterministic audit works without it.';
    }
  })();

  return page;
}
