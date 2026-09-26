/** Local privacy page (§114): claims that match the implementation. */
import { el } from '../app';

export function renderPrivacy(): HTMLElement {
  const page = el('div', {});
  page.append(el('h1', { style: 'font-size:18px;margin-top:0' }, 'Privacy — what this tool does and does not do'));

  const claims: Array<[boolean, string]> = [
    [true, 'No cloud AI — interpretation (when enabled) runs in your own LM Studio via http://127.0.0.1:1234.'],
    [true, 'No telemetry, no analytics, no crash reporting, no tracking pixels.'],
    [true, 'No user account, no login, no cloud synchronization.'],
    [true, 'No remote database — all scan history lives in a local store on this computer.'],
    [true, 'Extension files are analyzed locally by the native scanner on your own disk.'],
    [true, 'Reports are generated locally; export files go to your local reports folder.'],
    [true, 'Secret-like values detected in scanned extensions are redacted before any AI processing and never displayed.'],
    [true, 'The auditor extension itself requests only the permissions it needs: management (inventory), nativeMessaging (scanner), storage (settings), alarms (optional schedules).'],
    [true, 'The native host executes no programs, no shell, no PowerShell; it only reads and analyzes files.'],
    [true, 'Nothing is ever modified: the auditor is read-only toward other extensions.'],
  ];

  const card = el('div', { class: 'card' },
    el('h2', {}, 'Local-only guarantees'),
    el('div', { class: 'sub' }, 'Verified claims only — see SECURITY.md for how each is enforced.'));
  for (const [ok, text] of claims) {
    card.append(el('div', { class: 'row', style: 'margin-bottom:6px' },
      el('span', { class: `chip ${ok ? 'ok' : 'bad'}` }, ok ? 'verified' : 'unverified'),
      document.createTextNode(' ' + text)));
  }
  page.append(card);

  page.append(el('div', { class: 'notice section-gap' },
    el('b', {}, 'How you can verify this yourself. '),
    document.createTextNode(
      'The Chrome extension has no host permissions, so it cannot read websites. The native scanner is a standalone ' +
      'program you can inspect with --self-audit, and the source is included in the package. Run Diagnose.bat at any time ' +
      'to see exactly which local components are active.')));

  page.append(el('div', { class: 'card section-gap' },
    el('h2', {}, 'Data that stays on this computer'),
    el('ul', { style: 'line-height:1.8' },
      el('li', {}, 'Scan history, findings and snapshots (local store).'),
      el('li', {}, 'File hashes and per-file analysis caches.'),
      el('li', {}, 'Your notes and review statuses (extension storage).'),
      el('li', {}, 'AI summaries, cached locally with the model and prompt version.'),
    ),
    el('p', { class: 'muted' }, 'All of it is deletable from Settings → Local data.')));
  return page;
}
