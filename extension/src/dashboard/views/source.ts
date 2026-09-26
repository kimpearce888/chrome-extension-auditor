/** Read-only source viewer (§52, §81): file tree, highlighting, search, line
 * numbers, finding markers, jump-to-finding. Never executes analyzed code. */
import { el, state } from '../app';
import { nativeHost } from '../../core/native';
import { humanSize, type ExtensionReport, type FileInfo } from '../../core/types';

export function sourceViewerSection(ext: ExtensionReport): HTMLElement {
  const wrap = el('div', {});
  const requested = new URLSearchParams((location.hash.split('?')[1] || ''));

  const layout = el('div', { class: 'grid cols-2', style: 'grid-template-columns: 260px 1fr; align-items:start' });

  // ---- file tree ----
  const treeCard = el('div', { class: 'card', style: 'max-height:720px; overflow:auto' },
    el('h2', {}, 'Source files'));
  const tree = el('div', { role: 'tree', 'aria-label': 'Extension files' });
  const sorted = [...ext.files].sort((a, b) => a.path.localeCompare(b.path));
  const byDir = new Map<string, FileInfo[]>();
  for (const f of sorted) {
    const dir = f.path.includes('/') ? f.path.slice(0, f.path.lastIndexOf('/')) : '';
    if (!byDir.has(dir)) byDir.set(dir, []);
    byDir.get(dir)!.push(f);
  }
  for (const [dir, files] of [...byDir.entries()].sort((a, b) => a[0].localeCompare(b[0]))) {
    if (dir) tree.append(el('div', { class: 'muted', style: 'padding:4px 0 2px; font-size:11px' }, dir + '/'));
    for (const f of files) {
      const name = f.path.slice(dir ? dir.length + 1 : 0);
      const item = el('div', {
        role: 'treeitem', tabindex: '0',
        style: 'padding:2px 6px; border-radius:6px; cursor:pointer; display:flex; justify-content:space-between; gap:6px',
        title: `${f.path} · ${humanSize(f.size)}${f.minified ? ' · minified' : ''}`,
      }, el('span', { class: 'mono' }, name), el('span', { class: 'muted', style: 'font-size:10px' }, humanSize(f.size)));
      const open = () => { loadFile(f.path); };
      item.addEventListener('click', open);
      item.addEventListener('keydown', (e) => { if (e.key === 'Enter') open(); });
      tree.append(item);
    }
  }
  treeCard.append(tree);
  layout.append(treeCard);

  // ---- viewer ----
  const viewerCard = el('div', { class: 'card' });
  const viewer = el('div', { class: 'viewer' });
  const toolbar = el('div', { class: 'viewer-toolbar' });
  const pathEl = el('span', { class: 'path' }, 'Select a file to view it read-only.');
  const searchBox = el('input', { type: 'search', placeholder: 'Find in file (Ctrl+F)', 'aria-label': 'Find in file', style: 'width:180px;padding:4px 8px;border-radius:6px;border:1px solid var(--border);background:var(--bg);color:var(--text)' }) as HTMLInputElement;
  toolbar.append(pathEl, searchBox);
  const body = el('div', { class: 'viewer-body' });
  const linenos = el('div', { class: 'viewer-linenos' });
  const code = el('pre', { class: 'viewer-code', tabindex: '0' });
  body.append(linenos, code);
  viewer.append(toolbar, body);
  viewerCard.append(el('h2', {}, 'Read-only source viewer'),
    el('div', { class: 'sub' }, 'Analyzed code is treated as untrusted data: it is displayed, never executed.'), viewer);
  layout.append(viewerCard);
  wrap.append(layout);

  // finding markers for this extension: ruleId -> {file,line}
  const markers = new Map<string, Array<{ file: string; line: number; title: string }>>();
  for (const f of ext.findings) {
    for (const ev of f.evidence || []) {
      if (ev.file && ev.line) {
        if (!markers.has(ev.file)) markers.set(ev.file, []);
        markers.get(ev.file)!.push({ file: ev.file, line: ev.line, title: `${f.severity}: ${f.title}` });
      }
    }
  }

  async function loadFile(path: string): Promise<void> {
    pathEl.textContent = `${path} — loading…`;
    code.textContent = '';
    linenos.textContent = '';
    let content = '';
    let truncated = false;
    try {
      const res = await nativeHost.request<{ content: string; truncated: boolean }>('getSourceFile', {
        extensionId: ext.id, file: path,
      });
      content = res?.content || '';
      truncated = !!res?.truncated;
    } catch (e: any) {
      pathEl.textContent = `${path} — could not load: ${e.message}`;
      return;
    }
    pathEl.textContent = path + (truncated ? ' (truncated at 2 MB)' : '');
    renderCode(path, content);
  }

  function renderCode(path: string, content: string): void {
    const lines = content.split('\n');
    const isJS = /\.(js|mjs|cjs|ts|tsx|json|css|html)$/.test(path);
    const markLines = new Map<number, string>();
    for (const m of markers.get(path) || []) markLines.set(m.line, m.title);
    linenos.innerHTML = '';
    for (let i = 1; i <= lines.length; i++) {
      const ln = el('div', {}, String(i));
      if (markLines.has(i)) {
        ln.style.color = 'var(--warn)';
        ln.style.fontWeight = '700';
        ln.title = markLines.get(i)!;
      }
      linenos.append(ln);
    }
    code.innerHTML = '';
    if (isJS) {
      code.append(highlightJS(content, markLines));
    } else {
      code.append(document.createTextNode(content));
    }
    // jump to first marker (§81)
    const firstMark = Math.min(...[...markLines.keys()].filter((n) => n > 0).concat([1]));
    const lineEl = linenos.children[firstMark - 1] as HTMLElement;
    if (lineEl) {
      const top = lineEl.offsetTop - 100;
      body.scrollTo({ top });
      code.scrollTop = top;
    }
  }

  searchBox.addEventListener('input', () => {
    const q = searchBox.value.toLowerCase();
    if (!q) return;
    const text = code.textContent || '';
    const idx = text.toLowerCase().indexOf(q);
    if (idx < 0) return;
    const before = text.slice(0, idx).split('\n').length;
    const lineEl = linenos.children[before - 1] as HTMLElement;
    if (lineEl) body.scrollTo({ top: lineEl.offsetTop - 100 });
  });

  // auto-load requested file (§81 jump-to-source)
  const want = requested.get('file');
  const initial = want && ext.files.some((f) => f.path === want) ? want
    : (ext.files.find((f) => f.path === 'manifest.json')?.path || sorted[0]?.path);
  if (initial) setTimeout(() => loadFile(initial), 0);

  return wrap;
}

/** Minimal, dependency-free JS highlighter (never executes the code). */
function highlightJS(src: string, marks: Map<number, string>): DocumentFragment {
  const frag = document.createDocumentFragment();
  const lines = src.split('\n');
  const re = /("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|`(?:[^`\\]|\\.)*`)|(\b(?:function|return|if|else|for|while|do|switch|case|break|continue|new|delete|typeof|instanceof|in|of|var|let|const|class|extends|import|export|from|try|catch|finally|throw|async|await|yield|this|super|true|false|null|undefined|void)\b)|(\/\/[^\n]*|\/\*[\s\S]*?\*\/)|(\b\d+(?:\.\d+)?\b)|([A-Za-z_$][\w$]*)(?=\s*\()/g;  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const wrap = el('span', {});
    if (marks.has(i + 1)) wrap.setAttribute('class', 'ln-mark');
    let last = 0;
    let m: RegExpExecArray | null;
    re.lastIndex = 0;
    while ((m = re.exec(line))) {
      if (m.index > last) wrap.append(document.createTextNode(line.slice(last, m.index)));
      const cls = m[1] ? 'st' : m[2] ? 'kw' : m[3] ? 'cm' : m[4] ? 'num' : 'fn';
      wrap.append(el('span', { class: cls }, m[0]));
      last = m.index + m[0].length;
    }
    wrap.append(document.createTextNode(line.slice(last)));
    frag.append(wrap, document.createTextNode('\n'));
  }
  return frag;
}
