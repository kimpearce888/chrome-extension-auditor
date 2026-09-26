#!/usr/bin/env node
/**
 * Demo GIF recorder (development only).
 *
 * Drives the demo-harness dashboard (REAL scanner output, synthetic Chrome
 * profile) through a realistic first-run story and captures a deterministic
 * frame timeline with scripted cursor movements:
 *
 *   onboarding → live scan (progress) → overview KPIs → extensions + search
 *   → detail: security findings → read-only source viewer → snapshot diff
 *   → compare matrix → back to overview
 *
 * The browser cursor is NOT captured (headless); a cursor is drawn in
 * post-production by scripts/make-gif.py from the recorded waypoints, so
 * every frame also carries the live :hover state under the moving cursor.
 *
 *   node scripts/demo-gif.mjs            # requires demo server on :4318
 *   python3 scripts/make-gif.py          # then assemble the GIF
 *
 * Output: .demo/gif-frames/*.png + timeline.json (gitignored).
 */
import { chromium } from 'playwright';
import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const OUT = join(root, '.demo', 'gif-frames');
const URL_BASE = process.env.DEMO_URL || 'http://127.0.0.1:4318/';
const W = 1440;
const H = 900;
const FRAME_MS = 80; // logical duration of one motion frame

// ---------- recording primitives ----------
const frames = [];
const clicks = [];
let idx = 0;
let cur = { x: 980, y: 660, pressed: false };
let page;

async function snap(ms) {
  const buf = await page.screenshot({ type: 'png', animations: 'disabled', caret: 'hide' });
  const file = `f${String(idx).padStart(4, '0')}.png`;
  writeFileSync(join(OUT, file), buf);
  frames.push({ file, ms, cx: Math.round(cur.x * 10) / 10, cy: Math.round(cur.y * 10) / 10, pressed: !!cur.pressed });
  idx++;
}

const easeOut = (t) => 1 - Math.pow(1 - t, 3);

async function moveTo(x, y, ms = 420) {
  const fx = cur.x; const fy = cur.y;
  const steps = Math.max(4, Math.round(ms / FRAME_MS));
  for (let i = 1; i <= steps; i++) {
    const t = easeOut(i / steps);
    cur = { x: fx + (x - fx) * t, y: fy + (y - fy) * t, pressed: false };
    await page.mouse.move(cur.x, cur.y); // real hover states
    await snap(FRAME_MS);
  }
  cur = { x, y, pressed: false };
}

async function center(target) {
  const loc = typeof target === 'string' ? page.locator(target).first() : target;
  await loc.scrollIntoViewIfNeeded();
  const b = await loc.boundingBox();
  if (!b) throw new Error(`no bounding box for ${target}`);
  return {
    x: Math.min(W - 14, Math.max(14, b.x + b.width / 2)),
    y: Math.min(H - 14, Math.max(14, b.y + b.height / 2)),
  };
}

async function click(target, moveMs = 420) {
  const c = await center(target);
  await moveTo(c.x, c.y, moveMs);
  await page.mouse.move(c.x, c.y);
  cur.pressed = true;
  await page.mouse.down();
  await snap(70);
  clicks.push({ frame: idx, x: c.x, y: c.y }); // ripple begins on the release frame
  cur.pressed = false;
  await page.mouse.up();
  await snap(FRAME_MS);
}

const hold = (ms) => snap(ms);

async function type(text, perChar = 95) {
  for (const ch of text) {
    await page.keyboard.type(ch);
    await snap(perChar);
  }
}

async function wheel(dy, steps = 1) {
  for (let i = 0; i < steps; i++) {
    await page.mouse.wheel(0, dy);
    await snap(95);
  }
}

async function viewerScroll(dy, steps = 2) {
  for (let i = 0; i < steps; i++) {
    await page.evaluate((d) => {
      const v = document.querySelector('.viewer-body');
      if (v) v.scrollTop += d;
    }, dy);
    await snap(95);
  }
}

// ---------- story ----------
async function main() {
  mkdirSync(OUT, { recursive: true });
  rmSync(OUT, { recursive: true, force: true });
  mkdirSync(OUT, { recursive: true });

  const browser = await chromium.launch();
  const ctx = await browser.newContext({
    viewport: { width: W, height: H },
    deviceScaleFactor: 1,
    colorScheme: 'light', // matches the screenshots in docs/screenshots/
  });
  page = await ctx.newPage();
  page.setDefaultTimeout(20000);

  await page.goto(URL_BASE, { waitUntil: 'load' });
  await page.waitForSelector('.onboarding-steps');

  // wait for the live onboarding checks to settle (profiles / scanner / LM)
  for (let i = 0; i < 40; i++) {
    const steps = await page.evaluate(() =>
      [...document.querySelectorAll('.onb-step')].map((s) => s.textContent || ''));
    const ok = steps.length >= 4
      && /Found|No Chrome/.test(steps[0] || '')
      && /Connected|Failed/.test(steps[1] || '')
      && /reachable/.test(steps[2] || '');
    if (ok) break;
    await page.waitForTimeout(250);
  }
  await page.waitForTimeout(400);

  // --- A. onboarding: live checks, then run the first scan ---
  await hold(1000);
  await click('button:has-text("Run first scan")');

  let last = '';
  for (let i = 0; i < 320; i++) {
    const sig = await page.evaluate(() => {
      const t = document.querySelector('#scanProgressText');
      const b = document.querySelector('#scanBarFill');
      return JSON.stringify([t && t.textContent, b && b.style.width]);
    });
    if (sig !== last) { last = sig; await snap(150); }
    if (sig.includes('Scan completed')) break;
    if (sig.includes('Scan failed')) throw new Error('scan failed during recording');
    await page.waitForTimeout(80);
  }
  await page.waitForTimeout(400); // route() re-renders the overview
  await snap(650);                // "Scan completed" banner over fresh KPIs
  await page.evaluate(() => { const b = document.querySelector('#scanBanner'); if (b) b.hidden = true; });
  await snap(320);

  // --- B. overview: KPIs, then scroll to health summary ---
  await hold(1050);
  await wheel(300, 2);
  await wheel(260, 2);
  await hold(850);

  // --- C. extensions: grid, live search, back to full list ---
  await click('nav.tabs a[data-view="extensions"]');
  await page.waitForSelector('.ext-card');
  await hold(750);
  await click('#globalSearch');
  await hold(180);
  await type('permission');
  await hold(520);
  await page.keyboard.press('Control+a');
  await snap(80);
  await page.keyboard.press('Backspace');
  await snap(80);
  await hold(520);

  // --- D. detail page of Permission Heavy Fixture ---
  await click('.ext-card:has-text("Permission Heavy")');
  await page.waitForSelector('.dtabs');
  await hold(780);

  // security findings
  await click('.dtab:has-text("Security")');
  await page.waitForSelector('text=Security findings');
  await hold(950);
  await wheel(270, 3);
  await hold(620);

  // read-only source viewer
  await click('.dtab:has-text("Source")');
  await page.waitForSelector('[role="treeitem"]');
  await hold(420);
  await click(page.locator('[role="treeitem"]').filter({ hasText: /\.js/ }).first());
  await page.waitForSelector('.viewer-linenos > div');
  await hold(620);
  await viewerScroll(260, 2);
  await hold(460);

  // snapshot diff (flagship)
  await click('.dtab:has-text("History")');
  await page.waitForSelector('button:has-text("Compare with previous scan")');
  await hold(420);
  await click('button:has-text("Compare with previous scan")');
  await page.waitForSelector('.tag');
  await hold(1150);
  await wheel(230, 1);
  await hold(480);

  // --- E. compare matrix + outro ---
  await click('nav.tabs a[data-view="compare"]');
  await page.waitForSelector('text=Compare extensions');
  await hold(700);
  await click('label:has-text("Permission Heavy Fixture") input');
  await hold(320);
  await click('label:has-text("Network Heavy Fixture") input');
  await hold(950);
  await wheel(230, 1);
  await hold(420);

  await click('nav.tabs a[data-view="overview"]');
  await page.waitForSelector('.kpi');
  await hold(1150);

  writeFileSync(join(OUT, 'timeline.json'), JSON.stringify({
    viewport: { w: W, h: H },
    frames,
    clicks,
  }, null, 1));

  console.log(`[gif] captured ${frames.length} frames, ${clicks.length} clicks`);
  const total = frames.reduce((a, f) => a + f.ms, 0);
  console.log(`[gif] logical duration: ${(total / 1000).toFixed(1)}s`);
  await browser.close();
}

main().catch((e) => { console.error('[gif] fatal:', e); process.exit(1); });
