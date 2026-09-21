'use strict';

/*
 * md-154 — the wiring between the Rules panel and the main process.
 *
 * The panel shipped with an eternal "Loading rules…": it reached for the preload
 * bridge through a hand-written `window as unknown as { api?: … }` cast, but the
 * bridge is registered as `window.cth`. The cast invented a global that does not
 * exist, so every call optional-chained away to `undefined`, nothing threw, and the
 * spinner had no state to leave. rules-render.test.cjs passed throughout — it tests
 * RulesManager, and the break was two layers above it.
 *
 * So these cases walk the three layers the panel's load actually crosses —
 * renderer → preload channel → ipcMain handler — and then run the exact call the
 * panel makes against a hive laid out like a COPY (a separate harnessHome), which is
 * how the bug was found.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const loadTs = require('./load-ts.cjs');

const { RulesManager } = loadTs('src/main/rules.ts');

const read = (rel) => fs.readFileSync(path.join(__dirname, '..', rel), 'utf8');

/** Source with comments stripped. The checks below look for patterns that a fix's own
 *  comment is likely to quote while explaining why it is wrong — so match on code, or
 *  the test fails on the prose that documents it. Crude on purpose: a `//` inside a
 *  string literal would be mangled, and none of the files read here has one on a line
 *  these assertions care about. */
const code = (rel) => read(rel)
  .replace(/\/\*[\s\S]*?\*\//g, '')
  .replace(/^\s*\/\/.*$/gm, '');

const PANEL = 'src/renderer/src/components/RulesPanel.tsx';
const PRELOAD = 'src/preload/index.ts';
const MAIN = 'src/main/index.ts';

// ─── layer 1: the panel talks to the global the preload actually registers ────────

test('the preload bridge is exposed as `cth`, and the panel uses that name', () => {
  const exposed = [...read(PRELOAD).matchAll(/exposeInMainWorld\('([^']+)'/g)].map((m) => m[1]);
  assert.deepEqual(exposed, ['cth'], 'preload should expose exactly one bridge, named cth');

  const panel = code(PANEL);
  const globals = new Set([...panel.matchAll(/window\.([A-Za-z_$][\w$]*)/g)].map((m) => m[1]));
  for (const g of globals) {
    assert.ok(exposed.includes(g), `panel reads window.${g}, which no preload bridge registers`);
  }
});

test('the panel does not cast `window` to a shape of its own invention', () => {
  const panel = code(PANEL);
  // A cast like `window as unknown as { api?: … }` cannot disagree with reality: it
  // is an assertion, not a check, which is precisely why tsc stayed silent.
  assert.ok(!/window as unknown as/.test(panel),
    'reach the bridge through the declared `window.cth` global so tsc verifies the name');
});

// ─── layer 2: every method the panel calls exists on the bridge ───────────────────

test('every rules method the panel calls is defined in the preload', () => {
  const panel = read(PANEL);
  const preload = read(PRELOAD);
  const called = [...panel.matchAll(/window\.cth\.(rules[A-Za-z]*)\s*\(/g)].map((m) => m[1]);
  assert.ok(called.length >= 5, `expected the panel to call several rules methods, saw ${called.length}`);
  for (const m of new Set(called)) {
    assert.match(preload, new RegExp(`\\n\\s*${m}:`), `preload has no ${m} on the bridge`);
  }
});

// ─── layer 3: every bridge channel has a handler in main ──────────────────────────

test('every rules channel in the preload has an ipcMain handler', () => {
  const preload = read(PRELOAD);
  const main = read(MAIN);
  const channels = [...preload.matchAll(/rules[A-Za-z]*:[^\n]*ipcRenderer\.invoke\('([^']+)'/g)].map((m) => m[1]);
  assert.ok(channels.length >= 5, `expected several rules:* channels, saw ${channels.length}`);
  for (const ch of channels) {
    assert.ok(main.includes(`ipcMain.handle('${ch}'`), `no ipcMain.handle for '${ch}'`);
  }
});

test('the rules handlers resolve their paths from the LIVE harnessHome getter', () => {
  const main = read(MAIN);
  // A snapshotted path would read the hive that was configured at boot, so a profile
  // pointing at a copy would silently keep answering from the original.
  assert.match(main, /new RulesManager\(\s*\n\s*\(\) => readConfig\(\)\.harnessHome/,
    'RulesManager must take a getter, not a resolved path');
});

// ─── the load path itself, against a COPY-shaped hive ────────────────────────────

/** A harnessHome somewhere else entirely — the shape mode B's copy has. */
function copyHome(opts = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'md-154-copy-'));
  for (const id of opts.agents ?? ['jim', 'pam', 'god']) {
    fs.mkdirSync(path.join(root, 'hive', 'agents', id), { recursive: true });
    fs.writeFileSync(path.join(root, 'hive', 'agents', id, 'memory.md'),
      '# Memory\n\n## 📌 Durable facts (pinned — never condensed)\n\nA fact.\n');
  }
  if (opts.store !== null) {
    fs.mkdirSync(path.join(root, 'hive', 'policy'), { recursive: true });
    fs.writeFileSync(path.join(root, 'hive', 'policy', 'rules.json'), JSON.stringify(opts.store ?? {
      rev: 4,
      rules: [
        { id: 'own-folder', text: 'Write only to your own folder.', scope: { kind: 'global' }, status: 'active' },
        { id: 'jim-only', text: 'A jim rule.', scope: { kind: 'agents', ids: ['jim'] }, status: 'active' }
      ]
    }));
  }
  return root;
}

test('the panel load returns a usable overview from a hive that is NOT the default one', () => {
  const home = copyHome();
  const mgr = new RulesManager(() => home, () => {});
  const ov = mgr.overview(['jim', 'pam', 'god']);

  assert.ok(ov, 'overview must not be null — the panel treats an absent reply as "still loading"');
  assert.equal(ov.active, true);
  assert.equal(ov.rev, 4);
  assert.equal(ov.rules.length, 2);
  assert.deepEqual(ov.targets['own-folder'].sort(), ['god', 'jim', 'pam']);
  assert.deepEqual(ov.targets['jim-only'], ['jim']);
  assert.deepEqual(Object.keys(ov.deliveredRevs).sort(), ['god', 'jim', 'pam']);
  assert.ok(ov.caps && ov.caps.global && ov.caps.perAgent, 'caps are part of the one load call');
});

test('a hive with NO rules store still answers — active:false, never null', () => {
  // The panel has a real branch for this ("Rules are not set up for this hive"). If the
  // load returned null instead, that branch would be unreachable and the spinner would
  // be permanent — the same symptom, from the main side.
  const home = copyHome({ store: null });
  const mgr = new RulesManager(() => home, () => {});
  const ov = mgr.overview(['jim', 'god']);

  assert.ok(ov, 'a dormant feature must still return an overview object');
  assert.equal(ov.active, false);
  assert.equal(ov.rev, 0);
  assert.deepEqual(ov.rules, []);
});

test('a malformed store answers too, rather than throwing into the panel', () => {
  const home = copyHome({ store: '{ not json' });
  fs.writeFileSync(path.join(home, 'hive', 'policy', 'rules.json'), '{ not json');
  const mgr = new RulesManager(() => home, () => {});
  const ov = mgr.overview(['jim']);

  assert.ok(ov);
  assert.deepEqual(ov.rules, []);
});

test('the per-agent read-only view follows the same copy home', () => {
  const home = copyHome();
  const mgr = new RulesManager(() => home, () => {});
  const d = mgr.inEffect('jim');

  assert.ok(d);
  assert.equal(d.rev, 4);
  assert.deepEqual(d.rules.map((r) => r.id).sort(), ['jim-only', 'own-folder']);
});

test('switching the getter switches hives, with no restart and no cached path', () => {
  const a = copyHome();
  const b = copyHome({ store: { rev: 9, rules: [{ id: 'b-only', text: 'B.', scope: { kind: 'global' }, status: 'active' }] } });
  let home = a;
  const mgr = new RulesManager(() => home, () => {});

  assert.equal(mgr.overview(['jim']).rev, 4);
  home = b;
  assert.equal(mgr.overview(['jim']).rev, 9, 'the store path must be re-read per call');
});
