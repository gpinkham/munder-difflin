'use strict';

/*
 * Finish plan item 2: the Rules screen. Its pure parts (status line, backstop summary,
 * draft <-> rule) and its wiring: renderer -> preload -> main, and nothing else.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const loadTs = require('./load-ts.cjs');

const { describeBackstop, statusLine, fromDraft, toDraft, emptyDraft } = loadTs('src/renderer/src/components/rulesView.ts');
const read = (rel) => fs.readFileSync(path.join(__dirname, '..', rel), 'utf8');

const PUSH = { id: 'push', principle: 'Do not push without my approval.', agents: 'all',
  backstop: { on: true, does: 'ask', approve_on_card: ['git-push'], match: { tool: 'Bash', command_matches: '^git\\s+push\\b' }, on_error: 'deny' } };

test('the status line: active with a count, a red reason when nothing is enforced, or not set up', () => {
  const st = (o) => ({ configured: true, file: '/h/guardrail.json', rulesLoaded: 3, ruleIds: [], error: null, loadedAt: null, ...o });
  assert.deepEqual(statusLine({ exists: true, file: {}, stamp: 1, error: null, status: st({}), caps: null }), { text: 'Guardrail active: 3 rules enforced', bad: false });
  assert.equal(statusLine({ exists: true, file: null, stamp: 1, error: 'x: bad', status: st({}), caps: null }).bad, true);
  const failed = statusLine({ exists: true, file: {}, stamp: 1, error: null, status: st({ error: 'boom', rulesLoaded: 0 }), caps: null });
  assert.deepEqual([failed.bad, /nothing is enforced: boom/.test(failed.text)], [true, true]);
  assert.match(statusLine({ exists: true, file: {}, stamp: 1, error: null, status: st({ rulesLoaded: 0 }), caps: null }).text, /no backstop is on: nothing is enforced/);
  assert.match(statusLine({ exists: false, file: null, stamp: null, error: null, status: null, caps: null }).text, /not set up/);
});

test('a backstop reads as one line; a rule without one says it is not enforced', () => {
  assert.equal(describeBackstop(PUSH), 'Backstop: Ask me · approve on a card · matches command ^git\\s+push\\b');
  assert.equal(describeBackstop({ ...PUSH, backstop: { ...PUSH.backstop, on: false, does: 'block', approve_on_card: undefined } }),
    'Backstop: Block · matches command ^git\\s+push\\b · OFF');
  assert.equal(describeBackstop({ id: 'p', principle: 'x', agents: 'all' }), 'Principle only, not enforced');
});

test('editing round-trips, keeps what the form does not show, and drops a removed backstop', () => {
  assert.deepEqual(fromDraft(toDraft(PUSH), PUSH), PUSH, 'unchanged draft = same rule (on_error kept)');
  const d = { ...toDraft(PUSH), commandMatches: '', pathGlob: '**/secrets/**' };
  const r = fromDraft(d, PUSH);
  assert.deepEqual(r.backstop.match, { tool: 'Bash', path_glob: '**/secrets/**' }, 'a cleared pattern is gone, not kept from before');
  assert.equal(fromDraft({ ...toDraft(PUSH), hasBackstop: false }, PUSH).backstop, undefined);
  assert.equal(fromDraft({ ...toDraft(PUSH), does: 'block' }, PUSH).backstop.approve_on_card, undefined, 'approve on a card is for Ask me only');
  const fresh = fromDraft({ ...emptyDraft(), principle: 'Keep commits small.', allAgents: false, picked: ['pam'] });
  assert.deepEqual(fresh, { id: 'keep-commits-small', principle: 'Keep commits small.', agents: ['pam'] });
});

test('wiring: the screen uses guardrail:read/save/test through the bridge, and the old authoring channels are gone', () => {
  const panel = read('src/renderer/src/components/RulesPanel.tsx');
  const preload = read('src/preload/index.ts');
  const main = read('src/main/index.ts');
  for (const [m, ch] of [['guardrailRead', 'guardrail:read'], ['guardrailSave', 'guardrail:save'], ['guardrailTest', 'guardrail:test']]) {
    assert.match(panel, new RegExp(`window\\.cth\\.${m}\\(`), `panel calls ${m}`);
    assert.match(preload, new RegExp(`${m}:[\\s\\S]{0,160}ipcRenderer\\.invoke\\('${ch}'`), `preload maps ${m}`);
    assert.ok(main.includes(`ipcMain.handle('${ch}'`), `main handles ${ch}`);
  }
  for (const gone of ['rules:upsert', 'rules:retire', 'rules:capPreview', 'policy:rules']) {
    assert.ok(!main.includes(`'${gone}'`) && !preload.includes(`'${gone}'`), `${gone} is gone`);
  }
  assert.match(main, /new GuardrailEditor\(\{\s*\n\s*policyDir: \(\) => \{ const h = readConfig\(\)\.harnessHome/, 'the live harnessHome, never a path fixed at boot');
  assert.match(main, /afterSave: async \(\) => \{ await rules\.reconcile\(\); \}/, 'a save re-renders the agents');
});

// Finish plan item 10: the same status line at the top of Settings -> General, with a
// way into Rules, so "is the guardrail on?" never needs the Rules screen to answer.
test('Settings shows the guardrail status line on General, from the same statusLine', () => {
  const panel = read('src/renderer/src/components/RulesPanel.tsx');
  assert.match(panel, /export function GuardrailStatusLine\(/);
  const comp = panel.slice(panel.indexOf('export function GuardrailStatusLine('));
  assert.match(comp, /window\.cth\.guardrailRead\(\)/);
  assert.match(comp, /statusLine\(/);
  const settings = read('src/renderer/src/components/SettingsModal.tsx');
  const general = settings.slice(settings.indexOf("activeSection === 'General' && ("), settings.indexOf("activeSection === 'Prerequisites'"));
  assert.match(general, /<GuardrailStatusLine onOpen=\{\(\) => setActiveSection\('Rules'\)\} \/>/);
});
