'use strict';

/*
 * Finish plan item 2: the Rules screen edits guardrail.json through main. A save is
 * checked by the engine's own validator, refused when the file changed on disk since
 * the screen read it or when the principles are over the cap, written atomically with
 * a backup, and takes effect at once: the engine reloads and the agents' instructions
 * are re-rendered. Agents never reach this path (main only; the file is self-protected).
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const loadTs = require('./load-ts.cjs');

const electron = require.resolve('electron');
require.cache[electron] = { id: electron, filename: electron, loaded: true,
  exports: { Notification: class { show() {} static isSupported() { return false; } } } };

const { GuardrailEditor } = loadTs('src/main/guardrailEditor.ts');
const { GUARDRAIL_FILE } = loadTs('src/main/guardrail.ts');
const { HiveManager } = loadTs('src/main/hive.ts');
const { HookServer } = loadTs('src/main/hooks.ts');
const { RulesManager } = loadTs('src/main/rules.ts');

const PUSH = { id: 'push', principle: 'Do not push without my approval.', agents: 'all',
  backstop: { on: true, does: 'ask', approve_on_card: ['git-push'], match: { tool: 'Bash', command_matches: '^git\\s+push\\b' } } };

async function floor(t, initial) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'md-gr-editor-'));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  const hive = new HiveManager(() => home);
  fs.mkdirSync(path.join(home, 'hive', 'policy'), { recursive: true });
  const file = path.join(home, 'hive', 'policy', GUARDRAIL_FILE);
  if (initial) fs.writeFileSync(file, JSON.stringify(initial));
  await hive.ensureAgent({ id: 'jim-1', name: 'Jim', provider: 'claude', cwd: home });
  const server = new HookServer(hive, () => null, () => ({}), undefined, undefined);
  const rules = new RulesManager(() => home, () => {});
  const rendered = [];
  const editor = new GuardrailEditor({
    policyDir: () => path.join(home, 'hive', 'policy'),
    engine: server,
    principles: rules,
    agentIds: () => ['jim-1'],
    afterSave: async () => { rendered.push('jim-1'); },
    log: (r) => hive.appendLog(r),
  });
  const hook = (command) => server.handle({ agent_id: 'jim-1', session_id: 's', hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command }, cwd: home });
  const decision = async (command) => (await hook(command))?.hookSpecificOutput?.permissionDecision ?? 'none';
  const log = () => fs.readFileSync(path.join(home, 'hive', 'log.jsonl'), 'utf8');
  const baks = () => fs.readdirSync(path.dirname(file)).filter((f) => f.startsWith(`${GUARDRAIL_FILE}.bak-`));
  return { home, file, editor, rendered, decision, log, baks };
}

test('read: no file says so; a file comes back with its stamp, status and caps', async (t) => {
  const empty = await floor(t, null);
  const r0 = empty.editor.read();
  assert.equal(r0.exists, false);
  assert.equal(r0.file, null);
  const f = await floor(t, { version: 1, rev: 2, rules: [PUSH] });
  const r = f.editor.read();
  assert.equal(r.exists, true);
  assert.equal(r.file.rev, 2);
  assert.equal(typeof r.stamp, 'number');
  assert.deepEqual([r.status.configured, r.status.rulesLoaded, r.status.error], [true, 1, null]);
  assert.equal(r.caps.global.count, 1);
});

test('save: written atomically with a backup, rev bumped, engine reloaded, agents re-rendered', async (t) => {
  const f = await floor(t, { version: 1, rev: 2, rules: [PUSH] });
  assert.equal(await f.decision('rm -rf /x'), 'none', 'precondition: nothing blocks rm');
  const { file, stamp } = f.editor.read();
  const next = { ...file, rules: [...file.rules, { id: 'no-rm', principle: 'Never rm -rf.', agents: 'all',
    backstop: { on: true, does: 'block', match: { tool: 'Bash', command_matches: '^rm\\s+-rf\\b' } } }] };
  const out = await f.editor.save(next, stamp, 'gary');
  assert.equal(out.ok, true, JSON.stringify(out));
  assert.equal(out.rev, 3, 'rev is main\'s, not the screen\'s');
  assert.equal(JSON.parse(fs.readFileSync(f.file, 'utf8')).rules.length, 2);
  assert.equal(f.baks().length, 1);
  assert.equal(out.status.rulesLoaded, 2);
  assert.equal(await f.decision('rm -rf /x'), 'deny', 'in effect at once, no restart');
  assert.deepEqual(f.rendered, ['jim-1']);
  assert.match(f.log(), /"kind":"guardrail-saved"[^\n]*"rev":3[^\n]*"actor":"gary"/);
});

test('save: an invalid rule is refused with every problem named, and nothing is written', async (t) => {
  const f = await floor(t, { version: 1, rev: 2, rules: [PUSH] });
  const before = fs.readFileSync(f.file, 'utf8');
  const { file, stamp } = f.editor.read();
  const out = await f.editor.save({ ...file, rules: [
    { ...PUSH, principle: '' },
    { id: 'bad-re', principle: 'x', agents: 'all', backstop: { on: true, does: 'block', match: { tool: 'Bash', command_matches: '(' } } },
    { id: 'off-bad', principle: 'y', agents: 'all', backstop: { on: false, does: 'block', match: { tool: 'Bash', command_matches: '[' } } },
  ] }, stamp, 'gary');
  assert.ok(out.errors.some((e) => /off-bad/.test(e)), 'a backstop that is off is checked too, so turning it on cannot break the file');
  assert.equal(out.ok, false);
  assert.ok(out.errors.some((e) => /push: principle/.test(e)), out.errors.join(' | '));
  assert.ok(out.errors.some((e) => /bad-re/.test(e)), 'the engine\'s own check (the regex) runs too');
  assert.equal(fs.readFileSync(f.file, 'utf8'), before);
  assert.equal(f.baks().length, 0);
});

test('save: refused when the file changed on disk since it was read', async (t) => {
  const f = await floor(t, { version: 1, rev: 2, rules: [PUSH] });
  const { file, stamp } = f.editor.read();
  const later = new Date(Date.now() + 5000);
  fs.writeFileSync(f.file, JSON.stringify({ ...file, rev: 9 }));
  fs.utimesSync(f.file, later, later);
  const out = await f.editor.save({ ...file, rules: [] }, stamp, 'gary');
  assert.deepEqual([out.ok, out.reason], [false, 'changed-on-disk']);
  assert.equal(JSON.parse(fs.readFileSync(f.file, 'utf8')).rev, 9, 'the other change survives');
});

test('save: principles over the cap are refused', async (t) => {
  const f = await floor(t, { version: 1, rev: 1, rules: [PUSH] });
  const { file, stamp } = f.editor.read();
  const many = Array.from({ length: 13 }, (_, i) => ({ id: `r${i}`, principle: `Rule ${i}.`, agents: 'all' }));
  const out = await f.editor.save({ ...file, rules: many }, stamp, 'gary');
  assert.equal(out.ok, false);
  assert.ok(out.errors.some((e) => /cap/.test(e)), out.errors.join(' | '));
});

test('save: the first file is created when none exists', async (t) => {
  const f = await floor(t, null);
  const out = await f.editor.save({ version: 1, rev: 0, rules: [PUSH] }, null, 'gary');
  assert.equal(out.ok, true, JSON.stringify(out));
  assert.equal(out.rev, 1);
  assert.equal(await f.decision('git push origin main'), 'ask');
});

test('test: would this backstop stop a command, for which agent', async (t) => {
  const f = await floor(t, null);
  const b = PUSH.backstop;
  assert.deepEqual(f.editor.test({ ...PUSH, backstop: b }, 'git push origin main'), { fires: true, does: 'ask', on: 'command_matches' });
  assert.equal(f.editor.test({ ...PUSH, backstop: b }, 'git status').fires, false);
  assert.equal(f.editor.test({ ...PUSH, agents: ['pam'] }, 'git push', 'jim-1').fires, false, 'not this agent\'s backstop');
  assert.equal(f.editor.test({ ...PUSH, agents: ['pam'] }, 'git push', 'pam').fires, true);
  assert.match(f.editor.test({ ...PUSH, backstop: { ...b, match: { tool: 'Bash', command_matches: '(' } } }, 'git push').error, /./);
  assert.match(f.editor.test({ id: 'p', principle: 'x', agents: 'all' }, 'git push').error, /no backstop/);
});
