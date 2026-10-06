'use strict';

/*
 * Finish plan item 9: one install step. "Turn on guardrail" writes the starter rules
 * (the day job's three, as principles with backstops): never merge a PR, never push
 * master or production-*, push only with approval. Idempotent: a second run adds
 * nothing and writes nothing; over an existing file it adds only what is missing,
 * blocks before asks (first match wins), and loses no rule.
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
const { STARTER_RULES } = loadTs('src/main/guardrailStarter.ts');
const { HiveManager } = loadTs('src/main/hive.ts');
const { HookServer } = loadTs('src/main/hooks.ts');
const { RulesManager } = loadTs('src/main/rules.ts');

async function floor(t, initial) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'md-gr-install-'));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  const hive = new HiveManager(() => home);
  const dir = path.join(home, 'hive', 'policy');
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, 'guardrail.json');
  if (initial !== undefined) fs.writeFileSync(file, typeof initial === 'string' ? initial : JSON.stringify(initial));
  const server = new HookServer(hive, () => null, () => ({}), undefined, undefined);
  const editor = new GuardrailEditor({ policyDir: () => dir, engine: server, principles: new RulesManager(() => home, () => {}),
    agentIds: () => [], afterSave: async () => {}, log: () => {} });
  const decide = (command) => server.handle({ agent_id: 'jim-1', session_id: 's', hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command }, cwd: home })?.hookSpecificOutput?.permissionDecision ?? 'none';
  const baks = () => fs.readdirSync(dir).filter((f) => f.startsWith('guardrail.json.bak-'));
  return { file, editor, decide, baks };
}

test('on an empty hive: the three starter rules, blocks first, enforced at once', async (t) => {
  const f = await floor(t);
  const out = await f.editor.install('gary');
  assert.equal(out.ok, true, JSON.stringify(out));
  assert.deepEqual(out.added, ['bitbucket-merge', 'protected-branch-push', 'remote-push']);
  const g = JSON.parse(fs.readFileSync(f.file, 'utf8'));
  assert.deepEqual(g.rules.map((r) => [r.id, r.backstop.does]), [['bitbucket-merge', 'block'], ['protected-branch-push', 'block'], ['remote-push', 'ask']]);
  assert.deepEqual(g.rules.find((r) => r.id === 'remote-push').backstop.approve_on_card, ['git-push']);
  assert.equal(f.decide('git push origin master'), 'deny');
  assert.equal(f.decide('bb pr merge 12'), 'deny');
  assert.equal(f.decide('git push origin feat/x'), 'ask');
  assert.equal(f.decide('ls'), 'none');
});

test('twice: the second run adds nothing and writes nothing', async (t) => {
  const f = await floor(t);
  await f.editor.install('gary');
  const before = fs.readFileSync(f.file, 'utf8');
  const nBaks = f.baks().length;
  const out = await f.editor.install('gary');
  assert.deepEqual([out.ok, out.added], [true, []]);
  assert.equal(fs.readFileSync(f.file, 'utf8'), before);
  assert.equal(f.baks().length, nBaks);
});

test('over existing rules: keeps every one, adds what is missing, blocks before asks', async (t) => {
  const mine = [
    { id: 'my-ask', principle: 'Ask before deleting branches.', agents: 'all', backstop: { on: true, does: 'ask', match: { tool: 'Bash', command_matches: '^git\\s+branch\\s+-D' } } },
    { id: 'remote-push', principle: 'My own push rule.', agents: 'all', backstop: { on: false, does: 'log', match: { tool: 'Bash', command_matches: '^git\\s+push' } } },
    { id: 'kind', principle: 'Be kind.', agents: 'all' },
  ];
  const f = await floor(t, { version: 1, rev: 4, rules: mine });
  const out = await f.editor.install('gary');
  assert.deepEqual(out.added, ['bitbucket-merge', 'protected-branch-push'], 'an id already there is left as the operator set it');
  const g = JSON.parse(fs.readFileSync(f.file, 'utf8'));
  assert.deepEqual(g.rules.map((r) => r.id), ['bitbucket-merge', 'protected-branch-push', 'my-ask', 'remote-push', 'kind']);
  assert.equal(g.rules.find((r) => r.id === 'remote-push').principle, 'My own push rule.');
  assert.equal(g.rev, 5);
  assert.equal(f.baks().length, 1);
});

test('a broken file is not overwritten', async (t) => {
  const f = await floor(t, '{ torn');
  const out = await f.editor.install('gary');
  assert.equal(out.ok, false);
  assert.match(out.errors.join(' '), /broken|fix/i);
  assert.equal(fs.readFileSync(f.file, 'utf8'), '{ torn');
});

test('the starter rules are the day job\'s, and the screen offers the install', () => {
  assert.equal(STARTER_RULES.length, 3);
  const panel = fs.readFileSync(path.join(__dirname, '..', 'src/renderer/src/components/RulesPanel.tsx'), 'utf8');
  assert.match(panel, /window\.cth\.guardrailInstall\(\)/);
  assert.match(panel, /Turn on guardrail/);
  assert.match(fs.readFileSync(path.join(__dirname, '..', 'src/preload/index.ts'), 'utf8'), /guardrailInstall:[\s\S]{0,120}ipcRenderer\.invoke\('guardrail:install'\)/);
  assert.match(fs.readFileSync(path.join(__dirname, '..', 'src/main/index.ts'), 'utf8'), /ipcMain\.handle\('guardrail:install', \(\) => guardrailEditor\.install\('user'\)\)/);
});

// Dwight on items 6-11. M2b: the cap must not stop the starter rules (it is an
// attention budget for principles, not a reason to leave the floor unguarded). L11: an
// existing Log rule that matches pushes must not shadow the new ask.
test('M2b: install goes through even when the principles are at the cap, and says so', async (t) => {
  const ten = Array.from({ length: 10 }, (_, i) => ({ id: `r${i}`, principle: `Rule ${i}.`, agents: 'all' }));
  const f = await floor(t, { version: 1, rev: 1, rules: ten });
  const out = await f.editor.install('gary');
  assert.equal(out.ok, true, JSON.stringify(out));
  assert.equal(out.added.length, 3);
  assert.match(out.warning, /over the cap/);
  assert.equal(f.decide('git push origin master'), 'deny');
});

test('L11: a new ask goes before an existing rule that is not a block, so a Log rule cannot shadow it', async (t) => {
  const f = await floor(t, { version: 1, rev: 1, rules: [
    { id: 'my-push', principle: 'Watch pushes.', agents: 'all', backstop: { on: true, does: 'log', match: { tool: 'Bash', command_matches: '^git\\s+push' } } },
  ] });
  await f.editor.install('gary');
  const g = JSON.parse(fs.readFileSync(f.file, 'utf8'));
  assert.deepEqual(g.rules.map((r) => r.id), ['bitbucket-merge', 'protected-branch-push', 'remote-push', 'my-push']);
  assert.equal(f.decide('git push origin feat/x'), 'ask');
});
