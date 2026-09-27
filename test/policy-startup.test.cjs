'use strict';
/**
 * md-216: the guardrail engine rejected every rule on both floors, and the only
 * evidence was one log row written on the first tool call. These tests pin the
 * startup behaviour that replaces it: the policy loads when the hook server starts,
 * "rules loaded: N" is a log row and a status object, and a configured policy that
 * loaded nothing reaches god as a message.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const loadTs = require('./load-ts.cjs');

const electron = require.resolve('electron');
require.cache[electron] = {
  id: electron, filename: electron, loaded: true,
  exports: { Notification: class { show() {} static isSupported() { return false; } } },
};

const { HiveManager } = loadTs('src/main/hive.ts');
const { HookServer } = loadTs('src/main/hooks.ts');

const HOOK_SCHEMA = {
  version: 1,
  rules: [{ id: 'cross-agent-write', mode: 'DRY_RUN', decision: 'deny', on_error: 'open', match: { kind: 'cross_agent_write' }, reason: 'owned' }],
};
const PACK = () => JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'examples/policy/engine.example.json'), 'utf8'));

async function floor(t, files) {
  const home = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'md216-start-')));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  const hive = new HiveManager(() => home);
  await hive.ensureAgent({ id: 'god', name: 'God', provider: 'claude', cwd: home, isGod: true });
  await hive.ensureAgent({ id: 'jim-1', name: 'Jim', provider: 'claude', cwd: path.join(home, 'repo') });
  const dir = path.join(hive.root(), 'policy');
  fs.mkdirSync(dir, { recursive: true });
  for (const [name, body] of Object.entries(files)) fs.writeFileSync(path.join(dir, name), JSON.stringify(body));
  const server = new HookServer(hive, () => null, () => ({ harnessHome: home }), undefined, undefined);
  const logRows = () => fs.readFileSync(path.join(hive.root(), 'log.jsonl'), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
  const godInbox = () => fs.readdirSync(path.join(hive.root(), 'agents', 'god', 'inbox')).filter((f) => f.endsWith('.json'))
    .map((f) => JSON.parse(fs.readFileSync(path.join(hive.root(), 'agents', 'god', 'inbox', f), 'utf8')));
  return { home, hive, server, logRows, godInbox };
}

test('hook-schema authority.json alone: 0 rules, a status row, and god is told', async (t) => {
  const { server, logRows, godInbox } = await floor(t, { 'authority.json': HOOK_SCHEMA });
  server.announcePolicy();
  const status = logRows().find((r) => r.kind === 'policy-status');
  assert.equal(status.rules_loaded, 0);
  assert.match(status.error, /guardrail-hook schema/);
  const msg = godInbox().find((m) => /Guardrail policy failed to load/.test(m.subject));
  assert.ok(msg, 'the failure must reach god, not only log.jsonl');
  assert.equal(msg.from, 'guardrail');
  assert.equal(msg.requires_reply, false);
  const st = server.policyStatus();
  assert.equal(st.rulesLoaded, 0);
  assert.ok(st.error);
});

test('engine.json beside it: rules loaded 4, no message to god', async (t) => {
  const { server, logRows, godInbox } = await floor(t, { 'authority.json': HOOK_SCHEMA, 'engine.json': PACK() });
  server.announcePolicy();
  const status = logRows().find((r) => r.kind === 'policy-status');
  assert.equal(status.rules_loaded, 4);
  assert.equal(status.error, null);
  assert.equal(logRows().filter((r) => r.kind === 'policy-load-failed').length, 0);
  assert.equal(godInbox().filter((m) => /Guardrail/.test(m.subject)).length, 0);
  assert.deepEqual(server.policyStatus().ruleIds, ['cross-agent-write', 'cross-agent-workspace', 'destructive-shared-state', 'remote-push']);
});

test('no policy at all: silent, as before', async (t) => {
  const { server, hive, godInbox } = await floor(t, {});
  fs.rmSync(path.join(hive.root(), 'policy'), { recursive: true, force: true });
  server.announcePolicy();
  const log = path.join(hive.root(), 'log.jsonl');
  const rows = fs.existsSync(log) ? fs.readFileSync(log, 'utf8') : '';
  assert.doesNotMatch(rows, /policy-status|policy-load-failed/);
  assert.equal(godInbox().filter((m) => /Guardrail/.test(m.subject)).length, 0);
  assert.equal(server.policyStatus().configured, false);
});

test('agentWorkspaces: cwd, hive folder and harness worktree for live agents only', async (t) => {
  const { server, hive, home } = await floor(t, {});
  await hive.ensureAgent({ id: 'old-1', name: 'Old', provider: 'claude', cwd: path.join(home, 'old') });
  hive.setArchived('old-1', true);
  const ws = server.agentWorkspaces();
  const jim = ws.find((w) => w.agentId === 'jim-1');
  assert.deepEqual(jim.roots, [path.join(home, 'repo'), path.join(hive.root(), 'agents', 'jim-1'), path.join(home, 'worktrees', 'jim-1')]);
  assert.equal(ws.find((w) => w.agentId === 'old-1'), undefined, 'archived agents own nothing');
});

test('N1: an engine.json that parses but names no rules is a failure god hears about', async (t) => {
  for (const body of [{}, { rules: [] }, { rules: {} }]) {
    const { server, logRows, godInbox } = await floor(t, { 'engine.json': body });
    server.announcePolicy();
    const status = logRows().find((r) => r.kind === 'policy-status');
    assert.equal(status.rules_loaded, 0, JSON.stringify(body));
    assert.ok(status.error, `${JSON.stringify(body)}: error must be set`);
    assert.equal(godInbox().filter((m) => /Guardrail policy failed to load/.test(m.subject)).length, 1, JSON.stringify(body));
    assert.equal(server.policyStatus().error, status.error, 'fleet.json and the log say the same thing');
  }
});
