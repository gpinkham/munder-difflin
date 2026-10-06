'use strict';

/*
 * Finish plan item 5 (Dwight L1 on 3456403f): the hook server took any payload that
 * named an agent, so any local process could raise an Approvals card, a god notice or
 * an alert in an agent's name, or spend its approval. Each agent the app starts now
 * gets HIVE_HOOK_TOKEN (an HMAC of its id under a secret that lives only in the app's
 * memory) and every shim sends it. A payload naming an agent without the right token
 * gets the policy decision and nothing else: enforcement never weakens, side effects
 * need the token.
 *
 * Limit (stated, not hidden): a same-user process that reads an agent's environment
 * (ps eww) can copy that agent's token. This stops blind forgery, not that.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const loadTs = require('./load-ts.cjs');

const electron = require.resolve('electron');
require.cache[electron] = { id: electron, filename: electron, loaded: true,
  exports: { Notification: class { show() {} static isSupported() { return false; } } } };

const { HookAuth } = loadTs('src/main/hookAuth.ts');
const { HiveManager } = loadTs('src/main/hive.ts');
const { HookServer } = loadTs('src/main/hooks.ts');
const { GrantStore } = loadTs('src/main/grants.ts');

const SHA = '270d83f1c2c5572d4eec1d66819c64168ecd7a61';
const URL = 'git@github.com:o/r.git';
const PUSH = `git push origin ${SHA}:refs/heads/feat/x`;
const RULES = { version: 1, rev: 1, rules: [
  { id: 'push', principle: 'Do not push without my approval.', agents: 'all',
    backstop: { on: true, does: 'ask', approve_on_card: ['git-push'], match: { tool: 'Bash', command_matches: '^git(?:\\s+-C\\s+\\S+)*\\s+push\\b' } } },
  { id: 'no-rm', principle: 'Never rm -rf.', agents: 'all', backstop: { on: true, does: 'block', match: { tool: 'Bash', command_matches: '^rm\\s+-rf\\b' } } },
] };

async function floor(t) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'md-hookauth-'));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  const repo = path.join(home, 'repo');
  execFileSync('git', ['init', '-q', repo]);
  execFileSync('git', ['-C', repo, 'remote', 'add', 'origin', URL]);
  fs.mkdirSync(path.join(home, 'hive', 'policy'), { recursive: true });
  fs.writeFileSync(path.join(home, 'hive', 'policy', 'guardrail.json'), JSON.stringify(RULES));
  const auth = new HookAuth();
  const hive = new HiveManager(() => home);
  hive.setHookTokens((id) => auth.token(id));
  const server = new HookServer(hive, () => null, () => ({}), undefined, undefined);
  server.setHookAuth(auth);
  hive.setApprovalHandler((id, msg) => server.handleApprovalRequest(id, msg));
  await hive.ensureAgent({ id: 'god-1', name: 'God', provider: 'claude', cwd: home, isGod: true });
  const spawn = await hive.ensureAgent({ id: 'jim-1', name: 'Jim', provider: 'claude', cwd: repo });
  const events = [];
  server.onEvent = (agentId, event) => events.push([agentId, event]);
  const send = (command, token, event = 'PreToolUse') => server.handle({
    agent_id: 'jim-1', session_id: 's', hook_event_name: event, tool_name: 'Bash', tool_input: { command }, cwd: repo,
    ...(token === undefined ? {} : { hook_token: token }),
  });
  const decision = (out) => out?.hookSpecificOutput?.permissionDecision ?? 'none';
  const log = () => fs.readFileSync(path.join(home, 'hive', 'log.jsonl'), 'utf8');
  return { home, auth, hive, server, spawn, send, decision, log, events };
}

test('a token is per agent and per app run', () => {
  const a = new HookAuth();
  const b = new HookAuth();
  assert.equal(a.token('jim'), a.token('jim'));
  assert.notEqual(a.token('jim'), a.token('pam'));
  assert.notEqual(a.token('jim'), b.token('jim'), 'a new secret every run');
  assert.equal(a.verify('jim', a.token('jim')), true);
  for (const bad of [undefined, null, '', 'x', a.token('pam'), b.token('jim'), 42]) assert.equal(a.verify('jim', bad), false, String(bad));
});

test('an agent the app starts gets its token in the environment', async (t) => {
  const f = await floor(t);
  assert.equal(f.spawn.env.HIVE_HOOK_TOKEN, f.auth.token('jim-1'));
});

test('every shim sends the token on every socket write', () => {
  const src = fs.readFileSync(path.join(__dirname, '..', 'src', 'main', 'hive.ts'), 'utf8');
  const writes = src.match(/createConnection\([^\n]*JSON\.stringify\([^\n]*/g) ?? [];
  assert.ok(writes.length >= 7, `found ${writes.length} socket writes`);
  for (const w of writes) assert.match(w, /hook_token: process\.env\.HIVE_HOOK_TOKEN/, w);
  assert.match(src, /HIVE_SOCK: cfg\.sock,[\s\S]{0,200}HIVE_HOOK_TOKEN:/, 'the proxy sidecar gets it too');
});

test('with the token: the usual path (the push raises its Approvals card)', async (t) => {
  const f = await floor(t);
  assert.equal(f.decision(await f.send(PUSH, f.auth.token('jim-1'))), 'deny');
  assert.equal(f.server.pendingGrants().length, 1);
  assert.ok(f.events.some(([, e]) => e === 'PreToolUse'));
});

test('without the token: the decision only (rules still enforced), no card, no grant use, no events', async (t) => {
  const f = await floor(t);
  for (const token of [undefined, 'forged', f.auth.token('pam')]) {
    assert.equal(f.decision(await f.send('rm -rf /x', token)), 'deny', 'a block still blocks');
    assert.equal(f.decision(await f.send(PUSH, token)), 'ask', 'no approval path: the push asks');
    assert.equal(JSON.stringify(await f.send('ls', token, 'Stop')), '{}', 'other events are ignored');
  }
  assert.equal(f.server.pendingGrants().length, 0, 'no card was raised');
  assert.equal(f.events.length, 0, 'nothing reached the floor');
  assert.doesNotMatch(f.log(), /"kind":"grant-requested"/);
  assert.match(f.log(), /"kind":"hook-unauthenticated"[^\n]*"agent_id":"jim-1"/);
  // An approved push cannot be spent by a forged request.
  await f.send(PUSH, f.auth.token('jim-1'));
  const [p] = f.server.pendingGrants();
  f.server.decideGrant(p.id, true);
  assert.equal(f.decision(await f.send(PUSH, 'forged')), 'ask');
  assert.doesNotMatch(fs.readFileSync(path.join(f.home, 'hive', 'policy', 'grants.jsonl'), 'utf8'), /"op":"use"/);
  assert.equal(f.decision(await f.send(PUSH, f.auth.token('jim-1'))), 'allow', 'the real agent still has it');
});

test('the app wires one HookAuth into both the hook server and the agents it starts', () => {
  const main = fs.readFileSync(path.join(__dirname, '..', 'src', 'main', 'index.ts'), 'utf8');
  assert.match(main, /const hookAuth = new HookAuth\(\);/);
  assert.match(main, /hookServer\.setHookAuth\(hookAuth\);/);
  assert.match(main, /hive\.setHookTokens\(\(id\) => hookAuth\.token\(id\)\);/);
});
