'use strict';
/**
 * A policy `ask` in an interactive agent stops the session at Claude's native
 * permission prompt, and nothing else on the floor says so (spike 2026-09-29: the
 * one Notification is `permission_prompt`, which the harness did not alert on).
 * Now a permission prompt that FOLLOWS A POLICY ASK raises a desktop alert and an
 * ASK ME card naming the agent and rule; the card closes when the agent moves on.
 * With no policy file, and for Claude's own prompts, nothing changes.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const loadTs = require('./load-ts.cjs');

const toasts = [];
const electron = require.resolve('electron');
require.cache[electron] = {
  id: electron, filename: electron, loaded: true,
  exports: { Notification: class { constructor(o) { this.o = o; } show() { toasts.push(this.o); } static isSupported() { return true; } } }
};
const { HiveManager } = loadTs('src/main/hive.ts');
const { HookServer } = loadTs('src/main/hooks.ts');

const ASK_RULE = { id: 'remote-push', decision: 'ask', mode: 'live', reason: 'Pushing is the operator\'s call.', match: { tool: 'Bash', command_matches: '^git\\s+push\\b' } };
const PROMPT = { hook_event_name: 'Notification', notification_type: 'permission_prompt', message: 'Claude needs your permission' };

async function floor(t, policy) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'md-prompt-alert-'));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  const hive = new HiveManager(() => home);
  if (policy) {
    fs.mkdirSync(path.join(home, 'hive', 'policy'), { recursive: true });
    fs.writeFileSync(path.join(home, 'hive', 'policy', 'engine.json'), JSON.stringify(policy));
  }
  await hive.ensureAgent({ id: 'jim-1', name: 'Jim', provider: 'claude', cwd: home });
  const server = new HookServer(hive, () => null, () => ({ notifications: true }), undefined, undefined);
  const fire = (p) => server.handle({ session_id: 's1', cwd: home, ...p, agent_id: 'jim-1' });
  const cards = () => (hive.tasks()?.tasks ?? []).filter((c) => c.id.startsWith('policy-prompt-'));
  toasts.length = 0;
  return { fire, cards };
}

test('a prompt raised by a policy ask alerts, and puts a card on ASK ME naming agent and rule', async (t) => {
  const f = await floor(t, { version: 1, rules: [ASK_RULE] });
  const res = await f.fire({ hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command: 'git push origin main' } });
  assert.equal(res.hookSpecificOutput.permissionDecision, 'ask');
  await f.fire(PROMPT);
  assert.equal(toasts.length, 1);
  assert.match(toasts[0].body, /remote-push/);
  const [card] = f.cards();
  assert.equal(card.status, 'blocked');
  assert.equal(card.assignee, 'jim-1');
  assert.match(card.humanQA[0].q, /jim-1 is stopped/);
  assert.match(card.humanQA[0].q, /remote-push/);
  await f.fire(PROMPT);
  assert.equal(f.cards().length, 1, 'one card per prompt, not one per notification');
});

test('the card closes itself when the agent moves on', async (t) => {
  const f = await floor(t, { version: 1, rules: [ASK_RULE] });
  await f.fire({ hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command: 'git push origin main' } });
  await f.fire(PROMPT);
  await f.fire({ hook_event_name: 'PostToolUse', tool_name: 'Bash', tool_input: { command: 'git push origin main' }, tool_response: { stdout: '' } });
  const [card] = f.cards();
  assert.equal(card.status, 'done');
  assert.ok(card.humanQA[0].a);
});

test('Claude\'s own permission prompt, with a policy loaded, changes nothing', async (t) => {
  const f = await floor(t, { version: 1, rules: [ASK_RULE] });
  await f.fire({ hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command: 'ls' } });
  await f.fire(PROMPT);
  assert.equal(toasts.length, 0);
  assert.deepEqual(f.cards(), []);
});

test('with no policy file, a permission prompt changes nothing', async (t) => {
  const f = await floor(t, null);
  await f.fire({ hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command: 'git push origin main' } });
  await f.fire(PROMPT);
  assert.equal(toasts.length, 0);
  assert.deepEqual(f.cards(), []);
});

test('a dry_run rule never raises a prompt, so it never raises an alert', async (t) => {
  const f = await floor(t, { version: 1, rules: [{ ...ASK_RULE, mode: 'dry_run' }] });
  await f.fire({ hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command: 'git push origin main' } });
  await f.fire(PROMPT);
  assert.equal(toasts.length, 0);
  assert.deepEqual(f.cards(), []);
});
