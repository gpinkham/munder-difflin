'use strict';
/**
 * A policy ask leaves the agent at Claude Code's permission prompt. The inbox-wake
 * watchdog must not type into that terminal until the prompt is answered: its
 * trailing Enter would choose "1. Yes" and run the action the rule asked about.
 * HookServer is what knows a policy ask is pending, so it answers for it.
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
  exports: { Notification: class { show() {} static isSupported() { return false; } } }
};
const { HiveManager } = loadTs('src/main/hive.ts');
const { HookServer } = loadTs('src/main/hooks.ts');

const PUSH_RULE = {
  id: 'remote-push', decision: 'ask', mode: 'live', reason: 'Pushing is the operator\'s call.',
  match: { tool: 'Bash', command_matches: '^git(?:\\s+-C\\s+\\S+)*\\s+push\\b' },
};

async function floor(t) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'md-askhold-'));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  const hive = new HiveManager(() => home);
  fs.mkdirSync(path.join(home, 'hive', 'policy'), { recursive: true });
  fs.writeFileSync(path.join(home, 'hive', 'policy', 'engine.json'), JSON.stringify({ version: 1, rules: [PUSH_RULE] }));
  const server = new HookServer(hive, () => null, () => ({}), undefined, undefined);
  await hive.ensureAgent({ id: 'god-1', name: 'God', provider: 'claude', cwd: home, isGod: true });
  await hive.ensureAgent({ id: 'jim-1', name: 'Jim', provider: 'claude', cwd: home });
  const fire = (p) => server.handle({ session_id: 's1', cwd: home, ...p, agent_id: 'jim-1' });
  return { server, fire };
}

test('a policy ask is awaiting an answer until the agent moves on', async (t) => {
  const { server, fire } = await floor(t);
  assert.equal(server.awaitingPolicyAnswer('jim-1'), false);
  const out = await fire({ hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command: 'cd x && git commit -m y && git push -q' } });
  assert.equal(out.hookSpecificOutput.permissionDecision, 'ask', 'precondition: the rule asked');
  assert.equal(server.awaitingPolicyAnswer('jim-1'), true);
  await fire({ hook_event_name: 'Notification', notification_type: 'permission_prompt', message: 'Claude needs your permission to use Bash' });
  assert.equal(server.awaitingPolicyAnswer('jim-1'), true, 'the prompt showing is not an answer');
  await fire({ hook_event_name: 'PostToolUse', tool_name: 'Bash', tool_input: { command: 'git push -q' } });
  assert.equal(server.awaitingPolicyAnswer('jim-1'), false, 'the tool ran: answered');
});

test('an allowed call leaves nothing awaiting, and another agent is never held', async (t) => {
  const { server, fire } = await floor(t);
  await fire({ hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command: 'git status' } });
  assert.equal(server.awaitingPolicyAnswer('jim-1'), false);
  await fire({ hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command: 'git push' } });
  assert.equal(server.awaitingPolicyAnswer('god-1'), false);
  assert.equal(server.awaitingPolicyAnswer(undefined), false);
});

// 34956ccb review H1: Esc at the permission prompt fires no hook, so nothing would
// ever settle the ask. Main settles it when the screen shows the menu is gone.
test('a dismissed policy ask is settled: not awaiting, and its card closes', async (t) => {
  const { server, fire } = await floor(t);
  await fire({ hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command: 'git push -q' } });
  assert.equal(server.awaitingPolicyAnswer('jim-1'), true);
  server.dismissPolicyAsk('jim-1');
  assert.equal(server.awaitingPolicyAnswer('jim-1'), false);
  server.dismissPolicyAsk('jim-1'); // idempotent
  server.dismissPolicyAsk(undefined);
});

// Review M1: PermissionRequest is registered so the gate opens ~100 ms after the
// prompt shows, not ~6 s later. A PermissionRequest hook CAN allow or deny, so the
// server must answer it with no decision at all.
test('PermissionRequest and the Elicitation pair pass through with no decision', async (t) => {
  const { server, fire } = await floor(t);
  const seen = [];
  server.onEvent = (_id, event) => seen.push(event);
  for (const e of ['PermissionRequest', 'Elicitation', 'ElicitationResult']) {
    const out = await fire({ hook_event_name: e, tool_name: 'Bash', tool_input: { command: 'git push' } });
    assert.equal(out?.hookSpecificOutput, undefined, `${e}: no decision`);
    assert.equal(out?.decision, undefined, e);
  }
  assert.deepEqual(seen.filter((e) => e !== 'Unknown').slice(-3), ['PermissionRequest', 'Elicitation', 'ElicitationResult']);
});
