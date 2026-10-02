'use strict';
/**
 * Every automated write into an agent's terminal ends in Enter. While Claude Code
 * shows a menu — a permission prompt, an AskUserQuestion, a plan approval, an MCP
 * form — Enter chooses the highlighted option, so a nudge or a queued message
 * answers a question nobody read. The prompt gate is the one place that knows a
 * menu is open, from hook events, with the screen as a backstop.
 *
 * The event sequences below are what Claude Code 2.1.287 sent in a live session
 * (2026-10-02); the screen fixtures are the last 8 KB of that terminal, captured at
 * the menu and again after it was answered.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const loadTs = require('./load-ts.cjs');

const { PromptGate, screenShowsMenu } = loadTs('src/main/promptGate.ts');

const pre = (tool, id) => ({ hook_event_name: 'PreToolUse', tool_name: tool, tool_use_id: id });
const post = (tool, id) => ({ hook_event_name: 'PostToolUse', tool_name: tool, tool_use_id: id });
const permReq = (tool) => ({ hook_event_name: 'PermissionRequest', tool_name: tool });
const note = (type, message = 'Claude needs your permission') => ({ hook_event_name: 'Notification', notification_type: type, message });

function run(events, agent = 'jim') {
  const g = new PromptGate();
  for (const e of events) g.noteHook(agent, e);
  return g;
}

test('AskUserQuestion is a menu from its PreToolUse until its own PostToolUse', () => {
  const g = new PromptGate();
  g.noteHook('jim', { hook_event_name: 'UserPromptSubmit' });
  assert.equal(g.isOpen('jim'), false);
  g.noteHook('jim', pre('AskUserQuestion', 'q1'));
  assert.equal(g.isOpen('jim'), true, 'open before the 6-second notification');
  g.noteHook('jim', permReq('AskUserQuestion'));
  g.noteHook('jim', note('permission_prompt'));
  assert.equal(g.isOpen('jim'), true);
  g.noteHook('jim', post('AskUserQuestion', 'q1'));
  assert.equal(g.isOpen('jim'), false);
});

test('a plan approval (ExitPlanMode) is a menu until it is answered', () => {
  const g = run([pre('ExitPlanMode', 'p1'), permReq('ExitPlanMode'), note('permission_prompt', 'Claude Code needs your approval for the plan')]);
  assert.equal(g.isOpen('jim'), true);
  g.noteHook('jim', post('ExitPlanMode', 'p1'));
  assert.equal(g.isOpen('jim'), false);
});

test('a Bash permission prompt opens at PermissionRequest and closes with that call', () => {
  const g = run([pre('Bash', 'b1')]);
  assert.equal(g.isOpen('jim'), false, 'an ordinary tool call is not a menu');
  g.noteHook('jim', permReq('Bash'));
  assert.equal(g.isOpen('jim'), true);
  g.noteHook('jim', post('Bash', 'b1'));
  assert.equal(g.isOpen('jim'), false);
});

test('a parallel tool finishing does not close another call\'s prompt', () => {
  const g = run([pre('Read', 'r1'), pre('Bash', 'b1'), permReq('Bash'), post('Read', 'r1')]);
  assert.equal(g.isOpen('jim'), true, 'Read finished; the Bash prompt is still up');
  g.noteHook('jim', post('Bash', 'b1'));
  assert.equal(g.isOpen('jim'), false);
});

test('with only the notification (no PermissionRequest hook) the prompt still holds', () => {
  const g = run([pre('Bash', 'b1'), note('permission_prompt')]);
  assert.equal(g.isOpen('jim'), true);
  g.noteHook('jim', post('Read', 'other'));
  assert.equal(g.isOpen('jim'), true, 'a different call does not answer it');
  g.noteHook('jim', post('Bash', 'b1'));
  assert.equal(g.isOpen('jim'), false);
});

test('a refusal, a failure, a new prompt, the end of the turn or a restart all close it', () => {
  for (const closer of [
    { hook_event_name: 'PermissionDenied', tool_name: 'Bash', tool_use_id: 'b1' },
    { hook_event_name: 'PostToolUseFailure', tool_name: 'Bash', tool_use_id: 'b1' },
    { hook_event_name: 'UserPromptSubmit' },
    { hook_event_name: 'Stop' },
    { hook_event_name: 'StopFailure' },
    { hook_event_name: 'SessionStart' },
  ]) {
    const g = run([pre('Bash', 'b1'), permReq('Bash'), closer]);
    assert.equal(g.isOpen('jim'), false, closer.hook_event_name);
  }
});

test('idle and informational notifications are not menus', () => {
  for (const t of ['idle_prompt', 'auth_success', 'agent_completed', 'elicitation_complete']) {
    assert.equal(run([note(t, 'Claude is waiting for your input')]).isOpen('jim'), false, t);
  }
});

test('an MCP form is a menu until its result', () => {
  const g = run([{ hook_event_name: 'Elicitation', mcp_server_name: 'x' }]);
  assert.equal(g.isOpen('jim'), true);
  g.noteHook('jim', { hook_event_name: 'ElicitationResult', mcp_server_name: 'x' });
  assert.equal(g.isOpen('jim'), false);
  assert.equal(run([note('elicitation_dialog')]).isOpen('jim'), true);
});

test('agents are independent and forget clears one', () => {
  const g = run([pre('AskUserQuestion', 'q1')], 'jim');
  g.noteHook('pam', pre('Bash', 'x'));
  assert.equal(g.isOpen('pam'), false);
  assert.equal(g.isOpen('jim'), true);
  g.forget('jim');
  assert.equal(g.isOpen('jim'), false);
  assert.equal(g.isOpen(undefined), false);
});

const fixture = (name) => fs.readFileSync(path.join(__dirname, 'fixtures', 'prompt-tails', `${name}.bin`)).toString('utf8');

test('the screen shows a menu at each real prompt and not after it is answered', () => {
  for (const kind of ['ask', 'auq', 'plan']) {
    assert.equal(screenShowsMenu(fixture(`${kind}-menu`)), true, `${kind} at the menu`);
    assert.equal(screenShowsMenu(fixture(`${kind}-after`)), false, `${kind} after the answer`);
  }
  assert.equal(screenShowsMenu(''), false);
  assert.equal(screenShowsMenu(undefined), false);
});

test('a terminal that is not Claude Code never reads as a menu from the screen alone', () => {
  // Another CLI never draws Claude's input-box footer, so after one menu-like line it
  // would look "at a menu" until 8 KB of output scrolled past, starving its inbox.
  assert.equal(screenShowsMenu('codex> apply patch? (y/n)  Esc to cancel'), false);
  assert.equal(screenShowsMenu('? for shortcuts\n Do you want to proceed?\n 1. Yes  Esc to cancel'), true);
});
