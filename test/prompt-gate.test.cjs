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

// Dwight, 34956ccb review H1: Esc at a permission prompt or at an AskUserQuestion
// fires NO hook (live, 2.1.287), and an interrupt fires no Stop. Hook state alone
// would then hold the agent forever. The screen settles it: after Esc it ends on
// the input box again, and the terminal goes quiet.
const { holdState, DISMISS_QUIET_MS } = loadTs('src/main/promptGate.ts');

test('a menu dismissed with Esc reads as dismissed once the terminal is quiet', () => {
  for (const kind of ['ask', 'auq']) {
    const tail = fixture(`${kind}-esc`);
    assert.equal(screenShowsMenu(tail), false, `${kind}: after Esc the screen ends on the input box`);
    assert.equal(holdState(true, tail, DISMISS_QUIET_MS), 'dismissed', `${kind} quiet`);
    assert.equal(holdState(true, tail, DISMISS_QUIET_MS - 1), 'held', `${kind}: not yet quiet long enough`);
  }
});

test('a menu still on screen stays held however long it waits', () => {
  for (const kind of ['ask', 'auq', 'plan']) {
    assert.equal(holdState(true, fixture(`${kind}-menu`), 60 * 60_000), 'held', kind);
    assert.equal(holdState(false, fixture(`${kind}-menu`), 0), 'held', `${kind}: the screen alone holds`);
  }
});

test('with no open hook state, the input box is free and an unknown screen is free', () => {
  assert.equal(holdState(false, fixture('ask-after'), 0), 'free');
  assert.equal(holdState(false, '', 0), 'free');
  // Hook state open but no Claude Code screen to read: keep holding (errs closed).
  assert.equal(holdState(true, 'codex> working', 60 * 60_000), 'held');
  assert.equal(holdState(true, undefined, 60 * 60_000), 'held');
});

test('promptOpenOnPty releases a dismissed menu: the gate forgets it and the policy ask settles', () => {
  const src = fs.readFileSync(path.join(__dirname, '..', 'src', 'main', 'index.ts'), 'utf8');
  const fn = src.slice(src.indexOf('function promptOpenOnPty'), src.indexOf('function promptOpenOnPty') + 1600);
  assert.match(fn, /holdState\(/);
  assert.match(fn, /'dismissed'[\s\S]*promptGate\.forget\(agentId\)[\s\S]*hookServer\.dismissPolicyAsk\(agentId\)/);
  assert.match(fn, /ptyManager\.idleFor\(ptyId\)/);
});

// Review L2: when a menu opens between the text and its Enter, the text stays in
// the input box. A retry of the same text must send only Enter, not a second copy.
const { PendingSubmit } = loadTs('src/shared/pendingSubmit.ts');

test('text left in the input box is not typed again on the retry', () => {
  const p = new PendingSubmit();
  assert.equal(p.typeText('pty-1', 'hello'), true, 'nothing pending: type it');
  p.withheld('pty-1', 'hello');
  assert.equal(p.typeText('pty-1', 'hello'), false, 'the same text is already in the box');
  assert.equal(p.typeText('pty-2', 'hello'), true, 'another terminal is unaffected');
  p.submitted('pty-1');
  assert.equal(p.typeText('pty-1', 'hello'), true, 'after Enter the box is empty again');
});

test('interchangeable texts (inbox nudges) count as the same leftover', () => {
  const p = new PendingSubmit();
  p.withheld('pty-1', 'nudge a');
  assert.equal(p.typeText('pty-1', 'nudge b'), true, 'a different message is typed');
  assert.equal(p.typeText('pty-1', 'nudge b', true), false, 'a nudge already in the box serves');
  p.forget('pty-1');
  assert.equal(p.typeText('pty-1', 'nudge b', true), true);
});

test('the watchdog nudge sends only Enter when its text is already in the box', () => {
  const src = fs.readFileSync(path.join(__dirname, '..', 'src', 'main', 'index.ts'), 'utf8');
  const fn = src.slice(src.indexOf('function nudgeWorker'), src.indexOf('function runWorkerWakeBeat'));
  assert.match(fn, /nudgeLeftover\.typeText\(ptyId, text, true\)/);
  assert.match(fn, /nudgeLeftover\.withheld\(ptyId, text\)/);
  assert.match(fn, /nudgeLeftover\.submitted\(ptyId\)/);
  // The user (or anyone) submitting the box clears it; a dead terminal is forgotten.
  assert.match(src, /UserPromptSubmit'[\s\S]{0,200}nudgeLeftover\.submitted/);
  assert.match(src, /nudgeLeftover\.forget\(/);
});

// Review H1, part 3: a hold must never be invisible. The card says so.
test('an agent held at a menu says so on its card', () => {
  const read = (...p) => fs.readFileSync(path.join(__dirname, '..', 'src', 'renderer', 'src', ...p), 'utf8');
  assert.match(read('store', 'store.ts'), /heldAtMenu\?: boolean/);
  assert.match(read('components', 'AgentStrip.tsx'), /heldAtMenu=\{a\.heldAtMenu\}/);
  const card = read('components', 'AgentCard.tsx');
  assert.match(card, /heldAtMenu \? t\('agentCard\.heldAtMenu'\)/);
  const hive = read('hooks', 'useHive.ts');
  assert.match(hive, /ptyPromptOpen\(a\.ptyId\)[\s\S]{0,300}heldAtMenu/);
  for (const lang of ['en', 'ar', 'zh-CN']) {
    const json = JSON.parse(read('i18n', 'locales', `${lang}.json`));
    assert.ok(json.agentCard.heldAtMenu && json.agentCard.heldAtMenuTitle, lang);
  }
});

// Recheck LOW (c442a8a5): the renderer's leftover record must not outlive the text.
// If the user submits or edits the box, or the terminal exits, a retry that sent
// only Enter would submit an empty box and acknowledge a message never delivered.
test('the renderer forgets leftover text when the user submits, types, or the terminal exits', () => {
  const read = (...p) => fs.readFileSync(path.join(__dirname, '..', 'src', 'renderer', 'src', ...p), 'utf8');
  assert.match(read('hooks', 'inputLeftover.ts'), /export const inputLeftover = new PendingSubmit\(\)/);
  const hive = read('hooks', 'useHive.ts');
  assert.match(hive, /import \{ inputLeftover \} from '\.\/inputLeftover'/);
  assert.doesNotMatch(hive, /new PendingSubmit\(\)/, 'one shared record, not a private one');
  assert.match(hive, /e\.event === 'UserPromptSubmit' && self\.ptyId\) inputLeftover\.submitted\(self\.ptyId\)/);
  const pool = read('components', 'terminalPool.ts');
  const onData = pool.slice(pool.indexOf('term.onData((data) => {'), pool.indexOf('term.onData((data) => {') + 400);
  assert.match(onData, /inputLeftover\.forget\(ptyId\)/, 'a user keystroke');
  const onExit = pool.slice(pool.indexOf('window.cth.onPtyExit(ptyId'), pool.indexOf('window.cth.onPtyExit(ptyId') + 300);
  assert.match(onExit, /inputLeftover\.forget\(ptyId\)/, 'the terminal exited');
  const clear = pool.slice(pool.indexOf('export function clearTerminalDraft'), pool.indexOf('export function dismissTerminalPicker'));
  assert.match(clear, /inputLeftover\.forget\(ptyId\)/, 'Ctrl-U cleared the box');
  assert.match(read('components', 'PtyTerminalView.tsx'), /inputLeftover\.forget\(ptyId\)/, 'dropped paths');
});
