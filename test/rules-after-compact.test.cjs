'use strict';

/*
 * md-197 — the harness re-delivers an agent's full rule set after a compaction.
 *
 * A compact keeps the session id (md-138), so anything delivered once per session
 * — the standing goal, the first rules notice — is gone from context afterwards
 * unless the agent chooses to re-read memory.md. These tests drive a real
 * HookServer wired to a real RulesManager over a throwaway harnessHome.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const loadTs = require('./load-ts.cjs');

// hooks.ts imports Electron's Notification class; tests only read return values.
const electron = require.resolve('electron');
require.cache[electron] = {
  id: electron,
  filename: electron,
  loaded: true,
  exports: { Notification: class { show() {} static isSupported() { return false; } } }
};

const { HookServer } = loadTs('src/main/hooks.ts');
const { RulesManager } = loadTs('src/main/rules.ts');

const store = (rev, extra = []) => ({
  rev,
  rules: [
    { id: 'own-folder', text: 'Write only to your own folder.', scope: { kind: 'global' }, status: 'active' },
    { id: 'jim-only', text: 'Jim-specific rule.', scope: { kind: 'agents', ids: ['jim'] }, status: 'active' },
    ...extra
  ]
});

function harness(opts = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'md-compact-'));
  for (const id of ['jim', 'pam']) {
    fs.mkdirSync(path.join(root, 'hive', 'agents', id), { recursive: true });
    fs.writeFileSync(path.join(root, 'hive', 'agents', id, 'memory.md'), `# Memory — ${id}\n`);
  }
  const storePath = path.join(root, 'hive', 'policy', 'rules.json');
  const writeStore = (s) => {
    fs.mkdirSync(path.dirname(storePath), { recursive: true });
    fs.writeFileSync(storePath, JSON.stringify(s));
  };
  if (opts.store !== null) writeStore(opts.store ?? store(1));

  const rows = [];
  const rules = new RulesManager(() => root, (r) => rows.push(r));
  const hive = { recordSession() {}, isGod() { return false; } };
  const server = new HookServer(
    hive,
    () => null,
    () => ({ notifications: false }),
    undefined,
    undefined,
    () => opts.goal ?? null,
    undefined,
    (id) => rules.takeNotice(id),
    (id) => rules.fullSet(id)
  );
  const fire = (event, extra = {}, agentId = 'jim') => server.handle({
    agent_id: agentId,
    hook_event_name: event,
    session_id: 'session-1',
    ...extra
  });
  return { fire, writeStore, storePath, rows };
}

const context = (res) => res?.hookSpecificOutput?.additionalContext ?? '';
const FULL = /Re-delivered after compaction/;

test('compaction then prompt: the full rule set arrives once', () => {
  const { fire } = harness();
  fire('SessionStart');
  fire('UserPromptSubmit'); // first-ever notice consumed here

  assert.equal(context(fire('PreCompact')), '', 'PreCompact itself carries nothing');
  assert.equal(context(fire('PostCompact')), '', 'PostCompact itself carries nothing');

  const after = context(fire('UserPromptSubmit'));
  assert.match(after, FULL);
  assert.match(after, /Authority rules \(rev 1\)/);
  assert.match(after, /\(1\) Write only to your own folder\./);
  assert.match(after, /\(2\) Jim-specific rule\./);
  assert.doesNotMatch(after, /<!-- (BEGIN|END) managed rules/, 'sentinels stay in the file');

  assert.equal(context(fire('UserPromptSubmit')), '', 'second prompt does not repeat it');
});

test('without a compaction, prompts never carry the full set', () => {
  const { fire } = harness();
  fire('SessionStart');
  for (let i = 0; i < 3; i++) assert.doesNotMatch(context(fire('UserPromptSubmit')), FULL);
});

test('the set is role-scoped: each agent gets only the rules that target it', () => {
  const { fire } = harness();
  fire('PreCompact', {}, 'pam');
  fire('PostCompact', {}, 'pam');
  const pam = context(fire('UserPromptSubmit', {}, 'pam'));
  assert.match(pam, /Write only to your own folder/);
  assert.doesNotMatch(pam, /Jim-specific/);
  assert.doesNotMatch(context(fire('UserPromptSubmit', {}, 'jim')), FULL, 'jim was not compacted');
});

test('an agent working through tool calls gets it on the next PostToolUse', () => {
  const { fire } = harness();
  fire('SessionStart');
  fire('PreCompact');
  fire('PostCompact');
  assert.match(context(fire('PostToolUse', { tool_name: 'Read' })), FULL);
  assert.doesNotMatch(context(fire('UserPromptSubmit')), FULL);
});

test('SessionStart source=compact also re-delivers, once', () => {
  const { fire } = harness();
  assert.match(context(fire('SessionStart', { source: 'compact' })), FULL);
  assert.doesNotMatch(context(fire('UserPromptSubmit')), FULL);
});

test('each compaction re-delivers again', () => {
  const { fire } = harness();
  fire('SessionStart');
  fire('PreCompact');
  fire('PostCompact');
  assert.match(context(fire('UserPromptSubmit')), FULL);
  fire('PreCompact');
  fire('PostCompact');
  assert.match(context(fire('UserPromptSubmit')), FULL);
});

test('a rule change still notifies, and a later compaction delivers the new set', () => {
  const { fire, writeStore } = harness();
  fire('SessionStart');
  fire('UserPromptSubmit');

  writeStore(store(2, [{ id: 'new-rule', text: 'Brand-new rule.', scope: { kind: 'global' }, status: 'active' }]));
  const notice = context(fire('UserPromptSubmit'));
  assert.match(notice, /RULES UPDATED — rev 1 → 2/);
  assert.match(notice, /\[\+\] Brand-new rule\./);
  assert.doesNotMatch(notice, FULL, 'a change is a diff, not the full set');
  assert.equal(context(fire('UserPromptSubmit')), '', 'the change notice fires once');

  fire('PreCompact');
  fire('PostCompact');
  const after = context(fire('UserPromptSubmit'));
  assert.match(after, /Authority rules \(rev 2\)/);
  assert.match(after, /Brand-new rule\./);
});

test('re-delivery does not consume a pending change notice', () => {
  const { fire, writeStore } = harness();
  fire('SessionStart');
  fire('UserPromptSubmit');
  writeStore(store(2, [{ id: 'new-rule', text: 'Brand-new rule.', scope: { kind: 'global' }, status: 'active' }]));

  fire('PreCompact');
  fire('PostCompact');
  const both = context(fire('UserPromptSubmit'));
  assert.match(both, FULL);
  assert.match(both, /RULES UPDATED — rev 1 → 2/);
});

test('no rules store: a compaction injects nothing', () => {
  const { fire } = harness({ store: null });
  fire('SessionStart');
  fire('PreCompact');
  fire('PostCompact');
  assert.equal(context(fire('UserPromptSubmit')), '');
});

test('an unreadable store mid-edit does not lose the re-delivery', () => {
  const { fire, storePath, writeStore } = harness();
  fire('SessionStart');
  fire('UserPromptSubmit');
  fire('PreCompact');
  fire('PostCompact');

  fs.writeFileSync(storePath, '{"rev": 1, "rules": [');   // caught half-written
  assert.doesNotMatch(context(fire('UserPromptSubmit')), FULL);

  writeStore(store(1));
  assert.match(context(fire('UserPromptSubmit')), FULL, 'delivered once the store reads again');
  assert.doesNotMatch(context(fire('UserPromptSubmit')), FULL, 'and only once');
});

test('an app restart after a compaction: the resumed session gets the rules once', () => {
  const before = harness();
  before.fire('SessionStart');
  before.fire('PreCompact');
  before.fire('PostCompact');
  // The app restarts before the next prompt: a new HookServer, the mark gone.
  const { fire } = harness();
  assert.match(context(fire('SessionStart', { source: 'resume' })), FULL);
  assert.doesNotMatch(context(fire('UserPromptSubmit')), FULL);
});

test('a fresh startup session does not get the post-compact set', () => {
  const { fire } = harness();
  assert.doesNotMatch(context(fire('SessionStart', { source: 'startup' })), FULL);
});

test('SessionStart(compact) before PostCompact: rules and goal arrive once, not twice', () => {
  const { fire } = harness({ goal: 'Ship the release safely.' });
  fire('SessionStart');
  fire('UserPromptSubmit');

  fire('PreCompact');
  const start = context(fire('SessionStart', { source: 'compact' }));
  assert.match(start, FULL);
  assert.match(start, /Ship the release safely/);
  fire('PostCompact');
  assert.equal(context(fire('UserPromptSubmit')), '', 'nothing repeated after PostCompact');
});

test('SessionStart(compact) after PostCompact: rules arrive once', () => {
  const { fire } = harness();
  fire('SessionStart');
  fire('UserPromptSubmit');

  fire('PreCompact');
  fire('PostCompact');
  assert.match(context(fire('SessionStart', { source: 'compact' })), FULL);
  assert.doesNotMatch(context(fire('UserPromptSubmit')), FULL);
});

test('an inert rule is re-delivered with its note', () => {
  const { fire } = harness({ store: store(1, [
    { id: 'inert', text: 'Template-only rule.', scope: { kind: 'global' }, status: 'active',
      inertHere: true, note: 'INERT in this hive: carry on normally.' },
    { id: 'bare-inert', text: 'Inert without a note.', scope: { kind: 'global' }, status: 'active', inertHere: true },
    { id: 'live', text: 'Live rule.', scope: { kind: 'global' }, status: 'active', note: 'Not shown: this rule is live.' }
  ]) });
  fire('PreCompact');
  fire('PostCompact');
  const after = context(fire('UserPromptSubmit'));
  assert.match(after, /Template-only rule\.\n {4}↳ INERT in this hive: carry on normally\./);
  assert.match(after, /Inert without a note\.\n {4}↳ Inert on this instance/);
  assert.doesNotMatch(after, /Not shown/, 'only inert rules carry the note');
});

test('re-delivery is logged so an operator can see it happened', () => {
  const { fire, rows } = harness();
  fire('PreCompact');
  fire('PostCompact');
  fire('UserPromptSubmit');
  assert.ok(rows.some((r) => r.kind === 'rules-redelivered' && r.agentId === 'jim' && r.rev === 1));
});
