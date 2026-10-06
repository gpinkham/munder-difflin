'use strict';

/*
 * Finish plan item 1: one rules file, hive/policy/guardrail.json. A rule is a guiding
 * principle (text the agents get) with an optional backstop (what the hook enforces).
 * The engine reads only this file; the day job's engine.json and rules.json are
 * migrated into it once and renamed. Spec: for-gary/rules-editor-spec.md (v3).
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const loadTs = require('./load-ts.cjs');

const { GUARDRAIL_FILE, migrateLegacyPolicy, toEngineRules, validateGuardrail } = loadTs('src/main/guardrail.ts');
const { PolicyEngine } = loadTs('src/main/policy.ts');
const { RulesManager } = loadTs('src/main/rules.ts');

function home(t) {
  const h = fs.mkdtempSync(path.join(os.tmpdir(), 'md-guardrail-'));
  t.after(() => fs.rmSync(h, { recursive: true, force: true }));
  fs.mkdirSync(path.join(h, 'hive', 'policy'), { recursive: true });
  return h;
}
const pol = (h, f) => path.join(h, 'hive', 'policy', f);
const put = (h, f, v) => fs.writeFileSync(pol(h, f), JSON.stringify(v));
const get = (h, f) => JSON.parse(fs.readFileSync(pol(h, f), 'utf8'));
const pre = (command, agent_id = 'jim') => ({ hook_event_name: 'PreToolUse', agent_id, tool_name: 'Bash', tool_input: { command }, cwd: '/r' });
function engine(h, rows = []) {
  const e = new PolicyEngine(path.join(h, 'hive'), (r) => rows.push(r));
  e.load();
  return e;
}

const ENGINE = {
  version: 1,
  defaults: { mode: 'live', on_error: 'deny' },
  report_check: { mode: 'dry_run' },
  rules: [
    { id: 'no-master', decision: 'deny', reason: 'Never push master.', match: { tool: 'Bash', command_matches: 'master' } },
    { id: 'remote-push', decision: 'ask', mode: 'live', reason: 'Pushing is the operator\'s call.', grantable: ['git-push'], match: { tool: 'Bash', command_matches: '^git\\s+push\\b' } },
    { id: 'watch-rm', decision: 'deny', mode: 'dry_run', on_error: 'allow', reason: 'rm is watched.', match: { tool: 'Bash', command_matches: '^rm\\s' } },
  ],
};
const PROSE = {
  rev: 7,
  rules: [
    { id: 'small-commits', text: 'Keep commits small.', scope: { kind: 'agents', ids: ['pam', 'ryan'] }, why: 'reviewable' },
    { id: 'no-unapproved-work', text: 'Do no work a human has not approved.', scope: { kind: 'global' } },
    { id: 'old', text: 'An old rule.', status: 'retired' },
    { id: 'remote-push', text: 'Ask before pushing.', scope: 'all' },
  ],
};

test('migration: engine rules become backstops, prose rules principles; old files renamed; once', (t) => {
  const h = home(t);
  put(h, 'engine.json', ENGINE);
  put(h, 'rules.json', PROSE);
  const rows = [];
  assert.equal(migrateLegacyPolicy(pol(h, ''), (r) => rows.push(r)).migrated, true);
  const g = get(h, GUARDRAIL_FILE);
  assert.equal(g.version, 1);
  assert.equal(g.rev, 8, 'past the prose store rev, so agents are re-rendered');
  assert.deepEqual(g.defaults, { on_error: 'deny' });
  assert.deepEqual(g.report_check, { mode: 'dry_run' });
  const by = Object.fromEntries(g.rules.map((r) => [r.id, r]));
  assert.deepEqual(by['no-master'], { id: 'no-master', principle: 'Never push master.', agents: 'all',
    backstop: { on: true, does: 'block', match: { tool: 'Bash', command_matches: 'master' }, message: 'Never push master.' } });
  assert.deepEqual(by['remote-push'].backstop, { on: true, does: 'ask', approve_on_card: ['git-push'],
    match: { tool: 'Bash', command_matches: '^git\\s+push\\b' }, message: 'Pushing is the operator\'s call.' });
  assert.equal(by['watch-rm'].backstop.does, 'log');
  assert.equal(by['watch-rm'].backstop.on_error, 'allow');
  assert.deepEqual(by['small-commits'], { id: 'small-commits', principle: 'Keep commits small.', agents: ['pam', 'ryan'], why: 'reviewable' });
  assert.equal(by['no-unapproved-work'].agents, 'all');
  assert.equal(by['no-unapproved-work'].backstop, undefined);
  assert.equal(by.old, undefined, 'retired rules are not carried (they stay in the renamed file)');
  assert.equal(by['remote-push-principle'].principle, 'Ask before pushing.', 'an id clash is kept apart, not merged');
  for (const f of ['engine.json', 'rules.json']) {
    assert.equal(fs.existsSync(pol(h, f)), false, `${f} moved aside`);
    assert.equal(fs.readdirSync(pol(h, '')).filter((x) => x.startsWith(`${f}.migrated-`)).length, 1);
  }
  const row = rows.find((r) => r.kind === 'guardrail-migrated');
  assert.deepEqual([row.backstops, row.principles_only, row.skipped_retired], [3, 3, 1]);
  assert.equal(migrateLegacyPolicy(pol(h, ''), () => {}).migrated, false, 'once: guardrail.json exists');
});

test('the migrated file enforces what engine.json did', (t) => {
  const h = home(t);
  put(h, 'engine.json', ENGINE);
  const e = engine(h);
  assert.equal(e.evaluate(pre('git push origin master')).decision, 'deny');
  assert.equal(e.evaluate(pre('git push origin main')).decision, 'ask');
  const rm = e.evaluate(pre('rm -rf /tmp/x'));
  assert.deepEqual([rm.decision, rm.wouldDeny], ['allow', true], 'log only');
  assert.equal(e.evaluate(pre('ls')).decision, 'allow');
  assert.match(e.status.file, /guardrail\.json$/);
  assert.equal(e.status.error, null);
});

test('a backstop that is off, or for other agents, does not fire; principle-only rules never do', (t) => {
  const h = home(t);
  put(h, GUARDRAIL_FILE, { version: 1, rev: 1, rules: [
    { id: 'off', principle: 'x', agents: 'all', backstop: { on: false, does: 'block', match: { tool: 'Bash', command_matches: '^ls' } } },
    { id: 'pam-only', principle: 'y', agents: ['pam'], backstop: { on: true, does: 'block', match: { tool: 'Bash', command_matches: '^cat' } } },
    { id: 'text', principle: 'Be kind.', agents: 'all' },
  ] });
  const e = engine(h);
  assert.equal(e.evaluate(pre('ls')).decision, 'allow');
  assert.equal(e.evaluate(pre('cat f', 'jim')).decision, 'allow');
  assert.equal(e.evaluate(pre('cat f', 'pam')).decision, 'deny');
  assert.deepEqual(e.status.ruleIds, ['pam-only']);
});

test('all backstops off, or no rules at all, loads cleanly as nothing enforced; a legacy engine.json with no rules is an error', (t) => {
  const h = home(t);
  put(h, GUARDRAIL_FILE, { version: 1, rev: 1, rules: [{ id: 'text', principle: 'Be kind.', agents: 'all' }] });
  let e = engine(h);
  assert.deepEqual([e.status.configured, e.status.error, e.status.rulesLoaded], [true, null, 0]);
  put(h, GUARDRAIL_FILE, { version: 1, rev: 1, rules: [] });
  e = engine(h);
  assert.deepEqual([e.status.configured, e.status.error, e.status.rulesLoaded], [true, null, 0], 'Dwight L1: deleting every rule is not a broken file');
  const h2 = home(t);
  put(h2, 'engine.json', { version: 1, rules: [] });
  assert.match(engine(h2).status.error, /no rules/, 'a truncated legacy file still fails loudly');
});

test('validation names the rule and the field', () => {
  const bad = (rules, re) => assert.match(validateGuardrail({ version: 1, rev: 1, rules }).join('; '), re);
  bad([{ id: 'a', principle: '', agents: 'all' }], /a: principle/);
  bad([{ id: 'a', principle: 'p', agents: 'all' }, { id: 'a', principle: 'q', agents: 'all' }], /a: duplicate id/);
  bad([{ id: 'a', principle: 'p', agents: 'some' }], /a: agents/);
  bad([{ id: 'a', principle: 'p', agents: 'all', backstop: { on: true, does: 'nuke', match: { tool: 'Bash' } } }], /a: backstop\.does/);
  bad([{ id: 'a', principle: 'p', agents: 'all', backstop: { on: true, does: 'block', approve_on_card: ['git-push'], match: { tool: 'Bash' } } }], /a: approve_on_card.*ask/);
  bad([{ id: 'a', principle: 'p', agents: 'all', backstop: { on: true, does: 'block', match: { nope: 1 } } }], /a: unknown matcher/);
  assert.deepEqual(validateGuardrail({ version: 1, rev: 1, rules: [{ id: 'a', principle: 'p', agents: 'all' }] }), []);
  assert.match(validateGuardrail([]).join(''), /object/);
});

test('toEngineRules maps does to decision and mode, and the message to the reason', () => {
  const r = toEngineRules({ version: 1, rev: 1, rules: [
    { id: 'b', principle: 'P', agents: ['pam'], backstop: { on: true, does: 'block', match: { tool: 'Bash' } } },
    { id: 'a', principle: 'P', agents: 'all', backstop: { on: true, does: 'ask', approve_on_card: ['git-push'], match: { tool: 'Bash' }, message: 'M' } },
    { id: 'l', principle: 'P', agents: 'all', backstop: { on: true, does: 'log', match: { tool: 'Bash' } } },
  ] });
  assert.deepEqual(r.map((x) => [x.id, x.decision, x.mode, x.reason, x.agents, x.grantable]), [
    ['b', 'deny', 'live', 'P', ['pam'], undefined],
    ['a', 'ask', 'live', 'M', undefined, ['git-push']],
    ['l', 'deny', 'dry_run', 'P', undefined, undefined],
  ]);
});

test('the agents get the principles from guardrail.json', (t) => {
  const h = home(t);
  put(h, GUARDRAIL_FILE, { version: 1, rev: 4, rules: [
    { id: 'small', principle: 'Keep commits small.', agents: ['pam'] },
    { id: 'push', principle: 'Do not push without approval.', agents: 'all', backstop: { on: true, does: 'ask', match: { tool: 'Bash' } } },
  ] });
  const rm = new RulesManager(() => h, () => {});
  assert.equal(rm.active, true);
  const r = rm.read();
  assert.equal(r.rev, 4);
  assert.deepEqual(r.rules.map((x) => [x.id, x.text, JSON.stringify(x.scope)]), [
    ['small', 'Keep commits small.', JSON.stringify({ kind: 'agents', ids: ['pam'] })],
    ['push', 'Do not push without approval.', JSON.stringify({ kind: 'global' })],
  ]);
});

test('a hive with principles only is migrated by the engine at start, then read from guardrail.json', (t) => {
  const h = home(t);
  put(h, 'rules.json', PROSE);
  const e = engine(h);
  assert.ok(fs.existsSync(pol(h, GUARDRAIL_FILE)));
  assert.deepEqual([e.status.configured, e.status.error, e.status.rulesLoaded], [true, null, 0], 'principles only: nothing enforced, no error');
  const r = new RulesManager(() => h, () => {}).read();
  assert.equal(r.rev, 8);
  assert.deepEqual(r.rules.map((x) => x.id), ['small-commits', 'no-unapproved-work', 'remote-push']);
});

test('editing a principle keeps its backstop, bumps rev, and backs the file up', async (t) => {
  const h = home(t);
  fs.mkdirSync(path.join(h, 'hive', 'agents', 'jim'), { recursive: true });
  put(h, GUARDRAIL_FILE, { version: 1, rev: 3, rules: [
    { id: 'push', principle: 'Do not push.', agents: 'all', backstop: { on: true, does: 'ask', match: { tool: 'Bash', command_matches: '^git push' } } },
  ] });
  const rm = new RulesManager(() => h, () => {});
  const out = await rm.upsert({ id: 'push', text: 'Do not push without my approval.', scope: { kind: 'global' } }, { actor: 'gary', agentIds: ['jim'], expectedRev: 3 });
  assert.equal(out.ok, true, JSON.stringify(out));
  const g = get(h, GUARDRAIL_FILE);
  assert.equal(g.rev, 4);
  assert.equal(g.rules[0].principle, 'Do not push without my approval.');
  assert.deepEqual(g.rules[0].backstop, { on: true, does: 'ask', match: { tool: 'Bash', command_matches: '^git push' } });
  assert.equal(fs.readdirSync(pol(h, '')).filter((f) => f.startsWith(`${GUARDRAIL_FILE}.bak-`)).length, 1);
});

// --- Dwight's lows on items 1+2 ----------------------------------------------------------

test('L2: a reload resets the defaults, so an old on_error does not stick', (t) => {
  const h = home(t);
  put(h, GUARDRAIL_FILE, { version: 1, rev: 1, defaults: { on_error: 'deny' }, rules: [{ id: 'p', principle: 'x', agents: 'all' }] });
  const e = engine(h);
  assert.equal(e.defaults.on_error, 'deny');
  put(h, GUARDRAIL_FILE, { version: 1, rev: 2, rules: [{ id: 'p', principle: 'x', agents: 'all' }] });
  e.load();
  assert.equal(e.defaults.on_error, 'allow');
});

test('L4: migration keeps descriptions and notes, and refuses what it cannot carry instead of dropping it', (t) => {
  const h = home(t);
  put(h, 'engine.json', { version: 1, defaults: { mode: 'live' }, rules: [
    { id: 'no-rm', decision: 'deny', reason: 'No rm.', description: 'Stops rm -rf.', _match_why: 'anchored', match: { tool: 'Bash', command_matches: '^rm\\s' } },
  ] });
  migrateLegacyPolicy(pol(h, ''), () => {});
  const r = get(h, GUARDRAIL_FILE).rules[0];
  assert.equal(r.why, 'Stops rm -rf.');
  assert.deepEqual(r.notes, { _match_why: 'anchored' });
  for (const [what, engineRules, prose, re] of [
    ['an unknown scope', null, { rev: 1, rules: [{ id: 'r', text: 'x', scope: 'role' }] }, /r: .*scope/],
    ['duplicate engine ids', [{ id: 'a', decision: 'deny', reason: 'x', match: { tool: 'Bash' } }, { id: 'a', decision: 'deny', reason: 'y', match: { tool: 'Bash' } }], null, /a: duplicate/],
    ['duplicate prose ids', null, { rev: 1, rules: [{ id: 'b', text: 'x' }, { id: 'b', text: 'y' }] }, /b: duplicate/],
  ]) {
    const h2 = home(t);
    if (engineRules) put(h2, 'engine.json', { version: 1, rules: engineRules });
    if (prose) put(h2, 'rules.json', prose);
    const rows = [];
    const out = migrateLegacyPolicy(pol(h2, ''), (row) => rows.push(row));
    assert.equal(out.migrated, false, what);
    assert.match(out.error, re, what);
    assert.equal(fs.existsSync(pol(h2, GUARDRAIL_FILE)), false, `${what}: nothing written`);
    assert.ok(rows.some((row) => row.kind === 'guardrail-migration-failed'), what);
  }
});
