'use strict';

// push_destination (HAG-53): a matcher that resolves where a git push LANDS - the
// current branch, push.default, the upstream and remote.<name>.push - so a rule can
// catch `git push` from master, which names no branch at all. Opt-in: an engine
// whose rules do not use it never runs git. Real repos, real git config.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const loadTs = require('./load-ts.cjs');

const { PolicyEngine } = loadTs('src/main/policy.ts');
const { pushTargets, realPushGit } = loadTs('src/main/pushDestination.ts');

const RULE = {
  id: 'protected-branch-push-resolved', decision: 'deny', mode: 'live', on_error: 'deny',
  reason: 'Protected branch.', match: { tool: 'Bash', push_destination: ['master', 'production-*'] },
};

function tmp(t, prefix) {
  const d = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));
  t.after(() => fs.rmSync(d, { recursive: true, force: true }));
  return d;
}

/** A repo on `branch` with a commit, an origin, and master tracking origin/master. */
function repo(t, { branch = 'master', config = {} } = {}) {
  const r = path.join(tmp(t, 'md-pushdst-'), 'repo');
  const g = (...a) => execFileSync('git', ['-C', r, ...a], { stdio: 'pipe' });
  execFileSync('git', ['init', '-q', '-b', 'master', r]);
  g('-c', 'user.email=a@b', '-c', 'user.name=a', 'commit', '-q', '--allow-empty', '-m', 'x');
  g('remote', 'add', 'origin', 'https://bitbucket.example/scm/p/r.git');
  g('config', 'branch.master.remote', 'origin');
  g('config', 'branch.master.merge', 'refs/heads/master');
  if (branch !== 'master') g('checkout', '-q', '-b', branch);
  for (const [k, v] of Object.entries(config)) for (const x of [].concat(v)) g('config', '--add', k, x);
  return r;
}

function engine(t, rules = [RULE], pushGit) {
  const root = tmp(t, 'md-pushdst-hive-');
  fs.mkdirSync(path.join(root, 'policy'));
  fs.writeFileSync(path.join(root, 'policy', 'engine.json'), JSON.stringify({ version: 1, rules }));
  const rows = [];
  const e = new PolicyEngine(root, (r) => rows.push(r), () => ['agent-a'], undefined, undefined, undefined, pushGit);
  e.load();
  return { e, rows };
}

const pre = (command, cwd) => ({ hook_event_name: 'PreToolUse', agent_id: 'agent-a', tool_name: 'Bash', tool_input: { command }, cwd });
const decide = (e, command, cwd) => e.evaluate(pre(command, cwd));

test('D1. from master, a push that names no destination is denied: it lands on master', (t) => {
  const r = repo(t);
  const { e } = engine(t);
  for (const command of ['git push', 'git push origin', 'git push -u origin HEAD', 'git push origin HEAD', 'git push origin @', 'git push -f', 'git push --force-with-lease origin']) {
    const v = decide(e, command, r);
    assert.equal(v.decision, 'deny', command);
    assert.equal(v.ruleId, 'protected-branch-push-resolved', command);
    assert.equal(v.matchedOn, 'push_destination', command);
  }
});

test('D2. the same pushes from a feature branch are allowed', (t) => {
  const r = repo(t, { branch: 'feat/x', config: { 'push.autoSetupRemote': 'true' } });
  const { e } = engine(t);
  for (const command of ['git push', 'git push origin', 'git push -u origin HEAD', 'git push origin HEAD', 'git push -f'])
    assert.equal(decide(e, command, r).decision, 'allow', command);
});

test('D3. a production-* branch is protected; a name that merely contains the word is not', (t) => {
  const { e } = engine(t);
  assert.equal(decide(e, 'git push -u origin HEAD', repo(t, { branch: 'production-2026-09' })).decision, 'deny');
  assert.equal(decide(e, 'git push -u origin HEAD', repo(t, { branch: 'feat/master' })).decision, 'allow');
  assert.equal(decide(e, 'git push -u origin HEAD', repo(t, { branch: 'production' })).decision, 'allow');
});

test('D4. push.default decides a bare push, including a -c override on the command', (t) => {
  const { e } = engine(t);
  // upstream: a feature branch whose upstream is master lands on master.
  const up = repo(t, { branch: 'feat/x', config: { 'push.default': 'upstream', 'branch.feat/x.remote': 'origin', 'branch.feat/x.merge': 'refs/heads/master' } });
  assert.equal(decide(e, 'git push', up).decision, 'deny', 'upstream -> master');
  // simple with that upstream: git refuses the mismatch, and we fail toward deny.
  assert.equal(decide(e, 'git -c push.default=simple push', up).decision, 'deny');
  // current: the upstream no longer matters.
  assert.equal(decide(e, 'git -c push.default=current push', up).decision, 'allow');
  // matching: every local branch that exists on both sides, master included.
  assert.equal(decide(e, 'git push', repo(t, { branch: 'feat/y', config: { 'push.default': 'matching' } })).decision, 'deny');
  // nothing: a bare push pushes nothing.
  assert.equal(decide(e, 'git -c push.default=nothing push', repo(t)).decision, 'allow');
  // current, overridden on the command line from master.
  assert.equal(decide(e, 'git -c push.default=current push', repo(t)).decision, 'deny');
});

test('D5. a push refspec in git config is followed, and a wildcard one reaches every branch', (t) => {
  const { e } = engine(t);
  assert.equal(decide(e, 'git push', repo(t, { branch: 'feat/x', config: { 'remote.origin.push': 'HEAD:refs/heads/master' } })).decision, 'deny');
  assert.equal(decide(e, 'git push origin', repo(t, { branch: 'feat/x', config: { 'remote.origin.push': 'refs/heads/*:refs/heads/*' } })).decision, 'deny');
  // `git push origin feat/x` with a mapping for feat/x lands where the mapping says.
  assert.equal(decide(e, 'git push origin feat/x', repo(t, { branch: 'feat/x', config: { 'remote.origin.push': 'refs/heads/feat/x:refs/heads/production-1' } })).decision, 'deny');
  // remote.pushDefault picks the remote, and ITS push refspec applies.
  const fork = repo(t, { branch: 'feat/x', config: { 'remote.pushDefault': 'fork', 'remote.fork.url': 'https://x.example/r.git', 'remote.fork.push': 'HEAD:master' } });
  assert.equal(decide(e, 'git push', fork).decision, 'deny');
  assert.equal(decide(e, 'git push origin', fork).decision, 'allow', 'origin has no push refspec');
});

test('D6. explicit destinations are judged too', (t) => {
  const r = repo(t, { branch: 'feat/x' });
  const { e } = engine(t);
  for (const command of ['git push origin feat/x:master', 'git push origin HEAD:refs/heads/production-x', 'git push origin +HEAD:master',
    'git push origin --delete master', 'git push -d origin production-1', 'git push origin :master', 'git push origin master',
    'git push --all origin', 'git push --mirror origin', 'git push --prune origin refs/heads/*:refs/heads/*', 'git push -fu origin HEAD:master',
    'git push -o ci.skip origin HEAD:master', 'git push --repo=origin origin HEAD:master',
    'git push origin HEAD:heads/master', 'git push origin heads/master', 'git push origin +feat/x:heads/production-1'])
    assert.equal(decide(e, command, r).decision, 'deny', command);
  for (const command of ['git push origin master:feat/y', 'git push origin refs/tags/master', 'git push --tags origin', 'git push origin feat/x',
    'git push --delete origin feat/old', 'git push -o master origin feat/x', 'git push origin HEAD:feat/master',
    'git push origin tags/master', "git push -o 'x -n y' origin feat/x"])
    assert.equal(decide(e, command, r).decision, 'allow', command);
});

test('D7. a dry run publishes nothing, so it is not a destination', (t) => {
  const { e } = engine(t);
  for (const command of ['git push --dry-run', 'git push -n origin HEAD', 'git push -nf origin master', 'git push --no-dry-run --dry-run'])
    assert.equal(decide(e, command, repo(t)).decision, 'allow', command);
  // --no-dry-run cancels an earlier -n / --dry-run (Dwight, HAG-50).
  for (const command of ['git push --dry-run --no-dry-run', 'git push -n --no-dry-run origin HEAD', "git push -o 'x -n y' origin HEAD"])
    assert.equal(decide(e, command, repo(t)).decision, 'deny', command);
});

test('D8. the repo is the one the push runs in: -C, cd, and wrappers', (t) => {
  const r = repo(t);
  const elsewhere = tmp(t, 'md-pushdst-cwd-');
  const { e } = engine(t);
  for (const command of [`git -C ${r} push`, `cd ${r} && git push`, `bash -c 'cd ${r} && git push origin'`, `cd ${path.dirname(r)} && git -C repo push`])
    assert.equal(decide(e, command, elsewhere).decision, 'deny', command);
  // A feature checkout, reached the same way, is allowed.
  const f = repo(t, { branch: 'feat/x' });
  assert.equal(decide(e, `cd ${f} && git push -u origin HEAD`, r).decision, 'allow');
});

test('D9. when git cannot say where a push goes, the rule fails closed (on_error: deny)', (t) => {
  const r = repo(t, { branch: 'feat/x' });
  const { e, rows } = engine(t);
  for (const command of ['GIT_DIR=/elsewhere/.git git push origin HEAD', 'export GIT_CONFIG_PARAMETERS=x; git push', 'cd $X && git push',
    'git push --frobnicate origin HEAD', 'git --namespace=n push origin HEAD', 'git push $R HEAD', 'git push origin $B',
    'git push origin {feat,master}', 'git push origin feat/{1..3}']) {
    const v = decide(e, command, r);
    assert.equal(v.decision, 'deny', command);
    assert.equal(v.matchedOn, 'error', command);
  }
  assert.ok(rows.some((x) => x.kind === 'policy-rule-error' && x.rule_id === 'protected-branch-push-resolved'));
  // Outside a repo git cannot answer either.
  assert.equal(decide(e, 'git push', tmp(t, 'md-pushdst-norepo-')).matchedOn, 'error');
  // With on_error: allow the rule abstains instead.
  const open = engine(t, [{ ...RULE, on_error: 'allow' }]).e;
  assert.equal(decide(open, 'git push --frobnicate origin HEAD', r).decision, 'allow');
});

test('D10. a detached HEAD pushes nothing with no refspec, and git commands that are not pushes are left alone', (t) => {
  const r = repo(t);
  execFileSync('git', ['-C', r, 'checkout', '-q', '--detach']);
  const { e } = engine(t);
  assert.equal(decide(e, 'git push', r).decision, 'allow');
  for (const command of ['git status', 'git log --grep push', 'git --frobnicate status', 'git stash push -m wip', 'git checkout master', 'echo git push', 'git pull origin master'])
    assert.equal(decide(e, command, repo(t)).decision, 'allow', command);
});

test('D11. opt-in: with no rule using it, git is never run, even for a push', (t) => {
  const calls = [];
  const spy = { run: (dir, args) => { calls.push(args); return realPushGit.run(dir, args); } };
  const r = repo(t);
  const { e } = engine(t, [{ id: 'p', decision: 'ask', mode: 'live', reason: 'x', match: { tool: 'Bash', command_matches: '^git\\s+push\\b' } }], spy);
  assert.equal(decide(e, 'git push', r).decision, 'ask');
  assert.deepEqual(calls, []);
  // And a rule that uses it runs git only for a push.
  const used = engine(t, [RULE], spy).e;
  decide(used, 'git status && ls', r);
  assert.deepEqual(calls, []);
  decide(used, 'git push', r);
  assert.ok(calls.length > 0);
});

test('D12. a git that hangs or fails is an error, not a guess', (t) => {
  const r = repo(t);
  const boom = { run: () => { throw Object.assign(new Error('spawnSync git ETIMEDOUT'), { code: 'ETIMEDOUT' }); } };
  const v = decide(engine(t, [RULE], boom).e, 'git push', r);
  assert.equal(v.decision, 'deny');
  assert.equal(v.matchedOn, 'error');
});

test('D13. dry_run logs would_deny and allows', (t) => {
  const { e } = engine(t, [{ ...RULE, mode: 'dry_run' }]);
  const v = decide(e, 'git push', repo(t));
  assert.equal(v.decision, 'allow');
  assert.equal(v.wouldDeny, true);
});

test('D14. a malformed push_destination is rejected at load, with the reason', (t) => {
  for (const bad of [[], 'master', [''], [3]]) {
    const { rows } = engine(t, [{ ...RULE, match: { tool: 'Bash', push_destination: bad } }]);
    const row = rows.find((x) => x.kind === 'policy-load-failed' || x.kind === 'policy-rule-rejected');
    assert.ok(row && /push_destination/.test(JSON.stringify(row)), JSON.stringify(rows));
  }
});

test('D15. pushTargets reads a push the way git does (unit)', (t) => {
  const r = repo(t, { branch: 'feat/x' });
  const at = (argv) => pushTargets(argv, r, realPushGit);
  assert.deepEqual(at(['git', 'push', 'origin', 'a:b', 'c']), { any: false, branches: ['b', 'c'] });
  assert.deepEqual(at(['git', 'push', 'origin', '--', '-weird']), { any: false, branches: ['-weird'] });
  assert.deepEqual(at(['git', 'push', '--mirror', 'origin']), { any: true });
  assert.equal(at(['git', 'status']), null);
  assert.equal(at(['git', 'push', '--dry-run']), null);
});

test('D16. config the push reads from elsewhere is followed or refused (Dwight, HAG-53)', (t) => {
  const r = repo(t, { branch: 'feat/x' });
  const inc = path.join(tmp(t, 'md-pushdst-inc-'), 'extra.cfg');
  fs.writeFileSync(inc, '[remote "origin"]\n\tpush = refs/heads/feat/x:refs/heads/master\n');
  const { e } = engine(t);
  // An include pulled in with -c is read, as git reads it.
  assert.equal(decide(e, `git -c include.path=${inc} push origin feat/x`, r).decision, 'deny');
  // A mirror remote pushes everything, deletes included.
  assert.equal(decide(e, 'git push origin', repo(t, { branch: 'feat/x', config: { 'remote.origin.mirror': 'true' } })).decision, 'deny');
  // A different HOME, config home or environment, an inline alias, and env -C are unreadable.
  for (const command of ['HOME=/tmp/h git push origin feat/x', 'XDG_CONFIG_HOME=/tmp/x git push origin feat/x', 'env -i git push origin feat/x',
    `env -C ${r} git push`, 'git -c alias.p=push p', 'git -c alias.p=push p origin HEAD', 'git --config-env=alias.p=P p']) {
    const v = decide(e, command, r);
    assert.equal(v.decision, 'deny', command);
    assert.equal(v.matchedOn, 'error', command);
  }
  // An alias that is not in play, and HOME set for something that is not a push, change nothing.
  assert.equal(decide(e, 'HOME=/tmp/h ls', r).decision, 'allow');
});

test('D17. a bare push costs at most three git calls, under one shared deadline', (t) => {
  const calls = [];
  const spy = { run: (dir, args, timeout) => { calls.push({ args, timeout }); return realPushGit.run(dir, args, timeout); } };
  const { e } = engine(t, [RULE], spy);
  assert.equal(decide(e, 'git push', repo(t)).decision, 'deny');
  assert.ok(calls.length <= 3, JSON.stringify(calls.map((c) => c.args)));
  assert.ok(calls.every((c) => c.timeout > 0 && c.timeout <= 3000), JSON.stringify(calls));
  // Once the budget is spent the next call is not made: it errors instead.
  let now = 0;
  const slow = { now: () => now, run: (dir, args, timeout) => { now += 3001; return realPushGit.run(dir, args, timeout); } };
  const v = decide(engine(t, [RULE], slow).e, 'git push', repo(t));
  assert.equal(v.matchedOn, 'error');
});

