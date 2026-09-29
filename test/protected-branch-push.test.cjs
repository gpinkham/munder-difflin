'use strict';

// Held-out cases for protected-branch-push (HAG-50): a push whose destination is a
// protected branch (master, production-*) is DENIED, like a merge; a feature push,
// a dry run and PR creation are not. Run against the shipped pack forced live, with
// the rule placed ahead of remote-push as the README says (rules are first-match).
// Written with the rule in view, so they measure gaps, not a blind catch rate.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const loadTs = require('./load-ts.cjs');

const { PolicyEngine } = loadTs('src/main/policy.ts');

const RULE = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'examples/policy/protected-branch-push.rule.json'), 'utf8'));

/** The shipped pack plus the rule, forced live; or the rule alone. */
function engine({ alone = false } = {}) {
  const pack = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'examples/policy/engine.example.json'), 'utf8'));
  const rules = alone ? [] : pack.rules;
  const at = rules.findIndex((r) => r.id === 'remote-push');
  rules.splice(at < 0 ? rules.length : at, 0, { ...RULE });
  for (const r of rules) r.mode = 'live';
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'md-protected-'));
  fs.mkdirSync(path.join(root, 'policy'));
  fs.writeFileSync(path.join(root, 'policy', 'engine.json'), JSON.stringify({ version: 1, rules }));
  const rows = [];
  const e = new PolicyEngine(root, (row) => rows.push(row), () => ['agent-a']);
  e.load();
  return { e, rows };
}

const pre = (command) => ({ hook_event_name: 'PreToolUse', agent_id: 'agent-a', tool_name: 'Bash', tool_input: { command } });

test('P0. the rule loads beside the shipped pack, and alone, with nothing rejected', () => {
  const { rows } = engine();
  const loaded = rows.find((r) => r.kind === 'policy-loaded');
  assert.ok(loaded, JSON.stringify(rows));
  assert.equal(loaded.rules_loaded, 6);
  assert.ok(!rows.some((r) => r.kind === 'policy-load-failed'));
  assert.equal(engine({ alone: true }).rows.find((r) => r.kind === 'policy-loaded').rules_loaded, 1);
  assert.equal(RULE.decision, 'deny');
  assert.equal(RULE.on_error, 'deny');
  assert.ok(!('grantable' in RULE), 'a deny is not grantable: the operator pushes these');
});

test('P1. every push that names master or production-* as its destination is denied', () => {
  const { e } = engine();
  for (const command of [
    'git push origin master',
    'git push origin production-2026-09',
    'git push origin production-eu',
    'git push -u origin master',
    'git push origin HEAD:master',
    'git push origin @:master',
    'git push origin feat/x:master',
    'git push origin feat/x:refs/heads/master',
    'git push origin HEAD:refs/heads/production-hotfix',
    'git push origin refs/heads/master',
    'git push origin master:master',
    'git push origin +master',
    'git push origin +feat/x:master',
    'git push origin :master',
    'git push origin :refs/heads/production-1',
    'git push origin --delete master',
    'git push --delete origin production-old',
    'git push -d origin master',
    'git push --force origin master',
    'git push -f origin feat/x:master',
    'git push --force-with-lease origin master',
    'git push --force-with-lease=master:abc123 origin HEAD:master',
    'git push origin master --force',
    'git push origin feat/x master',
    'git push origin feat/x production-2',
    'git push https://bitbucket.corp.example/scm/p/r.git HEAD:master',
    'git push -o ci.skip origin master',
    'git push --repo=origin origin master',
    'git push origin --all',
    'git push --all origin',
    'git push --branches origin',
    'git push --mirror origin',
    "git push origin 'refs/heads/*:refs/heads/*'",
    'git push origin refs/heads/*',
    // wrapped forms: the parser hands the rule the bare invocation
    'git -C /r push origin master',
    'git -c push.default=current push origin master',
    'git --git-dir=/r/.git push origin master',
    'env GIT_TRACE=1 git push origin master',
    "bash -c 'git push origin HEAD:master'",
    'sh -c "git push origin production-1"',
    'cd /r && git push origin master',
    'git commit -am wip; git push origin master',
    '/usr/bin/git push origin master',
    'sudo git push origin master',
    'git push origin "master"',
    'git subtree push --prefix=lib origin master',
    'git send-pack origin master',
    // a real push that merely carries dry-run text as a flag's value
    'git push -o --dry-run origin master',
    'git push --push-option -n origin master',
    // a real push after a dry run in the same call
    'git push --dry-run origin master && git push origin master',
    // Dwight's HAG-50 review: each of these moved master in a real repo
    'git push -n --no-dry-run origin master',
    'git push --dry-run --no-dry-run origin master',
    "git push -o 'x -n y' origin master",
    "git push --push-option='x --dry-run' origin master",
    'git push origin HEAD:heads/master',
    'git push origin heads/master',
    'git push origin +feat/x:heads/production-1',
    'git push origin {feat,master}',
    'git push origin feat/{x,y}',
    'git push origin mas{t,}er',
    'git push origin HEAD:production-{1..3}x',
    'git --git-dir /r/.git push origin master',
    'git --work-tree /r push origin master',
    'git --git-dir /r/.git --work-tree /r push origin HEAD:master',
  ]) {
    const v = e.evaluate(pre(command));
    assert.equal(v.decision, 'deny', command);
    assert.equal(v.ruleId, 'protected-branch-push', command);
  }
});

test('P2. feature pushes, dry runs, PR creation and near-miss names are not denied by it', () => {
  const { e } = engine();
  for (const command of [
    'git push origin feat/x',
    'git push -u origin feat/x',
    'git push --force origin feat/x',
    'git push --force-with-lease origin feat/x',
    'git push origin HEAD:feat/x',
    'git push origin master:feat/x',
    'git push origin production-1:hotfix/copy',
    'git push origin feat/master',
    'git push origin feat/master-menu',
    'git push origin masterclass',
    'git push origin fix/production-notes',
    'git push origin production',
    'git push origin refs/tags/master',
    'git push origin feat/heads/master',
    'git push origin tags/master',
    'git push origin v1.2.3',
    'git push --tags origin',
    'git push --dry-run origin master',
    'git push -n origin master',
    'git push origin master --dry-run',
    'git push origin master -n',
    'git push --dry-run --force origin HEAD:master',
    'git push --delete origin feat/old',
    'git push production-mirror feat/x',
    'git push -o master origin feat/x',
    'git push origin feat/x && git log master',
    'git push origin feat/x; git checkout master',
    'git push origin feat/x # not master',
    'git push origin feat/x --all-the-things',
    'git checkout master',
    'git pull origin master',
    'git fetch origin master',
    'git merge origin/master',
    'git rebase origin/master',
    'git log origin/master..HEAD',
    'git diff master',
    'git branch -D master',
    "git commit -m 'push to master later'",
    "echo 'git push origin master'",
    "grep -rn 'git push origin master' notes.md",
    "bb pr create --source feat/x --destination master --title 'x'",
    'bb pr create -t fix --target production-1',
    'bb pr list --destination master',
  ]) {
    const v = e.evaluate(pre(command));
    assert.notEqual(v.ruleId, 'protected-branch-push', command);
    assert.notEqual(v.decision, 'deny', command);
  }
});

test('P3. with the rule alone, a feature push is allowed outright', () => {
  const { e } = engine({ alone: true });
  for (const command of ['git push origin feat/x', 'git push -u origin HEAD', 'bb pr create --destination master'])
    assert.equal(e.evaluate(pre(command)).decision, 'allow', command);
  assert.equal(e.evaluate(pre('git push origin master')).decision, 'deny');
});

test('P4. GAP: a push that names no destination is judged by its words, not by the branch it lands on',
  { todo: 'bare `git push`, `git push origin` and `git push origin HEAD` go where the current branch and push.default say; the push_destination card resolves that' }, () => {
    const { e } = engine();
    // Run from a checkout sitting on master, all three land on master.
    for (const command of ['git push', 'git push origin', 'git push -u origin HEAD'])
      assert.equal(e.evaluate(pre(command)).decision, 'deny', command);
  });

test('P5. GAP: an alias or a script file that pushes is not seen',
  { todo: 'the engine reads the command, not an alias defined elsewhere or the script a command runs' }, () => {
    const { e } = engine();
    assert.equal(e.evaluate(pre('git pm')).decision, 'deny');
    assert.equal(e.evaluate(pre('./scripts/release.sh')).decision, 'deny');
  });

test('P6. the pattern runs in linear time: a crafted command cannot stall the main process', () => {
  // 86428280's brace clause had three overlapping repeats: `a{,{,{,…` (16k chars) took
  // over 10 s, synchronously, in front of every tool call.
  const re = new RegExp(RULE.match.command_matches);
  for (const unit of ['{,', '{', '@{', '{}', "'", 'a:', 'a*', '-o ', 'heads/', '--x ', '-C ', '--git-dir '])
    for (const tail of ['Q', ',x}', ':master', ' master']) {
      const s = (unit.startsWith('-') ? 'git ' : 'git push origin a') + unit.repeat(unit.startsWith('-') ? 40 : 5000) + tail;
      const t = Date.now();
      re.test(s);
      assert.ok(Date.now() - t < 250, `${JSON.stringify(unit)} + ${JSON.stringify(tail)}: ${Date.now() - t} ms`);
    }
});
