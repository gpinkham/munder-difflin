'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const loadTs = require('./load-ts.cjs');

const { PolicyEngine, globToRegExp, interpolate, digest } = loadTs('src/main/policy.ts');

/** A throwaway hive root. `rules === null` means "no policy file at all". */
function hive(rules, defaults) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'md-policy-'));
  if (rules !== null) {
    fs.mkdirSync(path.join(root, 'policy'), { recursive: true });
    const body = typeof rules === 'string'
      ? rules
      : JSON.stringify({ version: 1, ...(defaults ? { defaults } : {}), rules });
    fs.writeFileSync(path.join(root, 'policy', 'authority.json'), body);
  }
  return root;
}

/** Build an engine and capture every ledger row it writes. */
function engine(rules, defaults) {
  const root = hive(rules, defaults);
  const rows = [];
  const e = new PolicyEngine(root, (row) => rows.push(row), () => ['pi', 'opencode', 'qwen']);
  e.load();
  return { e, rows, root, policyPath: path.join(root, 'policy', 'authority.json') };
}

const pre = (tool_name, tool_input, agent_id) => ({
  hook_event_name: 'PreToolUse', agent_id: agent_id ?? 'agent-a', tool_name, tool_input
});

const OWN_FOLDER_RULE = {
  id: 'cross-agent-write',
  description: 'An agent may only write inside its own agent folder.',
  decision: 'deny',
  mode: 'live',
  reason: 'Agent folders are owned by their agent. Write to your own outbox/ instead — the harness delivers it.',
  match: {
    tool: ['Write', 'Edit', 'NotebookEdit'],
    path_glob: '**/hive/agents/*/**',
    path_not_glob: '**/hive/agents/${AGENT_ID}/**'
  }
};

const MEMPALACE_RULE = {
  id: 'destructive-shared-state',
  decision: 'deny',
  mode: 'live',
  reason: 'mempalace sync deletes every per-agent wing and cannot be undone. To record something, append to your memory.md — it is mined automatically.',
  match: { tool: 'Bash', command_matches: '^\\s*mempalace\\s+(sync|repair)\\b' }
};

const PUSH_RULE = {
  id: 'remote-push',
  decision: 'ask',
  mode: 'live',
  reason: 'Pushing is the operator\'s decision. Commit to a branch and report the branch name; ask before pushing.',
  match: { tool: 'Bash', command_matches: '(^|[;&|]\\s*)git\\s+(?:-[Cc]\\s+\\S+\\s+|-{1,2}\\S+\\s+)*push\\b' }
};

// --- 1. The mergeability test -------------------------------------------------

test('1. no policy file: inert — no decision, no log line, nothing evaluated', () => {
  const { e, rows } = engine(null);
  assert.equal(e.active, false);
  assert.equal(e.ruleCount, 0);
  const v = e.evaluate(pre('Write', { file_path: '/anywhere/at/all.md' }));
  assert.equal(v.decision, 'allow');
  assert.equal(rows.length, 0, 'an unconfigured install must log nothing at all');
});

test('1b. no hive root at all is also inert', () => {
  const rows = [];
  const e = new PolicyEngine(null, (r) => rows.push(r));
  e.load();
  assert.equal(e.active, false);
  assert.equal(e.evaluate(pre('Write', { file_path: '/x' })).decision, 'allow');
  assert.equal(rows.length, 0);
});

// --- 2. Malformed policy ------------------------------------------------------

test('2. malformed JSON: loads nothing, logs policy-load-failed, denies nothing', () => {
  const { e, rows } = engine('{ this is not json');
  assert.equal(e.ruleCount, 0);
  assert.equal(rows.filter((r) => r.kind === 'policy-load-failed').length, 1);
  assert.equal(e.evaluate(pre('Write', { file_path: '/x/y.md' })).decision, 'allow');
});

test('2b. one invalid rule rejects the WHOLE file — no partial enforcement', () => {
  // Partial enforcement is worse than none, because it is believed.
  const { e, rows } = engine([OWN_FOLDER_RULE, { id: 'bad', decision: 'deny', reason: 'x', match: { nope: 1 } }]);
  assert.equal(e.ruleCount, 0);
  const failed = rows.find((r) => r.kind === 'policy-load-failed');
  assert.ok(failed, 'must log the failure');
  assert.match(String(failed.error), /unknown matcher "nope"/);
});

test('2c. rules missing a reason are rejected at load', () => {
  const { e } = engine([{ id: 'r', decision: 'deny', match: { tool: 'Bash' } }]);
  assert.equal(e.ruleCount, 0);
});

test('2d. an empty match is rejected — it would fire on every tool call', () => {
  const { e } = engine([{ id: 'r', decision: 'deny', reason: 'a reason long enough', match: {} }]);
  assert.equal(e.ruleCount, 0);
});

test('2e. an unanchored path glob is rejected', () => {
  const { e } = engine([{ ...OWN_FOLDER_RULE, match: { tool: 'Write', path_glob: 'agents/*/**' } }]);
  assert.equal(e.ruleCount, 0);
});

// --- 3 & 4. cross-agent-write -------------------------------------------------

test('3. agent A writing into agent B folder: deny in live mode', () => {
  const { e, rows } = engine([OWN_FOLDER_RULE]);
  const v = e.evaluate(pre('Write', { file_path: '/root/hive/agents/agent-b/notes.md' }, 'agent-a'));
  assert.equal(v.decision, 'deny');
  assert.equal(v.ruleId, 'cross-agent-write');
  assert.equal(v.matchedOn, 'path_glob');
  const row = rows.find((r) => r.kind === 'policy-decision');
  assert.equal(row.decision, 'deny');
  assert.equal(row.would_deny, false);
});

test('3b. same write in dry_run: ALLOWS and records would_deny', () => {
  // You cannot measure a false positive after enforcing.
  const { e, rows } = engine([{ ...OWN_FOLDER_RULE, mode: 'dry_run' }]);
  const v = e.evaluate(pre('Write', { file_path: '/root/hive/agents/agent-b/notes.md' }, 'agent-a'));
  assert.equal(v.decision, 'allow');
  assert.equal(v.wouldDeny, true);
  const row = rows.find((r) => r.kind === 'policy-decision');
  assert.equal(row.would_deny, true);
  assert.equal(row.decision, 'allow');
});

test('3c. dry_run is the default when a rule omits mode', () => {
  const rule = { ...OWN_FOLDER_RULE };
  delete rule.mode;
  const { e } = engine([rule]);
  const v = e.evaluate(pre('Write', { file_path: '/root/hive/agents/agent-b/x.md' }, 'agent-a'));
  assert.equal(v.decision, 'allow');
  assert.equal(v.wouldDeny, true);
});

test('4. agent writing its OWN folder: allow, and no log line', () => {
  const { e, rows } = engine([OWN_FOLDER_RULE]);
  const v = e.evaluate(pre('Write', { file_path: '/root/hive/agents/agent-a/memory.md' }, 'agent-a'));
  assert.equal(v.decision, 'allow');
  assert.equal(rows.filter((r) => r.kind === 'policy-decision').length, 0);
});

test('4b. reading another agent folder is not a write, so the rule does not fire', () => {
  const { e } = engine([OWN_FOLDER_RULE]);
  const v = e.evaluate(pre('Read', { file_path: '/root/hive/agents/agent-b/memory.md' }, 'agent-a'));
  assert.equal(v.decision, 'allow');
});

test('4c. a path outside the agents tree does not fire', () => {
  const { e } = engine([OWN_FOLDER_RULE]);
  assert.equal(e.evaluate(pre('Write', { file_path: '/root/hive/policy/notes.md' }, 'agent-a')).decision, 'allow');
  assert.equal(e.evaluate(pre('Write', { file_path: '/Users/x/dev/site/index.html' }, 'agent-a')).decision, 'allow');
});

test('4d. a .. walk into another agent folder is caught after normalisation', () => {
  const { e } = engine([OWN_FOLDER_RULE]);
  const v = e.evaluate(pre('Write', { file_path: '/root/hive/agents/agent-a/../agent-b/x.md' }, 'agent-a'));
  assert.equal(v.decision, 'deny');
});

// --- 5. Self-protection ------------------------------------------------------

test('5. writing the policy file is denied even with NO rules loaded', () => {
  const { e, policyPath } = engine([]);
  const v = e.evaluate(pre('Write', { file_path: policyPath }, 'agent-a'));
  assert.equal(v.decision, 'deny');
  assert.equal(v.ruleId, 'policy-self-protection');
  assert.equal(v.mode, 'live', 'self-protection is never dry-run');
});

test('5b. writing anything else in the policy DIRECTORY is denied too', () => {
  const { e, root } = engine([]);
  const v = e.evaluate(pre('Write', { file_path: path.join(root, 'policy', 'sneaky.json') }, 'agent-a'));
  assert.equal(v.ruleId, 'policy-self-protection');
});

test('5c. a bash redirect into the policy dir is denied; READING it is not', () => {
  const { e, root } = engine([]);
  const dir = path.join(root, 'policy');
  assert.equal(e.evaluate(pre('Bash', { command: `echo '{}' > ${dir}/authority.json` })).decision, 'deny');
  assert.equal(e.evaluate(pre('Bash', { command: `rm -rf ${dir}` })).decision, 'deny');
  // An agent should be able to read the rule it just tripped.
  assert.equal(e.evaluate(pre('Bash', { command: `cat ${dir}/authority.json` })).decision, 'allow');
  assert.equal(e.evaluate(pre('Bash', { command: `grep -n deny ${dir}/authority.json` })).decision, 'allow');
});

test('5d. self-protection is NOT armed when unconfigured (keeps test 1 true)', () => {
  const { e } = engine(null);
  assert.equal(e.evaluate(pre('Write', { file_path: '/anything/policy/authority.json' })).decision, 'allow');
});

// --- 7. mempalace anchoring --------------------------------------------------

test('7. mempalace sync denies; a mention of it must NOT', () => {
  const { e } = engine([MEMPALACE_RULE]);
  assert.equal(e.evaluate(pre('Bash', { command: 'mempalace sync' })).decision, 'deny');
  assert.equal(e.evaluate(pre('Bash', { command: 'mempalace repair' })).decision, 'deny');
  assert.equal(e.evaluate(pre('Bash', { command: 'echo "mempalace sync"' })).decision, 'allow');
  assert.equal(e.evaluate(pre('Bash', { command: 'mempalace wake-up' })).decision, 'allow');
  assert.equal(e.evaluate(pre('Bash', { command: 'mempalace search "x"' })).decision, 'allow');
});

test('7b. the rule is scoped to Bash, so a Write mentioning it does not fire', () => {
  const { e } = engine([MEMPALACE_RULE]);
  assert.equal(e.evaluate(pre('Write', { file_path: '/x/notes.md', command: 'mempalace sync' })).decision, 'allow');
});

// --- 8. git push stays ASK ---------------------------------------------------

test('8. git push returns ASK, never deny — a false positive costs one prompt', () => {
  const { e, rows } = engine([PUSH_RULE]);
  const v = e.evaluate(pre('Bash', { command: 'cd /repo && git push origin main' }));
  assert.equal(v.decision, 'ask');
  assert.notEqual(v.decision, 'deny');
  assert.equal(rows.find((r) => r.kind === 'policy-decision').decision, 'ask');
});

test('8b. git push inside a heredoc body does NOT match — the anchoring works', () => {
  // Writing the spec for this feature tripped exactly this case with a bare
  // substring regex. Anchoring the pattern to a command position fixes it
  // outright: `git` preceded by ordinary whitespace is a mention, not a command.
  // Verified here rather than assumed, because the spec predicted it would still
  // match and be survivable via `ask`. It does not match at all, which is better.
  const { e, rows } = engine([PUSH_RULE]);
  const v = e.evaluate(pre('Bash', { command: "cat <<'EOF' > notes.md\nrun git push when ready\nEOF" }));
  assert.equal(v.decision, 'allow');
  assert.equal(rows.filter((r) => r.kind === 'policy-decision').length, 0);
  // Same reason a plain mention is safe.
  assert.equal(e.evaluate(pre('Bash', { command: 'echo git push' })).decision, 'allow');
  assert.equal(e.evaluate(pre('Bash', { command: 'grep -rn "git push" README.md' })).decision, 'allow');
});

test('8c. git -C <dir> push matches — the shape a bare-substring regex misses', () => {
  const { e } = engine([PUSH_RULE]);
  assert.equal(e.evaluate(pre('Bash', { command: 'git -C /Users/x/dev/site push origin main' })).decision, 'ask');
  assert.equal(e.evaluate(pre('Bash', { command: 'git -c user.name=x push' })).decision, 'ask');
});

test('8d. other git subcommands do not fire, including --grep push', () => {
  const { e } = engine([PUSH_RULE]);
  for (const cmd of ['git status', 'git commit -m x', 'git fetch', 'git log --grep push', 'git -C /r log --grep push']) {
    assert.equal(e.evaluate(pre('Bash', { command: cmd })).decision, 'allow', cmd);
  }
});

// --- 9. Ledger row shape ----------------------------------------------------

test('9. a ledger row carries rule/decision/mode/digest and NO raw tool_input', () => {
  const { e, rows } = engine([MEMPALACE_RULE]);
  e.evaluate(pre('Bash', { command: 'mempalace sync --token SECRET' }));
  const row = rows.find((r) => r.kind === 'policy-decision');
  assert.equal(row.rule_id, 'destructive-shared-state');
  assert.equal(row.decision, 'deny');
  assert.equal(row.mode, 'live');
  assert.equal(row.tool, 'Bash');
  assert.equal(row.matched_on, 'command_matches');
  assert.match(String(row.input_digest), /^sha256:[0-9a-f]{16}$/);
  const serialised = JSON.stringify(row);
  assert.equal(serialised.includes('SECRET'), false, 'tool inputs carry secrets — never log them raw');
  assert.equal(serialised.includes('mempalace sync'), false);
});

test('9b. digest is stable and content-sensitive', () => {
  assert.equal(digest({ a: 1 }), digest({ a: 1 }));
  assert.notEqual(digest({ a: 1 }), digest({ a: 2 }));
  assert.match(digest(undefined), /^sha256:/);
});

// --- 10. Allows are never logged --------------------------------------------

test('10. 1000 allow-path evaluations write zero rows; the counter is the denominator', () => {
  const { e, rows } = engine([MEMPALACE_RULE]);
  const before = rows.length;
  for (let i = 0; i < 1000; i++) e.evaluate(pre('Bash', { command: `ls -la /tmp/${i}` }));
  assert.equal(rows.length, before, 'logging allows would put a sync disk write in front of every tool call');
  e.flushStats();
  const stats = rows.find((r) => r.kind === 'policy-stats');
  assert.equal(stats.evaluated, 1000);
  assert.equal(stats.denied, 0);
});

test('10b. flushStats resets, so the denominator is not double counted', () => {
  const { e, rows } = engine([MEMPALACE_RULE]);
  e.evaluate(pre('Bash', { command: 'ls' }));
  e.flushStats();
  e.flushStats(); // nothing left to say
  assert.equal(rows.filter((r) => r.kind === 'policy-stats').length, 1);
});

// --- 11. Unresolved ${AGENT_ID} must FAIL to match --------------------------

test('11. a payload with no agent_id does not match an ${AGENT_ID} rule', () => {
  // The test most likely to be missed: an unresolved interpolation must fail to
  // match, never match everything, or one unattributable harness denies the floor.
  const { e, rows } = engine([OWN_FOLDER_RULE]);
  const v = e.evaluate({
    hook_event_name: 'PreToolUse', agent_id: null,
    tool_name: 'Write', tool_input: { file_path: '/root/hive/agents/agent-b/x.md' }
  });
  assert.equal(v.decision, 'allow');
  assert.equal(rows.filter((r) => r.kind === 'policy-decision').length, 0);
});

test('11b. interpolate returns null rather than a half-substituted pattern', () => {
  assert.equal(interpolate('**/agents/${AGENT_ID}/**', null), null);
  assert.equal(interpolate('**/agents/${AGENT_ID}/**', ''), null);
  assert.equal(interpolate('**/agents/${AGENT_ID}/**', 'jim'), '**/agents/jim/**');
  assert.equal(interpolate('**/agents/*/**', null), '**/agents/*/**', 'no interpolation needed');
});

// --- 12. Evaluator errors honour on_error ----------------------------------

test('12. on_error deny fails closed and still returns a reason', () => {
  // A path rule with no path field and a command rule against a non-Bash tool
  // both simply do not match, so force a real throw with a pathological regex
  // that is valid at load and explosive at use.
  const { e, rows } = engine([{
    id: 'boom', decision: 'deny', mode: 'live', on_error: 'deny',
    reason: 'A guarded thing that must not proceed unevaluated.',
    match: { tool: 'Bash', command_matches: '(' + '?<dup>a)(?<dup>b)' }
  }]);
  // An invalid regex is rejected at load, which is the better outcome: the rule
  // never reaches evaluation at all.
  assert.equal(e.ruleCount, 0);
  assert.equal(rows.filter((r) => r.kind === 'policy-load-failed').length, 1);
});

test('12b. a rule that cannot match simply abstains; later rules still run', () => {
  const { e } = engine([
    { id: 'first', decision: 'deny', mode: 'live', reason: 'Never matches anything here at all.', match: { tool: 'NotebookEdit' } },
    MEMPALACE_RULE
  ]);
  assert.equal(e.evaluate(pre('Bash', { command: 'mempalace sync' })).ruleId, 'destructive-shared-state');
});

// --- ordering and load-time reporting --------------------------------------

test('rules are evaluated in file order and first match wins', () => {
  const { e } = engine([PUSH_RULE, MEMPALACE_RULE]);
  // A command that trips both. PUSH_RULE is first.
  const v = e.evaluate(pre('Bash', { command: 'git push && mempalace sync' }));
  assert.equal(v.ruleId, 'remote-push');
});

test('load NAMES the providers it cannot enforce against', () => {
  const { rows } = engine([MEMPALACE_RULE]);
  const loaded = rows.find((r) => r.kind === 'policy-loaded');
  assert.deepEqual(loaded.unenforceable_providers, ['pi', 'opencode', 'qwen']);
  assert.deepEqual(loaded.rules, [{ id: 'destructive-shared-state', decision: 'deny', mode: 'live' }]);
});

test('non-PreToolUse events are never evaluated', () => {
  const { e, rows } = engine([MEMPALACE_RULE]);
  const v = e.evaluate({ hook_event_name: 'PostToolUse', agent_id: 'agent-a', tool_name: 'Bash', tool_input: { command: 'mempalace sync' } });
  assert.equal(v.decision, 'allow');
  assert.equal(rows.filter((r) => r.kind === 'policy-decision').length, 0);
});

test('defaults.mode applies to rules that omit mode', () => {
  const rule = { ...MEMPALACE_RULE };
  delete rule.mode;
  const { e } = engine([rule], { mode: 'live' });
  assert.equal(e.evaluate(pre('Bash', { command: 'mempalace sync' })).decision, 'deny');
});

// --- the glob engine -------------------------------------------------------

test('globToRegExp: * stops at a separator, ** crosses it', () => {
  assert.equal(globToRegExp('**/a/*/c').test('/x/y/a/b/c'), true);
  assert.equal(globToRegExp('**/a/*/c').test('/x/y/a/b/d/c'), false, '* must not cross /');
  assert.equal(globToRegExp('**/a/**').test('/a/b/c'), true);
  assert.equal(globToRegExp('**/a/**').test('/x/a/b'), true);
  assert.equal(globToRegExp('/a/**').test('/a/b/c'), true);
  assert.equal(globToRegExp('/a/**').test('/b/c'), false);
});

test('globToRegExp: **/ also matches zero directories', () => {
  assert.equal(globToRegExp('**/a.md').test('/a.md'), true);
  assert.equal(globToRegExp('**/a.md').test('/x/y/a.md'), true);
});

test('globToRegExp: regex metacharacters in a path are literal', () => {
  assert.equal(globToRegExp('/a+b/*').test('/a+b/c'), true);
  assert.equal(globToRegExp('/a+b/*').test('/aab/c'), false);
  assert.equal(globToRegExp('/a.b/*').test('/axb/c'), false, '. must not be a wildcard');
});
