'use strict';
/**
 * The day-job branch runs the redacted decision corpus (md-136) beside the report
 * check (HAG-46), the prompt alert and one-action grants (HAG-49). Those add ledger
 * rows that carry values: a failed run's output, a report's words, a grant's target.
 * The corpus must stay a whitelist: one record per policy DECISION, built field by
 * field, so none of the new rows — and none of their values — can reach it.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const loadTs = require('./load-ts.cjs');

const electron = require.resolve('electron');
require.cache[electron] = {
  id: electron, filename: electron, loaded: true,
  exports: { Notification: class { show() {} static isSupported() { return false; } } }
};
const { HiveManager } = loadTs('src/main/hive.ts');
const { HookServer } = loadTs('src/main/hooks.ts');
const { GrantStore } = loadTs('src/main/grants.ts');

const SHA = '270d83f1c2c5572d4eec1d66819c64168ecd7a61';
const SECRETS = ['SECRET_RUN_OUTPUT', 'SECRET_REPORT_BODY', 'SECRET_REASON', 'secret-branch-name', SHA, 'evil.example', 'g_'];
const PUSH_RULE = {
  id: 'remote-push', decision: 'ask', mode: 'live', reason: 'Pushing is the operator\'s call.',
  grantable: ['git-push'], match: { tool: 'Bash', command_matches: '^git(?:\\s+-C\\s+\\S+)*\\s+push\\b' },
};
const DENY_RULE = { id: 'no-rm', decision: 'deny', mode: 'live', reason: 'no rm of that', match: { tool: 'Bash', command_matches: '^rm\\s' } };

async function floor(t, config) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'md-dayjob-'));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  const repo = path.join(home, 'repo');
  execFileSync('git', ['init', '-q', repo]);
  execFileSync('git', ['-C', repo, 'remote', 'add', 'origin', 'https://evil.example/o/r.git']);
  const hive = new HiveManager(() => home);
  fs.mkdirSync(path.join(home, 'hive', 'policy'), { recursive: true });
  fs.writeFileSync(path.join(home, 'hive', 'policy', 'engine.json'),
    JSON.stringify({ version: 1, rules: [DENY_RULE, PUSH_RULE], report_check: { mode: 'live' } }));
  const server = new HookServer(hive, () => null, () => config, undefined, undefined);
  hive.setRoutedObserver((msg) => server.checkDelivered(msg));
  hive.setApprovalHandler((id, msg) => server.handleApprovalRequest(id, msg));
  await hive.ensureAgent({ id: 'god-1', name: 'God', provider: 'claude', cwd: home, isGod: true });
  await hive.ensureAgent({ id: 'jim-1', name: 'Jim', provider: 'claude', cwd: repo });
  const fire = (p) => server.handle({ session_id: 's1', cwd: repo, ...p, agent_id: 'jim-1' });
  const corpusFile = path.join(home, 'hive', 'policy', 'decision-corpus.jsonl');
  const corpus = () => (fs.existsSync(corpusFile) ? fs.readFileSync(corpusFile, 'utf8') : '');
  return { home, hive, server, fire, repo, corpus, corpusFile };
}

/** Every new row kind, each carrying a value the corpus must never hold. */
async function exercise(f) {
  const push = `git push origin ${SHA}:refs/heads/secret-branch-name`;
  await f.fire({ hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command: 'rm -rf /tmp/x' } });           // deny
  await f.fire({ hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command: push } });                     // ask
  await f.fire({ hook_event_name: 'Notification', notification_type: 'permission_prompt', message: 'Claude needs your permission' }); // prompt alert
  await f.fire({ hook_event_name: 'PostToolUseFailure', tool_name: 'Bash', tool_input: { command: 'npm test' }, error: 'Exit code 1\nSECRET_RUN_OUTPUT\n# fail 2' });
  f.hive.send({ to: 'god', act: 'inform', subject: 'Done', body: 'Suite green. SECRET_REPORT_BODY' }, 'jim-1');  // report-check flag
  fs.writeFileSync(path.join(f.home, 'hive', 'agents', 'jim-1', 'outbox', 'req.json'),
    JSON.stringify({ to: 'god', act: 'approval-request', command: push, cwd: f.repo, reason: 'SECRET_REASON' }));
  f.hive.routeOnce();                                                                                                    // grant-requested
  const [req] = f.server.pendingGrants();
  f.server.decideGrant(req.id, true);                                                                                    // grant-decided
  await f.fire({ hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command: push } });                     // allow by grant
}

test('with the corpus on, only policy decisions reach it, and no new row kind or value does', async (t) => {
  const f = await floor(t, {}); // decisionCorpus unset = ON, as Gary decided
  await exercise(f);
  const rows = f.corpus().trim().split('\n').map((l) => JSON.parse(l));
  assert.deepEqual([...new Set(rows.map((r) => r.kind))], ['policy-decision-corpus']);
  assert.deepEqual(rows.map((r) => r.decision), ['deny', 'ask', 'allow']);
  const log = fs.readFileSync(path.join(f.home, 'hive', 'log.jsonl'), 'utf8');
  for (const kind of ['report-check-outcome', 'report-check-flag', 'policy-prompt-waiting', 'grant-requested', 'grant-decided'])
    assert.match(log, new RegExp(`"kind":"${kind}"`), `${kind} was written to the ledger, so the test exercised it`);
  for (const s of SECRETS) assert.ok(!f.corpus().includes(s), `corpus leaked ${s}`);
});

test('a push allowed by a grant is recorded as granted, without the grant or its target', async (t) => {
  const f = await floor(t, {});
  await exercise(f);
  const rows = f.corpus().trim().split('\n').map((l) => JSON.parse(l));
  const granted = rows.find((r) => r.decision === 'allow');
  assert.equal(granted.granted, true);
  assert.equal(granted.rule_id, 'remote-push');
  assert.equal(rows.find((r) => r.decision === 'ask').granted, false);
  assert.ok(!('grant_id' in granted));
  assert.equal(new GrantStore(path.join(f.home, 'hive', 'policy', 'grants.jsonl')).findUsable('jim-1', { class: 'git-push', target: { remote_url: 'https://evil.example/o/r.git', ref: 'refs/heads/secret-branch-name', sha: SHA } }) !== null, true, 'the grant itself is intact');
});

test('decisionCorpus: false writes no corpus, and the new features still run', async (t) => {
  const f = await floor(t, { decisionCorpus: false });
  await exercise(f);
  assert.equal(fs.existsSync(f.corpusFile), false);
  assert.match(fs.readFileSync(path.join(f.home, 'hive', 'log.jsonl'), 'utf8'), /"kind":"report-check-flag"/);
});
