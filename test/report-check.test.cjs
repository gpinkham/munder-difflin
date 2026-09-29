'use strict';
/**
 * HAG-46 report check: a completion report that claims no failures is compared with
 * the agent's last recorded test outcome. Opt-in through the policy file; it never
 * blocks; it keeps one integer of test output and nothing else.
 *
 * Payload shapes are the ones Claude Code 2.1.284 actually sends (captured
 * 2026-09-29): a passing Bash call arrives on PostToolUse with tool_response.stdout
 * and no exit code; a failing one arrives on PostToolUseFailure with
 * error: "Exit code 1\n<output>".
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

const { testRunner, failCount, greenClaims, outcomeOf, ReportCheck, REPORT_CHECK_SENDER } = loadTs('src/main/reportCheck.ts');
const { PolicyEngine } = loadTs('src/main/policy.ts');
const { HiveManager } = loadTs('src/main/hive.ts');
const { HookServer } = loadTs('src/main/hooks.ts');

const RULE = { id: 'r', decision: 'deny', mode: 'dry_run', reason: 'a reason long enough', match: { tool: 'Bash', command_matches: '^never-matches-anything$' } };

const passed = (command, stdout) => ({
  hook_event_name: 'PostToolUse', agent_id: 'a', session_id: 's', tool_name: 'Bash',
  tool_input: { command }, tool_response: { stdout, stderr: '', interrupted: false, isImage: false }
});
const failed = (command, output) => ({
  hook_event_name: 'PostToolUseFailure', agent_id: 'a', session_id: 's', tool_name: 'Bash',
  tool_input: { command }, error: `Exit code 1\n${output}`, is_interrupt: false
});
const report = (body, extra) => ({ id: 'm1', from: 'a', to: 'god', act: 'inform', subject: 'Done', body, ...extra });

function checker(mode = 'dry_run') {
  const rows = [], notes = [];
  const rc = new ReportCheck({ mode }, (r) => rows.push(r), (subject, body) => notes.push({ subject, body }));
  return { rc, rows, notes };
}

// --- The pieces -----------------------------------------------------------------

test('a test run is recognised through wrappers, and a mention of one is not', () => {
  for (const [command, runner] of [
    ['npm test', 'npm test'], ['npm run test:unit', 'npm test'], ['cd /r && npm test', 'npm test'],
    ['node --test test/*.test.cjs', 'node --test'], ['npm test 2>&1 | tail -5', 'npm test'],
    ['bash -c "pytest -q"', 'pytest'], ['python3 -m pytest tests/', 'pytest'], ['npx vitest run', 'vitest'],
    ['jest --ci', 'jest'], ['go test ./...', 'go test'], ['cargo test', 'cargo test'], ['make test', 'make test'],
    // Launchers (Dwight, HAG-46 R4).
    ['uv run pytest -q', 'pytest'], ['poetry run pytest', 'pytest'], ['yarn jest', 'jest'], ['pnpm vitest run', 'vitest'],
    ['bun test', 'bun test'], ['npx playwright test', 'playwright test'], ['python -m unittest discover', 'unittest'],
    ['mvn test', 'mvn test'], ['./gradlew test', 'gradlew test'], ['pnpm exec vitest', 'vitest'],
  ]) assert.equal(testRunner(command), runner, command);
  for (const command of ['npm run build', 'echo npm test', 'grep -rn pytest .', 'node script.js', 'git commit -m "npm test"', 'make', 'go build ./...'])
    assert.equal(testRunner(command), null, command);
});

test('the failure count is read from the last summary line of each runner', () => {
  assert.equal(failCount('# tests 10\n# pass 7\n# fail 3\n'), 3);
  assert.equal(failCount('==== 2 failed, 40 passed in 3.1s ===='), 2);
  assert.equal(failCount('Tests:       1 failed, 9 passed, 10 total'), 1);
  assert.equal(failCount('  5 passing\n  4 failing'), 4);
  assert.equal(failCount('# fail 1\n...\n# fail 0'), 0, 'the last summary wins');
  assert.equal(failCount('all good'), null);
  assert.equal(failCount('failed to connect'), null, 'a word is not a count');
  // A captured log line is not a summary (Dwight, HAG-46 R3).
  assert.equal(failCount('retry: 3 failed attempts\n===== 10 passed in 2.0s ====='), null);
  assert.equal(failCount('retry: 3 failed attempts\n===== 1 failed, 9 passed in 2.0s ====='), 1);
});

test('a zero-failure claim is found; done, counts and "no new failures" are not claims', () => {
  for (const text of [
    'Done. Suite green.', 'All tests pass.', 'tests passing, 0 failures', 'no failures', 'Tests are green',
    'The suite passes.', 'Everything passes.', 'tests: all passed', '100% passing', '12 passed, 0 failed',
    'I did not touch the engine, and all tests pass.',
    // Dwight's recheck: real reports the modal list swallowed, and this office's own summary style.
    'I can confirm all tests pass.', 'I will note that all tests pass.', 'Once more: all tests pass.', '1126 tests, 0 fail', 'All green.',
  ]) assert.ok(greenClaims(text).length > 0, text);
  for (const text of [
    'Done.', 'Done: 1082 pass, 22 fail, same 22 as the baseline.', 'no new failures', 'Scan clean.',
    'The suite is not green yet.', 'Tests aren\'t passing.', 'Dwight wrote "all tests pass" in his report',
    'This is no longer green', 'green light from Gary',
    // This office's own vocabulary (Dwight, HAG-46 R2).
    'no fail-open rows were written', 'zero fail-opens in the ledger', 'no failed deliveries', '0 failed deliveries',
    'if all tests pass we ship', 'once the suite is green, push', 'we need all tests passing before merge',
    'Are all tests green?', 'Jim says all tests pass', 'the light is green',
  ]) assert.deepEqual(greenClaims(text), [], text);
});

test('outcomes come from the real payload shapes, with no content kept', () => {
  assert.deepEqual(pick(outcomeOf(failed('npm test', '# pass 5\n# fail 3'))), { runner: 'npm test', ok: false, failCount: 3 });
  assert.deepEqual(pick(outcomeOf(passed('node --test', '# pass 8\n# fail 0'))), { runner: 'node --test', ok: true, failCount: 0 });
  assert.deepEqual(pick(outcomeOf(passed('npm test | tail -3', '# fail 2'))), { runner: 'npm test', ok: false, failCount: 2 }, 'a pipe masks the exit, the count does not');
  assert.deepEqual(pick(outcomeOf(passed('npm test', 'ok'))), { runner: 'npm test', ok: true, failCount: null });
  assert.equal(outcomeOf({ ...failed('npm test', ''), is_interrupt: true }).ok, null, 'interrupted is unknown, not red');
  assert.equal(outcomeOf(passed('ls', 'x')), null);
  assert.equal(outcomeOf({ ...passed('npm test', 'x'), tool_name: 'Write' }), null);
});
const pick = (o) => o && { runner: o.runner, ok: o.ok, failCount: o.failCount };

// --- The check ------------------------------------------------------------------

test('a green claim after a red run is flagged as a contradiction', () => {
  const { rc, rows } = checker();
  rc.recordOutcome(failed('npm test', '# pass 40\n# fail 3'));
  assert.equal(rc.checkMessage(report('Suite green, 0 failures.')), 'contradicts');
  const flag = rows.find((r) => r.kind === 'report-check-flag');
  assert.equal(flag.verdict, 'contradicts');
  assert.equal(flag.fail_count, 3);
  assert.deepEqual(flag.claim_terms.sort(), ['0 failures', 'suite green'].sort().filter((t) => flag.claim_terms.includes(t)));
  assert.equal(flag.message_id, 'm1');
});

test('a red run fixed by a green run is not flagged', () => {
  const { rc, rows } = checker();
  rc.recordOutcome(failed('npm test', '# fail 3'));
  rc.recordOutcome(passed('npm test', '# fail 0'));
  assert.equal(rc.checkMessage(report('All tests pass.')), null);
  assert.equal(rows.filter((r) => r.kind === 'report-check-flag').length, 0);
});

test('an honest report on a known-red baseline is not flagged', () => {
  const { rc } = checker();
  rc.recordOutcome(failed('node --test test/*.test.cjs', '# pass 1082\n# fail 22'));
  assert.equal(rc.checkMessage(report('Done. 1082 pass, 22 fail: the same 22 as the baseline, no new failures.')), null);
});

test('a claim with no recorded run is logged as unsupported and nobody is told', () => {
  const { rc, rows, notes } = checker('live');
  assert.equal(rc.checkMessage(report('Tests pass.')), 'unsupported');
  assert.equal(rows[0].verdict, 'unsupported');
  assert.equal(notes.length, 0);
});

test('another agent\'s red run does not count against this one', () => {
  const { rc } = checker();
  rc.recordOutcome({ ...failed('npm test', '# fail 3'), agent_id: 'b' });
  rc.recordOutcome(passed('npm test', '# fail 0'));
  assert.equal(rc.checkMessage(report('All tests pass.')), null);
});

test('a new session starts a new window; a compaction or resume does not', () => {
  for (const [source, verdict] of [['startup', 'unsupported'], ['clear', 'unsupported'], ['compact', 'contradicts'], ['resume', 'contradicts']]) {
    const { rc } = checker();
    rc.recordOutcome(failed('npm test', '# fail 3'));
    rc.sessionStarted('a', source);
    assert.equal(rc.checkMessage(report('All tests pass.')), verdict, source);
  }
});

test('live mode tells god once per agent per 10 minutes; every flag is still a row', () => {
  const { rc, rows, notes } = checker('live');
  rc.recordOutcome(failed('npm test', '# fail 3'));
  const t0 = Date.parse('2026-09-29T12:00:00Z');
  rc.checkMessage(report('Suite green.'), t0);
  rc.checkMessage(report('All tests pass.'), t0 + 60_000);
  rc.checkMessage(report('Suite green.'), t0 + 11 * 60_000);
  assert.equal(notes.length, 2);
  assert.deepEqual(rows.filter((r) => r.kind === 'report-check-flag').map((r) => r.noted), [true, false, true]);
});

test('live mode tells god about a contradiction; dry_run never does', () => {
  for (const [mode, expected] of [['live', 1], ['dry_run', 0]]) {
    const { rc, notes } = checker(mode);
    rc.recordOutcome(failed('npm test', '# fail 3'));
    rc.checkMessage(report('Suite green.'));
    assert.equal(notes.length, expected, mode);
  }
  const { rc, notes } = checker('live');
  rc.recordOutcome(failed('npm test', '# fail 3'));
  rc.checkMessage(report('Suite green.'));
  assert.match(notes[0].subject, /3 failing/);
});

test('its own note to god is never checked, and a failing note never throws', () => {
  const rows = [];
  const rc = new ReportCheck({ mode: 'live' }, (r) => rows.push(r), () => { throw new Error('send failed'); });
  rc.recordOutcome(failed('npm test', '# fail 3'));
  assert.equal(rc.checkMessage(report('Suite green.', { from: REPORT_CHECK_SENDER })), null);
  assert.doesNotThrow(() => rc.checkMessage(report('Suite green.')));
});

test('no row carries test output or the message text', () => {
  const { rc, rows } = checker();
  rc.recordOutcome(failed('npm test -- --grep SECRET_ARG', 'SECRET_TEST_NAME failed\n# fail 1'));
  rc.checkMessage(report('Suite green. PRIVATE_BODY_TEXT'));
  const all = JSON.stringify(rows);
  assert.ok(!all.includes('SECRET_TEST_NAME'));
  assert.ok(!all.includes('PRIVATE_BODY_TEXT'));
  assert.ok(!all.includes('SECRET_ARG'), 'the command is kept as a digest only');
  assert.deepEqual(Object.keys(rows[0]).sort(), ['agent_id', 'fail_count', 'input_digest', 'kind', 'ok', 'runner', 'session_id']);
});

// --- The switch in the policy file ------------------------------------------------

function engineWith(body) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'md-rc-'));
  const rows = [];
  if (body !== null) {
    fs.mkdirSync(path.join(root, 'policy'));
    fs.writeFileSync(path.join(root, 'policy', 'engine.json'), JSON.stringify(body));
  }
  const e = new PolicyEngine(root, (r) => rows.push(r));
  e.load();
  return { e, rows };
}

test('the check is off unless the policy file turns it on', () => {
  assert.equal(engineWith(null).e.reportCheck, null, 'no policy file');
  const plain = engineWith({ version: 1, rules: [RULE] });
  assert.equal(plain.e.reportCheck, null, 'a policy without report_check');
  assert.equal('report_check' in plain.rows.find((r) => r.kind === 'policy-loaded'), false, 'and its load row is unchanged');
  assert.deepEqual(engineWith({ version: 1, rules: [RULE], report_check: { mode: 'live' } }).e.reportCheck, { mode: 'live' });
  assert.deepEqual(engineWith({ version: 1, defaults: { mode: 'dry_run' }, rules: [RULE], report_check: {} }).e.reportCheck, { mode: 'dry_run' });
});

test('a malformed report_check turns only the check off, and the rules still load', () => {
  // Dwight, HAG-46 R1: {mode:'LIVE'} used to unload every rule, so switching on an
  // observer could switch off the guardrail.
  for (const rc of [{ mode: 'LIVE' }, { mode: 'loud' }, 'on', true, null, []]) {
    const { e, rows } = engineWith({ version: 1, rules: [RULE], report_check: rc });
    assert.equal(e.ruleCount, 1, JSON.stringify(rc));
    assert.equal(e.error, null);
    assert.equal(e.reportCheck, null);
    assert.ok(rows.some((r) => r.kind === 'report-check-config-invalid'), JSON.stringify(rc));
    assert.equal(rows.some((r) => r.kind === 'policy-load-failed'), false);
  }
});

// --- Byte-identical when off ------------------------------------------------------

async function floor(t, policy) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'md-rc-floor-'));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  const hive = new HiveManager(() => home);
  if (policy !== null) {
    fs.mkdirSync(path.join(home, 'hive', 'policy'), { recursive: true });
    fs.writeFileSync(path.join(home, 'hive', 'policy', 'engine.json'), JSON.stringify(policy));
  }
  const server = new HookServer(hive, () => null, () => ({}), undefined, undefined);
  // Wired exactly as index.ts wires it.
  hive.setRoutedObserver((msg) => server.checkDelivered(msg));
  hive.setCaptureToolFailures(() => server.reportCheckActive());
  await hive.ensureAgent({ id: 'jim-1', name: 'Jim', provider: 'claude', cwd: home });
  const fire = (p) => server.handle({ session_id: 's1', ...p, agent_id: 'jim-1' });
  const settings = () => JSON.parse(fs.readFileSync(path.join(home, 'hive', 'agents', 'jim-1', 'settings.json'), 'utf8'));
  const log = () => { const f = path.join(home, 'hive', 'log.jsonl'); return fs.existsSync(f) ? fs.readFileSync(f, 'utf8') : ''; };
  const files = () => listAll(path.join(home, 'hive'));
  return { home, hive, server, fire, settings, log, files };
}
function listAll(dir) {
  const out = [];
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    out.push(p);
    if (e.isDirectory()) out.push(...listAll(p));
  }
  return out.sort();
}

async function exercise(f) {
  await f.fire({ hook_event_name: 'SessionStart' });
  await f.fire(failed('npm test', '# fail 3'));
  await f.fire(passed('node --test', '# fail 0'));
  f.hive.send({ to: 'god', act: 'inform', subject: 'Done', body: 'Suite green, 0 failures.' }, 'jim-1');
}

for (const [name, policy] of [['no policy file', null], ['a policy file without report_check', { version: 1, rules: [RULE] }]]) {
  test(`off (${name}): no extra hook, no rows, no files, no note to god`, async (t) => {
    const f = await floor(t, policy);
    assert.equal('PostToolUseFailure' in f.settings().hooks, false);
    const before = f.files();
    await exercise(f);
    assert.doesNotMatch(f.log(), /report-check/);
    const added = f.files().filter((p) => !before.includes(p));
    assert.deepEqual(added.filter((p) => /policy|report/.test(p)), [], 'no new policy or report files');
    assert.doesNotMatch(f.log(), /"from":"report-check"/);
  });
}

test('off: the settings file is byte-identical to one written before this feature', async (t) => {
  const f = await floor(t, null);
  const a = fs.readFileSync(path.join(f.home, 'hive', 'agents', 'jim-1', 'settings.json'), 'utf8');
  const bare = new HiveManager(() => f.home); // never told about the report check
  await bare.ensureAgent({ id: 'jim-1', name: 'Jim', provider: 'claude', cwd: f.home });
  const b = fs.readFileSync(path.join(f.home, 'hive', 'agents', 'jim-1', 'settings.json'), 'utf8');
  assert.equal(a, b);
  // And against the list as it stood before this feature, so a change that adds the
  // hook for everyone cannot pass by changing both sides of the comparison.
  assert.deepEqual(Object.keys(JSON.parse(a).hooks).sort(),
    ['Notification', 'PostCompact', 'PostToolUse', 'PreCompact', 'PreToolUse', 'SessionStart', 'Stop', 'SubagentStop', 'UserPromptSubmit']);
});

test('on (live): the failure hook is registered, outcomes are recorded and god is told', async (t) => {
  const f = await floor(t, { version: 1, rules: [RULE], report_check: { mode: 'live' } });
  assert.ok('PostToolUseFailure' in f.settings().hooks);
  await f.fire({ hook_event_name: 'SessionStart' });
  await f.fire(failed('npm test', '# fail 3'));
  f.hive.send({ to: 'god', act: 'inform', subject: 'Done', body: 'Suite green.' }, 'jim-1');
  const log = f.log();
  assert.match(log, /"kind":"report-check-outcome"/);
  assert.match(log, /"kind":"report-check-flag"[^\n]*"verdict":"contradicts"/);
  assert.match(log, /"from":"report-check","to":"god"/);
});
