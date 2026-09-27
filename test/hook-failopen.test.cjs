'use strict';

/**
 * The hook transport is fail-open by construction (see policy.ts's header): the
 * shim exits 0 — no stdout, which Claude reads as allow — when HIVE_SOCK is unset,
 * when the socket cannot be reached, and when the daemon does not answer in time.
 * That is deliberate and stays exactly as it is.
 *
 * What was NOT deliberate is that it happened SILENTLY. A floor reading the logs
 * could not tell "the engine evaluated this and allowed it" from "the engine was
 * never asked", because an allow writes no row either (policy.ts `record()` is
 * only reached on a deny/ask). md-220 spent a whole investigation on that
 * ambiguity: a day-job agent removed two colleagues' checkouts, nothing appeared
 * in the logs, and the absence was read as a false ALLOW when it was equally
 * consistent with the daemon never being asked.
 *
 * So each fail-open path now says why, and the ONLY thing these tests care about
 * beyond the row itself is that the exit code is still 0. Observability that can
 * turn a fail-open into a fail-closed would be worse than the silence it fixes.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const loadTs = require('./load-ts.cjs');

const { HiveManager } = loadTs('src/main/hive.ts');

const POSIX = process.platform !== 'win32';

/** A bootstrapped hive, so the shim under test is the one the app actually writes. */
async function hiveWithShim(t, prefix = 'md-failopen-') {
  // Short base: a UDS path is bounded by sun_path (~104 bytes on macOS).
  const base = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  t.after(() => fs.rmSync(base, { recursive: true, force: true }));
  const hive = new HiveManager(() => base);
  await hive.ensureAgent({ id: 'a1', name: 'A', provider: 'claude', cwd: base });
  const root = path.join(base, 'hive');
  return { base, root, shim: path.join(root, 'bin', 'cth-hook.cjs'), log: path.join(root, 'log.jsonl') };
}

/** Run the shim on Electron's bundled node, as the real hook command does. */
function runShim(shim, env, payload) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [shim], {
      env: { ...env, ELECTRON_RUN_AS_NODE: '1' },
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    let stdout = '', stderr = '';
    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.on('data', (d) => { stderr += d; });
    child.stdin.on('error', (e) => { if (e.code !== 'EPIPE') stderr += `stdin: ${e.message}\n`; });
    child.stdin.end(JSON.stringify(payload));
    child.on('close', (code) => resolve({ code, stdout, stderr }));
  });
}

const rowsIn = (log) => (fs.existsSync(log) ? fs.readFileSync(log, 'utf8').trim().split('\n') : [])
  .filter(Boolean).map((l) => JSON.parse(l));
const failopens = (log) => rowsIn(log).filter((r) => r.kind === 'policy-transport-failopen');

const CALL = { hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command: 'rm -rf x' } };

test('a fail-open with no HIVE_SOCK says so, and still allows', { skip: !POSIX }, async (t) => {
  const { root, shim, log } = await hiveWithShim(t);

  const res = await runShim(shim, { HIVE_ROOT: root, AGENT_ID: 'a1' }, CALL);

  assert.equal(res.code, 0, 'fail-open must stay fail-open');
  assert.equal(res.stdout, '', 'no stdout is how the shim says "allow"');
  const rows = failopens(log);
  assert.equal(rows.length, 1, `expected one fail-open row, got ${JSON.stringify(rows)}`);
  assert.equal(rows[0].reason, 'no_socket');
  assert.equal(rows[0].agent_id, 'a1');
  assert.equal(rows[0].tool, 'Bash');
  assert.equal(rows[0].hook_event, 'PreToolUse');
  assert.equal(typeof rows[0].ts, 'number', 'operators grep log.jsonl by ts');
});

test('a socket that cannot be reached says socket_error, and still allows', { skip: !POSIX }, async (t) => {
  const { root, shim, log } = await hiveWithShim(t);
  // A path with no listener: connect() fails rather than hanging.
  const sock = path.join(root, 'nobody-is-listening.sock');

  const res = await runShim(shim, { HIVE_ROOT: root, AGENT_ID: 'a1', HIVE_SOCK: sock }, CALL);

  assert.equal(res.code, 0, 'fail-open must stay fail-open');
  const rows = failopens(log);
  assert.equal(rows.length, 1, `expected one fail-open row, got ${JSON.stringify(rows)}`);
  assert.equal(rows[0].reason, 'socket_error');
  assert.equal(rows[0].agent_id, 'a1');
  assert.equal(rows[0].tool, 'Bash');
});

test('a daemon that never answers says timeout, and still allows', { skip: !POSIX }, async (t) => {
  const { root, shim, log } = await hiveWithShim(t);
  const sock = path.join(root, 'silent.sock');
  // Accepts the payload and deliberately never replies, so only the 5s arm fires:
  // no 'error' (we connected) and no 'end' (we never hang up).
  const held = [];
  const server = net.createServer((conn) => { held.push(conn); conn.on('error', () => {}); });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(sock, resolve); });
  t.after(() => { for (const c of held) c.destroy(); server.close(); });

  const res = await runShim(shim, { HIVE_ROOT: root, AGENT_ID: 'a1', HIVE_SOCK: sock }, CALL);

  assert.equal(res.code, 0, 'fail-open must stay fail-open');
  const rows = failopens(log);
  assert.equal(rows.length, 1, `expected one fail-open row, got ${JSON.stringify(rows)}`);
  assert.equal(rows[0].reason, 'timeout');
});

test('a daemon that answers is NOT a fail-open and records nothing', { skip: !POSIX }, async (t) => {
  const { root, shim, log } = await hiveWithShim(t);
  const sock = path.join(root, 'answers.sock');
  const server = net.createServer((conn) => {
    conn.on('error', () => {});
    conn.write(JSON.stringify({ hookSpecificOutput: { permissionDecision: 'allow' } }) + '\n', () => conn.end());
  });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(sock, resolve); });
  t.after(() => server.close());

  const res = await runShim(shim, { HIVE_ROOT: root, AGENT_ID: 'a1', HIVE_SOCK: sock }, CALL);

  assert.equal(res.code, 0);
  assert.equal(failopens(log).length, 0, 'a real round trip is not a fail-open');
  assert.match(res.stdout, /permissionDecision/, 'the daemon answer must still reach claude');
});

test('a log sink that cannot be written never changes the exit code', { skip: !POSIX }, async (t) => {
  const { base, shim } = await hiveWithShim(t);
  // HIVE_ROOT is a FILE, so appending <root>/log.jsonl throws ENOTDIR. The whole
  // point of the guarantee: the evidence is best effort, the exit code is not.
  const wedged = path.join(base, 'not-a-directory');
  fs.writeFileSync(wedged, 'x');

  const res = await runShim(shim, { HIVE_ROOT: wedged, AGENT_ID: 'a1' }, CALL);

  assert.equal(res.code, 0, 'a logging failure must never turn a fail-open into a block');
  assert.equal(res.stdout, '', 'and must never inject stdout that claude would read as a decision');
});

test('a fail-open with no HIVE_ROOT to log to still allows', { skip: !POSIX }, async (t) => {
  const { shim } = await hiveWithShim(t);

  const res = await runShim(shim, { AGENT_ID: 'a1' }, CALL);

  assert.equal(res.code, 0, 'nowhere to write is not a reason to block');
  assert.equal(res.stdout, '');
});
