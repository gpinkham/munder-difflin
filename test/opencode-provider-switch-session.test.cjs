'use strict';
/* An agent switched from Claude to OpenCode kept its Claude session id: the
 * registry upsert spreads the previous entry, so sessionId and sessionHistory
 * survived the provider change, startup restore resumed with them, and
 * OpenCode refused `opencode --session <uuid>` (its ids start with ses_).
 * A synthetic registry in a throwaway home; no app, no real hive. */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const loadTs = require('./load-ts.cjs');

const { HiveManager } = loadTs('src/main/hive.ts');

const CLAUDE_SID = '3a71c769-245e-423b-915a-f107a5b82b40';
const OLDER_CLAUDE_SID = '9c0d1e2f-3a4b-4c5d-8e6f-708192a3b4c5';

function hiveIn(t) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'md-provider-switch-'));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  return new HiveManager(() => home);
}

test('switching an agent from Claude to OpenCode drops the Claude session ids', async (t) => {
  const hive = hiveIn(t);
  await hive.ensureAgent({ id: 'orchestrator-1', name: 'Orchestrator', provider: 'claude', cwd: os.tmpdir() });
  hive.recordSession('orchestrator-1', OLDER_CLAUDE_SID);
  hive.recordSession('orchestrator-1', CLAUDE_SID);
  assert.deepEqual(hive.resumeCandidates('orchestrator-1'), [CLAUDE_SID, OLDER_CLAUDE_SID]);

  await hive.ensureAgent({ id: 'orchestrator-1', name: 'Orchestrator', provider: 'opencode', cwd: os.tmpdir() });
  assert.deepEqual(hive.resumeCandidates('orchestrator-1'), [], 'nothing of Claude is left for startup restore to pass to opencode --session');
  assert.equal(hive.lastSession('orchestrator-1'), undefined);
});

test('a respawn on the same provider keeps its session ids', async (t) => {
  const hive = hiveIn(t);
  await hive.ensureAgent({ id: 'worker-a', name: 'Worker', provider: 'claude', cwd: os.tmpdir() });
  hive.recordSession('worker-a', CLAUDE_SID);
  await hive.ensureAgent({ id: 'worker-a', name: 'Worker', provider: 'claude', cwd: os.tmpdir() });
  assert.deepEqual(hive.resumeCandidates('worker-a'), [CLAUDE_SID]);
  // A spawn that does not say its provider changes nothing.
  await hive.ensureAgent({ id: 'worker-a', name: 'Worker', cwd: os.tmpdir() });
  assert.deepEqual(hive.resumeCandidates('worker-a'), [CLAUDE_SID]);
});

test('an entry from before providers were recorded counts as Claude', async (t) => {
  const hive = hiveIn(t);
  await hive.ensureAgent({ id: 'old-1', name: 'Old', cwd: os.tmpdir() });
  hive.recordSession('old-1', CLAUDE_SID);
  await hive.ensureAgent({ id: 'old-1', name: 'Old', provider: 'claude', cwd: os.tmpdir() });
  assert.deepEqual(hive.resumeCandidates('old-1'), [CLAUDE_SID], 'claude after no provider is the same provider');
  await hive.ensureAgent({ id: 'old-1', name: 'Old', provider: 'opencode', cwd: os.tmpdir() });
  assert.deepEqual(hive.resumeCandidates('old-1'), []);
});
