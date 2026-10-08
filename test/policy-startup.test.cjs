'use strict';
/**
 * md-216: the guardrail engine rejected every rule on both floors, and the only
 * evidence was one log row written on the first tool call. These tests pin the
 * startup behaviour that replaces it: the policy loads when the hook server starts,
 * "rules loaded: N" is a log row and a status object, and a configured policy that
 * loaded nothing reaches god as a message.
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
  exports: { Notification: class { show() {} static isSupported() { return false; } } },
};

const { HiveManager } = loadTs('src/main/hive.ts');
const { HookServer, sanitizeWorkspaceRoots, DEFAULT_WORKSPACE_ROOTS } = loadTs('src/main/hooks.ts');

const HOOK_SCHEMA = {
  version: 1,
  rules: [{ id: 'cross-agent-write', mode: 'DRY_RUN', decision: 'deny', on_error: 'open', match: { kind: 'cross_agent_write' }, reason: 'owned' }],
};
const PACK = () => JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'examples/policy/engine.example.json'), 'utf8'));

async function floor(t, files, cfg = {}) {
  const home = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'md216-start-')));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  const hive = new HiveManager(() => home);
  await hive.ensureAgent({ id: 'god', name: 'God', provider: 'claude', cwd: home, isGod: true });
  await hive.ensureAgent({ id: 'jim-1', name: 'Jim', provider: 'claude', cwd: path.join(home, 'repo') });
  const dir = path.join(hive.root(), 'policy');
  fs.mkdirSync(dir, { recursive: true });
  for (const [name, body] of Object.entries(files)) fs.writeFileSync(path.join(dir, name), JSON.stringify(body));
  const server = new HookServer(hive, () => null, () => ({ harnessHome: home, ...cfg }), undefined, undefined);
  const logRows = () => fs.readFileSync(path.join(hive.root(), 'log.jsonl'), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
  const godInbox = () => fs.readdirSync(path.join(hive.root(), 'agents', 'god', 'inbox')).filter((f) => f.endsWith('.json'))
    .map((f) => JSON.parse(fs.readFileSync(path.join(hive.root(), 'agents', 'god', 'inbox', f), 'utf8')));
  return { home, hive, server, logRows, godInbox };
}

test('hook-schema authority.json alone: 0 rules, a status row, and god is told', async (t) => {
  const { server, logRows, godInbox } = await floor(t, { 'authority.json': HOOK_SCHEMA });
  server.announcePolicy();
  const status = logRows().find((r) => r.kind === 'policy-status');
  assert.equal(status.rules_loaded, 0);
  assert.match(status.error, /guardrail-hook schema/);
  const msg = godInbox().find((m) => /Guardrail policy failed to load/.test(m.subject));
  assert.ok(msg, 'the failure must reach god, not only log.jsonl');
  assert.equal(msg.from, 'guardrail');
  assert.equal(msg.requires_reply, false);
  const st = server.policyStatus();
  assert.equal(st.rulesLoaded, 0);
  assert.ok(st.error);
});

test('engine.json beside it: rules loaded 5, no message to god', async (t) => {
  const { server, logRows, godInbox } = await floor(t, { 'authority.json': HOOK_SCHEMA, 'engine.json': PACK() });
  server.announcePolicy();
  const status = logRows().find((r) => r.kind === 'policy-status');
  assert.equal(status.rules_loaded, 5);
  assert.equal(status.error, null);
  assert.equal(logRows().filter((r) => r.kind === 'policy-load-failed').length, 0);
  assert.equal(godInbox().filter((m) => /Guardrail/.test(m.subject)).length, 0);
  assert.deepEqual(server.policyStatus().ruleIds, ['cross-agent-write', 'cross-agent-workspace', 'destructive-shared-state', 'bitbucket-merge', 'remote-push']);
});

test('no policy at all: silent, as before', async (t) => {
  const { server, hive, godInbox } = await floor(t, {});
  fs.rmSync(path.join(hive.root(), 'policy'), { recursive: true, force: true });
  server.announcePolicy();
  const log = path.join(hive.root(), 'log.jsonl');
  const rows = fs.existsSync(log) ? fs.readFileSync(log, 'utf8') : '';
  assert.doesNotMatch(rows, /policy-status|policy-load-failed/);
  assert.equal(godInbox().filter((m) => /Guardrail/.test(m.subject)).length, 0);
  assert.equal(server.policyStatus().configured, false);
});

test('agentWorkspaces: cwd, hive folder and harness worktree for live agents only', async (t) => {
  const { server, hive, home } = await floor(t, {});
  await hive.ensureAgent({ id: 'old-1', name: 'Old', provider: 'claude', cwd: path.join(home, 'old') });
  hive.setArchived('old-1', true);
  const ws = server.agentWorkspaces();
  const jim = ws.find((w) => w.agentId === 'jim-1');
  assert.deepEqual(jim.roots, [
    path.join(home, 'repo'), path.join(hive.root(), 'agents', 'jim-1'),
    path.join(home, 'worktrees', 'jim-1'), path.join(home, 'code-worktrees', 'jim-1'),
  ]);
  assert.equal(ws.find((w) => w.agentId === 'old-1'), undefined, 'archived agents own nothing');
});

test('N1: an engine.json that parses but names no rules is a failure god hears about', async (t) => {
  for (const body of [{}, { rules: [] }, { rules: {} }]) {
    const { server, logRows, godInbox } = await floor(t, { 'engine.json': body });
    server.announcePolicy();
    const status = logRows().find((r) => r.kind === 'policy-status');
    assert.equal(status.rules_loaded, 0, JSON.stringify(body));
    assert.ok(status.error, `${JSON.stringify(body)}: error must be set`);
    assert.equal(godInbox().filter((m) => /Guardrail policy failed to load/.test(m.subject)).length, 1, JSON.stringify(body));
    assert.equal(server.policyStatus().error, status.error, 'fleet.json and the log say the same thing');
  }
});

// --- md-223: workspace roots are a config list, not a hardcoded path ----------------
//
// md-220: the day-job floor keeps most checkouts under <home>/code-worktrees/<agent-id>/,
// which no root covered, so `rm` inside a colleague's checkout there fired nothing. The
// fix is a list — each LIVE agent owns <home>/<root>/<its-id>/** for every configured
// root — and the safety of it is structural: the list is joined per live registry agent,
// never discovered from disk, so a directory named for anyone else is never considered.

/** The md-220 floor, shrunk: a shared repo cwd (like this floor) plus code-worktrees
 *  for a live colleague, for the caller, for an unknown id and for an archived agent. */
async function dayJobFloor(t, cfg) {
  const f = await floor(t, { 'engine.json': PACK() }, cfg);
  const { hive, home } = f;
  await hive.ensureAgent({ id: 'ryan-1', name: 'Ryan', provider: 'claude', cwd: path.join(home, 'repo') });
  await hive.ensureAgent({ id: 'old-1', name: 'Old', provider: 'claude', cwd: path.join(home, 'old') });
  hive.setArchived('old-1', true);
  const cw = (id, ...rest) => path.join(home, 'code-worktrees', id, ...rest);
  for (const id of ['ryan-1', 'jim-1', 'nobody-9', 'old-1']) fs.mkdirSync(cw(id, 'app'), { recursive: true });
  fs.writeFileSync(cw('ryan-1', 'app', '.DS_Store'), 'x');
  fs.mkdirSync(path.join(home, 'repo', 'md199-guardrail'), { recursive: true }); // a TASK-named worktree
  const asJim = (command) => f.server.policyEngine().evaluate({
    hook_event_name: 'PreToolUse', agent_id: 'jim-1', tool_name: 'Bash',
    tool_input: { command }, cwd: path.join(home, 'repo'),
  });
  return { ...f, cw, asJim };
}

test('md-223: removing a live colleague\'s code-worktree now fires', async (t) => {
  const { cw, asJim } = await dayJobFloor(t);
  const v = asJim(`rm -rf ${cw('ryan-1', 'app')}`);
  assert.equal(v.ruleId, 'cross-agent-workspace', 'the md-220 layout must be owned now');
  assert.equal(v.matchedOn, 'path_in_other_agent_workspace');
});

test('md-223: md-220 step 5 exactly — rm -f .DS_Store then rmdir — fires', async (t) => {
  const { cw, asJim } = await dayJobFloor(t);
  const dir = cw('ryan-1', 'app');
  assert.equal(asJim(`rm -f ${dir}/.DS_Store && rmdir ${dir}`).ruleId, 'cross-agent-workspace');
});

test('md-223: an unknown id under a root is NOT attributed (false-allow, never false-deny)', async (t) => {
  const { cw, asJim } = await dayJobFloor(t);
  assert.equal(asJim(`rm -rf ${cw('nobody-9', 'app')}`).ruleId, undefined,
    'a directory named for nobody live belongs to nobody');
});

test('md-223: a dead agent\'s leftovers are NOT attributed, so anyone may clean them up', async (t) => {
  const { cw, asJim } = await dayJobFloor(t);
  assert.equal(asJim(`rm -rf ${cw('old-1', 'app')}`).ruleId, undefined);
});

test('md-223: your own code-worktree is yours', async (t) => {
  const { cw, asJim } = await dayJobFloor(t);
  assert.equal(asJim(`rm -rf ${cw('jim-1', 'app')}`).ruleId, undefined);
});

test('md-223: a shared cwd is still nobody\'s, and a task-named worktree stays unowned (this floor: a no-op)',
  async (t) => {
    const { home, asJim, server } = await dayJobFloor(t);
    assert.equal(asJim(`echo x > ${path.join(home, 'repo', 'notes.md')}`).ruleId, undefined,
      'jim and ryan share repo/, so it is multi-owner and dropped');
    assert.equal(asJim(`rm -rf ${path.join(home, 'repo', 'md199-guardrail')}`).ruleId, undefined,
      'a task-named worktree carries no agent id, so the new roots attribute nothing here');
    // And structurally: every root the change adds is <home>/<root>/<a live id>.
    const added = server.agentWorkspaces().flatMap((w) => w.roots.map((r) => ({ id: w.agentId, r })))
      .filter(({ r }) => r.startsWith(path.join(home, 'code-worktrees') + path.sep));
    for (const { id, r } of added) assert.equal(r, path.join(home, 'code-worktrees', id));
  });

test('md-223: the configured list is honoured — replaced, not merged, and [] opts out', async (t) => {
  const only = await floor(t, {}, { workspaceRoots: ['code-worktrees'] });
  const jim = only.server.agentWorkspaces().find((w) => w.agentId === 'jim-1');
  assert.ok(jim.roots.includes(path.join(only.home, 'code-worktrees', 'jim-1')));
  assert.ok(!jim.roots.includes(path.join(only.home, 'worktrees', 'jim-1')), 'a set list REPLACES the default');

  const none = await floor(t, {}, { workspaceRoots: [] });
  const jim2 = none.server.agentWorkspaces().find((w) => w.agentId === 'jim-1');
  assert.deepEqual(jim2.roots, [path.join(none.home, 'repo'), path.join(none.hive.root(), 'agents', 'jim-1')],
    'an explicit empty list is an opt-out, not "use the default"');
});

test('md-223: a bad root is never joined — nothing outside the harness, nor the harness itself, becomes owned',
  async (t) => {
    const bad = ['..', '../elsewhere', 'a/../../b', '', '   ', '.', './', '/etc', 42, null];
    const { server, home } = await floor(t, {}, { workspaceRoots: [...bad, 'code-worktrees'] });
    for (const w of server.agentWorkspaces()) {
      for (const r of w.roots) {
        assert.ok(r === home || r.startsWith(home + path.sep), `${r} escapes the harness`);
        assert.notEqual(r, path.join(home, w.agentId), `${r}: a "." root would make <home>/<id> owned`);
      }
    }
    const jim = server.agentWorkspaces().find((w) => w.agentId === 'jim-1');
    assert.ok(jim.roots.includes(path.join(home, 'code-worktrees', 'jim-1')), 'the good entry survives its bad neighbours');
  });

test('md-223: sanitizeWorkspaceRoots — default, trim, dedupe, and a reason for every rejection', () => {
  assert.deepEqual(DEFAULT_WORKSPACE_ROOTS, ['worktrees', 'code-worktrees']);
  assert.deepEqual(sanitizeWorkspaceRoots(undefined), { roots: ['worktrees', 'code-worktrees'], rejected: [] });
  assert.deepEqual(sanitizeWorkspaceRoots([]), { roots: [], rejected: [] });
  assert.deepEqual(sanitizeWorkspaceRoots([' worktrees ', 'worktrees', './code-worktrees', 'a/b']).roots,
    ['worktrees', 'code-worktrees', 'a/b']);

  const { roots, rejected } = sanitizeWorkspaceRoots(['..', 'x/../y', '', '.', '/abs', 'C:\\w', 7, 'ok']);
  assert.deepEqual(roots, ['ok']);
  assert.equal(rejected.length, 7);
  for (const r of rejected) assert.equal(typeof r.why, 'string', `${JSON.stringify(r)} must say why`);

  // Not a list at all is a hand-edit mistake: keep the long-standing protection
  // (worktrees/ was hardcoded before this) and say so, rather than drop to nothing.
  // N2: '~' is not expanded here, so '~/code-worktrees' would own a literal "~" dir
  // (the #140 trap) and silently protect nothing. Refused, and named.
  const tilde = sanitizeWorkspaceRoots(['~/code-worktrees', '~', 'ok~']);
  assert.deepEqual(tilde.roots, ['ok~'], 'only a LEADING ~ is the trap');
  assert.deepEqual(tilde.rejected.map((r) => r.root), ['~/code-worktrees', '~']);
  for (const r of tilde.rejected) assert.match(r.why, /~/);

  const typo = sanitizeWorkspaceRoots('code-worktrees');
  assert.deepEqual(typo.roots, ['worktrees', 'code-worktrees']);
  assert.equal(typo.rejected.length, 1);
});

test('md-223: the startup status row says which roots are live and which were dropped', async (t) => {
  const { server, logRows } = await floor(t, { 'engine.json': PACK() }, { workspaceRoots: ['code-worktrees', '..', ''] });
  server.announcePolicy();
  const status = logRows().find((r) => r.kind === 'policy-status');
  assert.deepEqual(status.workspace_roots, ['code-worktrees']);
  assert.deepEqual(status.workspace_roots_rejected.map((r) => r.root), ['..', '']);
  assert.equal(status.rules_loaded, 5, 'a bad root never blocks the policy from loading');
});

test('md-223 N1: a forged registry id cannot steal a colleague\'s checkout or own outside the harness',
  async (t) => {
    // The id is the one false-DENY channel in this feature: it is joined as a path
    // segment, so a hand-edited registry.json can aim it anywhere. Dwight's probe I.
    const { hive, home, cw, asJim, server } = await dayJobFloor(t);
    const regPath = path.join(hive.root(), 'registry.json');
    const reg = JSON.parse(fs.readFileSync(regPath, 'utf8'));
    const elsewhere = path.join(home, 'elsewhere');
    for (const id of ['../code-worktrees/ryan-1/app', '../../../etc']) {
      reg.agents[id] = { id, name: 'Forged', provider: 'claude', cwd: elsewhere, status: 'idle', lastSeen: 0 };
    }
    fs.writeFileSync(regPath, JSON.stringify(reg));
    fs.mkdirSync(cw('ryan-1', 'webclient'), { recursive: true });

    // Direction 1 — false DENY: ryan working in his own checkout must not be flagged.
    const ryan = server.policyEngine().evaluate({
      hook_event_name: 'PreToolUse', agent_id: 'ryan-1', tool_name: 'Bash',
      tool_input: { command: `rm -rf ${cw('ryan-1', 'app')}` }, cwd: path.join(home, 'repo'),
    });
    assert.equal(ryan.ruleId, undefined, "ryan's own checkout must stay his");

    // Direction 2 — false ALLOW: ryan's root must survive, so the REST of his checkout
    // is still protected from jim.
    assert.equal(asJim(`rm -rf ${cw('ryan-1', 'webclient')}`).ruleId, 'cross-agent-workspace',
      "a forged id must not knock ryan's root out of ownedRoots");

    // And a forged id gets no id-derived root at all — only the cwd it registered.
    for (const w of server.agentWorkspaces().filter((x) => x.agentId.includes('..'))) {
      assert.deepEqual(w.roots, [elsewhere], `${w.agentId} must not join into a path`);
    }
  });

// --- md-136: the corpus flag, as the HARNESS wires it -------------------------------

const CORPUS = 'decision-corpus.jsonl';
const corpusPathIn = (hive) => path.join(hive.root(), 'policy', CORPUS);

/** A decision, through the server's own engine, so the config wiring is under test. */
function decide(server, hive, home) {
  fs.mkdirSync(path.join(home, 'wt', 'ryan-2'), { recursive: true });
  return server.policyEngine().evaluate({
    hook_event_name: 'PreToolUse', agent_id: 'jim-1', tool_name: 'Bash',
    tool_input: { command: `rm -rf ${path.join(hive.root(), 'agents', 'god')}/memory.md` },
    cwd: path.join(home, 'repo'),
  });
}

test('md-136: the corpus is ON without any config (Gary opted in), and local to the hive', async (t) => {
  const { server, hive, home } = await floor(t, { 'engine.json': PACK() });
  const v = decide(server, hive, home);
  assert.ok(v.ruleId, 'precondition: a rule must fire for there to be a record');
  const rows = fs.readFileSync(corpusPathIn(hive), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
  assert.equal(rows.length, 1);
  assert.equal(rows[0].kind, 'policy-decision-corpus');
  assert.ok(rows[0].input_digest, 'the join key back to the audit row');
});

test('md-136: decisionCorpus:false turns it off with no restart and leaves no file', async (t) => {
  const { server, hive, home } = await floor(t, { 'engine.json': PACK() }, { decisionCorpus: false });
  assert.ok(decide(server, hive, home).ruleId);
  assert.equal(fs.existsSync(corpusPathIn(hive)), false);
});

// Dwight L1 on the upstream-main merge: upstream's socket code binds asynchronously and
// may never succeed (no root yet, or a stranger owns the path). The status row and the
// "failed to load" message to god must not wait for a bind; they come from start(),
// once per app run, and a later re-bind does not repeat them.
test('start() announces the policy even when the socket never binds, and only once', async (t) => {
  const { hive, server, logRows, godInbox } = await floor(t, { 'authority.json': HOOK_SCHEMA });
  // A path no socket can be bound at: its directory is a file.
  const blocker = path.join(hive.root(), 'not-a-dir');
  fs.writeFileSync(blocker, 'x');
  hive.sockPath = () => path.join(blocker, 'hooks.sock');
  server.start();
  t.after(() => server.stop());
  assert.equal(logRows().filter((r) => r.kind === 'policy-status').length, 1, 'written at start, before any bind');
  assert.equal(godInbox().filter((m) => /Guardrail policy failed to load/.test(m.subject)).length, 1);
  await new Promise((r) => setTimeout(r, 50));
  server.start();
  assert.equal(logRows().filter((r) => r.kind === 'policy-status').length, 1, 'not repeated');
});

// Dwight on acc0e860: announceOnce runs inside start() and inside bind(); a throw there
// would escape start() or reject the bind. It must swallow and log instead.
test('announceOnce never throws, even when the hive cannot answer', async (t) => {
  const { hive, server } = await floor(t, { 'authority.json': HOOK_SCHEMA });
  hive.root = () => { throw new Error('boom'); };
  hive.sockPath = () => null;
  assert.doesNotThrow(() => server.start());
  t.after(() => server.stop());
});
