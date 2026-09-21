'use strict';

/*
 * md-146 Phase 1 — render layer, sentinels, notice, reconcile.
 *
 * The sentinel branch table gets the most cases here on purpose: it is the one
 * piece where a wrong answer eats an agent's accumulated memory rather than just
 * failing a feature.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const loadTs = require('./load-ts.cjs');

const { RulesManager, applyBlock, findSentinels, RULE_CAPS } = loadTs('src/main/rules.ts');

const BEGIN = '<!-- BEGIN managed rules · rev 3 · 2026-09-21 · x -->';
const END = '<!-- END managed rules -->';
const PINNED = '## 📌 Durable facts (pinned — never condensed)';

/** A throwaway harnessHome with a hive, some agents, and optionally a rules store. */
function home(opts = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'md-rules-'));
  const agents = opts.agents ?? ['jim', 'pam', 'god'];
  for (const id of agents) {
    fs.mkdirSync(path.join(root, 'hive', 'agents', id), { recursive: true });
    fs.writeFileSync(path.join(root, 'hive', 'agents', id, 'memory.md'),
      opts.memory ?? `# Memory — ${id}\n\n${PINNED}\n\nExisting fact one.\nExisting fact two.\n\n## Recent\n\n## a section\nbody\n`);
  }
  if (opts.store !== null) {
    fs.mkdirSync(path.join(root, 'hive', 'policy'), { recursive: true });
    fs.writeFileSync(path.join(root, 'hive', 'policy', 'rules.json'),
      typeof opts.store === 'string' ? opts.store : JSON.stringify(opts.store ?? defaultStore()));
  }
  return root;
}

const defaultStore = () => ({
  rev: 3,
  rules: [
    { id: 'own-folder', text: 'Write only to your own folder.', scope: { kind: 'global' }, status: 'active' },
    { id: 'jim-only', text: 'Jim-specific rule.', scope: { kind: 'agents', ids: ['jim'] }, status: 'active' },
    { id: 'gone', text: 'A retired rule.', scope: { kind: 'global' }, status: 'retired' }
  ]
});

function mgr(root) {
  const rows = [];
  const m = new RulesManager(() => root, (r) => rows.push(r));
  return { m, rows };
}
const read = (root, id) => fs.readFileSync(path.join(root, 'hive', 'agents', id, 'memory.md'), 'utf8');

// --- dormancy: the mergeability property ----------------------------------

test('dormant with no rules store: nothing rendered, nothing logged', async () => {
  const root = home({ store: null });
  const { m, rows } = mgr(root);
  assert.equal(m.active, false);
  const before = read(root, 'jim');
  assert.deepEqual(await m.renderAll(), []);
  assert.equal(await m.takeNotice('jim'), null);
  assert.deepEqual(await m.reconcile(), { checked: 0, repaired: [], aborted: [] });
  assert.equal(read(root, 'jim'), before, 'an unconfigured install must not touch a byte');
  assert.equal(rows.length, 0);
});

test('a malformed store renders nothing and logs it', async () => {
  const root = home({ store: '{ not json' });
  const { m, rows } = mgr(root);
  const before = read(root, 'jim');
  const out = await m.renderFor('jim');
  assert.equal(out.ok, false);
  assert.equal(read(root, 'jim'), before);
  assert.equal(rows.filter((r) => r.kind === 'rules-load-failed').length, 1);
});

// --- the sentinel branch table --------------------------------------------

test('sentinels: BOTH present and in order -> replace between them', () => {
  const text = ['# t', PINNED, '', BEGIN, 'stale line', END, '', 'KEEP ME'].join('\n');
  const r = applyBlock(text, 'NEW-A\nNEW-B');
  assert.equal(r.ok, true);
  assert.equal(r.action, 'replaced');
  assert.match(r.text, /NEW-A\nNEW-B/);
  assert.equal(r.text.includes('stale line'), false);
  assert.match(r.text, /KEEP ME/, 'content after the block must survive');
  assert.match(r.text, /Durable facts/, 'content before the block must survive');
});

test('sentinels: NEITHER present -> insert right after the pinned header', () => {
  const text = ['# t', '', PINNED, '', 'Existing fact.', '', '## Recent'].join('\n');
  const r = applyBlock(text, 'BLOCK');
  assert.equal(r.ok, true);
  assert.equal(r.action, 'inserted');
  const lines = r.text.split('\n');
  const hi = lines.findIndex((l) => l.startsWith('## 📌'));
  assert.ok(lines.slice(hi, hi + 4).includes('BLOCK'), 'block must land immediately under the header');
  assert.match(r.text, /Existing fact\./);
});

test('sentinels: EXACTLY ONE -> abort and touch nothing', () => {
  const onlyBegin = ['# t', PINNED, BEGIN, 'orphan'].join('\n');
  const onlyEnd = ['# t', PINNED, 'orphan', END].join('\n');
  assert.deepEqual(applyBlock(onlyBegin, 'X'), { ok: false, reason: 'sentinel-end-missing' });
  assert.deepEqual(applyBlock(onlyEnd, 'X'), { ok: false, reason: 'sentinel-begin-missing' });
});

test('sentinels: OUT OF ORDER -> abort', () => {
  const text = ['# t', PINNED, END, 'inverted', BEGIN].join('\n');
  assert.deepEqual(applyBlock(text, 'X'), { ok: false, reason: 'sentinels-out-of-order' });
});

test('sentinels: no pinned region at all -> the header is created', () => {
  const text = ['# Memory', '', 'preamble line', '', '## Recent', 'stuff'].join('\n');
  const r = applyBlock(text, 'BLOCK');
  assert.equal(r.ok, true);
  const lines = r.text.split('\n');
  assert.ok(lines.some((l) => l.startsWith('## 📌')));
  assert.ok(lines.indexOf('BLOCK') < lines.indexOf('## Recent'), 'block must be inside the pinned region, not after history');
  assert.match(r.text, /preamble line/);
});

test('findSentinels reads the rev out of the BEGIN marker', () => {
  assert.equal(findSentinels([BEGIN, END]).rev, 3);
  assert.equal(findSentinels(['<!-- BEGIN managed rules -->', END]).rev, null);
  assert.equal(findSentinels(['nothing']).begin, -1);
});

// --- render: scope, tombstones, god --------------------------------------

test('render: global rules reach everyone, scoped rules only their agent', async () => {
  const root = home();
  const { m } = mgr(root);
  await m.renderAll();
  assert.match(read(root, 'jim'), /Write only to your own folder\./);
  assert.match(read(root, 'jim'), /Jim-specific rule\./);
  assert.match(read(root, 'pam'), /Write only to your own folder\./);
  assert.equal(read(root, 'pam').includes('Jim-specific rule.'), false);
});

test('render: a retired rule is a tombstone - kept in the store, rendered nowhere', async () => {
  const root = home();
  const { m } = mgr(root);
  await m.renderFor('jim');
  assert.equal(read(root, 'jim').includes('A retired rule.'), false);
  const store = JSON.parse(fs.readFileSync(path.join(root, 'hive', 'policy', 'rules.json'), 'utf8'));
  assert.ok(store.rules.some((r) => r.id === 'gone'), 'the tombstone stays in the store');
});

test('render: GOD is included - no isGod exclusion (md-140)', async () => {
  const root = home();
  const { m } = mgr(root);
  const out = await m.renderFor('god');
  assert.equal(out.ok, true);
  assert.match(read(root, 'god'), /Write only to your own folder\./);
  assert.match(read(root, 'god'), /BEGIN managed rules/);
});

test('render: the block lands INSIDE the pinned region, above the other sections', async () => {
  const root = home();
  const { m } = mgr(root);
  await m.renderFor('jim');
  const lines = read(root, 'jim').split('\n');
  const pinnedAt = lines.findIndex((l) => l.startsWith('## 📌'));
  const beginAt = lines.findIndex((l) => l.includes('BEGIN managed rules'));
  const recentAt = lines.findIndex((l) => l.trim() === '## Recent');
  assert.ok(pinnedAt < beginAt && beginAt < recentAt);
  assert.match(read(root, 'jim'), /Existing fact one\./, 'pre-existing facts survive');
});

test('render is idempotent: a second pass changes nothing', async () => {
  const root = home();
  const { m } = mgr(root);
  await m.renderFor('jim');
  const once = read(root, 'jim');
  const out = await m.renderFor('jim');
  assert.equal(out.ok, true);
  // Same rev, same rules: replacing the block reproduces the same bytes.
  assert.equal(read(root, 'jim'), once);
});

test('render never touches content outside the sentinels, across a rev bump', async () => {
  const root = home();
  const { m } = mgr(root);
  await m.renderFor('jim');
  const storePath = path.join(root, 'hive', 'policy', 'rules.json');
  const store = JSON.parse(fs.readFileSync(storePath, 'utf8'));
  store.rev = 4;
  store.rules[0].text = 'Write only to your own folder. Use your outbox.';
  fs.writeFileSync(storePath, JSON.stringify(store));
  await m.renderFor('jim');
  const after = read(root, 'jim');
  assert.match(after, /rev 4/);
  assert.match(after, /Use your outbox\./);
  assert.match(after, /Existing fact one\./);
  assert.match(after, /Existing fact two\./);
  assert.match(after, /## a section\nbody/);
  assert.equal(after.includes('rev 3'), false, 'the stale block is gone, not duplicated');
  assert.equal((after.match(/BEGIN managed rules/g) || []).length, 1, 'exactly one managed block');
});

test('render ABORTS on a damaged file and leaves it byte-identical', async () => {
  const root = home({ memory: ['# t', PINNED, BEGIN, 'half-marked'].join('\n') });
  const { m, rows } = mgr(root);
  const before = read(root, 'jim');
  const out = await m.renderFor('jim');
  assert.equal(out.ok, false);
  assert.equal(out.reason, 'sentinel-end-missing');
  assert.equal(read(root, 'jim'), before, 'a half-marked file must not be guessed at');
  assert.ok(rows.some((r) => r.kind === 'rules-render-aborted'));
});

// --- the agent-knows notice ---------------------------------------------

test('notice: first delivery announces the set, and fires only once per rev', async () => {
  const root = home();
  const { m } = mgr(root);
  const first = m.takeNotice('jim');
  assert.match(first, /RULES ACTIVE — rev 3/);
  assert.match(first, /2 rule\(s\) apply to you/);
  assert.match(first, /already there/);
  assert.equal(m.takeNotice('jim'), null, 'no re-delivery at the same rev');
  assert.equal(m.deliveredRev('jim'), 3);
});

test('notice: a rev bump produces a DIFF, not the whole set', async () => {
  const root = home();
  const { m } = mgr(root);
  m.takeNotice('jim');
  const storePath = path.join(root, 'hive', 'policy', 'rules.json');
  const store = JSON.parse(fs.readFileSync(storePath, 'utf8'));
  store.rev = 4;
  store.rules[1].text = 'Jim-specific rule, reworded.';                       // ~
  store.rules.push({ id: 'fresh', text: 'A brand new rule.', scope: { kind: 'global' }, status: 'active' }); // +
  fs.writeFileSync(storePath, JSON.stringify(store));

  const n = m.takeNotice('jim');
  assert.match(n, /RULES UPDATED — rev 3 → 4/);
  assert.match(n, /\[\+\] A brand new rule\./);
  assert.match(n, /\[~\] Jim-specific rule, reworded\./);
  assert.equal(n.includes('[+] Write only to your own folder.'), false, 'an unchanged rule is not re-announced');
});

test('notice: a retired rule shows as [-] using its tombstone text', async () => {
  const root = home();
  const { m } = mgr(root);
  m.takeNotice('jim');
  const storePath = path.join(root, 'hive', 'policy', 'rules.json');
  const store = JSON.parse(fs.readFileSync(storePath, 'utf8'));
  store.rev = 5;
  store.rules[1].status = 'retired';
  fs.writeFileSync(storePath, JSON.stringify(store));
  const n = m.takeNotice('jim');
  assert.match(n, /\[-\] Jim-specific rule\. \(retired/);
});

test('notice: a rev bump that changes nothing for THIS agent stays silent', async () => {
  const root = home();
  const { m, rows } = mgr(root);
  m.takeNotice('pam');
  const storePath = path.join(root, 'hive', 'policy', 'rules.json');
  const store = JSON.parse(fs.readFileSync(storePath, 'utf8'));
  store.rev = 9;
  store.rules[1].text = 'Jim-specific rule, changed — pam cannot see this.';
  fs.writeFileSync(storePath, JSON.stringify(store));
  assert.equal(m.takeNotice('pam'), null, 'a notice that says nothing trains agents to skip notices');
  assert.equal(m.deliveredRev('pam'), 9, 'but the rev is still recorded so it does not re-check forever');
  assert.ok(rows.some((r) => r.kind === 'rules-delivery' && r.notified === false));
});

test('notice: delivery state is on DISK, so a restart neither re-spams nor skips', async () => {
  const root = home();
  const a = mgr(root);
  a.m.takeNotice('jim');
  const b = mgr(root); // a fresh manager stands in for an app restart
  assert.equal(b.m.takeNotice('jim'), null, 'a restart must not re-send the same rev');
  assert.equal(b.m.deliveredRev('jim'), 3);
  assert.ok(fs.existsSync(path.join(root, 'hive', 'policy', 'rules-delivery.json')));
});

test('notice: every injection appends an auditable delivery row', async () => {
  const root = home();
  const { m, rows } = mgr(root);
  m.takeNotice('jim');
  const row = rows.find((r) => r.kind === 'rules-delivery');
  assert.equal(row.agentId, 'jim');
  assert.equal(row.rev, 3);
  assert.equal(row.notified, true);
});

// --- reconcile: the self-healing backstop -------------------------------

test('reconcile: re-renders a file whose rendered rev is behind the store', async () => {
  const root = home();
  const { m } = mgr(root);
  await m.renderAll();
  const storePath = path.join(root, 'hive', 'policy', 'rules.json');
  const store = JSON.parse(fs.readFileSync(storePath, 'utf8'));
  store.rev = 7;
  fs.writeFileSync(storePath, JSON.stringify(store));

  const r = await m.reconcile();
  assert.deepEqual(r.repaired.sort(), ['god', 'jim', 'pam']);
  assert.match(read(root, 'jim'), /rev 7/);
});

test('reconcile: heals a block a condense DROPPED entirely', async () => {
  const root = home();
  const { m } = mgr(root);
  await m.renderFor('jim');
  // Simulate the condenser rebuilding the pinned region and losing the block.
  const stripped = read(root, 'jim').split('\n')
    .filter((l) => !l.includes('managed rules') && !l.includes('Authority rules') && !l.startsWith('(1)') && !l.startsWith('(2)') && !l.includes('FAILSAFE'))
    .join('\n');
  fs.writeFileSync(path.join(root, 'hive', 'agents', 'jim', 'memory.md'), stripped);
  assert.equal(read(root, 'jim').includes('BEGIN managed rules'), false);

  const r = await m.reconcile();
  assert.ok(r.repaired.includes('jim'));
  assert.match(read(root, 'jim'), /BEGIN managed rules/);
  assert.match(read(root, 'jim'), /Write only to your own folder\./);
});

test('reconcile: leaves an already-current file untouched', async () => {
  const root = home();
  const { m } = mgr(root);
  await m.renderAll();
  const before = read(root, 'jim');
  const r = await m.reconcile();
  assert.deepEqual(r.repaired, []);
  assert.equal(read(root, 'jim'), before);
});

test('reconcile: reports a damaged file instead of repairing it', async () => {
  const root = home();
  const { m, rows } = mgr(root);
  await m.renderFor('jim');
  // Break the pair by deleting only the END marker.
  const broken = read(root, 'jim').split('\n').filter((l) => l.trim() !== END).join('\n');
  fs.writeFileSync(path.join(root, 'hive', 'agents', 'jim', 'memory.md'), broken);
  const r = await m.reconcile();
  assert.ok(r.aborted.includes('jim'));
  assert.equal(r.repaired.includes('jim'), false);
  assert.equal(read(root, 'jim'), broken, 'a damaged file is surfaced, never guessed at');
  assert.ok(rows.some((r2) => r2.kind === 'rules-render-aborted' && r2.reason === 'sentinels-damaged'));
});

// --- the single writer -------------------------------------------------

test('writes to one agent serialize rather than interleave', async () => {
  const root = home();
  const { m } = mgr(root);
  await m.renderFor('jim');
  // Fire several writes at once; each appends a marker line inside the block.
  const runs = [1, 2, 3, 4, 5].map((n) => m.writeMemoryFile('jim', (t) => ({
    ok: true, text: t.replace(END, `serialized-${n}\n${END}`), action: 'test'
  })));
  await Promise.all(runs);
  const text = read(root, 'jim');
  for (const n of [1, 2, 3, 4, 5]) {
    assert.match(text, new RegExp(`serialized-${n}`), `write ${n} must not be lost`);
  }
});

test('a rejected mutation does not wedge the queue for that agent', async () => {
  const root = home();
  const { m } = mgr(root);
  await m.renderFor('jim');
  const bad = await m.writeMemoryFile('jim', () => ({ ok: false, reason: 'deliberate' }));
  assert.equal(bad.ok, false);
  const good = await m.renderFor('jim');
  assert.equal(good.ok, true, 'the next write must still run');
});

test('a missing memory.md is a refusal, not a crash', async () => {
  const root = home();
  const { m } = mgr(root);
  const out = await m.renderFor('does-not-exist');
  assert.equal(out.ok, false);
  assert.equal(out.reason, 'no-memory-file');
});

// --- caps are recorded ------------------------------------------------

test('the caps are recorded in code for the authoring layer to read', () => {
  assert.equal(RULE_CAPS.globalMax, 12);
  assert.equal(RULE_CAPS.globalMaxTokens, 600);
  assert.equal(RULE_CAPS.perAgentMax, 5);
  assert.equal(RULE_CAPS.perAgentMaxTokens, 250);
});

// --- the store that actually exists on disk today -----------------------

test('legacy store: string scope "all" renders as global', async () => {
  const root = home({ store: { rev: 1, rules: [{ id: 'a', text: 'Applies to everyone.', scope: 'all' }] } });
  const { m } = mgr(root);
  await m.renderAll();
  assert.match(read(root, 'jim'), /Applies to everyone\./);
  assert.match(read(root, 'pam'), /Applies to everyone\./);
});

test('legacy store: an unaddressable scope renders to NOBODY and is logged loudly', async () => {
  // The live store carries scope:"role". A role is not an address, and decision 1
  // excludes roles, so the rule must reach no one - but silently dropping it looks
  // identical to a rule nobody needed.
  const root = home({ store: { rev: 1, rules: [
    { id: 'ok', text: 'Global one.', scope: 'all' },
    { id: 'roley', text: 'Role-scoped one.', scope: 'role' }
  ] } });
  const { m, rows } = mgr(root);
  await m.renderAll();
  assert.match(read(root, 'jim'), /Global one\./);
  assert.equal(read(root, 'jim').includes('Role-scoped one.'), false);
  const warn = rows.find((r) => r.kind === 'rules-scope-unresolvable');
  assert.ok(warn, 'an unaddressable scope must be logged');
  assert.deepEqual(warn.ruleIds, ['roley']);
});

test('legacy store: a missing top-level rev still renders, and says so', async () => {
  const root = home({ store: { rules: [{ id: 'a', text: 'No rev in this store.', scope: 'all' }] } });
  const { m, rows } = mgr(root);
  const out = await m.renderFor('jim');
  assert.equal(out.ok, true);
  assert.match(read(root, 'jim'), /No rev in this store\./);
  assert.match(read(root, 'jim'), /rev 0/);
  assert.ok(rows.some((r) => r.kind === 'rules-store-no-rev'));
});

test('the REAL hive store matches the locked schema and targets correctly', () => {
  // Reads the ACTUAL file rather than a fixture, so a schema drift on disk fails a
  // test instead of surfacing in production. This assertion set was inverted once:
  // it used to assert that a scope was UNRESOLVABLE, because the store carried
  // `scope:"role"` and no top-level rev. god migrated the store to the locked
  // schema, so it now asserts the healthy shape — the test earning its keep by
  // going red the moment the file changed.
  const live = '/Users/gpinkham/HarnessAgents/hive/policy/rules.json';
  if (!fs.existsSync(live)) return; // not this machine; skip rather than fail
  const store = JSON.parse(fs.readFileSync(live, 'utf8'));

  assert.equal(typeof store.rev, 'number',
    'a top-level integer rev is required: reconcile compares it, and the notice keys on it');
  for (const r of store.rules) {
    assert.equal(typeof r.scope, 'object',
      `${r.id}: scope must be the object form, not a legacy string`);
    assert.ok(r.scope.kind === 'global' || r.scope.kind === 'agents',
      `${r.id}: scope.kind must be global or agents, got ${r.scope.kind}`);
    if (r.scope.kind === 'agents') {
      assert.ok(Array.isArray(r.scope.ids) && r.scope.ids.length, `${r.id}: agents scope needs ids`);
    }
  }

  const root = home({ store, agents: ['jim-mt6j19d5', 'dwight-mt6j3ppy', 'god'] });
  const { m, rows } = mgr(root);
  const ids = (agent) => m.rulesFor(agent, store.rules).map((r) => r.id);

  const jim = ids('jim-mt6j19d5');
  const dwight = ids('dwight-mt6j3ppy');
  const god = ids('god');

  // Every scope resolves now, so nothing may be silently dropped.
  assert.equal(rows.some((r) => r.kind === 'rules-scope-unresolvable'), false,
    'a rule nobody can be addressed by would render to nobody');

  // The agent-scoped rule reaches exactly the agent it names.
  assert.ok(dwight.includes('no-review-cto-pr'), 'Dwight must now receive his own rule');
  assert.equal(jim.includes('no-review-cto-pr'), false, 'and nobody else may');
  assert.equal(god.includes('no-review-cto-pr'), false);

  // The globals reach everyone, god included (md-140: no isGod exclusion).
  for (const set of [jim, dwight, god]) {
    assert.ok(set.includes('own-folder-only'));
    assert.ok(set.includes('no-destructive-shared-state'));
    assert.ok(set.includes('no-push-without-signoff'));
    assert.ok(set.includes('triage-dont-self-authorize'));
  }
  assert.equal(jim.length, 4);
  assert.equal(dwight.length, 5, 'Dwight carries the four globals plus his own');
});
