'use strict';

/**
 * HAG-30 (md-224): god's heartbeat digest builds its "Recent log" from the newest few
 * `log.jsonl` rows. `policy-transport-failopen` (md-222) writes one row per hook call, so
 * during a transport outage on a busy floor every row in that window is a fail-open — and
 * the message, spawn and task rows god reads the digest FOR are evicted by an outage that
 * one line could have reported.
 *
 * This is the READ side only. Nothing here touches the fail-open write path in the
 * cth-hook shim: a row still gets written for every call, and the outage stays visible.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const loadTs = require('./load-ts.cjs');

const { activityLog, POLICY_TRANSPORT_FAILOPEN } = loadTs('src/main/hive.ts');

const failopen = (ts, reason = 'timeout') => ({
  ts, kind: POLICY_TRANSPORT_FAILOPEN, reason, agent_id: 'jim-1', tool: 'Bash', hook_event: 'PreToolUse', answered: false
});
const msg = (ts, from) => ({ ts, kind: 'message', from, to: 'god-1' });
const lines = (block) => block.split('\n').filter(Boolean);

test('a quiet floor reads exactly as it always did: the newest N rows, one JSON per line', () => {
  const rows = [msg(1, 'a'), msg(2, 'b'), msg(3, 'c')];
  assert.deepEqual(lines(activityLog(rows, 8)), rows.map((r) => JSON.stringify(r)));
  // The limit still bites, newest last, and nothing is prepended when there is no outage.
  assert.deepEqual(lines(activityLog(rows, 2)), [JSON.stringify(rows[1]), JSON.stringify(rows[2])]);
  assert.equal(activityLog([], 8), '');
});

test('an outage cannot evict the message, spawn and task rows god reads this digest for', () => {
  // The exact shape of the harm: on the old read, eight fail-opens were the whole window.
  const rows = [
    msg(1, 'kelly'), { ts: 2, kind: 'spawn', agent_id: 'ryan-1' }, { ts: 3, kind: 'task', id: 'md-224' },
    ...[4, 5, 6, 7, 8, 9, 10, 11].map((ts) => failopen(ts))
  ];
  const out = lines(activityLog(rows, 8));
  assert.equal(out.filter((l) => l.includes('"kind":"message"')).length, 1, 'the message survived');
  assert.equal(out.filter((l) => l.includes('"kind":"spawn"')).length, 1);
  assert.equal(out.filter((l) => l.includes('"kind":"task"')).length, 1);
  assert.equal(out.filter((l) => l.startsWith('{') && l.includes(POLICY_TRANSPORT_FAILOPEN)).length, 0,
    'no fail-open row is spent on a line of its own');
});

test('the outage is still reported — a count, and the newest row so its reason is readable', () => {
  const rows = [msg(1, 'kelly'), ...[2, 3, 4].map((ts) => failopen(ts, 'no_socket')), failopen(5, 'socket_error')];
  const out = lines(activityLog(rows, 8));
  const note = out.find((l) => l.includes(POLICY_TRANSPORT_FAILOPEN));
  assert.ok(note, 'collapsing it silently would hide an outage, which is what md-222 fixed');
  assert.match(note, /×4\b/, 'how many were collapsed');
  assert.ok(note.includes('"reason":"socket_error"'), 'the NEWEST row, so the current reason is the one shown');
  assert.equal(note.includes('no_socket'), false, 'and only that one — not four copies');
  assert.equal(out.indexOf(note), 0, 'first, so it is not mistaken for a log row');
  assert.ok(out.at(-1).includes('"from":"kelly"'), 'the real rows keep their order after it');
});

test('one fail-open is still collapsed, so the digest has one shape to read', () => {
  const out = lines(activityLog([msg(1, 'kelly'), failopen(2)], 8));
  assert.equal(out.length, 2);
  assert.match(out[0], /×1\b/);
  assert.ok(out[1].includes('"from":"kelly"'));
});

test('an outage that is OVER heads nothing — the count is scoped to the rows we print', () => {
  // Dwight's D2. Scanning 200 rows to find 8 real ones means a fail-open from an outage
  // that ended hours ago is still in `rows`. Counting it printed a leading banner above
  // eight current rows, asserting an outage that is not happening — a NEW false alarm in
  // the one channel md-222 built to be honest, and sticky for days on a quiet floor. The
  // failure mode is the mirror of md-220: god chases a resolved outage instead of missing
  // a live one.
  const resolved = [...Array.from({ length: 40 }, (_, i) => failopen(i, 'socket_error')),
    ...Array.from({ length: 8 }, (_, i) => msg(9000 + i, 'kelly'))];
  const out = lines(activityLog(resolved, 8));
  assert.equal(out.length, 8, 'eight real rows and no banner');
  assert.equal(out.some((l) => l.includes(POLICY_TRANSPORT_FAILOPEN)), false,
    'every one of those fail-opens is older than every row shown');
});

test('a new fail-open after that window is counted once, not forty-one times', () => {
  const rows = [...Array.from({ length: 40 }, (_, i) => failopen(i, 'timeout')),
    ...Array.from({ length: 8 }, (_, i) => msg(100 + i, 'kelly')),
    failopen(999, 'socket_error')];
  const out = lines(activityLog(rows, 8));
  assert.match(out[0], /\u00d71\b/, 'the live outage, not the history');
  assert.ok(out[0].includes('"reason":"socket_error"'));
  assert.equal(out.length, 9, 'one banner plus the eight real rows');
});

test('an outage that really did fill the log still counts every row of it', () => {
  // With no real row anywhere in the scan there is no window to be inside, so the
  // window-scoping must NOT collapse this case to zero — it is the case HAG-30 exists for.
  const out = lines(activityLog(Array.from({ length: 200 }, (_, i) => failopen(i)), 8));
  assert.equal(out.length, 1, 'one line, not eight blanks');
  assert.match(out[0], /\u00d7200\b/);
});

test('a row the parser could not read is signal, not noise, and is never dropped', () => {
  // logTail hands back `{raw: <line>}` for a line that would not parse, and a row may
  // carry no `kind` at all. Dropping either would lose the only evidence of it.
  const rows = [{ raw: 'not json' }, { ts: 2 }, { ts: 3, kind: 'other' }];
  assert.deepEqual(lines(activityLog(rows, 8)), rows.map((r) => JSON.stringify(r)));
});

test('a row that will not serialise costs its own line and nothing else', () => {
  const circular = { ts: 2, kind: 'message' };
  circular.self = circular;
  const out = lines(activityLog([msg(1, 'kelly'), circular, msg(3, 'creed')], 8));
  assert.deepEqual(out, [JSON.stringify(msg(1, 'kelly')), JSON.stringify(msg(3, 'creed'))]);
});

test('the collapsed kind is the one the shim writes, pinned against the writer itself', () => {
  // Reader and writer name the same string in two places; a rename of one alone would
  // silently stop collapsing and the crowd-out would come back with no test failing.
  const src = fs.readFileSync(path.join(__dirname, '..', 'src', 'main', 'hive.ts'), 'utf8');
  assert.ok(src.includes(`kind: '${POLICY_TRANSPORT_FAILOPEN}'`),
    'the cth-hook shim must still write the kind the digest collapses');
});

test('the digest call site pulls a deeper tail than it prints, or there is nothing to collapse', () => {
  // Collapsing inside a window of 8 that is ALREADY all fail-opens leaves god eight
  // blank rows. The fix only works if the read looks past them.
  const src = fs.readFileSync(path.join(__dirname, '..', 'src', 'main', 'index.ts'), 'utf8');
  const call = /activityLog\(hive\.logTail\((\w+)\),\s*(\w+)\)/.exec(src);
  assert.ok(call, 'buildHeartbeatDigest builds its log through activityLog');
  const value = (name) => {
    if (/^\d+$/.test(name)) return Number(name);
    const decl = new RegExp(`const ${name} = (\\d+);`).exec(src);
    assert.ok(decl, `${name} is declared with a literal`);
    return Number(decl[1]);
  };
  const [scanned, printed] = [value(call[1]), value(call[2])];
  assert.ok(scanned > printed, `scanned ${scanned} must exceed printed ${printed}`);
});
