'use strict';

/*
 * The Rules panel showed only rules.json (prose rules delivered to agents). The rules
 * the hook ENFORCES live in policy/engine.json and had no screen at all, so on the day
 * job the panel was empty while `remote-push` was live (2026-10-06). The panel now
 * lists the enforced rules read-only, whether or not rules.json exists.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const loadTs = require('./load-ts.cjs');

const { PolicyEngine } = loadTs('src/main/policy.ts');

const read = (rel) => fs.readFileSync(path.join(__dirname, '..', rel), 'utf8');

function engineWith(policy) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'md-enforced-'));
  if (policy !== undefined) {
    fs.mkdirSync(path.join(root, 'policy'));
    fs.writeFileSync(path.join(root, 'policy', 'engine.json'), typeof policy === 'string' ? policy : JSON.stringify(policy));
  }
  const e = new PolicyEngine(root, () => {});
  e.load();
  return e;
}

test('the engine lists its loaded rules for display, in order, with mode and grantable', () => {
  const e = engineWith({ version: 1, rules: [
    { id: 'protected-branch-push', decision: 'deny', mode: 'live', reason: 'Never push master.', match: { tool: 'Bash', command_matches: 'master' } },
    { id: 'remote-push', decision: 'ask', mode: 'live', reason: 'Pushing is the operator\'s call.', grantable: ['git-push'], match: { tool: 'Bash', command_matches: '^git\\s+push\\b' } },
    { id: 'quiet', decision: 'deny', reason: 'Defaults apply.', match: { tool: 'Bash', command_matches: '^rm\\s' } },
  ] });
  assert.deepEqual(e.enforcedRules(), [
    { id: 'protected-branch-push', decision: 'deny', mode: 'live', grantable: [], reason: 'Never push master.' },
    { id: 'remote-push', decision: 'ask', mode: 'live', grantable: ['git-push'], reason: 'Pushing is the operator\'s call.' },
    { id: 'quiet', decision: 'deny', mode: 'dry_run', grantable: [], reason: 'Defaults apply.' },
  ]);
});

test('no policy file, or one that failed to load, lists nothing', () => {
  assert.deepEqual(engineWith(undefined).enforcedRules(), []);
  assert.deepEqual(engineWith('{ not json').enforcedRules(), []);
});

// Dwight L1: a broken engine.json leaves no rules loaded, which read exactly like no
// file. The panel gets the load status with the rules and says which it is.
test('the panel is told the policy file, and why nothing loaded when it is broken', (t) => {
  const electron = require.resolve('electron');
  require.cache[electron] = { id: electron, filename: electron, loaded: true,
    exports: { Notification: class { show() {} static isSupported() { return false; } } } };
  const { HiveManager } = loadTs('src/main/hive.ts');
  const { HookServer } = loadTs('src/main/hooks.ts');
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'md-enforced-hook-'));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  fs.mkdirSync(path.join(home, 'hive', 'policy'), { recursive: true });
  fs.writeFileSync(path.join(home, 'hive', 'policy', 'engine.json'), '{ "version": 1, "rules": [ { "id": "x" } ] }');
  const server = new HookServer(new HiveManager(() => home), () => null, () => ({}), undefined, undefined);
  const out = server.policyRules();
  assert.deepEqual(out.rules, []);
  assert.equal(out.configured, true);
  assert.match(out.error, /x:/, 'the reason the file did not load');
  assert.match(out.file, /engine\.json$/);
  const panel = read('src/renderer/src/components/RulesPanel.tsx');
  assert.match(panel, /error/);
  assert.match(panel, /nothing is enforced/i);
});

test('the panel reads the enforced rules over IPC and shows them even without rules.json', () => {
  assert.match(read('src/main/hooks.ts'), /policyRules\(\)[\s\S]{0,500}enforcedRules\(\)/);
  assert.match(read('src/main/index.ts'), /ipcMain\.handle\('policy:rules', \(\) => hookServer\.policyRules\(\)\)/);
  assert.match(read('src/preload/index.ts'), /policyRules:[\s\S]{0,120}ipcRenderer\.invoke\('policy:rules'\)/);
  const panel = read('src/renderer/src/components/RulesPanel.tsx');
  assert.match(panel, /window\.cth\.policyRules\(\)/);
  // Both the "rules.json not set up" view and the normal view carry the list.
  const notSetUp = panel.slice(panel.indexOf('if (!ov.active)'), panel.indexOf('const active = ov.rules'));
  assert.match(notSetUp, /<EnforcedRules/);
  assert.equal((panel.match(/<EnforcedRules/g) ?? []).length, 2);
});
