'use strict';

/**
 * md-136 — the redacted, trainable decision corpus.
 *
 * md-120's ledger stores `input_digest`, a sha256, precisely so the harness never
 * persists secrets: a tool_input carries tokens, passwords and private keys. But a
 * hash cannot be trained on, so six months of adjudicated rows would leave no corpus
 * for a local classifier (md-135 §5). This writes a SECOND, deliberately lossy record
 * beside the hash: the shape of the action, never its values.
 *
 * These tests are adversarial on purpose. The corpus is a new file that did not exist
 * before, so every test below asks the same question — can a secret reach it? — and
 * the redaction is required to fail CLOSED: a token it cannot confidently classify
 * loses its value rather than being emitted raw.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const loadTs = require('./load-ts.cjs');

const { scrubArgv, normalizeForCorpus, corpusRecord, CORPUS_FILE, CORPUS_SCHEMA } =
  loadTs('src/main/corpus.ts');
const { PolicyEngine } = loadTs('src/main/policy.ts');

/** Every one of these must be absent from every record, whatever shape it arrives in. */
// ASSEMBLED AT RUNTIME, never written as one literal. These canaries have to be
// credential-SHAPED to be worth testing, which is precisely what a secret scanner
// matches: GitHub push protection rejected this branch over the Slack one. Splitting
// each prefix from its body keeps the assembled value byte-identical for every
// assertion while leaving no matchable literal in the blob, so the fixture cannot be
// mistaken for a live credential by this repo's scanner or anyone else's.
const SECRETS = {
  gh: 'ghp' + '_' + 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8',
  anthropic: 'sk' + '-ant-api03-' + 'ZZZsupersecretvalueZZZ',
  aws: 'AKIA' + 'IOSFODNN7EXAMPLE',
  slack: 'xoxb' + '-123456789012-' + 'abcdefghijklmnopqrst',
  password: 'hunter2-Tr0ub4dor-correct-horse',
  jwt: 'eyJ' + 'hbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.abcdefghijklmnop',
  pem: '-----BEGIN' + ' RSA PRIVATE KEY-----MIIEowIBAAKCAQEA-----END RSA PRIVATE KEY-----',
};
/** The lowercase variants, split for the same reason. */
const LOWER_ANTHROPIC = 'sk' + '-ant-api03-' + 'zzzsupersecretvaluezzz';
const ALL = Object.values(SECRETS);

const CTX = {
  agentId: 'jim-1',
  agentIds: ['jim-1', 'ryan-2', 'god'],
  home: '/Users/dev',
  hiveRoot: '/Users/dev/Harness/hive',
  policyDir: '/Users/dev/Harness/hive/policy',
  cwd: '/Users/dev/repo',
};

const leaks = (value) => ALL.filter((s) => JSON.stringify(value).includes(s));
/** Catch a partial leak too: a long distinctive chunk of a secret is still a leak. */
const chunks = (value) => ALL.flatMap((s) => [s.slice(0, 24), s.slice(-24)])
  .filter((c) => c.length >= 12 && JSON.stringify(value).includes(c));

// --- 1. the shape survives -----------------------------------------------------

test('md-136: verbs and flags survive, argument values do not', () => {
  const out = scrubArgv(['rm', '-rf', '--force', '/Users/dev/repo/build'], CTX);
  assert.equal(out[0], 'rm', 'the verb is the point of the record');
  assert.ok(out.includes('-rf') && out.includes('--force'), 'flags are shape, not value');
  assert.ok(!out.some((t) => t.includes('build')) || out.some((t) => t.startsWith('<')),
    'a path is normalized, never raw beyond its classification');
});

test('md-136: a flag that carries a value keeps the flag and drops the value', () => {
  const out = scrubArgv(['curl', '--header=Authorization: Bearer ' + SECRETS.gh, '-u', SECRETS.password], CTX);
  assert.equal(out[0], 'curl');
  assert.ok(out.some((t) => t.startsWith('--header=')), 'the flag NAME is signal and is kept');
  assert.ok(out.includes('-u'), 'a value-taking flag keeps its name');
  assert.deepEqual(leaks(out), [], 'no secret may survive in a flag value');
});

test('md-136: an env-style assignment keeps the NAME and drops the value', () => {
  const out = scrubArgv(['TOKEN=' + SECRETS.gh, 'AWS_SECRET_ACCESS_KEY=' + SECRETS.aws, 'deploy'], CTX);
  assert.ok(out.some((t) => t.startsWith('TOKEN=')), 'the variable name is shape');
  assert.deepEqual(leaks(out), [], 'the variable VALUE is never shape');
});

// --- 2. paths: normalized, and comparable across floors ------------------------

test('md-136: home, hive, policy dir and agent ids normalize to placeholders', () => {
  const n = (p) => normalizeForCorpus(p, CTX);
  assert.equal(n('/Users/dev/repo'), '<home>/repo');
  assert.ok(n('/Users/dev/Harness/hive/policy/engine.json').startsWith('<policy>'));
  assert.ok(n('/Users/dev/Harness/hive/agents/jim-1/memory.md').includes('<agent:self>'),
    'the acting agent must be distinguishable from a colleague');
  assert.ok(n('/Users/dev/Harness/hive/agents/ryan-2/memory.md').includes('<agent:other>'));
  assert.ok(!n('/Users/dev/Harness/hive/agents/ryan-2/memory.md').includes('ryan-2'),
    'a raw agent id makes two floors incomparable');
});

test('md-136: a secret hiding INSIDE a path is redacted, not normalized through', () => {
  const n = normalizeForCorpus(`/tmp/${SECRETS.gh}/data.json`, CTX);
  assert.deepEqual(leaks(n), [], 'a path segment is not automatically safe');
  assert.deepEqual(chunks(n), []);
});

test('md-136: fail CLOSED — a segment that cannot be confidently classified loses its value', () => {
  for (const weird of ['a'.repeat(200), SECRETS.jwt, SECRETS.aws, 'Zm9vYmFyYmF6cXV4Y29ycmVjdA==']) {
    const n = normalizeForCorpus(`/Users/dev/repo/${weird}`, CTX);
    assert.ok(n.includes('<'), `${weird.slice(0, 16)}…: must be replaced, not passed through`);
    assert.deepEqual(leaks(n), []);
  }
});

// --- 3. the leak battery -------------------------------------------------------

const NASTY = [
  ['bearer token in a header', ['curl', '-H', `Authorization: Bearer ${SECRETS.gh}`, 'https://api.example.com/v1'], 'curl'],
  ['exported secret then a removal', ['env', `ANTHROPIC_API_KEY=${SECRETS.anthropic}`, 'rm', '-rf', '/Users/dev/Harness/hive/agents/ryan-2/checkout'], 'env'],
  ['a quoted password argument', ['psql', `postgres://user:${SECRETS.password}@db.internal/app`], 'psql'],
  ['a private key on the command line', ['ssh-add', '-q', SECRETS.pem], 'ssh-add'],
  ['a jwt as a bare operand', ['./deploy.sh', SECRETS.jwt, '--prod'], 'deploy.sh'],
  ['an aws key in a path', ['cp', `/tmp/${SECRETS.aws}/creds`, '/Users/dev/repo/'], 'cp'],
  ['a slack token in a redirection target', ['tee', `/Users/dev/repo/${SECRETS.slack}.log`], 'tee'],
  ['a heredoc body as one argv word', ['sh', '-c', `cat <<EOF > /Users/dev/repo/f\n${SECRETS.anthropic}\nEOF`], 'sh'],
  ['a whole secret file inlined', ['echo', SECRETS.pem], 'echo'],
];

for (const [name, argv, verb] of NASTY) {
  test(`md-136 leak battery: ${name}`, () => {
    const out = scrubArgv(argv, CTX);
    assert.deepEqual(leaks(out), [], `LEAKED into ${JSON.stringify(out)}`);
    assert.deepEqual(chunks(out), [], `partial leak into ${JSON.stringify(out)}`);
    assert.ok(out[0].includes(verb.replace('./', '')) || out[0].startsWith('<'),
      `the verb should survive for training: got ${out[0]}`);
  });
}

test('md-136: the whole record, not just argv, is clean for every nasty shape', () => {
  for (const [name, argv] of NASTY) {
    const rec = corpusRecord({
      payload: { tool_name: 'Bash', agent_id: 'jim-1', tool_input: { command: argv.join(' ') }, cwd: CTX.cwd },
      verdict: { decision: 'deny', ruleId: 'cross-agent-write', mode: 'dry_run', matchedOn: 'path_glob' },
      commands: [{ argv, writes: [`/tmp/${SECRETS.aws}/out`], removes: [], unresolved: [] }],
      ctx: CTX,
      digest: 'sha256:deadbeef',
    });
    assert.deepEqual(leaks(rec), [], `${name}: leaked into the record`);
    assert.deepEqual(chunks(rec), [], `${name}: partial leak into the record`);
    assert.ok(!JSON.stringify(rec).includes(argv.join(' ')), `${name}: the raw command must never appear`);
  }
});

test('md-136: the record keeps what training needs', () => {
  const rec = corpusRecord({
    payload: { tool_name: 'Bash', agent_id: 'jim-1', tool_input: { command: 'x' }, cwd: CTX.cwd },
    verdict: { decision: 'deny', ruleId: 'cross-agent-workspace', mode: 'dry_run', matchedOn: 'path_in_other_agent_workspace', wouldDeny: true },
    commands: [{ argv: ['rm', '-rf', '/Users/dev/Harness/hive/agents/ryan-2/checkout'], writes: ['/Users/dev/Harness/hive/agents/ryan-2/checkout'], removes: [], unresolved: [] }],
    ctx: CTX,
    digest: 'sha256:abc',
  });
  assert.equal(rec.schema, CORPUS_SCHEMA);
  assert.ok(CORPUS_SCHEMA >= 4, 'approval_needed rows must be tellable apart from older denies');
  assert.equal(rec.approval_needed, false);
  assert.equal(rec.rule_id, 'cross-agent-workspace');
  assert.equal(rec.decision, 'deny');
  assert.equal(rec.mode, 'dry_run');
  assert.equal(rec.matched_on, 'path_in_other_agent_workspace');
  assert.equal(rec.would_deny, true);
  assert.equal(rec.tool, 'Bash');
  assert.equal(rec.agent, '<agent:self>');
  assert.equal(rec.input_digest, 'sha256:abc', 'the digest joins the corpus row to the audit row');
  assert.equal(rec.commands[0].argv[0], 'rm');
  assert.ok(JSON.stringify(rec.commands[0]).includes('<agent:other>'));
});

test('md-136: a non-Bash tool records its path shape without the file body', () => {
  const rec = corpusRecord({
    payload: {
      tool_name: 'Write', agent_id: 'jim-1', cwd: CTX.cwd,
      tool_input: { file_path: '/Users/dev/Harness/hive/agents/ryan-2/notes.md', content: SECRETS.anthropic },
    },
    verdict: { decision: 'deny', ruleId: 'cross-agent-write', mode: 'dry_run', matchedOn: 'path_glob' },
    commands: [], ctx: CTX, digest: 'sha256:abc',
  });
  assert.deepEqual(leaks(rec), [], 'a Write payload carries the file BODY — it must never be recorded');
  assert.equal(rec.tool, 'Write');
  assert.ok(JSON.stringify(rec.paths).includes('<agent:other>'), 'the path shape is the signal');
});

// --- 4. end to end, through the real engine ------------------------------------

function floor(t, { corpus = true } = {}) {
  const base = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'md136-')));
  t.after(() => fs.rmSync(base, { recursive: true, force: true }));
  const hiveRoot = path.join(base, 'hive');
  fs.mkdirSync(path.join(hiveRoot, 'policy'), { recursive: true });
  const pack = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'examples/policy/engine.example.json'), 'utf8'));
  delete pack._comment;
  fs.writeFileSync(path.join(hiveRoot, 'policy', 'engine.json'), JSON.stringify(pack));
  const rows = [];
  const ws = [
    { agentId: 'jim-1', roots: [path.join(base, 'wt', 'jim-1')] },
    { agentId: 'ryan-2', roots: [path.join(base, 'wt', 'ryan-2')] },
  ];
  for (const w of ws) fs.mkdirSync(w.roots[0], { recursive: true });
  const engine = new PolicyEngine(hiveRoot, (r) => rows.push(r), () => [], () => ws, () => corpus);
  engine.load();
  const corpusPath = path.join(hiveRoot, 'policy', CORPUS_FILE);
  const corpusRows = () => (fs.existsSync(corpusPath) ? fs.readFileSync(corpusPath, 'utf8').trim().split('\n') : [])
    .filter(Boolean).map((l) => JSON.parse(l));
  return { base, hiveRoot, engine, rows, corpusPath, corpusRows, ws };
}

const deny = (engine, base, command) => engine.evaluate({
  hook_event_name: 'PreToolUse', agent_id: 'jim-1', tool_name: 'Bash',
  tool_input: { command }, cwd: path.join(base, 'wt', 'jim-1'),
});

test('md-136 e2e: a decision writes a corpus record beside the unchanged digest row', async (t) => {
  const { engine, base, rows, corpusRows } = floor(t);
  const v = deny(engine, base, `rm -rf ${path.join(base, 'wt', 'ryan-2')}/checkout --token=${SECRETS.gh}`);
  assert.ok(v.ruleId, 'precondition: this must be a decision worth recording');

  const audit = rows.filter((r) => r.kind === 'policy-decision');
  assert.equal(audit.length, 1);
  assert.deepEqual(Object.keys(audit[0]).sort(),
    ['agent_id', 'decision', 'input_digest', 'kind', 'matched_on', 'mode', 'rule_id', 'tool', 'would_deny'],
    'the audit row must be byte-for-byte the same shape as before md-136');

  const c = corpusRows();
  assert.equal(c.length, 1, 'exactly one corpus record per decision');
  assert.equal(c[0].input_digest, audit[0].input_digest, 'the two rows join on the digest');
  assert.deepEqual(leaks(c), [], 'the corpus file must never hold a secret');
});

test('md-136 e2e: an allow with no match records nothing at all', async (t) => {
  const { engine, base, corpusRows, rows } = floor(t);
  const v = engine.evaluate({
    hook_event_name: 'PreToolUse', agent_id: 'jim-1', tool_name: 'Bash',
    tool_input: { command: 'ls -la' }, cwd: path.join(base, 'wt', 'jim-1'),
  });
  assert.equal(v.decision, 'allow');
  assert.equal(v.ruleId, undefined);
  assert.equal(corpusRows().length, 0, 'the corpus is decisions, not traffic');
  assert.equal(rows.filter((r) => r.kind === 'policy-decision').length, 0);
});

test('md-136 e2e: the flag turns it off, and off writes no file at all', async (t) => {
  const { engine, base, corpusPath, rows } = floor(t, { corpus: false });
  deny(engine, base, `rm -rf ${path.join(base, 'wt', 'ryan-2')}/checkout`);
  assert.equal(fs.existsSync(corpusPath), false, 'opting out must leave no file behind');
  assert.equal(rows.filter((r) => r.kind === 'policy-decision').length, 1, 'the audit row is never gated');
});

test('md-136 e2e: a corpus write that fails never changes the decision', async (t) => {
  const { engine, base, hiveRoot, corpusPath } = floor(t);
  fs.rmSync(path.join(hiveRoot, 'policy', 'guardrail.json'));
  fs.rmSync(corpusPath, { force: true });
  fs.mkdirSync(corpusPath, { recursive: true }); // a DIRECTORY where the file goes: append throws
  const v = deny(engine, base, `rm -rf ${path.join(base, 'wt', 'ryan-2')}/checkout`);
  assert.ok(v.ruleId, 'the verdict must survive a corpus that cannot be written');
  assert.equal(v.decision, 'allow', 'dry_run still allows; the corpus never alters a verdict');
});

test('md-136 e2e: a dry_run row keeps the commands and write paths it was decided on', async (t) => {
  const { engine, base, corpusRows } = floor(t);
  const target = path.join(base, 'wt', 'ryan-2', 'notes.md');
  const v = deny(engine, base, `echo hi > ${target}`);
  assert.equal(v.mode, 'dry_run', 'precondition: the dry_run branch is the one under test');
  assert.equal(v.wouldDeny, true, 'precondition: a would-deny is what gets recorded');

  const c = corpusRows();
  assert.equal(c.length, 1);
  assert.ok(c[0].commands.length > 0,
    'the parsed commands the rule judged must reach the row, or a dry_run match records no evidence');
  assert.equal(c[0].commands[0].argv[0], 'echo');
  assert.ok(c[0].paths.writes.length > 0, 'the write target that matched must be on the row');
  assert.ok(c[0].paths.writes.every((w) => w.includes('<agent:other>') && !w.includes('ryan-2')),
    'and only in its redacted form');
});

// --- md-136 N1 (Dwight): a flag NAME is a value too -------------------------------
//
// The first pass checked flag VALUES and never flag NAMES, so a name went out through
// `--<name>` with none of the checks a path segment must pass — no length cap, no
// credential prefix, no run heuristic. `curl --sk-ant-api03-…` was written verbatim:
// the very string that is correctly `<x>` one line away, as a path segment. An argument
// does not become shape by having two dashes in front of it.

const FLAG_LEAKS = [
  ['a long-flag whose NAME is the secret', ['curl', '--' + SECRETS.anthropic]],
  ['a long-flag name with a value after it', ['curl', '--' + SECRETS.gh + '=x']],
  ['a github token as a long flag', ['x', '--' + SECRETS.gh]],
  ['an aws key as an attached short option', ['tar', '-' + SECRETS.aws]],
  ['a pure-alpha short cluster that is a credential', ['tar', '-AKIA' + 'IOSFODNNEXAMPLE']],
  ['a lowercased anthropic key as a flag', ['curl', '--' + LOWER_ANTHROPIC]],
];

for (const [name, argv] of FLAG_LEAKS) {
  test(`md-136 N1: ${name}`, () => {
    const out = scrubArgv(argv, CTX);
    assert.deepEqual(leaks(out), [], `LEAKED via a flag name into ${JSON.stringify(out)}`);
    assert.deepEqual(chunks(out), [], `partial leak into ${JSON.stringify(out)}`);
    assert.ok(!out.some((t) => t.includes('AKIA' + 'IOSFODNNEXAMPLE') || t.includes(LOWER_ANTHROPIC.slice(0, 16))),
      `credential-shaped flag name survived: ${JSON.stringify(out)}`);
  });
}

test('md-136 N1: ordinary flags are untouched by the fix', () => {
  const argv = ['tar', '--force', '--dry-run', '--token', '-rf', '-xzvf', '--max-count=5', '-C'];
  const out = scrubArgv(argv, CTX);
  assert.deepEqual(out, ['tar', '--force', '--dry-run', '--token', '-rf', '-xzvf', '--max-count=<v>', '-C'],
    'the fix must not cost the flag shape that makes a record trainable');
});

// --- md-136 N2 (Gary approved): the subcommand is the signal ----------------------
//
// Two of the four shipped rules match on `command_matches`, i.e. verb PLUS subcommand:
// `git push` is an ask, `git status` is nothing. Recording both as ['git','<arg>']
// destroys exactly the distinction the corpus exists to learn. The subcommand slot is
// still an argument position, though, so it is kept only when it looks like a keyword.

test('md-136 N2: a subcommand after a multi-verb program survives', () => {
  for (const [argv, want] of [
    [['git', 'push', '--force'], 'push'],
    [['git', 'status'], 'status'],
    [['git', 'worktree', 'remove'], 'worktree'],
    [['npm', 'publish'], 'publish'],
    [['docker', 'build', '-t'], 'build'],
    [['gh', 'pr', 'create'], 'pr'],
    [['kubectl', 'delete'], 'delete'],
  ]) {
    const out = scrubArgv(argv, CTX);
    assert.equal(out[1], want, `${argv.join(' ')}: the subcommand is the signal md-135 wants`);
  }
});

test('md-136 N2: a subcommand slot holding a secret is still dropped', () => {
  for (const secret of ALL.concat([LOWER_ANTHROPIC, 'a'.repeat(64)])) {
    const out = scrubArgv(['git', secret], CTX);
    // A placeholder, whichever one: a PEM begins with '-' so it lands in the flag
    // branch. What matters is that the slot never carries the value.
    assert.ok(out[1].startsWith('<'), `a value in the subcommand slot must not be kept: ${JSON.stringify(out)}`);
  }
  assert.deepEqual(leaks(scrubArgv(['git', SECRETS.gh, 'push'], CTX)), []);
});

test('md-136 N2: only the FIRST token, and only for a known multi-verb program', () => {
  assert.equal(scrubArgv(['rm', 'push'], CTX)[1], '<arg>', 'rm has no subcommands — that is an operand');
  assert.equal(scrubArgv(['git', 'push', 'origin'], CTX)[2], '<arg>', 'a remote NAME is a value, not shape');
});

test('md-136 N2: the schema version is bumped, so early rows are distinguishable', () => {
  assert.ok(CORPUS_SCHEMA >= 2, 'rows written before the subcommand existed must be tellable apart');
});

// --- md-136: the raw command text must never reach the record ---------------------

test('md-136: EffectiveCommand.text never appears, even though it is on the input object', () => {
  const raw = `curl -H "Authorization: Bearer ${SECRETS.gh}" https://api.example.com`;
  const rec = corpusRecord({
    payload: { tool_name: 'Bash', agent_id: 'jim-1', tool_input: { command: raw }, cwd: CTX.cwd },
    verdict: { decision: 'deny', ruleId: 'r', mode: 'dry_run', matchedOn: 'command_matches' },
    // `text` is a real field of EffectiveCommand. It is kept out only because the
    // record is BUILT field by field rather than spread, so this guards a refactor.
    commands: [{ argv: ['curl', '-H', 'x'], text: raw, writes: [], removes: [], unresolved: [] }],
    ctx: CTX, digest: 'sha256:abc',
  });
  assert.ok(!JSON.stringify(rec).includes('Authorization'), 'the raw command text leaked into the record');
  assert.deepEqual(leaks(rec), []);
  assert.equal(rec.commands[0].text, undefined, 'no `text` field may survive onto a record');
});

test('md-136 N2: a global flag before the subcommand does not hide it', () => {
  // The dominant real form, and the one `remote-push` actually matches:
  // `git -C <dir> push`. shell.ts keeps the global flags in argv, so the subcommand
  // is not at index 1 and a naive index-1 rule records `<arg>` for the very case the
  // corpus most needs.
  assert.equal(scrubArgv(['git', '-C', '/Users/dev/repo', 'push', '--force'], CTX)[3], 'push');
  assert.equal(scrubArgv(['git', '--no-pager', 'status'], CTX)[2], 'status');
  assert.equal(scrubArgv(['git', '-C', '/Users/dev/repo', 'worktree', 'remove'], CTX)[3], 'worktree');
});

test('md-136 N2: skipping global flags does not open a value channel', () => {
  // The flag VALUE that was skipped over is still scrubbed as an ordinary token, and
  // the subcommand slot still has to look like a keyword.
  const out = scrubArgv(['git', '-C', `/tmp/${SECRETS.aws}`, SECRETS.gh], CTX);
  assert.deepEqual(leaks(out), [], `leaked: ${JSON.stringify(out)}`);
  assert.deepEqual(chunks(out), []);
  for (const secret of ALL) {
    assert.deepEqual(leaks(scrubArgv(['git', '-C', '/Users/dev/repo', secret], CTX)), [],
      'a credential in the post-global-flag subcommand slot must still go');
  }
});

// --- md-136 N6 (Dwight re-review): the N2 stepping walked ONTO flag values ---------
//
// My N2 stepping skipped an unrecognised leading flag assuming it took no value. When it
// does, the index landed on that flag's VALUE and wrote it verbatim — and the flags this
// happens to are called --token, --password, -u, -p. This is a REGRESSION: the separated
// form `--token SECRET` was safe before N2, and it is the ordinary way a secret reaches a
// command line. GLOBAL_VALUE_FLAGS can never be complete across 33 programs' CLIs, so the
// guess itself was the bug: on an unrecognised flag, give up on finding a subcommand.

const D_VECTORS = [
  ['kubectl --token', ['kubectl', '--token', 'hunter2password', 'get', 'pods'], 'hunter2password'],
  ['docker -u', ['docker', '-u', 'rootpassword', 'ps'], 'rootpassword'],
  ['aws --profile', ['aws', '--profile', 'prodsecret', 's3', 'ls'], 'prodsecret'],
  ['pip --proxy', ['pip', '--proxy', 'hunter2proxy', 'install', 'pkg'], 'hunter2proxy'],
  ['helm --kube-token', ['helm', '--kube-token', 'deploykey1234', 'install'], 'deploykey1234'],
  ['kubectl -n', ['kubectl', '-n', 'mysecretns', 'get', 'pods'], 'mysecretns'],
];

for (const [name, argv, secret] of D_VECTORS) {
  test(`md-136 N6: ${name} <SECRET> — the flag's value is never captured`, () => {
    const out = scrubArgv(argv, CTX);
    assert.ok(!out.includes(secret), `LEAKED the flag value verbatim: ${JSON.stringify(out)}`);
    assert.ok(!JSON.stringify(out).includes(secret), `LEAKED: ${JSON.stringify(out)}`);
  });
}

test('md-136 N6: an UNRECOGNISED leading flag makes us give up rather than guess', () => {
  // The whole point: we cannot enumerate every CLI, so an unknown flag must not be
  // assumed value-less. Whatever follows it is never captured as a subcommand.
  for (const flag of ['--totally-unknown-flag', '--some-future-option', '-Z']) {
    const out = scrubArgv(['kubectl', flag, 'hunter2password', 'get'], CTX);
    assert.ok(!out.includes('hunter2password'),
      `${flag}: guessed onto the value — ${JSON.stringify(out)}`);
  }
});

test('md-136 N6: the benign captures the stepping existed for still work', () => {
  assert.equal(scrubArgv(['git', '-C', '/Users/dev/repo', 'push', '--force'], CTX)[3], 'push',
    'this is the case N2 was added for and it must survive the N6 fix');
  assert.equal(scrubArgv(['git', '--no-pager', 'status'], CTX)[2], 'status');
  assert.equal(scrubArgv(['git', 'push'], CTX)[1], 'push');
  assert.equal(scrubArgv(['npm', 'publish'], CTX)[1], 'publish');
});

test('md-136 N6: listing a credential flag recovers the SUBCOMMAND without its value', () => {
  // Safety here does not depend on this list — an unlisted flag hits the give-up branch
  // and is equally safe. The list is what buys back the signal, so it needs its own
  // test: without this, deleting the entries would pass every other test silently.
  for (const [argv, want] of [
    [['kubectl', '--token', 'hunter2password', 'get', 'pods'], 'get'],
    [['docker', '-u', 'rootpassword', 'ps'], 'ps'],
    [['aws', '--profile', 'prodsecret', 's3', 'ls'], 's3'],
    [['pip', '--proxy', 'hunter2proxy', 'install', 'pkg'], 'install'],
    [['helm', '--kube-token', 'deploykey1234', 'install'], 'install'],
    [['kubectl', '-n', 'mysecretns', 'get', 'pods'], 'get'],
  ]) {
    const out = scrubArgv(argv, CTX);
    assert.ok(out.includes(want), `${argv[0]} ${argv[1]}: lost the subcommand — ${JSON.stringify(out)}`);
    assert.ok(!out.includes(argv[2]), `and the value must still be gone — ${JSON.stringify(out)}`);
  }
});
