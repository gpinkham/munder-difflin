'use strict';

// The Bash normaliser. Every case here is a disguise that md-188 measured the raw-string
// matcher missing, or a MENTION it must keep missing. Read alongside test/policy.test.cjs,
// which asserts the same thing through the rules.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const loadTs = require('./load-ts.cjs');

const { effectiveCommands, realAbsolute } = loadTs('src/main/shell.ts');

/** Every command the call runs, as normalised text. */
const texts = (cmd, cwd) => effectiveCommands(cmd, cwd ?? '/work').map((c) => c.text);
/** Every path the call writes. */
const writes = (cmd, cwd) => effectiveCommands(cmd, cwd ?? '/work').flatMap((c) => c.writes);

// --- 1. the disguises ---------------------------------------------------------

test('1. a wrapper, a prefix or an absolute program path collapses onto the plain command', () => {
  for (const cmd of [
    'mempalace sync',
    'sudo mempalace sync',
    'nohup mempalace sync &',
    'env FOO=1 mempalace sync',
    'time mempalace sync',
    'timeout 30 mempalace sync',
    '/usr/local/bin/mempalace sync',
    'bash -c "mempalace sync"',
    "sh -c 'mempalace sync'",
    'eval "mempalace sync"',
    '(mempalace sync)',
    '{ mempalace sync; }',
    'python3 -m mempalace sync',
    'M=mempalace; $M sync',
    'S=sync; mempalace $S',
    'for c in sync; do mempalace $c; done',
    'xargs -I{} mempalace {} <<< sync',
    'ls\nmempalace sync',
    'echo go && mempalace sync',
    'false || mempalace sync',
    'cd /tmp; mempalace sync',
  ]) {
    assert.ok(texts(cmd).includes('mempalace sync'), cmd);
  }
});

test('1b. a MENTION stays one word and never becomes a command', () => {
  for (const cmd of [
    'echo "never run mempalace sync"',
    "grep -n 'mempalace sync' PROTOCOL.md",
    'echo git push',
    "git commit -m 'prepare push'",
    "cat <<'EOF'\nmempalace sync\ngit push\nEOF",
    'cat <<-END\n\tmempalace sync\n\tEND',
  ]) {
    const t = texts(cmd);
    assert.equal(t.includes('mempalace sync'), false, cmd);
    assert.equal(t.includes('git push'), false, cmd);
  }
});

test('1c. a heredoc body is data, and the command after it still parses', () => {
  const t = texts("cat <<'EOF' > /tmp/x\nmempalace sync\nEOF\ngit push");
  assert.equal(t.includes('mempalace sync'), false, 'the body is not a command');
  assert.ok(t.includes('git push'), 'the line after the delimiter is');
});

test('1d. an unset variable is left as written rather than collapsing to nothing', () => {
  assert.deepEqual(texts('mempalace $UNSET'), ['mempalace $UNSET']);
  assert.deepEqual(writes('rm -rf $UNSET/x'), ['/work/$UNSET/x']);
});

test('1e. a command substitution runs its own commands', () => {
  assert.ok(texts('echo "$(mempalace sync)"').includes('mempalace sync'));
  assert.ok(texts('echo `git push`').includes('git push'));
});

test('1f. git keeps its flags so a rule can still require push in subcommand position', () => {
  assert.deepEqual(texts('git -C ~/dev/x push'), [`git -C ${os.homedir()}/dev/x push`]);
  assert.deepEqual(texts('git log --grep push'), ['git log --grep push']);
  assert.deepEqual(texts('git stash push -m wip'), ['git stash push -m wip']);
});

// --- 2. write targets ---------------------------------------------------------

test('2. a redirection is a write, a read redirection is not', () => {
  assert.deepEqual(writes('cat a > /x/out.md'), ['/x/out.md']);
  assert.deepEqual(writes('cat a >> /x/out.md'), ['/x/out.md']);
  assert.deepEqual(writes('sort < /x/in.md'), []);
  assert.deepEqual(writes('wc -l /x/in.md'), []);
  assert.deepEqual(writes('npm run build 2> /x/err.log'), ['/x/err.log']);
  assert.deepEqual(writes('npm run build &> /x/all.log'), ['/x/all.log']);
});

test('2b. cp/mv/rsync/ln/install write their LAST operand only', () => {
  assert.deepEqual(writes('cp /a/src.md /b/dest.md'), ['/b/dest.md']);
  assert.deepEqual(writes('mv -f /a/one /a/two /b/dir/'), ['/b/dir/']);
  assert.deepEqual(writes('rsync -a /a/ /b/'), ['/b/']);
  assert.deepEqual(writes('ln -s /a/real /b/link'), ['/b/link']);
  assert.deepEqual(writes('install -m 600 /a/f /b/f'), ['/b/f']);
  assert.deepEqual(writes('cp /a/only'), [], 'one operand is not a destination');
});

test('2c. a directory destination keeps its trailing slash, so "inside here" still globs', () => {
  assert.deepEqual(writes('rsync -a ./out/ /b/dir/'), ['/b/dir/']);
  assert.deepEqual(writes('cp x /b/dir'), ['/b/dir'], 'no trailing slash written, none invented');
});

test('2d. verbs that only mutate write every operand; reads write nothing', () => {
  assert.deepEqual(writes('rm -rf /a/x /a/y'), ['/a/x', '/a/y']);
  assert.deepEqual(writes('touch /a/x'), ['/a/x']);
  assert.deepEqual(writes('tee /a/x /a/y'), ['/a/x', '/a/y']);
  assert.deepEqual(writes('chmod 600 /a/x'), ['/a/x'], 'the mode is not a path');
  assert.deepEqual(writes('chown me:staff /a/x'), ['/a/x']);
  assert.deepEqual(writes('dd if=/a/in of=/a/out'), ['/a/out']);
  for (const cmd of ['cat /a/x', 'ls /a', 'grep -n TODO /a/x', 'head -5 /a/x', 'diff /a/x /a/y']) {
    assert.deepEqual(writes(cmd), [], cmd);
  }
});

test('2e. sed writes only in place, and the script is not mistaken for a file', () => {
  assert.deepEqual(writes("sed -i '' s/a/b/ /a/x"), ['/a/x'], 'BSD sed -i takes an empty suffix');
  assert.deepEqual(writes('sed -i s/a/b/ /a/x'), ['/a/x'], 'GNU sed -i does not');
  assert.deepEqual(writes('sed -i -e s/a/b/ /a/x'), ['/a/x'], '-e supplies the script');
  assert.deepEqual(writes("sed -n '1,5p' /a/x"), [], 'sed -n reads');
});

test('2f. an inline script is searched for paths only when it also writes', () => {
  assert.deepEqual(writes(`node -e "require('fs').writeFileSync('/a/x','y')"`), ['/a/x']);
  assert.deepEqual(writes(`python3 -c "open('/a/x','w').write('y')"`), ['/a/x']);
  assert.deepEqual(writes(`node -e "console.log(require('fs').readFileSync('/a/x','utf8'))"`), [],
    'a read is not a write');
  assert.deepEqual(writes(`python3 -c "print('/a/x')"`), []);
});

test('2g. paths are resolved: relative to cwd, through .., ~ and $HOME', () => {
  assert.deepEqual(writes('touch out.md', '/work/sub'), ['/work/sub/out.md']);
  assert.deepEqual(writes('touch ../out.md', '/work/sub'), ['/work/out.md']);
  assert.deepEqual(writes('touch a/../b/out.md', '/work'), ['/work/b/out.md']);
  assert.deepEqual(writes('touch ~/out.md'), [`${os.homedir()}/out.md`]);
  assert.deepEqual(writes('H=/h; touch $H/out.md'), ['/h/out.md']);
  assert.deepEqual(writes('touch $HOME/out.md'), [`${os.homedir()}/out.md`]);
  assert.deepEqual(writes('touch $AGENT_DIR/out.md'), ['/work/$AGENT_DIR/out.md'],
    'an agent-shell variable is not in the daemon environment, so it is left alone rather than guessed');
});

test('2h. cd moves the cwd for the commands that follow it, but not out of a subshell', () => {
  assert.deepEqual(writes('cd /elsewhere && touch out.md', '/work'), ['/elsewhere/out.md']);
  assert.deepEqual(writes('(cd /elsewhere; touch a.md); touch b.md', '/work'),
    ['/elsewhere/a.md', '/work/b.md']);
});

test('2i. a symlinked parent resolves to the real path, for a file that does not exist yet', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'md199-shell-'));
  const real = fs.realpathSync(root);
  fs.mkdirSync(path.join(real, 'target'));
  fs.symlinkSync(path.join(real, 'target'), path.join(real, 'link'));
  assert.deepEqual(writes(`touch ${real}/link/new.md`), [`${real}/target/new.md`]);
  assert.equal(realAbsolute(`${real}/link/`, '/work'), `${real}/target/`, 'and keeps the trailing slash');
  fs.rmSync(root, { recursive: true, force: true });
});

test('2j. an unpacker writes into its -C directory, but only when extracting', () => {
  assert.deepEqual(writes('tar -xzf a.tgz -C /b/dir'), ['/b/dir/']);
  assert.deepEqual(writes('tar --extract --file a.tgz --directory /b/dir'), ['/b/dir/']);
  assert.deepEqual(writes('unzip a.zip -d /b/dir'), ['/b/dir/']);
  assert.deepEqual(writes('tar -czf a.tgz -C /b/dir .'), [], 'creating an archive writes the archive, not the dir');
});

test('2k. a string an inline script hands to a shell is a command; one it prints is not', () => {
  assert.ok(texts(`python3 -c "import os; os.system('git push')"`).includes('git push'));
  assert.ok(texts(`node -e "require('child_process').execSync('mempalace sync')"`).includes('mempalace sync'));
  assert.deepEqual(
    texts(`node -e "console.log('git push after approval')"`).filter((t) => t.startsWith('git')),
    [], 'a logged sentence must not read as an invocation');
  assert.ok(writes(`python3 -c "os.system('echo x > /a/out.md')"`).includes('/a/out.md'));
});

// --- F1-F6: Dwight's review of md-199 ---------------------------------------

test('F1. a wrapper flag VALUE is not the command it wraps', () => {
  // Skipping flags but not their arguments buried the real command one word deeper,
  // which defeated all three rules at once. `sudo -u` is the ordinary spelling.
  assert.deepEqual(texts('sudo -u gpinkham mempalace sync'), ['mempalace sync']);
  assert.deepEqual(texts('nice -n 5 mempalace repair'), ['mempalace repair']);
  assert.deepEqual(texts('nice -n 10 git push'), ['git push']);
  assert.deepEqual(texts('ionice -c 2 mempalace sync'), ['mempalace sync']);
  assert.deepEqual(texts('script -q /dev/null mempalace sync'), ['mempalace sync']);
  assert.deepEqual(texts('doas -u gpinkham git push'), ['git push']);
  assert.deepEqual(texts('stdbuf -o L npm run dev'), ['npm run dev']);
  assert.deepEqual(texts('sudo --user=gpinkham mempalace sync'), ['mempalace sync'],
    'an attached value carries no extra word');
  assert.deepEqual(texts('sudo -n true'), ['true'], 'a boolean flag takes no value');
});

test('F1b. a command buried behind a wrapper flag still contributes its write target', () => {
  assert.deepEqual(writes('sudo -u gpinkham cp ./a.md /o/inbox/x.json'), ['/o/inbox/x.json']);
  assert.deepEqual(writes('nice -n 10 mv ./a.md /o/results/a.md'), ['/o/results/a.md']);
});

test('F3. a # comment is discarded, and the newline after it still separates', () => {
  assert.deepEqual(texts('git push # --dry-run'), ['git push']);
  assert.deepEqual(texts('echo hi # mempalace sync'), ['echo hi']);
  assert.deepEqual(texts('# nothing here\ngit push'), ['git push']);
  assert.deepEqual(texts('ls foo#bar'), ['ls foo#bar'], 'a # inside a word is not a comment');
  assert.deepEqual(texts("echo '# not a comment'"), ["echo '# not a comment'"]);
});

test('F4. printing a file is not writing it, and the file being READ is not a target', () => {
  assert.deepEqual(writes(`node -e "process.stdout.write(require('fs').readFileSync('/o/memory.md','utf8'))"`), []);
  assert.deepEqual(writes(`python3 -c "import sys; sys.stdout.write(open('/o/memory.md').read())"`), []);
  assert.deepEqual(writes(`python3 -c "print(open('/o/memory.md').read())"`), []);
  assert.deepEqual(writes(`node -e "require('fs').writeFileSync('/m/out', require('fs').readFileSync('/o/in'))"`),
    ['/m/out'], 'the write names its target; the read is not one');
  assert.deepEqual(writes(`python3 -c "import shutil; shutil.copy('/m/a','/o/b')"`), ['/o/b'],
    'a copy targets its SECOND argument');
});

test('F4b. a regex .exec is not a shell exec', () => {
  assert.deepEqual(texts(`node -e "const r=/a/.exec('mempalace sync')"`),
    [`node -e 'const r=/a/.exec('\\''mempalace sync'\\'')'`]);
  assert.ok(texts(`node -e "require('child_process').execSync('mempalace sync')"`).includes('mempalace sync'),
    'an unmistakable exec API still is one');
  assert.ok(texts(`python3 -c "import os; os.system('git push')"`).includes('git push'));
});

test('F5. -t / --target-directory inverts the coreutils copiers', () => {
  assert.deepEqual(writes('cp -t /o/results /m/a.md'), ['/o/results/']);
  assert.deepEqual(writes('mv -t /o/inbox /m/msg.json'), ['/o/inbox/']);
  assert.deepEqual(writes('cp --target-directory=/o/results /m/a.md'), ['/o/results/']);
  assert.deepEqual(writes('cp -t /m/results /o/a.md /o/b.md'), ['/m/results/'],
    'and a source is not the destination');
  assert.deepEqual(writes('rsync -a -t /m/src/ /o/dst/'), ['/o/dst/'],
    "rsync's -t means preserve times, so it must not be read as a destination");
});

test('F5b. install -d creates directories; sed --in-place is still in place', () => {
  assert.deepEqual(writes('install -d /o/newdir'), ['/o/newdir']);
  assert.deepEqual(writes('install -m 600 /a/f /b/f'), ['/b/f'], 'the ordinary form is unchanged');
  assert.deepEqual(writes('sed --in-place s/a/b/ /o/memory.md'), ['/o/memory.md']);
  assert.deepEqual(writes('sed --in-place=.bak s/a/b/ /o/memory.md'), ['/o/memory.md']);
  assert.deepEqual(writes('sed --in-place --expression=s/a/b/ /o/memory.md'), ['/o/memory.md']);
});

test('F6. an archiver reads its sources and writes only the archive', () => {
  assert.deepEqual(writes('zip -r /tmp/backup.zip /o/results'), ['/private/tmp/backup.zip']);
  assert.deepEqual(writes('gzip /o/f'), ['/o/f'], 'gzip does replace its operand');
});

test('E. $(echo WORD) is the one substitution resolvable without running it', () => {
  assert.deepEqual(texts('$(echo mempalace) sync'), ['mempalace sync']);
  assert.deepEqual(texts('eval $(echo "mempalace sync")'), ['mempalace sync']);
  assert.deepEqual(texts('`echo mempalace` repair'), ['mempalace repair']);
  assert.deepEqual(texts('$(echo git) push'), ['git push']);
  // Anything whose output we cannot see stays unresolved, and still runs as its own
  // command — this is a documented miss, not a guess.
  assert.deepEqual(texts('$(echo -n mempalace) sync').includes('mempalace sync'), false,
    'echo -n changes the output, so it is not resolved');
  assert.ok(texts('$(cat which) sync').includes('cat which'),
    'an unresolvable substitution is still a command in its own right');
});

// --- 3. honesty and robustness ------------------------------------------------

test('3. an xargs operand we cannot read is reported as unresolved, not invented', () => {
  const [c] = effectiveCommands('cat plan.txt | xargs -I{} mempalace {}', '/work');
  assert.deepEqual(effectiveCommands('cat plan.txt | xargs -I{} mempalace {}', '/work').at(-1).unresolved, ['{}']);
  assert.ok(c, 'the pipeline still parses');
});

test('3b. malformed input never throws and always yields a subject to match', () => {
  for (const cmd of ['', '   ', '"unterminated', "echo 'unclosed", '$(', '`', '>>>', 'cat <<EOF', 'a|||b', '((((']) {
    const r = effectiveCommands(cmd, '/work');
    assert.ok(Array.isArray(r), JSON.stringify(cmd));
  }
});

test('3c. a pathological command is bounded, not unbounded', () => {
  const r = effectiveCommands('true; '.repeat(5000), '/work');
  assert.ok(r.length <= 200, `${r.length} commands`);
});

test('3d. rejoining argv cannot invent a command boundary that was not there', () => {
  assert.deepEqual(texts("grep -n 'a; mempalace sync' f"), ["grep -n 'a; mempalace sync' f"]);
  assert.deepEqual(texts('echo "two  spaces"'), ["echo 'two  spaces'"]);
});
