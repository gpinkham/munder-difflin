/**
 * Where a `git push` lands (HAG-53).
 *
 * A rule that names protected branches in a regex catches `git push origin master`
 * and misses `git push` run from master, which names no branch at all: git picks the
 * destination from the current branch, push.default, the upstream and
 * remote.<name>.push. This reads the same things git reads, in the repo the push
 * runs in, and returns the branches the push would update.
 *
 * Opt-in: nothing here runs unless a loaded rule uses `push_destination`, and then
 * only for a command that is a git push.
 *
 * It errs one way. Anything it cannot read the way git would - an unknown flag, a
 * variable, an environment override, a git that fails or hangs - THROWS, and the
 * engine applies the rule's on_error. Where git itself would refuse the push, the
 * branch it names is still returned: a false deny costs a retry, a miss costs master.
 */

import { execFileSync } from 'node:child_process';
import { isAbsolute, join } from 'node:path';

/** How the matcher runs git. Injected by tests. */
export interface PushGit {
  /** stdout of `git -C <dir> <args>`; null when git exits 1 (detached HEAD).
   *  Throws on any other failure, including running past `timeoutMs`. */
  run(dir: string, args: string[], timeoutMs: number): string | null;
  /** The clock the shared deadline is measured on. Tests supply one. */
  now?(): number;
}

/** One deadline for every git call a push costs. This runs on the main process,
 *  so a hung git must not stall it for longer than this. */
const BUDGET_MS = 3000;

export const realPushGit: PushGit = {
  run(dir, args, timeoutMs) {
    try {
      return execFileSync('git', ['-C', dir, ...args], {
        timeout: timeoutMs, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'],
      });
    } catch (e) {
      if ((e as { status?: number }).status === 1) return null;
      throw e;
    }
  },
};

/** `any`: the push can reach every branch (--mirror, a wildcard destination). */
export type PushTargets = { any: true } | { any: false; branches: string[] };

/** Global options that change nothing about where a push goes. */
const GLOBAL_NOOP = new Set([
  '-p', '--paginate', '-P', '--no-pager', '--no-replace-objects', '--bare', '--literal-pathspecs',
  '--glob-pathspecs', '--noglob-pathspecs', '--icase-pathspecs', '--no-optional-locks', '--no-advice',
]);

/** push flags that take no value, and the short ones that may be clustered. */
const PUSH_FLAGS = new Set([
  '--all', '--branches', '--mirror', '--tags', '--follow-tags', '--no-follow-tags', '--atomic', '--no-atomic',
  '--dry-run', '--porcelain', '--delete', '--force', '--no-force', '--prune', '--no-prune', '--verify', '--no-verify',
  '--progress', '--no-progress', '--quiet', '--verbose', '--set-upstream', '--thin', '--no-thin', '--ipv4', '--ipv6',
  '--signed', '--no-signed', '--force-with-lease', '--no-force-with-lease', '--force-if-includes',
  '--no-force-if-includes', '--recurse-submodules', '--no-recurse-submodules',
]);
const PUSH_VALUED = new Set(['--repo', '--receive-pack', '--exec', '--push-option']);
const PUSH_ATTACHED = /^--(repo|receive-pack|exec|push-option|force-with-lease|signed|recurse-submodules)=/;
const SHORT = new Set(['v', 'q', 'n', 'f', 'u', 'd', '4', '6']);

/** -c keys that can change where a push lands (an include can set any of them);
 *  any other -c is not passed to git. */
const RELEVANT_KEY = /^(push|remote|branch|include|includeif)\./i;

const unreadable = (why: string): never => { throw new Error(`push destination unknown: ${why}`); };
const noVar = (w: string, what: string) => {
  if (w.includes('$')) unreadable(`${what} holds a variable (${w})`);
  // The parser does not expand braces: {feat,master} is two refspecs to the shell.
  // Everything between the first { and the last }: nested groups count too, since
  // bash expands HEAD:{{a}x,master} to HEAD:master (Dwight). No regex, so a crafted
  // `{,{,{,…` cannot make it backtrack (the single regex this replaced was cubic).
  const open = w.indexOf('{');
  const close = w.lastIndexOf('}');
  const inner = open >= 0 && close > open ? w.slice(open + 1, close) : '';
  if (inner.includes(',') || inner.includes('..')) unreadable(`${what} uses brace expansion (${w.slice(0, 80)})`);
};

/**
 * The branches a parsed git command would push to, or null when it is not a push
 * (or is a dry run). `cwd` is the directory the command runs in, or null if unknown.
 */
export function pushTargets(argv: string[], cwd: string | null, git: PushGit = realPushGit): PushTargets | null {
  if (argv[0] !== 'git') return null;
  const isPush = () => argv.includes('push');
  let dir = cwd;
  const pre: string[] = []; // global options passed to every git call we make
  let i = 1;
  for (; i < argv.length && argv[i].startsWith('-'); i++) {
    const a = argv[i];
    if (a === '-C') {
      const d = argv[++i];
      if (d === undefined) return isPush() ? unreadable('-C needs a directory') : null;
      noVar(d, '-C');
      dir = isAbsolute(d) ? d : dir ? join(dir, d) : null;
    } else if (a === '-c') {
      const kv = argv[++i];
      if (kv === undefined) return isPush() ? unreadable('-c needs key=value') : null;
      // `git -c alias.p=push p` pushes with no "push" word to find (Dwight, HAG-53).
      if (/^alias\./i.test(kv)) unreadable('an inline alias');
      if (RELEVANT_KEY.test(kv)) { noVar(kv, '-c'); pre.push('-c', kv); }
    } else if (a === '--git-dir' || a.startsWith('--git-dir=')) {
      const d = a === '--git-dir' ? argv[++i] : a.slice('--git-dir='.length);
      if (d === undefined) return isPush() ? unreadable('--git-dir needs a directory') : null;
      noVar(d, '--git-dir');
      pre.push(`--git-dir=${isAbsolute(d) || !dir ? d : join(dir, d)}`);
    } else if (a === '--work-tree') {
      i++;
    } else if (a.startsWith('--work-tree=') || GLOBAL_NOOP.has(a)) {
      // no effect on the destination
    } else {
      // --namespace, --config-env, --exec-path=… or something new: we cannot tell
      // what it changes, or even whether the next word is its value.
      // --config-env can define an alias, so it is unreadable push or not.
      return isPush() || a.startsWith('--config-env') ? unreadable(`global option ${a}`) : null;
    }
  }
  if (argv[i] !== 'push') return null;

  let mirror = false, all = false, del = false, prune = false, dry = false, repoOpt: string | null = null;
  const pos: string[] = [];
  for (i++; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--') { pos.push(...argv.slice(i + 1)); break; }
    if (!a.startsWith('-') || a === '-') { pos.push(a); continue; }
    // The last of -n / --dry-run / --no-dry-run wins, as in git (Dwight, HAG-50).
    if (a === '--dry-run') { dry = true; continue; }
    if (a === '--no-dry-run') { dry = false; continue; }
    if (a.startsWith('--')) {
      if (PUSH_VALUED.has(a)) { const v = argv[++i]; if (a === '--repo') repoOpt = v ?? null; continue; }
      if (PUSH_ATTACHED.test(a)) { if (a.startsWith('--repo=')) repoOpt = a.slice(7); continue; }
      if (!PUSH_FLAGS.has(a)) unreadable(`push option ${a}`);
      if (a === '--mirror') mirror = true;
      else if (a === '--all' || a === '--branches') all = true;
      else if (a === '--delete') del = true;
      else if (a === '--prune') prune = true;
      continue;
    }
    // A short cluster: -fu, -nq, -o <value>, -ovalue.
    for (let k = 1; k < a.length; k++) {
      const c = a[k];
      if (c === 'o') { if (k === a.length - 1) i++; break; }
      if (!SHORT.has(c)) unreadable(`push option -${c}`);
      if (c === 'n') dry = true;
      if (c === 'd') del = true;
    }
  }
  if (dry) return null;
  if (mirror || prune) return { any: true }; // both can delete any remote branch
  if (!dir) unreadable('the working directory is unknown');
  for (const w of pos) noVar(w, 'the push');

  const clock = () => (git.now ? git.now() : Date.now());
  const start = clock();
  const run = (args: string[]) => {
    const left = BUDGET_MS - (clock() - start);
    if (left <= 0) unreadable('git took too long');
    return git.run(dir!, [...pre, ...args], Math.min(2000, left));
  };
  // Two calls, whatever the push: the branch, then the whole effective config (with
  // the -c overrides and includes applied, as git applies them).
  const cur = run(['symbolic-ref', '-q', '--short', 'HEAD'])?.trim() || null;
  const config = readConfig(run(['config', '--list', '-z']) ?? '');
  const cfgAll = (key: string) => config.get(configKey(key)) ?? [];
  const cfg = (key: string): string | null => { const v = cfgAll(key); return v.length ? v[v.length - 1] : null; };
  const locals = () => (run(['for-each-ref', '--format=%(refname:short)', 'refs/heads/']) ?? '').split('\n').filter(Boolean);

  const repo = pos[0] ?? repoOpt ?? ((cur && cfg(`branch.${cur}.pushRemote`)) || cfg('remote.pushDefault')
    || (cur && cfg(`branch.${cur}.remote`)) || 'origin');
  // A URL or a path has no remote.<name>.push.
  const isName = !/[:/\\]/.test(repo) && repo !== '.';
  const configured = isName ? cfgAll(`remote.${repo}.push`) : [];
  const refspecs = pos.slice(1);

  // remote.<name>.mirror makes a plain push behave as --mirror.
  if (isName && /^(?:true|yes|on|1|)$/i.test(cfg(`remote.${repo}.mirror`) ?? 'false')) return { any: true };
  if (all) return { any: false, branches: locals() };

  const out = new Set<string>();
  let any = false;
  const land = (dst: string) => {
    if (dst.includes('*')) { any = true; return; }
    if (dst === 'HEAD' || dst === '@') { if (cur) out.add(cur); return; }
    if (dst.startsWith('refs/heads/')) out.add(dst.slice('refs/heads/'.length));
    // git also resolves heads/<name> to refs/heads/<name> (Dwight, HAG-50).
    else if (dst.startsWith('heads/')) out.add(dst.slice('heads/'.length));
    else if (!/^(?:refs|tags|remotes)\//.test(dst)) out.add(dst); // a short name: taken as a branch
  };
  const split = (spec: string): [string, string | null] => {
    const s = spec.replace(/^\+/, '');
    const at = s.indexOf(':');
    return at < 0 ? [s, null] : [s.slice(0, at), s.slice(at + 1)];
  };

  if (!refspecs.length && !del) {
    if (configured.length) {
      for (const spec of configured) { const [src, dst] = split(spec); land(dst || src); }
    } else {
      const mode = (cfg('push.default') ?? 'simple').toLowerCase();
      const merge = cur ? cfg(`branch.${cur}.merge`) : null;
      if (mode === 'nothing') { /* pushes nothing */ }
      else if (mode === 'current') { if (cur) out.add(cur); }
      else if (mode === 'upstream' || mode === 'tracking') { if (merge) land(merge); }
      else if (mode === 'simple') { if (cur) out.add(cur); if (merge) land(merge); }
      else if (mode === 'matching') { for (const b of locals()) out.add(b); }
      else unreadable(`push.default is ${mode}`);
    }
  }
  for (const spec of refspecs) {
    if (del) { land(spec); continue; }
    const [src, dst] = split(spec);
    if (dst) { land(dst); continue; }
    const name = src === 'HEAD' || src === '@' ? cur : src;
    if (!name) continue; // detached HEAD with no destination: git refuses
    land(name);
    // `git push origin feat` with a remote.origin.push mapping for feat lands where
    // the mapping says, not on feat.
    for (const c of configured) {
      const [cs, cd] = split(c);
      if (!cd) continue;
      if (cd.includes('*')) { any = true; continue; }
      if (cs === name || cs === `refs/heads/${name}` || ((cs === 'HEAD' || cs === '@') && name === cur)) land(cd);
    }
  }
  return any ? { any: true } : { any: false, branches: [...out] };
}

/** A branch glob as a regex: `*` is any run of characters, `/` included. */
export function branchGlob(glob: string): RegExp {
  return new RegExp('^' + glob.split('*').map((p) => p.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('.*') + '$');
}

/**
 * A call that changes which repo or config git reads: GIT_DIR/GIT_CONFIG_*, HOME and
 * XDG_CONFIG_HOME (the global config), or env with an option (-i clears the
 * environment, -C moves the directory). The parser drops all of these.
 */
export const ENV_OVERRIDE =
  /(?:^|[\s;&|(])(?:export\s+)?(?:GIT_(?:DIR|WORK_TREE|COMMON_DIR|NAMESPACE|CONFIG\w*|INDEX_FILE)|HOME|XDG_CONFIG_HOME)=|(?:^|[\s;&|(])env\s+-/;

/** `git config --list -z`: key NUL-terminated entries, value after the first newline;
 *  a key with no value is a boolean true. */
function readConfig(out: string): Map<string, string[]> {
  const m = new Map<string, string[]>();
  for (const entry of out.split('\0')) {
    if (!entry) continue;
    const nl = entry.indexOf('\n');
    const key = configKey(nl < 0 ? entry : entry.slice(0, nl));
    const value = nl < 0 ? '' : entry.slice(nl + 1);
    m.set(key, [...(m.get(key) ?? []), value]);
  }
  return m;
}

/** Section and variable names are case-insensitive; a subsection is not. */
function configKey(key: string): string {
  const first = key.indexOf('.');
  const last = key.lastIndexOf('.');
  if (first < 0) return key.toLowerCase();
  if (first === last) return key.toLowerCase();
  return key.slice(0, first).toLowerCase() + key.slice(first, last) + key.slice(last).toLowerCase();
}
