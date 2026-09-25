/**
 * shell.ts — turn one Bash `command` string into the set of commands it actually
 * runs and the set of paths it actually writes.
 *
 * WHY THIS EXISTS. The PolicyEngine's Bash matchers used to read the raw command
 * string: a regex anchored at `^` or after `;&|`, and nothing at all for paths. A
 * measurement of the three shipped rules against 520 scenarios (md-188) found the
 * engine wrongly ALLOWED 81.5% of the disguised violations — not because the rules
 * were wrong, but because the subject they matched was the wrong string.
 * `sudo mempalace sync`, `eval "mempalace repair"`, `M=mempalace; $M sync`,
 * `/usr/local/bin/mempalace repair` and `bash -c 'mempalace sync'` are all the
 * guarded command; `echo 'never run mempalace sync'` is not. No amount of regex on
 * the raw string separates those, because the distinction is syntactic. So the
 * command is parsed once and the rules match the RESULT.
 *
 * WHAT THIS IS NOT. Not a shell. It does not implement globbing, arithmetic,
 * arrays, process substitution, functions, or `case`; it expands only the variables
 * it can see assigned in the same command. It is a normaliser whose job is to make
 * the common disguises collapse onto the plain form, and to be HONEST about the
 * ones it cannot: an unresolvable target is reported as unresolved rather than
 * silently dropped, so a caller that wants to fail closed can. Every function here
 * is total — it never throws, because the one rule that fails closed would turn a
 * parser bug into a floor-wide deny.
 *
 * WHAT IT DELIBERATELY UNDER-CLAIMS. `curl … | sh`, a command read from a file, a
 * path assembled at run time from something we cannot see: these parse to
 * something harmless and are not caught. That is the same posture as the rest of
 * this feature (see the transport note in policy.ts) — a salience aid against
 * disguise and forgetfulness, not a sandbox against a hostile agent.
 */
import { homedir } from 'node:os';
import { realpathSync } from 'node:fs';
import { isAbsolute, resolve, dirname, basename, sep } from 'node:path';

/** One command the Bash call would actually run. */
export interface EffectiveCommand {
  /** argv after prefix stripping, basename-ing of argv[0] and variable expansion. */
  argv: string[];
  /** argv rejoined, words containing whitespace re-quoted. What `command_matches` sees. */
  text: string;
  /** Absolute paths this command writes. Directory targets keep a trailing `/`. */
  writes: string[];
  /** A write target we could not pin down (an xargs placeholder, an unset variable). */
  unresolved: string[];
}

/** Guards against a pathological command turning one hook call into a hang. */
const MAX_DEPTH = 6;
const MAX_COMMANDS = 200;

/** Prefixes that wrap another command without changing which command it is. */
const TRANSPARENT = new Set([
  'sudo', 'doas', 'nohup', 'command', 'exec', 'time', 'nice', 'ionice',
  'stdbuf', 'setsid', 'caffeinate', 'script',
]);

/** Shell keywords that may lead a segment once `;`/newline splitting is done. */
const KEYWORDS = new Set(['do', 'done', 'then', 'else', 'elif', 'fi', 'esac', 'in', '!', '{', '}']);

/** `cp a b` — the LAST operand is the destination, every earlier one is a source. */
const LAST_ARG_DEST = new Set(['cp', 'mv', 'rsync', 'ln', 'install', 'scp', 'rclone']);

/** Every operand is a target: these verbs only ever mutate what they are given. */
const ALL_ARGS_TARGET = new Set([
  'rm', 'rmdir', 'unlink', 'touch', 'mkdir', 'truncate', 'shred',
  'chmod', 'chown', 'chgrp', 'tee', 'gzip', 'gunzip', 'zip',
]);

/** Interpreters that take a program on the command line instead of a file. */
const SHELL_DASH_C = new Set(['sh', 'bash', 'zsh', 'dash', 'ksh', 'fish']);
const INLINE_SCRIPT: Record<string, string[]> = {
  node: ['-e', '--eval', '-p', '--print'],
  python: ['-c'], python2: ['-c'], python3: ['-c'],
  perl: ['-e', '-E'], ruby: ['-e'], php: ['-r'], deno: ['eval'], bun: ['-e'],
};

/** A write in an inline script. Paired with a path literal from the same script. */
const INLINE_WRITE = /(writeFile|appendFile|createWriteStream|copyFile|rename|mkdir|rmdir|unlink|rmSync|rm\(|truncate|open\s*\([^)]*['"][wax]|\.write\(|shutil\.(copy|move)|os\.remove|os\.rename|>\s*open)/;

type Tok = { t: 'word'; v: string; q: boolean; subs: string[] } | { t: 'op'; v: string };

/**
 * Tokenise, tracking quoting so that a MENTION of a command inside a string stays
 * one word. Heredoc BODIES are consumed and discarded: they are data, and the
 * single largest source of false positives on the raw string was a guarded phrase
 * sitting in a heredoc or an echo.
 */
function tokenise(src: string): Tok[] {
  const out: Tok[] = [];
  let word = '';
  let quoted = false;
  let started = false;
  const subs: string[] = [];
  const pendingHeredocs: Array<{ delim: string; strip: boolean }> = [];

  const flush = () => {
    if (started) out.push({ t: 'word', v: word, q: quoted, subs: subs.slice() });
    word = ''; quoted = false; started = false; subs.length = 0;
  };
  const op = (v: string) => { flush(); out.push({ t: 'op', v }); };

  let i = 0;
  while (i < src.length) {
    const c = src[i];

    if (c === '\n' && pendingHeredocs.length) {
      // Swallow every queued heredoc body before resuming.
      op('\n');
      i++;
      while (pendingHeredocs.length) {
        const { delim, strip } = pendingHeredocs.shift()!;
        for (;;) {
          const nl = src.indexOf('\n', i);
          const line = src.slice(i, nl === -1 ? src.length : nl);
          i = nl === -1 ? src.length : nl + 1;
          if ((strip ? line.trim() : line) === delim || nl === -1) break;
        }
      }
      continue;
    }

    if (c === '\\' && i + 1 < src.length) {
      // A backslash-newline is a line continuation, not a character.
      if (src[i + 1] === '\n') { i += 2; continue; }
      started = true; word += src[i + 1]; i += 2; continue;
    }
    if (c === "'") {
      started = true; quoted = true;
      const end = src.indexOf("'", i + 1);
      word += src.slice(i + 1, end === -1 ? src.length : end);
      i = end === -1 ? src.length : end + 1;
      continue;
    }
    if (c === '"') {
      started = true; quoted = true;
      i++;
      while (i < src.length && src[i] !== '"') {
        if (src[i] === '\\' && i + 1 < src.length) { word += src[i + 1]; i += 2; continue; }
        if (src[i] === '$' && src[i + 1] === '(') { const [body, next] = readBalanced(src, i + 2, '(', ')'); subs.push(body); i = next; continue; }
        if (src[i] === '`') { const end = src.indexOf('`', i + 1); subs.push(src.slice(i + 1, end === -1 ? src.length : end)); i = end === -1 ? src.length : end + 1; continue; }
        word += src[i]; i++;
      }
      i++;
      continue;
    }
    if (c === '$' && src[i + 1] === '(') { started = true; const [body, next] = readBalanced(src, i + 2, '(', ')'); subs.push(body); i = next; continue; }
    if (c === '`') { started = true; const end = src.indexOf('`', i + 1); subs.push(src.slice(i + 1, end === -1 ? src.length : end)); i = end === -1 ? src.length : end + 1; continue; }

    if (c === ' ' || c === '\t' || c === '\r') { flush(); i++; continue; }
    if (c === '\n') { op('\n'); i++; continue; }
    if (c === ';') { op(src[i + 1] === ';' ? ';;' : ';'); i += src[i + 1] === ';' ? 2 : 1; continue; }
    if (c === '&') {
      if (src[i + 1] === '&') { op('&&'); i += 2; continue; }
      if (src[i + 1] === '>') { const two = src[i + 2] === '>'; op('>'); i += two ? 3 : 2; continue; }
      op('&'); i++; continue;
    }
    if (c === '|') { op(src[i + 1] === '|' ? '||' : '|'); i += src[i + 1] === '|' ? 2 : 1; continue; }
    if (c === '(' || c === ')') { op(c); i++; continue; }
    if (c === '{' || c === '}') {
      // Only a standalone brace is a group; `{}` inside a word (xargs) is a word.
      const alone = !started && (i + 1 >= src.length || /[\s;&|]/.test(src[i + 1] ?? ' '));
      if (alone) { op(c); i++; continue; }
      started = true; word += c; i++; continue;
    }
    if (c === '<') {
      if (src.startsWith('<<<', i)) { op('<<<'); i += 3; continue; }
      if (src.startsWith('<<', i)) {
        const strip = src[i + 2] === '-';
        i += strip ? 3 : 2;
        while (src[i] === ' ' || src[i] === '\t') i++;
        let delim = '';
        while (i < src.length && !/[\s;&|<>]/.test(src[i])) { if (src[i] !== '"' && src[i] !== "'") delim += src[i]; i++; }
        pendingHeredocs.push({ delim, strip });
        continue;
      }
      op('<'); i++; continue;
    }
    if (c === '>') {
      // A leading fd number belongs to the redirection, not to the next word.
      if (/^\d+$/.test(word) && started) { word = ''; started = false; }
      if (src[i + 1] === '>') { op('>>'); i += 2; continue; }
      op(src[i + 1] === '|' ? '>' : '>'); i += src[i + 1] === '|' ? 2 : 1; continue;
    }
    started = true; word += c; i++;
  }
  flush();
  while (pendingHeredocs.length) pendingHeredocs.pop();
  return out;
}

/** Read to the matching close, honouring nesting. Returns [body, indexAfterClose]. */
function readBalanced(src: string, from: number, open: string, close: string): [string, number] {
  let depth = 1;
  let i = from;
  for (; i < src.length; i++) {
    if (src[i] === open) depth++;
    else if (src[i] === close) { depth--; if (!depth) break; }
  }
  return [src.slice(from, i), i + 1];
}

interface Ctx {
  env: Map<string, string>;
  cwd: string;
  depth: number;
  out: EffectiveCommand[];
}

/**
 * Names taken from this process's environment when a command does not assign them.
 *
 * Deliberately a fixed list of machine-wide ones. The daemon's environment is NOT
 * the agent shell's: expanding an arbitrary `$AGENT_DIR` or `$HIVE_ROOT` from here
 * would substitute a value the command never had and judge a path nobody wrote.
 * These six are the same for every process of this user, so using them is reading
 * the same variable the shell would.
 */
const AMBIENT = ['HOME', 'TMPDIR', 'TMP', 'TEMP', 'USER', 'LOGNAME'];

/** Flags that swallow the next word, so its value is not mistaken for an operand. */
const VALUE_FLAGS: Record<string, Set<string>> = {
  sed: new Set(['-e', '-f', '-l', '--expression', '--file']),
  install: new Set(['-m', '-o', '-g', '--mode', '--owner', '--group']),
  rsync: new Set(['--exclude', '--include', '--files-from', '-e']),
  tee: new Set(['--output-error']),
};

/** Operands that are not paths: chmod's mode, chown's owner. */
const SKIP_FIRST_OPERAND = new Set(['chmod', 'chown', 'chgrp']);

/** Expand `~`, `$NAME` and `${NAME}` from what we have seen assigned. Unknown names
 *  are left as written: an unset variable silently becoming '' would turn
 *  `rm -rf "$DIR"/x` into a different path than the one the rule should judge. */
function expand(word: string, env: Map<string, string>): string {
  let out = word.replace(/\$\{(\w+)\}|\$(\w+)/g, (m, a, b) => {
    const name = a ?? b;
    const v = env.get(name) ?? (AMBIENT.includes(name) ? process.env[name] : undefined);
    return v === undefined ? m : v;
  });
  if (out === '~') out = homedir();
  else if (out.startsWith('~/')) out = homedir() + out.slice(1);
  return out;
}

/** Single-quote a word that contains whitespace, so rejoining argv cannot invent a
 *  command boundary that was not there — `grep -n 'mempalace sync' f` must not read
 *  as a `mempalace sync` invocation. */
function requote(w: string): string {
  return /[\s]/.test(w) || w === '' ? `'${w.split("'").join("'\\''")}'` : w;
}

/** Absolute, symlink-resolved form, keeping a trailing `/` to mean "inside here".
 *  Resolves the longest existing prefix so a path that does not exist yet (the
 *  usual case for a write) still normalises through any symlinked parent. */
export function realAbsolute(p: string, cwd: string): string {
  const trailing = /[/\\]$/.test(p);
  let abs = isAbsolute(p) ? resolve(p) : resolve(cwd, p);
  const parts: string[] = [];
  let probe = abs;
  for (let i = 0; i < 64; i++) {
    try { probe = realpathSync(probe); break; } catch { /* does not exist yet */ }
    const parent = dirname(probe);
    if (parent === probe) break;
    parts.unshift(basename(probe));
    probe = parent;
  }
  abs = parts.length ? resolve(probe, ...parts) : probe;
  const fwd = sep === '\\' ? abs.replace(/\\/g, '/') : abs;
  return trailing && !fwd.endsWith('/') ? fwd + '/' : fwd;
}

/**
 * Parse one Bash command string into the commands it runs.
 *
 * Returns at most MAX_COMMANDS entries. When parsing yields nothing at all the raw
 * string is handed back as a single command, so a caller's regex still has a
 * subject — degrading to the old behaviour rather than to "no command at all".
 */
export function effectiveCommands(command: string, cwd = process.cwd()): EffectiveCommand[] {
  const ctx: Ctx = { env: new Map(), cwd, depth: 0, out: [] };
  try {
    walk(tokenise(command), ctx);
  } catch {
    // Total by contract: a parser bug must not reach a rule with on_error: deny.
  }
  if (!ctx.out.length) {
    const argv = command.trim().split(/\s+/).filter(Boolean);
    return [{ argv, text: command.trim(), writes: [], unresolved: [] }];
  }
  return ctx.out;
}

/** Split a token stream on control operators and dispatch each simple command. */
function walk(toks: Tok[], ctx: Ctx): void {
  if (ctx.depth > MAX_DEPTH) return;
  let seg: Tok[] = [];
  const flush = () => { if (seg.length) simple(seg, ctx); seg = []; };
  for (let i = 0; i < toks.length; i++) {
    const t = toks[i];
    if (t.t === 'op' && (t.v === '(' || t.v === '{')) {
      const close = t.v === '(' ? ')' : '}';
      let depth = 1, j = i + 1;
      for (; j < toks.length; j++) {
        const u = toks[j];
        if (u.t === 'op' && u.v === t.v) depth++;
        else if (u.t === 'op' && u.v === close) { depth--; if (!depth) break; }
      }
      flush();
      walk(toks.slice(i + 1, j), { ...ctx, depth: ctx.depth + 1 });
      i = j;
      continue;
    }
    if (t.t === 'op' && [';', ';;', '&&', '||', '|', '&', '\n', ')', '}'].includes(t.v)) { flush(); continue; }
    seg.push(t);
  }
  flush();
}

/** One simple command: assignments, redirections, wrapper unwrapping, then record. */
function simple(toks: Tok[], ctx: Ctx): void {
  if (ctx.out.length >= MAX_COMMANDS) return;
  const argv: string[] = [];
  const redirects: string[] = [];
  let herestring: string | null = null;
  const subs: string[] = [];
  let leading = true;

  for (let i = 0; i < toks.length; i++) {
    const t = toks[i];
    if (t.t === 'op') {
      const target = toks[i + 1];
      if ((t.v === '>' || t.v === '>>') && target?.t === 'word') { redirects.push(expand(target.v, ctx.env)); i++; continue; }
      if (t.v === '<<<' && target?.t === 'word') { herestring = expand(target.v, ctx.env); i++; continue; }
      if (t.v === '<' && target?.t === 'word') { i++; continue; } // a read
      continue;
    }
    for (const s of t.subs) subs.push(s);
    if (leading && !t.q && /^\w+=/.test(t.v)) {
      const eq = t.v.indexOf('=');
      ctx.env.set(t.v.slice(0, eq), expand(t.v.slice(eq + 1), ctx.env));
      continue;
    }
    const w = expand(t.v, ctx.env);
    if (leading && !argv.length && KEYWORDS.has(w)) continue; // `do mempalace sync` → `mempalace sync`
    leading = false;
    argv.push(w);
  }

  // `$(…)` and backticks run their own commands, whatever the outer one does.
  for (const s of subs) walk(tokenise(s), { ...ctx, depth: ctx.depth + 1 });

  if (!argv.length) {
    if (redirects.length) record(ctx, [], redirects, []);
    return;
  }
  dispatch(argv, redirects, herestring, ctx);
}

/** Resolve wrappers down to the command that actually runs, then record it. */
function dispatch(argv: string[], redirects: string[], herestring: string | null, ctx: Ctx): void {
  if (ctx.depth > MAX_DEPTH || ctx.out.length >= MAX_COMMANDS) return;
  const deeper = { ...ctx, depth: ctx.depth + 1 };

  // `for c in sync; do …` arrives as the segment `for c in sync`: bind the loop
  // variable so the body's `$c` expands. One binding per value, first wins.
  if (argv[0] === 'for' && argv[1] && argv[2] === 'in' && argv[3]) { ctx.env.set(argv[1], argv[3]); return; }
  if (argv[0] === 'while' || argv[0] === 'until' || argv[0] === 'if' || argv[0] === 'case') {
    return dispatch(argv.slice(1), redirects, herestring, ctx);
  }

  let head = argv[0];

  // env VAR=v cmd … — the assignments are this command's, not the shell's.
  if (head === 'env') {
    let i = 1;
    while (i < argv.length && /^\w+=/.test(argv[i])) { const eq = argv[i].indexOf('='); ctx.env.set(argv[i].slice(0, eq), argv[i].slice(eq + 1)); i++; }
    while (i < argv.length && argv[i].startsWith('-')) i++;
    if (i < argv.length) return dispatch(argv.slice(i), redirects, herestring, ctx);
    return;
  }
  if (TRANSPARENT.has(basename(head))) {
    let i = 1;
    while (i < argv.length && argv[i].startsWith('-')) i++;
    if (i < argv.length) return dispatch(argv.slice(i), redirects, herestring, ctx);
    return;
  }
  if (basename(head) === 'timeout') {
    let i = 1;
    while (i < argv.length && (argv[i].startsWith('-') || /^[\d.]+[smhd]?$/.test(argv[i]))) i++;
    if (i < argv.length) return dispatch(argv.slice(i), redirects, herestring, ctx);
    return;
  }
  if (basename(head) === 'eval') {
    walk(tokenise(argv.slice(1).join(' ')), deeper);
    return;
  }
  if (basename(head) === 'xargs') {
    // The inner command is the first non-flag operand; `-I TOKEN` names a
    // placeholder that stdin fills. A herestring is the one stdin we can read.
    let i = 1, token: string | null = null;
    while (i < argv.length && argv[i].startsWith('-')) {
      const m = /^-I(.*)$/.exec(argv[i]);
      if (m) token = m[1] || argv[++i] || null;
      else if (argv[i] === '-n' || argv[i] === '-P' || argv[i] === '-d') i++;
      i++;
    }
    const inner = argv.slice(i);
    if (!inner.length) return;
    const words = herestring === null ? null : herestring.split(/\s+/).filter(Boolean);
    if (token && words) return dispatch(inner.flatMap((a) => (a === token ? words : [a])), redirects, null, ctx);
    if (!token && words) return dispatch([...inner, ...words], redirects, null, ctx);
    // stdin we cannot see: record it as it stands and say the operand is unknown.
    record(ctx, inner, redirects, token ? [token] : ['<stdin>']);
    return;
  }

  const base = basename(head);
  if (SHELL_DASH_C.has(base)) {
    const ci = argv.findIndex((a, k) => k > 0 && (a === '-c' || a === '-lc' || a === '-cl'));
    if (ci !== -1 && argv[ci + 1] !== undefined) { walk(tokenise(argv[ci + 1]), deeper); return; }
  }
  if ((base === 'python' || base === 'python3' || base === 'python2') && argv[1] === '-m' && argv[2]) {
    // `python3 -m mempalace sync` IS `mempalace sync`.
    return dispatch([argv[2], ...argv.slice(3)], redirects, herestring, ctx);
  }
  const inlineFlags = INLINE_SCRIPT[base];
  if (inlineFlags) {
    const fi = argv.findIndex((a, k) => k > 0 && inlineFlags.includes(a));
    if (fi !== -1 && argv[fi + 1] !== undefined) {
      const script = argv[fi + 1];
      record(ctx, [base, ...argv.slice(1)], [...redirects, ...inlineTargets(script)], []);
      return;
    }
  }
  if (base === 'cd' && argv[1]) { ctx.cwd = realAbsolute(argv[1], ctx.cwd); record(ctx, [base, ...argv.slice(1)], redirects, []); return; }

  // `git -C dir …` runs in dir; it writes no path we track, but a later command in
  // the same line does not inherit that, so only argv is normalised here.
  record(ctx, [base, ...argv.slice(1)], [...redirects, ...verbTargets(base, argv)], []);
}

/** Paths a known mutating verb writes, given its argv. */
function verbTargets(base: string, argv: string[]): string[] {
  const takesValue = VALUE_FLAGS[base] ?? new Set<string>();
  const operands: string[] = [];
  const flags: string[] = [];
  for (let i = 1; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('-') && a !== '-') {
      flags.push(a);
      // `sed -e s/a/b/ f` — the script is the flag's value, not a file to rewrite.
      if (takesValue.has(a)) i++;
      continue;
    }
    operands.push(a);
  }
  if (base === 'sed') {
    if (!flags.some((f) => /^-[a-zA-Z]*i/.test(f))) return [];
    // BSD `sed -i '' script file` leaves an empty operand; the script is the first
    // real operand unless -e/-f already supplied it.
    const real = operands.filter((o) => o !== '');
    const suppliedScript = flags.some((f) => f === '-e' || f === '-f' || f === '--expression' || f === '--file');
    return suppliedScript ? real : real.slice(1);
  }
  if (base === 'dd') return argv.filter((a) => a.startsWith('of=')).map((a) => a.slice(3));
  if (ALL_ARGS_TARGET.has(base)) return SKIP_FIRST_OPERAND.has(base) ? operands.slice(1) : operands;
  if (LAST_ARG_DEST.has(base)) return operands.length >= 2 ? [operands[operands.length - 1]] : [];
  return [];
}

/** Path-looking literals in an inline script, but only when the script also writes. */
function inlineTargets(script: string): string[] {
  if (!INLINE_WRITE.test(script)) return [];
  const out: string[] = [];
  for (const m of script.matchAll(/['"]([^'"\n]*\/[^'"\n]*)['"]/g)) out.push(m[1]);
  return out;
}

function record(ctx: Ctx, argv: string[], writes: string[], unresolved: string[]): void {
  if (ctx.out.length >= MAX_COMMANDS) return;
  ctx.out.push({
    argv,
    text: argv.map(requote).join(' '),
    writes: writes.map((w) => realAbsolute(w, ctx.cwd)),
    unresolved,
  });
}
