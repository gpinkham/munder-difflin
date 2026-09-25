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

/**
 * Something in this command the parser could not pin down.
 *
 * `code` is a STABLE identifier, meant to be grepped and counted in the ledger — it
 * is part of this module's contract, so renaming one is a schema change.
 *
 * `detail` is a STRUCTURAL token only: a placeholder, a program or variable NAME, or
 * a path. Never an argument value. That line exists because these rows are written to
 * a file an operator reads, and a command's arguments carry file contents, tokens and
 * secrets — the same reason `policy.ts` logs a digest of a tool input rather than the
 * input. A program name tells a reader what happened; its arguments do not need to.
 */
export type UnresolvedCode =
  /** An operand arrives on stdin we cannot read — `cat plan | xargs mempalace`. */
  | 'stdin_operand'
  /** A word is the OUTPUT of another command — `$(cat which) sync`. */
  | 'substitution_output'
  /** The program itself arrives on a pipe — `curl -s … | sh`. */
  | 'piped_program'
  /** The program is a file we do not read — `bash ./deploy.sh`, `source env.sh`. */
  | 'program_from_file'
  /** The command defines a name whose expansion we will never see — `alias gp=…`. */
  | 'alias_definition'
  /** A path still holds a variable we never saw assigned — `$AGENT_DIR/memory.md`. */
  | 'unexpanded_variable';

export interface Unresolved {
  code: UnresolvedCode;
  /** A placeholder, program name, variable name or path — never an argument value. */
  detail: string;
}

/** One command the Bash call would actually run. */
export interface EffectiveCommand {
  /** argv after prefix stripping, basename-ing of argv[0] and variable expansion. */
  argv: string[];
  /** argv rejoined, words containing whitespace re-quoted. What `command_matches` sees. */
  text: string;
  /** Absolute paths this command writes. Directory targets keep a trailing `/`. */
  writes: string[];
  /** What this command hides from us. Logged, never enforced on — see policy.ts. */
  unresolved: Unresolved[];
}

/** Guards against a pathological command turning one hook call into a hang. */
const MAX_DEPTH = 6;
const MAX_COMMANDS = 200;

/**
 * Prefixes that wrap another command without changing which command it is, and the
 * flags of each that swallow the next word.
 *
 * The value table is the whole point: skipping flags but not their arguments buries
 * the real command one word deeper, so `sudo -u gpinkham mempalace sync` parses as
 * `gpinkham mempalace sync` — a command name no rule describes, with no write
 * targets. `sudo -u` is the ordinary spelling of sudo, so that is not an edge case:
 * it defeated all three rules at once, and `cp` buried that way contributed nothing
 * for path_glob to judge.
 *
 * `firstOperandIsFile` is for `script`, whose typescript file sits between the flags
 * and the command it records.
 */
const TRANSPARENT: Record<string, { values: Set<string>; firstOperandIsFile?: boolean }> = {
  sudo: { values: new Set(['-u', '-g', '-U', '-p', '-C', '-h', '-r', '-t', '-T', '--user', '--group', '--prompt', '--close-from', '--host', '--role', '--type']) },
  doas: { values: new Set(['-a', '-C', '-u']) },
  nohup: { values: new Set() },
  command: { values: new Set() },
  exec: { values: new Set(['-a']) },
  time: { values: new Set(['-o', '-f', '--output', '--format']) },
  nice: { values: new Set(['-n', '--adjustment']) },
  ionice: { values: new Set(['-c', '-n', '-p', '-P', '--class', '--classdata', '--pid']) },
  stdbuf: { values: new Set(['-i', '-o', '-e', '--input', '--output', '--error']) },
  setsid: { values: new Set() },
  caffeinate: { values: new Set(['-t', '-w']) },
  script: { values: new Set(['-F', '-t', '-T', '--command', '--logfile']), firstOperandIsFile: true },
};

/** Shell keywords that may lead a segment once `;`/newline splitting is done. */
const KEYWORDS = new Set(['do', 'done', 'then', 'else', 'elif', 'fi', 'esac', 'in', '!', '{', '}']);

/** `cp a b` — the LAST operand is the destination, every earlier one is a source. */
const LAST_ARG_DEST = new Set(['cp', 'mv', 'rsync', 'ln', 'install', 'scp', 'rclone', 'ditto']);

/** Unpackers whose destination is a `-C`/`-d` directory rather than an operand. */
const DEST_FLAG: Record<string, { flags: string[]; needsExtract: boolean }> = {
  tar: { flags: ['-C', '--directory'], needsExtract: true },
  bsdtar: { flags: ['-C', '--directory'], needsExtract: true },
  unzip: { flags: ['-d'], needsExtract: false },
};

/** Every operand is a target: these verbs only ever mutate what they are given. */
const ALL_ARGS_TARGET = new Set([
  'rm', 'rmdir', 'unlink', 'touch', 'mkdir', 'truncate', 'shred',
  'chmod', 'chown', 'chgrp', 'tee', 'gzip', 'gunzip',
]);

/** Archivers whose FIRST operand is the archive and the rest are sources being read.
 *  `zip` sat in ALL_ARGS_TARGET, so `zip -r /tmp/backup.zip <other>/results` counted
 *  a read-only archive of someone else's folder as a write to it. */
const ARCHIVE_FIRST_ARG = new Set(['zip', 'jar']);

/**
 * `-t DIR` / `--target-directory=DIR` inverts the coreutils copiers: the destination
 * comes first, as a flag value, and EVERY operand is a source. Both readings were
 * wrong — `cp -t <other>/results mine.md` was allowed, and `cp -t mine/ <other>/a.md
 * <other>/b.md` was DENIED because the last source was read as the destination.
 *
 * Only the coreutils verbs: rsync's `-t` means "preserve times", so reading it as a
 * destination would invent a target out of a source.
 */
const TARGET_DIR_VERBS = new Set(['cp', 'mv', 'ln', 'install']);
const TARGET_DIR_FLAGS = ['-t', '--target-directory'];

/** Interpreters that take a program on the command line instead of a file. */
const SHELL_DASH_C = new Set(['sh', 'bash', 'zsh', 'dash', 'ksh', 'fish']);
const INLINE_SCRIPT: Record<string, string[]> = {
  node: ['-e', '--eval', '-p', '--print'],
  python: ['-c'], python2: ['-c'], python3: ['-c'],
  perl: ['-e', '-E'], ruby: ['-e'], php: ['-r'], deno: ['eval'], bun: ['-e'],
};

/**
 * Ways an inline script hands a string back to a shell, so the string is parsed as a
 * command. Every name here is unambiguous ON PURPOSE. A bare `exec` also names
 * `RegExp.prototype.exec`, so `/a/.exec('mempalace sync')` was read as an invocation
 * and denied; a bare `spawn` or `system` has the same problem. The cost of naming
 * only the unmistakable ones is a miss, which is the direction to err.
 */
const EXEC_API = /(?:os\.system|os\.popen|subprocess\.(?:run|call|check_call|check_output|Popen)|child_process\.(?:exec|execFile|spawn)|execSync|execFileSync|spawnSync)\s*\(\s*(?:\[\s*)?(['"])((?:(?!\1).)*)\1/g;

/**
 * Write calls in an inline script, and WHICH argument each one targets.
 *
 * Harvesting every path literal in a script that wrote anywhere was wrong in both
 * directions: `writeFileSync(mine, readFileSync(theirs))` counted the file being READ
 * as a write, and `stdout.write(readFileSync(theirs))` counted a print as a write at
 * all — a read of another agent's folder denied by a rule whose own reason says
 * reading it is fine. So the target is taken from the call that names it: argument 1
 * for a call that writes its first argument, argument 2 for a copy or a rename.
 */
const INLINE_WRITE_CALLS: Array<{ re: RegExp; arg: 1 | 2; needsWriteMode?: boolean }> = [
  { re: /^(?:.*\.)?(?:writeFileSync|writeFile|appendFileSync|appendFile|createWriteStream|truncateSync|truncate|unlinkSync|unlink|rmSync|rmdirSync|mkdirSync|mkdir|makedirs|remove)$/, arg: 1 },
  { re: /^(?:.*\.)?(?:copyFileSync|copyFile|copyfile|renameSync|rename|replace|cpSync|linkSync|symlinkSync|copy|copy2|move)$/, arg: 2 },
  // `open(path, 'w')` writes; `open(path)` and `open(path, 'r')` read.
  { re: /^(?:.*\.)?open$/, arg: 1, needsWriteMode: true },
];

/**
 * `$(echo WORD)` and `` `echo WORD` `` resolved textually, before tokenising.
 *
 * The output of a substitution is normally unknowable without running it, and this
 * parser never runs anything — which is why `$(cat which_agent)` is on the residual
 * list and stays there. `echo` with literal arguments is the one exception: its
 * output is provably its arguments, so `$(echo mempalace) sync` IS `mempalace sync`.
 * Narrow on purpose: no flags (`echo -n` changes the output), and nothing containing
 * `$`, a backtick or a paren, so nothing is resolved that we cannot see all of.
 * Other substitutions are untouched and still recursed into as commands.
 */
function resolveEcho(src: string): string {
  let out = src;
  for (let pass = 0; pass < 3; pass++) {
    const next = out
      .replace(/\$\(\s*echo\s+([^()$`]*?)\s*\)/g, (m, args) => (args.startsWith('-') ? m : args))
      .replace(/`\s*echo\s+([^`$()]*?)\s*`/g, (m, args) => (args.startsWith('-') ? m : args));
    if (next === out) break;
    out = next;
  }
  return out;
}

/** Tokenise, with the one substitution we can resolve without running it. */
function prepare(src: string): Tok[] {
  return tokenise(resolveEcho(src));
}

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

    // A comment at word start runs to the end of the line. Left in, its words land in
    // the preceding command's argv, which is both wrong and a way to feed tokens into
    // whatever string a rule matches.
    if (c === '#' && !started) {
      const nl = src.indexOf('\n', i);
      i = nl === -1 ? src.length : nl; // stop AT the newline: it is still a separator
      continue;
    }
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
    walk(prepare(command), ctx);
  } catch {
    // Total by contract: a parser bug must not reach a rule with on_error: deny.
  }
  if (!ctx.out.length) {
    const argv = command.trim().split(/\s+/).filter(Boolean);
    return [{ argv, text: command.trim(), writes: [], unresolved: [] as Unresolved[] }];
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
      // `D=$(cat who)` — the value is a command's output. Binding the rest of the word
      // ('' here) would make `$D/memory.md` resolve to `/memory.md`: a real absolute
      // path that nobody wrote. Leave the name unset so `$D` stays visible instead.
      if (!t.subs.length) ctx.env.set(t.v.slice(0, eq), expand(t.v.slice(eq + 1), ctx.env));
      continue;
    }
    const w = expand(t.v, ctx.env);
    if (leading && !argv.length && KEYWORDS.has(w)) continue; // `do mempalace sync` → `mempalace sync`
    leading = false;
    argv.push(w);
  }

  // `$(…)` and backticks run their own commands, whatever the outer one does.
  for (const s of subs) walk(prepare(s), { ...ctx, depth: ctx.depth + 1 });
  // …and the OUTER word is that command's output, which we do not have. resolveEcho
  // has already handled the one case we can compute, so anything left here is a real
  // blind spot: `$(cat which) sync` is a command whose name we never learn.
  const hidden: Unresolved[] = subs.map((x) => ({ code: 'substitution_output', detail: programOf(x) }));

  if (!argv.length) {
    if (redirects.length) record(ctx, [], redirects, hidden);
    return;
  }
  dispatch(argv, redirects, herestring, ctx, hidden);
}

/** Resolve wrappers down to the command that actually runs, then record it. */
function dispatch(argv: string[], redirects: string[], herestring: string | null, ctx: Ctx, hidden: Unresolved[] = []): void {
  if (ctx.depth > MAX_DEPTH || ctx.out.length >= MAX_COMMANDS) return;
  const deeper = { ...ctx, depth: ctx.depth + 1 };

  // `for c in sync; do …` arrives as the segment `for c in sync`: bind the loop
  // variable so the body's `$c` expands. One binding per value, first wins.
  if (argv[0] === 'for' && argv[1] && argv[2] === 'in' && argv[3]) { ctx.env.set(argv[1], argv[3]); return; }
  if (argv[0] === 'while' || argv[0] === 'until' || argv[0] === 'if' || argv[0] === 'case') {
    return dispatch(argv.slice(1), redirects, herestring, ctx, hidden);
  }

  let head = argv[0];

  // env VAR=v cmd … — the assignments are this command's, not the shell's.
  if (head === 'env') {
    let i = 1;
    while (i < argv.length && /^\w+=/.test(argv[i])) { const eq = argv[i].indexOf('='); ctx.env.set(argv[i].slice(0, eq), argv[i].slice(eq + 1)); i++; }
    while (i < argv.length && argv[i].startsWith('-')) i++;
    if (i < argv.length) return dispatch(argv.slice(i), redirects, herestring, ctx, hidden);
    return;
  }
  const wrapper = TRANSPARENT[basename(head)];
  if (wrapper) {
    let i = 1;
    while (i < argv.length && argv[i].startsWith('-') && argv[i] !== '-' && !argv[i].includes('=')) {
      if (wrapper.values.has(argv[i])) i++; // `-u gpinkham` — the user is not the command
      i++;
    }
    while (i < argv.length && argv[i].startsWith('--') && argv[i].includes('=')) i++;
    // `script /dev/null cmd …` records into that file; only what follows is a command.
    if (wrapper.firstOperandIsFile && i + 1 < argv.length) i++;
    if (i < argv.length) return dispatch(argv.slice(i), redirects, herestring, ctx, hidden);
    return;
  }
  if (basename(head) === 'timeout') {
    let i = 1;
    while (i < argv.length && (argv[i].startsWith('-') || /^[\d.]+[smhd]?$/.test(argv[i]))) i++;
    if (i < argv.length) return dispatch(argv.slice(i), redirects, herestring, ctx, hidden);
    return;
  }
  if (basename(head) === 'eval') {
    walk(prepare(argv.slice(1).join(' ')), deeper);
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
    if (token && words) return dispatch(inner.flatMap((a) => (a === token ? words : [a])), redirects, null, ctx, hidden);
    if (!token && words) return dispatch([...inner, ...words], redirects, null, ctx, hidden);
    // stdin we cannot see: record it as it stands and say the operand is unknown.
    record(ctx, inner, redirects, [{ code: 'stdin_operand', detail: token ?? '(appended)' }]);
    return;
  }

  const base = basename(head);
  if (SHELL_DASH_C.has(base)) {
    const ci = argv.findIndex((a, k) => k > 0 && (a === '-c' || a === '-lc' || a === '-cl'));
    if (ci !== -1 && argv[ci + 1] !== undefined) { walk(prepare(argv[ci + 1]), deeper); return; }
    // No -c: the program is a script FILE we do not open, or it is stdin — which is
    // what `curl … | sh` is. Either way every command it runs is invisible here.
    const file = argv.slice(1).find((a) => !a.startsWith('-'));
    hidden = [...hidden, file
      ? { code: 'program_from_file', detail: file.slice(0, 200) }
      : { code: 'piped_program', detail: base }];
  }
  if (base === 'source' || base === '.') {
    const file = argv[1];
    if (file) hidden = [...hidden, { code: 'program_from_file', detail: file.slice(0, 200) }];
  }
  // `alias gp='git push'` / `gp() { git push; }` — the name is ours to see, its later
  // use is not, because a parser only ever gets one command at a time.
  if (base === 'alias' && argv[1]) {
    hidden = [...hidden, { code: 'alias_definition', detail: argv[1].split('=')[0].slice(0, 60) }];
  }
  if (base === 'function' && argv[1]) {
    hidden = [...hidden, { code: 'alias_definition', detail: argv[1].slice(0, 60) }];
  }
  if ((base === 'python' || base === 'python3' || base === 'python2') && argv[1] === '-m' && argv[2]) {
    // `python3 -m mempalace sync` IS `mempalace sync`.
    return dispatch([argv[2], ...argv.slice(3)], redirects, herestring, ctx, hidden);
  }
  const inlineFlags = INLINE_SCRIPT[base];
  if (inlineFlags) {
    const fi = argv.findIndex((a, k) => k > 0 && inlineFlags.includes(a));
    if (fi !== -1 && argv[fi + 1] !== undefined) {
      const script = argv[fi + 1];
      record(ctx, [base, ...argv.slice(1)], [...redirects, ...inlineTargets(script)], hidden);
      // A string the script hands to a shell is a command, so parse it as one.
      for (const m of script.matchAll(EXEC_API)) walk(prepare(m[2]), deeper);
      return;
    }
  }
  if (base === 'cd' && argv[1]) { ctx.cwd = realAbsolute(argv[1], ctx.cwd); record(ctx, [base, ...argv.slice(1)], redirects, hidden); return; }

  // `git -C dir …` runs in dir; it writes no path we track, but a later command in
  // the same line does not inherit that, so only argv is normalised here.
  record(ctx, [base, ...argv.slice(1)], [...redirects, ...verbTargets(base, argv)], hidden);
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
  if (TARGET_DIR_VERBS.has(base)) {
    const dir = flagValue(argv, TARGET_DIR_FLAGS);
    if (dir !== null) return [/[/\\]$/.test(dir) ? dir : dir + '/'];
    // `install -d a b` creates directories; there is no source among the operands.
    if (base === 'install' && flags.some((f) => /^-[a-zA-Z]*d$/.test(f) || f === '--directory')) return operands;
  }
  if (base === 'sed') {
    if (!flags.some((f) => /^-[a-zA-Z]*i/.test(f) || f === '--in-place' || f.startsWith('--in-place='))) return [];
    // BSD `sed -i '' script file` leaves an empty operand; the script is the first
    // real operand unless -e/-f already supplied it.
    const real = operands.filter((o) => o !== '');
    const suppliedScript = flags.some((f) => f === '-e' || f === '-f' || f === '--expression' || f === '--file'
      || f.startsWith('--expression=') || f.startsWith('--file='));
    return suppliedScript ? real : real.slice(1);
  }
  if (base === 'dd') return argv.filter((a) => a.startsWith('of=')).map((a) => a.slice(3));
  const dest = DEST_FLAG[base];
  if (dest) {
    if (dest.needsExtract && !argv.some((a) => /^-[^-]*x/.test(a) || a === '--extract')) return [];
    // `tar -xzf a.tgz -C dir` writes into dir; the same flag on a `-c` writes the
    // archive instead, so tar has to say it is extracting. unzip only extracts.
    for (let i = 1; i < argv.length; i++) {
      if (!dest.flags.includes(argv[i])) continue;
      const dir = argv[i + 1];
      if (dir) return [/[/\\]$/.test(dir) ? dir : dir + '/'];
    }
    return [];
  }
  if (ARCHIVE_FIRST_ARG.has(base)) return operands.slice(0, 1);
  if (ALL_ARGS_TARGET.has(base)) return SKIP_FIRST_OPERAND.has(base) ? operands.slice(1) : operands;
  if (LAST_ARG_DEST.has(base)) return operands.length >= 2 ? [operands[operands.length - 1]] : [];
  return [];
}

/** A flag's value, whether written `-t DIR`, `--target-directory DIR` or `=DIR`. */
function flagValue(argv: string[], names: string[]): string | null {
  for (let i = 1; i < argv.length; i++) {
    const a = argv[i];
    for (const n of names) {
      if (a === n) return argv[i + 1] ?? null;
      if (a.startsWith(n + '=')) return a.slice(n.length + 1);
    }
  }
  return null;
}

/** The path each write call in an inline script targets — not every path in it. */
function inlineTargets(script: string): string[] {
  const out: string[] = [];
  // NAME ( 'first' , 'second'  — enough to tell a target from a source without
  // parsing the host language. A call whose argument is not a literal is skipped,
  // which is a miss (see the residual list), not a guess.
  const call = /([\w.$]+)\s*\(\s*(?:(['"])((?:(?!\2).)*)\2)?\s*(?:,\s*(['"])((?:(?!\4).)*)\4)?/g;
  for (const m of script.matchAll(call)) {
    const [, name, , first, , second] = m;
    for (const spec of INLINE_WRITE_CALLS) {
      if (!spec.re.test(name)) continue;
      if (spec.needsWriteMode && !/^[wax]/.test(second ?? '')) continue;
      const target = spec.arg === 1 ? first : second;
      if (target) out.push(target);
      break;
    }
  }
  return out;
}

/** The first word of a command string — a program name, safe to put in a ledger. */
function programOf(src: string): string {
  const [first] = src.trim().split(/\s+/);
  return (first ?? '').slice(0, 60) || '(empty)';
}

/** Variable names still unexpanded in these words, if any. */
function unexpandedVars(words: string[]): Unresolved[] {
  const out: Unresolved[] = [];
  for (const w of words) {
    for (const m of w.matchAll(/\$\{?(\w+)\}?/g)) out.push({ code: 'unexpanded_variable', detail: m[1] });
  }
  return out;
}

function record(ctx: Ctx, argv: string[], writes: string[], unresolved: Unresolved[]): void {
  if (ctx.out.length >= MAX_COMMANDS) return;
  ctx.out.push({
    argv,
    text: argv.map(requote).join(' '),
    writes: writes.map((w) => realAbsolute(w, ctx.cwd)),
    // A target holding `$SOMETHING` was resolved against a name we never saw, so the
    // absolute path above is a guess at best. Say so rather than only recording it.
    unresolved: [...unresolved, ...unexpandedVars(writes)],
  });
}
