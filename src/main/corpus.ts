/**
 * md-136 — the redacted, trainable decision corpus.
 *
 * WHY THIS EXISTS. md-120's decision ledger stores `input_digest`, a sha256 of the
 * tool input, and that is deliberate: a tool input carries tokens, passwords and file
 * bodies, so the audit record holds a hash rather than the thing itself. But a hash
 * cannot be trained on. md-135 §5 makes the point with a deadline attached — the
 * operator's weekly adjudication is generating `(action, verdict, human label)` triples
 * in this floor's own distribution right now, and if the ledger runs for six months on
 * digests alone, the corpus a local classifier would need does not exist and cannot be
 * reconstructed.
 *
 * So this writes a SECOND, deliberately lossy record beside the hash: the SHAPE of an
 * action, never its values. The digest row remains the audit record and is untouched.
 *
 * THE RULE, and it is the whole design: a value is never emitted. Verbs, flag NAMES,
 * variable NAMES and the classification of a path are shape. Everything else — every
 * operand, every flag value, every quoted string, every heredoc body, every file body —
 * is a value, and a value is replaced rather than written. Redaction therefore FAILS
 * CLOSED: a token this module cannot confidently classify loses its content, because
 * the cost of over-redacting is a weaker training signal and the cost of under-redacting
 * is a secret on disk.
 *
 * THE EXACT CLAIM, because a looser one would be false (md-136 N-review): no value is
 * emitted except an ordinary-name-shaped path segment. A secret stored AS a pathname and
 * shaped like an ordinary word WILL survive; credential-shaped strings will not, in any
 * position — including a flag NAME, which is why the flag branch runs the same test a
 * path segment does.
 *
 * WHAT THIS IS NOT. Not a secret scanner. It never tries to decide whether a given
 * string IS a secret and keep it when it looks innocent — that test is unwinnable and a
 * single false negative is permanent. It works the other way round: a segment is kept
 * only when it is positively recognisable as an ordinary, non-secret name, and the
 * prefix and separator-run checks below only REMOVE things that would otherwise have
 * passed it. A password shaped exactly like a filename is still dropped when it appears
 * anywhere a value can appear, because operands are dropped by position, not by looks.
 */

/** Bumped when the record shape changes, so a corpus is never silently mixed.
 *  2 — the subcommand of a multi-verb program is kept (md-136 N2). Schema-1 rows
 *  predate that and record it as `<arg>`, so they are not comparable on it.
 *  3 — `granted` (HAG-49): an ask rule's action allowed by an operator's one-action
 *  grant. Without it that row reads as an ordinary allow. The grant's id is a value
 *  and is never written; only the fact that one was used.
 *  4 — `approval_needed`: an approvable push with no grant is denied (and put on the
 *  Approvals card) instead of asked. Without it that row reads as an ordinary deny. */
export const CORPUS_SCHEMA = 4;

/** Local-only, and beside the policy it describes: `<hive>/policy/`. That directory is
 *  already the one place agents may not write (policy self-protection), and keeping the
 *  corpus out of `log.jsonl` makes it separable — it is hive data, never a PR artefact. */
export const CORPUS_FILE = 'decision-corpus.jsonl';

/** What the placeholders are resolved against. All optional: an absent root simply
 *  means paths under it are not recognised, which costs comparability, never safety. */
export interface CorpusContext {
  /** The agent that took the action, so its own tree is distinguishable from a colleague's. */
  agentId?: string | null;
  /** Every agent id the floor knows, so a colleague's id is normalized rather than written. */
  agentIds?: string[];
  home?: string | null;
  hiveRoot?: string | null;
  policyDir?: string | null;
  cwd?: string;
}

/** Token shapes that are never a filename, whatever else they look like. */
const SECRET_PREFIX =
  /^(sk-|pk-|ghp_|gho_|ghs_|ghu_|ghr_|github_pat_|glpat-|xox[baprse]-|AKIA|ASIA|AIza|ya29\.|eyJ|-----BEGIN|Bearer)/;

/** Longest run of characters with no separator. A real name breaks into words; a
 *  generated credential usually does not. */
function longestRun(s: string): number {
  return s.split(/[._\-]+/).reduce((m, part) => Math.max(m, part.length), 0);
}

/**
 * Is this path segment positively recognisable as an ordinary name?
 *
 * Deliberately narrow, and the ONLY way a real substring of a path reaches the corpus.
 * Anything with a character a filename does not normally need (a space, `=`, `:`, `@`,
 * `/`, a quote, a newline) fails, which is what keeps a URL's `user:password@host`, a
 * base64 blob and a heredoc body out.
 */
export function safeSegment(s: string): boolean {
  if (!s || s.length > 40) return false;
  if (!/^[A-Za-z0-9._-]+$/.test(s)) return false;
  if (s === '.' || s === '..') return false;
  if (SECRET_PREFIX.test(s)) return false;
  const run = longestRun(s);
  // A long unbroken run mixing letters and digits is the shape of a generated token,
  // not of `md-223-notes.md`, whose runs are short words.
  if (run >= 16 && /[0-9]/.test(s) && /[A-Za-z]/.test(s)) return false;
  if (run >= 24) return false;
  return true;
}

/** `<agent:self>` / `<agent:other>` for a known id, else null. Two floors' records are
 *  only comparable if an id never appears verbatim. */
function agentLabel(seg: string | null | undefined, ctx: CorpusContext): string | null {
  if (!seg) return null;
  if (ctx.agentId && seg === ctx.agentId) return '<agent:self>';
  if (ctx.agentIds?.includes(seg)) return '<agent:other>';
  return null;
}

/**
 * A path reduced to its classification: which known root it sits under, whose agent
 * tree it belongs to, and the ordinary names in between. Segments that are not
 * positively ordinary become `<x>`, so a credential used as a directory name — the case
 * a root-prefix scheme alone would pass straight through — does not survive.
 */
export function normalizeForCorpus(raw: unknown, ctx: CorpusContext): string {
  if (typeof raw !== 'string' || !raw) return '<x>';
  // A value carrying whitespace or a newline is not a path we will reason about.
  if (/\s/.test(raw)) return '<x>';
  let p = raw.replace(/\/+$/, '');
  if (!p) return '/';

  const roots: Array<[string, string]> = [
    [ctx.policyDir ?? '', '<policy>'],
    [ctx.hiveRoot ?? '', '<hive>'],
    [ctx.home ?? '', '<home>'],
  ].filter(([d]) => !!d) as Array<[string, string]>;
  // Most specific root first: the policy dir is inside the hive, which is inside home.
  roots.sort((a, b) => b[0].length - a[0].length);

  let prefix = raw.startsWith('/') ? '<abs>' : '<rel>';
  for (const [dir, label] of roots) {
    if (p === dir) return label;
    if (p.startsWith(dir + '/')) { prefix = label; p = p.slice(dir.length + 1); break; }
  }

  const out: string[] = [];
  const segs = p.split('/').filter(Boolean);
  segs.forEach((seg, i) => {
    const known = agentLabel(seg, ctx);
    if (known) { out.push(known); return; }
    // An id we do not know still sits in the agents directory, and its NAME is not
    // ours to publish — say where it is instead.
    if (i > 0 && segs[i - 1] === 'agents' && (prefix === '<hive>' || prefix === '<policy>')) {
      out.push('<agent:unknown>');
      return;
    }
    out.push(safeSegment(seg) ? seg : '<x>');
  });
  return [prefix, ...out].join('/');
}

const ASSIGNMENT = /^([A-Za-z_][A-Za-z0-9_]*)=/;
const PATH_LIKE = /^(\/|\.\.?\/|~\/)/;

/**
 * md-136 N1. A flag NAME is an argument like any other — two dashes in front of a
 * string do not make it shape. The first pass returned `--<name>` whenever it matched
 * a flag-ish regex, which applies none of the checks a path segment must pass, so
 * `curl --sk-ant-api03-…` was written verbatim: the very string that is `<x>` one
 * branch away. The name now runs the same `safeSegment` test, de-dashed.
 */
function flagNameIsShape(name: string): boolean {
  return /^--[A-Za-z0-9][A-Za-z0-9-]*$/.test(name) && safeSegment(name.replace(/^-+/, ''));
}

/**
 * md-136 N2. Programs whose real verb is the SECOND word. Two of the four shipped rules
 * match on `command_matches`, i.e. verb plus subcommand — `git push` is an ask and
 * `git status` is nothing — so recording both as `['git','<arg>']` destroys precisely
 * the distinction this corpus exists to learn.
 */
const MULTI_VERB = new Set([
  'git', 'gh', 'hub', 'npm', 'npx', 'yarn', 'pnpm', 'bun', 'deno', 'pip', 'pip3',
  'docker', 'podman', 'kubectl', 'helm', 'cargo', 'go', 'dotnet', 'brew', 'apt',
  'apt-get', 'systemctl', 'aws', 'gcloud', 'az', 'terraform', 'gradle', 'mvn',
  'bundle', 'composer', 'flatpak', 'snap', 'mempalace',
]);

/** A subcommand is still an ARGUMENT POSITION, so it is kept only when it looks like a
 *  keyword: lowercase, short, and passing the same segment test everything else does. */
const SUBCOMMAND = /^[a-z][a-z0-9-]{0,19}$/;

/** Global flags that swallow the next word, so the subcommand is not the token after
 *  the program. `git -C <dir> push` is the dominant real form and the one `remote-push`
 *  matches, so an index-1 rule would record `<arg>` for exactly the case that matters.
 *  Credential-bearing flags are listed so their VALUE is stepped over rather than
 *  stumbled onto — but the set is not, and cannot be, complete (md-136 N6). */
const GLOBAL_VALUE_FLAGS = new Set([
  '-C', '-c', '--git-dir', '--work-tree', '--namespace', '--exec-path',
  '--config', '--context', '--cluster', '--chdir', '--cwd', '--prefix',
  '-n', '-p', '-u', '-t', '-e', '-f', '-o',
  '--token', '--password', '--passwd', '--key', '--api-key', '--secret',
  '--profile', '--otp', '--proxy', '--kube-token', '--user', '--username',
  '--registry', '--host', '--server', '--region', '--file', '--output',
]);

/** Leading flags that take NO value, so the next word really is the subcommand. */
const GLOBAL_BOOL_FLAGS = new Set([
  '--no-pager', '--paginate', '--bare', '--quiet', '--verbose', '--debug',
  '--no-color', '--help', '--version', '-q', '-v',
]);

/**
 * Where the subcommand sits: the first non-flag token, stepping over leading global
 * flags and the values they take. Only an INDEX — whatever lands there still has to
 * pass the keyword and segment tests before any of it is written.
 *
 * md-136 N6, and the reason this returns -1. The first version stepped over an
 * unrecognised flag ASSUMING it took no value; when it does, the index landed on that
 * flag's VALUE and wrote it verbatim — and the flags this happens to are called
 * `--token`, `--password`, `-u`, `-p`. `--token SECRET` was safe before the subcommand
 * feature existed, so that was a regression, and the worst kind: the ordinary way a
 * secret reaches a command line. The sets above cannot be completed across 33 programs'
 * CLIs, so completeness is the wrong fix and the GUESS was the bug. On anything
 * unrecognised we give up on finding a subcommand at all: -1 matches no index, so
 * nothing is captured. The cost is signal (`kubectl -n ns get pods` may lose `get`),
 * recoverable later by adding a flag to a set — never by trusting a guess again.
 */
function subcommandIndex(argv: string[]): number {
  let i = 1;
  while (i < argv.length) {
    const t = argv[i];
    if (typeof t !== 'string' || !t.startsWith('-') || t === '-' || t === '--') break;
    if (GLOBAL_VALUE_FLAGS.has(t)) { i += 2; continue; }
    // `--flag=value` carries its own value, so the next word is still the subcommand.
    if (t.startsWith('--') && t.includes('=')) { i += 1; continue; }
    if (GLOBAL_BOOL_FLAGS.has(t)) { i += 1; continue; }
    return -1; // an unknown flag may eat the next word — do not guess onto it
  }
  return i;
}

/** One argv token, reduced to shape. Position decides the rule, never appearance. */
function scrubToken(tok: string, index: number, ctx: CorpusContext, prog: string, subAt: number): string {
  if (typeof tok !== 'string') return '<arg>';
  // An assignment can precede the program (`TOKEN=… deploy`), so it is checked first.
  const assign = ASSIGNMENT.exec(tok);
  if (assign) return `${assign[1]}=<v>`;

  if (index === 0) {
    const base = tok.split('/').pop() ?? '';
    return safeSegment(base) ? base : '<prog>';
  }

  // The verb's second half, and only there: the first token after a known multi-verb
  // program, and only when it is keyword-shaped. A credential in that slot is still a
  // value and still goes.
  if (index === subAt && MULTI_VERB.has(prog) && SUBCOMMAND.test(tok) && safeSegment(tok)) return tok;

  if (tok.startsWith('--')) {
    const eq = tok.indexOf('=');
    const name = eq === -1 ? tok : tok.slice(0, eq);
    const suffix = eq === -1 ? '' : '=<v>';
    return flagNameIsShape(name) ? `${name}${suffix}` : `<flag>${suffix}`;
  }
  if (tok.startsWith('-') && tok.length > 1) {
    // A short cluster is shape; a value ATTACHED to one (`-uSECRET`) is not, so only
    // the flag letters survive. The length cap matters: `-AKIAIOSFODNNEXAMPLE` is a
    // credential, not a nineteen-letter cluster, and no real one is that long.
    if (/^-[A-Za-z]{1,8}$/.test(tok)) return tok;
    const m = /^(-[A-Za-z])/.exec(tok);
    return m ? `${m[1]}<v>` : '<flag>';
  }
  if (tok === '-' || tok === '--') return tok;

  // Everything left is an operand, i.e. a value. A path is kept as its classification
  // because WHERE an action lands is the signal the rules turn on; anything else goes.
  if (PATH_LIKE.test(tok) && !/\s/.test(tok)) return normalizeForCorpus(tok, ctx);
  return '<arg>';
}

/** A parsed command reduced to shape: the verb, its flags, and where it points. */
export function scrubArgv(argv: unknown, ctx: CorpusContext): string[] {
  if (!Array.isArray(argv)) return [];
  const first = typeof argv[0] === 'string' ? (argv[0] as string).split('/').pop() ?? '' : '';
  const subAt = subcommandIndex(argv as string[]);
  return argv.map((t, i) => scrubToken(t as string, i, ctx, first, subAt));
}

/** The subset of a tool input that names a path. The rest of a tool input — `content`,
 *  `old_string`, a command's text — is value, and is never read here. */
const PATH_FIELDS = ['file_path', 'notebook_path', 'path'] as const;

export interface CorpusInput {
  payload: {
    tool_name?: string;
    agent_id?: string | null;
    tool_input?: unknown;
    cwd?: string;
  };
  verdict: {
    decision: string;
    ruleId?: string;
    mode?: string;
    matchedOn?: string;
    wouldDeny?: boolean;
    /** True when an operator's grant allowed an ask rule's action (HAG-49). */
    granted?: boolean;
    /** True when the deny only waits on the operator's Approve (schema 4). */
    approvalNeeded?: boolean;
  };
  /** Already parsed by shell.ts for the decision itself, so this costs no re-parse. */
  commands?: Array<{ argv: string[]; writes: string[]; removes: string[]; unresolved?: Array<{ code: string }> }>;
  ctx: CorpusContext;
  /** The audit row's digest — the join key between the two files, and already a hash. */
  digest: string;
}

/**
 * One corpus record. Everything here is either a verdict field the engine produced, a
 * hash, or a value that has been through the scrubbers above.
 */
export function corpusRecord(input: CorpusInput): Record<string, unknown> {
  const { payload, verdict, ctx, digest } = input;
  const ti = (payload.tool_input ?? {}) as Record<string, unknown>;
  const fields = PATH_FIELDS
    .filter((f) => typeof ti[f] === 'string' && ti[f])
    .map((f) => normalizeForCorpus(ti[f], ctx));

  // BUILT FIELD BY FIELD, NEVER SPREAD. `EffectiveCommand` also carries `text`, the raw
  // command as written, and a `{ ...c }` here would put it — secrets and all — straight
  // into the record. Listing the fields is what keeps it out, so this is load-bearing
  // and not a style choice; a test asserts the raw text never appears.
  const commands = (input.commands ?? []).map((c) => ({
    argv: scrubArgv(c.argv, ctx),
    writes: (c.writes ?? []).map((w) => normalizeForCorpus(w, ctx)),
    removes: (c.removes ?? []).map((r) => normalizeForCorpus(r, ctx)),
    // CODES only. An `unresolved` entry also carries a `detail` naming a program or a
    // path, and a reason code is shape while that detail is not.
    unresolved: [...new Set((c.unresolved ?? []).map((u) => u.code))].sort(),
  }));

  return {
    schema: CORPUS_SCHEMA,
    kind: 'policy-decision-corpus',
    rule_id: verdict.ruleId ?? null,
    decision: verdict.decision,
    mode: verdict.mode ?? null,
    would_deny: verdict.wouldDeny ?? false,
    granted: verdict.granted === true,
    approval_needed: verdict.approvalNeeded === true,
    matched_on: verdict.matchedOn ?? null,
    tool: payload.tool_name ?? null,
    agent: agentLabel(payload.agent_id, ctx) ?? '<agent:unknown>',
    input_digest: digest,
    cwd: payload.cwd ? normalizeForCorpus(payload.cwd, ctx) : null,
    paths: { fields, writes: commands.flatMap((c) => c.writes), removes: commands.flatMap((c) => c.removes) },
    commands,
  };
}
