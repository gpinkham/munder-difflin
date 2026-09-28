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
 * WHAT THIS IS NOT. Not a secret scanner. It never tries to decide whether a given
 * string IS a secret and keep it when it looks innocent — that test is unwinnable and a
 * single false negative is permanent. It works the other way round: a segment is kept
 * only when it is positively recognisable as an ordinary, non-secret name, and the
 * prefix and entropy checks below only REMOVE things that would otherwise have passed
 * that test. A password shaped exactly like a filename is still dropped when it appears
 * anywhere a value can appear, because operands are dropped by position, not by looks.
 */

/** Bumped when the record shape changes, so a corpus is never silently mixed. */
export const CORPUS_SCHEMA = 1;

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

/** One argv token, reduced to shape. Position decides the rule, never appearance. */
function scrubToken(tok: string, index: number, ctx: CorpusContext): string {
  if (typeof tok !== 'string') return '<arg>';
  // An assignment can precede the program (`TOKEN=… deploy`), so it is checked first.
  const assign = ASSIGNMENT.exec(tok);
  if (assign) return `${assign[1]}=<v>`;

  if (index === 0) {
    const base = tok.split('/').pop() ?? '';
    return safeSegment(base) ? base : '<prog>';
  }

  if (tok.startsWith('--')) {
    const eq = tok.indexOf('=');
    if (eq !== -1) {
      const name = tok.slice(0, eq);
      return /^--[A-Za-z0-9][A-Za-z0-9-]*$/.test(name) ? `${name}=<v>` : '<flag>=<v>';
    }
    return /^--[A-Za-z0-9][A-Za-z0-9-]*$/.test(tok) ? tok : '<flag>';
  }
  if (tok.startsWith('-') && tok.length > 1) {
    // A short cluster is shape; a value ATTACHED to one (`-uSECRET`) is not, so only
    // the flag letters survive.
    if (/^-[A-Za-z]+$/.test(tok)) return tok;
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
  return argv.map((t, i) => scrubToken(t as string, i, ctx));
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
    matched_on: verdict.matchedOn ?? null,
    tool: payload.tool_name ?? null,
    agent: agentLabel(payload.agent_id, ctx) ?? '<agent:unknown>',
    input_digest: digest,
    cwd: payload.cwd ? normalizeForCorpus(payload.cwd, ctx) : null,
    paths: { fields, writes: commands.flatMap((c) => c.writes), removes: commands.flatMap((c) => c.removes) },
    commands,
  };
}
