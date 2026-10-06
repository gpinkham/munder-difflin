/**
 * PolicyEngine — opt-in, deterministic PreToolUse policy.
 *
 * Evaluates a small set of hand-written rules against a hook payload and returns
 * `allow | deny | ask` plus a reason string the model reads. It exists because
 * standing process rules ("an agent may only write inside its own folder") live as
 * prose in prompts and memory files, so they depend on salience: under task
 * pressure an agent optimises for the immediate goal over a rule it is not
 * actively holding. This moves those rules from remembered to enforced.
 *
 * WHAT THIS IS NOT. The hook transport is fail-open by construction — the shim
 * exits 0 (no stdout = allow) when HIVE_SOCK is unset, on socket error, and on its
 * own timeout. So this governs agents running under a live harness; it is a
 * salience aid for a cooperative agent, NOT a security boundary against a hostile
 * one. No policy setting can change that, so it is documented rather than papered
 * over.
 *
 * DESIGN CONSTRAINTS, all deliberate:
 *   - No model call, ever. A model in the enforcement path adds latency to every
 *     tool call and makes the decision nondeterministic.
 *   - No network, no new service, no dependency. The matcher vocabulary is tiny
 *     on purpose (see MATCHERS below); the moment it needs an expression language
 *     the correct move is to adopt OPA/Rego rather than grow one here.
 *   - Unconfigured is inert. With no policy file the engine loads nothing,
 *     evaluates nothing and denies nothing, so an existing install sees
 *     byte-identical behaviour.
 *
 * BASH IS PARSED, NOT PATTERN-MATCHED. A Bash payload is handed to shell.ts,
 * which returns the commands it actually runs and the paths it actually writes;
 * `command_matches` is tested against each of those as well as against the raw
 * string, and `path_glob` sees bash write targets the way it sees a Write's
 * file_path. Without that, `sudo mempalace sync` and `cat x > <other agent>/f`
 * were simply different strings from the ones the rules described — measured at
 * 81.5% of disguised violations wrongly allowed (md-188), 0.6% after (md-199).
 * The parser is a normaliser, not a sandbox: see its own header for what it does
 * not claim to catch. What it CANNOT see, it says so about: a Bash call whose target
 * or program the parser could not pin down gets an `event: "unresolved"` row in the
 * ledger, carrying a stable reason code. That row changes no decision — it exists so
 * the size and shape of the blind spot is a number an operator can read rather than a
 * paragraph in a report.
 *
 * Runs in the Electron main process, called from HookServer.handle().
 */
import { readFileSync, existsSync, appendFileSync, readdirSync, statSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { canonicalAction, GrantStore, GRANT_CLASSES, gitInspector, type Grant, type GitInspector } from './grants';
import {
  effectiveCommands, realAbsolute, inlineScript, scriptLiterals, scriptWrites, operandsOf, verbOf,
  STRUCTURAL_UNRESOLVED, type EffectiveCommand, type Unresolved,
} from './shell';
import { corpusRecord, CORPUS_FILE, type CorpusContext } from './corpus';
import { GUARDRAIL_FILE, LEGACY_ENGINE_FILE, MATCHERS, migrateLegacyPolicy, readGuardrail, toEngineRules } from './guardrail';

/** Where a rule's path matcher reads its subject from, per tool. */
const PATH_FIELDS = ['file_path', 'notebook_path', 'path'] as const;

/**
 * The entire matcher vocabulary. Adding a key here is a spec change, not an
 * implementation detail: every present key must match (AND), rules are evaluated
 * in file order, and first match wins. If you need OR, write two rules.
 */

/** Verbs whose written targets are removed wholesale, as opposed to written into. */
const DESTROY_VERBS = new Set(['rm', 'rmdir', 'unlink', 'shred', 'find', 'mv']);

/**
 * The engine's own policy file, and the one it falls back to.
 *
 * TWO FILES, ON PURPOSE (md-216). `authority.json` belongs to `bin/guardrail-hook.cjs`,
 * whose schema (`match.kind`, `mode: "DRY_RUN"`) predates this engine and still writes
 * the `firing` rows in decisions.jsonl. The engine read the same file, rejected every
 * rule with `unknown matcher "kind"`, and enforced nothing on either floor for as long
 * as it was installed. Sharing one file between two schemas means one reader is always
 * wrong, so each reader gets its own file and neither has to understand the other.
 * Since finish plan item 1 the engine reads only guardrail.json; engine.json is moved
 * into it once, and authority.json is never the engine's (it only explains, at load,
 * that the rules live in guardrail.json).
 */
/** The engine's rules file (finish plan item 1): guardrail.json, the backstops of the rules. */
export const ENGINE_POLICY_FILE = GUARDRAIL_FILE;
export const LEGACY_POLICY_FILE = 'authority.json';

/** One agent's workspace roots, as the harness knows them: its registered cwd, its
 *  hive folder, and its isolated worktree. Supplied by HookServer from the registry. */
export interface AgentWorkspace {
  agentId: string;
  roots: string[];
}

/** What `status` reports. The UI, fleet.json and the startup log all read this one
 *  shape, so "how many rules are actually loaded" has a single answer. */
export interface PolicyStatus {
  configured: boolean;
  /** The file the rules came from, or the file that failed. Null when unconfigured. */
  file: string | null;
  rulesLoaded: number;
  ruleIds: string[];
  /** Why no rules are loaded when a policy is configured. Null when all is well. */
  error: string | null;
  loadedAt: string | null;
}

/**
 * Write indicators for the Bash half of policy self-protection: a redirection, a
 * `tee`, an in-place `sed`, or one of the verbs that only ever mutates. Reads
 * (`cat`, `grep`, `sed -n`) are absent on purpose — an agent should be able to
 * read the rule it just tripped.
 *
 * SCOPED TO ONE PARSED COMMAND, not to the whole Bash string. Applied to the whole
 * string it denied `cp a b && wc -l <policy>/decisions.jsonl` — two unrelated
 * segments, one of which merely READS the ledger — because the verb and the path
 * were both somewhere in the text. That was a measured false positive on real work,
 * and it recurs for anyone working on the policy files, which is exactly the person
 * who needs to read them. The verb and the path must appear in the same segment.
 *
 * The whole-string form survives as a fallback for a command the parser admits it
 * could not read (`unresolved` in shell.ts): if the segmentation is not trustworthy
 * we should not lean on it, and for the one invariant that makes every other rule
 * meaningful the unreadable case errs toward deny.
 */
const POLICY_WRITE_SHAPE =
  /(>>?\s*\S*policy)|(\btee\b)|(\bsed\b[^|;&]*\s-[a-zA-Z]*i)|(\b(rm|mv|cp|mkdir|touch|chmod|chown|truncate|shred|unlink|ln|install|rsync|dd)\b)/;

/** How long between `policy-stats` rollups. Flushed lazily, so no timer. */
const STATS_INTERVAL_MS = 60 * 60 * 1000;

/** At most this many blind spots per row. A pathological command cannot flood a file. */
const MAX_UNRESOLVED_PER_ROW = 20;

/**
 * THE ONE PLACE TO EDIT. Verbs allowed to name a path inside the policy directory.
 *
 * For the policy directory only, the default is inverted: a Bash command that names a
 * path under it is DENIED unless its verb is listed here. Everywhere else on the disk
 * the engine works the other way round — a write is denied, everything else passes.
 *
 * WHY THE INVERSION IS WORTH IT HERE AND NOWHERE ELSE. A deny-known-writers list is a
 * list of verbs, and there is always another verb: `perl -i`, `ed -s`, `ex -sc '%d|x'`,
 * `vim -es`, `python3 -m json.tool src dest`, tomorrow's editor. Six of them were
 * measured writing the policy file unseen (md-199f), and each one closed by hand only
 * invited the seventh. An allow-known-readers list cannot be outrun that way: a verb
 * nobody has listed fails closed. The price is the opposite error — an unusual READ
 * verb gets denied until someone adds it — and that is a one-line, reversible fix by
 * the operator, where the other error is a guardrail that quietly does not apply.
 *
 * WHAT BELONGS HERE: a verb that cannot modify a file handed to it as an operand. A
 * verb whose writes the parser already tables (`cp`, `sed`, `tar`, `zip`, `unzip`) is
 * safe to list, because a write among its operands is caught before this list is
 * consulted — that is what keeps `cp <policy>/authority.json /tmp/mine.json` (copying
 * the rules OUT, a read) working. `mv`, `ln`, `tee`, `dd`, `rm`, `touch`, `install` and
 * friends are deliberately ABSENT even though they are also tabled: naming the policy
 * directory with one of those is not something ordinary work does.
 *
 * NOT HERE, on purpose: `node`, `python3`, `perl`, `ruby` and `sh -c`. An interpreter
 * can do anything, so it is judged by what its SCRIPT contains rather than by its name
 * (see `interpreterTouchesPolicy`) — reading the rules from a script stays allowed,
 * writing them from one does not, even when the path is assembled at run time.
 */
/**
 * Verbs on the list above that stop being readers when given a particular flag.
 *
 * `find` is the one that matters: `find <dir> -name '*.json'` is a read and `find <dir>
 * -delete` empties the directory, under the same verb. Listing `find` without this was a
 * hole I opened in the allowlist itself, not an open class — a read verb with a mutating
 * mode belongs here, next to the list that vouches for it.
 */
const POLICY_READ_VERB_UNLESS: Record<string, RegExp> = {
  find: /^(?:-delete|-exec|-execdir|-ok|-okdir|-fprint|-fprintf|-fls)$/,
};

export const POLICY_READ_VERBS = new Set([
  // read a file
  'cat', 'bat', 'head', 'tail', 'less', 'more', 'nl', 'od', 'xxd', 'strings', 'fold',
  // search it
  'grep', 'egrep', 'fgrep', 'rg', 'ag', 'ack', 'awk', 'gawk', 'sed',
  // parse it
  'jq', 'yq', 'gojq', 'plutil', 'xmllint',
  // compare it
  'diff', 'colordiff', 'cmp', 'comm',
  // count, slice, reshape
  'wc', 'sort', 'uniq', 'cut', 'paste', 'join', 'tr', 'column',
  // ask about it
  'ls', 'find', 'fd', 'stat', 'file', 'du', 'df', 'realpath', 'readlink', 'basename', 'dirname',
  // checksum it
  'md5', 'md5sum', 'shasum', 'sha1sum', 'sha256sum', 'cksum',
  // copy or archive it ELSEWHERE — a write among the operands is caught before this list
  'cp', 'tar', 'zip', 'unzip', 'gzip', 'gunzip', 'ditto',
  // say its name
  'echo', 'printf', 'true', 'false', ':', 'test', '[',
  // move around
  'cd', 'pwd', 'pushd', 'popd',
]);

export type PolicyDecision = 'allow' | 'deny' | 'ask';
export type PolicyMode = 'dry_run' | 'live';

export interface PolicyRule {
  id: string;
  description?: string;
  decision: Exclude<PolicyDecision, 'allow'>;
  mode?: PolicyMode;
  on_error?: 'allow' | 'deny';
  reason: string;
  /**
   * Opt-in (HAG-49): action classes an operator may approve one at a time. When an
   * `ask` rule fires on an action that fits the class grammar and the agent holds a
   * matching grant, the call is allowed and the grant is used. Omit it and the rule
   * asks every time, exactly as before. Valid only on `ask` rules.
   */
  grantable?: string[];
  /** Only these agents (guardrail.json `agents`); absent means every agent. */
  agents?: string[];
  match: {
    tool?: string | string[];
    path_glob?: string;
    path_not_glob?: string;
    command_matches?: string;
    command_not_matches?: string;
    /**
     * true: fires when a path this call writes or removes lies inside ANOTHER agent's
     * workspace (registered cwd, hive folder or isolated worktree) and not inside the
     * acting agent's own. A root that several agents share, or that contains another
     * agent's root, is nobody's: see `ownedRoots`.
     */
    path_in_other_agent_workspace?: boolean;
  };
}

export interface PolicyFile {
  version?: number;
  defaults?: { mode?: PolicyMode; on_error?: 'allow' | 'deny' };
  rules?: PolicyRule[];
  /**
   * Opt-in (HAG-46): check completion reports against recorded test outcomes. Absent
   * means off, and off means nothing of it runs: no extra hook, no outcome capture,
   * no rows. dry_run writes rows only; live also tells god. It never blocks.
   */
  report_check?: { mode?: PolicyMode };
}

/** Per-evaluation scratch, so one payload is parsed once however many rules read it. */
interface EvalContext {
  commands: EffectiveCommand[] | null;
}

export interface PolicyPayload {
  hook_event_name?: string;
  agent_id?: string | null;
  tool_name?: string;
  tool_input?: unknown;
  /**
   * The directory the AGENT's shell is in, from the hook payload.
   *
   * Load-bearing, not a nicety. Without it a relative path resolves against
   * `process.cwd()` — the Electron main process — so `echo x > ../kelly/memory.md`,
   * which is how an agent sitting in its own folder writes to a sibling, resolved to
   * a path under the app's working directory and matched nothing. Only an explicit
   * absolute `cd` in the same command rescued it. It can also misfire the other way,
   * if the daemon's cwd ever sits inside some agent's folder.
   *
   * SECURITY-RELEVANT AND AGENT-CONTROLLED. This value is read straight from the hook
   * payload, so an agent that wants to can send a `cwd` that is not where it is — `/`,
   * `/tmp`, `""` — and turn a relative cross-agent write back into an allow. That sits
   * inside the declared threat model at the top of this file (the transport is fail-open
   * by construction; this is a salience aid against disguise and forgetfulness, not a
   * sandbox against a hostile agent), but it is a NEW field in that category and worth
   * naming rather than leaving to be discovered. A cwd that is merely MISSING is
   * different: that is recorded as an `missing_cwd` blind spot in the ledger.
   */
  cwd?: string;
}

export interface PolicyVerdict {
  decision: PolicyDecision;
  /** The rule that fired, if any. */
  ruleId?: string;
  reason?: string;
  mode?: PolicyMode;
  /** Which matcher key decided it — for the weekly adjudication, so a reviewer
   *  can see whether a glob or a regex produced a questionable deny. */
  matchedOn?: string;
  /** True when a rule in dry_run mode would have denied. The action proceeds. */
  wouldDeny?: boolean;
  /** The grant that allowed an `ask` rule's action (live), or would have (dry_run). */
  grantId?: string;
  /** Live, grantable, and approvable but with no grant: denied so that no terminal
   *  prompt opens (a grant is used on a later call, so it could never answer one).
   *  The daemon raises the approval card; the agent retries after Approve. */
  approvalNeeded?: true;
  /** Live and grantable, but no grant could cover this form (`git push`, force, …).
   *  The daemon may refuse it with the exact approved command instead of asking. */
  notApprovable?: true;
}

/**
 * Glob → RegExp for the path matchers.
 *
 * `**` crosses separators, `*` does not, `?` is one non-separator character.
 * Hand-rolled rather than taken from a dependency: this is two dozen lines, it
 * runs in front of every tool call, and an upstream PR that adds a runtime
 * dependency to evaluate three rules is a harder sell than one that adds none.
 */
export function globToRegExp(glob: string): RegExp {
  let out = '';
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === '*') {
      if (glob[i + 1] === '*') {
        // `**/` should also match zero directories, so `**/a` matches `/a`.
        if (glob[i + 2] === '/') { out += '(?:.*/)?'; i += 2; }
        else if (i === glob.length - 2 && out.endsWith('/')) {
          // A trailing `/**` also matches the directory ITSELF (md-217 N2): the rule
          // "nothing under agents/<x>/" has to include `rm -rf agents/<x>`, which removes
          // everything under it and names no path inside it.
          out = out.slice(0, -1) + '(?:/.*)?';
          i += 1;
        } else { out += '.*'; i += 1; }
      } else {
        out += '[^/]*';
      }
    } else if (c === '?') {
      out += '[^/]';
    } else if ('\\^$.|+()[]{}'.includes(c)) {
      out += '\\' + c;
    } else {
      out += c;
    }
  }
  return new RegExp('^' + out + '$');
}

/**
 * Normalise a payload path to an absolute, forward-slash, symlink-resolved form.
 *
 * Symlinks are resolved because a glob compares strings: without it,
 * `/tmp/shortcut/memory.md` and the agent folder it points into are different
 * subjects, and the shorter one is not covered by any rule. Resolution walks back
 * to the longest existing prefix, so a file that does not exist yet — the normal
 * case for a write — still normalises through a symlinked parent.
 */
export function normalisePath(p: string, cwd?: string): string {
  return realAbsolute(p, cwd ?? process.cwd());
}

/**
 * Substitute the one supported interpolation, `${AGENT_ID}`.
 *
 * Returns null when the glob needs an agent id and the payload has none. That
 * null is load-bearing: an unresolved `${AGENT_ID}` must make the rule FAIL TO
 * MATCH, never match everything. A payload with no agent id is a harness we
 * cannot attribute, and silently applying an ownership rule to it would deny
 * every write on the floor.
 */
export function interpolate(pattern: string, agentId: string | null | undefined): string | null {
  if (!pattern.includes('${AGENT_ID}')) return pattern;
  if (!agentId) return null;
  return pattern.split('${AGENT_ID}').join(agentId);
}

export class PolicyEngine {
  private rules: PolicyRule[] = [];
  private policyPath: string;
  private policyDir: string;
  private hiveRoot: string | null;
  private loadError: string | null = null;
  /** True once a policy FILE has been found on disk. Self-protection is armed by
   *  this, not by rule count: an install with no policy file must behave
   *  byte-identically (nothing evaluated, nothing logged, nothing denied), while
   *  a policy file present but empty of rules must still protect itself. */
  private configured = false;
  private defaults: { mode: PolicyMode; on_error: 'allow' | 'deny' } = { mode: 'dry_run', on_error: 'allow' };
  private loadedAt: string | null = null;
  /** The report check's settings, or null when the policy file does not turn it on. */
  private reportCheckConfig: { mode: PolicyMode } | null = null;

  /** Denominator for the false-positive rate. Counted in memory, never logged
   *  per action: allows are the overwhelming majority and appendLog is a
   *  synchronous append, so logging them would put a disk write in front of
   *  every tool call of every agent. */
  private stats = { evaluated: 0, denied: 0, asked: 0 };
  private lastStatsFlush = Date.now();

  constructor(
    hiveRoot: string | null,
    private log: (row: Record<string, unknown>) => void,
    /** Provider names currently spawned that cannot be governed, so the engine
     *  can name them at load time instead of leaving it to be discovered. */
    private unenforceableProviders: () => string[] = () => [],
    /** Every agent's workspace roots, for `path_in_other_agent_workspace`. Read per
     *  evaluation that needs it, because agents are spawned and archived while the
     *  daemon runs. Optional: without it that matcher never fires. */
    private workspaces: () => AgentWorkspace[] = () => [],
    /** md-136: whether to write the redacted training corpus beside the digest row.
     *  Read per decision so the operator can turn it off without a restart. Defaults
     *  OFF here so an engine built without the wiring behaves exactly as before; the
     *  harness supplies the config, where it defaults ON. */
    private corpusEnabled: () => boolean = () => false,
    /** How the grant check reads a repo (push url, push risks). Injected by tests. */
    private gitInspect: GitInspector = gitInspector
  ) {
    this.hiveRoot = hiveRoot;
    this.policyDir = hiveRoot ? join(hiveRoot, 'policy') : '';
    this.policyPath = this.policyDir ? join(this.policyDir, ENGINE_POLICY_FILE) : '';
  }

  /**
   * Load the policy once, at daemon start.
   *
   * Reload only on an explicit operator action — deliberately NO filesystem
   * watcher. A watcher turns "edit the file" into "disarm the guardrail" with no
   * human in the loop, which is the opposite of what this is for.
   */
  load(): void {
    this.rules = [];
    this.loadError = null;
    this.configured = false;
    this.loadedAt = null;
    this.reportCheckConfig = null;
    if (!this.policyDir) return;
    // One-time move of engine.json + rules.json into guardrail.json. A legacy rule the
    // engine would have refused is not migrated: its file stays and its error is shown.
    let migrationError: string | null = null;
    try {
      const m = migrateLegacyPolicy(this.policyDir, this.log, (r) => this.validate(r as PolicyRule));
      migrationError = m.error ?? null;
    } catch (e) {
      migrationError = `migration to ${GUARDRAIL_FILE} failed: ${e instanceof Error ? e.message : String(e)}`;
    }
    const guardrailPath = join(this.policyDir, GUARDRAIL_FILE);
    const enginePath = join(this.policyDir, LEGACY_ENGINE_FILE);
    const legacyPath = join(this.policyDir, LEGACY_POLICY_FILE);
    const hasGuardrail = existsSync(guardrailPath);
    const hasEngine = existsSync(enginePath);
    const hasLegacy = existsSync(legacyPath);
    if (!hasGuardrail && !hasEngine && !hasLegacy) { this.policyPath = guardrailPath; return; } // unconfigured → inert
    // Any policy file arms self-protection: an install that has any policy at all must
    // not let an agent rewrite it, whichever reader the file was written for.
    this.configured = true;
    if (!hasGuardrail) {
      this.policyPath = hasEngine ? enginePath : legacyPath;
      if (hasEngine) { this.fail(migrationError ?? `${LEGACY_ENGINE_FILE} could not be moved into ${GUARDRAIL_FILE}`); return; }
      let legacy: unknown = null;
      try { legacy = JSON.parse(readFileSync(legacyPath, 'utf8')); } catch { /* reported below */ }
      let hookSchema = false;
      try { hookSchema = !!legacy && typeof legacy === 'object' && isHookSchema(legacy as PolicyFile); } catch { /* not the hook's either */ }
      this.fail(hookSchema
        ? `${LEGACY_POLICY_FILE} is the guardrail-hook schema (match.kind), which this engine does not read; `
          + `the engine's rules live in ${GUARDRAIL_FILE}. 0 engine rules loaded.`
        : `${LEGACY_POLICY_FILE} is not read by the engine; the rules live in ${GUARDRAIL_FILE}. 0 engine rules loaded.`);
      return;
    }
    this.policyPath = guardrailPath;
    const g = readGuardrail(guardrailPath);
    if (!g.ok) {
      // Refuse a half-read policy. Partial enforcement is worse than none, because it
      // is believed.
      this.fail(g.error);
      return;
    }
    const parsed: PolicyFile = {
      version: 1,
      ...(g.file.defaults?.on_error ? { defaults: { on_error: g.file.defaults.on_error } } : {}),
      ...(g.file.report_check !== undefined ? { report_check: g.file.report_check } : {}),
      rules: toEngineRules(g.file),
    };

    try {
      // A file with rules whose backstops are all off enforces nothing ON PURPOSE; a
      // file with no rules at all is a truncated write or a bad edit.
      this.loadParsed(parsed, g.file.rules.length > 0);
    } catch (e) {
      // md-217 N1: a file that parses but has the wrong shape threw here and left
      // `configured: true, error: null` behind, which reads as healthy. Nothing that
      // happens past the parse may leave the engine silently enforcing nothing.
      this.rules = [];
      this.loadedAt = null;
      this.fail(`policy file could not be read as rules: ${e instanceof Error ? e.message : String(e)}`);
    }
  }

  /** Everything after the JSON parse. Split out so `load` can guarantee that a throw
   *  becomes a logged failure instead of a quiet zero. */
  private loadParsed(parsed: PolicyFile, noBackstopsIsFine: boolean): void {
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
      this.fail(`policy file must be a JSON object with a "rules" array, got ${parsed === null ? 'null' : Array.isArray(parsed) ? 'an array' : typeof parsed}`);
      return;
    }
    if (parsed.rules !== undefined && !Array.isArray(parsed.rules)) {
      this.fail(`"rules" must be an array, got ${parsed.rules === null ? 'null' : typeof parsed.rules}`);
      return;
    }
    const invalid: Array<{ id: string; why: string }> = [];
    const rules: PolicyRule[] = [];
    for (const rule of parsed.rules ?? []) {
      const why = this.validate(rule);
      if (why) { invalid.push({ id: rule?.id ?? '(no id)', why }); continue; }
      rules.push(rule);
    }
    if (invalid.length) {
      this.fail(invalid.map((i) => `${i.id}: ${i.why}`).join('; '), invalid);
      return; // all-or-nothing: a policy you cannot fully trust is not loaded
    }
    // The report check is an observer, not a rule. A bad block turns IT off and says so;
    // it must never unload the rules (Dwight, HAG-46 R1): "partial enforcement is
    // believed" is about rules, and nobody believes an off observer is enforcing.
    let rc: { mode?: PolicyMode } | undefined = parsed.report_check;
    if (rc !== undefined) {
      const why = rc === null || typeof rc !== 'object' || Array.isArray(rc)
        ? 'report_check must be an object, e.g. { "mode": "dry_run" }'
        : rc.mode !== undefined && rc.mode !== 'dry_run' && rc.mode !== 'live'
          ? `report_check.mode must be dry_run or live, got ${JSON.stringify(rc.mode)}`
          : null;
      if (why) {
        this.log({ kind: 'report-check-config-invalid', path: this.policyPath, error: why });
        rc = undefined;
      }
    }
    if (!rules.length && !noBackstopsIsFine) {
      // A policy file that exists but names no rules is a truncated write or a bad
      // hand edit far more often than a deliberate choice, and it enforces nothing.
      // Self-protection stays armed; the status says so loudly. (To turn the engine
      // off, remove the file, or touch nothing and set every rule to dry_run.)
      this.fail('policy file has no rules: nothing is enforced');
      return;
    }

    if (parsed.defaults?.mode) this.defaults.mode = parsed.defaults.mode;
    if (parsed.defaults?.on_error) this.defaults.on_error = parsed.defaults.on_error;
    this.rules = rules;
    this.loadedAt = new Date().toISOString();
    if (rc) this.reportCheckConfig = { mode: (rc.mode ?? this.defaults.mode) as PolicyMode };

    const gaps = this.unenforceableProviders();
    this.log({
      kind: 'policy-loaded',
      path: this.policyPath,
      rules_loaded: rules.length,
      rules: rules.map((r) => ({ id: r.id, decision: r.decision, mode: r.mode ?? this.defaults.mode })),
      // Named, not a static warning. A generic "some providers may not be
      // governed" gets skimmed; a list of the agents running right now does not.
      unenforceable_providers: gaps,
      // Only when turned on, so a policy without it logs exactly the row it always did.
      ...(this.reportCheckConfig ? { report_check: this.reportCheckConfig.mode } : {}),
    });
  }

  /** A configured policy that loaded no rules. One place, so every failure is logged
   *  the same way and `status` reports the same string the log carries. */
  private fail(error: string, invalid?: Array<{ id: string; why: string }>): void {
    this.loadError = error;
    this.log({ kind: 'policy-load-failed', path: this.policyPath, rules_loaded: 0, error, ...(invalid ? { invalid } : {}) });
  }

  /** The single answer to "is the guardrail enforcing anything?". */
  get status(): PolicyStatus {
    return {
      configured: this.configured,
      file: this.configured ? this.policyPath : null,
      rulesLoaded: this.rules.length,
      ruleIds: this.rules.map((r) => r.id),
      error: this.loadError,
      loadedAt: this.loadedAt,
    };
  }

  /** The engine's own check of rules about to be saved (the Rules screen), as
   *  "<id>: <why>". Empty when every rule would load. */
  checkRules(rules: PolicyRule[]): string[] {
    const out: string[] = [];
    for (const r of rules) {
      const why = this.validate(r);
      if (why) out.push(`${r?.id ?? '(no id)'}: ${why}`);
    }
    return out;
  }

  /** Would this rule fire on this call? For the Rules screen's tester: it logs and
   *  records nothing, and never touches the loaded rules. */
  wouldMatch(rule: PolicyRule, p: PolicyPayload): { fires: boolean; on?: string; error?: string } {
    const why = this.validate(rule);
    if (why) return { fires: false, error: why };
    if (rule.agents && !(p.agent_id && rule.agents.includes(p.agent_id))) return { fires: false };
    try {
      const hit = this.matches(rule, p, { commands: null });
      return hit ? { fires: true, on: hit } : { fires: false };
    } catch (e) {
      return { fires: false, error: e instanceof Error ? e.message : String(e) };
    }
  }

  /** Reason a rule is unusable, or null. Rejected at load, never at evaluation. */
  private validate(rule: PolicyRule): string | null {
    if (!rule || typeof rule !== 'object') return 'not an object';
    if (!rule.id) return 'missing id';
    if (rule.decision !== 'deny' && rule.decision !== 'ask') return `decision must be deny or ask, got ${String(rule.decision)}`;
    if (!rule.reason) return 'missing reason — a refusal with no sanctioned alternative makes an agent retry or route around it';
    if (!rule.match || typeof rule.match !== 'object') return 'missing match';
    const keys = Object.keys(rule.match);
    if (!keys.length) return 'match is empty — it would fire on every tool call';
    for (const k of keys) {
      if (!(MATCHERS as readonly string[]).includes(k)) return `unknown matcher "${k}"`;
    }
    for (const k of ['path_glob', 'path_not_glob'] as const) {
      const g = rule.match[k];
      // An unanchored glob such as "agents/*/**" would match relative to nothing.
      if (g && !g.startsWith('/') && !g.startsWith('**')) return `${k} must be absolute or start with ** (got "${g}")`;
    }
    if (rule.match.path_in_other_agent_workspace !== undefined && rule.match.path_in_other_agent_workspace !== true) {
      return 'path_in_other_agent_workspace must be true (omit the key to turn it off)';
    }
    for (const k of ['command_matches', 'command_not_matches'] as const) {
      const r = rule.match[k];
      if (r) { try { new RegExp(r); } catch (e) { return `${k} is not a valid regex: ${String(e)}`; } }
    }
    if (rule.mode && rule.mode !== 'dry_run' && rule.mode !== 'live') return `mode must be dry_run or live, got ${String(rule.mode)}`;
    if (rule.on_error && rule.on_error !== 'allow' && rule.on_error !== 'deny') return `on_error must be allow or deny, got ${String(rule.on_error)}`;
    if (rule.grantable !== undefined) {
      if (!Array.isArray(rule.grantable) || !rule.grantable.length) return 'grantable must be a non-empty array, e.g. ["git-push"]';
      const bad = rule.grantable.find((g) => !(GRANT_CLASSES as readonly string[]).includes(g));
      if (bad !== undefined) return `grantable: unknown action class ${JSON.stringify(bad)} (known: ${GRANT_CLASSES.join(', ')})`;
      if (rule.decision !== 'ask') return 'grantable is only valid on an ask rule: a grant answers an ask, it does not lift a deny';
    }
    return null;
  }

  /**
   * True when this payload WRITES to the policy file or its directory.
   *
   * Write/Edit/NotebookEdit are exact — the path is a field. Bash is matched by
   * looking for the policy directory in the command together with a write
   * indicator, so that reading the policy (to explain a deny, say) stays allowed
   * while rewriting it does not. That is deliberately under-inclusive on the long
   * tail: a script given the path indirectly is not caught, and no regex would.
   * The tools that do the overwhelming majority of writes are matched exactly.
   */
  private targetsPolicy(p: PolicyPayload, ctx: EvalContext): boolean {
    if (!this.policyDir) return false;
    const dir = normalisePath(this.policyDir);
    const under = (path: string) => {
      const abs = normalisePath(path, p.cwd);
      return abs === dir || abs.startsWith(dir + '/');
    };
    const tool = p.tool_name;
    if (tool === 'Write' || tool === 'Edit' || tool === 'NotebookEdit') {
      return this.paths(p, ctx).some(under);
    }
    if (tool === 'Bash') {
      const input = (p.tool_input ?? {}) as Record<string, unknown>;
      const cmd = typeof input.command === 'string' ? input.command : '';
      if (!cmd) return false;
      const commands = this.commands(p, ctx);
      // 1. A resolved path the command mutates: written INTO, or taken away. `mv
      //    <policy>/authority.json /tmp/` disables every rule on the floor in one
      //    command, so a source a verb removes counts as a mutation of where it was.
      for (const c of commands) if (c.writes.some(under) || c.removes.some(under)) return true;
      // 2. THE INVERTED DEFAULT. A segment that names a path inside the policy
      //    directory is denied unless its verb is a known reader. This is what closes
      //    the class the previous string heuristic could only chase one verb at a time.
      for (const c of commands) {
        if (!this.segmentTouchesPolicy(c, dir, p.cwd)) continue;
        // Could not read the command AND it names the directory. Only a STRUCTURAL blind
        // spot counts: a path whose value is a guess does not mean the parse is wrong,
        // and `cp <policy>/authority.json mine.json` is still a read.
        if (c.unresolved.some((u) => STRUCTURAL_UNRESOLVED.has(u.code))) return true;
        const verb = verbOf(c.argv);
        const script = inlineScript(c.argv);
        // An interpreter is judged by its script, not its name: a script that names the
        // directory and writes is a write, even with the path built at run time.
        if (script !== null) { if (scriptWrites(script)) return true; continue; }
        if (!POLICY_READ_VERBS.has(verb)) return true;
        const unless = POLICY_READ_VERB_UNLESS[verb];
        if (unless && c.argv.slice(1).some((a) => unless.test(a))) return true;
      }
      // 3. The old string heuristic, per segment, still there for a segment that does
      //    not resolve a policy path but looks like it mutates one anyway.
      for (const c of commands) {
        if (c.verbWrites.length) continue;
        if (c.text.includes(this.policyDir) && POLICY_WRITE_SHAPE.test(c.text)) return true;
      }
      // 4. Only when the parser says it could not read this command do we fall back to
      //    the whole string, because then the segmentation above cannot be trusted.
      if (commands.some((c) => c.unresolved.some((u) => STRUCTURAL_UNRESOLVED.has(u.code)))) {
        return cmd.includes(this.policyDir) && POLICY_WRITE_SHAPE.test(cmd);
      }
      return false;
    }
    return false;
  }

  /**
   * Every path this payload would write, across tools and bash redirection.
   *
   * For a tool with a path FIELD the answer is that field — exact, and unchanged.
   * For Bash it is what shell.ts says the command writes, which is the half that
   * used to be missing entirely: a rule saying "not outside your own folder"
   * described `Write` and said nothing about `cat x > …`, `cp … other/`,
   * `sed -i … other/f` or `node -e "writeFileSync(…)"`, which is how a bash-first
   * agent writes files.
   */
  private paths(p: PolicyPayload, ctx: EvalContext): string[] {
    const input = (p.tool_input ?? {}) as Record<string, unknown>;
    const out: string[] = [];
    for (const f of PATH_FIELDS) {
      const v = input[f];
      if (typeof v === 'string' && v) out.push(v);
    }
    if (p.tool_name === 'Bash') {
      for (const c of this.commands(p, ctx)) {
        out.push(...c.writes);
        // …and the paths a verb takes AWAY. `mv <other agent>/memory.md /tmp/` destroys
        // their file as surely as writing over it, and an ownership rule that only looks
        // at where a write LANDS calls that a read. Same principle the policy invariant
        // needed; there is no reason it stops at the policy directory.
        out.push(...c.removes);
      }
    }
    return out;
  }

  /**
   * The paths this payload REMOVES wholesale, normalised with no trailing slash: the
   * targets of a deleting verb (rm, rmdir, unlink, shred, a deleting find, xargs rm)
   * and the sources a verb takes away (mv). Only these can "contain" another agent's
   * workspace — `cp report.md <hive>/` writes INTO a directory and leaves its contents
   * alone, so it must not count as destroying everything under it.
   */
  private destroyPaths(p: PolicyPayload, ctx: EvalContext): string[] {
    if (p.tool_name !== 'Bash') return [];
    const out: string[] = [];
    for (const c of this.commands(p, ctx)) {
      const verb = (c.argv[0] ?? '').split('/').pop() ?? '';
      const targets = [...c.removes, ...(DESTROY_VERBS.has(verb) ? c.verbWrites : [])];
      for (const t of targets) out.push(normalisePath(t, p.cwd).replace(/\/+$/, '') || '/');
    }
    return out;
  }

  /** shell.ts output for this payload, parsed once per evaluation and reused by
   *  every rule — parsing is the only non-trivial cost in front of a tool call. */
  private commands(p: PolicyPayload, ctx: EvalContext): EffectiveCommand[] {
    if (ctx.commands) return ctx.commands;
    const input = (p.tool_input ?? {}) as Record<string, unknown>;
    const cmd = typeof input.command === 'string' ? input.command : '';
    ctx.commands = cmd ? effectiveCommands(cmd, p.cwd) : [];
    return ctx.commands;
  }

  /**
   * Evaluate one payload.
   *
   * Only PreToolUse is considered; every other event returns allow untouched.
   */
  evaluate(p: PolicyPayload): PolicyVerdict {
    if (p.hook_event_name !== 'PreToolUse') return { decision: 'allow' };
    if (!this.configured) return { decision: 'allow' }; // unconfigured → byte-identical

    const ctx: EvalContext = { commands: null };
    const verdict = this.decide(p, ctx);
    // AFTER the verdict, and it cannot change it — the row carries the decision that
    // was actually returned, so a reader can tell a blind spot that was allowed from
    // one a rule caught anyway.
    this.recordUnresolved(p, ctx, verdict);
    return verdict;
  }

  /** The rules, in order. Split out so every return path is one `evaluate` call. */
  private decide(p: PolicyPayload, ctx: EvalContext): PolicyVerdict {
    this.stats.evaluated++;
    this.maybeFlushStats();

    // Invariant, ahead of user rules and not overridable by config: an agent that
    // can edit the policy file makes every rule advisory. This holds even with no
    // policy loaded, which is why it is part of the mechanism and not a rule.
    if (this.configured && this.targetsPolicy(p, ctx)) {
      const verdict: PolicyVerdict = {
        decision: 'deny',
        ruleId: 'policy-self-protection',
        mode: 'live',
        matchedOn: 'policy_path',
        reason:
          'The policy file governs every agent, so no agent may edit it. If a rule is wrong, '
          + 'say which rule and why in your reply — the operator changes it.',
      };
      this.record(p, verdict, ctx);
      return verdict;
    }

    for (const rule of this.rules) {
      // A backstop for named agents is not this agent's: it neither fires nor errors.
      if (rule.agents && !(p.agent_id && rule.agents.includes(p.agent_id))) continue;
      let hit: string | null;
      try {
        hit = this.matches(rule, p, ctx);
      } catch (e) {
        // Per-rule failure posture. An evaluator exception is something the daemon
        // can see, unlike a daemon that never received the call — see the transport
        // note at the top of this file.
        const posture = rule.on_error ?? this.defaults.on_error;
        this.log({
          kind: 'policy-rule-error', rule_id: rule.id, on_error: posture,
          error: e instanceof Error ? e.message : String(e),
        });
        if (posture === 'deny') {
          const verdict: PolicyVerdict = {
            decision: 'deny', ruleId: rule.id, mode: 'live', matchedOn: 'error',
            reason: `${rule.reason} (this rule could not be evaluated and is configured to fail closed)`,
          };
          this.record(p, verdict, ctx);
          return verdict;
        }
        continue; // fail open: this rule abstains, later rules still run
      }
      if (!hit) continue;

      const mode = rule.mode ?? this.defaults.mode;
      const { grant, approvable } = rule.grantable ? this.grantFor(rule, p) : { grant: null, approvable: false };
      if (mode === 'dry_run') {
        // Evaluate fully, log, and ALLOW. You cannot measure a false positive
        // after enforcing, because the deny already stopped the work you would
        // have judged. A grant is noted, not used: it is what live mode would do.
        const verdict: PolicyVerdict = {
          decision: 'allow', ruleId: rule.id, reason: rule.reason,
          mode, matchedOn: hit, wouldDeny: true, ...(grant ? { grantId: grant.id } : {}),
        };
        this.record(p, verdict, ctx);
        return verdict;
      }
      if (grant) {
        // The operator approved exactly this action for this agent. Use the grant
        // BEFORE returning, so a second identical call sees it used.
        this.grants().use(grant);
        const verdict: PolicyVerdict = {
          decision: 'allow', ruleId: rule.id, reason: rule.reason, mode, matchedOn: hit, grantId: grant.id,
        };
        this.record(p, verdict, ctx);
        return verdict;
      }
      // An approvable action with no grant is denied, not asked: an ask opens Claude
      // Code's terminal prompt, and the grant the operator mints for it is only used
      // on a LATER call, so Approve could never answer that prompt.
      const verdict: PolicyVerdict = approvable
        ? { decision: 'deny', ruleId: rule.id, reason: rule.reason, mode, matchedOn: hit, approvalNeeded: true }
        : { decision: rule.decision, ruleId: rule.id, reason: rule.reason, mode, matchedOn: hit, ...(rule.grantable ? { notApprovable: true as const } : {}) };
      this.record(p, verdict, ctx);
      return verdict;
    }
    return { decision: 'allow' };
  }

  /** The grants file. Touched only when a rule is grantable, so an install with no
   *  grantable rule never reads, creates or names it. */
  private grantStore: GrantStore | null = null;
  private grants(): GrantStore {
    if (!this.grantStore) this.grantStore = GrantStore.in(this.policyDir);
    return this.grantStore;
  }

  /** True when some loaded rule is grantable: the switch for the whole approval flow. */
  get grantsActive(): boolean {
    return this.rules.some((r) => Array.isArray(r.grantable) && r.grantable.length > 0);
  }

  /** A grant that covers this exact call, or null, and whether a grant COULD cover
   *  it (the approvable form, for a grantable class). Any error means neither: it asks. */
  private grantFor(rule: PolicyRule, p: PolicyPayload): { grant: Grant | null; approvable: boolean } {
    const none = { grant: null, approvable: false };
    if (rule.decision !== 'ask' || !p.agent_id || !this.policyDir) return none;
    try {
      const input = (p.tool_input ?? {}) as Record<string, unknown>;
      if (p.tool_name !== 'Bash' || typeof input.command !== 'string') return none;
      const c = canonicalAction(input.command, p.cwd, this.gitInspect);
      if (!c.ok || !rule.grantable!.includes(c.action.class)) return none;
      return { grant: this.grants().findUsable(p.agent_id, c.action), approvable: true };
    } catch {
      return none;
    }
  }

  /** Which matcher key fired, or null if the rule does not match. */
  private matches(rule: PolicyRule, p: PolicyPayload, ctx: EvalContext): string | null {
    const m = rule.match;
    let matchedOn: string | null = null;

    if (m.tool !== undefined) {
      const want = Array.isArray(m.tool) ? m.tool : [m.tool];
      if (!p.tool_name || !want.includes(p.tool_name)) return null;
      matchedOn = 'tool';
    }

    if (m.command_matches !== undefined || m.command_not_matches !== undefined) {
      const input = (p.tool_input ?? {}) as Record<string, unknown>;
      const cmd = typeof input.command === 'string' ? input.command : '';
      // The raw string AND every command the parser says this call runs. Raw is
      // kept so a pack written against the old behaviour keeps working; the
      // parsed forms are what let a rule be anchored at ^ and still catch
      // `sudo`, `eval`, `$VAR`, an absolute path or a `bash -c` wrapper.
      const subjects = cmd ? [cmd, ...this.commands(p, ctx).map((c) => c.text)] : [];
      if (m.command_matches !== undefined) {
        const re = new RegExp(m.command_matches);
        if (!subjects.some((s) => re.test(s))) return null;
        matchedOn = 'command_matches';
      }
      if (m.command_not_matches !== undefined) {
        const re = new RegExp(m.command_not_matches);
        if (subjects.some((s) => re.test(s))) return null;
      }
    }

    if (m.path_glob !== undefined || m.path_not_glob !== undefined) {
      const paths = this.paths(p, ctx).map((x) => normalisePath(x, p.cwd));
      if (!paths.length) return null;

      // Judged PER PATH, not per payload. With one path field the two are the
      // same thing, which is why this never mattered before; a Bash command can
      // write several places at once, and `tee mine/a theirs/b` must not exempt
      // itself with the half that is allowed.
      let negative: RegExp | null = null;
      if (m.path_not_glob !== undefined) {
        const pattern = interpolate(m.path_not_glob, p.agent_id);
        // A negative glob that cannot be resolved cannot exempt anything, so the
        // rule must not fire at all rather than fire on every agent's own files.
        if (pattern === null) return null;
        negative = globToRegExp(pattern);
      }
      const eligible = negative ? paths.filter((x) => !negative!.test(x)) : paths;
      if (!eligible.length) return null;

      if (m.path_glob !== undefined) {
        const pattern = interpolate(m.path_glob, p.agent_id);
        if (pattern === null) return null; // unresolved ${AGENT_ID} must not match
        const re = globToRegExp(pattern);
        // A removal of a directory that CONTAINS matching paths counts too: `rm -rf
        // hive/agents` names no path inside any agent folder and empties all of them.
        const destroyed = new Set(this.destroyPaths(p, ctx));
        const hit = eligible.some((x) => re.test(x)
          || (destroyed.has(x) && globContains(x, pattern, negative)));
        if (!hit) return null;
        matchedOn = 'path_glob';
      }
    }

    if (m.path_in_other_agent_workspace) {
      // No agent id: we cannot say whose workspace is "other", so nothing is.
      if (!p.agent_id) return null;
      const paths = this.paths(p, ctx).map((x) => normalisePath(x, p.cwd));
      if (!paths.length) return null;
      const roots = ownedRoots(this.workspaces());
      const foreign = paths.some((x) => {
        const owner = ownerOf(x, roots);
        return owner !== null && owner !== p.agent_id;
      }) || this.destroyPaths(p, ctx).some((x) => {
        // md-217 N2: removing a directory that CONTAINS someone else's workspace —
        // `rm -rf <home>/worktrees`, `rm -rf ..` from inside your own worktree — takes
        // theirs with it, and names no path inside it.
        const prefix = x === '/' ? '/' : x + '/';
        return roots.some((r) => r.agentId !== p.agent_id && r.root.startsWith(prefix));
      });
      if (!foreign) return null;
      matchedOn = 'path_in_other_agent_workspace';
    }

    return matchedOn;
  }

  /**
   * One ledger row per deny or ask (including a dry-run would-deny). Never for an
   * allow, and never the raw tool_input — tool inputs carry file contents and
   * secrets, so the row keeps a digest plus which matcher fired.
   */
  private record(p: PolicyPayload, v: PolicyVerdict, ctx?: EvalContext): void {
    if (v.decision === 'deny') this.stats.denied++;
    else if (v.decision === 'ask') this.stats.asked++;
    const input_digest = digest(p.tool_input);
    this.log({
      kind: 'policy-decision',
      agent_id: p.agent_id ?? null,
      rule_id: v.ruleId,
      tool: p.tool_name,
      decision: v.decision,
      mode: v.mode,
      would_deny: v.wouldDeny ?? false,
      matched_on: v.matchedOn,
      input_digest,
      ...(v.grantId ? { grant_id: v.grantId } : {}),
      ...(v.approvalNeeded ? { approval_needed: true } : {}),
    });
    this.recordCorpus(p, v, ctx, input_digest);
  }

  /**
   * md-136: the redacted training record, beside the hash and never instead of it.
   *
   * Everything that could carry a value goes through corpus.ts, which emits shape or a
   * placeholder and nothing in between. Wrapped exactly like the ledger in md-222: the
   * write is best effort and cannot reach the verdict, because a corpus that failed to
   * append must never be the reason an action was allowed or denied.
   */
  private recordCorpus(p: PolicyPayload, v: PolicyVerdict, ctx: EvalContext | undefined, input_digest: string): void {
    if (!this.policyDir || !this.corpusEnabled()) return;
    try {
      const cctx: CorpusContext = {
        agentId: p.agent_id ?? null,
        agentIds: this.workspaces().map((w) => w.agentId),
        home: homedir(),
        hiveRoot: this.hiveRoot,
        policyDir: this.policyDir,
        cwd: p.cwd,
      };
      const row = corpusRecord({
        payload: { tool_name: p.tool_name, agent_id: p.agent_id, tool_input: p.tool_input, cwd: p.cwd },
        // Field by field, as corpus.ts requires: `grantId` is a value, so only the fact
        // that a grant was used (live) crosses over. A dry_run note of a grant is not a use.
        verdict: { decision: v.decision, ruleId: v.ruleId, mode: v.mode, matchedOn: v.matchedOn, wouldDeny: v.wouldDeny, granted: !!v.grantId && !v.wouldDeny, approvalNeeded: v.approvalNeeded === true },
        commands: ctx?.commands ?? [],
        ctx: cctx,
        digest: input_digest,
      });
      appendFileSync(join(this.policyDir, CORPUS_FILE), JSON.stringify({ ts: new Date().toISOString(), ...row }) + '\n');
    } catch { /* the corpus is a byproduct, never a dependency */ }
  }

  /**
   * One `unresolved` row per Bash payload the parser could not fully read.
   *
   * NO DECISION IS TAKEN FROM THIS. Failing closed on an unreadable command is a
   * separate call with a real cost — every `curl | sh` in ordinary build work would
   * start asking — so this deliberately only counts. `event: "unresolved"` and the
   * `codes` array are the query surface: `jq 'select(.event=="unresolved") | .codes'`
   * over the ledger answers "what are we blind to, and how often" without reading
   * prose.
   *
   * What is NOT in the row: the command. Rows go to a file an operator reads, and an
   * argument carries file contents and secrets — the same reason `record()` logs a
   * digest instead of the tool input. Each blind spot contributes a reason code and a
   * structural token (a placeholder, a program or variable NAME, a path), and the
   * digest ties the row back to the call if someone needs the rest.
   */
  private recordUnresolved(p: PolicyPayload, ctx: EvalContext, v: PolicyVerdict): void {
    if (p.tool_name !== 'Bash') return;
    const commands = ctx.commands;
    if (!commands?.length) return; // nothing was parsed, so nothing was hidden

    const seen = new Set<string>();
    const blind: Unresolved[] = [];
    for (const c of commands) {
      for (const u of c.unresolved) {
        const key = `${u.code}\u0000${u.detail}`;
        if (seen.has(key)) continue;
        seen.add(key);
        if (blind.length < MAX_UNRESOLVED_PER_ROW) blind.push(u);
      }
    }
    if (!blind.length) return;

    const row = {
      kind: 'policy-unresolved',
      event: 'unresolved',
      agent_id: p.agent_id ?? null,
      tool: p.tool_name,
      decision: v.decision,
      rule_id: v.ruleId ?? null,
      codes: [...new Set(blind.map((u) => u.code))].sort(),
      unresolved: blind,
      input_digest: digest(p.tool_input),
    };
    this.log(row);
    this.appendLedger(row);
  }

  /**
   * Mirror a row into `<hive>/policy/decisions.jsonl`, the ledger an operator already
   * reads (the shell guardrail writes its `event: "firing"` rows there).
   *
   * Best effort by construction: a ledger that cannot be written must never fail a
   * tool call, so every error is swallowed. The file is the audit trail, not the
   * mechanism.
   */
  /**
   * Does this one command name a path inside the policy directory?
   *
   * Operands, redirection targets, and — for an inline script — the string literals in
   * it. Resolved, so a relative path or a symlink counts. A MENTION does not: the
   * operand of `echo "never edit <policy>/authority.json"` is a whole sentence, which
   * resolves under the cwd rather than under the policy directory, so prose about the
   * rules is not an attempt on them.
   */
  private segmentTouchesPolicy(c: EffectiveCommand, dir: string, cwd?: string): boolean {
    const under = (path: string) => {
      const abs = normalisePath(path, cwd);
      return abs === dir || abs.startsWith(dir + '/');
    };
    if (c.writes.some(under) || c.removes.some(under)) return true;
    const script = inlineScript(c.argv);
    if (script !== null && scriptLiterals(script).some(under)) return true;
    return operandsOf(c.argv).some(under);
  }

  private appendLedger(row: Record<string, unknown>): void {
    if (!this.policyDir) return;
    try {
      appendFileSync(
        join(this.policyDir, 'decisions.jsonl'),
        JSON.stringify({ id: ledgerId(), ts: new Date().toISOString(), ...row }) + '\n'
      );
    } catch { /* the ledger is evidence, never a dependency */ }
  }

  private maybeFlushStats(): void {
    if (Date.now() - this.lastStatsFlush < STATS_INTERVAL_MS) return;
    this.flushStats();
  }

  /**
   * Emit the denominator. Called hourly (lazily, on the next evaluation) and at
   * shutdown. The headline metric is the false-positive RATE from adjudicated
   * deny rows; this supplies denies-per-N-evaluated as load. A block count is
   * deliberately not a headline — "1,247 actions blocked" is the metric of a
   * feature about to be switched off.
   */
  flushStats(): void {
    if (!this.stats.evaluated) return;
    this.log({ kind: 'policy-stats', ...this.stats });
    this.stats = { evaluated: 0, denied: 0, asked: 0 };
    this.lastStatsFlush = Date.now();
  }

  /** Whether a policy file was found. False means fully inert: HookServer skips
   *  the engine entirely, so an unconfigured install evaluates nothing. */
  get active(): boolean { return this.configured; }
  /** Non-null only when a policy file loaded cleanly AND turned the report check on. */
  get reportCheck(): { mode: PolicyMode } | null { return this.reportCheckConfig; }
  get ruleCount(): number { return this.rules.length; }
  get error(): string | null { return this.loadError; }
  get path(): string { return this.policyPath; }
}

/**
 * True when a parsed policy file is written for bin/guardrail-hook.cjs rather than for
 * this engine: its rules carry `match.kind`, or an upper-case mode. Either marker is
 * enough — no engine rule can have one and still validate.
 */
export function isHookSchema(parsed: PolicyFile): boolean {
  return (parsed.rules ?? []).some((r) => {
    const rule = r as unknown as { match?: Record<string, unknown>; mode?: unknown };
    return (rule?.match && 'kind' in rule.match) || rule?.mode === 'DRY_RUN' || rule?.mode === 'LIVE';
  });
}

/**
 * The workspace roots that belong to exactly one agent.
 *
 * A root is OWNED only when (a) no other agent registered the same root and (b) it
 * does not contain another agent's root. Both exclusions are what keep this from
 * firing on ordinary work. On a floor where every agent starts in the same repo
 * directory, that directory is everyone's, so writing to it is nobody's business. The
 * orchestrator's cwd usually contains the whole hive, so it is a container, not a
 * workspace. What is left is the case that went unnoticed: an agent's own worktree or
 * checkout, which is where `rm -rf` into a colleague's work actually lands.
 */
export function ownedRoots(workspaces: AgentWorkspace[]): Array<{ agentId: string; root: string }> {
  const byRoot = new Map<string, Set<string>>();
  for (const w of workspaces) {
    for (const r of w.roots) {
      if (!r) continue;
      const root = normalisePath(r).replace(/\/+$/, '') || '/';
      if (!byRoot.has(root)) byRoot.set(root, new Set());
      byRoot.get(root)!.add(w.agentId);
    }
  }
  const all = [...byRoot.keys()];
  const out: Array<{ agentId: string; root: string }> = [];
  for (const [root, owners] of byRoot) {
    if (owners.size !== 1) continue;
    const [agentId] = owners;
    const prefix = root === '/' ? '/' : root + '/';
    const containsOther = all.some((o) => o !== root && o.startsWith(prefix)
      && [...byRoot.get(o)!].some((id) => id !== agentId));
    if (containsOther) continue;
    out.push({ agentId, root });
  }
  return out;
}

/**
 * Does the existing directory `dir` contain a path that `glob` matches and `negative`
 * does not? Grounded in the disk, not in the pattern: `rm -rf /tmp/build` must not
 * fire because a `hive/agents/x/y` COULD be created under it, only because one IS there.
 *
 * The glob is split at each segment boundary; where the head of the pattern matches
 * `dir` itself, the tail is walked into the real directory (a literal segment must
 * exist, a wildcard segment reads the entries, `**` stands for anything below). Bounded
 * by entry count and depth, and any fs error just means "not shown to contain".
 */
export function globContains(dir: string, glob: string, negative: RegExp | null): boolean {
  const full = globToRegExp(glob);
  const segs = glob.split('/');
  const probe = (d: string) => {
    const leaf = d.replace(/\/+$/, '') + '/\u0001';
    return full.test(leaf) && !(negative && negative.test(leaf));
  };
  const isDir = (d: string) => { try { return statSync(d).isDirectory(); } catch { return false; } };
  const walk = (d: string, rest: string[], depth: number): boolean => {
    if (depth > 8 || !isDir(d)) return false;
    if (!rest.length || rest[0] === '**') return probe(d);
    const [seg, ...tail] = rest;
    if (!/[*?]/.test(seg)) return walk(join(d, seg), tail, depth + 1);
    const re = globToRegExp(seg);
    let names: string[] = [];
    try { names = readdirSync(d).slice(0, 500); } catch { return false; }
    return names.some((n) => re.test(n) && walk(join(d, n), tail, depth + 1));
  };
  for (let k = segs.length - 2; k >= 0; k--) {
    const head = segs.slice(0, k + 1).join('/');
    if (!head || head === '**') continue;
    if (!globToRegExp(head).test(dir)) continue;
    if (walk(dir, segs.slice(k + 1), 0)) return true;
  }
  return false;
}

/** The agent whose owned root holds this absolute path, or null. Deepest root wins. */
function ownerOf(abs: string, roots: Array<{ agentId: string; root: string }>): string | null {
  let best: { agentId: string; root: string } | null = null;
  for (const r of roots) {
    if (abs === r.root || abs.startsWith(r.root === '/' ? '/' : r.root + '/')) {
      if (!best || r.root.length > best.root.length) best = r;
    }
  }
  return best ? best.agentId : null;
}

/** The ledger's id shape, matching the rows the shell guardrail already writes. */
function ledgerId(): string {
  return Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 8);
}

/** sha256 of the tool input, so a row is correlatable without storing content. */
export function digest(input: unknown): string {
  let s: string;
  try { s = JSON.stringify(input ?? null) ?? 'null'; } catch { s = '[unserialisable]'; }
  return 'sha256:' + createHash('sha256').update(s).digest('hex').slice(0, 16);
}
