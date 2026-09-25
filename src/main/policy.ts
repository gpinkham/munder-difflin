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
import { readFileSync, existsSync, appendFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import { effectiveCommands, realAbsolute, type EffectiveCommand, type Unresolved } from './shell';

/** Where a rule's path matcher reads its subject from, per tool. */
const PATH_FIELDS = ['file_path', 'notebook_path', 'path'] as const;

/**
 * The entire matcher vocabulary. Adding a key here is a spec change, not an
 * implementation detail: every present key must match (AND), rules are evaluated
 * in file order, and first match wins. If you need OR, write two rules.
 */
const MATCHERS = [
  'tool',
  'path_glob',
  'path_not_glob',
  'command_matches',
  'command_not_matches',
] as const;

/**
 * Write indicators for the Bash half of policy self-protection: a redirection, a
 * `tee`, an in-place `sed`, or one of the verbs that only ever mutates. Reads
 * (`cat`, `grep`, `sed -n`) are absent on purpose — an agent should be able to
 * read the rule it just tripped.
 *
 * Kept as a FALLBACK beside the parsed write targets rather than replaced by them.
 * It fires on shapes the parser resolves to nothing (a path built at run time, a
 * verb not in its table). Two over-inclusive tests OR'd together can only deny
 * more than either alone, which for the one invariant that makes every other rule
 * meaningful is the right direction.
 */
const POLICY_WRITE_SHAPE =
  /(>>?\s*\S*policy)|(\btee\b)|(\bsed\b[^|;&]*\s-[a-zA-Z]*i)|(\b(rm|mv|cp|mkdir|touch|chmod|chown|truncate|shred|unlink|ln|install|rsync|dd)\b)/;

/** How long between `policy-stats` rollups. Flushed lazily, so no timer. */
const STATS_INTERVAL_MS = 60 * 60 * 1000;

/** At most this many blind spots per row. A pathological command cannot flood a file. */
const MAX_UNRESOLVED_PER_ROW = 20;

export type PolicyDecision = 'allow' | 'deny' | 'ask';
export type PolicyMode = 'dry_run' | 'live';

export interface PolicyRule {
  id: string;
  description?: string;
  decision: Exclude<PolicyDecision, 'allow'>;
  mode?: PolicyMode;
  on_error?: 'allow' | 'deny';
  reason: string;
  match: {
    tool?: string | string[];
    path_glob?: string;
    path_not_glob?: string;
    command_matches?: string;
    command_not_matches?: string;
  };
}

export interface PolicyFile {
  version?: number;
  defaults?: { mode?: PolicyMode; on_error?: 'allow' | 'deny' };
  rules?: PolicyRule[];
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
        else { out += '.*'; i += 1; }
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
  private loadError: string | null = null;
  /** True once a policy FILE has been found on disk. Self-protection is armed by
   *  this, not by rule count: an install with no policy file must behave
   *  byte-identically (nothing evaluated, nothing logged, nothing denied), while
   *  a policy file present but empty of rules must still protect itself. */
  private configured = false;
  private defaults: { mode: PolicyMode; on_error: 'allow' | 'deny' } = { mode: 'dry_run', on_error: 'allow' };

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
    private unenforceableProviders: () => string[] = () => []
  ) {
    this.policyDir = hiveRoot ? join(hiveRoot, 'policy') : '';
    this.policyPath = this.policyDir ? join(this.policyDir, 'authority.json') : '';
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
    if (!this.policyPath || !existsSync(this.policyPath)) return; // unconfigured → inert
    this.configured = true;

    let parsed: PolicyFile;
    try {
      parsed = JSON.parse(readFileSync(this.policyPath, 'utf8')) as PolicyFile;
    } catch (e) {
      // Refuse a half-parsed policy. Partial enforcement is worse than none,
      // because it is believed.
      this.loadError = e instanceof Error ? e.message : String(e);
      this.log({ kind: 'policy-load-failed', path: this.policyPath, error: this.loadError });
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
      this.loadError = invalid.map((i) => `${i.id}: ${i.why}`).join('; ');
      this.log({ kind: 'policy-load-failed', path: this.policyPath, error: this.loadError, invalid });
      return; // all-or-nothing: a policy you cannot fully trust is not loaded
    }

    if (parsed.defaults?.mode) this.defaults.mode = parsed.defaults.mode;
    if (parsed.defaults?.on_error) this.defaults.on_error = parsed.defaults.on_error;
    this.rules = rules;

    const gaps = this.unenforceableProviders();
    this.log({
      kind: 'policy-loaded',
      path: this.policyPath,
      rules: rules.map((r) => ({ id: r.id, decision: r.decision, mode: r.mode ?? this.defaults.mode })),
      // Named, not a static warning. A generic "some providers may not be
      // governed" gets skimmed; a list of the agents running right now does not.
      unenforceable_providers: gaps,
    });
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
    for (const k of ['command_matches', 'command_not_matches'] as const) {
      const r = rule.match[k];
      if (r) { try { new RegExp(r); } catch (e) { return `${k} is not a valid regex: ${String(e)}`; } }
    }
    if (rule.mode && rule.mode !== 'dry_run' && rule.mode !== 'live') return `mode must be dry_run or live, got ${String(rule.mode)}`;
    if (rule.on_error && rule.on_error !== 'allow' && rule.on_error !== 'deny') return `on_error must be allow or deny, got ${String(rule.on_error)}`;
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
      const abs = normalisePath(path);
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
      // Parsed first: this catches `node -e "writeFileSync('<policy>')"` and a
      // write through a symlink, neither of which the string test sees.
      for (const c of this.commands(p, ctx)) if (c.writes.some(under)) return true;
      if (!cmd.includes(this.policyDir)) return false;
      return POLICY_WRITE_SHAPE.test(cmd);
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
    if (p.tool_name === 'Bash') for (const c of this.commands(p, ctx)) out.push(...c.writes);
    return out;
  }

  /** shell.ts output for this payload, parsed once per evaluation and reused by
   *  every rule — parsing is the only non-trivial cost in front of a tool call. */
  private commands(p: PolicyPayload, ctx: EvalContext): EffectiveCommand[] {
    if (ctx.commands) return ctx.commands;
    const input = (p.tool_input ?? {}) as Record<string, unknown>;
    const cmd = typeof input.command === 'string' ? input.command : '';
    ctx.commands = cmd ? effectiveCommands(cmd) : [];
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
      this.record(p, verdict);
      return verdict;
    }

    for (const rule of this.rules) {
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
          this.record(p, verdict);
          return verdict;
        }
        continue; // fail open: this rule abstains, later rules still run
      }
      if (!hit) continue;

      const mode = rule.mode ?? this.defaults.mode;
      if (mode === 'dry_run') {
        // Evaluate fully, log, and ALLOW. You cannot measure a false positive
        // after enforcing, because the deny already stopped the work you would
        // have judged.
        const verdict: PolicyVerdict = {
          decision: 'allow', ruleId: rule.id, reason: rule.reason,
          mode, matchedOn: hit, wouldDeny: true,
        };
        this.record(p, verdict);
        return verdict;
      }
      const verdict: PolicyVerdict = {
        decision: rule.decision, ruleId: rule.id, reason: rule.reason, mode, matchedOn: hit,
      };
      this.record(p, verdict);
      return verdict;
    }
    return { decision: 'allow' };
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
      const paths = this.paths(p, ctx).map((x) => normalisePath(x));
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
        if (!eligible.some((x) => re.test(x))) return null;
        matchedOn = 'path_glob';
      }
    }

    return matchedOn;
  }

  /**
   * One ledger row per deny or ask (including a dry-run would-deny). Never for an
   * allow, and never the raw tool_input — tool inputs carry file contents and
   * secrets, so the row keeps a digest plus which matcher fired.
   */
  private record(p: PolicyPayload, v: PolicyVerdict): void {
    if (v.decision === 'deny') this.stats.denied++;
    else if (v.decision === 'ask') this.stats.asked++;
    this.log({
      kind: 'policy-decision',
      agent_id: p.agent_id ?? null,
      rule_id: v.ruleId,
      tool: p.tool_name,
      decision: v.decision,
      mode: v.mode,
      would_deny: v.wouldDeny ?? false,
      matched_on: v.matchedOn,
      input_digest: digest(p.tool_input),
    });
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
  get ruleCount(): number { return this.rules.length; }
  get error(): string | null { return this.loadError; }
  get path(): string { return this.policyPath; }
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
