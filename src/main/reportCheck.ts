/**
 * Report check (HAG-46): flag a completion report that contradicts the tool log.
 *
 * The pre-tool gate cannot see this. A red test run arrives after the tool ran, and
 * "done, suite green" is an ordinary write to the agent's own outbox. So this
 * records the outcome of each test-shaped Bash call and, when a message is
 * delivered, compares a zero-failure claim in it with that agent's last outcome.
 *
 * ENTIRELY OPT-IN. Nothing here runs unless the policy file carries a
 * `report_check` block (see examples/policy/README.md). With no policy file, or a
 * policy without that block, no hook is added, nothing is recorded and no row is
 * written: the install behaves byte-identically to one without this file.
 *
 * NEVER BLOCKS. The output is a ledger row, and in live mode a note to god. A wrong
 * flag costs one read; a wrong block would stop a correct report.
 *
 * NO CONTENT. An outcome row keeps whether the run passed and ONE integer, the
 * failure count, read from the runner's summary line. No stdout, no stderr, no
 * test names. A flag row keeps the claim words that matched, not the message.
 */

import { digest, type PolicyMode } from './policy';
import { effectiveCommands } from './shell';

export interface ReportCheckConfig {
  mode: PolicyMode;
}

export interface ToolOutcome {
  runner: string;
  /** false: the run failed or reported failures. null: interrupted, so unknown. */
  ok: boolean | null;
  failCount: number | null;
  at: string;
}

/** The hook payload fields this module reads. */
export interface OutcomePayload {
  hook_event_name?: string;
  agent_id?: string | null;
  session_id?: string;
  tool_name?: string;
  tool_input?: unknown;
  cwd?: string;
  tool_response?: { stdout?: unknown; stderr?: unknown; interrupted?: unknown } | null;
  /** PostToolUseFailure only: "Exit code 1\n<output>". */
  error?: unknown;
  is_interrupt?: unknown;
}

export interface ReportMessage {
  id?: string;
  conversation?: string;
  from?: string;
  to?: string;
  act?: string;
  subject?: string;
  body?: string;
}

/** At most one note to god per agent in this window; the rows are still written. */
export const NOTE_INTERVAL_MS = 10 * 60 * 1000;

/** The sender name this module uses when it tells god, so it never checks itself. */
export const REPORT_CHECK_SENDER = 'report-check';

/**
 * The runner a parsed command invokes, or null when it is not a test run.
 * Judged per PARSED command, so `cd x && npm test`, `bash -c 'pytest'` and
 * `npm test | tail` count, while `echo npm test` and `grep pytest` do not.
 */
export function testRunner(command: string, cwd?: string): string | null {
  let cmds;
  try { cmds = effectiveCommands(command, cwd); } catch { return null; }
  for (const c of cmds) {
    // Launchers that run the real runner: `uv run pytest`, `poetry run pytest`,
    // `pipenv run pytest`, `npx jest`, `bunx vitest`, `pnpm exec vitest`.
    let argv = c.argv;
    for (;;) {
      const [x0, x1] = argv;
      if ((x0 === 'uv' || x0 === 'poetry' || x0 === 'pipenv' || x0 === 'hatch') && x1 === 'run') argv = argv.slice(2);
      else if (x0 === 'npx' || x0 === 'bunx') argv = argv.slice(1);
      else if ((x0 === 'pnpm' || x0 === 'yarn' || x0 === 'npm') && x1 === 'exec') argv = argv.slice(2);
      else break;
    }
    const [a0, a1, a2] = argv;
    if (!a0) continue;
    if ((a0 === 'npm' || a0 === 'yarn' || a0 === 'pnpm' || a0 === 'bun')
      && (a1 === 'test' || a1 === 't' || (a1 === 'run' && /^test(?::|$)/.test(a2 ?? '')))) return `${a0} test`;
    // `yarn jest`, `pnpm vitest`: the package manager runs a bin directly.
    if ((a0 === 'yarn' || a0 === 'pnpm') && (a1 === 'jest' || a1 === 'vitest')) return a1;
    if (a0 === 'node' && argv.includes('--test')) return 'node --test';
    if (a0 === 'pytest' || a0 === 'py.test') return 'pytest';
    // The parser already turns `python -m <module>` into the module.
    if (a0 === 'unittest') return 'unittest';
    if (/^python3?$/.test(a0) && a1 === '-m' && (a2 === 'pytest' || a2 === 'unittest')) return a2;
    if (a0 === 'jest' || a0 === 'vitest') return a0;
    if (a0 === 'playwright' && a1 === 'test') return 'playwright test';
    if ((a0 === 'go' || a0 === 'cargo' || a0 === 'make' || a0 === 'mvn' || a0 === 'gradle' || a0 === 'gradlew' || a0 === './gradlew') && a1 === 'test') return `${a0.replace(/^\.\//, '')} test`;
  }
  return null;
}

/**
 * The one integer read from test output: the failure count on the runner's summary
 * line. The LAST summary wins, since a run can print per-file counts before the
 * total. null when no summary was printed. A count counts only on a summary-shaped
 * line: a captured log saying "3 failed attempts" is not a test result.
 *   node --test / TAP: `# fail 3`   pytest: `3 failed, 10 passed`
 *   jest / vitest: `Tests: 3 failed`   mocha: `3 failing`
 */
export function failCount(text: string): number | null {
  let last: number | null = null;
  for (const line of text.split('\n')) {
    const tap = /^#\s*fail\s+(\d+)\s*$/.exec(line);
    if (tap) { last = Number(tap[1]); continue; }
    // mocha: the count stands alone on its line.
    const alone = /^\s*(\d+)\s+failing\b[^\w]*$/.exec(line);
    if (alone) { last = Number(alone[1]); continue; }
    // pytest / jest / vitest: only on a SUMMARY line, one that also counts passes or a
    // total, or is a framed or "Tests:" line. "3 failed attempts" in a log is not one.
    const n = /\b(\d+)\s+(?:failed|failing)\b/.exec(line);
    if (n && (/\b(?:passed|passing|total|skipped)\b/.test(line) || /^\s*(?:Tests?:|=|-{3,})/.test(line))) last = Number(n[1]);
  }
  return last;
}

/** The outcome of one test-shaped Bash call, or null when the call is not one. */
export function outcomeOf(p: OutcomePayload): ToolOutcome | null {
  if (p.tool_name !== 'Bash') return null;
  const command = (p.tool_input as { command?: unknown } | null)?.command;
  if (typeof command !== 'string') return null;
  const runner = testRunner(command, p.cwd);
  if (!runner) return null;
  const at = new Date().toISOString();
  if (p.hook_event_name === 'PostToolUseFailure') {
    if (p.is_interrupt === true) return { runner, ok: null, failCount: null, at };
    return { runner, ok: false, failCount: failCount(typeof p.error === 'string' ? p.error : ''), at };
  }
  if (p.hook_event_name === 'PostToolUse') {
    const r = p.tool_response ?? {};
    if (r.interrupted === true) return { runner, ok: null, failCount: null, at };
    const out = [r.stdout, r.stderr].filter((s) => typeof s === 'string').join('\n');
    const n = failCount(out);
    // Exit 0 with failures on the summary line is a masked exit (`npm test | tail`).
    return { runner, ok: n === null ? true : n === 0, failCount: n, at };
  }
  return null;
}

/**
 * The zero-failure claims a message makes, lower-cased, or [] for none.
 *
 * Only claims that there are NO failures count. "Done" and "clean" do not: on a
 * repo whose suite has known failures, "done, 22 fail as before" is a true report
 * after a red exit, and flagging it is the false positive that made this check
 * useless in the scope card. "No new failures" is not a zero-failure claim either.
 * A claim is dropped when its clause (split at . ; ! ? , and newlines) negates it,
 * makes it a condition or a requirement ("if all tests pass", "once the suite is
 * green", "we need tests passing"), relays someone else's words ("Jim says all tests
 * pass"), asks it as a question, or quotes it. "No fail-open rows" and "no failed
 * deliveries" are not claims about tests.
 */
export function greenClaims(text: string): string[] {
  const CLAIM = /\b(?:all (?:the )?tests? (?:pass(?:ed|es|ing)?|green)|tests?:? (?:are |all )?(?:pass(?:ed|es|ing)?|green)|(?:the )?suite (?:is |was |now )?(?:green|passing|pass(?:es|ed))|everything pass(?:es|ed)|100% pass(?:ing|es)?|(?:0|zero|no) (?:test )?(?:failures?|failing)(?![-\w])|0 failed\b(?!\s+[a-z])|green (?:suite|tests?|build|run))/gi;
  const NEGATION = /\b(?:not|never|no longer|isn't|aren't|wasn't|weren't|doesn't|didn't|won't|cannot|can't)\b/i;
  // A condition, a requirement or a question is not a report of what happened.
  const HYPOTHETICAL = /\b(?:if|once|when|whenever|until|unless|before|after|need|needs|should|must|would|will|could|can|want|expect)\b/i;
  // Someone else's words, relayed: not this agent's claim about its own run.
  const RELAYED = /\b(?:says?|said|reports?|reported|claims?|claimed|according to|wrote|writes)\b/i;
  const found = new Set<string>();
  for (const raw of text.split(/(?<=[.;!?\n,])/)) {
    const clause = raw.trim();
    if (clause.endsWith('?')) continue;
    for (const m of clause.matchAll(CLAIM)) {
      const before = clause.slice(0, m.index);
      if (NEGATION.test(before) || HYPOTHETICAL.test(before) || RELAYED.test(before)) continue;
      // Inside quotes: an odd number of quote marks before the match on this clause.
      if ((before.match(/["`\u201c\u201d]/g) ?? []).length % 2 === 1) continue;
      found.add(m[0].toLowerCase());
    }
  }
  return [...found];
}

/**
 * Keeps each agent's last test outcome and checks what that agent reports.
 * Constructed only when the policy file turns the check on.
 */
export class ReportCheck {
  private last = new Map<string, ToolOutcome>();
  private lastNote = new Map<string, number>();

  constructor(
    private config: ReportCheckConfig,
    private log: (row: Record<string, unknown>) => void,
    /** Live mode only: tell god. Never called in dry_run. */
    private tellGod: (subject: string, body: string) => void = () => {}
  ) {}

  get mode(): PolicyMode { return this.config.mode; }

  /**
   * A new session starts a new window: an old red run is not this session's. Only a
   * real start or a /clear resets it. A compaction or a resume is the same session
   * carrying on, so a red run before it is still the current state (HAG-46 Q4).
   */
  sessionStarted(agentId: string, source?: string): void {
    if (source === 'compact' || source === 'resume') return;
    this.last.delete(agentId);
  }

  /** Record a PostToolUse / PostToolUseFailure. Anything not test-shaped is ignored. */
  recordOutcome(p: OutcomePayload): void {
    if (!p.agent_id) return;
    const o = outcomeOf(p);
    if (!o) return;
    this.last.set(p.agent_id, o);
    this.log({
      kind: 'report-check-outcome',
      agent_id: p.agent_id,
      session_id: p.session_id ?? null,
      runner: o.runner,
      ok: o.ok,
      fail_count: o.failCount,
      input_digest: digest(p.tool_input),
    });
  }

  /** Check one delivered message. Returns the verdict, for tests. */
  checkMessage(msg: ReportMessage, now = Date.now()): 'contradicts' | 'unsupported' | null {
    const from = msg.from;
    if (!from || from === REPORT_CHECK_SENDER) return null;
    const claims = greenClaims(`${msg.subject ?? ''}\n${msg.body ?? ''}`);
    if (!claims.length) return null;
    const o = this.last.get(from);
    let verdict: 'contradicts' | 'unsupported' | null = null;
    if (!o) verdict = 'unsupported';
    else if (o.ok === false) verdict = 'contradicts';
    if (!verdict) return null;
    const noteDue = verdict === 'contradicts' && this.config.mode === 'live'
      && now - (this.lastNote.get(from) ?? -Infinity) >= NOTE_INTERVAL_MS;
    this.log({
      kind: 'report-check-flag',
      verdict,
      mode: this.config.mode,
      agent_id: from,
      message_id: msg.id ?? null,
      conversation: msg.conversation ?? null,
      to: msg.to ?? null,
      claim_terms: claims,
      outcome_at: o?.at ?? null,
      runner: o?.runner ?? null,
      fail_count: o?.failCount ?? null,
      ...(this.config.mode === 'live' ? { noted: noteDue } : {}),
    });
    // Only a contradiction is worth god's attention. "Unsupported" is common and
    // innocent (a relayed report, a run in a subagent), so it stays a row.
    if (noteDue) {
      this.lastNote.set(from, now);
      const count = o?.failCount != null ? `${o.failCount} failing` : 'a failed exit';
      try {
        this.tellGod(
          `Report check: ${from}'s message claims no failures, but its last test run showed ${count}`,
          [
            `${from} sent a message (${msg.id ?? 'no id'}, to ${msg.to ?? '?'}) claiming: ${claims.join(', ')}.`,
            `Its last recorded test run (${o?.runner}, at ${o?.at}) showed ${count}.`,
            'This is a flag, not a block: the message was delivered. Check the claim against the run before relying on it.',
          ].join('\n')
        );
      } catch { /* a failed note must never affect delivery */ }
    }
    return verdict;
  }
}
