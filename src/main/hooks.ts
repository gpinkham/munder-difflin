/**
 * HookServer — the bridge between `claude` lifecycle hooks and the harness.
 *
 * Each spawned agent is launched with `--settings` pointing its hooks at a tiny
 * shim (see HOOK_SHIM in hive.ts) that forwards the hook payload to the Unix
 * domain socket this server listens on. We then:
 *   - drive avatar state from PreToolUse/PostToolUse/Notification/etc., and
 *   - report lifecycle boundaries while renderer-side guarded queues deliver
 *     inbox work only after the session reaches a safe idle prompt.
 *
 * Runs in the Electron main process.
 */
import { createServer, createConnection, type Server, type Socket } from 'node:net';
import { existsSync, rmSync, statSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { isAbsolute, join, normalize } from 'node:path';
import { Notification, type WebContents } from 'electron';
import type { HiveManager, HiveTask, HumanQA } from './hive';
import type { HarnessConfig } from './config';
import type { ControlRegistry } from './control';
import type { CircuitBreaker } from './breaker';
import { estimateCostUsd } from './pricing';
import { validateHookEvent } from '../shared/hookEvents';
import { PolicyEngine, type AgentWorkspace, type PolicyPayload, type PolicyRule, type PolicyStatus } from './policy';
import { ReportCheck, REPORT_CHECK_SENDER, type ReportMessage } from './reportCheck';
import type { HookAuth } from './hookAuth';
import { GrantDesk, GrantStore, runnablePush, type GrantRequest } from './grants';
import { WORKER_WAKE_ANSWERED_EVENTS } from './workerWake';

/** The sender name on the approval desk's messages. */
export const GRANT_DESK_SENDER = 'grant-desk';

/** A policy ask counts as the cause of a permission prompt for this long. */
const POLICY_PROMPT_WINDOW_MS = 60_000;
/** How long after an approved push is allowed its request to leave the sandbox is
 *  answered. Claude Code asks within a second; anything later is not that run's. */
const APPROVED_RUN_WINDOW_MS = 60_000;
/** Events that mean the agent is past the prompt, whichever way it was answered. */
const ANSWERED_EVENTS = WORKER_WAKE_ANSWERED_EVENTS;
function isPermissionPrompt(p: { notification_type?: string; message?: string }): boolean {
  return p.notification_type === 'permission_prompt' || /needs your permission/i.test(p.message ?? '');
}

/** Maximum JSON payload bytes in one newline-delimited hook frame. */
const MAX_HOOK_FRAME_BYTES = 256 * 1024;

export interface HookPayload {
  /** Ownership probe from ensureListening(): answered with { pong, instance }, never a hook. */
  ping?: string;
  hook_event_name?: string;
  agent_id?: string | null;
  /** The CLI's own subagent id, when the hook fired inside a subagent (agent_id is the hive agent). */
  subagent_id?: string;
  session_id?: string;
  transcript_path?: string;
  /** Status-line payloads only: the session's live context accounting. */
  context_window?: { total_input_tokens?: number; context_window_size?: number };
  cwd?: string;
  tool_name?: string;
  tool_input?: unknown;
  stop_hook_active?: boolean;
  prompt?: string;
  source?: string;
  notification_type?: string;
  /** Notification hook text, e.g. "Claude is waiting for your input" (idle) vs a
   *  permission request. Used to tell "needs you" from "just done / lingering". */
  message?: string;
  /** CostSample payloads only (synthesized by the proxy-bridge sidecar for
   *  qwen). Raw token counts for one response, fed to the cost ledger. */
  model?: string;
  input?: number;
  output?: number;
  cache_read?: number;
  cache_creation?: number;
  /** PostToolUse: what the tool returned (Bash: stdout/stderr/interrupted). */
  tool_response?: { stdout?: unknown; stderr?: unknown; interrupted?: unknown } | null;
  /** PostToolUseFailure: "Exit code N\n<output>", and whether the user interrupted. */
  error?: unknown;
  is_interrupt?: unknown;
}

/**
 * md-223: the directories under harnessHome whose per-agent children count as that
 * agent's workspace, when `workspaceRoots` is not set. `worktrees` is where the
 * harness puts an isolated agent (it was the one hardcoded root before this);
 * `code-worktrees` is where the day-job floor keeps most checkouts (md-220).
 */
export const DEFAULT_WORKSPACE_ROOTS: readonly string[] = ['worktrees', 'code-worktrees'];

/**
 * Clean `workspaceRoots` from a hand-edited config file. Pure, so it runs wherever
 * the roots are joined AND once at startup to report what it dropped.
 *
 * Every root is joined as `<harnessHome>/<root>/<agent-id>`, so a root is only safe if
 * it stays inside harnessHome and is not harnessHome itself: relative, non-empty, no
 * `..` segment (checked on the raw text, because normalize would quietly fold
 * `a/../b` into `b` and hide it), and not `.`. A bad entry is dropped and named, never
 * an error — the guardrail's bias is that an attribution failure costs protection,
 * not work, so the worst a typo can do here is own less.
 *
 * Unset means the default. Anything that is not a list is a hand-edit mistake, and
 * falling back to the default keeps `worktrees` protected, as it was before md-223,
 * instead of silently protecting nothing. An explicit `[]` is honoured as an opt-out.
 */
export function sanitizeWorkspaceRoots(raw: unknown): {
  roots: string[];
  rejected: Array<{ root: unknown; why: string }>;
} {
  if (raw === undefined || raw === null) return { roots: [...DEFAULT_WORKSPACE_ROOTS], rejected: [] };
  if (!Array.isArray(raw)) {
    return { roots: [...DEFAULT_WORKSPACE_ROOTS], rejected: [{ root: raw, why: 'not a list; using the default' }] };
  }
  const roots: string[] = [];
  const rejected: Array<{ root: unknown; why: string }> = [];
  for (const r of raw) {
    if (typeof r !== 'string') { rejected.push({ root: r, why: 'not a string' }); continue; }
    const t = r.trim();
    if (!t) { rejected.push({ root: r, why: 'empty' }); continue; }
    // N2: '~' is not expanded here, so '~/x' would own a literal directory named "~"
    // and silently protect nothing — the trap this repo already paid for in #140.
    if (t.startsWith('~')) { rejected.push({ root: r, why: "'~' is not expanded; give a path relative to harnessHome" }); continue; }
    if (isAbsolute(t) || /^[a-zA-Z]:/.test(t) || t.startsWith('\\')) {
      rejected.push({ root: r, why: 'absolute; roots are relative to harnessHome' });
      continue;
    }
    if (t.split(/[\\/]+/).includes('..')) { rejected.push({ root: r, why: "contains '..'" }); continue; }
    const n = normalize(t).replace(/[\\/]+$/, '');
    if (!n || n === '.') { rejected.push({ root: r, why: 'resolves to harnessHome itself' }); continue; }
    if (!roots.includes(n)) roots.push(n);
  }
  return { roots, rejected };
}

/** Live health of the hook socket — the ONE endpoint every lifecycle hook,
 *  proxy-bridge emit and cost sample travels through. When nothing accepts on
 *  it the shims' connect() fails and they exit 0 with empty stdout, which the
 *  CLI reads as "allow": the breaker is inert, fleet.json never appears, no cost
 *  is recorded — and until #277 nothing said so. The beat writes this into
 *  fleet.json so an operator (or god) can see it without a debugger. */
export interface HookSocketHealth {
  /** HIVE_SOCK — where the shims connect. null while the hive has no root. */
  path: string | null;
  /** True only while our server is listening AND (POSIX) the path still
   *  resolves to the socket we bound — a socket FILE can exist while nothing
   *  accepts on it, so existence proves nothing. */
  listening: boolean;
  /** Epoch ms of the current bind; null when not listening. */
  since: number | null;
  /** The last bind/verify failure — 'EADDRINUSE', 'ENOENT', 'REPLACED',
   *  'NOROOT', … — or null when healthy. */
  lastError: string | null;
  /** Bind attempts since the last successful listen (0 when healthy). */
  attempts: number;
  /** Listeners this process had to abandon because a stranger took the path
   *  (see detach()) — a non-zero count is worth a look. */
  orphans: number;
}

/** Back-off between automatic re-bind attempts after a failure. Once spent, the
 *  beat still calls ensureListening() on its own cadence, so the server never
 *  stops trying — it just stops toasting. */
const BIND_RETRY_MS = [500, 1_000, 2_000, 4_000, 8_000];

/** Identity of the socket FILE we bound — enough to tell, synchronously, whether
 *  the path still leads to it (APFS/NTFS never reuse inode numbers). */
interface FileMark { dev: number; ino: number }
const markOf = (p: string): FileMark | null => {
  try { const st = statSync(p); return { dev: st.dev, ino: st.ino }; } catch { return null; }
};
const sameMark = (a: FileMark | null, b: FileMark | null): boolean =>
  !!a && !!b && a.dev === b.dev && a.ino === b.ino;

/** Who answers at the path: nobody (missing, or a stale file from a crashed
 *  run), a stranger (another live instance — never touched), or us. */
type PathOwner = 'nobody' | 'other' | 'self';

export class HookServer {
  private server: Server | null = null;
  /** This process's identity, echoed back by the ownership ping so a probe can
   *  tell "our listener" from "some other live instance" at the same path. */
  private readonly instanceId = randomUUID();
  /** The socket FILE we bound (POSIX), so stop() and the beat can tell our
   *  socket from one another instance created at the same path (#277). */
  private mark: FileMark | null = null;
  private bound: { path: string; since: number } | null = null;
  /** Listeners abandoned because a stranger owns the path now. Closing one would
   *  make libuv unlink(2) the PATH — by name, not by inode — and take the
   *  stranger's live socket with it. Kept unref()ed until the process exits. */
  private orphans: Server[] = [];
  private lastError: string | null = null;
  private bindAttempts = 0;
  private binding = false;
  private retryTimer: NodeJS.Timeout | null = null;
  /** One toast per outage, not one per retry. */
  private alerted = false;
  /** Set by stop(): the beat must not re-bind while the hive is being moved or
   *  the app is quitting — only start() re-arms. */
  private stopped = false;
  /** agentId → the live session's transcript file, learned from hook payloads.
   *  Lets the harness read per-agent telemetry (e.g. current context size)
   *  even when several agents share one cwd. */
  private transcriptPaths = new Map<string, string>();
  /** agentId → the latest context-window accounting from the statusLine shim
   *  (current tokens + the REAL window size — 200k vs 1M, which nothing else
   *  exposes). The renderer already gets this pushed live on `hive:contextUpdate`;
   *  we also retain the last value here so a main-side read (the voice read-layer's
   *  get_agent_detail / list_agents) can report "how full is each agent's context"
   *  without depending on a renderer round-trip. */
  private contextById = new Map<string, { tokens: number; limit: number; ts: number }>();
  /** The goal last delivered to each agent's current session. Goals are durable
   *  roster state, so repeating an unchanged multi-kilobyte briefing on every
   *  prompt only bloats the transcript. One entry per agent is sufficient: an
   *  agent has one live session, and a new session id replaces the old entry. */
  private deliveredGoalByAgent = new Map<string, { sessionId: string | null; goal: string | null }>();
  /** Agents compacted since their rules were last put back in context (md-197).
   *  Set on PreCompact, drained by the next hook that can carry context. Lost on
   *  an app restart, and that is covered without saving it: a restarted agent
   *  resumes its (possibly compacted) session, and SessionStart source=resume
   *  arms the re-delivery again. Nothing reaches the agent from memory.md unless
   *  it chooses to read the file, so memory.md is not the backstop. */
  private rulesDueAfterCompact = new Set<string>();

  /** Opt-in authority policy (policy.ts). Built on first use so a harness with no
   *  policy file pays nothing, and so tests that construct a HookServer without a
   *  hive root behave exactly as before. */
  private policy: PolicyEngine | null = null;
  /** The report check (HAG-46), built only when the policy file turns it on.
   *  `undefined` = not decided yet; `null` = off for this daemon's life. */
  private reportChecker: ReportCheck | null | undefined = undefined;
  /** The last policy `ask` per agent, so the permission prompt it raises can be told
   *  apart from one Claude raises on its own. Only a loaded policy ever sets it. */
  private policyAsks = new Map<string, { ruleId: string; at: number; cardId?: string }>();
  /** The approved push each agent was last allowed to run outside the sandbox. */
  private approvedRuns = new Map<string, { command: string; cwd: string | null; at: number }>();
  /** The approval desk (HAG-49), built only when a loaded rule is grantable. */
  private desk: GrantDesk | null | undefined = undefined;

  constructor(
    private hive: HiveManager,
    private getWebContents: () => WebContents | null,
    private getConfig: () => HarnessConfig,
    /** #7C — operator control state. Optional so tests can omit it. */
    private control?: ControlRegistry,
    /** Circuit breaker (Lane A #6.6b) — fed the hook-derived signals (session id,
     *  repeated identical tool calls). Optional so the server still runs without it. */
    private breaker?: CircuitBreaker,
    /** Standing goal text for an agent (from the durable roster). Optional so
     *  tests can omit it; when set, injected at session start and when changed. */
    private getStandingGoal?: (agentId: string) => string | null,
    /** Optional observer of every hook boundary (agentId, event, message, payload).
     *  The inbox-wake watchdog (workerWake.ts) and the prompt gate (promptGate.ts)
     *  feed on this to learn when an agent is parked at a menu, so nothing types
     *  into it. */
    private onEvent?: (agentId: string | undefined, event: string, message: string | undefined, payload: HookPayload) => void,
    /** md-146 rules notice. Returns a one-off diff for an agent that has not yet
     *  been told about the current rule revision, or null. Keyed on REVISION and
     *  persisted to disk, so unlike the standing goal it neither decays after a
     *  compact nor re-spams after a restart. Optional: no rules store, no notice. */
    private takeRulesNotice?: (agentId: string) => string | null,
    /** md-197 — the agent's FULL current rule set, re-injected once after each
     *  compaction so the rules do not depend on the agent choosing to re-read
     *  memory.md. Optional: no rules store, nothing to re-deliver. */
    private getRulesFullSet?: (agentId: string) => string | null
  ) {}

  /** Bind the hook socket. Asynchronous and safe to call repeatedly — a
   *  listening server is left alone. Before #277 this returned SILENTLY when the
   *  hive had no root yet, and left the outcome of listen() to a console.error
   *  nobody reads: either way the whole control plane could be dead for a
   *  session with nothing logged. Now every outcome is logged (console and the
   *  hive's log.jsonl), failures are retried, and the beat keeps verifying. */
  start(): void {
    this.stopped = false;
    // The policy's load status does not need the socket: say it now, so a bind that
    // never succeeds (no root yet, a stranger on the path) cannot hide it.
    this.announceOnce();
    void this.ensureListening();
  }

  /** The hook socket's live state — the beat writes it into fleet.json. */
  health(): HookSocketHealth {
    const listening = !!this.server?.listening && this.bound !== null;
    return {
      path: this.hive.sockPath(),
      listening,
      since: listening && this.bound ? this.bound.since : null,
      lastError: this.lastError,
      attempts: this.bindAttempts,
      orphans: this.orphans.length
    };
  }

  /** Make sure something is listening at HIVE_SOCK, and that it is US. Called
   *  by start() and then from the beat. Three outcomes:
   *    - not bound (never, or the last bind failed) → bind, with back-off;
   *    - bound, but the path no longer leads to our socket → we are "listening"
   *      on an orphaned inode while every shim's connect() fails: log it as lost
   *      and re-bind — unless a LIVE server owns the path now, which is never
   *      stolen;
   *    - bound and verified → nothing to do. */
  async ensureListening(): Promise<HookSocketHealth> {
    if (this.stopped || this.binding) return this.health();
    const sock = this.hive.sockPath();
    if (!sock) {
      if (this.lastError !== 'NOROOT') {
        this.lastError = 'NOROOT';
        console.warn('[hive] hook socket not bound: the hive has no root yet (the beat will retry)');
      }
      return this.health();
    }
    if (this.server?.listening && this.bound) {
      // Cheap check first (POSIX): the file at the path is still the one we bound.
      if (this.mark && sameMark(this.mark, markOf(sock))) return this.health();
      // Definitive check: does connecting to the path reach US?
      const owner = await this.probe(sock);
      if (owner === 'self') { this.mark = markOf(sock); return this.health(); }
      const code = owner === 'other' ? 'REPLACED' : 'ENOENT';
      this.detach(owner === 'other');
      console.error(`[hive] hook socket LOST (${code}): ${sock} no longer reaches our listener — every hook has been allowed meanwhile`);
      this.hive.appendLog({ kind: 'hooks', state: 'lost', path: sock, code });
      if (owner === 'other') { this.bindAttempts += 1; this.fail(sock, 'EADDRINUSE', 'another process is listening there now'); return this.health(); }
    }
    await this.bind(sock);
    return this.health();
  }

  private policyAnnounced = false;
  /** The policy's load status, once per app run: from start(), or from the first bind
   *  when start() ran before the hive had a root. Never again on a re-bind after a lost
   *  socket: the policy has not changed, and god would only hear the same thing twice. */
  private announceOnce(): void {
    if (this.policyAnnounced || !this.hive.root()) return;
    this.policyAnnounced = true;
    this.announcePolicy();
  }

  private async bind(sock: string): Promise<void> {
    this.binding = true;
    try {
      this.bindAttempts += 1;
      if (process.platform !== 'win32' && existsSync(sock)) {
        // A file left by a crashed run is normal and is cleared. A file a LIVE
        // stranger accepts on is theirs: report it, never steal it.
        if (await this.probe(sock) === 'other') { this.fail(sock, 'EADDRINUSE', 'another process is listening there'); return; }
        try { rmSync(sock); } catch { /* listen() below reports it */ }
      }
      const server = createServer((conn) => this.serve(conn));
      const outcome = new Promise<string | null>((resolve) => {
        server.once('listening', () => resolve(null));
        server.once('error', (e: NodeJS.ErrnoException) => resolve(e.code ?? e.message));
      });
      // listen() binds the path — and creates the socket file — synchronously;
      // only the 'listening' event is deferred. Publish the handle and record
      // which file is ours right here, before anything else can run: a caller
      // that looks straight after start() sees the server, and a file that
      // replaces ours later can never be mistaken for it.
      server.listen(sock);
      this.server = server;
      this.mark = process.platform === 'win32' ? null : markOf(sock);
      this.bound = { path: sock, since: Date.now() };
      const err = await outcome;
      if (this.server !== server) return; // stop() or a re-bind took this handle over meanwhile
      if (err !== null) {
        this.server = null;
        this.mark = null;
        this.bound = null;
        try { server.close(); } catch { /* noop */ }
        this.fail(sock, err, 'listen() failed');
        return;
      }
      server.on('error', (e) => console.error('[hive] hook server error:', e));
      this.lastError = null;
      this.bindAttempts = 0;
      this.alerted = false;
      console.log(`[hive] hook server listening on ${sock}`);
      this.hive.appendLog({ kind: 'hooks', state: 'listening', path: sock });
      // Once per app run, not per re-bind: the policy load status (md-216).
      this.announceOnce();
    } finally {
      this.binding = false;
    }
  }

  /** A bind (or verify) failed: say so where an operator can find it, schedule
   *  a retry, and — once the back-off is spent — toast once per outage. */
  private fail(sock: string, code: string, detail: string): void {
    this.lastError = code;
    console.error(`[hive] hook socket bind FAILED (${code}) at ${sock}: ${detail} — attempt ${this.bindAttempts}. Until this recovers every agent hook is ALLOWED and no cost is recorded.`);
    this.hive.appendLog({ kind: 'hooks', state: 'bind-failed', path: sock, code, attempt: this.bindAttempts });
    const i = Math.max(0, this.bindAttempts - 1);
    if (i < BIND_RETRY_MS.length) {
      if (this.retryTimer) clearTimeout(this.retryTimer);
      this.retryTimer = setTimeout(() => { this.retryTimer = null; void this.ensureListening(); }, BIND_RETRY_MS[i]);
      this.retryTimer.unref();
    } else if (!this.alerted) {
      this.alerted = true;
      this.notify('Hive hooks are down', `Nothing is listening at ${sock} (${code}). Every agent hook is being allowed and no cost is recorded until this recovers.`);
    }
  }

  /** One shim connection: a bounded, newline-delimited JSON frame in (#399),
   *  a JSON reply out. The ownership ping is answered here and never reaches
   *  handle(). */
  private serve(conn: Socket): void {
    let pending = Buffer.alloc(0);
    const rejectOversizedFrame = (bytes: number): void => {
      this.hive.appendLog({
        kind: 'hook-frame-rejected',
        reason: 'frame-too-large',
        bytes,
        limit: MAX_HOOK_FRAME_BYTES,
      });
      conn.destroy();
    };
    conn.on('data', (chunk) => {
      pending = Buffer.concat([pending, chunk]);
      const nl = pending.indexOf(0x0a);
      if (nl === -1) {
        if (pending.length > MAX_HOOK_FRAME_BYTES) rejectOversizedFrame(pending.length);
        return; // wait for the full line
      }
      // The byte limit covers the JSON payload and excludes its newline.
      if (nl > MAX_HOOK_FRAME_BYTES) {
        rejectOversizedFrame(nl);
        return;
      }
      // Hook shims send one newline-delimited request per connection and stop writing.
      // conn.end() below closes the connection after that single frame is handled.
      const frame = pending.subarray(0, nl).toString('utf8');
      let payload: HookPayload = {};
      try { payload = JSON.parse(frame); } catch { /* ignore */ }
      if (typeof payload.ping === 'string') { conn.end(JSON.stringify({ pong: payload.ping, instance: this.instanceId })); return; }
      let res: unknown = {};
      try { res = this.handle(payload); } catch { res = {}; }
      conn.end(JSON.stringify(res ?? {}));
    });
    conn.on('error', () => { /* shim hung up — ignore */ });
  }

  /** Connect to the path and ask who is there. */
  private probe(sock: string, timeoutMs = 750): Promise<PathOwner> {
    return new Promise((resolve) => {
      let settled = false;
      let connected = false;
      let data = '';
      const nonce = randomUUID();
      const finish = (v: PathOwner): void => {
        if (!settled) { settled = true; resolve(v); }
        try { c.destroy(); } catch { /* noop */ }
      };
      const c = createConnection(sock, () => { connected = true; c.write(JSON.stringify({ ping: nonce }) + '\n'); });
      c.setEncoding('utf8');
      c.on('data', (d) => { data += d; });
      c.on('end', () => {
        try {
          const r = JSON.parse(data) as { pong?: string; instance?: string };
          finish(r.pong === nonce && r.instance === this.instanceId ? 'self' : 'other');
        } catch { finish('other'); }
      });
      c.on('error', () => finish(connected ? 'other' : 'nobody'));
      setTimeout(() => finish(connected ? 'other' : 'nobody'), timeoutMs).unref();
    });
  }


  /**
   * Load the policy at START, not on the first tool call, and say what loaded.
   *
   * md-216: the engine rejected every rule on both floors and nothing noticed, because
   * the only evidence was one `policy-load-failed` row in log.jsonl written whenever the
   * first PreToolUse happened to arrive. Now "rules loaded: N" is a startup fact in the
   * log and on stdout, fleet.json carries the same status on every snapshot, and a
   * configured policy that loaded nothing is sent to god as a message, once per start,
   * where somebody reads it.
   */
  private announcePolicy(): void {
    let status: PolicyStatus;
    try { status = this.policyEngine().status; } catch (e) {
      console.error('[policy] load threw:', e);
      return;
    }
    if (!status.configured) return; // unconfigured → inert, and quiet about it
    // md-223: which workspace roots are live, and what a hand edit got dropped. Here
    // rather than at every read, so a bad entry is named once per start, not per call.
    const ws = sanitizeWorkspaceRoots(this.getConfig().workspaceRoots);
    this.hive.appendLog({
      kind: 'policy-status',
      rules_loaded: status.rulesLoaded,
      rule_ids: status.ruleIds,
      file: status.file,
      error: status.error,
      workspace_roots: ws.roots,
      workspace_roots_rejected: ws.rejected,
    } as Parameters<HiveManager['appendLog']>[0]);
    if (ws.rejected.length) {
      console.warn(`[policy] workspaceRoots: dropped ${ws.rejected.map((r) => `${JSON.stringify(r.root)} (${r.why})`).join(', ')}`);
    }
    // Configured with zero rules is a failure whether or not an error string came with
    // it (md-217 N1): "enforcing nothing" is exactly the condition this exists to shout.
    const failed = status.error ?? (status.rulesLoaded === 0 ? 'policy configured but 0 rules loaded' : null);
    console.log(`[policy] rules loaded: ${status.rulesLoaded} (${status.file})${failed ? ` FAILED: ${failed}` : ''}`);
    if (failed) {
      try {
        this.hive.send({
          to: 'god',
          act: 'inform',
          subject: 'Guardrail policy failed to load: 0 rules enforced',
          body: `The in-app guardrail found a policy at ${status.file} but loaded NO rules, so nothing is being checked `
            + `(policy self-protection is still on). Reason: ${failed}\n`
            + 'Fix the file and restart the app; fleet.json "policy" shows the current status.',
          requires_reply: false,
        }, 'guardrail');
      } catch (e) { console.error('[policy] could not notify god:', e); }
    }
  }

  private hookAuth: HookAuth | null = null;
  /** Turn on the hook token check (index.ts does, with the HookAuth the agents' tokens
   *  come from). Without it every payload is taken at its word, as before item 5. */
  setHookAuth(auth: HookAuth | null): void {
    this.hookAuth = auth;
  }

  private unauthLogged = new Map<string, number>();
  /** A payload that names an agent without its token: enforce, but do nothing in the
   *  agent's name (no card, no approval used, no alert, no event, no inbox). */
  private unauthenticated(agentId: string, event: string, p: HookPayload): unknown {
    let decision: string | null = null;
    let out: unknown = {};
    if (event === 'PreToolUse') {
      try {
        const policy = this.policyEngine();
        if (policy.active) {
          // No decision or corpus row under the claimed agent (Dwight L7): the refusal
          // is recorded below, as unauthenticated.
          const v = policy.evaluate({ hook_event_name: event, agent_id: agentId, tool_name: p.tool_name, tool_input: p.tool_input, cwd: p.cwd }, { grants: false, record: false });
          // F2: an ask that approve-on-card would answer cannot be answered for an agent
          // without its token, and an ask is a terminal question. Refuse it and say why.
          const stale = v.decision === 'ask' && policy.isGrantable(v.ruleId);
          decision = stale ? 'deny' : v.decision;
          if (v.decision !== 'allow') {
            out = { hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: decision, permissionDecisionReason: `[policy:${v.ruleId}] ${v.reason ?? 'Denied by policy.'}`
              + (stale ? ' Not run: this agent\'s hook token is not valid (it was not started by the running app), so an approval cannot apply. Ask the operator to restart this agent, then push again.' : '') } };
          }
        }
      } catch { out = {}; }
    }
    // Every refusal is logged; an allow or another event once per agent per 10 minutes.
    const now = Date.now();
    if ((decision && decision !== 'allow') || now - (this.unauthLogged.get(agentId) ?? 0) > 10 * 60_000) {
      this.unauthLogged.set(agentId, now);
      this.hive.appendLog({ kind: 'hook-unauthenticated', agent_id: agentId, event, ...(decision ? { decision } : {}) } as Parameters<HiveManager['appendLog']>[0]);
    }
    return out;
  }

  /** True while this agent has a push on the Approvals card or an approval not yet
   *  spent: it waits on the operator, not idle (finish plan item 7). Bounded: a
   *  request expires after 60 minutes, an approval when its grant can't be used. */
  awaitingApproval(agentId: string, now = Date.now()): boolean {
    try { return !!this.grantDesk()?.openFor(agentId, now); } catch { return false; }
  }

  /** Re-read guardrail.json after the Rules screen saved it: an explicit operator
   *  action, so it takes effect now instead of at the next start. */
  reloadPolicy(): PolicyStatus | null {
    if (!this.hive.root()) return null;
    const e = this.policyEngine();
    e.load();
    // The approvals desk follows the rules: on when some backstop asks with approve on
    // a card. Pending requests survive a reload while it stays on.
    if (!e.grantsActive) {
      try { this.desk?.dropPending('approvals-off'); } catch { /* the desk goes either way */ }
      this.desk = null;
    } else if (!this.desk) this.desk = undefined;
    return e.status;
  }

  /** The engine's own check of the rules a save would load. */
  checkEngineRules(rules: PolicyRule[]): string[] {
    return this.policyEngine().checkRules(rules);
  }

  /** Would this rule fire on this call (the Rules screen's tester). */
  wouldMatch(rule: PolicyRule, p: PolicyPayload): { fires: boolean; on?: string; error?: string } {
    return this.policyEngine().wouldMatch(rule, p);
  }

  /** Current guardrail status, for fleet.json. Null when no hive is configured. */
  policyStatus(): PolicyStatus | null {
    if (!this.hive.root()) return null;
    try { return this.policyEngine().status; } catch { return null; }
  }

  /**
   * Every live agent's workspace roots: its registered cwd, its hive folder and the
   * isolated worktree the harness gives a worker. Archived agents are left out; their
   * worktrees are cleaned up by whoever archived them, and that is not a trespass.
   */
  private agentWorkspaces(): AgentWorkspace[] {
    const root = this.hive.root();
    if (!root) return [];
    const cfg = this.getConfig();
    const home = cfg.harnessHome;
    // md-223: joined per LIVE registry agent, never discovered from disk — so a
    // directory under a root that is named for anyone else (an unknown id, an archived
    // agent's leftovers) is simply never considered, and belongs to nobody.
    const { roots: wsRoots } = sanitizeWorkspaceRoots(cfg.workspaceRoots);
    const reg = this.hive.registry();
    return Object.entries(reg.agents)
      .filter(([, a]) => !a.archived)
      .map(([id, a]) => {
        // md-223 N1: the id is joined as a path segment, so it is the one way this
        // feature could produce a false DENY. A hand-edited registry id like
        // '../code-worktrees/<colleague>/portal' would both own the colleague's
        // checkout (flagging their own writes) and knock their root out of
        // ownedRoots as a container; '../../etc' would own outside harnessHome. So an
        // id that is not one plain segment derives no root at all — failing toward
        // owning LESS, like everything else here. Its registered cwd still counts.
        const plain = /^[A-Za-z0-9._-]+$/.test(id) && id !== '.' && id !== '..';
        const derived = plain ? [join(root, 'agents', id), ...(home ? wsRoots.map((r) => join(home, r, id)) : [])] : [];
        return { agentId: id, roots: [a.cwd, ...derived].filter(Boolean) as string[] };
      });
  }

  /** Where agent ids are folder names: the hive's agents/ and each configured
   *  workspace root under harnessHome. The corpus masks any id found there. */
  private workspaceContainers(): string[] {
    try {
      const root = this.hive.root();
      const home = this.getConfig().harnessHome;
      const { roots } = sanitizeWorkspaceRoots(this.getConfig().workspaceRoots);
      return [...(root ? [join(root, 'agents')] : []), ...(home ? roots.map((r) => join(home, r)) : [])];
    } catch { return []; }
  }

  /** Build the policy engine once, on first PreToolUse. */
  private policyEngine(): PolicyEngine {
    if (!this.policy) {
      this.policy = new PolicyEngine(
        this.hive.root(),
        (row) => this.hive.appendLog(row as Parameters<HiveManager['appendLog']>[0]),
        // Providers whose bridge cannot receive a decision, named at load time
        // rather than left to be discovered: pi and opencode post fire-and-forget,
        // and the qwen proxy synthesizes PostToolUse only (it observes traffic
        // after the fact, so there is no before-the-action boundary to hold).
        () => ['pi', 'opencode', 'qwen'],
        () => { try { return this.agentWorkspaces(); } catch { return []; } },
        // md-136: on unless the config file says otherwise. Read per decision, so
        // turning it off takes effect without a restart.
        () => { try { return this.getConfig().decisionCorpus !== false; } catch { return false; } },
        undefined,
        { workspaceContainers: () => this.workspaceContainers() }
      );
      this.policy.load();
    }
    return this.policy;
  }

  /** The report check, or null when the policy file does not turn it on. Decided
   *  once, like the policy load itself: an edit takes effect on restart. */
  private reportCheck(): ReportCheck | null {
    if (this.reportChecker === undefined) {
      const cfg = this.policyEngine().reportCheck;
      this.reportChecker = cfg
        ? new ReportCheck(
          cfg,
          (row) => this.hive.appendLog(row as Parameters<HiveManager['appendLog']>[0]),
          (subject, body) => { this.hive.send({ to: 'god', act: 'inform', subject, body }, REPORT_CHECK_SENDER); }
        )
        : null;
    }
    return this.reportChecker;
  }

  /** True when the policy file turns the report check on. The hive asks this when it
   *  writes an agent's hook settings, to decide whether to register PostToolUseFailure. */
  reportCheckActive(): boolean {
    try { return this.reportCheck() !== null; } catch { return false; }
  }

  /** Called for every delivered hive message. A no-op unless the check is on. */
  checkDelivered(msg: ReportMessage): void {
    try { this.reportCheck()?.checkMessage(msg); } catch { /* never affect delivery */ }
  }

  /** Desktop alert plus an ASK ME card for an agent stopped at a policy prompt. */
  private raisePolicyPrompt(agentId: string, ruleId: string): string {
    const now = new Date().toISOString();
    const cardId = `policy-prompt-${agentId}-${Date.now().toString(36)}`;
    this.notify(agentId, `Waiting on you: rule ${ruleId} asked before a tool call. Answer in ${agentId}'s terminal.`);
    this.hive.addTask({
      id: cardId,
      title: `${agentId} is stopped at a prompt (rule ${ruleId})`,
      status: 'blocked', dependsOn: [], priority: 1, createdAt: now, assignee: agentId,
      humanQA: [{
        q: `**${agentId} is stopped until you answer a permission prompt in its terminal.**\n\nThe policy rule \`${ruleId}\` asked before a tool call. Open ${agentId}'s terminal and choose Yes or No. This card closes itself once the agent moves on.`,
        askedAt: now,
        from: agentId,
      } as HumanQA],
    } as HiveTask);
    this.hive.appendLog({ kind: 'policy-prompt-waiting', agent_id: agentId, rule_id: ruleId, card_id: cardId } as Parameters<HiveManager['appendLog']>[0]);
    return cardId;
  }

  /** The agent moved on, so the prompt was answered: close its card. */
  private settlePolicyPrompt(agentId: string, answer = 'Answered in the terminal.'): void {
    const ask = this.policyAsks.get(agentId);
    if (!ask) return;
    this.policyAsks.delete(agentId);
    if (!ask.cardId) return;
    try {
      const now = new Date().toISOString();
      const task = ((this.hive.tasks() as { tasks?: HiveTask[] })?.tasks ?? []).find((t) => t?.id === ask.cardId);
      const qa = (task?.humanQA ?? []).map((e: HumanQA) => (e.a ? e : { ...e, a: answer, answeredAt: now }));
      this.hive.patchTask(ask.cardId, { status: 'done', humanQA: qa });
    } catch { /* best-effort */ }
  }

  /** The grant desk, or null when no rule is grantable. Decided once per daemon. */
  private grantDesk(): GrantDesk | null {
    if (this.desk === undefined) {
      const root = this.hive.root();
      this.desk = root && this.policyEngine().grantsActive
        ? new GrantDesk(GrantStore.in(join(root, 'policy')), undefined, (q, why) => this.requestDropped(q, why))
        : null;
    }
    return this.desk;
  }

  /** True while a policy ask for this agent is unanswered: it is at Claude Code's
   *  permission prompt, so nothing may type into its terminal (an Enter would answer
   *  Yes). Cleared by the same answered events that close its prompt card. */
  awaitingPolicyAnswer(agentId: string | undefined): boolean {
    return !!agentId && this.policyAsks.has(agentId);
  }

  /** The permission prompt went away with no hook (Esc fires none): main saw the
   *  input box again on a quiet terminal. Settle the ask and close its card. */
  dismissPolicyAsk(agentId: string | undefined): void {
    if (agentId) this.settlePolicyPrompt(agentId, 'Dismissed in the terminal.');
  }

  /** True when the policy file makes some rule grantable. The UI shows nothing otherwise. */
  grantsActive(): boolean {
    try { return this.grantDesk() !== null; } catch { return false; }
  }

  /**
   * An agent's `approval-request` outbox message. Returns false when approvals are
   * off, so the hive routes the message as it always did.
   */
  handleApprovalRequest(agentId: string, msg: Record<string, unknown>): boolean {
    const desk = this.grantDesk();
    if (!desk) return false;
    const log = (row: Record<string, unknown>) => this.hive.appendLog(row as Parameters<HiveManager['appendLog']>[0]);
    const r = desk.request(agentId, { command: msg.command, cwd: msg.cwd, reason: msg.reason ?? msg.body });
    if (!r.ok && 'denied' in r && r.denied) {
      log({ kind: 'grant-request-refused', agent_id: agentId, why: r.why, denied: true });
      this.hive.send({ to: agentId, act: 'refuse', subject: 'Push denied', body: `Not accepted: ${r.why}.` }, GRANT_DESK_SENDER);
      return true;
    }
    if (!r.ok) {
      log({ kind: 'grant-request-refused', agent_id: agentId, why: r.why });
      this.hive.send({
        to: agentId, act: 'refuse', subject: 'Approval request not accepted',
        body: `It cannot be approved as written: ${r.why}.
The approvable form is one Bash call: git [-C <dir>] push <remote> <40-char sha>:refs/heads/<branch>, sent as {"act":"approval-request","command":"…","cwd":"<dir>","reason":"…"}. Anything else still needs the operator in person.`,
      }, GRANT_DESK_SENDER);
      return true;
    }
    const q = r.request;
    if (r.fresh) this.announceRequest(agentId, q, 'outbox');
    this.hive.send({
      to: agentId, act: 'inform', subject: `Approval requested: ${q.action.summary}`,
      body: `Request ${q.id} is waiting for the operator. Do not run the push until a message says it is approved; then run exactly this, as one Bash call, within 60 minutes (no cd in front: it names its repo):\n${runnablePush(q.command, q.cwd)}`,
    }, GRANT_DESK_SENDER);
    return true;
  }

  /** What to tell an agent that tried another push form while one is waiting or
   *  approved for it, or null when it has none (then the rule asks as usual). */
  private openApproval(agentId: string, p: HookPayload): string | null {
    try {
      const command = (p.tool_input as { command?: unknown } | undefined)?.command;
      if (typeof command !== 'string') return null;
      // Only toward the remote that was approved (finish plan item 4): a push to some
      // other repo asks as it always did.
      const o = this.grantDesk()?.openForPush(agentId, command, typeof p.cwd === 'string' ? p.cwd : null);
      if (!o) return null;
      this.hive.appendLog({ kind: 'grant-form-refused', agent_id: agentId, state: o.state, id: o.id } as Parameters<HiveManager['appendLog']>[0]);
      const run = runnablePush(o.command, o.cwd);
      return o.state === 'approved'
        ? `Not run: no approval covers this push. Your approved push (grant ${o.id}) is exactly this, as one Bash call, with no cd in front: ${run}\nAny other push needs its own approval.`
        : `Not run: request ${o.id} is still waiting for the operator. End your turn; after "Approved", run exactly this, as one Bash call, with no cd in front: ${run}`;
    } catch { return null; }
  }

  /** `cd <repo> && <approvable push>`: no grant covers that form and an ask would open
   *  the terminal prompt (day job, 2026-10-06), so refuse it with the one runnable
   *  command that can go on the card. Null for anything else. */
  private cdFormRefusal(p: HookPayload): string | null {
    try {
      const command = (p.tool_input as { command?: unknown } | undefined)?.command;
      const run = typeof command === 'string' ? this.grantDesk()?.cdFormRunnable(command) ?? null : null;
      return run ? `Not run: a push with cd in front cannot be approved. Run it as one git command that names its repo: ${run}` : null;
    } catch { return null; }
  }

  /** A request left the card without the operator's decision: tell the agent waiting
   *  on it, so it does not wait for an answer that will never come (Dwight L3, L8). */
  private requestDropped(q: GrantRequest, why: 'expired' | 'approvals-off'): void {
    this.hive.appendLog({ kind: 'grant-request-dropped', request_id: q.id, agent_id: q.agent_id, why } as Parameters<HiveManager['appendLog']>[0]);
    this.hive.send({
      to: q.agent_id, act: 'refuse', subject: `Approval request ${q.id} dropped`,
      body: why === 'expired'
        ? `Request ${q.id} waited 60 minutes with no decision and expired. If you still need the push, run it again to put it on a new card.`
        : `Approvals were turned off in the rules, so request ${q.id} will not be decided. The push now asks in the terminal.`,
    }, GRANT_DESK_SENDER);
    this.getWebContents()?.send('policy:grantsChanged');
  }

  /** A new request is on the Approvals card: log it, tell god, alert the operator. */
  private announceRequest(agentId: string, q: GrantRequest, via: 'outbox' | 'hook'): void {
    this.hive.appendLog({
      kind: 'grant-requested', request_id: q.id, agent_id: agentId, class: q.action.class, target: q.action.target, via,
    } as Parameters<HiveManager['appendLog']>[0]);
    this.hive.send({
      to: 'god', act: 'inform', subject: `${agentId} is waiting on the operator: ${q.action.summary}`,
      body: `The operator approves or denies it under Approvals in the ASK ME tab. ${agentId} will wait; nothing to relay.`,
    }, GRANT_DESK_SENDER);
    this.notify(agentId, `Approval needed: ${q.action.summary}`);
    this.getWebContents()?.send('policy:grantsChanged');
  }

  /**
   * The engine denied an approvable push that has no grant (rather than ask: a grant
   * is used on a LATER call, so Approve could never answer a terminal prompt that is
   * already open). Put the push on the Approvals card, once, and tell the agent how to
   * finish. The deny itself never depends on this succeeding.
   */
  private approvalNeeded(agentId: string, p: HookPayload): string {
    try {
      const input = (p.tool_input ?? {}) as Record<string, unknown>;
      const desk = this.grantDesk();
      const r = desk?.request(agentId, { command: input.command, cwd: p.cwd, reason: 'Raised by the push itself.' });
      if (r && !r.ok && 'denied' in r && r.denied) return `Not run: ${r.why}.`;
      if (r?.ok) {
        if (r.fresh) this.announceRequest(agentId, r.request, 'hook');
        return `Not run: this push needs the operator's approval. Request ${r.request.id} is on the Approvals card in ASK ME. End your turn and wait. When a message says "Approved", run exactly this, as one Bash call, with no cd in front: ${runnablePush(r.request.command, r.request.cwd)}
If it says "Denied", do not push.`;
      }
    } catch { /* never break a hook */ }
    return 'Not run: this push needs the operator\'s approval. Send an approval-request outbox message for exactly this command, end your turn, and run it again only after a message says "Approved".';
  }

  /** What the operator sees: main's own copy of each pending request. */
  pendingGrants(): GrantRequest[] {
    try { return this.grantDesk()?.pending() ?? []; } catch { return []; }
  }

  /** The operator's Approve or Deny. Reached only from the app's own UI, never an agent. */
  decideGrant(requestId: string, approve: boolean): { ok: boolean; error?: string } {
    const desk = this.grantDesk();
    if (!desk) return { ok: false, error: 'approvals are off in the policy file' };
    const d = desk.decide(requestId, approve === true);
    if (!d) return { ok: false, error: 'that request is no longer pending' };
    const { request: q, grant } = d;
    this.hive.appendLog({
      kind: 'grant-decided', request_id: q.id, agent_id: q.agent_id, approved: !!grant, grant_id: grant?.id ?? null,
    } as Parameters<HiveManager['appendLog']>[0]);
    this.hive.send(grant
      ? {
        to: q.agent_id, act: 'agree', subject: `Approved: ${q.action.summary}`,
        body: `Grant ${grant.id}. Run exactly this, as one Bash call, with no cd in front, before ${grant.expires_at}:\n${runnablePush(q.command, q.cwd)}\nIt works once; the identical command may be retried within 10 minutes of the first run. Any other form of the push is refused; any other push needs its own approval.`,
      }
      : {
        to: q.agent_id, act: 'refuse', subject: `Denied: ${q.action.summary}`,
        body: `The operator denied request ${q.id}. Do not run it.`,
      }, GRANT_DESK_SENDER);
    this.getWebContents()?.send('policy:grantsChanged');
    return { ok: true };
  }


  /** Let go of the current listener. Closing it is right ONLY while the path
   *  still leads to our socket (or to nothing): libuv unlink(2)s the path by NAME
   *  on close, so closing a listener whose path a live stranger has since bound
   *  deletes THEIR socket — the app is up, hooks.sock is gone, every hook
   *  allows, nothing is logged (#277). In that case the handle is abandoned
   *  instead: unreachable by path, one fd, reclaimed at exit. */
  private detach(orphan: boolean): void {
    const s = this.server;
    this.server = null;
    this.mark = null;
    this.bound = null;
    if (!s) return;
    if (orphan) {
      try { s.unref(); } catch { /* noop */ }
      this.orphans.push(s);
      return;
    }
    try { s.close(); } catch { /* noop */ }
  }

  stop(): void {
    // Flush the false-positive denominator before the daemon goes away.
    try { this.policy?.flushStats(); } catch { /* noop */ }
    this.stopped = true;
    if (this.retryTimer) { clearTimeout(this.retryTimer); this.retryTimer = null; }
    // Synchronous (quit and relaunch paths cannot wait for a probe): the file
    // at the path is ours → close, and libuv removes it; missing → close, the
    // unlink is a no-op; a DIFFERENT file → someone else bound the path after
    // us, leave their socket alone and abandon ours.
    const sock = this.bound?.path ?? null;
    const now = sock && process.platform !== 'win32' ? markOf(sock) : null;
    const stranger = !!this.mark && !!now && !sameMark(this.mark, now);
    this.detach(stranger);
  }

  /** The transcript file of an agent's CURRENT session, if any hook has fired. */
  transcriptPath(agentId: string): string | undefined {
    return this.transcriptPaths.get(agentId);
  }

  /** The latest context-window accounting for an agent (current tokens + the real
   *  window size), or undefined if no statusLine tick has fired for it yet. */
  contextFor(agentId: string): { tokens: number; limit: number; ts: number } | undefined {
    return this.contextById.get(agentId);
  }

  private handle(p: HookPayload): unknown {
    const agentId = p.agent_id ?? undefined;
    const event = p.hook_event_name ?? 'Unknown';
    // Finish plan item 5: a payload naming an agent must carry that agent's token.
    // Without it, the decision only; nothing else happens in that agent's name.
    if (this.hookAuth && agentId && !this.hookAuth.verify(agentId, (p as { hook_token?: unknown }).hook_token)) {
      return this.unauthenticated(agentId, event, p);
    }
    // The approved push just allowed above asks to leave the sandbox: that request is
    // the operator's Approve too. Only the same agent, the exact command, once, soon.
    if (event === 'PermissionRequest' && agentId) {
      const run = this.approvedRuns.get(agentId);
      const input = p.tool_input as { command?: unknown; dangerouslyDisableSandbox?: unknown } | undefined;
      if (run && Date.now() - run.at < APPROVED_RUN_WINDOW_MS && p.tool_name === 'Bash' && (p.cwd ?? null) === run.cwd
        && input?.command === run.command && input?.dangerouslyDisableSandbox === true) {
        this.approvedRuns.delete(agentId);
        this.hive.appendLog({ kind: 'grant-sandbox-exit', agent_id: agentId } as Parameters<HiveManager['appendLog']>[0]);
        return { hookSpecificOutput: { hookEventName: 'PermissionRequest', decision: { behavior: 'allow' } } };
      }
    }
    // The run is over, whether or not it asked (Dwight L1: bypass mode never does).
    if ((event === 'PostToolUse' || event === 'PostToolUseFailure') && agentId && p.tool_name === 'Bash'
      && (p.tool_input as { command?: unknown } | undefined)?.command === this.approvedRuns.get(agentId)?.command) {
      this.approvedRuns.delete(agentId);
    }
    this.onEvent?.(agentId, event, p.message, p);
    if (agentId && typeof p.transcript_path === 'string' && p.transcript_path) {
      this.transcriptPaths.set(agentId, p.transcript_path);
    }

    // Status-line payloads carry the session's EXACT context accounting —
    // current tokens AND the real window size (200k vs 1M, which nothing else
    // exposes). Forward to the renderer for the agent-card context gauge.
    // Handled FIRST and returned early: this is pure telemetry from the
    // statusLine shim, not a real hook boundary — it must never trip the
    // HALT gate or feed the breaker's loop detector below. The early return
    // also (deliberately) skips recordSession for status ticks: a statusLine
    // payload's session_id adds nothing the real hooks don't already record,
    // and telemetry should never write to the registry. transcript_path IS
    // still captured above, where every payload shape benefits from it.
    if (event === 'Status') {
      const cw = p.context_window;
      if (agentId && cw && typeof cw.total_input_tokens === 'number'
        && typeof cw.context_window_size === 'number' && cw.context_window_size > 0) {
        // Retain for main-side reads (voice get_agent_detail / list_agents) …
        this.contextById.set(agentId, {
          tokens: cw.total_input_tokens,
          limit: cw.context_window_size,
          ts: Date.now()
        });
        // … and forward live to the renderer's agent-card context gauge.
        this.getWebContents()?.send('hive:contextUpdate', {
          agentId,
          tokens: cw.total_input_tokens,
          limit: cw.context_window_size
        });
      }
      return {};
    }

    // 7C.3 — a graceful operator HALT overrides everything (incl. the inbox
    // drain below): stop the agent CLEANLY at this hook boundary rather than
    // killing the PTY. session_id is in the payload for a later --resume.
    if (agentId && this.control?.shouldHalt(agentId)) {
      this.emit(agentId, event, p);
      return { continue: false, stopReason: 'Halted by the operator from the floor.' };
    }

    // Capture the Claude Code session id for idempotent --resume + cost dedup
    // (Lane A #6.6a). Cheap: recordSession writes only when it changes.
    if (agentId && p.session_id) this.hive.recordSession(agentId, p.session_id);

    // CostSample — synthesized by the proxy-bridge sidecar (qwen) on every
    // response with usage. Persist it to the SAME cost ledger as Claude's OTel
    // path, keyed by the synthesized session_id, then return early so cost stays
    // OUT of the Claude-only OTel/breaker/drain paths below. `usd` is the fallback
    // per-model estimate (a local model normally costs ~$0, but the row keeps the
    // accounting schema uniform). Pure telemetry — never feeds the loop detector.
    if (event === 'CostSample') {
      if (agentId && p.session_id) {
        const input = p.input ?? 0;
        const output = p.output ?? 0;
        const cacheRead = p.cache_read ?? 0;
        const cacheCreation = p.cache_creation ?? 0;
        this.hive.appendCostLedger({
          agentId,
          sessionId: p.session_id,
          ts: Date.now(),
          input,
          output,
          cacheRead,
          cacheCreation,
          model: p.model ?? '',
          usd: estimateCostUsd(p.model, {
            inputTokens: input,
            outputTokens: output,
            cacheReadTokens: cacheRead,
            cacheWriteTokens: cacheCreation
          })
        });
      }
      return {};
    }

    // Feed the breaker its hook-derived loop signal: a tool that actually ran.
    // A repeated identical (name+input) PostToolUse is the runaway-loop tell.
    if (event === 'PostToolUse' && agentId) {
      this.breaker?.recordToolUse(agentId, p.tool_name, p.tool_input);
    }

    // HAG-46 report check: record test outcomes. Off unless the policy file turns it
    // on, and PostToolUseFailure is only registered for agents when it is.
    if ((event === 'PostToolUse' || event === 'PostToolUseFailure' || event === 'SessionStart') && agentId) {
      try {
        const rc = this.reportCheck();
        if (rc) {
          if (event === 'SessionStart') rc.sessionStarted(agentId, p.source);
          else rc.recordOutcome({ ...p, agent_id: agentId });
        }
      } catch { /* the check must never break a hook */ }
    }

    // A human just spoke to this agent (issue #376): stamp the third progress
    // clock the no-progress arm reads. A conversation is prose in, prose out —
    // no hive file changes, no tool spans — which the arm otherwise reads as
    // "generating tokens without coordinating". A runaway loop is ONE prompt
    // followed by many tool calls, so this clock goes stale exactly when it
    // should and blinds nothing.
    if (event === 'UserPromptSubmit' && agentId) {
      this.breaker?.recordUserPrompt(agentId);
    }

    // Compaction exemption (issue #109): PreCompact opens it so the compaction
    // token burst can't trip the Δoutput arms; PostCompact — or any SessionStart,
    // since a fresh session makes in-flight compaction state moot — closes it
    // down to the trailing grace (a no-op when nothing was compacting).
    if (event === 'PreCompact' && agentId) this.breaker?.recordCompactStart(agentId);
    if ((event === 'PostCompact' || event === 'SessionStart') && agentId) {
      this.breaker?.recordCompactEnd(agentId);
    }
    // A compact keeps the session id (md-138), so the once-per-session goal
    // would otherwise never come back. Forget it when the compaction STARTS:
    // no context-carrying hook fires before it ends, and forgetting at the end
    // would re-send a goal that a SessionStart(compact) had already delivered.
    if ((event === 'PreCompact' || event === 'SessionStart') && agentId) {
      this.deliveredGoalByAgent.delete(agentId);
    }
    // md-197: the compaction summary keeps only what the agent chose to carry,
    // so the rules go back in on the next hook that can carry context. Armed
    // when the compaction starts, for the same reason as the goal above. Also
    // armed by SessionStart source=compact, should Claude Code ever send one,
    // and source=resume: a resume rebuilds context from a transcript that may
    // have been compacted, and it is how an agent comes back after an app restart.
    if (agentId && (event === 'PreCompact'
      || (event === 'SessionStart' && (p.source === 'compact' || p.source === 'resume')))) {
      this.rulesDueAfterCompact.add(agentId);
    }

    // A subagent finishing is not its agent finishing (Dwight M5): since the shims send
    // the hive agent's id, a SubagentStop arrives as the parent mid-turn. Report it as
    // activity only: no idle notice, nothing that waits for the agent to be idle.
    if (event === 'SubagentStop' && agentId) {
      this.emit(agentId, event, p);
      return {};
    }

    if (event === 'Stop' && agentId) {
      // Respect any upstream Stop hook that already re-entered this boundary.
      if (p.stop_hook_active) { this.emit(agentId, event, p); return {}; }
      // Never turn unread hive mail into a forced continuation at Stop. That old
      // path bypassed terminal-draft/HITL safety and could spend credits while a
      // user was answering a question. Inbox files remain durable; the renderer
      // wakes the agent later through its guarded idle-only delivery path.
      this.notify(agentId ?? 'Agent', 'finished — idle');
      this.emit(agentId, event, p);
      return {};
    }

    // 7C.1 — HITL gate: deny a tool call at the PreToolUse boundary when the
    // agent is paused or this tool is gated. Race-free (immediate return, no
    // renderer round-trip → can't hit the shim timeout). Slow human APPROVAL is
    // deliberately left to Claude's native permission prompt.
    if (event === 'PreToolUse' && agentId && this.control) {
      const d = this.control.toolDecision(agentId, p.tool_name ?? '');
      if (d.deny) {
        this.emitControl(agentId, p.tool_name, d.reason);
        this.emit(agentId, event, p);
        return {
          hookSpecificOutput: {
            hookEventName: 'PreToolUse',
            permissionDecision: 'deny',
            permissionDecisionReason: d.reason ?? 'Denied by operator.'
          }
        };
      }
    }

    // 7C.3 — authority policy: a standing, declared rule evaluated AFTER operator
    // control, so a live operator instruction always outranks a standing rule and
    // the 7C.1 branch above stays byte-identical. Fully inert with no policy file:
    // `active` is false, nothing is evaluated and nothing is logged.
    if (event === 'PreToolUse') {
      const policy = this.policyEngine();
      if (policy.active) {
        const v = policy.evaluate({
          hook_event_name: event,
          agent_id: agentId ?? null,
          tool_name: p.tool_name,
          tool_input: p.tool_input,
          // The agent shell's cwd, not ours: a relative write target means nothing
          // without it, and the daemon's own cwd is not where the agent is standing.
          cwd: p.cwd
        });
        if (v.grantId && v.decision === 'allow' && !v.wouldDeny) {
          // The operator's Approve IS the permission. Without an explicit allow an agent
          // that is not in bypassPermissions stops at Claude Code's own prompt for the
          // very push that was approved (day job, 2026-10-06).
          // The allow answers the permission check but not the sandbox's: its network
          // check for the remote's host is a prompt of its own (third day-job report,
          // reproduced with Claude Code 2.1.291). So the approved push runs outside
          // the sandbox, and the one request to leave it is answered below.
          // What leaves it is the push rebuilt from the grant, never the agent's text.
          const input = p.tool_input && typeof p.tool_input === 'object' ? p.tool_input as Record<string, unknown> : null;
          let command: string | null = null;
          if (agentId && p.tool_name === 'Bash' && typeof input?.command === 'string') {
            try { command = this.grantDesk()?.approvedPushRun(agentId, v.grantId, input.command, typeof p.cwd === 'string' ? p.cwd : null) ?? null; } catch { command = null; }
          }
          if (agentId && command) this.approvedRuns.set(agentId, { command, cwd: p.cwd ?? null, at: Date.now() });
          this.emit(agentId, event, p);
          return {
            hookSpecificOutput: {
              hookEventName: 'PreToolUse',
              permissionDecision: 'allow',
              permissionDecisionReason: `[policy:${v.ruleId}] Approved by the operator (grant ${v.grantId}).`,
              ...(command ? { updatedInput: { ...input, command, dangerouslyDisableSandbox: true } } : {})
            }
          };
        }
        // Another push form while this agent has a push waiting or approved: no grant can
        // cover it and an ask would open the prompt again, so refuse it and name the
        // exact approved command. A cd form names its own repo, so it gets its own
        // command first, never another repo's open approval (Dwight F1-M1).
        const open = v.notApprovable && agentId ? (this.cdFormRefusal(p) ?? this.openApproval(agentId, p)) : null;
        if (v.decision !== 'allow') {
          const decision = open ? 'deny' : v.decision;
          if (decision === 'ask' && agentId && v.ruleId) this.policyAsks.set(agentId, { ruleId: v.ruleId, at: Date.now() });
          const why = `[policy:${v.ruleId}] ${v.reason ?? 'Denied by policy.'}`;
          this.emit(agentId, event, p);
          return {
            hookSpecificOutput: {
              hookEventName: 'PreToolUse',
              permissionDecision: decision,
              permissionDecisionReason: open ? `${why} ${open}`
                : v.approvalNeeded && agentId ? `${why} ${this.approvalNeeded(agentId, p)}` : why
            }
          };
        }
      }
    }

    // 7C.2 — mid-run steering: inject queued operator guidance as context on the
    // next eligible hook (no fragile typing into the TUI). Delivered once.
    // Merged with the roster line below so the two injections never displace each
    // other (only ONE additionalContext can be returned per hook).
    let steer: string | null = null;
    if ((event === 'UserPromptSubmit' || event === 'PostToolUse') && agentId && this.control) {
      steer = this.control.takeSteer(agentId) ?? null;
    }

    // Keep god's roster CURRENT. fleet.json is always fresh on disk, but god's
    // context is not: after a restart it resumes a transcript describing the old
    // floor and messages agents that are long gone. Push the live roster in as
    // additionalContext at the start of each session and on every prompt, so god
    // knows the floor all the time instead of only when it remembers to Read.
    // God-only and one line — every other agent is unaffected.
    const wantsRoster = (event === 'SessionStart' || event === 'UserPromptSubmit')
      && !!agentId && this.hive.isGod(agentId);
    // Hand the roster the LIVE context-window occupancy (contextById) so each
    // agent line can carry a `ctx NN%` — god then sees whose context is nearly
    // full when it routes work, instead of guessing from cumulative token spend.
    const roster = wantsRoster
      ? this.hive.rosterContext((id) => this.contextFor(id))
      : null;

    // Standing goal (hire Briefing) — durable roster field, re-read every cycle so
    // an Edit Agent save is picked up on the next UserPromptSubmit without
    // restarting the worker. Deliver it once at SessionStart, then only when its
    // value changes; repeating an unchanged briefing on every prompt can make it
    // one of the largest elements in a long transcript. Kept out of
    // --append-system-prompt (volatile-free cache invariant); lives on the live
    // hook channel instead.
    const wantsGoal = (event === 'SessionStart' || event === 'UserPromptSubmit') && !!agentId;
    const goalRaw = wantsGoal ? (this.getStandingGoal?.(agentId) ?? null) : null;
    let goal: string | null = null;
    if (wantsGoal) {
      const sessionId = p.session_id ?? null;
      const delivered = this.deliveredGoalByAgent.get(agentId);
      const newSession = !delivered || delivered.sessionId !== sessionId;
      const changed = !!delivered && delivered.sessionId === sessionId && delivered.goal !== goalRaw;
      if (event === 'SessionStart' || newSession || changed) {
        this.deliveredGoalByAgent.set(agentId, { sessionId, goal: goalRaw });
        if (goalRaw) {
          goal = `<goal>\n${goalRaw}\n</goal>`;
        } else if (changed && delivered?.goal) {
          // Silence would leave the old briefing alive in the model's context.
          // Explicitly revoke it when the operator clears the durable field.
          goal = '<goal>\n[Cleared by the operator. Stop following the previous standing goal.]\n</goal>';
        }
      }
    }

    // Rules notice (md-146 §4) — rides the same channel as the goal rather than
    // replacing it. Deliberately NOT keyed on session: that is the md-138 bug,
    // where a once-per-session injection quietly stops arriving after the first
    // compaction. This is keyed on the rule revision and recorded on disk, so it
    // fires once per change per agent and survives a restart.
    const rulesNotice = (event === 'SessionStart' || event === 'UserPromptSubmit') && agentId
      ? (this.takeRulesNotice?.(agentId) ?? null)
      : null;

    // Full rule set after a compaction (md-197) — once per compaction, on the
    // first hook that can carry context. PostToolUse counts: an agent that
    // auto-compacts mid-task may not see another prompt for a long time.
    // The mark clears only on an actual delivery: a rules.json caught mid-edit
    // reads as null, and clearing then would lose the re-delivery for good.
    let rulesFull: string | null = null;
    if ((event === 'SessionStart' || event === 'UserPromptSubmit' || event === 'PostToolUse')
      && agentId && this.rulesDueAfterCompact.has(agentId)) {
      rulesFull = this.getRulesFullSet?.(agentId) ?? null;
      if (rulesFull) this.rulesDueAfterCompact.delete(agentId);
    }

    if (steer || roster || goal || rulesFull || rulesNotice) {
      this.emit(agentId, event, p);
      return {
        hookSpecificOutput: {
          hookEventName: event,
          additionalContext: [roster, goal, rulesFull, rulesNotice, steer].filter(Boolean).join('\n\n')
        }
      };
    }

    // A permission prompt that a POLICY ask raised (spike 2026-09-29): in an agent's
    // own terminal the session stops there until someone answers, and nothing else on
    // the floor says so. Only an ask the engine returned counts, so with no policy file
    // (and for Claude's own prompts) this changes nothing.
    if (event === 'Notification' && agentId && isPermissionPrompt(p)) {
      const ask = this.policyAsks.get(agentId);
      if (ask && !ask.cardId && Date.now() - ask.at < POLICY_PROMPT_WINDOW_MS) {
        try { ask.cardId = this.raisePolicyPrompt(agentId, ask.ruleId); } catch { /* never break a hook */ }
      }
    }
    if (agentId && ANSWERED_EVENTS.has(event)) this.settlePolicyPrompt(agentId);

    // A Notification hook that means "the agent is blocked waiting for the user"
    // (idle prompt) deserves a desktop toast too — distinct from a permission
    // request, which surfaces natively in the agent's own Claude Code session
    // (approvable remotely via /remote-control).
    if (
      event === 'Notification' &&
      (p.notification_type === 'idle' ||
        (p.message ?? '').toLowerCase().includes('waiting for your input'))
    ) {
      this.notify(agentId ?? 'Agent', p.message ?? 'needs your attention');
    }

    // Forward everything else to the renderer so avatars reflect real activity.
    this.emit(agentId, event, p);
    return {};
  }

  /** Fire a native desktop notification — gated on the user's `notifications`
   *  setting. Only the OS toast is gated; the hive:hookEvent emit is always sent
   *  so avatars/UI stay live regardless. Best-effort: never throw into the hook. */
  private notify(title: string, body: string): void {
    if (!this.getConfig().notifications) return;
    try {
      if (!Notification.isSupported()) return;
      new Notification({ title, body }).show();
    } catch { /* notifications unsupported on this platform — ignore */ }
  }

  /** Tell the renderer a tool call was gated/denied (#7C.1) so it can surface it
   *  (toast / control strip) — distinct from the avatar hook stream. */
  private emitControl(agentId: string, tool: string | undefined, reason: string | undefined): void {
    this.getWebContents()?.send('control:approvalRequest', { agentId, tool, reason });
  }

  private emit(agentId: string | undefined, event: string, p: HookPayload, blocked = false): void {
    const payload = {
      agentId,
      event,
      tool: p.tool_name,
      notificationType: p.notification_type,
      source: p.source,
      message: p.message,
      blocked
    };
    if (!validateHookEvent(payload)) {
      console.warn('[hive] rejected invalid hook event:', event);
      return;
    }
    this.getWebContents()?.send('hive:hookEvent', payload);
  }
}
