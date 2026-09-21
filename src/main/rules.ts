/**
 * RulesManager — the render layer for agent authority rules (md-146 Phase 1).
 *
 * WHAT PROBLEM THIS SOLVES. Standing process rules only work if the agent is
 * holding them, and the only channel that is re-read on every task is the agent's
 * own pinned memory block. Before this, getting a rule into that block meant a
 * human editing a store and then hand-messaging every agent to paste it in — a
 * manual step per agent per change, which does not scale past the first week.
 * This renders the store into each targeted agent's pinned block automatically,
 * and tells the agent what changed.
 *
 * THE SAFETY PROPERTY IS THE SENTINELS. The renderer writes ONLY between explicit
 * markers and never touches a byte outside them. A memory.md is an agent's
 * accumulated work; an automated edit that guesses at boundaries is how the app
 * eats it. If the markers are damaged — exactly one present, or out of order —
 * this ABORTS and touches nothing, because a half-marked file means something else
 * edited it and guessing there is the expensive mistake.
 *
 * DORMANT UNLESS CONFIGURED. With no rules store on disk, every entry point
 * no-ops: nothing rendered, nothing logged, nothing notified. Same property the
 * policy engine has, and for the same reason — an install that has not opted in
 * must behave byte-identically.
 *
 * Runs in the Electron main process.
 */
import { existsSync, mkdirSync, readFileSync, readdirSync, renameSync, writeFileSync, copyFileSync, openSync, fsyncSync, closeSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join } from 'node:path';

/** Marker text. The BEGIN line carries the rev, which is what reconcile reads. */
const BEGIN_PREFIX = '<!-- BEGIN managed rules';
const END_MARKER = '<!-- END managed rules -->';
const PINNED_PREFIX = '## \u{1F4CC}';
const PINNED_HEADING = '## \u{1F4CC} Durable facts (pinned — never condensed)';

/**
 * Caps from md-146 §5. RECORDED, not enforced here: enforcement belongs at
 * authoring time, where a human can see the number move and drop a rule instead
 * of being refused after the fact. Kept in code so the authoring UI and any
 * report read the same constants rather than re-deciding them.
 */
export const RULE_CAPS = {
  globalMax: 12,
  globalMaxTokens: 600,
  perAgentMax: 5,
  perAgentMaxTokens: 250,
  why: 'The cap is an alignment mechanism, not a token budget: fewer rules means each is more salient.'
} as const;

/**
 * Canonical scope, per the locked decision: global, or an explicit agent list.
 * There is deliberately no `role` kind — a role is not a durable address, and a
 * rule that cannot name who it binds cannot be rendered to anyone.
 *
 * The string forms are the hand-written md-137-era store that exists on disk
 * today. `"all"` is accepted as global so the live file renders; anything else
 * (notably `"role"`) targets NOBODY and is logged, because silently rendering a
 * rule to the wrong agents is worse than rendering it to none.
 */
export type RuleScope =
  | { kind: 'global' }
  | { kind: 'agents'; ids: string[] }
  | 'all'
  | string;

export interface Rule {
  id: string;
  text: string;
  scope?: RuleScope;
  enforceable?: 'yes' | 'proposed' | 'no';
  authority_rule_id?: string;
  why?: string;
  status?: 'active' | 'retired';
  added_by?: string;
  added?: string;
  retired?: string;
}

export interface RulesFile {
  rev?: number;
  rules?: Rule[];
}

/** Why a render did not happen. `ok` means the file now holds the current rev. */
export type RenderOutcome =
  | { ok: true; agentId: string; rev: number; action: 'replaced' | 'inserted' | 'unchanged'; count: number }
  | { ok: false; agentId: string; reason: string };

interface DeliveryRecord {
  rev: number;
  at: string;
  /** id -> sha1 of the rule text at delivery. Enough to diff without storing a
   *  second copy of the text; retired text is recovered from the tombstone. */
  digest: Record<string, string>;
}

const sha1 = (s: string): string => createHash('sha1').update(s).digest('hex').slice(0, 12);

/** Read a JSON file, or null. Never throws — a broken store must not take the app down. */
function readJson<T>(path: string): T | null {
  try { return JSON.parse(readFileSync(path, 'utf8')) as T; } catch { return null; }
}

/** temp sibling → fsync → rename. The rename is the durability guarantee. */
function atomicWrite(path: string, text: string): void {
  const tmp = `${path}.tmp-${Math.random().toString(36).slice(2, 10)}`;
  writeFileSync(tmp, text, 'utf8');
  try {
    const fd = openSync(tmp, 'r+');
    try { fsyncSync(fd); } finally { closeSync(fd); }
  } catch { /* fsync best-effort */ }
  renameSync(tmp, path);
}

// ---------------------------------------------------------------------------
// Sentinel surgery — the part that must never be clever
// ---------------------------------------------------------------------------

export interface SentinelSpan {
  /** Line index of the BEGIN marker, or -1. */
  begin: number;
  /** Line index of the END marker, or -1. */
  end: number;
  /** rev parsed out of the BEGIN marker, or null when absent/unparseable. */
  rev: number | null;
}

export function findSentinels(lines: string[]): SentinelSpan {
  let begin = -1;
  let end = -1;
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i].trim();
    if (begin === -1 && l.startsWith(BEGIN_PREFIX)) begin = i;
    else if (end === -1 && l === END_MARKER) end = i;
  }
  let rev: number | null = null;
  if (begin !== -1) {
    const m = lines[begin].match(/rev\s+(\d+)/);
    if (m) rev = Number(m[1]);
  }
  return { begin, end, rev };
}

/**
 * Produce the new file content, or a reason to refuse.
 *
 * Pure: takes text in, gives text out, so the branch table below is testable
 * without a hive on disk. That matters more here than anywhere else in this file.
 */
export function applyBlock(text: string, block: string): { ok: true; text: string; action: 'replaced' | 'inserted' } | { ok: false; reason: string } {
  const lines = text.split('\n');
  const { begin, end } = findSentinels(lines);

  // Both markers, in order → replace what is between them, inclusive.
  if (begin !== -1 && end !== -1) {
    if (end < begin) return { ok: false, reason: 'sentinels-out-of-order' };
    const next = [...lines.slice(0, begin), ...block.split('\n'), ...lines.slice(end + 1)];
    return { ok: true, text: next.join('\n'), action: 'replaced' };
  }
  // Exactly one marker → something else edited this file. Do not guess.
  if (begin !== -1 || end !== -1) {
    return { ok: false, reason: begin !== -1 ? 'sentinel-end-missing' : 'sentinel-begin-missing' };
  }

  // Neither marker → first render. Insert after the pinned header, creating the
  // header when the file has none.
  const headerIdx = lines.findIndex((l) => l.trim().startsWith(PINNED_PREFIX));
  if (headerIdx !== -1) {
    const next = [...lines.slice(0, headerIdx + 1), '', ...block.split('\n'), ...lines.slice(headerIdx + 1)];
    return { ok: true, text: next.join('\n'), action: 'inserted' };
  }
  // No pinned region at all: create one after the file's own title/preamble, i.e.
  // before the first `## ` section so the block lands in the protected region
  // rather than after the history.
  const firstSection = lines.findIndex((l) => /^##\s/.test(l));
  const at = firstSection === -1 ? lines.length : firstSection;
  const next = [...lines.slice(0, at), PINNED_HEADING, '', ...block.split('\n'), '', ...lines.slice(at)];
  return { ok: true, text: next.join('\n'), action: 'inserted' };
}

// ---------------------------------------------------------------------------

export class RulesManager {
  /** Per-agent promise chain. BOTH the renderer and the condenser write memory.md,
   *  and two independent writers on one file eventually lose an update. This is an
   *  in-process queue rather than a lockfile because both writers live in this
   *  process — a cross-process lock would be more machinery for no more safety. */
  private queues = new Map<string, Promise<unknown>>();

  constructor(
    private getHome: () => string | null,
    private log: (row: Record<string, unknown>) => void
  ) {}

  private policyDir(): string | null {
    const home = this.getHome();
    return home ? join(home, 'hive', 'policy') : null;
  }
  storePath(): string | null {
    const d = this.policyDir();
    return d ? join(d, 'rules.json') : null;
  }
  historyPath(): string | null {
    const d = this.policyDir();
    return d ? join(d, 'rules-history.jsonl') : null;
  }
  deliveryPath(): string | null {
    const d = this.policyDir();
    return d ? join(d, 'rules-delivery.json') : null;
  }
  private agentsDir(): string | null {
    const home = this.getHome();
    return home ? join(home, 'hive', 'agents') : null;
  }

  /** False when there is no store on disk. Every entry point checks this first. */
  get active(): boolean {
    const p = this.storePath();
    return !!p && existsSync(p);
  }

  read(): { rev: number; rules: Rule[] } | null {
    const p = this.storePath();
    if (!p || !existsSync(p)) return null;
    const f = readJson<RulesFile>(p);
    if (!f) {
      // A malformed store renders nothing rather than something partial — the
      // same call the policy engine makes, for the same reason.
      this.log({ kind: 'rules-load-failed', path: p });
      return null;
    }
    const rules = Array.isArray(f.rules) ? f.rules.filter((r) => r && typeof r.id === 'string' && typeof r.text === 'string') : [];
    if (typeof f.rev !== 'number') {
      // Without a rev, reconcile has nothing to compare and the notice can never
      // fire a second time. Rendering still works; the store just needs the field.
      this.log({ kind: 'rules-store-no-rev', path: p, hint: 'add a top-level integer "rev" and bump it on every change' });
    }
    return { rev: typeof f.rev === 'number' ? f.rev : 0, rules };
  }

  /**
   * Does this rule target this agent? Returns null when the scope cannot be
   * resolved to any agent, which the caller logs rather than swallows.
   */
  private targets(r: Rule, agentId: string): boolean | null {
    const s = r.scope as RuleScope | undefined;
    if (s === undefined || s === null) return true;                 // unscoped = global
    if (typeof s === 'string') {
      if (s === 'all' || s === 'global') return true;               // legacy hand-written store
      return null;                                                  // e.g. "role" — not addressable
    }
    if (s.kind === 'global') return true;
    if (s.kind === 'agents') return Array.isArray(s.ids) && s.ids.includes(agentId);
    return null;
  }

  /** Active rules targeting this agent: global, plus any naming it explicitly. */
  rulesFor(agentId: string, all?: Rule[]): Rule[] {
    const rules = all ?? this.read()?.rules ?? [];
    const unresolved: string[] = [];
    const out = rules.filter((r) => {
      if ((r.status ?? 'active') !== 'active') return false; // tombstones render nowhere
      const t = this.targets(r, agentId);
      if (t === null) { unresolved.push(r.id); return false; }
      return t;
    });
    if (unresolved.length) {
      // Loud, not silent. A rule nobody can be addressed by looks identical to a
      // rule nobody needs, and the difference only shows up weeks later when
      // someone asks why an agent never got it.
      this.log({ kind: 'rules-scope-unresolvable', agentId, ruleIds: unresolved,
        hint: 'scope must be {kind:"global"} or {kind:"agents",ids:[...]} - "role" cannot be addressed' });
    }
    return out;
  }

  /** The managed block for one agent. Deterministic: same inputs, same bytes. */
  renderBlock(agentId: string, rev: number, rules: Rule[]): string {
    const day = new Date().toISOString().slice(0, 10);
    const out = [
      `${BEGIN_PREFIX} · rev ${rev} · ${day} · managed by Munder Difflin — edit the rules store, not here -->`,
      `### ⚖️ Authority rules (rev ${rev})`,
      'The guardrail is only a FAILSAFE — follow these so it never has to fire.'
    ];
    if (!rules.length) out.push('_(no rules apply to you at this revision)_');
    rules.forEach((r, i) => {
      out.push(`(${i + 1}) ${r.text}`);
    });
    out.push(END_MARKER);
    return out.join('\n');
  }

  // — the single writer —

  /**
   * Serialized read-modify-write of one agent's memory.md.
   *
   * backup → mutate in memory → temp → rename → re-read and verify. On a verify
   * failure the backup is restored, because a memory.md that is half-written is
   * worse than one that is stale.
   */
  writeMemoryFile(agentId: string, mutate: (text: string) => { ok: true; text: string; action: string } | { ok: false; reason: string }): Promise<RenderOutcome> {
    const prev = this.queues.get(agentId) ?? Promise.resolve();
    const next = prev.then(() => this.writeNow(agentId, mutate), () => this.writeNow(agentId, mutate));
    // Keep the chain alive past a rejection so one bad write cannot wedge the agent.
    this.queues.set(agentId, next.catch(() => undefined));
    return next;
  }

  private writeNow(agentId: string, mutate: (text: string) => { ok: true; text: string; action: string } | { ok: false; reason: string }): RenderOutcome {
    const dir = this.agentsDir();
    if (!dir) return { ok: false, agentId, reason: 'no-hive-home' };
    const mem = join(dir, agentId, 'memory.md');
    if (!existsSync(mem)) return { ok: false, agentId, reason: 'no-memory-file' };

    let before: string;
    try { before = readFileSync(mem, 'utf8'); } catch { return { ok: false, agentId, reason: 'read-failed' }; }

    const res = mutate(before);
    if (!res.ok) {
      this.log({ kind: 'rules-render-aborted', agentId, reason: res.reason });
      return { ok: false, agentId, reason: res.reason };
    }
    if (res.text === before) {
      return { ok: true, agentId, rev: findSentinels(before.split('\n')).rev ?? 0, action: 'unchanged', count: 0 };
    }

    // Backup first. Append-only, never pruned — same rule the hive already lives by.
    let backup: string | null = null;
    try {
      const home = this.getHome();
      if (home) {
        const bdir = join(home, 'hive', 'backups', 'rules-render', agentId);
        mkdirSync(bdir, { recursive: true });
        backup = join(bdir, `memory-${Date.now()}.md`);
        copyFileSync(mem, backup);
      }
    } catch { backup = null; }

    try {
      atomicWrite(mem, res.text);
    } catch {
      return { ok: false, agentId, reason: 'write-failed' };
    }

    // VERIFY, don't trust. Re-read and confirm both markers survived.
    const after = readFileSync(mem, 'utf8');
    const span = findSentinels(after.split('\n'));
    if (span.begin === -1 || span.end === -1 || span.end < span.begin) {
      if (backup) { try { copyFileSync(backup, mem); } catch { /* nothing better to do */ } }
      this.log({ kind: 'rules-render-aborted', agentId, reason: 'verify-failed', restored: !!backup });
      return { ok: false, agentId, reason: 'verify-failed' };
    }
    return { ok: true, agentId, rev: span.rev ?? 0, action: res.action as 'replaced' | 'inserted', count: 0 };
  }

  // — render —

  /** Render one agent. god is included like anyone else (md-140): no isGod branch. */
  async renderFor(agentId: string): Promise<RenderOutcome> {
    if (!this.active) return { ok: false, agentId, reason: 'dormant' };
    const store = this.read();
    if (!store) return { ok: false, agentId, reason: 'store-unreadable' };
    const mine = this.rulesFor(agentId, store.rules);
    const block = this.renderBlock(agentId, store.rev, mine);
    const out = await this.writeMemoryFile(agentId, (text) => applyBlock(text, block));
    if (out.ok && out.action !== 'unchanged') {
      this.log({ kind: 'rules-rendered', agentId, rev: store.rev, rules: mine.length, action: out.action });
    }
    return out.ok ? { ...out, count: mine.length } : out;
  }

  /** Every agent with a memory.md — the store decides who gets which rules. */
  async renderAll(): Promise<RenderOutcome[]> {
    if (!this.active) return [];
    const out: RenderOutcome[] = [];
    for (const id of this.agentIds()) out.push(await this.renderFor(id));
    return out;
  }

  /**
   * Re-render any agent whose file is behind the store.
   *
   * This is what lets the design claim the rules RELIABLY land: a lost update —
   * a condense that dropped the block, a failed write, an app killed mid-render —
   * becomes self-healing instead of permanent. Compares REV, not bytes, because
   * the condenser legitimately reflows the pinned region and a byte comparison
   * would re-render on every pass forever.
   */
  async reconcile(): Promise<{ checked: number; repaired: string[]; aborted: string[] }> {
    const repaired: string[] = [];
    const aborted: string[] = [];
    if (!this.active) return { checked: 0, repaired, aborted };
    const store = this.read();
    if (!store) return { checked: 0, repaired, aborted };

    const ids = this.agentIds();
    for (const id of ids) {
      const mem = join(this.agentsDir()!, id, 'memory.md');
      let text: string;
      try { text = readFileSync(mem, 'utf8'); } catch { continue; }
      const span = findSentinels(text.split('\n'));
      const damaged = (span.begin === -1) !== (span.end === -1) || (span.begin !== -1 && span.end !== -1 && span.end < span.begin);
      if (damaged) {
        // Do not "repair" a half-marked file. Surface it and leave it alone.
        this.log({ kind: 'rules-render-aborted', agentId: id, reason: 'sentinels-damaged', phase: 'reconcile' });
        aborted.push(id);
        continue;
      }
      if (span.rev === store.rev) continue; // already current
      const out = await this.renderFor(id);
      if (out.ok) repaired.push(id); else aborted.push(id);
    }
    if (repaired.length || aborted.length) {
      this.log({ kind: 'rules-reconciled', rev: store.rev, checked: ids.length, repaired, aborted });
    }
    return { checked: ids.length, repaired, aborted };
  }

  private agentIds(): string[] {
    const dir = this.agentsDir();
    if (!dir) return [];
    try {
      return readdirSync(dir, { withFileTypes: true })
        .filter((e) => e.isDirectory() && !e.name.startsWith('.'))
        .map((e) => e.name);
    } catch { return []; }
  }

  // — the agent-knows notice —

  private delivery(): Record<string, DeliveryRecord> {
    const p = this.deliveryPath();
    if (!p) return {};
    return readJson<Record<string, DeliveryRecord>>(p) ?? {};
  }

  private saveDelivery(all: Record<string, DeliveryRecord>): void {
    const p = this.deliveryPath();
    if (!p) return;
    try {
      mkdirSync(join(p, '..'), { recursive: true });
      atomicWrite(p, JSON.stringify(all, null, 2) + '\n');
    } catch { /* a lost delivery record re-notifies once; it never loses a rule */ }
  }

  /**
   * The notice for an agent that has not yet been told about the current rev, or
   * null. Calling this RECORDS the delivery, so it fires once per rev per agent.
   *
   * Keyed on REV, not session. A compact does not re-deliver (no spam); a rule
   * change does (correct). That is deliberate: keying on session is the md-138
   * bug, where a once-per-session injection decays silently after the first
   * compaction and neither side can tell.
   *
   * State is on DISK, not in a map, so an app restart neither re-spams nor
   * silently skips.
   */
  takeNotice(agentId: string): string | null {
    if (!this.active) return null;
    const store = this.read();
    if (!store) return null;
    const mine = this.rulesFor(agentId, store.rules);
    const digest: Record<string, string> = {};
    for (const r of mine) digest[r.id] = sha1(r.text);

    const all = this.delivery();
    const prev = all[agentId];
    if (prev && prev.rev === store.rev) return null; // already told

    // First ever delivery: announce the set rather than a diff against nothing.
    const isFirst = !prev;
    const lines: string[] = [];
    if (isFirst) {
      lines.push(`RULES ACTIVE — rev ${store.rev}. ${mine.length} rule(s) apply to you.`);
    } else {
      const added: string[] = [];
      const changed: string[] = [];
      const removed: string[] = [];
      for (const r of mine) {
        if (!(r.id in prev.digest)) added.push(r.text);
        else if (prev.digest[r.id] !== digest[r.id]) changed.push(r.text);
      }
      for (const id of Object.keys(prev.digest)) {
        if (!(id in digest)) {
          const tomb = store.rules.find((r) => r.id === id);
          removed.push(tomb ? tomb.text : `(rule ${id}, text no longer in the store)`);
        }
      }
      if (!added.length && !changed.length && !removed.length) {
        // Rev moved but nothing this agent can see changed. Record and stay quiet:
        // a notice that says nothing trains the agent to skip notices.
        all[agentId] = { rev: store.rev, at: new Date().toISOString(), digest };
        this.saveDelivery(all);
        this.log({ kind: 'rules-delivery', agentId, rev: store.rev, notified: false, reason: 'no-visible-change' });
        return null;
      }
      lines.push(`RULES UPDATED — rev ${prev.rev} → ${store.rev}.`);
      for (const t of added) lines.push(`  [+] ${t}`);
      for (const t of changed) lines.push(`  [~] ${t}`);
      for (const t of removed) lines.push(`  [-] ${t} (retired — no longer applies)`);
    }
    lines.push('Your full rule set is in the managed block in your pinned memory. Nothing to paste or install — it is already there.');

    all[agentId] = { rev: store.rev, at: new Date().toISOString(), digest };
    this.saveDelivery(all);
    this.log({ kind: 'rules-delivery', agentId, rev: store.rev, notified: true, first: isFirst });
    return lines.join('\n');
  }


  // — authoring (Phase 3) —

  /**
   * Rough token estimate for the cap display. Chars/4 is the usual approximation
   * and it is deliberately not precise: the cap is an alignment mechanism, so
   * "you are near the limit" is the useful signal, not a figure to the token.
   */
  static estimateTokens(text: string): number {
    return Math.ceil(text.trim().length / 4);
  }

  /**
   * Per-agent and global budget against RULE_CAPS, for the authoring UI.
   *
   * `candidate` lets the panel ask "what would this look like if I saved?" before
   * committing, which is the whole point of enforcing the cap at authoring time:
   * a human can see the number move and retire something, instead of being
   * refused after writing the rule.
   */
  capReport(agentIds: string[], candidate?: Rule): {
    global: { count: number; tokens: number; max: number; maxTokens: number; over: boolean };
    perAgent: Record<string, { count: number; tokens: number; max: number; maxTokens: number; over: boolean }>;
    over: string[];
  } {
    const store = this.read();
    let rules = store?.rules ?? [];
    if (candidate) {
      rules = [...rules.filter((r) => r.id !== candidate.id), candidate];
    }
    const active = rules.filter((r) => (r.status ?? 'active') === 'active');
    const gTokens = active.reduce((n, r) => n + RulesManager.estimateTokens(r.text), 0);
    const global = {
      count: active.length, tokens: gTokens,
      max: RULE_CAPS.globalMax, maxTokens: RULE_CAPS.globalMaxTokens,
      over: active.length > RULE_CAPS.globalMax || gTokens > RULE_CAPS.globalMaxTokens
    };
    const perAgent: Record<string, { count: number; tokens: number; max: number; maxTokens: number; over: boolean }> = {};
    const over: string[] = [];
    if (global.over) over.push('global');
    for (const id of agentIds) {
      const mine = this.rulesFor(id, active);
      const tokens = mine.reduce((n, r) => n + RulesManager.estimateTokens(r.text), 0);
      const entry = {
        count: mine.length, tokens,
        max: RULE_CAPS.perAgentMax, maxTokens: RULE_CAPS.perAgentMaxTokens,
        over: mine.length > RULE_CAPS.perAgentMax || tokens > RULE_CAPS.perAgentMaxTokens
      };
      perAgent[id] = entry;
      if (entry.over) over.push(id);
    }
    return { global, perAgent, over };
  }

  private appendHistory(row: Record<string, unknown>): void {
    const p = this.historyPath();
    if (!p) return;
    try {
      mkdirSync(join(p, '..'), { recursive: true });
      // Append, never rewrite. A bad rule is only traceable if the trail is intact.
      writeFileSync(p, JSON.stringify({ at: new Date().toISOString(), ...row }) + '\n', { flag: 'a' });
    } catch { /* history is best-effort; it must not block a write */ }
  }

  /** Write the store with the rev bumped, atomically. */
  private commit(rules: Rule[], rev: number): boolean {
    const p = this.storePath();
    if (!p) return false;
    const existing = readJson<RulesFile>(p) ?? {};
    const next = { ...existing, rev, rules };
    try { atomicWrite(p, JSON.stringify(next, null, 2) + '\n'); return true; } catch { return false; }
  }

  /** Agents a rule reaches, given the roster to resolve `global` against. */
  private targetsOf(rule: Rule, agentIds: string[]): string[] {
    return agentIds.filter((id) => this.targets(rule, id) === true);
  }

  /**
   * Add or replace a rule, bump the rev, record history, and render the agents it
   * reaches. Rejects an over-cap save and a stale write.
   *
   * `expectedRev` is optimistic concurrency: the panel sends back the rev it read,
   * and a mismatch is refused rather than merged. Two writers on one small file is
   * exactly where a silent overwrite happens, and the panel can reload and
   * re-present far more cheaply than anyone can reconstruct a lost rule.
   */
  async upsert(rule: Rule, opts: { actor: string; agentIds: string[]; expectedRev?: number }): Promise<{ ok: true; rev: number; rendered: string[] } | { ok: false; reason: string; detail?: unknown }> {
    if (!this.active) return { ok: false, reason: 'dormant' };
    const store = this.read();
    if (!store) return { ok: false, reason: 'store-unreadable' };
    if (opts.expectedRev !== undefined && opts.expectedRev !== store.rev) {
      return { ok: false, reason: 'stale-rev', detail: { expected: opts.expectedRev, actual: store.rev } };
    }
    if (!rule.id || !rule.text?.trim()) return { ok: false, reason: 'id-and-text-required' };

    const candidate: Rule = {
      ...rule,
      text: rule.text.trim(),
      status: rule.status ?? 'active',
      added_by: rule.added_by ?? opts.actor,
      added: rule.added ?? new Date().toISOString().slice(0, 10)
    };
    const cap = this.capReport(opts.agentIds, candidate);
    if (cap.over.length) return { ok: false, reason: 'over-cap', detail: cap };

    const existed = store.rules.some((r) => r.id === candidate.id);
    const rules = [...store.rules.filter((r) => r.id !== candidate.id), candidate];
    const rev = store.rev + 1;
    if (!this.commit(rules, rev)) return { ok: false, reason: 'write-failed' };
    this.appendHistory({ rev, actor: opts.actor, op: existed ? 'edit' : 'add', ruleId: candidate.id });
    this.log({ kind: 'rules-authored', rev, actor: opts.actor, op: existed ? 'edit' : 'add', ruleId: candidate.id });

    const rendered: string[] = [];
    for (const id of opts.agentIds) {
      const out = await this.renderFor(id);
      if (out.ok) rendered.push(id);
    }
    return { ok: true, rev, rendered };
  }

  /**
   * Retire a rule: a TOMBSTONE in the store, dropped from every rendered block.
   *
   * Never a silent removal. A rule that simply vanishes leaves the next reader
   * noticing a gap and re-opening the question it settled; the tombstone is what
   * makes the decision legible later.
   */
  async retire(id: string, opts: { actor: string; agentIds: string[]; expectedRev?: number }): Promise<{ ok: true; rev: number; rendered: string[] } | { ok: false; reason: string; detail?: unknown }> {
    if (!this.active) return { ok: false, reason: 'dormant' };
    const store = this.read();
    if (!store) return { ok: false, reason: 'store-unreadable' };
    if (opts.expectedRev !== undefined && opts.expectedRev !== store.rev) {
      return { ok: false, reason: 'stale-rev', detail: { expected: opts.expectedRev, actual: store.rev } };
    }
    const target = store.rules.find((r) => r.id === id);
    if (!target) return { ok: false, reason: 'unknown-rule' };
    if ((target.status ?? 'active') === 'retired') return { ok: false, reason: 'already-retired' };

    const rules = store.rules.map((r) => r.id === id
      ? { ...r, status: 'retired' as const, retired: new Date().toISOString().slice(0, 10) }
      : r);
    const rev = store.rev + 1;
    if (!this.commit(rules, rev)) return { ok: false, reason: 'write-failed' };
    this.appendHistory({ rev, actor: opts.actor, op: 'retire', ruleId: id });
    this.log({ kind: 'rules-authored', rev, actor: opts.actor, op: 'retire', ruleId: id });

    const rendered: string[] = [];
    for (const aid of opts.agentIds) {
      const out = await this.renderFor(aid);
      if (out.ok) rendered.push(aid);
    }
    return { ok: true, rev, rendered };
  }

  /** Everything the panel needs in one call: store, per-agent targeting, caps. */
  overview(agentIds: string[]): {
    active: boolean; rev: number; rules: Rule[];
    targets: Record<string, string[]>;
    caps: ReturnType<RulesManager['capReport']>;
    deliveredRevs: Record<string, number | null>;
  } {
    const store = this.read();
    const rules = store?.rules ?? [];
    const targets: Record<string, string[]> = {};
    for (const r of rules) targets[r.id] = this.targetsOf(r, agentIds);
    const deliveredRevs: Record<string, number | null> = {};
    for (const id of agentIds) deliveredRevs[id] = this.deliveredRev(id);
    return {
      active: this.active, rev: store?.rev ?? 0, rules,
      targets, caps: this.capReport(agentIds), deliveredRevs
    };
  }

  /** The rules in effect for one agent — the read-only per-agent view. */
  inEffect(agentId: string): { rev: number; rules: Rule[]; deliveredRev: number | null } {
    const store = this.read();
    return { rev: store?.rev ?? 0, rules: this.rulesFor(agentId, store?.rules ?? []), deliveredRev: this.deliveredRev(agentId) };
  }

  /** Read-only view for an operator answering "did agent X get rule N?". */
  deliveredRev(agentId: string): number | null {
    return this.delivery()[agentId]?.rev ?? null;
  }
}
